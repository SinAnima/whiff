//! Python pickles, by walking the opcode stream (protocols 0–5); nothing
//! is ever unpickled. Reported: protocol, pickles in the file, opcode
//! count, the globals the pickle imports (`module.name`, from `GLOBAL`,
//! `INST` and `STACK_GLOBAL` with its strings resolved through the memo),
//! what the globals say it holds (pandas DataFrame, NumPy array,
//! scikit-learn model, PyTorch tensors …), and the string literals for the
//! secret scan. Globals that run commands or code when loaded (`os.system`,
//! `subprocess.*`, `builtins.eval` …) are flagged.
//!
//! Specification: CPython `Lib/pickletools.py` (opcode table) and
//! PEP 307 / 3154 / 574.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};

use super::Walk;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for pickles.
pub struct Pickle;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.pickle",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pickle",
            name: "Python pickle",
            family: "data.binser",
            mimes: &["application/x-python-pickle"],
            extensions: &["pkl", "pickle", "pckl", "joblib"],
            magic: &[],
            parent: None,
        },
        // Redirected to from `pickle` when the globals show a pandas object.
        FormatSpec {
            id: "pandas_pickle",
            name: "pandas DataFrame pickle",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("pickle"),
        },
    ],
};

/// Opcodes walked.
const MAX_OPS: u64 = 20_000_000;
/// Globals listed.
const MAX_GLOBALS: usize = 100;

/// Modules whose every callable can run commands or code.
const UNSAFE_MODULES: [&str; 16] = [
    "os",
    "posix",
    "nt",
    "subprocess",
    "commands",
    "pty",
    "runpy",
    "socket",
    "webbrowser",
    "ctypes",
    "importlib",
    "code",
    "shutil",
    "sys",
    "asyncio.subprocess",
    "multiprocessing",
];

/// Single callables that run code.
const UNSAFE_NAMES: [&str; 14] = [
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "builtins.__import__",
    "builtins.getattr",
    "builtins.open",
    "__builtin__.eval",
    "__builtin__.execfile",
    "__builtin__.file",
    "__builtin__.__import__",
    "marshal.loads",
    "pickle.loads",
    "types.CodeType",
    "types.FunctionType",
];

/// What a pickle holds, from a global it imports.
const KINDS: [(&str, &str); 11] = [
    ("pandas.core.frame.DataFrame", "pandas_dataframe"),
    ("pandas.DataFrame", "pandas_dataframe"),
    ("pandas.Series", "pandas_series"),
    ("pandas.core.series.Series", "pandas_series"),
    ("torch._utils._rebuild_tensor_v2", "pytorch_tensors"),
    ("torch._utils._rebuild_parameter", "pytorch_tensors"),
    ("sklearn.", "scikit_learn_model"),
    ("xgboost.", "xgboost_model"),
    ("keras.", "keras_model"),
    ("numpy.core.multiarray._reconstruct", "numpy_array"),
    ("numpy._core.multiarray._reconstruct", "numpy_array"),
];

pub(crate) fn is_unsafe(global: &str) -> bool {
    let module = global.rsplit_once('.').map_or(global, |(m, _)| m);
    UNSAFE_NAMES.contains(&global)
        || UNSAFE_MODULES.iter().any(|m| module == *m || module.starts_with(&format!("{m}.")))
}

/// The protocol and the globals (in order, without repeats) of the
/// pickles in `data`, for formats that wrap pickles (PyTorch checkpoints).
#[cfg(feature = "data")]
pub(crate) fn imports(data: &[u8]) -> (Option<u8>, Vec<String>) {
    let f = walk(data, &mut Walk::default());
    let mut globals = Vec::new();
    for g in f.globals {
        if !globals.contains(&g) {
            globals.push(g);
        }
    }
    (f.protocol, globals)
}

/// What the walk found.
#[derive(Default)]
struct Found {
    protocol: Option<u8>,
    pickles: u64,
    ops: u64,
    globals: Vec<String>,
    opcodes: BTreeMap<&'static str, u64>,
    error: Option<&'static str>,
}

/// Walk the opcodes of all pickles in `b`.
#[allow(clippy::too_many_lines)] // the opcode table
fn walk(b: &[u8], w: &mut Walk) -> Found {
    let mut f = Found::default();
    let mut at = 0usize;
    // Strings pushed most recently (for STACK_GLOBAL) and the memo.
    let mut recent: Vec<Option<String>> = Vec::new();
    let mut memo: HashMap<u64, Option<String>> = HashMap::new();
    let mut last: Option<String> = None;
    let line = |at: &mut usize| -> Option<&[u8]> {
        let rest = b.get(*at..)?;
        let i = rest.iter().position(|&c| c == b'\n')?;
        *at += i + 1;
        Some(&rest[..i])
    };
    let int = |at: &mut usize, n: usize| -> Option<u64> {
        let v = b.get(*at..*at + n)?.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
        *at += n;
        Some(v)
    };
    let mut in_pickle = false;
    while at < b.len() {
        if f.ops >= MAX_OPS {
            f.error = Some("too many opcodes");
            break;
        }
        if !in_pickle && b[at..].iter().all(|&c| c == 0 || c.is_ascii_whitespace()) {
            break;
        }
        in_pickle = true;
        let op = b[at];
        at += 1;
        f.ops += 1;
        let mut push: Option<Option<String>> = Some(None);
        let ok = (|| -> Option<()> {
            match op {
                // Arguments read from a line.
                b'I' | b'L' | b'F' | b'g' | b'p' | b'P' => {
                    let l = line(&mut at)?;
                    let n =
                        std::str::from_utf8(l).ok().and_then(|s| s.trim().trim_end_matches('L').parse::<u64>().ok());
                    match op {
                        b'p' => {
                            memo.insert(n?, last.clone());
                            push = None;
                        }
                        b'g' => push = Some(memo.get(&n?).cloned().flatten()),
                        _ => {}
                    }
                }
                b'S' | b'V' => {
                    let l = String::from_utf8_lossy(line(&mut at)?).into_owned();
                    let s = l.trim_matches(['\'', '"']).to_string();
                    w.string(&s);
                    push = Some(Some(s));
                }
                b'c' | b'i' => {
                    let m = String::from_utf8_lossy(line(&mut at)?).into_owned();
                    let n = String::from_utf8_lossy(line(&mut at)?).into_owned();
                    f.globals.push(format!("{m}.{n}"));
                }
                // Fixed-size arguments.
                b'J' | b'G' | b'M' | b'K' | b'h' | b'q' | b'j' | b'r' | 0x80 | 0x82 | 0x83 | 0x84 | 0x95 => {
                    let n = match op {
                        b'J' | b'j' | b'r' | 0x84 => 4,
                        b'G' | 0x95 => 8,
                        b'M' | 0x83 => 2,
                        _ => 1,
                    };
                    let v = int(&mut at, n)?;
                    match op {
                        0x80 => {
                            f.protocol.get_or_insert(u8::try_from(v).ok()?);
                            push = None;
                        }
                        0x95 => push = None,
                        b'h' | b'j' => push = Some(memo.get(&v).cloned().flatten()),
                        b'q' | b'r' => {
                            memo.insert(v, last.clone());
                            push = None;
                        }
                        _ => {}
                    }
                }
                // Length-prefixed strings and bytes.
                b'T' | b'U' | b'X' | b'B' | b'C' | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x96 => {
                    let n = match op {
                        b'U' | b'C' | 0x8a | 0x8c => 1,
                        0x8d | 0x8e | 0x96 => 8,
                        _ => 4,
                    };
                    let len = usize::try_from(int(&mut at, n)?).ok()?;
                    let body = b.get(at..at.checked_add(len)?)?;
                    at += len;
                    if matches!(op, b'T' | b'U' | b'X' | 0x8c | 0x8d) {
                        let s = String::from_utf8_lossy(body).into_owned();
                        w.string(&s);
                        push = Some(Some(s));
                    }
                }
                0x94 => {
                    let n = memo.len() as u64;
                    memo.insert(n, last.clone());
                    push = None;
                }
                0x93 => {
                    let name = recent.pop().flatten();
                    let module = recent.pop().flatten();
                    let g = match (module, name) {
                        (Some(m), Some(n)) => format!("{m}.{n}"),
                        _ => "?".to_string(),
                    };
                    f.globals.push(g);
                }
                b'.' => {
                    f.pickles += 1;
                    in_pickle = false;
                    push = None;
                }
                b'(' | b'0' | b'1' | b'2' | b'N' | b'Q' | b'R' | b'a' | b'b' | b'd' | b'}' | b'e' | b'l' | b']'
                | b'o' | b's' | b't' | b')' | b'u' | 0x81 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8f | 0x90 | 0x91
                | 0x92 | 0x97 | 0x98 => {}
                _ => return None,
            }
            Some(())
        })();
        if ok.is_none() {
            f.error = Some(if at >= b.len() { "truncated" } else { "unknown opcode" });
            break;
        }
        *f.opcodes.entry(name(op)).or_default() += 1;
        if let Some(p) = push {
            last.clone_from(&p);
            recent.push(p);
            if recent.len() > 64 {
                recent.remove(0);
            }
        }
    }
    if in_pickle && f.error.is_none() {
        f.error = Some("no STOP opcode");
    }
    f
}

/// Opcode names for the histogram (the common ones; others by class).
fn name(op: u8) -> &'static str {
    match op {
        b'c' | b'i' | 0x93 => "global",
        b'R' | 0x81 | 0x92 | b'o' => "call",
        b'b' => "build",
        b'(' => "mark",
        b'.' => "stop",
        0x80 => "proto",
        0x95 => "frame",
        b'h' | b'j' | b'g' => "get",
        b'q' | b'r' | b'p' | 0x94 => "put",
        b'S' | b'V' | b'T' | b'U' | b'X' | 0x8c | 0x8d => "string",
        b'B' | b'C' | 0x8e | 0x96 | 0x97 | 0x98 => "bytes",
        b'I' | b'J' | b'K' | b'M' | b'L' | 0x8a | 0x8b => "int",
        b'F' | b'G' => "float",
        b']' | b'l' | b'a' | b'e' => "list",
        b'}' | b'd' | b's' | b'u' => "dict",
        b')' | b't' | 0x85 | 0x86 | 0x87 => "tuple",
        _ => "other",
    }
}

impl Extractor for Pickle {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ends = probe.tail.last() == Some(&b'.');
        // Protocol 2+: PROTO n, then (4+) a FRAME.
        let binary = h.first() == Some(&0x80)
            && h.get(1).is_some_and(|p| (2..=5).contains(p))
            && (h.get(1).is_some_and(|&p| p < 4) || h.get(2) == Some(&0x95));
        if binary && ends {
            // pandas objects name their class among the first globals.
            let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
            let pandas = has(b"pandas") && (has(b"DataFrame") || has(b"Series"));
            return Some(if pandas {
                Sniff { format: "pandas_pickle", confidence: 0.9 }
            } else {
                Sniff { format: "pickle", confidence: 0.85 }
            });
        }
        let named = probe.extension.is_some_and(|e| ["pkl", "pickle", "pckl", "joblib"].contains(&e));
        let text = matches!(h.first(), Some(b'(' | b'c' | b']' | b'}' | b'I' | b'S' | b'V' | b'N'));
        (named && (binary || text) && ends).then_some(Sniff { format: "pickle", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        let mut w = Walk::default();
        let f = walk(&data, &mut w);
        if f.ops == 0 || (f.pickles == 0 && !cut) && f.error == Some("unknown opcode") {
            return Err(ExtractError::malformed("not a pickle"));
        }
        // A pandas object: report it as such (the engine runs this extractor
        // again under `pandas_pickle`; nothing is written on this pass).
        let pandas = f.globals.iter().any(|g| {
            g.starts_with("pandas.core.frame.")
                || g.starts_with("pandas.core.series.")
                || g == "pandas.DataFrame"
                || g == "pandas.Series"
        });
        if pandas && cx.format_id() == "pickle" {
            cx.redirect("pandas_pickle");
            return Ok(());
        }
        cx.format_set("protocol", f.protocol.unwrap_or(0));
        if f.pickles != 1 {
            cx.format_set("pickles", f.pickles);
        }
        cx.format_set("opcodes", f.ops);
        if let Some(e) = f.error.filter(|_| !cut) {
            cx.format_set("decode_error", e);
        }
        if cut {
            cx.format_set("truncated", true);
        }
        let m: Map<String, Value> = f.opcodes.iter().map(|(k, n)| ((*k).to_string(), (*n).into())).collect();
        cx.format_set("opcode_classes", Value::Object(m));
        let mut globals: Vec<&str> = Vec::new();
        for g in &f.globals {
            if !globals.contains(&g.as_str()) {
                globals.push(g);
            }
        }
        if !globals.is_empty() {
            let shown: Vec<String> = globals.iter().take(MAX_GLOBALS).map(|g| truncate_chars(g, 200)).collect();
            cx.format_set("globals", shown);
        }
        let kind = KINDS.iter().find(|(prefix, _)| globals.iter().any(|g| g.starts_with(prefix))).map(|(_, k)| *k);
        if let Some(k) = kind {
            cx.format_set("kind", k);
        }
        let unsafe_globals: Vec<&str> = globals.iter().copied().filter(|g| is_unsafe(g)).collect();
        if !unsafe_globals.is_empty() {
            cx.security().risk("unsafe_deserialization", Some(truncate_chars(&unsafe_globals.join(", "), 300)));
        }
        if !w.text.is_empty() {
            cx.emit_text(TextRole::Data, &w.text);
        }
        Ok(())
    }
}

crate::register_extractor!(Pickle);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    #[test]
    fn stack_global_through_the_memo() {
        // Protocol 4: "os" MEMOIZE, "system" MEMOIZE, STACK_GLOBAL, … STOP.
        let mut b = vec![0x80, 4, 0x95];
        b.extend(0u64.to_le_bytes());
        b.extend([0x8c, 2]);
        b.extend(b"os");
        b.push(0x94);
        b.extend([0x8c, 6]);
        b.extend(b"system");
        b.push(0x94);
        b.push(0x93);
        b.extend([0x8c, 4]);
        b.extend(b"true");
        b.extend([0x85, b'R', b'.']);
        let mut w = Walk::default();
        let f = walk(&b, &mut w);
        assert_eq!((f.globals.as_slice(), f.pickles, f.error), (&["os.system".to_string()][..], 1, None));
        let r = report_for("x.pkl", &b);
        assert!(r.security.risks.iter().any(|r| r.kind == "unsafe_deserialization"));
    }

    #[test]
    fn protocol_0_globals() {
        let b = b"ccollections\nOrderedDict\np0\n(tRp1\n.";
        let f = walk(b, &mut Walk::default());
        assert_eq!(f.globals, ["collections.OrderedDict"]);
        assert!(!is_unsafe("collections.OrderedDict"));
        assert!(is_unsafe("subprocess.Popen") && is_unsafe("builtins.eval") && !is_unsafe("os2.x"));
    }

    crate::fixture_tests!("pickle", "pandas_pickle");
}
