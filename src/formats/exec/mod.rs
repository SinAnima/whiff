//! `exec` extractors (feature `common`): native executables, libraries and
//! object files (ELF, PE / COFF and the MS-DOS family, Mach-O) and
//! WebAssembly modules. Each reports what the file is (kind, architecture,
//! bitness, entry point, target OS), how it is built (sections with their
//! entropy, segments, the libraries and functions it imports, its exports),
//! how it is protected (`hardening`: PIE / ASLR, NX, RELRO, stack canary,
//! FORTIFY, CFG, hardened runtime …), who signed it (Authenticode, Apple
//! code signature, through [`der`](crate::plugin::der)) and what built it
//! (`toolchain`: compilers, Go build information, Rust, installers and
//! packers found by a bounded scan). Nothing is executed or disassembled.

pub(crate) mod debug;
pub(crate) mod elf;
pub(crate) mod macho;
pub(crate) mod misc;
pub(crate) mod pe;
pub(crate) mod scripting;
pub(crate) mod wasm;

use aho_corasick::AhoCorasick;
use serde_json::{Map, Value, json};

// Readers shared with the archive and bytecode extractors.
pub(crate) use super::archive::unix_time;
pub(crate) use super::bytecode::cli;
use crate::plugin::{Context, ExtractError, Source, redact_secrets};

/// Sections listed in the report (the counts cover all of them).
const MAX_SECTIONS: usize = 96;
/// Names listed per import / export list.
pub(crate) const MAX_NAMES: usize = 64;
/// Bytes of a section read for its entropy.
const ENTROPY_SAMPLE: u64 = 1 << 20;
/// Entropy above which an executable section looks compressed or encrypted.
const PACKED_ENTROPY: f64 = 7.2;

/// One section (or segment) of a binary.
#[derive(Debug, Default, Clone)]
pub(crate) struct Section {
    pub name: String,
    /// Where its bytes are in the file, and how many (0 for BSS-like sections).
    pub offset: u64,
    pub size: u64,
    /// Load address and size in memory.
    pub address: u64,
    pub memory_size: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Shannon entropy in bits per byte, to three decimals.
pub(crate) fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    let n = data.len() as f64;
    let h: f64 = counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum();
    (h * 1000.0).round() / 1000.0
}

/// Lower-case hex digits.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `0x…` for addresses.
pub(crate) fn addr(v: u64) -> String {
    format!("{v:#x}")
}

/// List the sections (with the entropy of their first MiB, within the
/// parse limit) and flag writable-and-executable ones and packed code.
pub(crate) fn report_sections(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    sections: &[Section],
) -> Result<(), ExtractError> {
    let mut budget = cx.parse_limit() as u64;
    let mut list = Vec::new();
    let mut packed = None;
    for s in sections {
        let mut m = Map::new();
        m.insert("name".into(), s.name.clone().into());
        m.insert("size".into(), s.size.into());
        if s.memory_size != s.size {
            m.insert("memory_size".into(), s.memory_size.into());
        }
        if s.address != 0 {
            m.insert("address".into(), addr(s.address).into());
        }
        let flags: String =
            [(s.read, 'r'), (s.write, 'w'), (s.execute, 'x')].iter().map(|&(on, c)| if on { c } else { '-' }).collect();
        m.insert("flags".into(), flags.into());
        let take = s.size.min(ENTROPY_SAMPLE).min(budget).min(src.len().saturating_sub(s.offset));
        if take > 0 {
            budget -= take;
            let data = src.read_vec(s.offset, usize::try_from(take).unwrap_or(0))?;
            let e = entropy(&data);
            m.insert("entropy".into(), e.into());
            if s.execute && e > PACKED_ENTROPY && take >= 4096 {
                packed.get_or_insert_with(|| format!("section {} has entropy {e}", s.name));
            }
        }
        if s.write && s.execute {
            cx.security()
                .risk("writable_executable_memory", Some(format!("section {} is writable and executable", s.name)));
        }
        if list.len() < MAX_SECTIONS {
            list.push(Value::Object(m));
        }
    }
    if let Some(upx) = sections.iter().find(|s| s.name.starts_with("UPX")) {
        packed = Some(format!("UPX section {}", upx.name));
    }
    if let Some(detail) = packed {
        cx.security().risk("packed_executable", Some(detail));
    }
    cx.format_set("section_count", sections.len());
    if !list.is_empty() {
        cx.format_set("sections", list);
    }
    Ok(())
}

/// Names as a JSON list, at most [`MAX_NAMES`].
pub(crate) fn names<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> Value {
    items.into_iter().take(MAX_NAMES).map(|s| Value::from(s.as_ref())).collect::<Vec<_>>().into()
}

/// What the toolchain scan finds.
#[derive(Debug, Default)]
pub(crate) struct Toolchain {
    pub facts: Map<String, Value>,
}

impl Toolchain {
    /// Add a compiler or linker identification (at most eight, no repeats).
    pub fn add_compiler(&mut self, s: String) {
        let list = self.facts.entry("compilers").or_insert_with(|| json!([]));
        let Some(a) = list.as_array_mut() else { return };
        if a.iter().any(|v| v.as_str().is_some_and(|v| v.contains(s.as_str()))) {
            return;
        }
        a.retain(|v| !v.as_str().is_some_and(|v| s.contains(v)));
        if a.len() < 8 {
            a.push(s.into());
        }
    }

    /// Write `toolchain` (when anything was found).
    pub fn write(self, cx: &mut Context<'_>) {
        if !self.facts.is_empty() {
            cx.format_set("toolchain", Value::Object(self.facts));
        }
    }
}

/// Markers the scan looks for.
const MARKERS: &[&[u8]] = &[
    b"\xff Go buildinf:",
    b"/rustc/",
    b"rustc version ",
    b"GCC: (",
    b"clang version ",
    b"Linker: ",
    b"NullsoftInst",
    b"Inno Setup Setup Data (",
    b"MEI\x0c\x0b\x0a\x0b\x0e",
    b"UPX!",
    b"PyInstaller",
    b"Go build ID: \"",
    b"Swift version ",
];

/// Scan the first parse-limit bytes of the file for build markers.
pub(crate) fn scan_toolchain(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<Toolchain, ExtractError> {
    const CHUNK: u64 = 1 << 20;
    const OVERLAP: u64 = 64;
    let mut t = Toolchain::default();
    let Ok(ac) = AhoCorasick::new(MARKERS) else { return Ok(t) };
    let end = src.len().min(cx.parse_limit() as u64);
    let mut hits: Vec<(usize, u64)> = Vec::new();
    let mut at = 0u64;
    while at < end {
        cx.checkpoint()?;
        let n = (end - at).min(CHUNK + OVERLAP);
        let data = src.read_vec(at, usize::try_from(n).unwrap_or(0))?;
        for m in ac.find_iter(&data) {
            let p = m.pattern().as_usize();
            let off = at + m.start() as u64;
            // A marker in the overlap is found again by the next chunk.
            if (m.start() as u64) < CHUNK && hits.iter().filter(|h| h.0 == p).count() < 16 {
                hits.push((p, off));
            }
        }
        at += CHUNK;
    }
    for (p, off) in hits {
        let tail = src.read_vec(off, usize::try_from((src.len() - off).min(4096)).unwrap_or(0))?;
        match p {
            0 => {
                if !t.facts.contains_key("go") {
                    let go = src.read_vec(off, usize::try_from((src.len() - off).min(1 << 20)).unwrap_or(0))?;
                    if let Some(g) = go_buildinfo(&go) {
                        t.facts.insert("go".into(), Value::Object(g));
                    }
                }
            }
            1 => {
                let hash: String = tail[7..].iter().take(40).map(|&b| char::from(b)).collect();
                if hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && tail.get(47) == Some(&b'/') {
                    rust(&mut t).insert("rustc_commit".into(), hash.into());
                }
            }
            2 => {
                let v = c_string(&tail[14..], 80);
                if !v.is_empty() {
                    rust(&mut t).insert("rustc_version".into(), v.into());
                }
            }
            3 | 4 | 5 | 12 => {
                let s = c_string(&tail, 120);
                if s.len() > 8 {
                    t.add_compiler(s);
                }
            }
            6 => {
                t.facts.entry("installer").or_insert_with(|| "nsis".into());
            }
            7 => {
                let v = c_string(&tail[23..], 16);
                t.facts.insert("installer".into(), "inno_setup".into());
                if let Some(v) = v.split(')').next().filter(|v| !v.is_empty()) {
                    t.facts.insert("installer_version".into(), v.into());
                }
            }
            8 => {
                // PyInstaller cookie: length, TOC offset and size, Python version.
                if let Some(v) = tail.get(20..24).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    && (20..400).contains(&v)
                {
                    t.facts.insert("bundler".into(), "pyinstaller".into());
                    let (major, minor) = if v >= 100 { (v / 100, v % 100) } else { (v / 10, v % 10) };
                    t.facts.insert("python_version".into(), format!("{major}.{minor}").into());
                }
            }
            9 => {
                t.facts.entry("packer").or_insert_with(|| "upx".into());
            }
            10 => {
                t.facts.entry("bundler").or_insert_with(|| "pyinstaller".into());
            }
            11 => {
                let id = c_string(&tail[13..], 120);
                if let Some(id) = id.split('"').next().filter(|s| !s.is_empty()) {
                    t.facts.entry("go_build_id").or_insert_with(|| id.into());
                }
            }
            _ => {}
        }
    }
    if t.facts.contains_key("packer") {
        cx.security().risk("packed_executable", Some("UPX".into()));
    }
    Ok(t)
}

fn rust(t: &mut Toolchain) -> &mut Map<String, Value> {
    t.facts.entry("rust").or_insert_with(|| json!({})).as_object_mut().expect("object")
}

/// The printable text at the start of `b`, up to a NUL or `max` bytes.
pub(crate) fn c_string(b: &[u8], max: usize) -> String {
    let end = b
        .iter()
        .take(max)
        .position(|&c| c == 0 || c == b'\n' || !(0x20..0x7f).contains(&c))
        .unwrap_or(b.len().min(max));
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

/// Build keys reported from Go build information (`-ldflags` can hold secrets).
const GO_BUILD_KEYS: &[&str] = &[
    "-buildmode",
    "-compiler",
    "-trimpath",
    "-race",
    "CGO_ENABLED",
    "GOARCH",
    "GOOS",
    "GOAMD64",
    "GOARM",
    "GOARM64",
    "vcs",
    "vcs.revision",
    "vcs.time",
    "vcs.modified",
];

/// Go build information (Go 1.18+ inline format): toolchain version, main
/// package and module, dependencies, build settings.
pub(crate) fn go_buildinfo(b: &[u8]) -> Option<Map<String, Value>> {
    let flags = *b.get(15)?;
    let mut out = Map::new();
    if flags & 2 == 0 {
        // Go 1.17 and older point at the strings instead.
        out.insert("format".into(), "pointer".into());
        return Some(out);
    }
    let mut at = 32;
    let mut field = || -> Option<&[u8]> {
        let (n, used) = uleb(b.get(at..)?)?;
        let start = at + used;
        let end = start.checked_add(usize::try_from(n).ok()?)?;
        at = end;
        b.get(start..end)
    };
    let version = String::from_utf8_lossy(field()?).into_owned();
    let modinfo = field().unwrap_or_default();
    out.insert("version".into(), version.into());
    // The module information is framed by 16-byte sentinels.
    let modinfo = if modinfo.len() >= 33 && modinfo[modinfo.len() - 17] == b'\n' {
        &modinfo[16..modinfo.len() - 16]
    } else {
        modinfo
    };
    let text = String::from_utf8_lossy(modinfo);
    let mut deps = Vec::new();
    let mut build = Map::new();
    for line in text.lines() {
        let mut f = line.split('\t');
        match (f.next(), f.next(), f.next()) {
            (Some("path"), Some(p), _) => {
                out.insert("path".into(), p.into());
            }
            (Some("mod"), Some(m), v) => {
                out.insert("module".into(), m.into());
                if let Some(v) = v.filter(|v| !v.is_empty()) {
                    out.insert("module_version".into(), v.into());
                }
            }
            (Some("dep"), Some(d), v) => deps.push(format!("{d}@{}", v.unwrap_or(""))),
            (Some("build"), Some(kv), _) => {
                if let Some((k, v)) = kv.split_once('=')
                    && GO_BUILD_KEYS.contains(&k)
                {
                    build.insert(k.into(), redact_secrets(v).into_owned().into());
                }
            }
            _ => {}
        }
    }
    if !deps.is_empty() {
        out.insert("dependency_count".into(), deps.len().into());
        out.insert("dependencies".into(), names(&deps));
    }
    if !build.is_empty() {
        out.insert("build".into(), Value::Object(build));
    }
    Some(out)
}

/// Archive and installer payloads appended to an executable.
pub(crate) fn overlay_kind(head: &[u8]) -> Option<&'static str> {
    Some(match head {
        [b'P', b'K', 3, 4, ..] => "zip",
        [b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c, ..] => "7z",
        [b'R', b'a', b'r', b'!', 0x1a, 7, ..] => "rar",
        [b'M', b'S', b'C', b'F', ..] => "cab",
        [_, _, _, _, 0xef, 0xbe, 0xad, 0xde, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', ..] => "nsis",
        _ => return None,
    })
}

/// Report data after the last section (`overlay_bytes`) and hand on an
/// archive found there (self-extractors, installers).
pub(crate) fn report_overlay(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    start: u64,
    end: u64,
) -> Result<(), ExtractError> {
    if end <= start {
        return Ok(());
    }
    cx.format_set("overlay_bytes", end - start);
    let head = src.read_vec(start, usize::try_from((end - start).min(64)).unwrap_or(0))?;
    let Some(kind) = overlay_kind(&head) else { return Ok(()) };
    cx.format_set("overlay", kind);
    if kind == "nsis" {
        nsis_first_header(cx, &head);
    }
    if kind != "nsis" && cx.child_room() > 0 {
        let n = (end - start).min(cx.parse_limit() as u64);
        let data = src.read_vec(start, usize::try_from(n).unwrap_or(0))?;
        cx.emit_child(&format!("[overlay].{kind}"), data)?;
    }
    Ok(())
}

/// NSIS's first header (`fileform.h`): flags, the signature, then the size
/// of the (compressed) installer header and of everything that follows.
fn nsis_first_header(cx: &mut Context<'_>, h: &[u8]) {
    let le = |at: usize| h.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let (Some(flags), Some(header), Some(data)) = (le(0), le(20), le(24)) else { return };
    cx.format_set("nsis_uninstaller", flags & 1 != 0);
    if flags & 2 != 0 {
        cx.format_set("nsis_silent", true);
    }
    cx.format_set("nsis_header_bytes", header);
    cx.format_set("nsis_data_bytes", data);
}

/// Fixed-width integers of either byte order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Endian {
    pub le: bool,
}

impl Endian {
    pub fn u16(self, b: &[u8], at: usize) -> Option<u16> {
        let x: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
        Some(if self.le { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) })
    }

    pub fn u32(self, b: &[u8], at: usize) -> Option<u32> {
        let x: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.le { u32::from_le_bytes(x) } else { u32::from_be_bytes(x) })
    }

    pub fn u64(self, b: &[u8], at: usize) -> Option<u64> {
        let x: [u8; 8] = b.get(at..at + 8)?.try_into().ok()?;
        Some(if self.le { u64::from_le_bytes(x) } else { u64::from_be_bytes(x) })
    }

    /// A 4- or 8-byte word.
    pub fn word(self, b: &[u8], at: usize, wide: bool) -> Option<u64> {
        if wide { self.u64(b, at) } else { self.u32(b, at).map(u64::from) }
    }
}

/// An unsigned LEB128 number and its length.
pub(crate) fn uleb(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate().take(10) {
        v |= u64::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// The string sections a DWARF unit refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DebugStr {
    /// `.debug_str` / `__debug_str`.
    Str,
    /// `.debug_line_str`.
    LineStr,
    /// `.debug_str_offsets` (an index, resolved through the unit's base).
    Offsets,
}

/// Producer, name and language of the first compile unit in `.debug_info`.
/// `strings` reads the NUL-terminated string at an offset of a string
/// section; `offsets` reads an entry of `.debug_str_offsets` (4 or 8 bytes).
#[allow(clippy::too_many_lines)] // one form table, read in order
pub(crate) fn dwarf_unit(
    info: &[u8],
    abbrev: &[u8],
    e: Endian,
    strings: &mut dyn FnMut(DebugStr, u64) -> Option<String>,
    offsets: &mut dyn FnMut(u64, bool) -> Option<u64>,
) -> Option<Map<String, Value>> {
    enum V {
        Str(DebugStr, u64),
        Inline(String),
        Num(u64),
    }
    let len32 = e.u32(info, 0)?;
    let (wide, mut at) = if len32 == 0xffff_ffff { (true, 12) } else { (false, 4) };
    let osize = if wide { 8 } else { 4 };
    let version = e.u16(info, at)?;
    at += 2;
    let (abbrev_off, addr_size) = if version >= 5 {
        let unit_type = *info.get(at)?;
        if unit_type != 1 {
            return None;
        }
        let a = *info.get(at + 1)?;
        let off = e.word(info, at + 2, wide)?;
        at += 2 + osize;
        (off, a)
    } else if (2..=4).contains(&version) {
        let off = e.word(info, at, wide)?;
        let a = *info.get(at + osize)?;
        at += osize + 1;
        (off, a)
    } else {
        return None;
    };
    let (code, n) = uleb(info.get(at..)?)?;
    at += n;
    // Find the abbreviation.
    let mut ab = usize::try_from(abbrev_off).ok()?;
    let attrs = loop {
        let (c, n) = uleb(abbrev.get(ab..)?)?;
        if c == 0 {
            return None;
        }
        ab += n;
        let (_tag, n) = uleb(abbrev.get(ab..)?)?;
        ab += n + 1;
        let mut list = Vec::new();
        loop {
            let (name, n) = uleb(abbrev.get(ab..)?)?;
            ab += n;
            let (form, n) = uleb(abbrev.get(ab..)?)?;
            ab += n;
            if name == 0 && form == 0 {
                break;
            }
            if form == 0x21 {
                ab += uleb(abbrev.get(ab..)?)?.1;
            }
            list.push((name, form));
            if list.len() > 256 {
                return None;
            }
        }
        if c == code {
            break list;
        }
    };
    let mut values: Vec<(u64, V)> = Vec::new();
    for (name, mut form) in attrs {
        if form == 0x16 {
            let (f, n) = uleb(info.get(at..)?)?;
            at += n;
            form = f;
        }
        let fixed = |n: usize| -> Option<u64> {
            let b = info.get(at..at + n)?;
            Some(if e.le {
                b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
            } else {
                b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))
            })
        };
        let (value, used) = match form {
            0x01 => (V::Num(fixed(usize::from(addr_size))?), usize::from(addr_size)),
            0x0b | 0x11 | 0x0c | 0x29 => (V::Num(fixed(1)?), 1),
            0x05 | 0x12 | 0x2a => (V::Num(fixed(2)?), 2),
            0x2b => (V::Num(fixed(3)?), 3),
            0x06 | 0x13 | 0x1c | 0x2c => (V::Num(fixed(4)?), 4),
            // strx1 … strx4: indexes into the string offsets table.
            0x25..=0x28 => {
                let n = usize::try_from(form - 0x24).unwrap_or(1);
                (V::Str(DebugStr::Offsets, fixed(n)?), n)
            }
            0x07 | 0x14 | 0x20 | 0x24 => (V::Num(fixed(8)?), 8),
            0x1e => (V::Num(0), 16),
            0x0e => (V::Str(DebugStr::Str, fixed(osize)?), osize),
            0x1f => (V::Str(DebugStr::LineStr, fixed(osize)?), osize),
            0x10 if version == 2 => (V::Num(0), usize::from(addr_size)),
            0x10 | 0x17 | 0x1d => (V::Num(fixed(osize)?), osize),
            0x0d | 0x0f | 0x15 | 0x1b | 0x22 | 0x23 => {
                let (v, n) = uleb(info.get(at..)?)?;
                (V::Num(v), n)
            }
            0x1a => {
                let (v, n) = uleb(info.get(at..)?)?;
                (V::Str(DebugStr::Offsets, v), n)
            }
            0x08 => {
                let rest = info.get(at..)?;
                let end = rest.iter().position(|&b| b == 0)?;
                (V::Inline(String::from_utf8_lossy(&rest[..end]).into_owned()), end + 1)
            }
            0x03 => (V::Num(0), 2 + usize::try_from(fixed(2)?).ok()?),
            0x04 => (V::Num(0), 4 + usize::try_from(fixed(4)?).ok()?),
            0x0a => (V::Num(0), 1 + usize::try_from(fixed(1)?).ok()?),
            0x09 | 0x18 => {
                let (v, n) = uleb(info.get(at..)?)?;
                (V::Num(0), n + usize::try_from(v).ok()?)
            }
            0x19 | 0x21 => (V::Num(1), 0),
            _ => return None,
        };
        at = at.checked_add(used)?;
        values.push((name, value));
    }
    // DW_AT_str_offsets_base (DWARF 5), else just past the table header.
    let base = values
        .iter()
        .find_map(|(n, v)| match v {
            V::Num(b) if *n == 0x72 => Some(*b),
            _ => None,
        })
        .unwrap_or(if wide { 16 } else { 8 });
    let mut out = Map::new();
    out.insert("dwarf_version".into(), version.into());
    for (name, v) in values {
        let key = match name {
            0x25 => "producer",
            0x03 => "name",
            0x13 => "language",
            _ => continue,
        };
        let text = match v {
            V::Inline(s) => Some(s),
            V::Str(DebugStr::Offsets, i) => {
                offsets(base + i * osize as u64, wide).and_then(|o| strings(DebugStr::Str, o))
            }
            V::Str(kind, o) => strings(kind, o),
            V::Num(n) if key == "language" => dwarf_language(n).map(str::to_string),
            V::Num(_) => None,
        };
        if let Some(t) = text.filter(|t| !t.is_empty()) {
            out.insert(key.into(), redact_secrets(&t).into_owned().into());
        }
    }
    Some(out)
}

/// The first compile unit of the DWARF in a binary's `.debug_info`;
/// `find` gives the offset and size of a section by its ELF name.
pub(crate) fn dwarf_summary(
    src: &mut dyn Source,
    e: Endian,
    find: &dyn Fn(&str) -> Option<(u64, u64)>,
) -> Option<Map<String, Value>> {
    let (io, isz) = find(".debug_info")?;
    let (ao, asz) = find(".debug_abbrev")?;
    let info = src.read_vec(io, usize::try_from(isz.min(1 << 16)).ok()?).ok()?;
    let abbrev = src.read_vec(ao, usize::try_from(asz.min(1 << 16)).ok()?).ok()?;
    let str_sec = find(".debug_str");
    let line_sec = find(".debug_line_str");
    let off_sec = find(".debug_str_offsets");
    // Both readers use the source, one at a time.
    let src = std::cell::RefCell::new(src);
    let mut strings = |kind: DebugStr, off: u64| -> Option<String> {
        let (base, size) = match kind {
            DebugStr::LineStr => line_sec?,
            _ => str_sec?,
        };
        if off >= size {
            return None;
        }
        let b = src.borrow_mut().read_vec(base + off, usize::try_from((size - off).min(512)).ok()?).ok()?;
        Some(c_string(&b, 512))
    };
    let mut offsets = |at: u64, wide: bool| -> Option<u64> {
        let (base, size) = off_sec?;
        let n = if wide { 8 } else { 4 };
        if at + n > size {
            return None;
        }
        let b = src.borrow_mut().read_vec(base + at, usize::try_from(n).ok()?).ok()?;
        e.word(&b, 0, wide)
    };
    dwarf_unit(&info, &abbrev, e, &mut strings, &mut offsets)
}

fn dwarf_language(n: u64) -> Option<&'static str> {
    Some(match n {
        0x01 | 0x02 | 0x0c | 0x1d | 0x2c => "C",
        0x04 | 0x1a | 0x21 | 0x2a | 0x2b => "C++",
        0x07 | 0x08 | 0x0e | 0x22 | 0x23 => "Fortran",
        0x10 => "Objective-C",
        0x11 => "Objective-C++",
        0x13 => "D",
        0x16 => "Go",
        0x1c => "Rust",
        0x1e => "Swift",
        0x03 | 0x0d | 0x2e | 0x2f => "Ada",
        0x8001 => "assembly",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(entropy(&all), 8.0);
    }

    #[test]
    fn go_build_information() {
        let mut b = b"\xff Go buildinf:\x08\x02".to_vec();
        b.resize(32, 0);
        let version = b"go1.24.6";
        let modinfo = [
            &[0x30u8; 16][..],
            b"path\texample.org/saltmere/tides\nmod\texample.org/saltmere\tv1.2.0\th1:abc=\n",
            b"dep\tgolang.org/x/text\tv0.21.0\th1:def=\n",
            b"build\t-ldflags=-X main.token=hunter2\nbuild\tGOOS=linux\nbuild\tvcs.revision=0123abcd\n",
            &[0x31u8; 16][..],
        ]
        .concat();
        b.push(u8::try_from(version.len()).unwrap());
        b.extend_from_slice(version);
        let n = u16::try_from(modinfo.len()).unwrap();
        b.extend([u8::try_from(n & 0x7f).unwrap() | 0x80, u8::try_from(n >> 7).unwrap()]);
        b.extend_from_slice(&modinfo);
        let g = go_buildinfo(&b).unwrap();
        assert_eq!(g["version"], "go1.24.6");
        assert_eq!(g["path"], "example.org/saltmere/tides");
        assert_eq!(g["module_version"], "v1.2.0");
        assert_eq!(g["dependencies"], json!(["golang.org/x/text@v0.21.0"]));
        assert_eq!(g["build"], json!({"GOOS": "linux", "vcs.revision": "0123abcd"}));
        // Pointer format (Go 1.17 and older).
        let mut old = b"\xff Go buildinf:\x08\x00".to_vec();
        old.resize(32, 0);
        assert_eq!(go_buildinfo(&old).unwrap()["format"], "pointer");
    }

    #[test]
    fn overlays() {
        assert_eq!(overlay_kind(b"PK\x03\x04rest"), Some("zip"));
        assert_eq!(overlay_kind(b"MZ"), None);
        let mut nsis = vec![1, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde];
        nsis.extend(b"NullsoftInst");
        nsis.extend(0x1234u32.to_le_bytes());
        nsis.extend(0x5678u32.to_le_bytes());
        assert_eq!(overlay_kind(&nsis), Some("nsis"));
    }
}
