//! Files carried as text, and shell scripts that carry files. The decoded
//! payload is handed on as a child:
//!
//! * uuencode (`begin 644 name` … `end`) and its base64 form
//!   (`begin-base64` … `====`), one or more files per text;
//! * yEnc (`=ybegin` … `=yend`), with its size and CRC-32 checked;
//! * a bare base64 file (`.b64`);
//! * shell archives (`shar`): each member's name, size, mode and time, from
//!   the here-documents that hold them (`sed 's/^X//' << 'SHAR_EOF' > name`,
//!   uuencoded where binary);
//! * Makeself installers: the label, the startup script, the checksums and
//!   the compression, from the script's variables, and the payload that
//!   follows the script's first `skip` lines.
//!
//! Specifications: POSIX `uuencode`; yEnc 1.3 (Jürgen Helbing); GNU
//! sharutils 4.15; Makeself 2.5.

use super::{Entry, Inventory, Kind, child};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, latin1_or_utf8,
};

/// Extractor for uuencode, yEnc, base64, shar and Makeself files.
pub struct Encoded;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.encoded",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "uuencode",
            name: "uuencoded file",
            family: "archive",
            mimes: &["text/x-uuencode"],
            extensions: &["uue", "uu", "xxe"],
            magic: &[Magic::prefix(b"begin "), Magic::prefix(b"begin-base64 ")],
            parent: None,
        },
        FormatSpec {
            id: "yenc",
            name: "yEnc encoded file",
            family: "archive",
            mimes: &["text/x-yenc"],
            extensions: &["yenc", "ync"],
            magic: &[Magic::prefix(b"=ybegin ")],
            parent: None,
        },
        FormatSpec {
            id: "base64",
            name: "Base64 encoded file",
            family: "archive",
            mimes: &["application/base64"],
            extensions: &["b64", "base64"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "shar",
            name: "Shell archive (shar)",
            family: "archive",
            mimes: &["application/x-shar"],
            extensions: &["shar"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "makeself",
            name: "Makeself self-extracting archive",
            family: "archive",
            mimes: &["application/x-makeself"],
            extensions: &["run"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Members of a shar read.
const MAX_MEMBERS: usize = 4096;

impl Extractor for Encoded {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = &probe.head[..probe.head.len().min(4096)];
        let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
        if head.starts_with(b"#!") {
            if has(b"# This script was generated using Makeself") {
                return Some(Sniff { format: "makeself", confidence: 0.95 });
            }
            if has(b"# This is a shell archive") {
                return Some(Sniff { format: "shar", confidence: 0.95 });
            }
        }
        // uuencode and yEnc often follow mail or news headers.
        let starts_line = |needle: &[u8]| {
            head.starts_with(needle) || head.windows(needle.len() + 1).any(|w| w[0] == b'\n' && &w[1..] == needle)
        };
        if starts_line(b"=ybegin ") {
            return Some(Sniff { format: "yenc", confidence: 0.9 });
        }
        if lines(head).any(|l| uu_begin(l).is_some()) {
            return Some(Sniff { format: "uuencode", confidence: 0.85 });
        }
        if matches!(probe.extension, Some("b64" | "base64"))
            && !head.is_empty()
            && head.iter().all(|&b| b.is_ascii_alphanumeric() || b"+/=\r\n".contains(&b))
        {
            return Some(Sniff { format: "base64", confidence: 0.8 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let text = src.read_vec(0, usize::try_from(len.min(cx.parse_limit() as u64)).unwrap_or(0))?;
        let complete = text.len() as u64 == len;
        match cx.format_id() {
            "uuencode" => uuencode(cx, &text),
            "yenc" => yenc(cx, &text),
            "base64" => {
                let body = String::from_utf8_lossy(&text);
                let data =
                    super::super::audio::vorbis::base64(&body).ok_or_else(|| ExtractError::malformed("base64"))?;
                cx.format_set("decoded_bytes", data.len());
                child(cx, "decoded", data, complete).map(|_| ())
            }
            "shar" => shar(cx, &text),
            _ => makeself(src, cx, &text),
        }
    }
}

crate::register_extractor!(Encoded);

/// Lines without their line ending.
fn lines(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    b.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// `begin 644 name` (or `begin-base64 644 name`): (base64, mode, name).
fn uu_begin(line: &[u8]) -> Option<(bool, u32, String)> {
    let (b64, rest) = if let Some(r) = line.strip_prefix(b"begin-base64 ") {
        (true, r)
    } else {
        (false, line.strip_prefix(b"begin ")?)
    };
    let sp = rest.iter().position(|&c| c == b' ')?;
    let mode = std::str::from_utf8(&rest[..sp]).ok()?;
    if !(3..=4).contains(&mode.len()) {
        return None;
    }
    let mode = u32::from_str_radix(mode, 8).ok()?;
    let name = latin1_or_utf8(&rest[sp + 1..]);
    (!name.trim().is_empty()).then_some((b64, mode, name.trim().to_string()))
}

/// One uuencoded line: a length character, then 4 characters per 3 bytes.
fn uu_line(line: &[u8], out: &mut Vec<u8>) -> bool {
    let Some((&n, rest)) = line.split_first() else { return false };
    let n = usize::from(n.wrapping_sub(32) & 63);
    if n == 0 {
        return false;
    }
    let start = out.len();
    for g in rest.chunks(4) {
        let c = |i: usize| g.get(i).map_or(0, |&b| b.wrapping_sub(32) & 63);
        out.extend([(c(0) << 2) | (c(1) >> 4), (c(1) << 4) | (c(2) >> 2), (c(2) << 6) | c(3)]);
    }
    out.truncate(start + n.min(out.len() - start));
    true
}

fn uuencode(cx: &mut Context<'_>, text: &[u8]) -> Result<(), ExtractError> {
    let mut inv = Inventory::new();
    let mut members: Vec<(String, Vec<u8>, bool)> = Vec::new();
    let mut it = lines(text);
    while let Some(line) = it.next() {
        let Some((b64, mode, name)) = uu_begin(line) else { continue };
        let mut data = Vec::new();
        let mut ended = false;
        if b64 {
            let mut body = String::new();
            for l in it.by_ref() {
                if l == b"====" {
                    ended = true;
                    break;
                }
                body.push_str(&String::from_utf8_lossy(l));
            }
            data = super::super::audio::vorbis::base64(&body).ok_or_else(|| ExtractError::malformed("base64"))?;
        } else {
            for l in it.by_ref() {
                if l == b"end" {
                    ended = true;
                    break;
                }
                uu_line(l, &mut data);
            }
        }
        inv.push(Entry {
            path: name.clone(),
            kind: Kind::File,
            size: Some(data.len() as u64),
            mode: Some(mode & 0o7777),
            method: Some(if b64 { "base64" } else { "uuencode" }.into()),
            ..Entry::default()
        });
        members.push((name, data, ended));
    }
    if members.is_empty() {
        return Err(ExtractError::malformed("no uuencoded file"));
    }
    inv.report(cx, text.len() as u64);
    for (name, data, ended) in members {
        if !data.is_empty() && !child(cx, &name, data, ended)? {
            break;
        }
    }
    Ok(())
}

/// `key=value` pairs of a yEnc control line; `name` runs to the end.
fn y_params(line: &[u8]) -> Vec<(String, String)> {
    let s = latin1_or_utf8(line);
    let mut out = Vec::new();
    let mut rest = s.as_str();
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].rsplit(' ').next().unwrap_or("").to_string();
        let after = &rest[eq + 1..];
        if key == "name" {
            out.push((key, after.trim().to_string()));
            break;
        }
        let end = after.find(' ').unwrap_or(after.len());
        out.push((key, after[..end].to_string()));
        rest = &after[end..];
    }
    out
}

fn yenc(cx: &mut Context<'_>, text: &[u8]) -> Result<(), ExtractError> {
    let mut it = lines(text).skip_while(|l| !l.starts_with(b"=ybegin "));
    let begin = it.next().ok_or_else(|| ExtractError::malformed("=ybegin"))?;
    let params = y_params(&begin[8..]);
    let get = |k: &str| params.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    let name = get("name").unwrap_or_default();
    let declared: Option<u64> = get("size").and_then(|s| s.parse().ok());
    let (mut data, mut end) = (Vec::new(), None);
    for l in it {
        if l.starts_with(b"=ypart ") {
            continue;
        }
        if l.starts_with(b"=yend") {
            end = Some(y_params(&l[5..]));
            break;
        }
        let mut esc = false;
        for &c in l {
            if esc {
                data.push(c.wrapping_sub(64).wrapping_sub(42));
                esc = false;
            } else if c == b'=' {
                esc = true;
            } else {
                data.push(c.wrapping_sub(42));
            }
        }
    }
    cx.format_set("name", name.clone());
    if let Some(p) = get("part") {
        cx.format_set("part", p);
    }
    if let Some(t) = get("total") {
        cx.format_set("parts", t);
    }
    cx.format_set("decoded_bytes", data.len());
    if let Some(n) = declared {
        cx.format_set("declared_bytes", n);
    }
    let Some(end) = end else {
        cx.warn("no =yend line");
        return child(cx, &name, data, false).map(|_| ());
    };
    let crc =
        end.iter().find(|(k, _)| k == "crc32" || k == "pcrc32").and_then(|(_, v)| u32::from_str_radix(v, 16).ok());
    if let Some(crc) = crc {
        cx.format_set("crc32_ok", crc32(&data) == crc);
    }
    child(cx, &name, data, true).map(|_| ())
}

/// CRC-32 (IEEE), as yEnc declares it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// The quoted or bare word after `>` in a here-document command line.
fn redirect_target(line: &str) -> Option<String> {
    let after = line[line.rfind('>')? + 1..].trim().trim_end_matches("&&").trim();
    let name = after.trim_matches(['\'', '"']);
    (!name.is_empty() && !name.contains(' ')).then(|| name.to_string())
}

/// The delimiter of a here-document (`<< 'SHAR_EOF'`, `<< \SHAR_EOF`, `<<EOF`).
fn heredoc(line: &str) -> Option<String> {
    let after = line[line.find("<<")? + 2..].trim_start().trim_start_matches('-');
    let word = after.split_whitespace().next()?;
    let word = word.trim_start_matches('\\').trim_matches(['\'', '"']);
    (!word.is_empty()).then(|| word.to_string())
}

#[allow(clippy::too_many_lines)] // one pass over the script
fn shar(cx: &mut Context<'_>, text: &[u8]) -> Result<(), ExtractError> {
    let body = String::from_utf8_lossy(text);
    let mut all = body.lines();
    let mut inv = Inventory::new();
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    while let Some(line) = all.next() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("# This is a shell archive (produced by ") {
            cx.format_set("generator", v.trim_end_matches(").").trim_end_matches(')'));
        } else if let Some(d) = t.strip_prefix("# Made on ") {
            // `2025-09-01 12:00 UTC by <user@host>.`: the date only.
            let date = d.split(" by ").next().unwrap_or(d).trim_end_matches('.');
            cx.format_set("created", date);
        } else if t.starts_with("MD5SUM=") {
            cx.format_set("md5_checked", true);
        } else if let Some(rest) = t.strip_prefix("(set ") {
            // `(set 20 25 09 01 12 00 00 'name'`: the member's time.
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 8 {
                let name = parts[7..].join(" ").trim_matches(['\'', '"']).to_string();
                let stamp = format!(
                    "{}{}-{}-{}T{}:{}:{}",
                    parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                );
                if let Some(e) = entries.iter_mut().rev().find(|e| e.path == name) {
                    e.modified = Some(stamp);
                }
            }
        } else if let Some(rest) = t.strip_prefix("chmod ") {
            let mut w = rest.split_whitespace();
            if let (Some(mode), Some(name)) = (w.next(), w.next()) {
                let name = name.trim_matches(['\'', '"']);
                if let (Ok(m), Some(e)) =
                    (u32::from_str_radix(mode, 8), entries.iter_mut().rev().find(|e| e.path == name))
                {
                    e.mode = Some(m & 0o7777);
                }
            }
        } else if (t.starts_with("sed ") || t.starts_with("cat ") || t.contains("uudecode"))
            && t.contains("<<")
            && members.len() < MAX_MEMBERS
        {
            let Some(delim) = heredoc(t) else { continue };
            let uu = t.contains("uudecode");
            // `uudecode -o name` names the file; otherwise the redirect does.
            let target = if uu {
                t.split_whitespace().skip_while(|w| *w != "-o").nth(1).map(|n| n.trim_matches(['\'', '"']).to_string())
            } else {
                redirect_target(t)
            };
            let strip_x = t.contains("s/^X//");
            let mut data = Vec::new();
            for l in all.by_ref() {
                if l == delim {
                    break;
                }
                let l = if strip_x { l.strip_prefix('X').unwrap_or(l) } else { l };
                data.extend_from_slice(l.as_bytes());
                data.push(b'\n');
            }
            let (name, data) = if uu {
                let mut name = target;
                let mut decoded = Vec::new();
                let mut inner = lines(&data);
                for l in inner.by_ref() {
                    if let Some((_, _, n)) = uu_begin(l) {
                        name = name.or(Some(n));
                        break;
                    }
                }
                for l in inner {
                    if l == b"end" {
                        break;
                    }
                    uu_line(l, &mut decoded);
                }
                (name, decoded)
            } else {
                (target, data)
            };
            let Some(name) = name else { continue };
            entries.push(Entry {
                path: name.clone(),
                kind: Kind::File,
                size: Some(data.len() as u64),
                method: Some(if uu { "uuencode" } else { "text" }.into()),
                ..Entry::default()
            });
            members.push((name, data));
        }
    }
    for e in entries {
        inv.push(e);
    }
    inv.report(cx, text.len() as u64);
    for (name, data) in members {
        if !data.is_empty() && !child(cx, &name, data, true)? {
            break;
        }
    }
    Ok(())
}

/// `name="value"` (or `name=value`) of a shell script line.
fn shell_var<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let v = line.strip_prefix(name)?.strip_prefix('=')?;
    Some(v.trim().trim_matches('"'))
}

fn makeself(src: &mut dyn Source, cx: &mut Context<'_>, text: &[u8]) -> Result<(), ExtractError> {
    let len = src.len();
    // The script is text; the payload after it is not.
    let script_end = text.iter().position(|&b| b == 0).unwrap_or(text.len()).min(256 * 1024);
    let script = String::from_utf8_lossy(&text[..script_end]);
    let (mut skip, mut sizes) = (None, Vec::new());
    for line in script.lines().take(4096) {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("# This script was generated using Makeself ") {
            cx.format_set("makeself_version", v.trim());
        } else if let Some(v) = shell_var(t, "label") {
            cx.format_set("label", v);
            cx.content().title(v);
        } else if let Some(v) = shell_var(t, "script") {
            if !v.is_empty() {
                cx.format_set("startup_script", v);
            }
        } else if let Some(v) = shell_var(t, "targetdir") {
            // A shell expression (`${2:-.}`) is decided when it runs.
            if !v.contains('$') {
                cx.format_set("target_directory", v);
            }
        } else if let Some(v) = shell_var(t, "filesizes") {
            sizes = v.split_whitespace().filter_map(|n| n.parse::<u64>().ok()).collect();
        } else if let Some(v) = shell_var(t, "totalsize") {
            if let Ok(n) = v.parse::<u64>() {
                cx.format_set("payload_bytes", n);
            }
        } else if let Some(v) = shell_var(t, "skip") {
            skip = v.parse::<usize>().ok();
        } else if let Some(v) = shell_var(t, "MD5") {
            if v.bytes().any(|b| b != b'0') {
                cx.format_set("md5", v);
            }
        } else if let Some(v) = shell_var(t, "SHA") {
            if v.bytes().any(|b| b != b'0') {
                cx.format_set("sha256", v);
            }
        } else if let Some(v) = shell_var(t, "CRCsum") {
            if v != "0000000000" && !v.is_empty() {
                cx.format_set("crc", v);
            }
        } else if let Some(v) = t.strip_prefix("echo COMPRESS=") {
            cx.format_set("compression", v);
        } else if let Some(v) = shell_var(t, "decrypt_cmd")
            && !v.is_empty()
        {
            cx.security().encrypted(true);
        }
    }
    // The payload starts after the first `skip` lines of the file.
    let Some(skip) = skip else { return Ok(()) };
    let offset = text.split_inclusive(|&b| b == b'\n').take(skip).map(<[u8]>::len).sum::<usize>() as u64;
    let size = sizes.first().copied().unwrap_or(len.saturating_sub(offset));
    cx.format_set("payload_offset", offset);
    if offset < len && size > 0 && cx.child_room() > 0 {
        let n = size.min(len - offset).min(cx.parse_limit() as u64);
        let data = src.read_vec(offset, usize::try_from(n).unwrap_or(0))?;
        child(cx, "payload", data, n == size)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("uuencode", "yenc", "base64", "shar", "makeself");

    #[test]
    fn uu_lines() {
        let mut out = Vec::new();
        assert!(uu_line(b"#0V%T", &mut out));
        assert_eq!(out, b"Cat");
        assert!(!uu_line(b"`", &mut out));
        assert_eq!(uu_begin(b"begin 644 notes.txt"), Some((false, 0o644, "notes.txt".into())));
        assert_eq!(uu_begin(b"begin-base64 600 a b.bin"), Some((true, 0o600, "a b.bin".into())));
        assert_eq!(uu_begin(b"begin the day"), None);
    }

    #[test]
    fn yenc_params_and_crc() {
        let p = y_params(b"line=128 size=3 name=x y.txt");
        assert_eq!(p[2], ("name".into(), "x y.txt".into()));
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn heredocs() {
        assert_eq!(heredoc("sed 's/^X//' << 'SHAR_EOF' > 'notes.txt' &&").as_deref(), Some("SHAR_EOF"));
        assert_eq!(heredoc("cat <<-\\EOF").as_deref(), Some("EOF"));
        assert_eq!(redirect_target("sed 's/^X//' << 'SHAR_EOF' > 'notes.txt' &&").as_deref(), Some("notes.txt"));
    }
}
