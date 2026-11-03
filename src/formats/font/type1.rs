//! PostScript Type 1 fonts and their metrics:
//! * PFB (binary segments) and PFA (hex): the font dictionary (name, full
//!   and family names, weight, version, notice, copyright, italic angle,
//!   fixed pitch, bounding box, encoding) and, from the decrypted `eexec`
//!   part, the glyph and subroutine counts;
//! * AFM: the global metrics (names, weight, version, notice, character
//!   set, encoding, heights) and the character, kerning and composite
//!   counts;
//! * PFM: the Windows printer-font header (face, PostScript name,
//!   copyright, weight, italic, character set, point size).
//!
//! Specifications: Adobe "Type 1 Font Format" (1990) §7 (`eexec`
//! encryption); Adobe Technical Note #5004 (AFM 4.1); Adobe Technical Note
//! #5178 (PFM).

use super::bitmap::win_header;
use super::{le16, le32};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for Type 1 fonts and metrics.
pub struct Type1;

static META: ExtractorMeta = ExtractorMeta {
    id: "font.type1",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pfb",
            name: "PostScript Type 1 font (binary)",
            family: "font",
            mimes: &["application/x-font-type1"],
            extensions: &["pfb"],
            magic: &[Magic::at(0, b"\x80\x01")],
            parent: None,
        },
        FormatSpec {
            id: "pfa",
            name: "PostScript Type 1 font (ASCII)",
            family: "font",
            mimes: &["application/x-font-type1"],
            extensions: &["pfa", "t1"],
            magic: &[Magic::at(0, b"%!PS-AdobeFont-"), Magic::at(0, b"%!FontType1")],
            parent: None,
        },
        FormatSpec {
            id: "afm",
            name: "Adobe font metrics",
            family: "font",
            mimes: &["application/x-font-afm"],
            extensions: &["afm", "amfm", "acfm"],
            magic: &[
                Magic::at(0, b"StartFontMetrics"),
                Magic::at(0, b"StartMasterFontMetrics"),
                Magic::at(0, b"StartCompFontMetrics"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "pfm",
            name: "Printer font metrics",
            family: "font",
            mimes: &[],
            extensions: &["pfm"],
            magic: &[],
            parent: None,
        },
    ],
};

/// The `eexec` decryption (r = 55665), without the four lead bytes.
fn eexec(cipher: &[u8]) -> Vec<u8> {
    let mut r: u16 = 55665;
    let mut out = Vec::with_capacity(cipher.len());
    for &c in cipher {
        out.push(c ^ (r >> 8).to_le_bytes()[0]);
        r = u16::from(c).wrapping_add(r).wrapping_mul(52845).wrapping_add(22719);
    }
    out.drain(..out.len().min(4));
    out
}

/// Hex digits to bytes (whitespace skipped; stops at the first non-hex).
fn unhex(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut hi: Option<u8> = None;
    for &c in text {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => break,
        };
        match hi.take() {
            Some(h) => out.push(h << 4 | v),
            None => hi = Some(v),
        }
    }
    out
}

/// A PostScript string `(…)` or name `/…` after `/key` in the cleartext.
fn ps_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("/{key}");
    let mut from = 0;
    while let Some(i) = text[from..].find(&needle) {
        let start = from + i + needle.len();
        from = start;
        // A longer key with the same prefix (`/FontName` vs `/FontNameX`).
        if text[start..].starts_with(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let rest = text[start..].trim_start();
        if let Some(s) = rest.strip_prefix('(') {
            let mut depth = 1;
            let mut out = String::new();
            let mut esc = false;
            for c in s.chars() {
                match c {
                    _ if esc => {
                        out.push(c);
                        esc = false;
                    }
                    '\\' => esc = true,
                    '(' => {
                        depth += 1;
                        out.push(c);
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        out.push(c);
                    }
                    _ => out.push(c),
                }
                if out.len() > 2000 {
                    break;
                }
            }
            return Some(out);
        }
        let token: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != '/' && *c != '{').collect();
        if let Some(name) = rest.strip_prefix('/') {
            return Some(name.chars().take_while(|c| !c.is_whitespace() && *c != '/').collect());
        }
        if rest.starts_with('{') || rest.starts_with('[') {
            let close = if rest.starts_with('{') { '}' } else { ']' };
            return rest.find(close).map(|j| rest[1..j].trim().to_string());
        }
        return Some(token);
    }
    None
}

/// The cleartext and the decrypted private part of a PFB or PFA.
fn split(cx: &mut Context<'_>, b: &[u8], binary: bool) -> (String, Vec<u8>) {
    if binary {
        let (mut clear, mut cipher) = (Vec::new(), Vec::new());
        let mut at = 0;
        while b.get(at) == Some(&0x80) {
            let kind = b.get(at + 1).copied().unwrap_or(3);
            if kind == 3 {
                break;
            }
            let Some(len) = le32(b, at + 2).and_then(|n| usize::try_from(n).ok()) else { break };
            let body = b.get(at + 6..(at + 6).saturating_add(len).min(b.len())).unwrap_or_default();
            match kind {
                1 if cipher.is_empty() => clear.extend_from_slice(body),
                2 => cipher.extend_from_slice(body),
                _ => {}
            }
            at = at + 6 + len;
        }
        cx.format_set("segments", if cipher.is_empty() { "cleartext only" } else { "cleartext, binary eexec" });
        return (String::from_utf8_lossy(&clear).into_owned(), eexec(&cipher));
    }
    let marker = b.windows(17).position(|w| w == b"currentfile eexec").map(|i| {
        let after = i + 17;
        after + b[after..].iter().take_while(|c| c.is_ascii_whitespace()).count()
    });
    match marker {
        Some(i) => {
            let clear = String::from_utf8_lossy(&b[..i]).into_owned();
            let rest = &b[i..];
            let hexed = rest.iter().take(64).filter(|c| !c.is_ascii_whitespace()).all(u8::is_ascii_hexdigit);
            let cipher = if hexed { unhex(rest) } else { rest.to_vec() };
            (clear, eexec(&cipher))
        }
        _ => (String::from_utf8_lossy(b).into_owned(), Vec::new()),
    }
}

/// A count after `/key` in the private part (`/CharStrings 312 dict`).
fn private_count(plain: &[u8], key: &[u8]) -> Option<u64> {
    let i = plain.windows(key.len()).position(|w| w == key)? + key.len();
    let digits: Vec<u8> =
        plain[i..].iter().skip_while(|c| c.is_ascii_whitespace()).take_while(|c| c.is_ascii_digit()).copied().collect();
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

fn type1(cx: &mut Context<'_>, b: &[u8], binary: bool) {
    let (clear, plain) = split(cx, b, binary);
    if let Some(first) = clear.lines().next().filter(|l| l.starts_with("%!")) {
        cx.format_set("header", truncate_chars(first.trim(), 200));
    }
    if let Some(d) = clear.lines().find_map(|l| l.strip_prefix("%%CreationDate:")) {
        cx.format_set("creation_date", truncate_chars(d.trim(), 100));
    }
    for (key, out) in [
        ("FontName", "postscript_name"),
        ("FullName", "full_name"),
        ("FamilyName", "family"),
        ("Weight", "weight"),
        ("version", "version"),
        ("Notice", "notice"),
        ("Copyright", "copyright"),
        ("ItalicAngle", "italic_angle"),
        ("isFixedPitch", "monospace"),
        ("FontType", "font_type"),
        ("UniqueID", "unique_id"),
        ("FontBBox", "bounding_box"),
        ("Encoding", "encoding"),
    ] {
        let Some(v) = ps_value(&clear, key) else { continue };
        let v = v.trim().to_string();
        match out {
            "italic_angle" => {
                if let Ok(a) = v.parse::<f64>() {
                    cx.format_set(out, a);
                }
            }
            "monospace" => cx.format_set(out, v == "true"),
            "font_type" | "unique_id" => {
                if let Ok(n) = v.parse::<i64>() {
                    cx.format_set(out, n);
                }
            }
            "encoding" => cx.format_set(out, if v.chars().all(char::is_alphanumeric) { v } else { "custom".into() }),
            _ => cx.format_set(out, truncate_chars(&v, 500)),
        }
    }
    if let Some(full) = ps_value(&clear, "FullName").or_else(|| ps_value(&clear, "FontName")) {
        cx.content().source("type1.FullName").title(truncate_chars(&full, 200));
    }
    if let Some(c) = ps_value(&clear, "Copyright").or_else(|| ps_value(&clear, "Notice")) {
        cx.rights().source("type1.Copyright").copyright(truncate_chars(&c, 500));
    }
    if !plain.is_empty() {
        cx.format_set("eexec_decrypted", plain.windows(8).any(|w| w == b"/Private"));
        if let Some(n) = private_count(&plain, b"/CharStrings") {
            cx.format_set("glyph_count", n);
        }
        if let Some(n) = private_count(&plain, b"/Subrs") {
            cx.format_set("subroutines", n);
        }
    }
}

fn afm(cx: &mut Context<'_>, text: &str) {
    let mut comments = Vec::new();
    for line in text.lines().take(200_000) {
        let (key, value) = line.trim().split_once(char::is_whitespace).unwrap_or((line.trim(), ""));
        let value = value.trim();
        let out = match key {
            "StartFontMetrics" | "StartMasterFontMetrics" | "StartCompFontMetrics" => "afm_version",
            "FontName" => "postscript_name",
            "FullName" => "full_name",
            "FamilyName" => "family",
            "Weight" => "weight",
            "Version" => "version",
            "Notice" => "notice",
            "EncodingScheme" => "encoding",
            "CharacterSet" => "character_set",
            "ItalicAngle" => "italic_angle",
            "IsFixedPitch" => "monospace",
            "CapHeight" => "cap_height",
            "XHeight" => "x_height",
            "Ascender" => "ascender",
            "Descender" => "descender",
            "FontBBox" => "bounding_box",
            "StartCharMetrics" => "glyph_count",
            "StartKernPairs" | "StartKernPairs0" => "kern_pairs",
            "StartComposites" => "composites",
            "StartTrackKern" => "track_kerns",
            "Comment" => {
                if comments.len() < 10 {
                    comments.push(truncate_chars(value, 200));
                }
                continue;
            }
            "EndFontMetrics" => break,
            _ => continue,
        };
        match out {
            "italic_angle" | "cap_height" | "x_height" | "ascender" | "descender" => {
                if let Ok(v) = value.parse::<f64>() {
                    cx.format_set(out, v);
                }
            }
            "glyph_count" | "kern_pairs" | "composites" | "track_kerns" => {
                if let Ok(v) = value.parse::<u64>() {
                    cx.format_set(out, v);
                }
            }
            "monospace" => cx.format_set(out, value == "true"),
            _ => cx.format_set(out, truncate_chars(value, 500)),
        }
    }
    if !comments.is_empty() {
        cx.format_set("comments", comments);
    }
    let full = text
        .lines()
        .find_map(|l| l.strip_prefix("FullName "))
        .or_else(|| text.lines().find_map(|l| l.strip_prefix("FontName ")));
    if let Some(f) = full {
        cx.content().source("afm.FullName").title(truncate_chars(f.trim(), 200));
    }
    if let Some(n) = text.lines().find_map(|l| l.strip_prefix("Notice ")) {
        cx.rights().source("afm.Notice").copyright(truncate_chars(n.trim(), 500));
    }
}

/// A NUL-terminated string at `at`.
pub(crate) fn cstr(b: &[u8], at: usize, max: usize) -> Option<String> {
    let s = b.get(at..)?;
    let end = s.iter().take(max).position(|&c| c == 0).unwrap_or(s.len().min(max));
    let v = String::from_utf8_lossy(&s[..end]).trim().to_string();
    (!v.is_empty()).then_some(v)
}

impl Extractor for Type1 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // PFM: version 1.0, the declared size, the PostScript device.
        let version = h.get(0..2) == Some(&[0, 1]);
        let size = le32(h, 2).map(u64::from) == Some(probe.len);
        let device = le32(h, 101).and_then(|o| usize::try_from(o).ok()).and_then(|o| cstr(h, o, 32));
        if version && size && device.is_some_and(|d| d.eq_ignore_ascii_case("postscript")) {
            return Some(Sniff { format: "pfm", confidence: 0.95 });
        }
        (probe.extension == Some("pfa") && h.starts_with(b"%!")).then_some(Sniff { format: "pfa", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        match cx.format_id() {
            "pfb" => type1(cx, &b, true),
            "pfa" => type1(cx, &b, false),
            "afm" => afm(cx, &String::from_utf8_lossy(&b)),
            _ => {
                win_header(cx, &b).ok_or_else(|| ExtractError::malformed("PFM header"))?;
                // The PostScript name, from the driver-info offset.
                if let Some(n) = le32(&b, 139).and_then(|o| usize::try_from(o).ok()).and_then(|o| cstr(&b, o, 256)) {
                    cx.format_set("postscript_name", truncate_chars(&n, 200));
                }
                if let Some(n) = le16(&b, 117) {
                    cx.format_set("extension_size", n);
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Type1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eexec_round_trip() {
        // Encrypt "1234/CharStrings 3 dict" and decrypt it back.
        let plain = b"1234/CharStrings 3 dict";
        let mut r: u16 = 55665;
        let cipher: Vec<u8> = plain
            .iter()
            .map(|&p| {
                let c = p ^ (r >> 8).to_le_bytes()[0];
                r = u16::from(c).wrapping_add(r).wrapping_mul(52845).wrapping_add(22719);
                c
            })
            .collect();
        let out = eexec(&cipher);
        assert_eq!(out, b"/CharStrings 3 dict");
        assert_eq!(private_count(&out, b"/CharStrings"), Some(3));
        assert_eq!(unhex(b"4a 6b\n7C"), vec![0x4a, 0x6b, 0x7c]);
    }

    #[test]
    fn postscript_values() {
        let t = "/FullName (Tide \\(Bold\\)) readonly def /FontNameX /No def /FontName /Tide-Bold def /FontBBox {0 -200 900 800} def";
        assert_eq!(ps_value(t, "FullName").as_deref(), Some("Tide (Bold)"));
        assert_eq!(ps_value(t, "FontName").as_deref(), Some("Tide-Bold"));
        assert_eq!(ps_value(t, "FontBBox").as_deref(), Some("0 -200 900 800"));
    }

    crate::fixture_tests!("pfb", "pfa", "afm", "pfm");
}
