//! OpenType / TrueType fonts and their containers: collections (`.ttc`,
//! `.otc`), WOFF 1 and 2, Embedded OpenType (`.eot`) and Mac `dfont`
//! resource files. Each is decoded into its sfnt tables and described the
//! same way (see the module root); collections and resource files also
//! list their members.
//!
//! Specifications: OpenType 1.9.1 ("Font Collections"); W3C WOFF 1.0 and
//! WOFF 2.0; W3C Embedded OpenType submission (2008); Apple "Inside
//! Macintosh: More Macintosh Toolbox" (resource file format).

use std::borrow::Cow;

use serde_json::Value;

use super::{Font, be16, be32, describe, le16, le32, member, utf16};
use crate::plugin::{
    Codec, Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for sfnt fonts and their containers.
pub struct Sfnt;

static META: ExtractorMeta = ExtractorMeta {
    id: "font.sfnt",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ttf",
            name: "TrueType font",
            family: "font",
            mimes: &["font/ttf", "application/x-font-ttf"],
            extensions: &["ttf"],
            // The fifth byte is the high byte of the table count (< 256):
            // it keeps Access databases (`00 01 00 00 Standard Jet DB`) out.
            magic: &[Magic::at(0, b"\x00\x01\x00\x00\x00"), Magic::at(0, b"true")],
            parent: None,
        },
        FormatSpec {
            id: "otf",
            name: "OpenType font",
            family: "font",
            mimes: &["font/otf"],
            extensions: &["otf"],
            magic: &[Magic::at(0, b"OTTO")],
            parent: None,
        },
        FormatSpec {
            id: "ttc",
            name: "TrueType / OpenType collection",
            family: "font",
            mimes: &["font/collection"],
            extensions: &["ttc", "otc"],
            magic: &[Magic::at(0, b"ttcf")],
            parent: None,
        },
        FormatSpec {
            id: "woff",
            name: "WOFF web font",
            family: "font",
            mimes: &["font/woff"],
            extensions: &["woff"],
            magic: &[Magic::at(0, b"wOFF")],
            parent: None,
        },
        FormatSpec {
            id: "woff2",
            name: "WOFF2 web font",
            family: "font",
            mimes: &["font/woff2"],
            extensions: &["woff2"],
            magic: &[Magic::at(0, b"wOF2")],
            parent: None,
        },
        FormatSpec {
            id: "eot",
            name: "EOT embedded OpenType",
            family: "font",
            mimes: &["application/vnd.ms-fontobject"],
            extensions: &["eot"],
            magic: &[Magic::at(34, b"LP")],
            parent: None,
        },
        FormatSpec {
            id: "dfont",
            name: "Apple dfont / suitcase",
            family: "font",
            mimes: &[],
            extensions: &["dfont", "suit"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Members of a collection described.
const MAX_MEMBERS: usize = 256;
/// Tables loaded when a font is read through the source.
const WANTED: [&[u8; 4]; 14] = [
    b"name", b"head", b"maxp", b"OS/2", b"post", b"cmap", b"fvar", b"COLR", b"CPAL", b"GSUB", b"GPOS", b"DSIG",
    b"hhea", b"STAT",
];
/// Bytes read from the layout tables (the lists sit near the start).
const MAX_LAYOUT: usize = 2 << 20;

/// Read an sfnt directory at `at` and the tables the report needs through
/// the source (fonts can be far larger than the parse limit).
fn read_font(src: &mut dyn Source, at: u64, cap: usize) -> Option<Font<'static>> {
    let head = src.read_vec(at, 12).ok()?;
    let n = usize::from(be16(&head, 4)?);
    if n == 0 || n > 1000 {
        return None;
    }
    let dir = src.read_vec(at + 12, 16 * n).ok()?;
    let mut buf = head.clone();
    buf.extend_from_slice(&dir);
    // The directory alone, offsets ignored: tables are filled in below.
    let shell = Font::parse(&buf, 0)?;
    let mut tables = Vec::with_capacity(n);
    for (i, (t, _)) in shell.tables.iter().enumerate() {
        let r = 16 * i;
        let data = if WANTED.contains(&t) {
            let off = u64::from(be32(&dir, r + 8)?);
            let len = usize::try_from(be32(&dir, r + 12)?).ok()?;
            let max = if t == b"GSUB" || t == b"GPOS" { MAX_LAYOUT.min(cap) } else { cap };
            src.read_vec(off, len.min(max)).unwrap_or_default()
        } else {
            Vec::new()
        };
        tables.push((*t, Cow::Owned(data)));
    }
    Some(Font { version: shell.version, tables })
}

/// WOFF 2.0 known-table tags, by index.
const WOFF2_TAGS: [&[u8; 4]; 63] = [
    b"cmap", b"head", b"hhea", b"hmtx", b"maxp", b"name", b"OS/2", b"post", b"cvt ", b"fpgm", b"glyf", b"loca",
    b"prep", b"CFF ", b"VORG", b"EBDT", b"EBLC", b"gasp", b"hdmx", b"kern", b"LTSH", b"PCLT", b"VDMX", b"vhea",
    b"vmtx", b"BASE", b"GDEF", b"GPOS", b"GSUB", b"EBSC", b"JSTF", b"MATH", b"CBDT", b"CBLC", b"COLR", b"CPAL",
    b"SVG ", b"sbix", b"acnt", b"avar", b"bdat", b"bloc", b"bsln", b"cvar", b"fdsc", b"feat", b"fmtx", b"fvar",
    b"gvar", b"hsty", b"just", b"lcar", b"mort", b"morx", b"opbd", b"prop", b"trak", b"Zapf", b"Silf", b"Glat",
    b"Gloc", b"Feat", b"Sill",
];

fn base128(b: &[u8], at: &mut usize) -> Option<u32> {
    let mut v = 0u32;
    for i in 0..5 {
        let x = *b.get(*at)?;
        *at += 1;
        if i == 0 && x == 0x80 {
            return None;
        }
        v = v.checked_mul(128)? | u32::from(x & 0x7f);
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn uint255(b: &[u8], at: &mut usize) -> Option<u16> {
    let c = *b.get(*at)?;
    *at += 1;
    Some(match c {
        253 => {
            let v = be16(b, *at)?;
            *at += 2;
            v
        }
        255 | 254 => {
            let x = u16::from(*b.get(*at)?);
            *at += 1;
            x + if c == 255 { 253 } else { 506 }
        }
        _ => u16::from(c),
    })
}

/// A WOFF2 file: its fonts (one, or the members of a collection).
fn woff2(cx: &mut Context<'_>, b: &[u8]) -> Result<Vec<Font<'static>>, ExtractError> {
    let bad = || ExtractError::malformed("WOFF2 header");
    let flavor = be32(b, 4).ok_or_else(bad)?;
    let n = usize::from(be16(b, 12).ok_or_else(bad)?);
    let total_sfnt = usize::try_from(be32(b, 16).ok_or_else(bad)?).map_err(|_| bad())?;
    let compressed = usize::try_from(be32(b, 20).ok_or_else(bad)?).map_err(|_| bad())?;
    metadata_block(cx, b, 28, Codec::Brotli);
    let mut at = 48;
    // (tag, stored length, transformed)
    let mut dir = Vec::with_capacity(n.min(1000));
    for _ in 0..n.min(1000) {
        let flags = *b.get(at).ok_or_else(bad)?;
        at += 1;
        let t: [u8; 4] = if flags & 0x3f == 63 {
            let t = b.get(at..at + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
            at += 4;
            t
        } else {
            *WOFF2_TAGS[usize::from(flags & 0x3f)]
        };
        let orig = base128(b, &mut at).ok_or_else(bad)?;
        let version = flags >> 6;
        let glyph_data = &t == b"glyf" || &t == b"loca";
        let transformed = if glyph_data { version != 3 } else { version != 0 };
        let len = if transformed { base128(b, &mut at).ok_or_else(bad)? } else { orig };
        dir.push((t, usize::try_from(len).map_err(|_| bad())?, transformed));
    }
    // Collections list each member's tables by index.
    let mut members: Vec<(u32, Vec<usize>)> = Vec::new();
    if flavor == 0x7474_6366 {
        at += 4;
        let fonts = uint255(b, &mut at).ok_or_else(bad)?;
        for _ in 0..fonts.min(256) {
            let k = uint255(b, &mut at).ok_or_else(bad)?;
            let fl = be32(b, at).ok_or_else(bad)?;
            at += 4;
            let idx =
                (0..k).map(|_| uint255(b, &mut at).map(usize::from)).collect::<Option<Vec<_>>>().ok_or_else(bad)?;
            members.push((fl, idx));
        }
    } else {
        members.push((flavor, (0..dir.len()).collect()));
    }
    let data = b.get(at..at.saturating_add(compressed).min(b.len())).ok_or_else(bad)?;
    let room = total_sfnt.max(dir.iter().map(|d| d.1).sum()).min(cx.parse_limit().max(1 << 20));
    let out = cx.decompress(data, Codec::Brotli, room)?;
    if !matches!(out.end, crate::plugin::End::Complete) {
        cx.warn("WOFF2 data did not decompress completely");
    }
    let mut offsets = Vec::with_capacity(dir.len());
    let mut off = 0usize;
    for &(_, len, _) in &dir {
        offsets.push(off);
        off = off.saturating_add(len);
    }
    let fonts = members
        .into_iter()
        .map(|(version, idx)| {
            let tables = idx
                .into_iter()
                .filter_map(|i| {
                    let (t, len, transformed) = *dir.get(i)?;
                    let body = if transformed {
                        Vec::new()
                    } else {
                        out.data.get(offsets[i]..offsets[i].saturating_add(len)).unwrap_or_default().to_vec()
                    };
                    Some((t, Cow::Owned(body)))
                })
                .collect();
            Font { version, tables }
        })
        .collect();
    Ok(fonts)
}

/// A WOFF 1.0 file.
fn woff(cx: &mut Context<'_>, b: &[u8]) -> Result<Font<'static>, ExtractError> {
    let bad = || ExtractError::malformed("WOFF header");
    let version = be32(b, 4).ok_or_else(bad)?;
    let n = usize::from(be16(b, 12).ok_or_else(bad)?);
    metadata_block(cx, b, 24, Codec::Zlib);
    let mut tables = Vec::with_capacity(n.min(1000));
    for i in 0..n.min(1000) {
        let r = 44 + 20 * i;
        let t: [u8; 4] = b.get(r..r + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let off = usize::try_from(be32(b, r + 4).ok_or_else(bad)?).map_err(|_| bad())?;
        let comp = usize::try_from(be32(b, r + 8).ok_or_else(bad)?).map_err(|_| bad())?;
        let orig = usize::try_from(be32(b, r + 12).ok_or_else(bad)?).map_err(|_| bad())?;
        let stored = off.checked_add(comp).and_then(|e| b.get(off..e)).unwrap_or_default();
        let body = if comp < orig && super::sfnt::WANTED.contains(&&t) {
            cx.inflate_prefix(stored, Compression::Zlib, orig.min(cx.parse_limit())).unwrap_or_default()
        } else if comp < orig {
            Vec::new()
        } else {
            stored.to_vec()
        };
        tables.push((t, Cow::Owned(body)));
    }
    Ok(Font { version, tables })
}

/// The extended metadata block of a WOFF file (XML): vendor, licence.
fn metadata_block(cx: &mut Context<'_>, b: &[u8], at: usize, codec: Codec) {
    let (Some(off), Some(len), Some(orig)) = (be32(b, at), be32(b, at + 4), be32(b, at + 8)) else { return };
    let (Ok(off), Ok(len), Ok(orig)) = (usize::try_from(off), usize::try_from(len), usize::try_from(orig)) else {
        return;
    };
    if off == 0 || len == 0 {
        return;
    }
    let Some(raw) = off.checked_add(len).and_then(|e| b.get(off..e)) else { return };
    let Ok(xml) = cx.decompress(raw, codec, orig.min(1 << 20)) else { return };
    let text = String::from_utf8_lossy(&xml.data);
    cx.format_set("woff_metadata", true);
    let attr = |el: &str, name: &str| {
        let i = text.find(&format!("<{el}"))?;
        let rest = &text[i..text[i..].find('>').map_or(text.len(), |j| i + j)];
        let k = rest.find(&format!("{name}=\""))? + name.len() + 2;
        Some(rest[k..].split('"').next()?.to_string())
    };
    if let Some(v) = attr("vendor", "name") {
        cx.format_set("woff_vendor", truncate_chars(&v, 200));
    }
    if let Some(u) = attr("license", "url") {
        cx.format_set("woff_license_url", truncate_chars(&u, 500));
    }
}

/// An EOT file: header facts, then the embedded font when it is stored
/// plainly or XOR-obfuscated (MicroType Express compression is not undone).
fn eot<'a>(cx: &mut Context<'_>, b: &'a [u8]) -> Result<Option<Cow<'a, [u8]>>, ExtractError> {
    let bad = || ExtractError::malformed("EOT header");
    let size = usize::try_from(le32(b, 4).ok_or_else(bad)?).map_err(|_| bad())?;
    let version = le32(b, 8).ok_or_else(bad)?;
    let flags = le32(b, 12).ok_or_else(bad)?;
    cx.format_set("eot_version", format!("{}.{}", version >> 16, version & 0xffff));
    let mut at = 82;
    let mut strings = Vec::new();
    for key in ["eot_family", "eot_style", "eot_version_name", "eot_full_name"] {
        let n = usize::from(le16(b, at).ok_or_else(bad)?);
        let s = utf16(b.get(at + 2..at + 2 + n).ok_or_else(bad)?, true);
        if !s.is_empty() {
            cx.format_set(key, truncate_chars(&s, 200));
        }
        strings.push(s);
        at += 2 + n + 2;
    }
    if version >= 0x0002_0001 {
        let n = usize::from(le16(b, at).unwrap_or(0));
        let roots = utf16(b.get(at + 2..at + 2 + n).unwrap_or_default(), true);
        let urls: Vec<String> =
            roots.split('\0').filter(|u| !u.is_empty()).take(50).map(|u| truncate_chars(u, 300)).collect();
        if !urls.is_empty() {
            cx.format_set("root_urls", urls);
        }
    }
    let compressed = flags & 0x4 != 0;
    let xor = flags & 0x1000_0000 != 0;
    if flags & 0x1 != 0 {
        cx.format_set("subset", true);
    }
    if compressed {
        cx.format_set("compression", "microtype_express");
    }
    if xor {
        cx.format_set("obfuscated", true);
    }
    let total = usize::try_from(le32(b, 0).ok_or_else(bad)?).map_err(|_| bad())?;
    let start = total.saturating_sub(size);
    let Some(data) = start.checked_add(size).and_then(|e| b.get(start..e)) else { return Ok(None) };
    if compressed {
        if let Some(s) = strings.last().filter(|s| !s.is_empty()) {
            cx.content().source("eot.FullName").title(truncate_chars(s, 200));
        }
        if let Some(fs) = le16(b, 32) {
            cx.rights().source("eot.fsType").embedding(super::embedding(fs));
        }
        return Ok(None);
    }
    Ok(Some(if xor { Cow::Owned(data.iter().map(|x| x ^ 0x50).collect()) } else { Cow::Borrowed(data) }))
}

/// The `sfnt` resources (and the resource types) of a resource file.
fn dfont(cx: &mut Context<'_>, b: &[u8]) -> Result<Vec<usize>, ExtractError> {
    let bad = || ExtractError::malformed("resource map");
    let data_at = usize::try_from(be32(b, 0).ok_or_else(bad)?).map_err(|_| bad())?;
    let map = usize::try_from(be32(b, 4).ok_or_else(bad)?).map_err(|_| bad())?;
    let types_at = map + usize::from(be16(b, map + 24).ok_or_else(bad)?);
    let n_types = usize::from(be16(b, types_at).ok_or_else(bad)?) + 1;
    let mut kinds = Vec::new();
    let mut fonts = Vec::new();
    for i in 0..n_types.min(256) {
        let e = types_at + 2 + 8 * i;
        let (Some(t), Some(count), Some(refs)) = (b.get(e..e + 4), be16(b, e + 4), be16(b, e + 6)) else { break };
        let name = super::tag(t).unwrap_or_default();
        let count = usize::from(count) + 1;
        kinds.push(Value::from(format!("{name} ×{count}")));
        if t != b"sfnt" {
            continue;
        }
        for j in 0..count.min(MAX_MEMBERS) {
            let r = types_at + usize::from(refs) + 12 * j;
            let Some(off) = be32(b, r + 4).map(|v| v & 0x00ff_ffff) else { break };
            let Ok(off) = usize::try_from(off) else { break };
            fonts.push(data_at + off + 4);
        }
    }
    cx.format_set("resource_types", kinds);
    Ok(fonts)
}

/// Describe the first font and list every member.
fn collection(cx: &mut Context<'_>, fonts: &[Font<'_>]) {
    cx.format_set("fonts", fonts.len());
    cx.format_set("members", fonts.iter().take(MAX_MEMBERS).map(member).collect::<Vec<_>>());
    if let Some(first) = fonts.first() {
        describe(cx, first);
    }
}

/// Whether `b` starts with a plausible sfnt table directory.
fn plausible(b: &[u8]) -> bool {
    let Some(n) = be16(b, 4) else { return false };
    let n = usize::from(n);
    (1..=100).contains(&n)
        && (0..n).all(|i| b.get(12 + 16 * i..16 + 16 * i).is_none_or(|t| t.iter().all(|c| (0x20..0x7f).contains(c))))
        && b.len() >= 12 + 16 * n.min(4)
}

impl Extractor for Sfnt {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // EOT: the version and the declared sizes must hold.
        if h.get(34..36) == Some(b"LP") {
            let size = le32(h, 0).map(u64::from);
            let version = le32(h, 8);
            if size == Some(probe.len) && matches!(version, Some(0x0001_0000 | 0x0002_0001 | 0x0002_0002)) {
                return Some(Sniff { format: "eot", confidence: 0.95 });
            }
        }
        // Resource files: header offsets that fit, and an sfnt or FOND type.
        if matches!(probe.extension, Some("dfont" | "suit")) || h.starts_with(&[0, 0, 1, 0]) {
            let data = be32(h, 0).map(u64::from);
            let map = be32(h, 4).map(u64::from);
            let dlen = be32(h, 8).map(u64::from);
            let ok = data == Some(256) && map.zip(dlen).is_some_and(|(m, d)| m == 256 + d && m < probe.len);
            let fonty = probe.extension.is_some_and(|e| e == "dfont" || e == "suit")
                || probe.tail.windows(4).any(|w| w == b"sfnt" || w == b"FOND" || w == b"NFNT");
            if ok && fonty {
                return Some(Sniff { format: "dfont", confidence: 0.95 });
            }
        }
        // A bare `00 01 00 00` is weak magic: check the directory too.
        (h.starts_with(b"\x00\x01\x00\x00") && plausible(h)).then_some(Sniff { format: "ttf", confidence: 0.98 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let cap = cx.parse_limit();
        match cx.format_id() {
            "ttf" | "otf" => {
                let font = read_font(src, 0, cap).ok_or_else(|| ExtractError::malformed("table directory"))?;
                describe(cx, &font);
            }
            "ttc" => {
                let head = src.read_vec(0, 12).map_err(|_| ExtractError::malformed("collection header"))?;
                let n = be32(&head, 8).unwrap_or(0);
                cx.format_set("collection_version", format!("{}.0", be16(&head, 4).unwrap_or(0)));
                let count = usize::try_from(n).unwrap_or(0).min(MAX_MEMBERS);
                let offs = src.read_vec(12, 4 * count).map_err(|_| ExtractError::malformed("collection offsets"))?;
                let mut fonts = Vec::new();
                for i in 0..count {
                    cx.checkpoint()?;
                    if let Some(f) = be32(&offs, 4 * i).and_then(|o| read_font(src, u64::from(o), cap)) {
                        fonts.push(f);
                    }
                }
                collection(cx, &fonts);
                cx.format_set("fonts", n);
            }
            "woff" => {
                let (b, _) = cx.read_bytes(src)?;
                let font = woff(cx, &b)?;
                describe(cx, &font);
            }
            "woff2" => {
                let (b, _) = cx.read_bytes(src)?;
                let fonts = woff2(cx, &b)?;
                if fonts.len() == 1 && be32(&b, 4) != Some(0x7474_6366) {
                    describe(cx, &fonts[0]);
                } else {
                    collection(cx, &fonts);
                }
            }
            "eot" => {
                let (b, _) = cx.read_bytes(src)?;
                if let Some(data) = eot(cx, &b)? {
                    let font = Font::parse(&data, 0).ok_or_else(|| ExtractError::malformed("embedded font"))?;
                    describe(cx, &font);
                }
            }
            _ => {
                let (b, _) = cx.read_bytes(src)?;
                let offs = dfont(cx, &b)?;
                // Each sfnt resource is a font whose offsets start at its data.
                let fonts: Vec<Font<'_>> = offs.iter().filter_map(|&o| Font::parse(b.get(o..)?, 0)).collect();
                collection(cx, &fonts);
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Sfnt);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn woff2_numbers() {
        let mut at = 0;
        assert_eq!(base128(&[0x3f], &mut at), Some(63));
        at = 0;
        assert_eq!(base128(&[0x81, 0x00], &mut at), Some(128));
        at = 0;
        assert_eq!(base128(&[0x80, 0x01], &mut at), None);
        at = 0;
        assert_eq!(uint255(&[253, 1, 0], &mut at), Some(256));
        at = 0;
        assert_eq!(uint255(&[255, 7], &mut at), Some(260));
        at = 0;
        assert_eq!(uint255(&[254, 0], &mut at), Some(506));
    }

    crate::fixture_tests!("ttf", "otf", "ttc", "woff", "woff2", "eot", "dfont");
}
