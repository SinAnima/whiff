//! `font` extractors (feature `common`): OpenType / TrueType fonts and the
//! containers that carry them (collections, WOFF, WOFF2, EOT, Mac dfont),
//! PostScript Type 1 fonts and metrics, bitmap fonts (BDF, PCF, Windows
//! FNT / FON, PC Screen Font) and font sources (`FontForge`, Glyphs, UFO,
//! Metafont).
//!
//! The sfnt reader here is shared: every container is decoded into a
//! [`Font`] (its tables) and described the same way.
//!
//! Specifications: OpenType 1.9.1 (`name`, `head`, `OS/2`, `post`, `maxp`,
//! `cmap`, `fvar`, `GSUB` / `GPOS`, `COLR` / `CPAL`, `DSIG`); Apple's
//! TrueType Reference Manual for the Mac name encodings.

pub(crate) mod bitmap;
pub(crate) mod sfnt;
pub(crate) mod source;
pub(crate) mod type1;
mod unicode;

use std::borrow::Cow;
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::plugin::{Context, DateField, identify_license, truncate_chars};

// Shared with the other extractors of the group.
pub(crate) use super::archive::unix_time;

/// Tables listed by tag.
const MAX_TABLES: usize = 200;
/// Feature and script tags listed.
const MAX_TAGS: usize = 200;
/// Named instances listed.
const MAX_INSTANCES: usize = 100;
/// Seconds from 1904-01-01 (the sfnt epoch) to 1970-01-01.
const MAC_EPOCH: i64 = 2_082_844_800;

pub(crate) fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn fixed(b: &[u8], at: usize) -> Option<f64> {
    Some(f64::from(be32(b, at)?.cast_signed()) / 65536.0)
}

/// A 16.16 value rounded for the report (3 decimals).
fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// A four-character tag, printable or not reported.
pub(crate) fn tag(t: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(t).ok()?;
    s.bytes().all(|c| (0x20..0x7f).contains(&c)).then(|| s.trim_end().to_string())
}

/// Decode UTF-16BE (sfnt names, EOT strings use little-endian: see `utf16`).
pub(crate) fn utf16(b: &[u8], little: bool) -> String {
    let units =
        b.as_chunks::<2>().0.iter().map(|c| if little { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) });
    char::decode_utf16(units).map(|c| c.unwrap_or('\u{fffd}')).collect::<String>().trim_matches('\0').to_string()
}

/// An sfnt font: its version tag and tables.
pub(crate) struct Font<'a> {
    pub(crate) version: u32,
    /// Tables in directory order; a table whose data could not be read
    /// (truncated, transformed WOFF2 glyph data) is listed with no data.
    pub(crate) tables: Vec<([u8; 4], Cow<'a, [u8]>)>,
}

impl<'a> Font<'a> {
    /// The table directory at `at` of `data` (offsets are from the start of
    /// `data`, as in collections).
    pub(crate) fn parse(data: &'a [u8], at: usize) -> Option<Self> {
        let version = be32(data, at)?;
        if !matches!(version, 0x0001_0000 | 0x4F54_544F | 0x7472_7565 | 0x7479_7031) {
            return None;
        }
        let n = usize::from(be16(data, at + 4)?);
        if n == 0 || n > 1000 {
            return None;
        }
        let mut tables = Vec::with_capacity(n);
        for i in 0..n {
            let r = at + 12 + 16 * i;
            let t: [u8; 4] = data.get(r..r + 4)?.try_into().ok()?;
            let off = usize::try_from(be32(data, r + 8)?).ok()?;
            let len = usize::try_from(be32(data, r + 12)?).ok()?;
            let body = off.checked_add(len).and_then(|end| data.get(off..end)).unwrap_or_default();
            tables.push((t, Cow::Borrowed(body)));
        }
        Some(Self { version, tables })
    }

    pub(crate) fn table(&self, t: &[u8]) -> Option<&[u8]> {
        self.tables.iter().find(|(x, d)| x.as_slice() == t && !d.is_empty()).map(|(_, d)| d.as_ref())
    }

    fn has(&self, t: &[u8]) -> bool {
        self.tables.iter().any(|(x, _)| x.as_slice() == t)
    }

    /// A string of the `name` table, preferring Windows English.
    pub(crate) fn name(&self, id: u16) -> Option<String> {
        let t = self.table(b"name")?;
        let count = usize::from(be16(t, 2)?);
        let storage = usize::from(be16(t, 4)?);
        let mut best: Option<(u8, String)> = None;
        for i in 0..count.min(5000) {
            let r = 6 + 12 * i;
            let (Some(platform), Some(encoding), Some(language), Some(name_id)) =
                (be16(t, r), be16(t, r + 2), be16(t, r + 4), be16(t, r + 6))
            else {
                break;
            };
            if name_id != id {
                continue;
            }
            let (Some(len), Some(off)) = (be16(t, r + 8), be16(t, r + 10)) else { break };
            let start = storage + usize::from(off);
            let Some(raw) = t.get(start..start + usize::from(len)) else { continue };
            let (rank, text) = match (platform, encoding, language) {
                (3, 1 | 10, 0x409) => (0, utf16(raw, false)),
                (3, 0 | 1 | 10, _) => (1, utf16(raw, false)),
                (0, _, _) => (2, utf16(raw, false)),
                (1, 0, 0) => (3, encoding_rs::MACINTOSH.decode_without_bom_handling(raw).0.into_owned()),
                _ => continue,
            };
            let text = text.trim().to_string();
            if !text.is_empty() && best.as_ref().is_none_or(|(r, _)| rank < *r) {
                best = Some((rank, text));
            }
        }
        best.map(|(_, s)| s)
    }
}

/// The OS/2 vendor ID, which is often padded with NULs or spaces.
fn vendor_id(raw: &[u8]) -> Option<String> {
    let end = raw.iter().rposition(|&c| c != 0 && c != b' ')?;
    tag(&raw[..=end])
}

/// The fsType embedding permission, as words.
fn embedding(fs_type: u16) -> String {
    let base = match fs_type & 0x000f {
        0 => "installable",
        x if x & 0x8 != 0 => "editable",
        x if x & 0x4 != 0 => "preview_and_print",
        x if x & 0x2 != 0 => "restricted",
        _ => "installable",
    };
    let mut s = base.to_string();
    if fs_type & 0x0100 != 0 {
        s.push_str(", no subsetting");
    }
    if fs_type & 0x0200 != 0 {
        s.push_str(", bitmap embedding only");
    }
    s
}

fn weight_name(w: u16) -> &'static str {
    match w {
        0..=149 => "thin",
        150..=249 => "extra_light",
        250..=349 => "light",
        350..=449 => "regular",
        450..=549 => "medium",
        550..=649 => "semi_bold",
        650..=749 => "bold",
        750..=849 => "extra_bold",
        _ => "black",
    }
}

fn width_name(w: u16) -> Option<&'static str> {
    Some(match w {
        1 => "ultra_condensed",
        2 => "extra_condensed",
        3 => "condensed",
        4 => "semi_condensed",
        5 => "normal",
        6 => "semi_expanded",
        7 => "expanded",
        8 => "extra_expanded",
        9 => "ultra_expanded",
        _ => return None,
    })
}

/// The feature (or script) tags of a `GSUB` / `GPOS` table.
fn layout_tags(t: &[u8], list_at: usize, out: &mut BTreeSet<String>) {
    let Some(list) = be16(t, list_at).map(usize::from).filter(|&o| o != 0) else { return };
    let Some(n) = be16(t, list) else { return };
    for i in 0..usize::from(n).min(2000) {
        let Some(raw) = t.get(list + 2 + 6 * i..list + 6 + 6 * i) else { break };
        if let Some(s) = tag(raw)
            && out.len() < MAX_TAGS
        {
            out.insert(s);
        }
    }
}

/// The names of the font (for collection members).
pub(crate) fn member(font: &Font<'_>) -> Value {
    let mut m = Map::new();
    for (id, key) in [(4, "full_name"), (6, "postscript_name"), (1, "family"), (2, "subfamily")] {
        if let Some(s) = font.name(id) {
            m.insert(key.into(), truncate_chars(&s, 200).into());
        }
    }
    Value::Object(m)
}

/// Describe an sfnt font in the report.
#[allow(clippy::too_many_lines)] // one pass over the tables, in report order
pub(crate) fn describe(cx: &mut Context<'_>, font: &Font<'_>) {
    let outlines = if font.has(b"CFF2") {
        "cff2"
    } else if font.has(b"CFF ") {
        "cff"
    } else if font.has(b"glyf") {
        "truetype"
    } else if font.has(b"sbix") || font.has(b"CBDT") || font.has(b"EBDT") || font.has(b"bdat") {
        "bitmap"
    } else {
        "none"
    };
    cx.format_set("outlines", outlines);
    cx.format_set("table_count", font.tables.len());
    let tags: Vec<String> = font.tables.iter().take(MAX_TABLES).filter_map(|(t, _)| tag(t)).collect();
    cx.format_set("tables", tags);

    // Names.
    for (id, key, max) in [
        (1, "family", 200),
        (2, "subfamily", 200),
        (16, "typographic_family", 200),
        (17, "typographic_subfamily", 200),
        (4, "full_name", 200),
        (6, "postscript_name", 200),
        (5, "version", 200),
        (3, "unique_id", 200),
        (8, "manufacturer", 200),
        (9, "designer", 200),
        (7, "trademark", 500),
        (11, "vendor_url", 500),
        (12, "designer_url", 500),
        (14, "license_url", 500),
        (19, "sample_text", 500),
    ] {
        if let Some(s) = font.name(id) {
            cx.format_set(key, truncate_chars(&s, max));
        }
    }
    if let Some(full) = font.name(4).or_else(|| font.name(1)) {
        cx.content().source("name.4").title(truncate_chars(&full, 200));
    }
    if let Some(d) = font.name(10) {
        cx.content().source("name.10").description(truncate_chars(&d, 1000));
    }
    if let Some(d) = font.name(9) {
        cx.content().source("name.9").author(truncate_chars(&d, 200));
    }
    if let Some(c) = font.name(0) {
        cx.format_set("copyright", truncate_chars(&c, 1000));
        cx.rights().source("name.0").copyright(truncate_chars(&c, 1000));
    }
    let licence = font.name(13);
    let url = font.name(14);
    if let Some(l) = &licence {
        cx.format_set("license", truncate_chars(l, 2000));
    }
    let id = licence.as_deref().and_then(identify_license);
    let short = id.map(str::to_string).or_else(|| licence.as_deref().map(|l| truncate_chars(l, 200)));
    cx.rights().source("name.13").license(short.as_deref(), url.as_deref());

    // head: revision, units per em, dates, style bits.
    if let Some(h) = font.table(b"head") {
        if let Some(r) = fixed(h, 4) {
            cx.format_set("font_revision", round3(r));
        }
        if let Some(u) = be16(h, 18) {
            cx.format_set("units_per_em", u);
        }
        for (at, field, key) in [(20, DateField::Created, "created"), (28, DateField::Modified, "modified")] {
            let secs = h.get(at..at + 8).and_then(|b| b.try_into().ok()).map(i64::from_be_bytes);
            if let Some(t) = secs.and_then(|s| s.checked_sub(MAC_EPOCH)).and_then(unix_time) {
                cx.format_set(key, t.clone());
                cx.temporal().source(format!("head.{key}")).content_date(field, t, true);
            }
        }
    }
    if let Some(m) = font.table(b"maxp").and_then(|m| be16(m, 4)) {
        cx.format_set("glyph_count", m);
    }

    // OS/2: vendor, weight, width, embedding, style.
    let os2 = font.table(b"OS/2");
    if let Some(o) = os2 {
        if let Some(v) = o.get(58..62).and_then(vendor_id) {
            cx.format_set("vendor_id", v);
        }
        if let Some(w) = be16(o, 4) {
            cx.format_set("weight_class", w);
            cx.format_set("weight", weight_name(w));
        }
        if let Some(w) = be16(o, 6) {
            cx.format_set("width_class", w);
            if let Some(n) = width_name(w) {
                cx.format_set("width", n);
            }
        }
        if let Some(fs) = be16(o, 8) {
            cx.format_set("fs_type", fs);
            let e = embedding(fs);
            cx.format_set("embedding", e.clone());
            cx.rights().source("OS/2.fsType").embedding(e);
        }
        if let Some(sel) = be16(o, 62) {
            cx.format_set("italic", sel & 0x01 != 0);
            cx.format_set("bold", sel & 0x20 != 0);
            if sel & 0x200 != 0 {
                cx.format_set("oblique", true);
            }
        }
        if be16(o, 0).is_some_and(|v| v >= 2) {
            if let Some(x) = be16(o, 86).map(u16::cast_signed).filter(|&x| x > 0) {
                cx.format_set("x_height", x);
            }
            if let Some(c) = be16(o, 88).map(u16::cast_signed).filter(|&c| c > 0) {
                cx.format_set("cap_height", c);
            }
        }
    } else if let Some(style) = font.table(b"head").and_then(|h| be16(h, 44)) {
        cx.format_set("bold", style & 1 != 0);
        cx.format_set("italic", style & 2 != 0);
    }
    if let Some(p) = font.table(b"post") {
        if let Some(a) = fixed(p, 4).filter(|a| *a != 0.0) {
            cx.format_set("italic_angle", round3(a));
        }
        if let Some(m) = be32(p, 12) {
            cx.format_set("monospace", m != 0);
        }
    }

    // Unicode coverage.
    if let Some(c) = font.table(b"cmap") {
        let (ranges, symbol) = unicode::coverage(c);
        let total: u64 = ranges.iter().map(|(a, b)| u64::from(b - a + 1)).sum();
        if total > 0 {
            cx.format_set("codepoints", total);
            let scripts = unicode::scripts(&ranges);
            let m: Map<String, Value> = scripts.into_iter().map(|(s, n)| (s.to_string(), n.into())).collect();
            cx.format_set("unicode_scripts", Value::Object(m));
        }
        if symbol {
            cx.format_set("symbol_encoding", true);
        }
    }

    // Variations.
    if let Some(f) = font.table(b"fvar") {
        variations(cx, font, f);
    }

    // Colour and bitmap glyphs.
    let mut colour = Vec::new();
    if let Some(v) = font.table(b"COLR").and_then(|t| be16(t, 0)) {
        colour.push(format!("COLRv{v}"));
    }
    for (t, name) in [(b"SVG ", "SVG"), (b"sbix", "sbix"), (b"CBDT", "CBDT"), (b"EBDT", "EBDT")] {
        if font.has(t) {
            colour.push(name.to_string());
        }
    }
    if !colour.is_empty() {
        cx.format_set("glyph_formats", colour);
    }
    if let Some(n) = font.table(b"CPAL").and_then(|t| be16(t, 4)) {
        cx.format_set("palettes", n);
    }

    // OpenType layout.
    let mut features = BTreeSet::new();
    let mut scripts = BTreeSet::new();
    for t in [b"GSUB", b"GPOS"] {
        if let Some(t) = font.table(t) {
            layout_tags(t, 6, &mut features);
            layout_tags(t, 4, &mut scripts);
        }
    }
    if !features.is_empty() {
        cx.format_set("features", features.into_iter().collect::<Vec<_>>());
    }
    if !scripts.is_empty() {
        cx.format_set("layout_scripts", scripts.into_iter().collect::<Vec<_>>());
    }
    if font.has(b"glyf") {
        cx.format_set("hinted", font.has(b"fpgm") || font.has(b"prep"));
    }
    if let Some(n) = font.table(b"DSIG").and_then(|t| be16(t, 4)) {
        cx.format_set("signatures", n);
        if n > 0 {
            cx.security().signed(true);
        }
    }
}

/// Axes and named instances of a variable font.
fn variations(cx: &mut Context<'_>, font: &Font<'_>, f: &[u8]) {
    let (Some(axes_at), Some(n_axes), Some(axis_size), Some(n_inst), Some(inst_size)) =
        (be16(f, 4), be16(f, 8), be16(f, 10), be16(f, 12), be16(f, 14))
    else {
        return;
    };
    let (axes_at, n_axes, axis_size) = (usize::from(axes_at), usize::from(n_axes), usize::from(axis_size));
    let mut axes = Vec::new();
    for i in 0..n_axes.min(64) {
        let a = axes_at + axis_size * i;
        let (Some(t), Some(min), Some(def), Some(max)) =
            (f.get(a..a + 4).and_then(tag), fixed(f, a + 4), fixed(f, a + 8), fixed(f, a + 12))
        else {
            break;
        };
        let mut m = Map::new();
        m.insert("tag".into(), t.into());
        if let Some(name) = be16(f, a + 18).and_then(|id| font.name(id)) {
            m.insert("name".into(), truncate_chars(&name, 100).into());
        }
        m.insert("min".into(), round3(min).into());
        m.insert("default".into(), round3(def).into());
        m.insert("max".into(), round3(max).into());
        if be16(f, a + 16).is_some_and(|fl| fl & 1 != 0) {
            m.insert("hidden".into(), true.into());
        }
        axes.push(Value::Object(m));
    }
    cx.format_set("variable", true);
    cx.format_set("axes", axes);
    let inst_at = axes_at + axis_size * n_axes;
    let instances: Vec<String> = (0..usize::from(n_inst).min(MAX_INSTANCES))
        .filter_map(|i| be16(f, inst_at + usize::from(inst_size) * i).and_then(|id| font.name(id)))
        .map(|s| truncate_chars(&s, 100))
        .collect();
    cx.format_set("instance_count", n_inst);
    if !instances.is_empty() {
        cx.format_set("instances", instances);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_words() {
        assert_eq!(embedding(0), "installable");
        assert_eq!(embedding(2), "restricted");
        assert_eq!(embedding(4 | 0x100), "preview_and_print, no subsetting");
        assert_eq!(embedding(8 | 0x200), "editable, bitmap embedding only");
        assert_eq!(weight_name(400), "regular");
        assert_eq!(width_name(3), Some("condensed"));
    }

    #[test]
    fn padded_vendor_ids() {
        // Found by the oracle: `JB\0\0` (JetBrains Mono) and `TT  `.
        assert_eq!(vendor_id(b"JB\0\0").as_deref(), Some("JB"));
        assert_eq!(vendor_id(b"TT  ").as_deref(), Some("TT"));
        assert_eq!(vendor_id(b"\0\0\0\0"), None);
        assert_eq!(vendor_id(b"B&H ").as_deref(), Some("B&H"));
    }

    #[test]
    fn rejects_short_directory() {
        assert!(Font::parse(&[0, 1, 0, 0, 0, 1], 0).is_none());
        assert!(Font::parse(b"OTTO\0\0", 0).is_none());
    }
}
