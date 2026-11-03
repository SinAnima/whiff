//! Bitmap fonts:
//! * BDF (text): the XLFD name, size, bounding box, the properties
//!   (foundry, family, weight, slant, spacing, character set, copyright …)
//!   and the glyph count;
//! * PCF (the X11 compiled form): the same properties, glyph and encoded
//!   character counts;
//! * Windows FNT and the FON resource libraries that hold them: version,
//!   face name, copyright, point size, resolution, pixel height, weight,
//!   italic, character set and character range, for each face of a FON;
//! * PC Screen Font (PSF 1 and 2): glyph count, cell size, the Unicode
//!   table's code points.
//!
//! Specifications: Adobe "Glyph Bitmap Distribution Format 2.2"; the X.Org
//! PCF format notes (`pcfread.c`); Microsoft "Windows 3.0 font file format"
//! (KB65123) and the NE resource table; the Linux kbd `psf.h`.

use serde_json::{Map, Value};

use super::type1::cstr;
use super::{le16, le32};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for bitmap fonts.
pub struct Bitmap;

static META: ExtractorMeta = ExtractorMeta {
    id: "font.bitmap",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "bdf",
            name: "BDF bitmap font",
            family: "font",
            mimes: &["application/x-font-bdf"],
            extensions: &["bdf"],
            magic: &[Magic::at(0, b"STARTFONT ")],
            parent: None,
        },
        FormatSpec {
            id: "pcf",
            name: "PCF bitmap font",
            family: "font",
            mimes: &["application/x-font-pcf"],
            extensions: &["pcf"],
            magic: &[Magic::at(0, b"\x01fcp")],
            parent: None,
        },
        FormatSpec {
            id: "fnt",
            name: "Windows bitmap font",
            family: "font",
            mimes: &[],
            extensions: &["fnt"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "fon",
            name: "Windows font library",
            family: "font",
            mimes: &[],
            extensions: &["fon"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "psf",
            name: "PC Screen Font",
            family: "font",
            mimes: &[],
            extensions: &["psf", "psfu"],
            magic: &[Magic::at(0, b"\x36\x04"), Magic::at(0, b"\x72\xb5\x4a\x86")],
            parent: None,
        },
    ],
};

/// Faces of a FON listed.
const MAX_FACES: usize = 64;

/// Windows character sets.
fn charset(c: u8) -> String {
    match c {
        0 => "ANSI".into(),
        1 => "default".into(),
        2 => "symbol".into(),
        77 => "Mac".into(),
        128 => "Shift JIS".into(),
        129 => "Hangul".into(),
        134 => "GB2312".into(),
        136 => "Big5".into(),
        161 => "Greek".into(),
        162 => "Turkish".into(),
        177 => "Hebrew".into(),
        178 => "Arabic".into(),
        186 => "Baltic".into(),
        204 => "Russian".into(),
        222 => "Thai".into(),
        238 => "East Europe".into(),
        255 => "OEM".into(),
        _ => format!("charset {c}"),
    }
}

/// The Windows font header shared by FNT and PFM (`FONTINFO`): writes the
/// common facts and returns the face name.
pub(crate) fn win_header(cx: &mut Context<'_>, b: &[u8]) -> Option<String> {
    let version = le16(b, 0)?;
    if b.len() < 117 {
        return None;
    }
    cx.format_set("font_version", format!("{}.{}", version >> 8, version & 0xff));
    if let Some(c) = cstr(b, 6, 60) {
        cx.format_set("copyright", truncate_chars(&c, 200));
        cx.rights().source("fnt.dfCopyright").copyright(truncate_chars(&c, 200));
    }
    if le16(b, 66).is_some_and(|t| t & 1 != 0) {
        cx.format_set("vector", true);
    }
    cx.format_set("points", le16(b, 68)?);
    cx.format_set("resolution", format!("{}x{}", le16(b, 72)?, le16(b, 70)?));
    cx.format_set("weight_class", le16(b, 83)?);
    cx.format_set("italic", b[80] != 0);
    cx.format_set("charset", charset(b[85]));
    if let Some(h) = le16(b, 88).filter(|&h| h > 0) {
        cx.format_set("pixel_height", h);
    }
    if let Some(w) = le16(b, 86).filter(|&w| w > 0) {
        cx.format_set("pixel_width", w);
    }
    cx.format_set("monospace", b[90] & 1 == 0);
    let face = le32(b, 105).and_then(|o| usize::try_from(o).ok()).and_then(|o| cstr(b, o, 256));
    if let Some(f) = &face {
        cx.format_set("face", truncate_chars(f, 200));
        cx.content().source("fnt.dfFace").title(truncate_chars(f, 200));
    }
    if let Some(d) = le32(b, 101).and_then(|o| usize::try_from(o).ok()).filter(|&o| o > 0).and_then(|o| cstr(b, o, 64))
    {
        cx.format_set("device", truncate_chars(&d, 64));
    }
    face
}

/// One face of a FON, for the face list.
fn face(b: &[u8]) -> Option<Value> {
    let mut m = Map::new();
    let name = le32(b, 105).and_then(|o| usize::try_from(o).ok()).and_then(|o| cstr(b, o, 256));
    if let Some(n) = name {
        m.insert("face".into(), truncate_chars(&n, 100).into());
    }
    m.insert("points".into(), le16(b, 68)?.into());
    m.insert("pixel_height".into(), le16(b, 88)?.into());
    m.insert("weight_class".into(), le16(b, 83)?.into());
    if b.get(80).is_some_and(|&i| i != 0) {
        m.insert("italic".into(), true.into());
    }
    Some(Value::Object(m))
}

/// Byte ranges of font resources, and the module description.
type NeFonts = (Vec<(usize, usize)>, Option<String>);

/// The `RT_FONT` resources of an NE executable, as byte ranges.
fn ne_fonts(b: &[u8]) -> Option<NeFonts> {
    let ne = usize::try_from(le32(b, 0x3c)?).ok()?;
    if b.get(ne..ne + 2)? != b"NE" {
        return None;
    }
    let res = ne + usize::from(le16(b, ne + 0x24)?);
    let shift = u32::from(le16(b, res)?.min(16));
    let mut at = res + 2;
    let mut fonts = Vec::new();
    for _ in 0..64 {
        let kind = le16(b, at)?;
        if kind == 0 {
            break;
        }
        let count = usize::from(le16(b, at + 2)?);
        for i in 0..count.min(1024) {
            let r = at + 8 + 12 * i;
            if kind == 0x8008 {
                let off = usize::from(le16(b, r)?) << shift;
                let len = usize::from(le16(b, r + 2)?) << shift;
                fonts.push((off, len));
            }
        }
        at += 8 + 12 * count;
    }
    // The module description: the first non-resident name.
    let nonres = usize::try_from(le32(b, ne + 0x2c)?).ok()?;
    let desc = b.get(nonres).and_then(|&n| b.get(nonres + 1..nonres + 1 + usize::from(n)));
    let desc = desc.map(|d| String::from_utf8_lossy(d).trim().to_string()).filter(|d| !d.is_empty());
    Some((fonts, desc))
}

fn bdf(cx: &mut Context<'_>, text: &str) {
    let mut props = Map::new();
    let mut in_props = false;
    for line in text.lines().take(100_000) {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        let value = value.trim();
        match key {
            "STARTFONT" => cx.format_set("bdf_version", value),
            "FONT" => cx.format_set("font", truncate_chars(value, 300)),
            "SIZE" => cx.format_set("size", value),
            "FONTBOUNDINGBOX" => cx.format_set("bounding_box", value),
            "STARTPROPERTIES" => in_props = true,
            "ENDPROPERTIES" => in_props = false,
            "CHARS" => {
                if let Ok(n) = value.parse::<u64>() {
                    cx.format_set("glyph_count", n);
                }
                break;
            }
            _ if in_props && props.len() < 100 => {
                let v = value.trim_matches('"');
                let v = v.parse::<i64>().map_or_else(|_| Value::from(truncate_chars(v, 500)), Value::from);
                props.insert(key.to_ascii_lowercase(), v);
            }
            _ => {}
        }
    }
    x_properties(cx, &props);
    if !props.is_empty() {
        cx.format_set("properties", Value::Object(props));
    }
}

/// The well-known X font properties into the normalised fields.
fn x_properties(cx: &mut Context<'_>, props: &Map<String, Value>) {
    let get = |k: &str| props.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let name = get("face_name").map(str::to_string).or_else(|| {
        let family = get("family_name")?;
        Some(match get("weight_name") {
            Some(w) => format!("{family} {w}"),
            None => family.to_string(),
        })
    });
    if let Some(n) = name {
        cx.content().source("bdf.FAMILY_NAME").title(truncate_chars(&n, 200));
    }
    if let Some(c) = get("copyright").or_else(|| get("notice")) {
        cx.rights().source("bdf.COPYRIGHT").copyright(truncate_chars(c, 500));
    }
}

/// A PCF table: (format, data starting at the format word).
fn pcf_table(b: &[u8], kind: u32) -> Option<(u32, &[u8])> {
    let n = usize::try_from(le32(b, 4)?).ok()?;
    for i in 0..n.min(64) {
        let r = 8 + 16 * i;
        if le32(b, r)? == kind {
            let size = usize::try_from(le32(b, r + 8)?).ok()?;
            let off = usize::try_from(le32(b, r + 12)?).ok()?;
            let t = b.get(off..off.checked_add(size)?)?;
            return Some((le32(t, 0)?, t));
        }
    }
    None
}

fn pcf32(t: &[u8], at: usize, big: bool) -> Option<u32> {
    let raw: [u8; 4] = t.get(at..at + 4)?.try_into().ok()?;
    Some(if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
}

fn pcf16(t: &[u8], at: usize, big: bool) -> Option<u16> {
    let raw: [u8; 2] = t.get(at..at + 2)?.try_into().ok()?;
    Some(if big { u16::from_be_bytes(raw) } else { u16::from_le_bytes(raw) })
}

fn pcf(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    cx.format_set("table_count", le32(b, 4)?);
    let mut props = Map::new();
    if let Some((fmt, t)) = pcf_table(b, 1) {
        let big = fmt & 4 != 0;
        let n = usize::try_from(pcf32(t, 4, big)?).ok()?.min(1000);
        let pad = (4 - n % 4) % 4;
        let strings_at = 8 + 9 * n + pad + 4;
        let strings = t.get(strings_at..).unwrap_or_default();
        for i in 0..n {
            let r = 8 + 9 * i;
            let (Some(name), Some(&is_str), Some(value)) = (pcf32(t, r, big), t.get(r + 4), pcf32(t, r + 5, big))
            else {
                break;
            };
            let Some(key) = usize::try_from(name).ok().and_then(|o| cstr(strings, o, 256)) else { continue };
            let v = if is_str != 0 {
                usize::try_from(value)
                    .ok()
                    .and_then(|o| cstr(strings, o, 1000))
                    .map_or(Value::Null, |s| truncate_chars(&s, 500).into())
            } else {
                value.cast_signed().into()
            };
            if props.len() < 100 {
                props.insert(key.to_ascii_lowercase(), v);
            }
        }
    }
    if let Some(font) = props.get("font").and_then(Value::as_str) {
        cx.format_set("font", font.to_string());
    }
    if let Some((fmt, t)) = pcf_table(b, 8) {
        cx.format_set("glyph_count", pcf32(t, 4, fmt & 4 != 0)?);
    } else if let Some((fmt, t)) = pcf_table(b, 4) {
        let big = fmt & 4 != 0;
        let n = if fmt & 0x100 != 0 { pcf16(t, 4, big).map(u32::from) } else { pcf32(t, 4, big) };
        cx.format_set("glyph_count", n?);
    }
    if let Some((fmt, t)) = pcf_table(b, 32) {
        let big = fmt & 4 != 0;
        let (c0, c1, r0, r1) = (pcf16(t, 4, big)?, pcf16(t, 6, big)?, pcf16(t, 8, big)?, pcf16(t, 10, big)?);
        let cols = usize::from(c1.saturating_sub(c0)) + 1;
        let rows = usize::from(r1.saturating_sub(r0)) + 1;
        let n = (cols * rows).min(65_536);
        let encoded = (0..n).filter(|i| pcf16(t, 14 + 2 * i, big).is_some_and(|g| g != 0xffff)).count();
        cx.format_set("encoded_characters", encoded);
    }
    x_properties(cx, &props);
    if !props.is_empty() {
        cx.format_set("properties", Value::Object(props));
    }
    Some(())
}

/// The code points of a PSF Unicode table.
fn psf_unicode(t: &[u8], v2: bool) -> usize {
    let mut count = 0usize;
    if v2 {
        // UTF-8 per glyph, 0xFE starts the sequences (not counted), 0xFF ends.
        for glyph in t.split(|&c| c == 0xff) {
            let single = glyph.split(|&c| c == 0xfe).next().unwrap_or_default();
            count += String::from_utf8_lossy(single).chars().count();
        }
    } else {
        let mut seq = false;
        for c in t.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)) {
            match c {
                0xffff => seq = false,
                0xfffe => seq = true,
                _ if !seq => count += 1,
                _ => {}
            }
        }
    }
    count
}

fn psf(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    if b.starts_with(&[0x36, 0x04]) {
        let mode = *b.get(2)?;
        let height = *b.get(3)?;
        let glyphs = if mode & 1 != 0 { 512 } else { 256 };
        cx.format_set("psf_version", 1);
        cx.format_set("glyph_count", glyphs);
        cx.format_set("width", 8);
        cx.format_set("height", height);
        if mode & 6 != 0 {
            let at = 4 + glyphs * usize::from(height);
            cx.format_set("codepoints", psf_unicode(b.get(at..).unwrap_or_default(), false));
        }
        return Some(());
    }
    let header = usize::try_from(le32(b, 8)?).ok()?;
    let flags = le32(b, 12)?;
    let glyphs = le32(b, 16)?;
    let size = le32(b, 20)?;
    cx.format_set("psf_version", 2);
    cx.format_set("glyph_count", glyphs);
    cx.format_set("height", le32(b, 24)?);
    cx.format_set("width", le32(b, 28)?);
    if flags & 1 != 0 {
        let at = header.checked_add(usize::try_from(u64::from(glyphs) * u64::from(size)).ok()?)?;
        cx.format_set("codepoints", psf_unicode(b.get(at..).unwrap_or_default(), true));
    }
    Some(())
}

impl Extractor for Bitmap {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let size = le32(h, 2).map(u64::from) == Some(probe.len);
        if matches!(le16(h, 0), Some(0x0100 | 0x0200 | 0x0300)) && size && le32(h, 101) == Some(0) && h.len() >= 118 {
            return Some(Sniff { format: "fnt", confidence: 0.9 });
        }
        if h.starts_with(b"MZ") && ne_fonts(h).is_some_and(|(f, _)| !f.is_empty()) {
            return Some(Sniff { format: "fon", confidence: 0.98 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        let bad = |what: &str| ExtractError::malformed(what.to_string());
        match cx.format_id() {
            "bdf" => bdf(cx, &String::from_utf8_lossy(&b)),
            "pcf" => pcf(cx, &b).ok_or_else(|| bad("PCF tables"))?,
            "fnt" => {
                win_header(cx, &b).ok_or_else(|| bad("FNT header"))?;
                let (first, last) = (b[95], b[96]);
                cx.format_set("first_char", first);
                cx.format_set("last_char", last);
                cx.format_set("glyph_count", u16::from(last.saturating_sub(first)) + 1);
            }
            "fon" => {
                let (fonts, desc) = ne_fonts(&b).ok_or_else(|| bad("NE resource table"))?;
                if let Some(d) = desc {
                    cx.format_set("description", truncate_chars(&d, 300));
                }
                cx.format_set("fonts", fonts.len());
                let faces: Vec<Value> =
                    fonts.iter().take(MAX_FACES).filter_map(|&(o, l)| face(b.get(o..o.checked_add(l)?)?)).collect();
                if let Some(&(o, l)) = fonts.first()
                    && let Some(first) = o.checked_add(l).and_then(|e| b.get(o..e))
                {
                    win_header(cx, first);
                }
                cx.format_set("faces", faces);
            }
            _ => psf(cx, &b).ok_or_else(|| bad("PSF header"))?,
        }
        Ok(())
    }
}

crate::register_extractor!(Bitmap);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psf_tables() {
        // PSF2: "A", then "B" + a sequence, then "é".
        assert_eq!(psf_unicode(b"A\xffB\xfeAB\xff\xc3\xa9\xff", true), 3);
        // PSF1: 0x41, then 0x42 and a sequence.
        assert_eq!(psf_unicode(&[0x41, 0, 0xff, 0xff, 0x42, 0, 0xfe, 0xff, 0x41, 0, 0xff, 0xff], false), 2);
        assert_eq!(charset(204), "Russian");
    }

    crate::fixture_tests!("bdf", "pcf", "fnt", "fon", "psf");
}
