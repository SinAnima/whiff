//! Photoshop asset files: actions (`.atn`), brushes (`.abr`), swatches
//! (`.aco`, Adobe Swatch Exchange `.ase`), gradients (`.grd`) and patterns
//! (`.pat`). Each reports its version and the names it holds (action sets
//! and actions with their commands, brushes, colours and groups,
//! gradients, patterns with size and colour mode), which describe what a
//! preset library contains.
//!
//! Actions, gradients and newer brushes store their settings as Photoshop
//! action descriptors, walked here to find the `Nm  ` (name) values.
//!
//! References: Adobe "Photoshop File Formats Specification" (Color Swatch,
//! Gradient, Pattern and Brush files; "Descriptor structure"); the Adobe
//! Swatch Exchange layout (`ASEF` blocks) and the Photoshop actions file
//! layout as documented by the Adobe community and `psd-tools`.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for Photoshop asset files.
pub struct Assets;

const fn asset(
    id: &'static str,
    name: &'static str,
    ext: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec { id, name, family: "image.raster", mimes: &[], extensions: ext, magic, parent: None }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.assets",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        asset("photoshop_actions", "Photoshop actions", &["atn"], &[]),
        asset("photoshop_brushes", "Photoshop brushes", &["abr"], &[]),
        asset("photoshop_swatches", "Photoshop colour swatches", &["aco"], &[]),
        asset("ase_swatches", "Adobe Swatch Exchange", &["ase"], &[Magic::prefix(b"ASEF")]),
        asset("photoshop_gradients", "Photoshop gradients", &["grd"], &[Magic::prefix(b"8BGR")]),
        asset("photoshop_patterns", "Photoshop patterns", &["pat"], &[Magic::prefix(b"8BPT")]),
    ],
};

const MAX_LISTED: usize = 200;
/// Asset bytes read at most.
const MAX_FILE: u64 = 64 << 20;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: u32 = 100_000;

impl Extractor for Assets {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let be16 = |at: usize| h.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        let format = match probe.extension? {
            "atn" if h.starts_with(&[0, 0, 0, 16]) => "photoshop_actions",
            "abr" if matches!(be16(0), Some(1 | 2 | 6 | 7 | 10)) => "photoshop_brushes",
            "aco" if matches!(be16(0), Some(1 | 2)) => "photoshop_swatches",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let n = usize::try_from(src.len().min(MAX_FILE)).unwrap_or(0);
        if src.len() > MAX_FILE {
            cx.warn("file cut at 64 MiB");
        }
        let d = src.read_vec(0, n)?;
        let mut names = Names::default();
        match cx.format_id() {
            "photoshop_actions" => actions(&d, cx)?,
            "photoshop_brushes" => brushes(&d, &mut names, cx)?,
            "photoshop_swatches" => aco(&d, cx)?,
            "ase_swatches" => ase(&d, cx)?,
            "photoshop_gradients" => gradients(&d, &mut names, cx)?,
            "photoshop_patterns" => patterns(&d, cx)?,
            other => return Err(ExtractError::Unsupported(format!("format {other}"))),
        }
        if !names.0.is_empty() {
            cx.format_set("names", json!(names.0));
        }
        Ok(())
    }
}

crate::register_extractor!(Assets);

#[derive(Default)]
struct Names(Vec<String>);

impl Names {
    fn push(&mut self, s: String) {
        if self.0.len() < MAX_LISTED && !s.is_empty() {
            self.0.push(s);
        }
    }
}

/// A Photoshop Unicode string: a code-unit count, then UTF-16BE (trailing NUL dropped).
fn unicode(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    let n = r.be_u32()? as usize;
    let b = r.bytes(n.checked_mul(2).ok_or_else(|| ExtractError::malformed("string length"))?)?;
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    Ok(truncate_chars(String::from_utf16_lossy(&units).trim_end_matches('\0'), 500))
}

/// A descriptor key or class id: a length, or 0 then a four-character code.
fn key(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    let n = r.be_u32()? as usize;
    let b = r.bytes(if n == 0 { 4 } else { n })?;
    Ok(String::from_utf8_lossy(b).into_owned())
}

/// Walk an action descriptor, collecting `Nm  ` text values.
fn descriptor(r: &mut ByteReader<'_>, depth: usize, names: &mut Names) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::LimitExceeded("descriptor nesting".into()));
    }
    unicode(r)?;
    key(r)?;
    let count = r.be_u32()?;
    if count > MAX_ITEMS {
        return Err(ExtractError::malformed(format!("descriptor with {count} items")));
    }
    for _ in 0..count {
        let k = key(r)?;
        let t = r.array::<4>()?;
        value(r, t, &k, depth, names)?;
    }
    Ok(())
}

fn value(r: &mut ByteReader<'_>, t: [u8; 4], k: &str, depth: usize, names: &mut Names) -> Result<(), ExtractError> {
    match &t {
        b"obj " => reference(r)?,
        b"Objc" | b"GlbO" => descriptor(r, depth + 1, names)?,
        b"VlLs" => {
            let n = r.be_u32()?;
            if n > MAX_ITEMS {
                return Err(ExtractError::malformed(format!("list of {n} items")));
            }
            for _ in 0..n {
                let t = r.array::<4>()?;
                value(r, t, k, depth + 1, names)?;
            }
        }
        b"doub" | b"comp" => r.advance(8)?,
        b"UntF" => r.advance(12)?,
        b"long" => r.advance(4)?,
        b"bool" => r.advance(1)?,
        b"TEXT" => {
            let s = unicode(r)?;
            if k == "Nm  " {
                names.push(s);
            }
        }
        b"enum" => {
            key(r)?;
            key(r)?;
        }
        b"type" | b"GlbC" => {
            unicode(r)?;
            key(r)?;
        }
        b"alis" | b"tdta" | b"Pth " => {
            let n = r.be_u32()? as usize;
            r.advance(n)?;
        }
        b"UnFl" => {
            r.advance(4)?;
            let n = r.be_u32()? as usize;
            r.advance(n.checked_mul(8).ok_or_else(|| ExtractError::malformed("unit list"))?)?;
        }
        _ => return Err(ExtractError::malformed(format!("descriptor value type {}", String::from_utf8_lossy(&t)))),
    }
    Ok(())
}

fn reference(r: &mut ByteReader<'_>) -> Result<(), ExtractError> {
    let n = r.be_u32()?;
    if n > MAX_ITEMS {
        return Err(ExtractError::malformed(format!("reference of {n} items")));
    }
    for _ in 0..n {
        match &r.array::<4>()? {
            b"prop" => {
                unicode(r)?;
                key(r)?;
                key(r)?;
            }
            b"Clss" => {
                unicode(r)?;
                key(r)?;
            }
            b"Enmr" => {
                unicode(r)?;
                key(r)?;
                key(r)?;
                key(r)?;
            }
            b"rele" => {
                unicode(r)?;
                key(r)?;
                r.advance(4)?;
            }
            b"Idnt" | b"indx" => r.advance(4)?,
            b"name" => {
                unicode(r)?;
                key(r)?;
                unicode(r)?;
            }
            t => return Err(ExtractError::malformed(format!("reference type {}", String::from_utf8_lossy(t)))),
        }
    }
    Ok(())
}

// ---- actions -----------------------------------------------------------------------

/// An event or dictionary name in an actions file: `TEXT` + length + bytes, or `long` + four bytes.
fn event(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    match &r.array::<4>()? {
        b"TEXT" => {
            let n = r.be_u32()? as usize;
            Ok(String::from_utf8_lossy(r.bytes(n)?).into_owned())
        }
        b"long" => Ok(String::from_utf8_lossy(r.bytes(4)?).into_owned()),
        t => Err(ExtractError::malformed(format!("event type {}", String::from_utf8_lossy(t)))),
    }
}

fn actions(d: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d);
    let version = r.be_u32()?;
    cx.format_set("version", version);
    let set = unicode(&mut r)?;
    r.advance(1)?;
    let count = r.be_u32()?;
    cx.format_set("set", set);
    cx.format_set("action_count", count);
    let mut list = Vec::new();
    let mut commands_total = 0u64;
    let mut events: BTreeMap<String, u64> = BTreeMap::new();
    let mut scratch = Names::default();
    for _ in 0..count.min(MAX_ITEMS) {
        r.advance(6)?;
        let name = unicode(&mut r)?;
        r.advance(1)?;
        let n = r.be_u32()?;
        let mut cmds = Vec::new();
        for _ in 0..n.min(MAX_ITEMS) {
            r.advance(4)?;
            event(&mut r)?;
            let label = {
                let n = r.be_u32()? as usize;
                String::from_utf8_lossy(r.bytes(n)?).into_owned()
            };
            if r.be_i32()? == -1 {
                r.advance(4)?; // descriptor version (16)
                descriptor(&mut r, 0, &mut scratch)?;
            }
            *events.entry(label.clone()).or_default() += 1;
            if cmds.len() < MAX_LISTED {
                cmds.push(json!(label));
            }
            commands_total += 1;
        }
        if list.len() < MAX_LISTED {
            list.push(json!({ "name": name, "commands": cmds }));
        }
    }
    cx.format_set("actions", Value::Array(list));
    cx.format_set("commands", commands_total);
    Ok(())
}

// ---- brushes ------------------------------------------------------------------------

fn brushes(d: &[u8], names: &mut Names, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d);
    let version = r.be_u16()?;
    cx.format_set("version", version);
    if matches!(version, 1 | 2) {
        let count = r.be_u16()?;
        let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
        for _ in 0..count {
            let kind = r.be_u16()?;
            let size = r.be_u32()? as usize;
            let body = r.bytes(size)?;
            *kinds.entry(if kind == 1 { "computed" } else { "sampled" }).or_default() += 1;
            if kind == 2 && version == 2 {
                let mut b = ByteReader::new(body).skip(6)?;
                names.push(unicode(&mut b)?);
            }
        }
        cx.format_set("brushes", count);
        cx.format_set("kinds", json!(kinds));
        return Ok(());
    }
    let sub = r.be_u16()?;
    cx.format_set("subversion", sub);
    let mut sections = Vec::new();
    while r.remaining() >= 12 {
        r.tag(b"8BIM")?;
        let k = r.array::<4>()?;
        let len = r.be_u32()? as usize;
        let body = r.bytes(len.min(r.remaining()))?;
        let k = String::from_utf8_lossy(&k).into_owned();
        match k.as_str() {
            "samp" => {
                let mut s = ByteReader::new(body);
                let mut n = 0u64;
                while s.remaining() >= 4 {
                    let l = s.be_u32()? as usize;
                    s.advance((l + 3) & !3)?;
                    n += 1;
                }
                cx.format_set("sampled_brushes", n);
            }
            "desc" => {
                let mut s = ByteReader::new(body).skip(4)?;
                descriptor(&mut s, 0, names)?;
            }
            _ => {}
        }
        sections.push(json!(k));
        if len % 2 == 1 && r.remaining() > 0 {
            r.advance(1)?;
        }
    }
    cx.format_set("sections", Value::Array(sections));
    if !names.0.is_empty() {
        cx.format_set("brushes", names.0.len());
    }
    Ok(())
}

// ---- swatches -----------------------------------------------------------------------

fn color_space(s: u16) -> &'static str {
    match s {
        0 => "RGB",
        1 => "HSB",
        2 => "CMYK",
        3 => "Pantone",
        4 => "Focoltone",
        5 => "Trumatch",
        6 => "Toyo",
        7 => "Lab",
        8 => "grayscale",
        9 => "wide CMYK",
        10 => "HKS",
        _ => "other",
    }
}

fn aco(d: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d);
    let mut versions = Vec::new();
    let mut names = Names::default();
    let mut spaces: BTreeMap<&str, u64> = BTreeMap::new();
    let mut count = 0;
    while r.remaining() >= 4 {
        let version = r.be_u16()?;
        if !matches!(version, 1 | 2) {
            return Err(ExtractError::malformed(format!("swatch block version {version}")));
        }
        count = r.be_u16()?;
        for _ in 0..count {
            let space = r.be_u16()?;
            r.advance(8)?;
            if version == 2 {
                names.push(unicode(&mut r)?);
            } else {
                *spaces.entry(color_space(space)).or_default() += 1;
            }
        }
        versions.push(version);
    }
    cx.format_set("versions", json!(versions));
    cx.format_set("colors", count);
    cx.format_set("color_spaces", json!(spaces));
    if !names.0.is_empty() {
        cx.format_set("names", json!(names.0));
    }
    Ok(())
}

fn ase(d: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d).skip(4)?;
    let (major, minor) = (r.be_u16()?, r.be_u16()?);
    let blocks = r.be_u32()?;
    cx.format_set("version", format!("{major}.{minor}"));
    let mut colors = Names::default();
    let mut groups = Names::default();
    let mut models: BTreeMap<String, u64> = BTreeMap::new();
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    let mut n_colors = 0u64;
    for _ in 0..blocks.min(MAX_ITEMS) {
        let kind = r.be_u16()?;
        let len = r.be_u32()? as usize;
        let body = r.bytes(len)?;
        let mut b = ByteReader::new(body);
        match kind {
            0xc001 => groups.push(ase_name(&mut b)?),
            0x0001 => {
                colors.push(ase_name(&mut b)?);
                let model = String::from_utf8_lossy(b.bytes(4)?).trim().to_string();
                let floats = match model.as_str() {
                    "CMYK" => 4,
                    "RGB" | "LAB" => 3,
                    _ => 1,
                };
                b.advance(4 * floats)?;
                let t = b.be_u16()?;
                *kinds
                    .entry(match t {
                        0 => "global",
                        1 => "spot",
                        _ => "normal",
                    })
                    .or_default() += 1;
                *models.entry(model).or_default() += 1;
                n_colors += 1;
            }
            _ => {}
        }
    }
    cx.format_set("colors", n_colors);
    cx.format_set("color_models", json!(models));
    cx.format_set("color_types", json!(kinds));
    if !groups.0.is_empty() {
        cx.format_set("groups", json!(groups.0));
    }
    if !colors.0.is_empty() {
        cx.format_set("names", json!(colors.0));
    }
    Ok(())
}

/// An ASE name: a UTF-16 code-unit count (NUL included) and UTF-16BE.
fn ase_name(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    let n = usize::from(r.be_u16()?);
    let b = r.bytes(n * 2)?;
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    Ok(truncate_chars(String::from_utf16_lossy(&units).trim_end_matches('\0'), 500))
}

// ---- gradients and patterns ---------------------------------------------------------

fn gradients(d: &[u8], names: &mut Names, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d).skip(4)?;
    let version = r.be_u16()?;
    cx.format_set("version", version);
    if version == 5 {
        r.advance(4)?; // descriptor version (16)
        descriptor(&mut r, 0, names)?;
        cx.format_set("gradients", names.0.len());
    } else {
        let count = r.be_u16()?;
        cx.format_set("gradients", count);
        if count > 0 {
            let n = usize::from(r.u8()?);
            names.push(String::from_utf8_lossy(r.bytes(n)?).into_owned());
        }
    }
    Ok(())
}

fn image_mode(m: u32) -> &'static str {
    match m {
        0 => "bitmap",
        1 => "grayscale",
        2 => "indexed",
        3 => "RGB",
        4 => "CMYK",
        7 => "multichannel",
        8 => "duotone",
        9 => "Lab",
        _ => "other",
    }
}

fn patterns(d: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d).skip(4)?;
    let version = r.be_u16()?;
    let count = r.be_u32()?;
    cx.format_set("version", version);
    cx.format_set("patterns", count);
    let mut list = Vec::new();
    for _ in 0..count.min(MAX_ITEMS) {
        r.advance(4)?;
        let mode = r.be_u32()?;
        let (h, w) = (r.be_u16()?, r.be_u16()?);
        let name = unicode(&mut r)?;
        let id_len = usize::from(r.u8()?);
        let id = String::from_utf8_lossy(r.bytes(id_len)?).into_owned();
        if mode == 2 {
            r.advance(256 * 3)?;
        }
        r.advance(4)?; // virtual memory array list version (3)
        let len = r.be_u32()? as usize;
        r.advance(len)?;
        if list.len() < MAX_LISTED {
            let mut m = Map::new();
            m.insert("name".into(), json!(name));
            m.insert("id".into(), json!(id));
            m.insert("width".into(), json!(w));
            m.insert("height".into(), json!(h));
            m.insert("mode".into(), json!(image_mode(mode)));
            list.push(Value::Object(m));
        }
    }
    cx.format_set("items", Value::Array(list));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().chain([0]).collect();
        let mut v = u32::try_from(units.len()).unwrap().to_be_bytes().to_vec();
        for c in units {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v
    }

    #[test]
    fn descriptor_names() {
        // class "" / "null", two items: Nm  TEXT "Sea", Ofst long 1.
        let mut d = u("");
        d.extend_from_slice(b"\0\0\0\0null\0\0\0\x02");
        d.extend_from_slice(b"\0\0\0\0Nm  TEXT");
        d.extend_from_slice(&u("Sea"));
        d.extend_from_slice(b"\0\0\0\0Ofstlong\0\0\0\x01");
        let mut names = Names::default();
        descriptor(&mut ByteReader::new(&d), 0, &mut names).unwrap();
        assert_eq!(names.0, ["Sea"]);
        let mut bad = d.clone();
        let n = bad.len();
        bad[n - 8..n - 4].copy_from_slice(b"zzzz");
        assert!(descriptor(&mut ByteReader::new(&bad), 0, &mut Names::default()).is_err());
    }

    crate::fixture_tests!(
        "photoshop_actions",
        "photoshop_brushes",
        "photoshop_swatches",
        "ase_swatches",
        "photoshop_gradients",
        "photoshop_patterns"
    );
}
