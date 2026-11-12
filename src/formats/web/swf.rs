//! Shockwave Flash (`.swf`): uncompressed (`FWS`), zlib (`CWS`) and LZMA
//! (`ZWS`) files. The header gives the SWF version, stage size, frame rate
//! and frame count; the tag walk gives the file attributes (`ActionScript`
//! 3, network access, GPU), the background colour, the XMP metadata
//! (handed to the XMP decoder), the compiler (`ProductInfo`: Flex SDK,
//! build, compile time), the main class and other symbols, exported and
//! imported assets, frame labels and scenes, `ActionScript` blocks, whether
//! a debugger is enabled or import is protected, and definitions by kind
//! (shapes, sprites, bitmaps, fonts, sounds, videos, binary data).
//!
//! Specification: Adobe "SWF File Format Specification" version 19.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::super::bytecode::longtail;

use crate::plugin::{
    BlockKind, Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
    truncate_chars,
};

/// Extractor for SWF files.
pub struct Swf;

static META: ExtractorMeta = ExtractorMeta {
    id: "web.swf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "swf",
        name: "Shockwave Flash",
        family: "web.misc",
        mimes: &["application/x-shockwave-flash"],
        extensions: &["swf"],
        magic: &[Magic::prefix(b"FWS"), Magic::prefix(b"CWS"), Magic::prefix(b"ZWS")],
        parent: None,
    }],
};

/// Bodies beyond this are not inflated (the tags of interest come first).
const MAX_BODY: usize = 64 << 20;

impl Extractor for Swf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        if data.len() < 8 {
            return Err(ExtractError::Truncated { offset: 0, needed: 8 });
        }
        let version = data[3];
        let declared = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let want = usize::try_from(declared).unwrap_or(usize::MAX).saturating_sub(8).min(MAX_BODY);
        let (compression, body) = match &data[..3] {
            b"CWS" => ("zlib", cx.decompress(&data[8..], Codec::Zlib, want)?.data),
            b"ZWS" => {
                let p = data.get(12..17).ok_or(ExtractError::Truncated { offset: 12, needed: 5 })?;
                let codec = Codec::Lzma {
                    props: p[0],
                    dict_size: u32::from_le_bytes([p[1], p[2], p[3], p[4]]),
                    size: Some(want as u64),
                };
                ("lzma", cx.decompress(&data[17..], codec, want)?.data)
            }
            _ => ("none", data[8..].to_vec()),
        };
        cx.format_set("version", version);
        cx.format_set("compression", compression);
        cx.format_set("file_length", declared);
        cx.physical().uncompressed_bytes(u64::from(declared));
        let (rect, at) = rect(&body).ok_or(ExtractError::Truncated { offset: 8, needed: 1 })?;
        let (w, h) = ((rect[1] - rect[0]) / 20, (rect[3] - rect[2]) / 20);
        let rate = body.get(at..at + 2).map_or(0.0, |r| f64::from(u16::from_le_bytes([r[0], r[1]])) / 256.0);
        let frames = body.get(at + 2..at + 4).map_or(0, |r| u16::from_le_bytes([r[0], r[1]]));
        cx.format_set("stage", json!({ "width": w, "height": h }));
        cx.format_set("frame_rate", (rate * 100.0).round() / 100.0);
        cx.format_set("frame_count", frames);
        if let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h)) {
            cx.physical().image(w, h).frames(u32::from(frames));
        }
        if rate > 0.0 {
            cx.physical().duration_s((f64::from(frames) / rate * 1000.0).round() / 1000.0);
        }
        tags(&body[(at + 4).min(body.len())..], cx)
    }
}

crate::register_extractor!(Swf);

/// The stage `RECT` (twips: xmin, xmax, ymin, ymax) and the offset after it.
fn rect(b: &[u8]) -> Option<([i64; 4], usize)> {
    let nbits = usize::from(*b.first()? >> 3);
    let total = 5 + 4 * nbits;
    let bytes = total.div_ceil(8);
    if b.len() < bytes {
        return None;
    }
    let bit = |i: usize| (b[i / 8] >> (7 - i % 8)) & 1;
    let mut out = [0i64; 4];
    for (k, v) in out.iter_mut().enumerate() {
        let start = 5 + k * nbits;
        let mut x: i64 = 0;
        for i in 0..nbits {
            x = (x << 1) | i64::from(bit(start + i));
        }
        // Signed: sign-extend from `nbits`.
        if nbits > 0 && x >> (nbits - 1) & 1 == 1 {
            x -= 1 << nbits;
        }
        *v = x;
    }
    Some((out, bytes))
}

fn cstr(b: &[u8]) -> (String, usize) {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    (String::from_utf8_lossy(&b[..end]).into_owned(), (end + 1).min(b.len()))
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

/// The definition kind a tag code adds, for the histogram.
fn definition(code: u16) -> Option<&'static str> {
    Some(match code {
        2 | 22 | 32 | 83 => "shapes",
        46 | 84 => "morph_shapes",
        39 => "sprites",
        6 | 21 | 35 | 90 | 20 | 36 => "bitmaps",
        10 | 48 | 75 | 91 => "fonts",
        11 | 33 | 37 => "texts",
        7 | 34 => "buttons",
        14 => "sounds",
        60 => "videos",
        87 => "binary_data",
        _ => return None,
    })
}

#[allow(clippy::too_many_lines)] // one arm per tag
fn tags(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut defs: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut pos, mut count) = (0usize, 0u64);
    let (mut symbols, mut exports, mut imports, mut labels, mut abc) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut actions, mut binary_bytes) = (0u64, 0u64);
    let mut flags = Map::new();
    let mut main_class = None;
    let mut classes = Vec::new();
    while pos + 2 <= b.len() {
        if count % 4096 == 0 {
            cx.checkpoint()?;
        }
        let header = u16::from_le_bytes([b[pos], b[pos + 1]]);
        let (code, mut len) = (header >> 6, usize::from(header & 0x3f));
        pos += 2;
        if len == 0x3f {
            len = u32_at(b, pos).and_then(|l| usize::try_from(l).ok()).unwrap_or(usize::MAX);
            pos += 4;
        }
        let Some(t) = b.get(pos..pos.saturating_add(len)) else {
            cx.warn(format!("tag {code} runs past the end"));
            break;
        };
        pos += len;
        count += 1;
        if let Some(k) = definition(code) {
            *defs.entry(k).or_default() += 1;
        }
        match code {
            0 => break,
            9 if t.len() >= 3 => {
                cx.format_set("background_color", format!("#{:02x}{:02x}{:02x}", t[0], t[1], t[2]));
            }
            12 | 59 => actions += 1,
            24 => {
                flags.insert("import_protected".into(), json!(true));
            }
            41 if t.len() >= 26 => {
                let product = match u32_at(t, 0) {
                    Some(1) => "Macromedia Flex for J2EE",
                    Some(2) => "Macromedia Flex for .NET",
                    Some(3) => "Adobe Flex",
                    _ => "unknown",
                };
                let edition = [
                    "Developer",
                    "Full Commercial",
                    "Non-Commercial",
                    "Educational",
                    "Not For Resale",
                    "Trial",
                    "None",
                ]
                .get(u32_at(t, 4).and_then(|e| usize::try_from(e).ok()).unwrap_or(99))
                .copied()
                .unwrap_or("unknown");
                let build = u64::from(u32_at(t, 10).unwrap_or(0)) | (u64::from(u32_at(t, 14).unwrap_or(0)) << 32);
                cx.format_set(
                    "product",
                    json!({ "name": product, "edition": edition, "version": format!("{}.{}.{build}", t[8], t[9]) }),
                );
                let ms =
                    t.get(18..26).map_or(0, |d| u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]));
                if let Some(at) = i64::try_from(ms / 1000).ok().and_then(super::unix_time) {
                    cx.temporal().content_date(DateField::Created, at, true);
                }
            }
            43 => {
                if labels.len() < 100 {
                    labels.push(truncate_chars(&cstr(t).0, 200));
                }
            }
            56 => named_list(t, &mut exports),
            57 | 71 => {
                let (url, _) = cstr(t);
                imports.push(truncate_chars(&url, 300));
            }
            58 | 64 => {
                flags.insert("debugger_enabled".into(), json!(true));
            }
            65 if t.len() >= 4 => {
                cx.format_set(
                    "script_limits",
                    json!({ "max_recursion_depth": u16_at(t, 0), "timeout_s": u16_at(t, 2) }),
                );
            }
            69 if !t.is_empty() => {
                for (bit, name) in [
                    (0x40, "use_direct_blit"),
                    (0x20, "use_gpu"),
                    (0x10, "has_metadata"),
                    (0x08, "actionscript3"),
                    (0x01, "use_network"),
                ] {
                    flags.insert(name.into(), json!(t[0] & bit != 0));
                }
            }
            76 => {
                let mut list = Vec::new();
                named_list(t, &mut list);
                for (id, name) in &list {
                    if *id == 0 {
                        main_class = Some(name.clone());
                    }
                }
                symbols.extend(list);
            }
            77 => {
                let (xmp, _) = cstr(t);
                cx.emit_block(BlockKind::XMP, xmp.into_bytes());
            }
            72 | 82 => {
                let (name, body) = if code == 82 {
                    let rest = t.get(4..).unwrap_or(&[]);
                    let (name, used) = cstr(rest);
                    (name, &rest[used..])
                } else {
                    (String::new(), t)
                };
                abc.push(truncate_chars(&name, 200));
                if let Some(parsed) = longtail::abc(body) {
                    classes.extend(parsed.classes);
                }
            }
            86 => {
                if let Some(scenes) = scenes(t) {
                    cx.format_set("scenes", json!(scenes));
                }
            }
            87 => binary_bytes += t.len().saturating_sub(6) as u64,
            93 => {
                flags.insert("telemetry".into(), json!(true));
            }
            _ => {}
        }
    }
    cx.format_set("tags", count);
    if !flags.is_empty() {
        cx.format_set("attributes", Value::Object(flags));
    }
    if !defs.is_empty() {
        cx.format_set("definitions", json!(defs));
    }
    if let Some(m) = main_class {
        cx.format_set("main_class", m);
    }
    if !symbols.is_empty() {
        cx.format_set("symbols", json!(symbols.iter().take(100).map(|(_, n)| n).collect::<Vec<_>>()));
    }
    if !exports.is_empty() {
        cx.format_set("exports", json!(exports.iter().take(100).map(|(_, n)| n).collect::<Vec<_>>()));
    }
    if !imports.is_empty() {
        cx.security().external_references(imports.len() as u64);
        cx.format_set("imports", json!(imports));
    }
    if !labels.is_empty() {
        cx.format_set("frame_labels", json!(labels));
    }
    // ActionScript 3 lives in DoABC; versions 1 and 2 in DoAction.
    if !abc.is_empty() || actions > 0 {
        cx.security().active_content("actionscript");
        let mut s = Map::new();
        if !abc.is_empty() {
            s.insert("abc_blocks".into(), json!(abc.len()));
            let named: Vec<&String> = abc.iter().filter(|n| !n.is_empty()).take(50).collect();
            if !named.is_empty() {
                s.insert("abc_names".into(), json!(named));
            }
        }
        if actions > 0 {
            s.insert("action_blocks".into(), json!(actions));
        }
        s.insert("language".into(), json!(if abc.is_empty() { "ActionScript 1/2" } else { "ActionScript 3" }));
        if !classes.is_empty() {
            classes.truncate(100);
            longtail::Abc::with_classes(classes).write_classes(&mut s);
        }
        cx.format_set("scripts", Value::Object(s));
    }
    if binary_bytes > 0 {
        cx.format_set("binary_data_bytes", binary_bytes);
    }
    Ok(())
}

/// `count: u16`, then `(id: u16, name: string)` pairs (`ExportAssets`, `SymbolClass`).
fn named_list(t: &[u8], out: &mut Vec<(u16, String)>) {
    let n = u16_at(t, 0).unwrap_or(0);
    let mut at = 2;
    for _ in 0..n {
        let Some(id) = u16_at(t, at) else { break };
        let (name, used) = cstr(&t[at + 2..]);
        at += 2 + used;
        if out.len() < 1000 {
            out.push((id, truncate_chars(&name, 200)));
        }
        if at >= t.len() {
            break;
        }
    }
}

/// `DefineSceneAndFrameLabelData`: the scene names.
fn scenes(t: &[u8]) -> Option<Vec<String>> {
    fn encoded_u32(t: &[u8], at: &mut usize) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..5 {
            let b = *t.get(*at)?;
            *at += 1;
            v |= u32::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                break;
            }
        }
        Some(v)
    }
    let mut at = 0;
    let n = encoded_u32(t, &mut at)?;
    let mut out = Vec::new();
    for _ in 0..n.min(100) {
        encoded_u32(t, &mut at)?;
        let (name, used) = cstr(t.get(at..)?);
        at += used;
        out.push(truncate_chars(&name, 200));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_rect() {
        // nbits = 15: 0, 11000 (550 px), 0, 8000 (400 px).
        let b = [0x78, 0x00, 0x05, 0x5f, 0x00, 0x00, 0x0f, 0xa0, 0x00];
        assert_eq!(rect(&b), Some(([0, 11000, 0, 8000], 9)));
    }

    #[test]
    fn symbol_list() {
        let mut v = Vec::new();
        named_list(b"\x02\x00\x00\x00Main\x00\x05\x00Boat\x00", &mut v);
        assert_eq!(v, [(0, "Main".to_string()), (5, "Boat".to_string())]);
        assert_eq!(scenes(b"\x01\x00Harbour\x00"), Some(vec!["Harbour".to_string()]));
    }

    crate::fixture_tests!("swf");
}
