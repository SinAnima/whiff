//! 2D / 3D drawings:
//! * `AutoCAD` DXF, ASCII and binary: the release (`$ACADVER`), code page,
//!   units, extents, creation and update times, layers, blocks, entities
//!   by type, layouts, images and external references, and the drawing's
//!   text (`TEXT`, `MTEXT`, attributes) into the text pipeline;
//! * `MicroStation` DGN v7: 2D / 3D, element types and levels.
//!
//! Specifications: Autodesk DXF Reference (2018); `MicroStation` DGN v7 as
//! documented by GDAL's DGN library (Frank Warmerdam, `dgnlib`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{Box3, bump, hist};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, truncate_chars,
};

/// Extractor for drawings.
pub struct Drawing;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.drawing",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "dxf",
            name: "AutoCAD DXF",
            family: "cad",
            mimes: &["image/vnd.dxf"],
            extensions: &["dxf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "dxf_binary",
            name: "AutoCAD binary DXF",
            family: "cad",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::at(0, b"AutoCAD Binary DXF\r\n\x1a\x00")],
            parent: None,
        },
        FormatSpec {
            id: "dgn",
            name: "MicroStation DGN",
            family: "cad",
            mimes: &[],
            extensions: &["dgn"],
            magic: &[],
            parent: None,
        },
    ],
};

/// The release of an `$ACADVER` code.
fn release(v: &str) -> &'static str {
    match v {
        "AC1006" => "R10",
        "AC1009" => "R11/R12",
        "AC1012" => "R13",
        "AC1014" => "R14",
        "AC1015" => "2000",
        "AC1018" => "2004",
        "AC1021" => "2007",
        "AC1024" => "2010",
        "AC1027" => "2013",
        "AC1032" => "2018",
        _ => "unknown",
    }
}

/// `$INSUNITS`.
fn units(code: i64) -> &'static str {
    match code {
        0 => "unitless",
        1 => "inches",
        2 => "feet",
        3 => "miles",
        4 => "millimeters",
        5 => "centimeters",
        6 => "meters",
        7 => "kilometers",
        8 => "microinches",
        9 => "mils",
        10 => "yards",
        13 => "microns",
        14 => "decimeters",
        _ => "other",
    }
}

/// A Julian date (`$TDCREATE`) as ISO 8601 (local time: DXF stores no zone).
fn julian(d: f64) -> Option<String> {
    if !(2_000_000.0..3_000_000.0).contains(&d) {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)] // seconds of a date
    let unix = ((d - 2_440_587.5) * 86_400.0).round() as i64;
    let t = jiff::Timestamp::from_second(unix).ok()?;
    Some(t.strftime("%Y-%m-%dT%H:%M:%S").to_string())
}

/// Group code / value pairs of ASCII or binary DXF.
fn pairs(b: &[u8], binary: bool) -> Vec<(i32, String)> {
    let mut out = Vec::new();
    if binary {
        let mut at = 22;
        while at + 2 <= b.len() && out.len() < 50_000_000 {
            let code = i32::from(u16::from_le_bytes([b[at], b[at + 1]]));
            at += 2;
            // Value types by code range (DXF reference, "Group code value types").
            let v = match code {
                0..=9
                | 100..=102
                | 105
                | 300..=309
                | 320..=369
                | 390..=399
                | 410..=419
                | 430..=439
                | 470..=481
                | 999
                | 1000..=1003
                | 1005..=1009 => {
                    let e = b[at..].iter().position(|&c| c == 0).map_or(b.len(), |i| at + i);
                    let s = String::from_utf8_lossy(&b[at..e]).into_owned();
                    at = e + 1;
                    s
                }
                10..=59 | 110..=149 | 210..=239 | 460..=469 | 1010..=1059 => {
                    let Some(r) = b.get(at..at + 8) else { break };
                    at += 8;
                    f64::from_le_bytes(r.try_into().unwrap_or_default()).to_string()
                }
                60..=79 | 170..=179 | 270..=289 | 370..=389 | 400..=409 | 1060..=1070 => {
                    let Some(r) = b.get(at..at + 2) else { break };
                    at += 2;
                    i16::from_le_bytes([r[0], r[1]]).to_string()
                }
                90..=99 | 420..=429 | 440..=459 | 1071 => {
                    let Some(r) = b.get(at..at + 4) else { break };
                    at += 4;
                    i32::from_le_bytes([r[0], r[1], r[2], r[3]]).to_string()
                }
                160..=169 => {
                    at += 8;
                    String::new()
                }
                290..=299 => {
                    at += 1;
                    String::new()
                }
                310..=319 | 1004 => {
                    let n = usize::from(*b.get(at).unwrap_or(&0));
                    at += 1 + n;
                    String::new()
                }
                _ => break,
            };
            out.push((code, v));
        }
    } else {
        let text = String::from_utf8_lossy(b);
        let mut lines = text.lines();
        while out.len() < 50_000_000 {
            let (Some(c), Some(v)) = (lines.next(), lines.next()) else { break };
            let Ok(code) = c.trim().parse::<i32>() else { break };
            out.push((code, v.trim_end_matches('\r').to_string()));
        }
    }
    out
}

/// MTEXT formatting codes removed: `\P` breaks, `{\fArial;…}` groups.
fn mtext_plain(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('P' | '~') => out.push(' '),
                Some('\\') => out.push('\\'),
                Some('{') => out.push('{'),
                Some('}') => out.push('}'),
                // \f…; \H…; \C…; and similar take arguments up to ';'.
                Some(_) => {
                    for d in chars.by_ref() {
                        if d == ';' {
                            break;
                        }
                    }
                }
                None => {}
            },
            '{' | '}' => {}
            _ => out.push(c),
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // the sections, one after the other
fn dxf(cx: &mut Context<'_>, b: &[u8], binary: bool) {
    let p = pairs(b, binary);
    let mut section = String::new();
    let mut header = Map::new();
    let mut var = String::new();
    let (mut ext_min, mut ext_max) = ([f64::NAN; 3], [f64::NAN; 3]);
    let mut layers = Vec::new();
    let mut blocks = Vec::new();
    let mut entities: BTreeMap<String, u64> = BTreeMap::new();
    let mut layouts = BTreeSet::new();
    let mut table = String::new();
    let mut kind = String::new();
    let mut images = BTreeSet::new();
    let mut texts = 0u64;
    let mut text_chars = 0usize;
    let mut i = 0;
    while i < p.len() {
        let (code, v) = (&p[i].0, p[i].1.as_str());
        i += 1;
        if *code == 0 {
            match v {
                "SECTION" => {
                    if let Some((2, name)) = p.get(i).map(|x| (x.0, x.1.clone())) {
                        section = name;
                        i += 1;
                    }
                    continue;
                }
                "ENDSEC" => {
                    section.clear();
                    continue;
                }
                "TABLE" => {
                    if let Some((2, name)) = p.get(i).map(|x| (x.0, x.1.clone())) {
                        table = name;
                    }
                }
                _ => {}
            }
            kind = v.to_string();
            if section == "ENTITIES" {
                bump(&mut entities, v, 200);
            }
            continue;
        }
        match section.as_str() {
            "HEADER" => {
                if code == &9 {
                    var = v.to_string();
                } else {
                    let k = var.as_str();
                    match k {
                        "$EXTMIN" | "$EXTMAX" => {
                            let target = if k == "$EXTMIN" { &mut ext_min } else { &mut ext_max };
                            if let 10 | 20 | 30 = code {
                                target[usize::try_from(code / 10 - 1).unwrap_or(0)] =
                                    v.trim().parse().unwrap_or(f64::NAN);
                            }
                        }
                        "$ACADVER" | "$DWGCODEPAGE" | "$PROJECTNAME" | "$FINGERPRINTGUID" | "$VERSIONGUID"
                        | "$ACADMAINTVER" | "$MEASUREMENT" => {
                            header.insert(
                                k.trim_start_matches('$').to_ascii_lowercase(),
                                truncate_chars(v.trim(), 100).into(),
                            );
                        }
                        "$INSUNITS" => {
                            header.insert("units".into(), units(v.trim().parse().unwrap_or(-1)).into());
                        }
                        "$TDCREATE" | "$TDUPDATE" => {
                            if let Some(d) = v.trim().parse::<f64>().ok().and_then(julian) {
                                let created = k == "$TDCREATE";
                                header.insert(if created { "created" } else { "updated" }.into(), d.clone().into());
                                cx.temporal().source(format!("dxf.{k}")).content_date(
                                    if created { DateField::Created } else { DateField::Modified },
                                    d,
                                    false,
                                );
                            }
                        }
                        "$LASTSAVEDBY" if !cx.privacy_strict() => {
                            header.insert("last_saved_by".into(), truncate_chars(v.trim(), 60).into());
                        }
                        _ => {}
                    }
                }
            }
            "TABLES" if *code == 2 && kind == table && table == "LAYER" && layers.len() < 1000 => {
                layers.push(truncate_chars(v, 100));
            }
            "BLOCKS" if *code == 2 && kind == "BLOCK" && !v.starts_with('*') && blocks.len() < 1000 => {
                blocks.push(truncate_chars(v, 100));
            }
            "OBJECTS" if *code == 1 && kind == "LAYOUT" && layouts.len() < 200 => {
                layouts.insert(truncate_chars(v, 60));
            }
            "OBJECTS" if *code == 1 && kind == "IMAGEDEF" && images.len() < 100 => {
                images.insert(truncate_chars(v.rsplit(['/', '\\']).next().unwrap_or(v), 100));
            }
            "ENTITIES" | "BLOCKS"
                if matches!(*code, 1 | 3)
                    && matches!(kind.as_str(), "TEXT" | "MTEXT" | "ATTRIB" | "ATTDEF" | "DIMENSION") =>
            {
                let s = if kind == "MTEXT" { mtext_plain(v) } else { v.to_string() };
                let s = s.trim();
                if !s.is_empty() && text_chars < 1 << 20 {
                    texts += u64::from(*code == 1);
                    text_chars += s.len();
                    cx.emit_text(TextRole::Body, s);
                }
            }
            _ => {}
        }
    }
    if let Some(v) = header.get("acadver").and_then(Value::as_str) {
        header.insert("release".into(), release(v).into());
    }
    cx.format_set("encoding", if binary { "binary" } else { "ascii" });
    cx.format_set("header", Value::Object(header));
    if ext_min.iter().chain(&ext_max).all(|v| v.is_finite()) && ext_min[0] <= ext_max[0] {
        let mut bx = Box3::default();
        bx.add(ext_min);
        bx.add(ext_max);
        bx.report(cx, "extents");
    }
    cx.format_set("layer_count", layers.len());
    cx.format_set("layers", layers);
    cx.format_set("blocks", blocks);
    cx.format_set("entities", hist(entities));
    if !layouts.is_empty() {
        cx.format_set("layouts", layouts.into_iter().collect::<Vec<_>>());
    }
    if !images.is_empty() {
        cx.format_set("images", images.into_iter().collect::<Vec<_>>());
    }
    cx.format_set("text_entities", texts);
}

/// DGN v7: element type and level of each element.
fn dgn(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    if b.len() < 4 || b[1] != 0x09 || !(b[0] == 0x08 || b[0] == 0xc8) {
        return Err(ExtractError::malformed("DGN v7 header"));
    }
    cx.format_set("dimension", if b[0] & 0x40 != 0 { "3D" } else { "2D" });
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut levels: BTreeSet<u8> = BTreeSet::new();
    let mut at = 0;
    let mut n = 0u64;
    while at + 4 <= b.len() && n < 10_000_000 {
        if b[at] == 0xff && b[at + 1] == 0xff {
            break; // end of design
        }
        let level = b[at] & 0x3f;
        let kind = b[at + 1] & 0x7f;
        let words = usize::from(u16::from_le_bytes([b[at + 2], b[at + 3]]));
        n += 1;
        bump(&mut types, &dgn_type(kind), 60);
        // Levels of graphic elements (not headers, settings or application data).
        if !matches!(kind, 0 | 8 | 9 | 10 | 66) {
            levels.insert(level);
        }
        at += 4 + words * 2;
    }
    cx.format_set("elements", n);
    cx.format_set("element_types", hist(types));
    cx.format_set("levels", levels.into_iter().collect::<Vec<_>>());
    Ok(())
}

fn dgn_type(t: u8) -> String {
    match t {
        3 => "line",
        4 => "line_string",
        5 => "group_data",
        6 => "shape",
        7 => "text_node",
        8 => "digitizer_setup",
        9 => "design_header",
        10 => "level_symbology",
        11 => "curve",
        12 => "complex_chain_header",
        14 => "complex_shape_header",
        15 => "ellipse",
        16 => "arc",
        17 => "text",
        18 => "3d_surface_header",
        19 => "3d_solid_header",
        21 => "bspline_pole",
        22 => "point_string",
        23 => "cone",
        24 => "bspline_surface_header",
        25 => "bspline_surface_boundary",
        26 => "bspline_knot",
        27 => "bspline_curve_header",
        28 => "bspline_weight_factor",
        33 => "dimension",
        34 => "shared_cell_definition",
        35 => "shared_cell",
        37 => "tag_value",
        66 => "application",
        _ => return format!("type {t}"),
    }
    .into()
}

impl Extractor for Drawing {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if probe.extension == Some("dgn")
            && h.len() > 4
            && h[1] == 0x09
            && (h[0] == 0x08 || h[0] == 0xc8)
            && h[2] == 0xfe
            && h[3] == 0x02
        {
            return Some(Sniff { format: "dgn", confidence: 0.97 });
        }
        let text = std::str::from_utf8(&h[..h.len().min(2048)]).ok()?;
        let mut l = text.lines().map(str::trim);
        // "  0\nSECTION\n  2\nHEADER" (or a comment `999` first).
        let mut first = (l.next()?, l.next()?);
        if first.0 == "999" {
            first = (l.next()?, l.next()?);
        }
        (first == ("0", "SECTION")
            && matches!(l.next(), Some("2"))
            && l.next().is_some_and(|s| matches!(s, "HEADER" | "CLASSES" | "TABLES" | "BLOCKS" | "ENTITIES")))
        .then_some(Sniff { format: "dxf", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        let (b, _) = cx.read_bytes(src)?;
        match id.as_str() {
            "dgn" => dgn(cx, &b),
            id => {
                dxf(cx, &b, id == "dxf_binary");
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Drawing);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dxf_helpers() {
        assert_eq!(release("AC1015"), "2000");
        assert_eq!(julian(2_460_919.75).as_deref(), Some("2025-09-01T06:00:00"));
        assert_eq!(mtext_plain(r"{\fArial|b1;Buoy}\PSaltmere"), "Buoy Saltmere");
        let p = pairs(b"  0\nSECTION\n  2\nHEADER\n", false);
        assert_eq!(p, vec![(0, "SECTION".into()), (2, "HEADER".into())]);
    }

    crate::fixture_tests!("dxf", "dxf_binary", "dgn");
}
