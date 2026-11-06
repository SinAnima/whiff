//! Electronics and parametric design:
//! * Gerber (RS-274X and X2): units, coordinate format, file attributes
//!   (function, polarity, generation software, creation date, project,
//!   part), apertures by shape, draws, moves, flashes, regions, bounds;
//! * Excellon drill files: units, format, tools and diameters, hits per
//!   tool, slots, the generator's comments;
//! * `KiCad` boards and schematics (S-expressions): version, generator,
//!   title block, layers, nets, footprints, tracks, vias, zones, symbols,
//!   wires, labels, sheets;
//! * `OpenSCAD` sources: modules, functions, includes and uses, primitives,
//!   the header comment;
//! * GDSII stream and OASIS layouts: library, units, dates, cells,
//!   elements by type, layers, bounds (GDSII); version, unit and
//!   validation (OASIS).
//!
//! Specifications: Ucamco Gerber Layer Format Specification 2023.08;
//! IPC-NC-349 and the Excellon format; `KiCad` file formats (s-expression,
//! v8); `OpenSCAD` language reference; GDSII Stream Format 6.0 (Calma);
//! SEMI P39 (OASIS).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{Box3, Sexp, bump, hist, num};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    parse_date, truncate_chars,
};

/// Extractor for electronics and parametric design files.
pub struct Eda;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.eda",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "gerber",
            name: "Gerber / Excellon PCB",
            family: "cad",
            mimes: &["application/vnd.gerber"],
            extensions: &["gbr", "ger", "gtl", "gbl", "gto", "gbo", "gts", "gbs", "gm1"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "excellon",
            name: "Excellon drill file",
            family: "cad",
            mimes: &[],
            extensions: &["drl", "xln", "exc"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "kicad_pcb",
            name: "KiCad / Eagle / Altium",
            family: "cad",
            mimes: &[],
            extensions: &["kicad_pcb"],
            magic: &[Magic::at(0, b"(kicad_pcb")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "kicad_sch",
            name: "KiCad schematic",
            family: "cad",
            mimes: &[],
            extensions: &["kicad_sch"],
            magic: &[Magic::at(0, b"(kicad_sch")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "openscad",
            name: "OpenSCAD / FreeCAD",
            family: "cad",
            mimes: &[],
            extensions: &["scad"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "gdsii",
            name: "GDSII / OASIS chip layout",
            family: "cad",
            mimes: &[],
            extensions: &["gds", "gds2", "gdsii"],
            // HEADER (version any), then BGNLIB: four bytes alone also start Photoshop 6.2 brushes.
            magic: &[Magic::masked(
                0,
                b"\x00\x06\x00\x02\0\0\x00\x1c\x01\x02",
                b"\xff\xff\xff\xff\0\0\xff\xff\xff\xff",
            )],
            parent: None,
        },
        FormatSpec {
            id: "oasis",
            name: "OASIS chip layout",
            family: "cad",
            mimes: &[],
            extensions: &["oas", "oasis"],
            magic: &[Magic::at(0, b"%SEMI-OASIS\r\n")],
            parent: None,
        },
    ],
};

// ---------------------------------------------------------------- Gerber

#[allow(clippy::too_many_lines)] // one arm per command family
fn gerber(cx: &mut Context<'_>, text: &str) {
    let mut attrs = Map::new();
    let mut apertures: BTreeMap<String, u64> = BTreeMap::new();
    let (mut draws, mut moves, mut flashes, mut regions) = (0u64, 0u64, 0u64, 0u64);
    let mut unit = None;
    let (mut xdec, mut ydec) = (6u32, 6u32);
    let mut b = Box3::default();
    let (mut x, mut y) = (0.0, 0.0);
    // Extended commands are %…*% blocks; others end at '*'.
    for cmd in text.split('*').take(50_000_000) {
        let c = cmd.trim().trim_start_matches('%').trim();
        // X2 attributes may also come as `G04 #@! TF.…` comments.
        let c = c.strip_prefix("G04 #@! ").unwrap_or(c);
        if c.is_empty() {
            continue;
        }
        if let Some(r) = c.strip_prefix("TF.") {
            let (k, v) = r.split_once(',').unwrap_or((r, ""));
            if attrs.len() < 40 {
                attrs.insert(truncate_chars(k, 40), truncate_chars(v, 200).into());
            }
            continue;
        }
        if let Some(r) = c.strip_prefix("FS") {
            // FSLAX46Y46: integer and decimal digits.
            let digits =
                |axis: char| r.split(axis).nth(1).and_then(|d| d.get(1..2)).and_then(|d| d.parse::<u32>().ok());
            xdec = digits('X').unwrap_or(xdec);
            ydec = digits('Y').unwrap_or(ydec);
            cx.format_set("coordinate_format", truncate_chars(r, 20));
            continue;
        }
        match c {
            "MOMM" => unit = Some("mm"),
            "MOIN" => unit = Some("inch"),
            "G36" => regions += 1,
            _ => {}
        }
        if let Some(r) = c.strip_prefix("AD") {
            // ADD10C,0.5: the shape follows the D-code.
            let shape: String = r
                .trim_start_matches('D')
                .trim_start_matches(|ch: char| ch.is_ascii_digit())
                .chars()
                .take_while(|ch| *ch != ',')
                .collect();
            let name = match shape.as_str() {
                "C" => "circle",
                "R" => "rectangle",
                "O" => "obround",
                "P" => "polygon",
                "" => "unknown",
                _ => "macro",
            };
            bump(&mut apertures, name, 20);
            continue;
        }
        if c.starts_with('%') || c.starts_with("AM") {
            continue;
        }
        // Coordinates and the operation: X…Y…D01 / D02 / D03.
        let op = c.rfind('D').and_then(|i| c[i + 1..].parse::<u32>().ok());
        let coord = |axis: char, dec: u32| -> Option<f64> {
            let i = c.find(axis)?;
            let digits: String =
                c[i + 1..].chars().take_while(|ch| ch.is_ascii_digit() || *ch == '-' || *ch == '+').collect();
            digits.parse::<f64>().ok().map(|v| v / 10f64.powi(dec.cast_signed()))
        };
        let (nx, ny) = (coord('X', xdec), coord('Y', ydec));
        if nx.is_some() || ny.is_some() {
            x = nx.unwrap_or(x);
            y = ny.unwrap_or(y);
            b.add([x, y, 0.0]);
        }
        match op {
            Some(1) => draws += 1,
            Some(2) => moves += 1,
            Some(3) => flashes += 1,
            _ => {}
        }
    }
    if let Some(u) = unit {
        cx.format_set("unit", u);
    }
    if let Some(d) = attrs.get("CreationDate").and_then(Value::as_str)
        && let Some((t, tz)) = parse_date(d)
    {
        cx.temporal().source("gerber.TF.CreationDate").content_date(DateField::Created, t, tz);
    }
    if !attrs.is_empty() {
        cx.format_set("attributes", Value::Object(attrs));
    }
    cx.format_set("apertures", hist(apertures));
    cx.format_set("draws", draws);
    cx.format_set("moves", moves);
    cx.format_set("flashes", flashes);
    cx.format_set("regions", regions);
    b.report(cx, "bounds");
}

fn excellon(cx: &mut Context<'_>, text: &str) {
    let mut tools: BTreeMap<String, f64> = BTreeMap::new();
    let mut hits: BTreeMap<String, u64> = BTreeMap::new();
    let mut comments = Vec::new();
    let (mut unit, mut current, mut slots, mut header) = (None, String::new(), 0u64, true);
    for line in text.lines().take(10_000_000) {
        let t = line.trim();
        if let Some(c) = t.strip_prefix(';') {
            if comments.len() < 20 && !c.trim().is_empty() {
                comments.push(truncate_chars(c.trim(), 200));
            }
            continue;
        }
        if t.starts_with("METRIC") {
            unit = Some("mm");
        } else if t.starts_with("INCH") {
            unit = Some("inch");
        } else if t == "%" || t == "M95" {
            header = false;
        } else if let Some(r) = t.strip_prefix('T') {
            let num_: String = r.chars().take_while(char::is_ascii_digit).collect();
            if let Some(d) = r.split_once('C').and_then(|(_, d)| d.parse::<f64>().ok()).filter(|_| header) {
                tools.insert(format!("T{num_}"), d);
            } else if !num_.is_empty() {
                current = format!("T{}", num_.trim_start_matches('0').parse::<u32>().unwrap_or(0));
            }
        } else if (t.starts_with('X') || t.starts_with('Y')) && !header {
            if t.contains("G85") {
                slots += 1;
            }
            *hits.entry(if current.is_empty() { "?".into() } else { current.clone() }).or_default() += 1;
        }
    }
    if let Some(u) = unit {
        cx.format_set("unit", u);
    }
    // Tool numbers as written (T01) and as selected (T1) are the same tool.
    let norm = |t: &str| format!("T{}", t[1..].trim_start_matches('0').parse::<u32>().unwrap_or(0));
    let list: Map<String, Value> = tools.iter().map(|(k, d)| (norm(k), num(*d, 4))).collect();
    cx.format_set("tools", Value::Object(list));
    cx.format_set("hits", hist(hits.clone()));
    cx.format_set("total_hits", hits.values().sum::<u64>());
    if slots > 0 {
        cx.format_set("slots", slots);
    }
    if !comments.is_empty() {
        cx.format_set("comments", comments);
    }
}

// ---------------------------------------------------------------- KiCad

fn kicad(cx: &mut Context<'_>, text: &str, board: bool) -> Result<(), ExtractError> {
    let root = Sexp::parse(text, 256).ok_or_else(|| ExtractError::malformed("S-expression"))?;
    let atom = |name: &str| root.child(name).and_then(|c| c.atom(1)).map(|s| truncate_chars(s, 60));
    for (k, out) in [
        ("version", "version"),
        ("generator", "generator"),
        ("generator_version", "generator_version"),
        ("paper", "paper"),
    ] {
        if let Some(v) = atom(k) {
            cx.format_set(out, v);
        }
    }
    if let Some(tb) = root.child("title_block") {
        let mut m = Map::new();
        for c in tb.items().iter().skip(1) {
            match (c.head(), c.atom(1), c.atom(2)) {
                (Some("comment"), Some(n), Some(v)) => {
                    m.insert(format!("comment_{n}"), truncate_chars(v, 200).into());
                }
                (Some(k), Some(v), _) => {
                    m.insert(k.to_string(), truncate_chars(v, 200).into());
                }
                _ => {}
            }
        }
        if let Some(t) = m.get("title").and_then(Value::as_str) {
            cx.content().source("kicad.title_block.title").title(t.to_string());
        }
        if let Some(d) = m.get("date").and_then(Value::as_str)
            && let Some((t, tz)) = parse_date(d)
        {
            cx.temporal().source("kicad.title_block.date").content_date(DateField::Modified, t, tz);
        }
        cx.format_set("title_block", Value::Object(m));
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for c in root.items().iter().skip(1) {
        if let Some(h) = c.head() {
            bump(&mut counts, h, 60);
        }
    }
    if board {
        if let Some(t) = root.child("general").and_then(|g| g.child("thickness")).and_then(|t| t.atom(1)) {
            cx.format_set("board_thickness", truncate_chars(t, 10));
        }
        let layers: Vec<String> = root
            .child("layers")
            .map(|l| l.items().iter().skip(1).filter_map(|x| x.atom(1)).map(|s| truncate_chars(s, 40)).collect())
            .unwrap_or_default();
        cx.format_set("copper_layers", layers.iter().filter(|l| l.ends_with(".Cu")).count());
        cx.format_set("layers", layers);
        let refs: BTreeSet<String> = root
            .items()
            .iter()
            .filter(|c| c.head() == Some("footprint"))
            .filter_map(|f| {
                f.items()
                    .iter()
                    .find(|p| p.head() == Some("property") && p.atom(1) == Some("Reference"))
                    .and_then(|p| p.atom(2))
            })
            .take(5000)
            .map(|s| s.chars().take_while(char::is_ascii_alphabetic).collect())
            .collect();
        cx.format_set("reference_prefixes", refs.into_iter().collect::<Vec<_>>());
    } else {
        let libs = root.child("lib_symbols").map_or(0, |l| l.items().len().saturating_sub(1));
        cx.format_set("library_symbols", libs);
    }
    cx.format_set("elements", hist(counts));
    Ok(())
}

// ---------------------------------------------------------------- OpenSCAD

fn openscad(cx: &mut Context<'_>, text: &str) {
    let (mut modules, mut functions, mut deps) = (Vec::new(), Vec::new(), Vec::new());
    let mut prims: BTreeMap<String, u64> = BTreeMap::new();
    let header: Vec<&str> = text
        .lines()
        .take(15)
        .map_while(|l| l.trim().strip_prefix("//"))
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !header.is_empty() {
        cx.format_set("header_comment", truncate_chars(&header.join(" | "), 300));
    }
    for line in text.lines().take(10_000_000) {
        let t = line.trim();
        let mut w = t.split(|c: char| c.is_whitespace() || c == '(').filter(|s| !s.is_empty());
        match w.next() {
            Some("module") if modules.len() < 500 => modules.push(truncate_chars(w.next().unwrap_or(""), 60)),
            Some("function") if functions.len() < 500 => functions.push(truncate_chars(w.next().unwrap_or(""), 60)),
            Some(k @ ("include" | "use")) => {
                if let Some(p) = t.split('<').nth(1).and_then(|r| r.split('>').next())
                    && deps.len() < 100
                {
                    deps.push(format!("{k} {}", truncate_chars(p, 100)));
                }
            }
            _ => {}
        }
        for p in [
            "cube",
            "sphere",
            "cylinder",
            "polyhedron",
            "square",
            "circle",
            "polygon",
            "text",
            "import",
            "surface",
            "linear_extrude",
            "rotate_extrude",
            "union",
            "difference",
            "intersection",
            "hull",
            "minkowski",
        ] {
            let n = t.matches(&format!("{p}(")).count();
            if n > 0 {
                *prims.entry(p.into()).or_default() += n as u64;
            }
        }
    }
    cx.format_set("modules", modules);
    cx.format_set("functions", functions);
    cx.format_set("dependencies", deps);
    cx.format_set("operations", hist(prims));
}

// ---------------------------------------------------------------- GDSII

/// A GDSII 8-byte real: sign, excess-64 base-16 exponent, 56-bit mantissa.
fn gds_real(b: &[u8]) -> f64 {
    let sign = if b[0] & 0x80 != 0 { -1.0 } else { 1.0 };
    let exp = i32::from(b[0] & 0x7f) - 64;
    let mant = b[1..8].iter().fold(0u64, |a, &x| a << 8 | u64::from(x)) as f64 / 2f64.powi(56);
    sign * mant * 16f64.powi(exp)
}

#[allow(clippy::too_many_lines)] // one arm per record type
fn gdsii(cx: &mut Context<'_>, b: &[u8]) {
    let mut at = 0;
    let mut elements: BTreeMap<String, u64> = BTreeMap::new();
    let mut layers: BTreeSet<i16> = BTreeSet::new();
    let mut cells = Vec::new();
    let mut ncells = 0u64;
    let mut bounds = Box3::default();
    let mut db_to_user = 1.0;
    let mut records = 0u64;
    let i16_at = |i: usize| b.get(i..i + 2).map(|s| i16::from_be_bytes([s[0], s[1]]));
    let date = |d: &[u8]| -> Option<String> {
        let v: Vec<i16> = d.as_chunks::<2>().0.iter().take(6).map(|c| i16::from_be_bytes([c[0], c[1]])).collect();
        let [y, mo, da, h, mi, s] = v[..] else { return None };
        let year = if y < 1900 { i32::from(y) + 1900 } else { i32::from(y) };
        (mo > 0).then(|| format!("{year:04}-{mo:02}-{da:02}T{h:02}:{mi:02}:{s:02}"))
    };
    while at + 4 <= b.len() && records < 50_000_000 {
        let len = usize::try_from(i16_at(at).unwrap_or(0).max(0)).unwrap_or(0);
        if len < 4 || at + len > b.len() {
            break;
        }
        records += 1;
        let (rt, d) = (b[at + 2], &b[at + 4..at + len]);
        match rt {
            0x00 => cx.format_set("stream_version", i16_at(at + 4).unwrap_or(0)),
            0x01 => {
                if let Some(m) = date(d) {
                    cx.format_set("modified", m.clone());
                    cx.temporal().source("gdsii.BGNLIB").content_date(DateField::Modified, m, false);
                }
                if let Some(a) = d.get(12..).and_then(date) {
                    cx.format_set("accessed", a);
                }
            }
            0x02 => {
                let n = String::from_utf8_lossy(d).trim_end_matches('\0').to_string();
                cx.format_set("library", truncate_chars(&n, 100));
                cx.content().source("gdsii.LIBNAME").title(truncate_chars(&n, 100));
            }
            0x03 if d.len() >= 16 => {
                // User units per database unit; metres per database unit.
                let (user, metres) = (gds_real(&d[..8]), gds_real(&d[8..16]));
                db_to_user = user;
                cx.format_set("user_units_per_db_unit", num(user, 12));
                cx.format_set("db_unit_m", Value::String(format!("{metres:e}")));
            }
            0x06 => {
                ncells += 1;
                if cells.len() < 200 {
                    cells.push(truncate_chars(String::from_utf8_lossy(d).trim_end_matches('\0'), 60));
                }
            }
            0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x15 | 0x2d => {
                let name = match rt {
                    0x08 => "boundary",
                    0x09 => "path",
                    0x0a => "sref",
                    0x0b => "aref",
                    0x0c => "text",
                    0x15 => "node",
                    _ => "box",
                };
                *elements.entry(name.into()).or_default() += 1;
            }
            0x0d => {
                if let Some(l) = i16_at(at + 4)
                    && layers.len() < 4096
                {
                    layers.insert(l);
                }
            }
            0x10 => {
                for p in d.as_chunks::<8>().0.iter().take(1_000_000) {
                    let x = f64::from(i32::from_be_bytes([p[0], p[1], p[2], p[3]]));
                    let y = f64::from(i32::from_be_bytes([p[4], p[5], p[6], p[7]]));
                    bounds.add([x, y, 0.0]);
                }
            }
            0x04 => break,
            _ => {}
        }
        at += len;
    }
    cx.format_set("cells", ncells);
    cx.format_set("cell_names", cells);
    cx.format_set("elements", hist(elements));
    cx.format_set("layers", layers.into_iter().collect::<Vec<_>>());
    if bounds.points > 0 {
        // In user units (usually µm): every cell's coordinates, untransformed.
        let s = db_to_user;
        cx.format_set(
            "bounds_user_units",
            Value::Array(
                [bounds.min[0], bounds.min[1], bounds.max[0], bounds.max[1]].iter().map(|v| num(v * s, 6)).collect(),
            ),
        );
    }
}

/// An OASIS unsigned integer (7-bit groups, low first).
fn oasis_uint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..63).step_by(7) {
        let c = *b.get(*at)?;
        *at += 1;
        v |= u64::from(c & 0x7f) << shift;
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// An OASIS real (the `type` byte, then its parts).
fn oasis_real(b: &[u8], at: &mut usize) -> Option<f64> {
    let t = oasis_uint(b, at)?;
    Some(match t {
        0 => oasis_uint(b, at)? as f64,
        1 => -(oasis_uint(b, at)? as f64),
        2 => 1.0 / oasis_uint(b, at)? as f64,
        3 => -1.0 / oasis_uint(b, at)? as f64,
        4 => oasis_uint(b, at)? as f64 / oasis_uint(b, at)? as f64,
        5 => -(oasis_uint(b, at)? as f64 / oasis_uint(b, at)? as f64),
        6 => {
            let v = f64::from(f32::from_le_bytes(b.get(*at..*at + 4)?.try_into().ok()?));
            *at += 4;
            v
        }
        7 => {
            let v = f64::from_le_bytes(b.get(*at..*at + 8)?.try_into().ok()?);
            *at += 8;
            v
        }
        _ => return None,
    })
}

fn oasis(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("OASIS START record");
    let mut at = 13;
    if oasis_uint(b, &mut at).ok_or_else(bad)? != 1 {
        return Err(bad());
    }
    let n = usize::try_from(oasis_uint(b, &mut at).ok_or_else(bad)?).map_err(|_| bad())?;
    let version = String::from_utf8_lossy(b.get(at..at + n).ok_or_else(bad)?).into_owned();
    at += n;
    cx.format_set("oasis_version", truncate_chars(&version, 10));
    let unit = oasis_real(b, &mut at).ok_or_else(bad)?;
    cx.format_set("db_units_per_micron", num(unit, 6));
    let offsets = oasis_uint(b, &mut at).ok_or_else(bad)?;
    cx.format_set("table_offsets_at_end", offsets == 1);
    // END: the last 256 bytes; the validation scheme is its last part.
    if b.len() >= 256 && b[b.len() - 256] == 2 {
        let tail = &b[b.len() - 256..];
        // The scheme is followed by 0 (none) or 4 signature bytes.
        let scheme = if tail[251] <= 2 && tail[250] != 0 { tail[251] } else { tail[255] };
        cx.format_set(
            "validation",
            match scheme {
                1 => "crc32",
                2 => "checksum32",
                _ => "none",
            },
        );
    }
    Ok(())
}

impl Extractor for Eda {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let text = std::str::from_utf8(&h[..h.len().min(8192)]).ok()?;
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if text.contains("%FSLA")
            || text.contains("%FSTA")
            || text.starts_with("%TF.")
            || text.contains("\n%TF.")
            || text.contains("G04 ") && text.contains("%MO")
        {
            return sure("gerber");
        }
        if text.starts_with("M48")
            || text.lines().take(20).any(|l| l.trim() == "M48") && text.contains("METRIC")
            || text.contains("INCH,")
        {
            return sure("excellon");
        }
        let scad = probe.extension == Some("scad")
            || text.lines().take(100).any(|l| {
                let t = l.trim_start();
                (t.starts_with("module ") || t.starts_with("$fn"))
                    && (text.contains("cube(") || text.contains("cylinder(") || text.contains("difference()"))
            });
        scad.then_some(Sniff { format: "openscad", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "gdsii" || id == "oasis" {
            let (b, _) = cx.read_bytes(src)?;
            if id == "gdsii" {
                gdsii(cx, &b);
                return Ok(());
            }
            return oasis(cx, &b);
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "gerber" => gerber(cx, &text),
            "excellon" => excellon(cx, &text),
            "kicad_pcb" => return kicad(cx, &text, true),
            "kicad_sch" => return kicad(cx, &text, false),
            _ => openscad(cx, &text),
        }
        Ok(())
    }
}

crate::register_extractor!(Eda);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        // 1e-3 as a GDSII real (the usual user unit).
        let r = [0x3e, 0x41, 0x89, 0x37, 0x4b, 0xc6, 0xa7, 0xf0];
        assert!((gds_real(&r) - 1e-3).abs() < 1e-12);
        let mut at = 0;
        assert_eq!(oasis_uint(&[0x96, 0x01], &mut at), Some(150));
        let mut at = 0;
        assert_eq!(oasis_real(&[0, 0xe8, 0x07], &mut at), Some(1000.0));
    }

    crate::fixture_tests!("gerber", "excellon", "kicad_pcb", "kicad_sch", "openscad", "gdsii", "oasis");
}
