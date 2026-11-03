//! Product data exchange:
//! * STEP and IFC (ISO 10303-21 clear text): the header's description,
//!   implementation level, file name, time stamp, authors, organisations,
//!   preprocessor, originating system, authorisation and schemas (the
//!   STEP application protocol: AP203 / AP214 / AP242 …); the data
//!   section's entities by type; products (STEP); project, site,
//!   building, storeys and the authoring application (IFC); IFC-ZIP;
//! * IGES: the global section (sender, file name, system, preprocessor,
//!   units, dates, author, organisation, version, drafting standard),
//!   entities by type, and the section counts.
//!
//! Specifications: ISO 10303-21:2016; buildingSMART IFC 2x3 / 4 / 4.3;
//! IGES 5.3 (US PRO, 1996).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    parse_date, truncate_chars, zip_names,
};

/// Extractor for STEP, IFC and IGES.
pub struct Step;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.step",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "step",
            name: "STEP",
            family: "cad",
            mimes: &["model/step"],
            extensions: &["step", "stp", "p21"],
            magic: &[Magic::at(0, b"ISO-10303-21;")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ifc",
            name: "IFC (BIM)",
            family: "cad",
            mimes: &["application/x-step"],
            extensions: &["ifc"],
            magic: &[Magic::at(0, b"ISO-10303-21;")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ifczip",
            name: "IFC-ZIP",
            family: "cad",
            mimes: &[],
            extensions: &["ifczip"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "iges",
            name: "IGES",
            family: "cad",
            mimes: &["model/iges"],
            extensions: &["igs", "iges"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// A Part 21 string's text: `''` and the `\X\`, `\X2\…\X0\` escapes.
fn p21_string(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if let Some(r) = rest.strip_prefix("\\X2\\") {
            let (hex, after) = r.split_once("\\X0\\").unwrap_or((r, ""));
            let units: Vec<u16> = hex
                .as_bytes()
                .chunks(4)
                .filter_map(|c| u16::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
                .collect();
            out.push_str(&String::from_utf16_lossy(&units));
            rest = after;
        } else if let Some(r) = rest.strip_prefix("\\X\\") {
            if let Some(c) = r.get(..2).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(char::from(c));
            }
            rest = r.get(2..).unwrap_or("");
        } else if let Some(r) = rest.strip_prefix("\\S\\") {
            if let Some(c) = r.chars().next() {
                out.push(char::from_u32(c as u32 + 128).unwrap_or(c));
            }
            rest = r.get(1..).unwrap_or("");
        } else {
            out.push('\\');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out.replace("''", "'")
}

/// The quoted strings of a Part 21 parameter list, in order (nested lists
/// flattened), with `$` (unset) as empty.
fn p21_strings(params: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = params.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < 200 {
        match b[i] {
            b'\'' => {
                let start = i + 1;
                i += 1;
                while i < b.len() {
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                out.push(p21_string(&params[start..i.min(params.len())]));
            }
            b'$' => out.push(String::new()),
            _ => {}
        }
        i += 1;
    }
    out
}

/// The parameters of `NAME(…)` in `s`, matching parentheses.
fn call<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let i = s.find(&format!("{name}("))? + name.len() + 1;
    let b = s.as_bytes();
    let (mut depth, mut quoted) = (1i32, false);
    for (j, &c) in b[i..].iter().enumerate() {
        match c {
            b'\'' => quoted = !quoted,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i..i + j]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The application protocol of a STEP schema.
fn protocol(schema: &str) -> Option<&'static str> {
    let s = schema.to_ascii_uppercase();
    Some(match () {
        () if s.starts_with("CONFIG_CONTROL_DESIGN") => "AP203",
        () if s.starts_with("CONFIG_CONTROL_3D_DESIGN") => "AP203e2",
        () if s.starts_with("AUTOMOTIVE_DESIGN") => "AP214",
        () if s.starts_with("AP242") => "AP242",
        () if s.starts_with("AP209") || s.starts_with("STRUCTURAL_ANALYSIS_DESIGN") => "AP209",
        () if s.starts_with("IFC") => "IFC",
        () => return None,
    })
}

#[allow(clippy::too_many_lines)] // the header, then the data section
fn p21(cx: &mut Context<'_>, text: &str, ifc: bool) -> Result<(), ExtractError> {
    let header = text.split("ENDSEC;").next().ok_or_else(|| ExtractError::malformed("no HEADER"))?;
    if let Some(d) = call(header, "FILE_DESCRIPTION") {
        let s = p21_strings(d);
        let (desc, level) = s.split_at(s.len().saturating_sub(1));
        let desc: Vec<String> = desc.iter().filter(|x| !x.is_empty()).map(|x| truncate_chars(x, 300)).collect();
        if !desc.is_empty() {
            cx.content().source("p21.FILE_DESCRIPTION").description(desc.join(" "));
            cx.format_set("description", desc);
        }
        if let Some(l) = level.first() {
            cx.format_set("implementation_level", truncate_chars(l, 20));
        }
    }
    if let Some(f) = call(header, "FILE_NAME") {
        // name, time_stamp, (author…), (organization…), preprocessor, originating system, authorization
        let parts = split_top(f);
        let strings = |i: usize| parts.get(i).map(|p| p21_strings(p)).unwrap_or_default();
        let one = |i: usize| strings(i).into_iter().next().filter(|s| !s.is_empty()).map(|s| truncate_chars(&s, 200));
        let mut m = Map::new();
        if let Some(n) = one(0) {
            m.insert("name".into(), n.into());
        }
        if let Some(t) = one(1) {
            m.insert("time_stamp".into(), t.clone().into());
            if let Some((d, tz)) = parse_date(&t) {
                cx.temporal().source("p21.FILE_NAME.time_stamp").content_date(DateField::Created, d, tz);
            }
        }
        let authors: Vec<String> =
            strings(2).into_iter().filter(|s| !s.is_empty()).take(20).map(|s| truncate_chars(&s, 100)).collect();
        for a in &authors {
            cx.content().source("p21.FILE_NAME.author").author(a.clone());
        }
        if !authors.is_empty() {
            m.insert("authors".into(), authors.into());
        }
        let orgs: Vec<String> =
            strings(3).into_iter().filter(|s| !s.is_empty()).take(20).map(|s| truncate_chars(&s, 100)).collect();
        if !orgs.is_empty() {
            m.insert("organizations".into(), orgs.into());
        }
        for (i, k) in [(4, "preprocessor"), (5, "originating_system"), (6, "authorization")] {
            if let Some(v) = one(i) {
                m.insert(k.into(), v.into());
            }
        }
        cx.format_set("file_name", Value::Object(m));
    }
    let schemas: Vec<String> = call(header, "FILE_SCHEMA")
        .map(p21_strings)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .take(10)
        .collect();
    if let Some(p) = schemas.first().and_then(|s| protocol(s)) {
        cx.format_set("protocol", p);
    }
    cx.format_set("schemas", schemas.iter().map(|s| truncate_chars(s, 120)).collect::<Vec<_>>());
    // DATA: `#n=TYPE(…);` or complex `#n=(A(…)B(…));`.
    let data = text.split_once("DATA;").map_or("", |x| x.1);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut count = 0u64;
    let mut names: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for stmt in data.split(";\n").chain(std::iter::once("")).take(100_000_000) {
        let s = stmt.trim_start();
        let Some(rest) = s.strip_prefix('#') else { continue };
        let Some((_, rhs)) = rest.split_once('=') else { continue };
        let rhs = rhs.trim_start();
        // Complex instances: `( NAME(…) NAME(…) )`, the first name counts.
        let name: String = rhs
            .trim_start_matches(|c: char| c == '(' || c.is_whitespace())
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        count += 1;
        bump(&mut types, &name, 400);
        // Names of products (STEP) and spatial structure (IFC): the third
        // attribute of IfcRoot subtypes, the second of PRODUCT.
        let key = name.to_ascii_uppercase();
        let pick = match key.as_str() {
            "PRODUCT" => Some(("products", 1)),
            "IFCPROJECT" => Some(("project", 2)),
            "IFCSITE" => Some(("sites", 2)),
            "IFCBUILDING" => Some(("buildings", 2)),
            "IFCBUILDINGSTOREY" => Some(("storeys", 2)),
            "IFCAPPLICATION" => Some(("applications", 2)),
            _ => None,
        };
        if let Some((k, idx)) = pick
            && let Some(p) = call(rhs, &name)
        {
            let args = split_top(p);
            if let Some(v) =
                args.get(idx).map(|a| p21_strings(a)).and_then(|s| s.into_iter().next()).filter(|s| !s.is_empty())
            {
                let list = names.entry(k).or_default();
                if list.len() < 100 {
                    list.push(truncate_chars(&v, 120));
                }
            }
        }
    }
    cx.format_set("entities", count);
    let mut top: Vec<(String, u64)> = types.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    cx.format_set("entity_types", top.len());
    cx.format_set("top_entity_types", hist(top.into_iter().take(40).collect()));
    if ifc && let Some(p) = names.get("project").and_then(|p| p.first()) {
        cx.content().source("ifc.IfcProject.Name").title(p.clone());
    }
    if !ifc && let Some(p) = names.get("products").and_then(|p| p.first()) {
        cx.content().source("step.PRODUCT.name").title(p.clone());
    }
    for (k, v) in names {
        cx.format_set(k, v);
    }
    Ok(())
}

/// Top-level comma-separated arguments of a parameter list.
fn split_top(p: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut quoted, mut start) = (0i32, false, 0);
    for (i, c) in p.char_indices() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(&p[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&p[start..]);
    out
}

fn ifczip(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 10_000)?;
    let name = zip
        .entries
        .iter()
        .map(|e| e.name.clone())
        .find(|n| n.to_ascii_lowercase().ends_with(".ifc"))
        .ok_or_else(|| ExtractError::malformed("no .ifc entry"))?;
    cx.format_set("document", truncate_chars(&name, 200));
    let limit = cx.parse_limit();
    let text = zip.read_text(src, &name, cx, limit).ok_or_else(|| ExtractError::malformed("entry"))??;
    p21(cx, &text, true)
}

/// IGES global parameters: Hollerith strings (`5HHello`), numbers.
fn iges_global(g: &str) -> Vec<String> {
    let b = g.as_bytes();
    // Field 1 and 2 may redefine the delimiters: `1H,,1H;,`.
    let (mut pd, mut rd) = (b',', b';');
    let mut at = 0;
    if g.starts_with("1H") && b.len() > 3 {
        pd = b[2];
        at = 4;
        if g[at..].starts_with("1H") && b.len() > at + 3 {
            rd = b[at + 2];
            at += 4;
        } else {
            at += 1;
        }
    } else if let Some(r) = g.strip_prefix(',') {
        at = 1;
        if r.starts_with(',') || r.starts_with(';') {
            at = 2;
        }
    }
    let mut out = vec![char::from(pd).to_string(), char::from(rd).to_string()];
    while at < b.len() && out.len() < 30 {
        // Lines are padded to 72 columns: blanks before a field are not part of it.
        while b.get(at) == Some(&b' ') {
            at += 1;
        }
        // A Hollerith string: digits, 'H', then that many characters.
        let digits = b[at..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && b.get(at + digits) == Some(&b'H') {
            let n: usize = g[at..at + digits].parse().unwrap_or(0);
            let s = at + digits + 1;
            out.push(g.get(s..(s + n).min(g.len())).unwrap_or("").to_string());
            at = s + n;
            at += usize::from(b.get(at).is_some_and(|&c| c == pd || c == rd));
            continue;
        }
        let end = b[at..].iter().position(|&c| c == pd || c == rd).map_or(b.len(), |i| at + i);
        out.push(g[at..end].trim().to_string());
        at = end + 1;
    }
    out
}

/// IGES `YYMMDD.HHNNSS` or `YYYYMMDD.HHNNSS` as ISO 8601.
fn iges_date(s: &str) -> Option<String> {
    let (d, t) = s.split_once('.')?;
    let (y, md) = match d.len() {
        6 => (format!("19{}", &d[..2]), &d[2..]),
        8 => (d[..4].to_string(), &d[4..]),
        _ => return None,
    };
    (t.len() >= 6 && md.len() == 4 && d.bytes().all(|c| c.is_ascii_digit()))
        .then(|| format!("{y}-{}-{}T{}:{}:{}", &md[..2], &md[2..4], &t[..2], &t[2..4], &t[4..6]))
}

fn iges_entity(t: u32) -> String {
    match t {
        100 => "circular_arc",
        102 => "composite_curve",
        104 => "conic_arc",
        106 => "copious_data",
        108 => "plane",
        110 => "line",
        112 => "parametric_spline_curve",
        116 => "point",
        118 => "ruled_surface",
        120 => "surface_of_revolution",
        122 => "tabulated_cylinder",
        123 => "direction",
        124 => "transformation_matrix",
        126 => "rational_bspline_curve",
        128 => "rational_bspline_surface",
        141 => "boundary",
        142 => "curve_on_surface",
        143 => "bounded_surface",
        144 => "trimmed_surface",
        186 => "manifold_solid_brep",
        190 => "plane_surface",
        192 => "cylindrical_surface",
        194 => "conical_surface",
        196 => "spherical_surface",
        198 => "toroidal_surface",
        212 => "general_note",
        308 => "subfigure_definition",
        314 => "color_definition",
        402 => "associativity_instance",
        406 => "property",
        408 => "singular_subfigure_instance",
        502 => "vertex_list",
        504 => "edge_list",
        508 => "loop",
        510 => "face",
        514 => "shell",
        _ => return format!("type {t}"),
    }
    .into()
}

fn iges(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut start, mut global) = (String::new(), String::new());
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut counts: BTreeMap<char, u64> = BTreeMap::new();
    let mut d_line = 0u64;
    for line in text.lines().take(50_000_000) {
        let l = line.trim_end_matches('\r');
        let Some(sec) = l.as_bytes().get(72).map(|&c| char::from(c)) else { continue };
        *counts.entry(sec).or_default() += 1;
        let body = l.get(..72).unwrap_or(l);
        match sec {
            'S' if start.len() < 2000 => {
                start.push_str(body.trim_end());
                start.push(' ');
            }
            'G' => global.push_str(body),
            'D' => {
                // Two lines per entry: the type in columns 1–8 of the first.
                if d_line.is_multiple_of(2)
                    && let Ok(t) = body.get(..8).unwrap_or("").trim().parse::<u32>()
                {
                    bump(&mut types, &iges_entity(t), 200);
                }
                d_line += 1;
            }
            _ => {}
        }
    }
    if global.is_empty() {
        return Err(ExtractError::malformed("IGES: no global section"));
    }
    let g = iges_global(&global);
    let f = |i: usize| g.get(i).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let start = start.trim();
    if !start.is_empty() {
        cx.format_set("start", truncate_chars(start, 300));
    }
    let mut m = Map::new();
    for (i, k) in [
        (2, "sender"),
        (3, "file_name"),
        (4, "system"),
        (5, "preprocessor"),
        (11, "receiver"),
        (14, "unit_name"),
        (20, "author"),
        (21, "organization"),
        (23, "drafting_standard"),
    ] {
        if let Some(v) = f(i) {
            m.insert(k.into(), truncate_chars(&v, 200).into());
        }
    }
    if let Some(v) = f(22) {
        m.insert(
            "iges_version".into(),
            match v.as_str() {
                "11" => "5.3".to_string(),
                "10" => "5.2".into(),
                "9" => "5.1".into(),
                "8" => "5.0".into(),
                "7" => "4.0".into(),
                "6" => "3.0".into(),
                x => x.to_string(),
            }
            .into(),
        );
    }
    for (i, k, field) in [(17, "created", DateField::Created), (24, "modified", DateField::Modified)] {
        if let Some(d) = f(i).and_then(|s| iges_date(&s)) {
            m.insert(k.into(), d.clone().into());
            cx.temporal().source(format!("iges.global.{k}")).content_date(field, d, false);
        }
    }
    if let Some(a) = f(20) {
        cx.content().source("iges.global.author").author(truncate_chars(&a, 100));
    }
    cx.format_set("global", Value::Object(m));
    cx.format_set("entities", d_line / 2);
    cx.format_set("entity_types", hist(types));
    cx.format_set("lines", hist(counts.into_iter().map(|(k, v)| (k.to_string(), v)).collect()));
    Ok(())
}

impl Extractor for Step {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"PK\x03\x04") {
            let ifc = probe.extension == Some("ifczip")
                || zip_names(probe, 10).iter().any(|n| n.to_ascii_lowercase().ends_with(".ifc"));
            return ifc.then_some(Sniff { format: "ifczip", confidence: 0.95 });
        }
        let text = std::str::from_utf8(&h[..h.len().min(16 << 10)])
            .ok()
            .or_else(|| std::str::from_utf8(&h[..h.len().min(8 << 10)]).ok())?;
        if text.starts_with("ISO-10303-21;") {
            let schema = call(text, "FILE_SCHEMA").map(p21_strings).unwrap_or_default();
            let ifc = schema.iter().any(|s| s.to_ascii_uppercase().starts_with("IFC"));
            return Some(Sniff { format: if ifc { "ifc" } else { "step" }, confidence: 0.98 });
        }
        // IGES: 80-column lines with S then G in column 73.
        let lines: Vec<&str> = text.lines().take(10).collect();
        let col = |l: &str| l.as_bytes().get(72).copied();
        (lines.len() > 2 && col(lines[0]) == Some(b'S') && lines.iter().any(|l| col(l) == Some(b'G')))
            .then_some(Sniff { format: "iges", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "ifczip" {
            return ifczip(cx, src);
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "iges" => iges(cx, &text),
            id => p21(cx, &text, id == "ifc"),
        }
    }
}

crate::register_extractor!(Step);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part21_and_iges() {
        assert_eq!(p21_string(r"Saltmere \X2\00E9\X0\cluse"), "Saltmere écluse");
        assert_eq!(p21_strings("('a','b''c'),$,'d'"), vec!["a", "b'c", "", "d"]);
        assert_eq!(call("FILE_NAME('x',('a','b'))", "FILE_NAME"), Some("'x',('a','b')"));
        assert_eq!(split_top("'a,b',(1,2),$"), vec!["'a,b'", "(1,2)", "$"]);
        assert_eq!(protocol("AUTOMOTIVE_DESIGN { 1 0 10303 214 3 1 1 }"), Some("AP214"));
        let g = iges_global("1H,,1H;,7HSaltmer,9Hbuoy.iges;");
        assert_eq!(&g[..4], &[",", ";", "Saltmer", "buoy.iges"]);
        assert_eq!(iges_date("20250901.060000").as_deref(), Some("2025-09-01T06:00:00"));
    }

    crate::fixture_tests!("step", "ifc", "ifczip", "iges");
}
