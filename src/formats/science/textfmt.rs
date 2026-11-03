//! Text formats of simulation and electronics tools:
//! * Gaussian and ORCA outputs: program version, the route / keywords,
//!   title, charge and multiplicity, final energy, optimisation, normal
//!   termination, run time;
//! * SPICE netlists: title, element counts by kind, subcircuits, models,
//!   analyses, included files; LTspice schematics (`.asc`): version,
//!   components and directives; Touchstone (`.sNp`): ports, option line,
//!   frequency points and range;
//! * IBIS models: version, file, date, source, components, manufacturer,
//!   pins, models; Liberty (`.lib`): library, technology, units, cells;
//!   LEF / DEF: version, units, layers, macros, design, die area,
//!   components, nets, pins;
//! * ENVI raster headers: size, bands, data type, interleave, byte order,
//!   wavelengths, band names, map projection.
//!
//! Specifications: Gaussian 16 and ORCA 6 output (by their markers);
//! Berkeley SPICE3 netlists; Touchstone 2.0; IBIS 7.1; Synopsys Liberty;
//! Cadence LEF / DEF 5.8; NV5 "ENVI Header Format".

use std::collections::BTreeMap;

use serde_json::Value;

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for simulation and electronics text formats.
pub struct ToolText;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.tooltext",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "gaussian",
            name: "Gaussian / ORCA / CP2K outputs",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "orca",
            name: "ORCA output",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "spice",
            name: "SPICE netlist",
            family: "sci",
            mimes: &[],
            extensions: &["cir", "sp", "spi", "spice", "net"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ltspice",
            name: "LTspice schematic",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "touchstone",
            name: "Touchstone network data",
            family: "sci",
            mimes: &[],
            extensions: &["s1p", "s2p", "s3p", "s4p"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ibis",
            name: "IBIS model",
            family: "sci",
            mimes: &[],
            extensions: &["ibs", "ibis"],
            magic: &[Magic::at(0, b"[IBIS Ver]")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "liberty",
            name: "Liberty cell library",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "lef",
            name: "LEF library",
            family: "sci",
            mimes: &[],
            extensions: &["lef"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "def",
            name: "DEF design",
            family: "sci",
            mimes: &[],
            extensions: &["def"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "envi",
            name: "ENVI / ERDAS / PCIDSK rasters",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::at(0, b"ENVI\n"), Magic::at(0, b"ENVI\r\n")],
            parent: Some("text"),
        },
    ],
};

fn hist(m: BTreeMap<String, u64>) -> Value {
    Value::Object(m.into_iter().map(|(k, v)| (k, v.into())).collect())
}

fn gaussian(cx: &mut Context<'_>, text: &str) {
    let mut energies = 0u64;
    let mut last = None;
    for (i, line) in text.lines().enumerate().take(5_000_000) {
        let t = line.trim();
        if t.starts_with("Gaussian ") && t.contains("Rev") && i < 40 {
            cx.format_set(
                "program",
                truncate_chars(t.split_whitespace().take(3).collect::<Vec<_>>().join(" ").trim_end_matches(':'), 60),
            );
        } else if t.starts_with('#') && i < 200 {
            cx.format_set("route", truncate_chars(t, 300));
        } else if let Some(r) = t.strip_prefix("Charge =") {
            cx.format_set("charge_multiplicity", truncate_chars(r.trim().replace("Multiplicity =", "/").trim(), 30));
        } else if let Some(r) = t.strip_prefix("SCF Done:") {
            energies += 1;
            last = r.split('=').nth(1).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse::<f64>().ok());
        } else if t.starts_with("Optimization completed") {
            cx.format_set("optimisation_completed", true);
        } else if t.starts_with("Normal termination") {
            cx.format_set("normal_termination", true);
        } else if t.starts_with("Error termination") {
            cx.format_set("normal_termination", false);
        }
    }
    cx.format_set("scf_cycles_reported", energies);
    if let Some(e) = last {
        cx.format_set("final_energy_hartree", e);
    }
}

fn orca(cx: &mut Context<'_>, text: &str) {
    let mut keywords = Vec::new();
    for line in text.lines().take(5_000_000) {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Program Version") {
            cx.format_set("program_version", truncate_chars(v.trim().trim_start_matches('-').trim(), 60));
        } else if let Some(k) = t.split("> !").nth(1) {
            keywords.push(truncate_chars(k.trim(), 200));
        } else if let Some(e) = t.strip_prefix("FINAL SINGLE POINT ENERGY") {
            if let Ok(v) = e.trim().parse::<f64>() {
                cx.format_set("final_energy_hartree", v);
            }
        } else if t.contains("OPTIMIZATION RUN DONE") {
            cx.format_set("optimisation_completed", true);
        } else if t.contains("ORCA TERMINATED NORMALLY") {
            cx.format_set("normal_termination", true);
        } else if let Some(r) = t.strip_prefix("TOTAL RUN TIME:") {
            cx.format_set("run_time", truncate_chars(r.trim(), 80));
        }
    }
    if !keywords.is_empty() {
        cx.format_set("keywords", keywords);
    }
}

fn spice(cx: &mut Context<'_>, text: &str) {
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let (mut subckts, mut models, mut analyses, mut includes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut lines = text.lines();
    if let Some(first) = lines.next() {
        cx.format_set("first_line", truncate_chars(first.trim_start_matches('*').trim(), 200));
    }
    for line in lines.take(5_000_000) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('*') || t.starts_with('+') {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        let word = lower.split_whitespace().next().unwrap_or("");
        match word {
            ".title" => cx.format_set("title", truncate_chars(t[6..].trim(), 200)),
            ".subckt" => subckts.push(truncate_chars(t.split_whitespace().nth(1).unwrap_or(""), 100)),
            ".model" => models.push(truncate_chars(t.split_whitespace().nth(1).unwrap_or(""), 100)),
            ".include" | ".inc" | ".lib" => {
                includes.push(truncate_chars(t.split_whitespace().nth(1).unwrap_or("").trim_matches('"'), 200));
            }
            ".tran" | ".ac" | ".dc" | ".op" | ".noise" | ".tf" | ".four" | ".sens" | ".pz" => {
                analyses.push(word.trim_start_matches('.').to_string());
            }
            w if !w.starts_with('.') => {
                let kind = match w.chars().next().unwrap_or(' ') {
                    'r' => "resistor",
                    'c' => "capacitor",
                    'l' => "inductor",
                    'v' => "voltage source",
                    'i' => "current source",
                    'd' => "diode",
                    'q' => "bjt",
                    'm' => "mosfet",
                    'j' => "jfet",
                    'x' => "subcircuit instance",
                    'e' | 'f' | 'g' | 'h' => "controlled source",
                    'k' => "coupling",
                    't' => "transmission line",
                    _ => "other",
                };
                *kinds.entry(kind.to_string()).or_default() += 1;
            }
            _ => {}
        }
    }
    cx.format_set("elements", hist(kinds));
    for (k, v) in [("subcircuits", subckts), ("models", models), ("analyses", analyses), ("includes", includes)] {
        if !v.is_empty() {
            cx.format_set(k, v.into_iter().take(200).collect::<Vec<_>>());
        }
    }
}

fn ltspice(cx: &mut Context<'_>, text: &str) {
    let mut symbols: BTreeMap<String, u64> = BTreeMap::new();
    let (mut names, mut directives) = (Vec::new(), Vec::new());
    for line in text.lines().take(1_000_000) {
        if let Some(v) = line.strip_prefix("Version ") {
            cx.format_set("version", truncate_chars(v.trim(), 10));
        } else if let Some(s) = line.strip_prefix("SYMBOL ") {
            *symbols.entry(truncate_chars(s.split_whitespace().next().unwrap_or(""), 60)).or_default() += 1;
        } else if let Some(n) = line.strip_prefix("SYMATTR InstName ") {
            if names.len() < 500 {
                names.push(truncate_chars(n.trim(), 50));
            }
        } else if let Some(d) = line.split(" !").nth(1).filter(|_| line.starts_with("TEXT ")) {
            directives.push(truncate_chars(d.trim(), 200));
        }
    }
    cx.format_set("symbols", hist(symbols));
    cx.format_set("instances", names);
    cx.format_set("directives", directives);
}

fn touchstone(cx: &mut Context<'_>, text: &str, ext: Option<&str>) {
    let ports =
        ext.and_then(|e| e.strip_prefix('s')).and_then(|e| e.strip_suffix('p')).and_then(|n| n.parse::<u32>().ok());
    if let Some(p) = ports {
        cx.format_set("ports", p);
    }
    let (mut points, mut fmin, mut fmax) = (0u64, f64::MAX, f64::MIN);
    let mut cols_per_point = ports.map_or(9, |p| 1 + 2 * p * p);
    let mut pending = 0u32;
    for line in text.lines().take(10_000_000) {
        let t = line.split('!').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        if let Some(o) = t.strip_prefix('#') {
            cx.format_set("options", truncate_chars(o.trim(), 60));
            continue;
        }
        if let Some(k) = t.strip_prefix('[') {
            let (key, v) = k.split_once(']').unwrap_or((k, ""));
            match key.to_ascii_lowercase().as_str() {
                "version" => cx.format_set("touchstone_version", truncate_chars(v.trim(), 10)),
                "number of ports" => {
                    if let Ok(p) = v.trim().parse::<u32>() {
                        cx.format_set("ports", p);
                        cols_per_point = 1 + 2 * p * p;
                    }
                }
                _ => {}
            }
            continue;
        }
        let nums: Vec<f64> = t.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if pending == 0 {
            if let Some(&f) = nums.first() {
                points += 1;
                fmin = fmin.min(f);
                fmax = fmax.max(f);
            }
            pending = cols_per_point;
        }
        pending = pending.saturating_sub(u32::try_from(nums.len()).unwrap_or(u32::MAX));
    }
    cx.format_set("frequency_points", points);
    if points > 0 {
        cx.format_set("frequency_min", fmin);
        cx.format_set("frequency_max", fmax);
    }
}

fn ibis(cx: &mut Context<'_>, text: &str) {
    let (mut components, mut models, mut pins) = (Vec::new(), BTreeMap::<String, u64>::new(), 0u64);
    let mut in_pins = false;
    for line in text.lines().take(5_000_000) {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('[') {
            let (k, v) = rest.split_once(']').unwrap_or((rest, ""));
            let v = v.trim();
            in_pins = k == "Pin";
            match k {
                "IBIS Ver" => cx.format_set("ibis_version", truncate_chars(v, 10)),
                "File Name" => cx.format_set("file_name", truncate_chars(v, 100)),
                "File Rev" => cx.format_set("file_revision", truncate_chars(v, 30)),
                "Date" => cx.format_set("date", truncate_chars(v, 60)),
                "Source" => cx.format_set("source", truncate_chars(v, 200)),
                "Component" => components.push(truncate_chars(v, 100)),
                "Manufacturer" => cx.format_set("manufacturer", truncate_chars(v, 100)),
                _ => {}
            }
            continue;
        }
        if in_pins && !t.is_empty() && !t.starts_with('|') && !t.starts_with("signal_name") {
            pins += 1;
        }
        if let Some(mt) = t.strip_prefix("Model_type") {
            *models.entry(truncate_chars(mt.trim(), 30)).or_default() += 1;
        }
    }
    cx.format_set("components", components);
    cx.format_set("pins", pins);
    cx.format_set("model_types", hist(models));
}

fn liberty(cx: &mut Context<'_>, text: &str) {
    let mut cells = Vec::new();
    let mut count = 0u64;
    let it = text.match_indices("cell");
    if let Some(name) = text.split("library").nth(1).and_then(|r| r.split('(').nth(1)).and_then(|r| r.split(')').next())
    {
        cx.format_set("library", truncate_chars(name.trim(), 100));
    }
    for (i, _) in it {
        let rest = text[i + 4..].trim_start();
        if let Some(r) = rest.strip_prefix('(') {
            count += 1;
            if cells.len() < 500 {
                cells.push(truncate_chars(r.split(')').next().unwrap_or("").trim().trim_matches('"'), 100));
            }
        }
    }
    for key in
        ["technology", "delay_model", "time_unit", "voltage_unit", "current_unit", "nom_voltage", "nom_temperature"]
    {
        let v = text.split(key).nth(1).and_then(|r| {
            let r = r.trim_start();
            if let Some(x) = r.strip_prefix(':') {
                x.split(';').next()
            } else {
                r.strip_prefix('(').and_then(|x| x.split(')').next())
            }
        });
        if let Some(v) = v {
            cx.format_set(key, truncate_chars(v.trim().trim_matches('"'), 60));
        }
    }
    cx.format_set("cell_count", count);
    cx.format_set("cells", cells);
}

fn lefdef(cx: &mut Context<'_>, text: &str, def: bool) {
    let (mut layers, mut macros) = (Vec::new(), Vec::new());
    for line in text.lines().take(5_000_000) {
        let t = line.trim();
        let mut w = t.split_whitespace();
        match w.next() {
            Some("VERSION") => {
                cx.format_set("version", truncate_chars(w.next().unwrap_or("").trim_end_matches(';'), 10));
            }
            Some("DESIGN") => {
                let d = w.next().unwrap_or("");
                cx.format_set("design", truncate_chars(d, 100));
                cx.content().source("def.DESIGN").title(truncate_chars(d, 100));
            }
            Some("DATABASE") if w.next() == Some("MICRONS") => cx.format_set(
                "database_units_per_micron",
                w.next().unwrap_or("").trim_end_matches(';').parse::<u64>().unwrap_or(0),
            ),
            Some("UNITS") if def => {
                if let Some(n) = t
                    .split("MICRONS")
                    .nth(1)
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    cx.format_set("database_units_per_micron", n);
                }
            }
            Some("DIEAREA") => cx.format_set(
                "die_area",
                truncate_chars(t.trim_start_matches("DIEAREA").trim().trim_end_matches(';').trim(), 100),
            ),
            Some(k @ ("COMPONENTS" | "NETS" | "PINS" | "SPECIALNETS" | "VIAS" | "ROWS")) if def => {
                if let Some(n) = w.next().and_then(|n| n.parse::<u64>().ok()) {
                    cx.format_set(&k.to_ascii_lowercase(), n);
                }
            }
            Some("LAYER") if !def && layers.len() < 500 => layers.push(truncate_chars(w.next().unwrap_or(""), 50)),
            Some("MACRO") if !def && macros.len() < 5000 => macros.push(truncate_chars(w.next().unwrap_or(""), 100)),
            _ => {}
        }
    }
    if !def {
        cx.format_set("layers", layers);
        cx.format_set("macro_count", macros.len());
        cx.format_set("macros", macros.into_iter().take(500).collect::<Vec<_>>());
    }
}

/// ENVI `key = value` (braced values may span lines).
fn envi(cx: &mut Context<'_>, text: &str) {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in text.lines().skip(1).take(100_000) {
        if let Some((k, v)) = open.as_mut() {
            v.push(' ');
            v.push_str(line.trim());
            if line.contains('}') {
                fields.push((k.clone(), v.clone()));
                open = None;
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        if v.starts_with('{') && !v.contains('}') {
            open = Some((k, v));
        } else {
            fields.push((k, v));
        }
    }
    let list = |v: &str| -> Vec<String> {
        v.trim_matches(['{', '}'])
            .split(',')
            .map(|x| truncate_chars(x.trim(), 60))
            .filter(|x| !x.is_empty())
            .take(1000)
            .collect()
    };
    for (k, v) in &fields {
        match k.as_str() {
            "samples" | "lines" | "bands" | "header offset" | "data type" | "byte order" => {
                if let Ok(n) = v.parse::<u64>() {
                    cx.format_set(&k.replace(' ', "_"), n);
                }
            }
            "interleave" | "file type" | "wavelength units" | "sensor type" => {
                cx.format_set(&k.replace(' ', "_"), truncate_chars(v, 60));
            }
            "description" => {
                let d = v.trim_matches(['{', '}']).trim();
                cx.format_set("description", truncate_chars(d, 500));
                cx.content().source("envi.description").description(truncate_chars(d, 500));
            }
            "band names" => cx.format_set("band_names", list(v)),
            "wavelength" => cx.format_set("wavelengths", list(v)),
            "map info" => cx.format_set("map_projection", list(v).first().cloned().unwrap_or_default()),
            "coordinate system string" => {
                cx.format_set("coordinate_system", truncate_chars(v.trim_matches(['{', '}']), 300));
            }
            _ => {}
        }
    }
    let dtype = fields.iter().find(|(k, _)| k == "data type").and_then(|(_, v)| v.parse::<u32>().ok());
    if let Some(t) = dtype {
        let name = match t {
            1 => "uint8",
            2 => "int16",
            3 => "int32",
            4 => "float32",
            5 => "float64",
            6 => "complex64",
            9 => "complex128",
            12 => "uint16",
            13 => "uint32",
            14 => "int64",
            15 => "uint64",
            _ => "?",
        };
        cx.format_set("data_type_name", name);
    }
}

impl Extractor for ToolText {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let text = std::str::from_utf8(&h[..h.len().min(16 << 10)]).ok()?;
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        let ext = probe.extension.unwrap_or_default();
        if text.contains("Entering Gaussian System") || text.contains("Gaussian, Inc.") {
            return sure("gaussian");
        }
        if text.contains("* O   R   C   A *") {
            return sure("orca");
        }
        if text.starts_with("Version 4") && text.contains("\nSHEET ") {
            return sure("ltspice");
        }
        let first = text.trim_start().lines().next().unwrap_or("");
        if first.starts_with("library") && first.contains('(') && text.contains("cell") {
            return sure("liberty");
        }
        if matches!(ext, "lef" | "def") && text.lines().any(|l| l.trim_start().starts_with("VERSION")) {
            return sure(if ext == "lef" { "lef" } else { "def" });
        }
        if ext.len() >= 3
            && ext.starts_with('s')
            && ext.ends_with('p')
            && text.lines().any(|l| l.trim_start().starts_with('#'))
        {
            return sure("touchstone");
        }
        let spice_ext = matches!(ext, "cir" | "sp" | "spi" | "spice" | "net");
        let spice = spice_ext && text.lines().any(|l| l.trim().to_ascii_lowercase().starts_with(".end"));
        spice.then_some(Sniff { format: "spice", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        // Touchstone gives its port count in the extension (`.s2p`).
        let ext = src.name_hint().and_then(|n| n.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase());
        let text = cx.read_text(src)?.text;
        let id = cx.format_id().to_string();
        match id.as_str() {
            "gaussian" => gaussian(cx, &text),
            "orca" => orca(cx, &text),
            "spice" => spice(cx, &text),
            "ltspice" => ltspice(cx, &text),
            "touchstone" => touchstone(cx, &text, ext.as_deref()),
            "ibis" => ibis(cx, &text),
            "liberty" => liberty(cx, &text),
            "lef" => lefdef(cx, &text, false),
            "def" => lefdef(cx, &text, true),
            _ => envi(cx, &text),
        }
        Ok(())
    }
}

crate::register_extractor!(ToolText);

#[cfg(test)]
mod tests {
    crate::fixture_tests!(
        "gaussian",
        "orca",
        "spice",
        "ltspice",
        "touchstone",
        "ibis",
        "liberty",
        "lef",
        "def",
        "envi"
    );
}
