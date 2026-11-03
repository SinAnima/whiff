//! Chemistry and structural biology files:
//! * PDB: classification, deposition date, ID, title, compound, organism,
//!   method, authors, resolution, unit cell and space group, models,
//!   atoms, chains, residues and ligands;
//! * mmCIF / PDBx: entry ID, title, method, atom-site rows, chains;
//! * MDL MOL and SDF: molecule names, the program line, atom and bond
//!   counts, the formula of the listed atoms (Hill order; implicit
//!   hydrogens are not counted), V2000 / V3000, SDF data fields;
//! * Tripos MOL2: molecules, atom and bond counts, types; XYZ: frames,
//!   atoms, the comment and formula.
//!
//! Specifications: wwPDB "Atomic Coordinate Entry Format" 3.3; PDBx/mmCIF
//! dictionary; BIOVIA "CTfile Formats" (2020); Tripos MOL2 format.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for chemistry files.
pub struct Chem;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.chem",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pdb",
            name: "PDB structure",
            family: "sci",
            mimes: &["chemical/x-pdb"],
            extensions: &["ent"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mmcif",
            name: "mmCIF structure",
            family: "sci",
            mimes: &["chemical/x-mmcif"],
            extensions: &["mmcif"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mol",
            name: "MDL molfile",
            family: "sci",
            mimes: &["chemical/x-mdl-molfile"],
            extensions: &["mol"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "sdf",
            name: "SDF structures",
            family: "sci",
            mimes: &["chemical/x-mdl-sdfile"],
            extensions: &["sdf", "sd"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mol2",
            name: "Tripos MOL2",
            family: "sci",
            mimes: &["chemical/x-mol2"],
            extensions: &["mol2"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "xyz",
            name: "XYZ coordinates",
            family: "sci",
            mimes: &["chemical/x-xyz"],
            extensions: &["xyz"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// The formula in Hill order (C, H, then alphabetical).
fn hill(counts: &BTreeMap<String, u64>) -> String {
    let mut out = String::new();
    let carbon = counts.contains_key("C");
    let mut push = |e: &str, n: u64| {
        out.push_str(e);
        if n > 1 {
            out.push_str(&n.to_string());
        }
    };
    if carbon {
        push("C", counts["C"]);
        if let Some(&h) = counts.get("H") {
            push("H", h);
        }
    }
    for (e, &n) in counts {
        if carbon && (e == "C" || e == "H") {
            continue;
        }
        push(e, n);
    }
    out
}

fn element(s: &str) -> String {
    let s = s.trim();
    let mut c = s.chars();
    match (c.next(), c.next()) {
        // Two letters (PDB writes them upper case: `CL`).
        (Some(a), Some(b)) if b.is_ascii_alphabetic() => {
            format!("{}{}", a.to_ascii_uppercase(), b.to_ascii_lowercase())
        }
        (Some(a), _) => a.to_ascii_uppercase().to_string(),
        _ => String::new(),
    }
}

#[allow(clippy::too_many_lines)] // one arm per record type
fn pdb(cx: &mut Context<'_>, text: &str) {
    let (mut atoms, mut hetatms, mut models) = (0u64, 0u64, 0u64);
    let mut chains = BTreeSet::new();
    let mut residues = BTreeSet::new();
    let mut ligands = BTreeSet::new();
    let mut elements: BTreeMap<String, u64> = BTreeMap::new();
    let mut title = String::new();
    let mut authors = String::new();
    for line in text.lines().take(5_000_000) {
        let rec = line.get(..6).unwrap_or(line).trim_end();
        let rest = line.get(10..).unwrap_or("").trim();
        match rec {
            "HEADER" => {
                cx.format_set("classification", truncate_chars(line.get(10..50).unwrap_or("").trim(), 100));
                cx.format_set("deposition_date", line.get(50..59).unwrap_or("").trim());
                let id = line.get(62..66).unwrap_or("").trim();
                if !id.is_empty() {
                    cx.format_set("id_code", id);
                }
            }
            "TITLE" => {
                if !title.is_empty() {
                    title.push(' ');
                }
                title.push_str(rest);
            }
            "COMPND" if rest.contains("MOLECULE:") => {
                cx.format_set(
                    "compound",
                    truncate_chars(rest.split("MOLECULE:").nth(1).unwrap_or("").trim().trim_end_matches(';'), 200),
                );
            }
            "SOURCE" if rest.contains("ORGANISM_SCIENTIFIC:") => {
                cx.format_set(
                    "organism",
                    truncate_chars(
                        rest.split("ORGANISM_SCIENTIFIC:").nth(1).unwrap_or("").trim().trim_end_matches(';'),
                        200,
                    ),
                );
            }
            "EXPDTA" => cx.format_set("method", truncate_chars(rest, 100)),
            "AUTHOR" => authors.push_str(rest),
            "REMARK" if line.get(6..10).map(str::trim) == Some("2") && line.contains("RESOLUTION.") => {
                if let Some(r) = line
                    .split("RESOLUTION.")
                    .nth(1)
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|r| r.parse::<f64>().ok())
                {
                    cx.format_set("resolution_angstrom", r);
                }
            }
            "CRYST1" => {
                cx.format_set("unit_cell", truncate_chars(line.get(6..54).unwrap_or("").trim(), 100));
                cx.format_set("space_group", truncate_chars(line.get(55..66).unwrap_or("").trim(), 20));
            }
            "MODEL" => models += 1,
            "ATOM" | "HETATM" => {
                if rec == "ATOM" {
                    atoms += 1;
                } else {
                    hetatms += 1;
                    let res = line.get(17..20).unwrap_or("").trim();
                    if res != "HOH" && ligands.len() < 200 {
                        ligands.insert(res.to_string());
                    }
                }
                let chain = line.get(21..22).unwrap_or("").trim();
                if chains.len() < 1000 {
                    chains.insert(chain.to_string());
                }
                let resid = (chain.to_string(), line.get(22..27).unwrap_or("").trim().to_string());
                if residues.len() < 1_000_000 {
                    residues.insert(resid);
                }
                let e = element(line.get(76..78).unwrap_or_else(|| line.get(12..14).unwrap_or("")));
                if !e.is_empty() {
                    *elements.entry(e).or_default() += 1;
                }
            }
            _ => {}
        }
    }
    if !title.is_empty() {
        cx.format_set("title", truncate_chars(&title, 500));
        cx.content().source("pdb.TITLE").title(truncate_chars(&title, 300));
    }
    if !authors.is_empty() {
        cx.format_set("authors", truncate_chars(&authors, 500));
    }
    cx.format_set("models", models.max(1));
    cx.format_set("atoms", atoms);
    cx.format_set("hetero_atoms", hetatms);
    cx.format_set("chains", chains.into_iter().filter(|c| !c.is_empty()).collect::<Vec<_>>());
    cx.format_set("residues", residues.len());
    if !ligands.is_empty() {
        cx.format_set("ligands", ligands.into_iter().collect::<Vec<_>>());
    }
    if !elements.is_empty() {
        cx.format_set(
            "elements",
            Value::Object(elements.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()),
        );
    }
}

fn mmcif(cx: &mut Context<'_>, text: &str) {
    let mut rows = 0u64;
    let mut in_atoms = false;
    let mut chain_col = None;
    let mut cols = 0usize;
    let mut chains = BTreeSet::new();
    for line in text.lines().take(5_000_000) {
        let t = line.trim();
        if let Some(b) = t.strip_prefix("data_") {
            cx.format_set("data_block", truncate_chars(b, 100));
            continue;
        }
        let value = |key: &str| {
            t.strip_prefix(key)
                .map(|v| v.trim().trim_matches(['\'', '"']).to_string())
                .filter(|v| !v.is_empty() && v != "?" && v != ".")
        };
        if let Some(v) = value("_entry.id") {
            cx.format_set("entry_id", truncate_chars(&v, 50));
        } else if let Some(v) = value("_struct.title") {
            cx.format_set("title", truncate_chars(&v, 300));
            cx.content().source("mmcif._struct.title").title(truncate_chars(&v, 300));
        } else if let Some(v) = value("_exptl.method") {
            cx.format_set("method", truncate_chars(&v, 100));
        }
        if t.starts_with("_atom_site.") {
            in_atoms = true;
            if t == "_atom_site.auth_asym_id" || (chain_col.is_none() && t == "_atom_site.label_asym_id") {
                chain_col = Some(cols);
            }
            cols += 1;
            continue;
        }
        if in_atoms {
            if t.starts_with("ATOM") || t.starts_with("HETATM") {
                rows += 1;
                if let Some(c) = chain_col.and_then(|i| t.split_whitespace().nth(i))
                    && chains.len() < 1000
                {
                    chains.insert(c.to_string());
                }
            } else if t == "#" || t.starts_with("loop_") || t.starts_with('_') {
                in_atoms = false;
            }
        }
    }
    cx.format_set("atom_site_rows", rows);
    cx.format_set("chains", chains.into_iter().collect::<Vec<_>>());
}

/// One MDL molfile block: (name, program line, atoms, bonds, version, formula).
fn molblock(b: &str) -> Option<(String, String, u64, u64, String, String)> {
    let lines: Vec<&str> = b.lines().collect();
    let name = lines.first()?.trim().to_string();
    let program = lines.get(1).map_or("", |l| l.trim()).to_string();
    let counts = lines.get(3)?;
    let mut elements: BTreeMap<String, u64> = BTreeMap::new();
    if counts.contains("V3000") {
        let (mut atoms, mut bonds) = (0, 0);
        for l in &lines {
            if let Some(c) = l.trim().strip_prefix("M  V30 COUNTS") {
                let mut it = c.split_whitespace();
                atoms = it.next()?.parse().ok()?;
                bonds = it.next()?.parse().ok()?;
            }
        }
        let mut in_atoms = false;
        for l in &lines {
            let t = l.trim();
            if t == "M  V30 BEGIN ATOM" {
                in_atoms = true;
            } else if t == "M  V30 END ATOM" {
                in_atoms = false;
            } else if in_atoms && let Some(e) = t.split_whitespace().nth(3) {
                *elements.entry(element(e)).or_default() += 1;
            }
        }
        return Some((name, program, atoms, bonds, "V3000".into(), hill(&elements)));
    }
    let atoms: u64 = counts.get(..3)?.trim().parse().ok()?;
    let bonds: u64 = counts.get(3..6)?.trim().parse().ok()?;
    for l in lines.iter().skip(4).take(usize::try_from(atoms).unwrap_or(0).min(100_000)) {
        let e = l.get(31..34).unwrap_or("").trim();
        if !e.is_empty() {
            *elements.entry(element(e)).or_default() += 1;
        }
    }
    Some((name, program, atoms, bonds, "V2000".into(), hill(&elements)))
}

/// The records of an SD file. Only the line break after `$$$$` is
/// dropped: a record's first line (the name) may be empty.
fn sd_records(text: &str) -> impl Iterator<Item = &str> {
    text.split("$$$$")
        .enumerate()
        .map(
            |(i, rec)| {
                if i == 0 { rec } else { rec.strip_prefix("\r\n").or_else(|| rec.strip_prefix('\n')).unwrap_or(rec) }
            },
        )
        .filter(|rec| !rec.trim().is_empty())
}

fn sdf(cx: &mut Context<'_>, text: &str, single: bool) {
    let mut mols = Vec::new();
    let mut fields = BTreeSet::new();
    for rec in sd_records(text).take(1_000_000) {
        if let Some(m) = molblock(rec) {
            mols.push(m);
        }
        for l in rec.lines() {
            if let Some(f) = l.strip_prefix("> ").and_then(|f| f.split('<').nth(1)).and_then(|f| f.split('>').next())
                && fields.len() < 200
            {
                fields.insert(f.to_string());
            }
        }
    }
    if single {
        if let Some((name, program, atoms, bonds, version, formula)) = mols.first() {
            cx.format_set("name", truncate_chars(name, 200));
            if !name.is_empty() {
                cx.content().source("mol.name").title(truncate_chars(name, 200));
            }
            cx.format_set("program", truncate_chars(program, 100));
            cx.format_set("atoms", *atoms);
            cx.format_set("bonds", *bonds);
            cx.format_set("ctab_version", version.clone());
            cx.format_set("atom_formula", formula.clone());
        }
        return;
    }
    cx.format_set("molecules", mols.len());
    let names: Vec<String> = mols.iter().take(100).map(|m| truncate_chars(&m.0, 100)).collect();
    cx.format_set("names", names);
    let formulas: Vec<String> = mols.iter().take(100).map(|m| m.5.clone()).collect();
    cx.format_set("atom_formulas", formulas);
    if !fields.is_empty() {
        cx.format_set("data_fields", fields.into_iter().collect::<Vec<_>>());
    }
}

fn mol2(cx: &mut Context<'_>, text: &str) {
    let mut mols = 0u64;
    let mut names = Vec::new();
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l.trim() == "@<TRIPOS>MOLECULE" {
            mols += 1;
            let name = lines.next().unwrap_or("").trim().to_string();
            let counts: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
            if names.len() < 100 {
                names.push(Value::String(format!(
                    "{} ({} atoms, {} bonds)",
                    truncate_chars(&name, 100),
                    counts.first().unwrap_or(&"?"),
                    counts.get(1).unwrap_or(&"?")
                )));
            }
            if let Some(kind) = lines.next() {
                cx.format_set("molecule_type", truncate_chars(kind.trim(), 30));
            }
        }
    }
    cx.format_set("molecules", mols);
    cx.format_set("molecule_list", names);
}

fn xyz(cx: &mut Context<'_>, text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    let mut frames = 0u64;
    let mut elements: BTreeMap<String, u64> = BTreeMap::new();
    while let Some(n) = lines.get(i).and_then(|l| l.trim().parse::<usize>().ok()) {
        if frames == 0 {
            cx.format_set("atoms", n);
            cx.format_set("comment", truncate_chars(lines.get(i + 1).map_or("", |c| c.trim()), 200));
            for l in lines.iter().skip(i + 2).take(n.min(1_000_000)) {
                if let Some(e) = l.split_whitespace().next() {
                    *elements.entry(element(e)).or_default() += 1;
                }
            }
        }
        frames += 1;
        i += n + 2;
        if frames > 1_000_000 {
            break;
        }
    }
    cx.format_set("frames", frames);
    cx.format_set("formula", hill(&elements));
}

impl Extractor for Chem {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = std::str::from_utf8(&probe.head[..probe.head.len().min(8192)]).ok()?;
        let ext = probe.extension.unwrap_or_default();
        let lines: Vec<&str> = text.lines().take(40).collect();
        let pdb_rec = |l: &&str| {
            ["HEADER", "ATOM  ", "HETATM", "CRYST1", "COMPND", "REMARK", "TITLE "].iter().any(|r| l.starts_with(r))
        };
        if (ext == "pdb" || ext == "ent") && lines.iter().filter(|l| pdb_rec(l)).count() >= 2 {
            return Some(Sniff { format: "pdb", confidence: 0.97 });
        }
        if lines.first().is_some_and(|l| l.starts_with("data_"))
            && text.contains("\n_")
            && matches!(ext, "cif" | "mmcif")
        {
            return Some(Sniff { format: "mmcif", confidence: 0.95 });
        }
        if text.contains("@<TRIPOS>MOLECULE") {
            return Some(Sniff { format: "mol2", confidence: 0.97 });
        }
        let ctab = lines.get(3).is_some_and(|l| l.contains("V2000") || l.contains("V3000"));
        if ctab {
            let format = if ext == "sdf" || ext == "sd" || text.contains("$$$$") { "sdf" } else { "mol" };
            return Some(Sniff { format, confidence: 0.97 });
        }
        let xyz = ext == "xyz" && lines.first().is_some_and(|l| l.trim().parse::<u32>().is_ok());
        xyz.then_some(Sniff { format: "xyz", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        match cx.format_id() {
            "pdb" => pdb(cx, &text),
            "mmcif" => mmcif(cx, &text),
            "mol" => sdf(cx, &text, true),
            "sdf" => sdf(cx, &text, false),
            "mol2" => mol2(cx, &text),
            _ => xyz(cx, &text),
        }
        Ok(())
    }
}

crate::register_extractor!(Chem);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sd_empty_names() {
        let mol = "\n     RDKit          2D\n\n  1  0  0  0  0  0  0  0  0  0999 V2000\n    0.0000    0.0000    0.0000 C   0  0\nM  END\n";
        let text = format!("{mol}$$$$\n{mol}$$$$\n");
        let recs: Vec<_> = sd_records(&text).collect();
        assert_eq!(recs.len(), 2);
        let (name, _, atoms, bonds, version, _) = molblock(recs[1]).unwrap();
        assert_eq!((name.as_str(), atoms, bonds, version.as_str()), ("", 1, 0, "V2000"));
    }

    #[test]
    fn hill_order() {
        let m: BTreeMap<String, u64> =
            [("O".into(), 2), ("C".into(), 3), ("H".into(), 7), ("N".into(), 1)].into_iter().collect();
        assert_eq!(hill(&m), "C3H7NO2");
        let w: BTreeMap<String, u64> = [("O".into(), 1), ("H".into(), 2)].into_iter().collect();
        assert_eq!(hill(&w), "H2O");
        assert_eq!(element("CL"), "Cl");
    }

    crate::fixture_tests!("pdb", "mmcif", "mol", "sdf", "mol2", "xyz");
}
