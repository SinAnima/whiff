//! `whiff-dev catalogue`: regenerate `docs/metadata-extracted.md` from
//! `data/families.tsv`, `data/formats.tsv`, `data/catalogue-header.md` and the
//! extractors compiled into this build (the "Extractor" column).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use whiff::Registry;
use whiff::plugin::Probe;

pub struct Family {
    pub id: String,
    pub category: String,
    pub feature: String,
    pub status: String,
    pub stage: String,
    pub information: String,
    pub llm_value: String,
    pub libraries: String,
}

pub struct Format {
    pub tier: u8,
    pub family: String,
    pub name: String,
    pub extensions: String,
    pub mime: String,
    pub note: String,
    pub order: usize,
}

fn rows(path: &Path, columns: usize) -> Result<Vec<Vec<String>>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let cells: Vec<String> = line.split('\t').map(str::to_string).collect();
        if cells.len() != columns {
            return Err(format!(
                "{}:{}: expected {columns} tab-separated columns, found {}",
                path.display(),
                n + 1,
                cells.len()
            ));
        }
        out.push(cells);
    }
    Ok(out)
}

pub fn load_families(root: &Path) -> Result<Vec<Family>, String> {
    rows(&root.join("data/families.tsv"), 8).map(|rows| {
        rows.into_iter()
            .map(|c| {
                let mut c = c.into_iter();
                let mut next = || c.next().unwrap_or_default();
                Family {
                    id: next(),
                    category: next(),
                    feature: next(),
                    status: next(),
                    stage: next(),
                    information: next(),
                    llm_value: next(),
                    libraries: next(),
                }
            })
            .collect()
    })
}

pub fn load_formats(root: &Path, families: &[Family]) -> Result<Vec<Format>, String> {
    let mut out = Vec::new();
    for (order, c) in rows(&root.join("data/formats.tsv"), 6)?.into_iter().enumerate() {
        let tier: u8 = c[0].parse().map_err(|_| format!("formats.tsv row {}: bad tier `{}`", order + 1, c[0]))?;
        if !families.iter().any(|f| f.id == c[1]) {
            return Err(format!("formats.tsv row {}: unknown family `{}`", order + 1, c[1]));
        }
        out.push(Format {
            tier,
            family: c[1].clone(),
            name: c[2].clone(),
            extensions: c[3].clone(),
            mime: c[4].clone(),
            note: c[5].clone(),
            order,
        });
    }
    Ok(out)
}

/// `data/coverage.tsv`: catalogue row name → the format id that handles it.
/// Every row must name a catalogue row and a format of this build.
fn load_overrides(root: &Path, formats: &[Format], registry: &Registry) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (n, c) in rows(&root.join("data/coverage.tsv"), 2)?.into_iter().enumerate() {
        let (name, id) = (&c[0], &c[1]);
        if !formats.iter().any(|f| f.name == *name) {
            return Err(format!("coverage.tsv row {}: no catalogue row `{name}`", n + 1));
        }
        if !registry.formats().any(|(spec, _)| spec.id == id) {
            return Err(format!("coverage.tsv row {}: no format `{id}` in this build", n + 1));
        }
        out.insert(name.clone(), id.clone());
    }
    Ok(out)
}

fn esc(s: &str) -> String {
    s.replace('<', "&lt;").replace('>', "&gt;").replace('|', "\\|")
}

fn stage_rank(stage: &str) -> u8 {
    stage.get(1..2).and_then(|d| d.parse().ok()).unwrap_or(9)
}

fn stage_for(f: &Format, fam: &Family, covered: bool) -> String {
    let note = f.note.to_lowercase();
    // Long-tail formats wait for S8 unless their family's stage already did them.
    if !covered && f.tier == 3 && (fam.status == "impl" || note.contains("header") || note.contains("impl")) {
        return "S8".into();
    }
    if f.tier == 1 { fam.stage.split('/').next().unwrap_or(&fam.stage).to_string() } else { fam.stage.clone() }
}

fn exts_md(e: &str) -> String {
    if e.is_empty() {
        return "—".into();
    }
    e.split_whitespace().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(" ")
}

fn short_lib(lib: &str) -> String {
    let first = lib.split(';').next().unwrap_or("");
    let first = first.split(" (").next().unwrap_or("");
    first.split(", ").take(2).collect::<Vec<_>>().join(", ")
}

/// Counts in first-seen order, then sorted by count (stable), like Python's `Counter.most_common`.
fn most_common<'a>(items: impl Iterator<Item = &'a str>) -> Vec<(&'a str, usize)> {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for item in items {
        match counts.iter_mut().find(|(k, _)| *k == item) {
            Some((_, n)) => *n += 1,
            None => counts.push((item, 1)),
        }
    }
    counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    counts
}

/// The extractor that handles a catalogue row: the format named for it in
/// `data/coverage.tsv`, else a format of the same family with the row's
/// name, else one with one of its extensions (in the row's order), else a
/// sniffer that recognises the row's file names.
fn coverage(registry: &Registry, f: &Format, overrides: &HashMap<String, String>) -> Option<&'static str> {
    if let Some(id) = overrides.get(&f.name) {
        return registry.formats().find(|(spec, _)| spec.id == id).map(|(_, e)| e.meta().id);
    }
    if let Some((_, e)) =
        registry.formats().find(|(spec, _)| spec.family == f.family && spec.name.eq_ignore_ascii_case(&f.name))
    {
        return Some(e.meta().id);
    }
    let by_extension = f.extensions.split_whitespace().map(str::to_ascii_lowercase).find_map(|x| {
        registry.formats().find(|(spec, _)| spec.family == f.family && spec.extensions.contains(&x.as_str()))
    });
    by_extension.map(|(_, e)| e.meta().id).or_else(|| {
        registry
            .extractors()
            .find(|e| {
                f.extensions.split_whitespace().any(|name| {
                    let probe = Probe { head: &[], tail: &[], len: 0, name: Some(name), extension: None };
                    e.sniff(&probe).is_some_and(|s| {
                        e.meta().formats.iter().any(|spec| spec.id == s.format && spec.family == f.family)
                    })
                })
            })
            .map(|e| e.meta().id)
    })
}

pub fn render(root: &Path, registry: &Registry) -> Result<String, String> {
    let families = load_families(root)?;
    let formats = load_formats(root, &families)?;
    let header = std::fs::read_to_string(root.join("data/catalogue-header.md"))
        .map_err(|e| format!("catalogue-header.md: {e}"))?;
    let fam: HashMap<&str, (usize, &Family)> =
        families.iter().enumerate().map(|(i, f)| (f.id.as_str(), (i, f))).collect();

    let mut rows: Vec<&Format> = formats.iter().collect();
    rows.sort_by_key(|r| {
        let (idx, f) = fam[r.family.as_str()];
        (r.tier, stage_rank(&f.stage), idx, r.order)
    });

    let mut out: Vec<String> = vec![header.trim_end().to_string() + "\n", "\n## 3. Parser families\n".into()];
    out.push("Each format in §5 maps to one **family**. A family is one extractor implementation (or one reusable *block decoder*, marked `Block`) that serves every format in it. This is why ~1000 formats need ~60 extractors.\n".into());
    out.push("Status: **crate** means a pure-Rust crate does the heavy lifting. **mixed** means a crate parses the container and whiff maps it to the schema. **impl** means no suitable pure-Rust crate exists, so whiff implements the parser.\n".into());
    out.push("| Family | Category | Feature | Information extracted | Why it helps an LLM | Library / implementation | Status | Stage | # formats |".into());
    out.push("|---|---|---|---|---|---|---|---|---|".into());
    for f in &families {
        let n = rows.iter().filter(|r| r.family == f.id).count();
        out.push(format!(
            "| `{}` | {} | `{}` | {} | {} | {} | {} | {} | {n} |",
            f.id,
            f.category,
            f.feature,
            esc(&f.information),
            esc(&f.llm_value),
            esc(&f.libraries),
            f.status,
            f.stage
        ));
    }

    out.push("\n## 4. Coverage summary\n".into());
    let tier = |t: u8| rows.iter().filter(|r| r.tier == t).count();
    out.push(format!(
        "* **{} formats** in total: tier 1 = {}, tier 2 = {}, tier 3 = {}.",
        rows.len(),
        tier(1),
        tier(2),
        tier(3)
    ));
    let overrides = load_overrides(root, &formats, registry)?;
    let cov: HashMap<usize, Option<&'static str>> =
        rows.iter().map(|r| (r.order, coverage(registry, r, &overrides))).collect();
    let covered = cov.values().filter(|c| c.is_some()).count();
    out.push(format!("* Formats with an extractor in this build: **{covered}** of {}.", rows.len()));
    let status = |s: &str| rows.iter().filter(|r| fam[r.family.as_str()].1.status == s).count();
    out.push(format!(
        "* Formats by family status: crate = {}, mixed = {}, impl = {}.",
        status("crate"),
        status("mixed"),
        status("impl")
    ));
    let mut stages: Vec<(String, usize)> = Vec::new();
    for r in &rows {
        let s = stage_for(r, fam[r.family.as_str()].1, cov[&r.order].is_some());
        match stages.iter_mut().find(|(k, _)| *k == s) {
            Some((_, n)) => *n += 1,
            None => stages.push((s, 1)),
        }
    }
    stages.sort();
    out.push(format!(
        "* Formats by target stage: {}.",
        stages.iter().map(|(k, n)| format!("{k} = {n}")).collect::<Vec<_>>().join(", ")
    ));
    let features = most_common(rows.iter().map(|r| fam[r.family.as_str()].1.feature.as_str()));
    out.push(format!(
        "* By feature: {}.",
        features.iter().map(|(k, n)| format!("`{k}` = {n}")).collect::<Vec<_>>().join(", ")
    ));
    let cats = most_common(rows.iter().map(|r| fam[r.family.as_str()].1.category.as_str()));
    out.push(format!(
        "* By category: {}.\n",
        cats.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ")
    ));

    out.push("## 5. Format table\n".into());
    out.push("`#` is the position after sorting by tier, then by stage and family. **Tier 1** is the ~140 formats a general-purpose tool meets every day. **Tier 2** is common in professional or specialist work. **Tier 3** is the long tail. Ordering inside a tier is by family, not a fine-grained popularity rank. \"Stage\" is the implementation stage (S0–S8) in the implementation plan. \"Feature\" is the cargo feature of the `whiff` crate that compiles the extractor: `common` is on by default; `geo`, `science`, `data`, `cad`, `forensics` and `games` are opt-in (`full` enables all). \"Extractor\" is the extractor that handles the format today (`—` = not implemented yet). Tier-3 formats not handled yet are scheduled for S8, the long-tail stage, when they need an in-house parser (impl family, or the notes say \"header\" / \"impl\").\n".into());
    out.push("| # | Format | Extensions | MIME | Tier | Family | Feature | Extractor | Library | Stage | Format-specific extras |".into());
    out.push("|---|---|---|---|---|---|---|---|---|---|---|".into());
    for (n, r) in rows.iter().enumerate() {
        let f = fam[r.family.as_str()].1;
        let ext = cov[&r.order].map_or_else(|| "—".to_string(), |id| format!("`{id}`"));
        let mut line = String::new();
        let _ = write!(
            line,
            "| {} | {} | {} | {} | {} | `{}` | `{}` | {ext} | {} | {} | {} |",
            n + 1,
            esc(&r.name),
            exts_md(&r.extensions),
            if r.mime.is_empty() { "—".to_string() } else { esc(&r.mime) },
            r.tier,
            r.family,
            f.feature,
            esc(&short_lib(&f.libraries)),
            stage_for(r, f, cov[&r.order].is_some()),
            if r.note.is_empty() { "—".to_string() } else { esc(&r.note) },
        );
        out.push(line);
    }
    Ok(out.join("\n") + "\n")
}

/// `docs/risks.md`: the risk vocabulary, by category.
pub fn render_risks() -> String {
    use std::fmt::Write as _;

    use whiff::{RISK_KINDS, RiskCategory};
    let mut out = String::from(
        "<!-- Generated by `cargo run --features dev --bin whiff-dev -- catalogue` from src/report/risk.rs. Do not edit. -->\n\
         # Risk signals\n\n\
         Every `security.risks[].kind` whiff reports, with the `category` and `severity` the engine\n\
         attaches to it. `security.risk_level` is the highest severity among a file's own risks and\n\
         those of its embedded files; `security.embedded_risks` counts the embedded files' risks by\n\
         kind. A risk is a signal worth a look, not a verdict: most kinds also occur in benign files.\n\n\
         Severities: **high**, rarely legitimate or a known exploitation or deception technique;\n\
         **medium**, can act for the reader or reach out but has legitimate uses; **low**, common in\n\
         benign files; **info**, worth knowing only.\n",
    );
    let categories = [
        (RiskCategory::ActiveContent, "Active content", "Code that can run: macros, scripts, actions, DDE."),
        (
            RiskCategory::Phishing,
            "Phishing",
            "Deceiving the reader: spoofed senders, misleading links, credential forms.",
        ),
        (
            RiskCategory::ExternalReference,
            "External references",
            "Content fetched from elsewhere when the file is opened.",
        ),
        (RiskCategory::Exploit, "Exploit techniques", "Constructs tied to known exploitation techniques."),
        (RiskCategory::Obfuscation, "Obfuscation", "Content hidden from a casual look."),
        (RiskCategory::DataExposure, "Data exposure", "Secrets or credentials in the content."),
        (RiskCategory::SupplyChain, "Supply chain", "Installs, fetches or trusts code from elsewhere."),
        (
            RiskCategory::UnsafeOperation,
            "Unsafe operations",
            "Operations that change or destroy state with broad privileges.",
        ),
        (RiskCategory::Provenance, "Provenance", "Where the content came from."),
    ];
    for (category, title, blurb) in categories {
        let mut kinds: Vec<_> = RISK_KINDS.iter().filter(|k| k.category == category).collect();
        if kinds.is_empty() {
            continue;
        }
        kinds.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(b.kind)));
        let _ = write!(
            out,
            "\n## {title} (`{}`)\n\n{blurb}\n\n| Kind | Severity | Meaning |\n|---|---|---|\n",
            category.as_str()
        );
        for k in kinds {
            let _ = writeln!(out, "| `{}` | {} | {} |", k.kind, k.severity.as_str(), k.meaning.replace('|', "\\|"));
        }
    }
    out
}
