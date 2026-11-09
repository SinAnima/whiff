//! Writing in plain-text and XML formats: citations, typesetting and
//! screenwriting sources, notes and note boards, word processors' and
//! spreadsheets' own XML. Each gives its title, authors, outline or entry
//! list, and hands its prose to the text analysis.
//!
//! * citations: RIS (`TY  - … ER  -`), EndNote tagged (`%0`, `%T` …),
//!   MEDLINE / PubMed (`PMID- …`) — entries, types, years, DOIs, distinct
//!   authors, titles — and CSL styles (title, id, citation format, parent);
//! * Typst (`#set document(...)`, `=` headings, `#import` packages), LyX
//!   (format, document class, title, author, sections) and Scribus
//!   (version, title, author, pages, text frames);
//! * Evernote exports (`.enex`: notes, titles, tags, dates) and Obsidian
//!   canvases (nodes by type, edges, text);
//! * Fountain screenplays (title page, scene headings, characters), Final
//!   Draft (`.fdx`) and Scrivener projects (`.scrivx`: binder items);
//! * AbiWord (`.abw`: Dublin Core metadata, sections) and Gnumeric
//!   workbooks (gzip XML: sheets, size, metadata);
//! * Marp slide decks (Markdown with `marp: true`: slides and their titles).
//!
//! Specifications: the RIS format (Research Information Systems), EndNote's
//! tagged import format, NLM's MEDLINE element list, CSL 1.0.2, Typst's
//! `document` function, LyX's file format notes, Scribus's SLA schema,
//! Evernote's ENEX DTD, JSON Canvas 1.0, Fountain 1.1, Final Draft's FDX,
//! Scrivener 3's `.scrivx`, AbiWord's and Gnumeric's schemas, Marp's
//! directives.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, xmlwalk,
};

/// Extractor for citation, typesetting, note, screenplay and XML office files.
pub struct Writing;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "doc.other",
            mimes: &[$mime],
            extensions: &[$($ext),*],
            magic: &[$($magic),*],
            parent: None,
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.writing",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "ris",
            "RIS citations",
            "application/x-research-info-systems",
            ["ris"],
            [Magic::prefix(b"TY  - "), Magic::prefix(b"\xef\xbb\xbfTY  - ")]
        ),
        spec!(
            "endnote",
            "EndNote tagged citations",
            "application/x-endnote-refer",
            ["enw"],
            [Magic::prefix(b"%0 "), Magic::prefix(b"\xef\xbb\xbf%0 ")]
        ),
        spec!("medline", "MEDLINE / PubMed citations", "application/nbib", ["nbib"], [Magic::prefix(b"PMID- ")]),
        spec!("csl_style", "CSL citation style", "application/vnd.citationstyles.style+xml", ["csl"], []),
        spec!("typst", "Typst document", "text/x-typst", ["typ"], []),
        spec!("lyx", "LyX document", "application/x-lyx", ["lyx"], [Magic::prefix(b"#LyX ")]),
        spec!("scribus", "Scribus document", "application/vnd.scribus", ["sla"], []),
        spec!("enex", "Evernote export", "application/enex+xml", ["enex"], []),
        spec!("obsidian_canvas", "Obsidian / JSON Canvas", "application/json", ["canvas"], []),
        spec!("fountain", "Fountain screenplay", "text/x-fountain", ["fountain", "spmd"], []),
        spec!("final_draft", "Final Draft screenplay", "application/x-final-draft", ["fdx"], []),
        spec!("scrivener", "Scrivener project", "application/x-scrivener", ["scrivx", "scriv"], []),
        spec!("abiword", "AbiWord document", "application/x-abiword", ["abw", "zabw"], []),
        spec!("gnumeric", "Gnumeric workbook", "application/x-gnumeric", ["gnumeric"], []),
        spec!("marp", "Marp slide deck", "text/markdown", ["marp"], []),
    ],
};

/// Entries, titles and names listed.
const MAX_LISTED: usize = 50;
/// XML events read.
const MAX_EVENTS: usize = 1_000_000;

impl Extractor for Writing {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = &probe.head[..probe.head.len().min(8192)];
        let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
        let ext = probe.extension.unwrap_or("");
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        // Gnumeric files are gzip-compressed XML.
        if h.starts_with(&[0x1f, 0x8b]) {
            return (ext == "gnumeric").then_some(Sniff { format: "gnumeric", confidence: 0.9 });
        }
        if has(b"<en-export") {
            return pick("enex", 0.95);
        }
        if has(b"<FinalDraft") {
            return pick("final_draft", 0.95);
        }
        if has(b"<ScrivenerProject") {
            return pick("scrivener", 0.95);
        }
        if has(b"<SCRIBUSUTF8NEW") || has(b"<SCRIBUSUTF8") {
            return pick("scribus", 0.95);
        }
        if has(b"<abiword") {
            return pick("abiword", 0.95);
        }
        if has(b"<gnm:Workbook") {
            return pick("gnumeric", 0.95);
        }
        if has(b"<style") && has(b"http://purl.org/net/xbiblio/csl") {
            return pick("csl_style", 0.95);
        }
        if ext == "canvas" && h.trim_ascii_start().starts_with(b"{") && (has(b"\"nodes\"") || has(b"\"edges\"")) {
            return pick("obsidian_canvas", 0.9);
        }
        // Markdown front matter with `marp: true`.
        if h.starts_with(b"---") && (has(b"\nmarp: true") || has(b"\nmarp:true")) {
            return pick("marp", 0.9);
        }
        if ext == "typ" && (has(b"#set ") || has(b"#import ") || has(b"#let ") || h.starts_with(b"= ")) {
            return pick("typst", 0.85);
        }
        if matches!(ext, "fountain" | "spmd") || (has(b"\nINT. ") || has(b"\nEXT. ")) && h.starts_with(b"Title:") {
            return pick("fountain", 0.85);
        }
        // Citations whose first record follows a blank line or a BOM.
        let start = h.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h).trim_ascii_start();
        if start.starts_with(b"TY  - ") {
            return pick("ris", 0.9);
        }
        if start.starts_with(b"PMID- ") {
            return pick("medline", 0.9);
        }
        if start.starts_with(b"%0 ") && (has(b"\n%T ") || has(b"\n%A ")) {
            return pick("endnote", 0.9);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let n = src.len().min(cx.parse_limit() as u64);
        let mut raw = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
        if raw.starts_with(&[0x1f, 0x8b]) {
            raw = cx.inflate(&raw, Compression::Gzip, cx.parse_limit())?;
        }
        let text = crate::plugin::decode_text(&raw).text;
        let format = cx.format_id().to_string();
        match format.as_str() {
            "ris" | "endnote" | "medline" => citations(cx, &format, &text),
            "csl_style" => csl(cx, &text),
            "typst" => typst(cx, &text),
            "lyx" => lyx(cx, &text),
            "scribus" => scribus(cx, &text),
            "enex" => enex(cx, &text),
            "obsidian_canvas" => canvas(cx, &text),
            "fountain" => fountain(cx, &text),
            "final_draft" => final_draft(cx, &text),
            "scrivener" => scrivener(cx, &text),
            "abiword" => abiword(cx, &text),
            "gnumeric" => gnumeric(cx, &text),
            _ => marp(cx, &text),
        }
    }
}

crate::register_extractor!(Writing);

fn strings(v: impl IntoIterator<Item = String>) -> Value {
    Value::Array(v.into_iter().take(MAX_LISTED).map(Value::String).collect())
}

// --- citations ---------------------------------------------------------------------

/// One citation: its type and tagged fields.
#[derive(Default)]
struct Citation {
    kind: String,
    title: Option<String>,
    authors: Vec<String>,
    year: Option<u16>,
    doi: bool,
}

fn year_of(v: &str) -> Option<u16> {
    v.split(|c: char| !c.is_ascii_digit()).find(|w| w.len() == 4).and_then(|w| w.parse().ok())
}

/// Tagged records: RIS (`XX  - value`, `ER  -` ends), EndNote (`%X value`,
/// blank line ends), MEDLINE (`XXXX- value`, continuation lines indented,
/// blank line ends).
fn citation_records(format: &str, text: &str) -> Vec<Citation> {
    let mut out: Vec<Citation> = Vec::new();
    let mut cur: Option<Citation> = None;
    let mut last_tag = String::new();
    for line in text.lines() {
        let (tag, value) = match format {
            "ris" => match line.get(..6) {
                Some(t) if t.as_bytes()[2..6] == *b"  - " || line.get(2..5) == Some("  -") => {
                    (t[..2].to_string(), line.get(6..).unwrap_or("").trim())
                }
                _ => continue,
            },
            "endnote" => {
                if line.trim().is_empty() {
                    out.extend(cur.take());
                    continue;
                }
                match line.strip_prefix('%').and_then(|l| l.split_once(' ')) {
                    Some((t, v)) => (t.to_string(), v.trim()),
                    None => continue,
                }
            }
            _ => {
                if line.trim().is_empty() {
                    out.extend(cur.take());
                    continue;
                }
                if line.starts_with(' ') {
                    // A continuation of the last field.
                    if last_tag == "TI"
                        && let Some(t) = cur.as_mut().and_then(|c| c.title.as_mut())
                    {
                        t.push(' ');
                        t.push_str(line.trim());
                    }
                    continue;
                }
                match line.get(4..6) {
                    Some("- ") => (line[..4].trim().to_string(), line[6..].trim()),
                    _ => continue,
                }
            }
        };
        last_tag.clone_from(&tag);
        let c = cur.get_or_insert_with(Citation::default);
        match (format, tag.as_str()) {
            ("ris", "TY") | ("endnote", "0") => c.kind = value.to_string(),
            ("medline", "PT") if c.kind.is_empty() => c.kind = value.to_string(),
            ("ris", "TI" | "T1") | ("endnote", "T") | ("medline", "TI") => c.title = Some(value.to_string()),
            ("ris", "AU" | "A1") | ("endnote", "A") | ("medline", "FAU") => c.authors.push(value.to_string()),
            ("ris", "PY" | "Y1" | "DA") | ("endnote", "D") | ("medline", "DP") => {
                c.year = c.year.or_else(|| year_of(value));
            }
            ("ris", "DO") | ("endnote", "R") => c.doi = true,
            ("medline", "LID" | "AID") if value.ends_with("[doi]") => c.doi = true,
            ("ris", "ER") => out.extend(cur.take()),
            _ => {}
        }
    }
    out.extend(cur);
    out
}

fn citations(cx: &mut Context<'_>, format: &str, text: &str) -> Result<(), ExtractError> {
    let records = citation_records(format, text);
    cx.checkpoint()?;
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut authors = BTreeSet::new();
    let (mut years, mut dois, mut titles) = (Vec::new(), 0u64, Vec::new());
    for r in &records {
        *types.entry(if r.kind.is_empty() { "(none)".into() } else { r.kind.clone() }).or_default() += 1;
        years.extend(r.year);
        dois += u64::from(r.doi);
        for a in &r.authors {
            if authors.len() < 100_000 {
                authors.insert(a.to_lowercase());
            }
        }
        titles.extend(r.title.clone());
    }
    cx.format_set("entries", records.len());
    cx.format_set("entry_types", json!(types));
    if let (Some(lo), Some(hi)) = (years.iter().min(), years.iter().max()) {
        cx.format_set("year_range", json!([lo, hi]));
    }
    if dois > 0 {
        cx.format_set("dois", dois);
    }
    if !authors.is_empty() {
        cx.format_set("distinct_authors", authors.len());
    }
    if !titles.is_empty() {
        cx.emit_text(TextRole::Body, &titles.join("\n"));
        cx.format_set("titles", strings(titles));
    }
    Ok(())
}

fn csl(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            match name {
                "style" => {
                    for k in ["class", "version", "default-locale"] {
                        if let Some(v) = xmlwalk::attr(attrs, k) {
                            cx.format_set(&k.replace('-', "_"), v);
                        }
                    }
                }
                "category" if path.last().is_some_and(|p| p == "info") => {
                    if let Some(v) = xmlwalk::attr(attrs, "citation-format") {
                        cx.format_set("citation_format", v);
                    }
                }
                "link"
                    if path.last().is_some_and(|p| p == "info")
                        && xmlwalk::attr(attrs, "rel") == Some("independent-parent") =>
                {
                    if let Some(v) = xmlwalk::attr(attrs, "href") {
                        cx.format_set("parent", v);
                    }
                }
                _ => {}
            }
            path.push(name.to_string());
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
        xmlwalk::Ev::Text(t) => {
            let parent = path.len().checked_sub(2).map(|i| path[i].as_str());
            match (parent, path.last().map(String::as_str)) {
                (Some("info"), Some("title")) => {
                    cx.format_set("title", t);
                    cx.content().title(t.to_string());
                }
                (Some("info"), Some("id")) => cx.format_set("id", t),
                (Some("info"), Some("updated")) => cx.format_set("updated", t),
                (Some("author"), Some("name")) => {
                    cx.content().author(t.to_string());
                }
                _ => {}
            }
        }
    })
}

// --- typesetting ---------------------------------------------------------------------

/// `key: "value"` inside `#set document(...)`.
fn typst_arg(args: &str, key: &str) -> Option<String> {
    let at = args.find(&format!("{key}:"))? + key.len() + 1;
    let rest = args[at..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        return Some(r[..r.find('"')?].to_string());
    }
    // `("A", "B")`
    let r = rest.strip_prefix('(')?;
    let inner = &r[..r.find(')')?];
    Some(inner.split('"').skip(1).step_by(2).collect::<Vec<_>>().join(", "))
}

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn typst(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut imports, mut outline, mut prose) = (Vec::new(), Vec::new(), String::new());
    if let Some(p) = text.find("#set document(") {
        let args = &text[p + 14..text.len().min(p + 14 + 2000)];
        if let Some(t) = typst_arg(args, "title") {
            cx.content().title(t.clone());
            cx.format_set("title", t);
        }
        if let Some(a) = typst_arg(args, "author") {
            for name in a.split(", ") {
                cx.content().author(name.to_string());
            }
            cx.format_set("author", a);
        }
    }
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(i) = t.strip_prefix("#import ") {
            if let Some(q) = i.split('"').nth(1) {
                imports.push(q.to_string());
            }
        } else if t.starts_with('=') {
            let level = t.chars().take_while(|&c| c == '=').count();
            let heading = t[level..].trim();
            if !heading.is_empty() && level <= 6 {
                cx.emit_heading(u8::try_from(level).unwrap_or(6), heading);
                outline.push(heading.to_string());
            }
        } else if !t.starts_with('#') && !t.starts_with("//") {
            prose.push_str(t);
            prose.push('\n');
        }
    }
    cx.format_set("headings", outline.len());
    if !imports.is_empty() {
        cx.format_set("imports", strings(imports));
    }
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn lyx(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut layout, mut buf, mut prose) = (String::new(), String::new(), String::new());
    let mut sections = Vec::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("#LyX ") {
            cx.format_set("created_by", v.split(" created").next().unwrap_or(v).trim());
        } else if let Some(v) = line.strip_prefix("\\lyxformat ") {
            cx.format_set("lyx_format", v.trim());
        } else if let Some(v) = line.strip_prefix("\\textclass ") {
            cx.format_set("document_class", v.trim());
        } else if let Some(v) = line.strip_prefix("\\language ") {
            cx.format_set("language", v.trim());
        } else if let Some(v) = line.strip_prefix("\\begin_layout ") {
            layout = v.trim().to_string();
            buf.clear();
        } else if line.starts_with("\\end_layout") {
            let t = buf.trim().to_string();
            match layout.as_str() {
                "Title" if !t.is_empty() => {
                    cx.content().title(t.clone());
                    cx.format_set("title", t.clone());
                }
                "Author" if !t.is_empty() => {
                    cx.content().author(t.clone());
                }
                "Section" | "Subsection" | "Chapter" | "Part" if !t.is_empty() => {
                    let level = match layout.as_str() {
                        "Part" | "Chapter" => 1,
                        "Section" => 2,
                        _ => 3,
                    };
                    cx.emit_heading(level, &t);
                    sections.push(t.clone());
                }
                _ => {}
            }
            prose.push_str(&t);
            prose.push('\n');
            layout.clear();
        } else if !layout.is_empty() && !line.starts_with('\\') {
            buf.push_str(line);
            buf.push(' ');
        }
    }
    cx.format_set("sections", strings(sections));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn scribus(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut pages, mut frames, mut prose) = (0u64, BTreeMap::<String, u64>::new(), String::new());
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| {
        let xmlwalk::Ev::Start(name, attrs) = ev else { return };
        match name {
            "SCRIBUSUTF8NEW" | "SCRIBUSUTF8" => {
                if let Some(v) = xmlwalk::attr(attrs, "Version") {
                    cx.format_set("scribus_version", v);
                }
            }
            "DOCUMENT" => {
                for (k, out) in
                    [("TITLE", "title"), ("AUTHOR", "author"), ("COMMENTS", "comments"), ("LANGUAGE", "language")]
                {
                    if let Some(v) = xmlwalk::attr(attrs, k).filter(|v| !v.is_empty()) {
                        cx.format_set(out, v);
                        match out {
                            "title" => _ = cx.content().title(v.to_string()),
                            "author" => _ = cx.content().author(v.to_string()),
                            _ => {}
                        }
                    }
                }
                if let Some(n) = xmlwalk::attr(attrs, "ANZPAGES").and_then(|v| v.parse::<u64>().ok()) {
                    cx.format_set("declared_pages", n);
                }
            }
            "PAGE" => pages += 1,
            "PAGEOBJECT" => {
                let kind = match xmlwalk::attr(attrs, "PTYPE") {
                    Some("2") => "image",
                    Some("4") => "text",
                    Some("5") => "line",
                    Some("6" | "7") => "shape",
                    Some("8") => "path text",
                    Some("12") => "table",
                    _ => "other",
                };
                *frames.entry(kind.to_string()).or_default() += 1;
            }
            "ITEXT" => {
                if let Some(t) = xmlwalk::attr(attrs, "CH") {
                    prose.push_str(t);
                    prose.push(' ');
                }
            }
            "para" | "breakline" => prose.push('\n'),
            _ => {}
        }
    })?;
    cx.format_set("pages", pages);
    cx.format_set("frames", json!(frames));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- notes ---------------------------------------------------------------------------

/// `20250901T120000Z` → RFC 3339.
fn enex_date(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() == 16 && s.as_bytes()[8] == b'T')
        .then(|| format!("{}-{}-{}T{}:{}:{}Z", &s[..4], &s[4..6], &s[6..8], &s[9..11], &s[11..13], &s[13..15]))
}

fn enex(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut notes, mut titles, mut tags, mut dates) = (0u64, Vec::new(), BTreeMap::<String, u64>::new(), Vec::new());
    let mut path: Vec<String> = Vec::new();
    let mut prose = String::new();
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            if name == "en-export" {
                for (k, out) in
                    [("application", "application"), ("version", "application_version"), ("export-date", "exported")]
                {
                    if let Some(v) = xmlwalk::attr(attrs, k) {
                        let v = if k == "export-date" {
                            enex_date(v).unwrap_or_else(|| v.to_string())
                        } else {
                            v.to_string()
                        };
                        cx.format_set(out, v);
                    }
                }
            }
            if name == "note" {
                notes += 1;
            }
            path.push(name.to_string());
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
        xmlwalk::Ev::Text(t) => match path.last().map(String::as_str) {
            Some("title") => titles.push(t.to_string()),
            Some("tag") => *tags.entry(t.to_string()).or_default() += 1,
            Some("created" | "updated") => dates.extend(enex_date(t)),
            // The note body: ENML (XHTML) inside CDATA.
            Some("content") => {
                prose.push_str(&crate::plugin::html_text(t, 1 << 20).0);
                prose.push('\n');
            }
            _ => {}
        },
    })?;
    cx.format_set("notes", notes);
    if !tags.is_empty() {
        cx.format_set("tags", json!(tags));
    }
    dates.sort();
    if let (Some(a), Some(b)) = (dates.first(), dates.last()) {
        cx.format_set("date_range", json!([a, b]));
    }
    if !titles.is_empty() {
        cx.format_set("titles", strings(titles.clone()));
    }
    cx.emit_text(TextRole::Body, &format!("{}\n{prose}", titles.join("\n")));
    Ok(())
}

fn canvas(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let v: Value = serde_json::from_str(text).map_err(|_| ExtractError::malformed("canvas JSON"))?;
    let nodes = v.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
    let edges = v.get("edges").and_then(Value::as_array).map_or(0, Vec::len);
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let (mut prose, mut files, mut links, mut groups) = (String::new(), Vec::new(), Vec::new(), Vec::new());
    for n in &nodes {
        let kind = n.get("type").and_then(Value::as_str).unwrap_or("unknown");
        *kinds.entry(kind.to_string()).or_default() += 1;
        let s = |k: &str| n.get(k).and_then(Value::as_str).map(str::to_string);
        match kind {
            "text" => {
                prose.push_str(&s("text").unwrap_or_default());
                prose.push('\n');
            }
            "file" => files.extend(s("file")),
            "link" => links.extend(s("url")),
            "group" => groups.extend(s("label")),
            _ => {}
        }
    }
    cx.format_set("nodes", nodes.len());
    cx.format_set("node_types", json!(kinds));
    cx.format_set("edges", edges);
    if !files.is_empty() {
        cx.format_set("files", strings(files));
    }
    if !groups.is_empty() {
        cx.format_set("groups", strings(groups));
    }
    if !links.is_empty() {
        cx.security().external_references(links.len() as u64);
        cx.format_set("links", strings(links));
    }
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- screenwriting -------------------------------------------------------------------

/// A Fountain scene heading: `INT.`, `EXT.`, `EST.`, `INT./EXT.`, `I/E`, or
/// a line forced with a leading `.`.
fn scene_heading(line: &str) -> Option<&str> {
    let up = line.to_ascii_uppercase();
    if ["INT.", "EXT.", "EST.", "INT./EXT.", "INT/EXT", "I/E"].iter().any(|p| up.starts_with(p)) {
        return Some(line.trim());
    }
    line.strip_prefix('.').filter(|r| !r.starts_with('.') && !r.trim().is_empty()).map(str::trim)
}

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn fountain(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut lines = text.lines().peekable();
    // The title page: `Key: value` lines up to the first blank line.
    let mut title_page = Map::new();
    if lines.peek().is_some_and(|l| l.contains(':')) {
        let mut key = String::new();
        for line in lines.by_ref() {
            if line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':').filter(|(k, _)| !k.starts_with([' ', '\t'])) {
                key = k.trim().to_ascii_lowercase().replace(' ', "_");
                if !v.trim().is_empty() {
                    title_page.insert(key.clone(), v.trim().into());
                }
            } else if let Some(Value::String(prev)) = title_page.get_mut(&key) {
                prev.push(' ');
                prev.push_str(line.trim());
            } else if !key.is_empty() {
                title_page.insert(key.clone(), line.trim().into());
            }
        }
    }
    if let Some(t) = title_page.get("title").and_then(Value::as_str) {
        cx.content().title(t.trim_matches('_').to_string());
    }
    for k in ["author", "authors", "credit"] {
        if let Some(a) = title_page.get(k).and_then(Value::as_str).filter(|_| k != "credit") {
            cx.content().author(a.to_string());
        }
    }
    let (mut scenes, mut characters, mut prose) = (Vec::new(), BTreeMap::<String, u64>::new(), String::new());
    let mut prev_blank = true;
    let rest: Vec<&str> = lines.collect();
    for (i, line) in rest.iter().enumerate() {
        let t = line.trim();
        if prev_blank && let Some(h) = scene_heading(t) {
            scenes.push(h.to_string());
            cx.emit_heading(2, h);
        } else if prev_blank
            && !t.is_empty()
            && t.chars().any(char::is_alphabetic)
            && t.trim_start_matches('@').split(" (").next().is_some_and(|n| n == n.to_uppercase())
            && rest.get(i + 1).is_some_and(|n| !n.trim().is_empty())
            && !t.ends_with("TO:")
        {
            let name = t.trim_start_matches('@').split(" (").next().unwrap_or(t).trim().to_string();
            *characters.entry(name).or_default() += 1;
        } else {
            prose.push_str(t);
            prose.push('\n');
        }
        prev_blank = t.is_empty();
    }
    cx.format_set("title_page", Value::Object(title_page));
    cx.format_set("scenes", scenes.len());
    cx.format_set("scene_headings", strings(scenes));
    cx.format_set("characters", json!(characters));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn final_draft(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut kind, mut buf) = (String::new(), String::new());
    let (mut counts, mut scenes, mut characters, mut prose) =
        (BTreeMap::<String, u64>::new(), Vec::new(), BTreeMap::<String, u64>::new(), String::new());
    let mut in_title_page = false;
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => match name {
            "FinalDraft" => {
                for (k, out) in [("DocumentType", "document_type"), ("Version", "version")] {
                    if let Some(v) = xmlwalk::attr(attrs, k) {
                        cx.format_set(out, v);
                    }
                }
            }
            "TitlePage" => in_title_page = true,
            "Paragraph" => {
                kind = xmlwalk::attr(attrs, "Type").unwrap_or("General").to_string();
                buf.clear();
            }
            _ => {}
        },
        xmlwalk::Ev::Text(t) => {
            buf.push_str(t);
        }
        xmlwalk::Ev::End(name) => match name {
            "TitlePage" => in_title_page = false,
            "Paragraph" => {
                let t = buf.trim().to_string();
                if in_title_page {
                    if !t.is_empty() && cx.format_id() == "final_draft" {
                        prose.push_str(&t);
                        prose.push('\n');
                    }
                    return;
                }
                *counts.entry(kind.clone()).or_default() += 1;
                match kind.as_str() {
                    "Scene Heading" if !t.is_empty() => {
                        cx.emit_heading(2, &t);
                        scenes.push(t);
                    }
                    "Character" if !t.is_empty() => {
                        let name = t.split(" (").next().unwrap_or(&t).to_string();
                        *characters.entry(name).or_default() += 1;
                    }
                    _ => {
                        prose.push_str(&t);
                        prose.push('\n');
                    }
                }
            }
            _ => {}
        },
    })?;
    cx.format_set("paragraph_types", json!(counts));
    cx.format_set("scenes", scenes.len());
    cx.format_set("scene_headings", strings(scenes));
    cx.format_set("characters", json!(characters));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn scrivener(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut kinds, mut titles, mut depth, mut path) =
        (BTreeMap::<String, u64>::new(), Vec::new(), 0usize, Vec::<String>::new());
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            match name {
                "ScrivenerProject" => {
                    for (k, out) in [("Version", "version"), ("Creator", "creator"), ("Template", "template")] {
                        if let Some(v) = xmlwalk::attr(attrs, k) {
                            cx.format_set(out, v);
                        }
                    }
                }
                "BinderItem" => {
                    depth += 1;
                    *kinds.entry(xmlwalk::attr(attrs, "Type").unwrap_or("Item").to_string()).or_default() += 1;
                }
                _ => {}
            }
            path.push(name.to_string());
        }
        xmlwalk::Ev::End(name) => {
            if name == "BinderItem" {
                depth = depth.saturating_sub(1);
            }
            path.pop();
        }
        xmlwalk::Ev::Text(t) => {
            let parent = path.len().checked_sub(2).map(|i| path[i].as_str());
            if parent == Some("BinderItem") && path.last().is_some_and(|p| p == "Title") {
                if depth <= 2 {
                    cx.emit_heading(u8::try_from(depth.max(1)).unwrap_or(2), t);
                }
                titles.push(t.to_string());
            }
        }
    })?;
    cx.format_set("binder_items", json!(kinds));
    cx.format_set("titles", strings(titles));
    Ok(())
}

// --- office XML ----------------------------------------------------------------------

fn abiword(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut key, mut in_m, mut sections, mut prose, mut in_body) = (String::new(), false, 0u64, String::new(), false);
    let mut meta = Map::new();
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => match name {
            "abiword" => {
                if let Some(v) = xmlwalk::attr(attrs, "version") {
                    cx.format_set("abiword_version", v);
                }
            }
            "m" => {
                key = xmlwalk::attr(attrs, "key").unwrap_or("").to_string();
                in_m = true;
            }
            "section" => {
                sections += 1;
                in_body = true;
            }
            _ => {}
        },
        xmlwalk::Ev::End(name) => match name {
            "m" => in_m = false,
            "p" => prose.push('\n'),
            _ => {}
        },
        xmlwalk::Ev::Text(t) => {
            if in_m {
                let k = key.trim_start_matches("dc.").trim_start_matches("abiword.").replace('.', "_");
                match key.as_str() {
                    "dc.title" => _ = cx.content().title(t.to_string()),
                    "dc.creator" => _ = cx.content().author(t.to_string()),
                    _ => {}
                }
                meta.insert(k, t.into());
            } else if in_body {
                prose.push_str(t);
                prose.push(' ');
            }
        }
    })?;
    cx.format_set("metadata", Value::Object(meta));
    cx.format_set("sections", sections);
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn gnumeric(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let (mut sheets, mut cells, mut meta) = (Vec::<Value>::new(), 0u64, Map::new());
    let (mut name, mut max_col, mut max_row) = (String::new(), 0u64, 0u64);
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(tag, attrs) => {
            match tag {
                "Workbook" => {
                    if let Some(v) = attrs.iter().find(|(k, _)| k == "gnm").map(|(_, v)| v.clone()) {
                        cx.format_set("namespace", v);
                    }
                }
                "Sheet" => (name, max_col, max_row) = (String::new(), 0, 0),
                "Cell" => cells += 1,
                _ => {}
            }
            path.push(tag.to_string());
        }
        xmlwalk::Ev::End(tag) => {
            if tag == "Sheet" {
                sheets.push(json!({ "name": name, "columns": max_col + 1, "rows": max_row + 1 }));
            }
            path.pop();
        }
        xmlwalk::Ev::Text(t) => {
            let parent = path.len().checked_sub(2).map(|i| path[i].as_str());
            match (parent, path.last().map(String::as_str)) {
                (Some("Sheet"), Some("Name")) => name = t.to_string(),
                (Some("Sheet"), Some("MaxCol")) => max_col = t.parse().unwrap_or(0),
                (Some("Sheet"), Some("MaxRow")) => max_row = t.parse().unwrap_or(0),
                (_, Some(k @ ("title" | "creator" | "date" | "description" | "subject" | "generator"))) => {
                    if k == "title" {
                        cx.content().title(t.to_string());
                    }
                    if k == "creator" {
                        cx.content().author(t.to_string());
                    }
                    meta.insert(k.to_string(), t.into());
                }
                _ => {}
            }
        }
    })?;
    cx.format_set("sheets", sheets.len());
    cx.format_set("sheet_list", Value::Array(sheets));
    cx.format_set("cells", cells);
    if !meta.is_empty() {
        cx.format_set("metadata", Value::Object(meta));
    }
    Ok(())
}

// --- slides -------------------------------------------------------------------------

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn marp(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut lines = text.lines();
    let mut front = Map::new();
    if lines.next().is_some_and(|l| l.trim() == "---") {
        for line in lines.by_ref() {
            if line.trim() == "---" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                front.insert(k.trim().to_string(), v.trim().trim_matches('"').into());
            }
        }
    }
    if let Some(t) = front.get("title").and_then(Value::as_str) {
        cx.content().title(t.to_string());
    }
    let (mut slides, mut titles, mut prose, mut fence) = (1u64, Vec::new(), String::new(), false);
    let mut has_title = false;
    for line in lines {
        let t = line.trim_end();
        if t.starts_with("```") {
            fence = !fence;
        }
        if !fence && t == "---" {
            slides += 1;
            has_title = false;
            continue;
        }
        if !fence
            && !has_title
            && let Some(h) = t.strip_prefix("# ").or_else(|| t.strip_prefix("## "))
        {
            titles.push(h.trim().to_string());
            cx.emit_heading(1, h.trim());
            has_title = true;
        } else {
            prose.push_str(t);
            prose.push('\n');
        }
    }
    for k in ["theme", "paginate", "size", "class"] {
        if let Some(v) = front.get(k) {
            cx.format_set(k, v.clone());
        }
    }
    cx.format_set("slides", slides);
    cx.format_set("slide_titles", strings(titles));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "ris",
        "endnote",
        "medline",
        "csl_style",
        "typst",
        "lyx",
        "scribus",
        "enex",
        "obsidian_canvas",
        "fountain",
        "final_draft",
        "scrivener",
        "abiword",
        "gnumeric",
        "marp"
    );

    #[test]
    fn helpers() {
        assert_eq!(year_of("2025 Sep 1"), Some(2025));
        assert_eq!(enex_date("20250901T120000Z").as_deref(), Some("2025-09-01T12:00:00Z"));
        assert_eq!(typst_arg(r#"title: "Tides", author: ("Ana", "Ben"))"#, "author").as_deref(), Some("Ana, Ben"));
        assert_eq!(scene_heading("INT. BELL TOWER - DAY"), Some("INT. BELL TOWER - DAY"));
        assert_eq!(scene_heading(".THE LONG WALL"), Some("THE LONG WALL"));
        assert_eq!(scene_heading("...and then"), None);
        let ris = "TY  - JOUR\nTI  - Tides\nAU  - Gull, Ben\nPY  - 2025\nDO  - 10.1/x\nER  - \n";
        let r = citation_records("ris", ris);
        assert_eq!((r.len(), r[0].title.as_deref(), r[0].year, r[0].doi), (1, Some("Tides"), Some(2025), true));
    }
}
