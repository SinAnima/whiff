//! Office Open XML (ECMA-376): Word, Excel, PowerPoint and Visio documents,
//! templates and macro-enabled variants.
//!
//! Reads the package parts directly (no rendering):
//! * `docProps/core.xml`, `app.xml`, `custom.xml` (title, authors, dates,
//!   counts, company, template, custom properties, sensitivity labels);
//! * Word: heading outline from paragraph styles, body text, comments,
//!   tracked changes, footnotes, fields (DDE, external includes);
//! * Excel: sheets (visibility, dimensions, formulas), defined names, shared
//!   strings, external links, Excel 4.0 macro sheets;
//! * PowerPoint: slide titles, slide and notes text, hidden slides, size;
//! * Visio: page names and shape text;
//! * security: VBA projects (module names, auto-run triggers, suspicious
//!   calls), ActiveX, OLE objects, external templates and links, digital
//!   signatures. Embedded files are analysed as children.
//!
//! Specification: ECMA-376 5th edition, Parts 1 and 2 (OPC); MS-OFFMACRO2.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::xml::{Ev, Flow, Tag, values, walk};
use crate::plugin::{
    Cfb, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Map, Probe, Sniff, Source,
    TextRole, Zip, ZipEntry, truncate_chars, zip_names,
};

/// Extractor for OOXML documents.
pub struct Ooxml;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $ext:literal) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "doc.ooxml",
            mimes: &[$mime],
            extensions: &[$ext],
            magic: &[],
            parent: Some("zip"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.ooxml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "docx",
            "Word document",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx"
        ),
        spec!("docm", "Word macro-enabled document", "application/vnd.ms-word.document.macroEnabled.12", "docm"),
        spec!(
            "dotx",
            "Word template",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
            "dotx"
        ),
        spec!("dotm", "Word macro-enabled template", "application/vnd.ms-word.template.macroEnabled.12", "dotm"),
        spec!("xlsx", "Excel workbook", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
        spec!("xlsm", "Excel macro-enabled workbook", "application/vnd.ms-excel.sheet.macroEnabled.12", "xlsm"),
        spec!("xltx", "Excel template", "application/vnd.openxmlformats-officedocument.spreadsheetml.template", "xltx"),
        spec!("xltm", "Excel macro-enabled template", "application/vnd.ms-excel.template.macroEnabled.12", "xltm"),
        spec!("xlam", "Excel add-in", "application/vnd.ms-excel.addin.macroEnabled.12", "xlam"),
        spec!("xlsb", "Excel binary workbook", "application/vnd.ms-excel.sheet.binary.macroEnabled.12", "xlsb"),
        spec!(
            "pptx",
            "PowerPoint presentation",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "pptx"
        ),
        spec!(
            "pptm",
            "PowerPoint macro-enabled presentation",
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            "pptm"
        ),
        spec!(
            "potx",
            "PowerPoint template",
            "application/vnd.openxmlformats-officedocument.presentationml.template",
            "potx"
        ),
        spec!(
            "potm",
            "PowerPoint macro-enabled template",
            "application/vnd.ms-powerpoint.template.macroEnabled.12",
            "potm"
        ),
        spec!(
            "ppsx",
            "PowerPoint slide show",
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
            "ppsx"
        ),
        spec!(
            "ppsm",
            "PowerPoint macro-enabled slide show",
            "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
            "ppsm"
        ),
        spec!("vsdx", "Visio drawing", "application/vnd.ms-visio.drawing", "vsdx"),
        spec!("vsdm", "Visio macro-enabled drawing", "application/vnd.ms-visio.drawing.macroEnabled.12", "vsdm"),
        spec!("vstx", "Visio template", "application/vnd.ms-visio.template", "vstx"),
    ],
};

/// Entries listed from the central directory at most.
const MAX_ENTRIES: usize = 20_000;
/// Worksheets / slides / pages read at most.
const MAX_PARTS: usize = 500;
/// Slide titles / sheet names listed at most.
const MAX_LISTED: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum App {
    Word,
    Excel,
    PowerPoint,
    Visio,
}

fn app_of(format: &str) -> App {
    match format.as_bytes().first() {
        Some(b'x') => App::Excel,
        Some(b'p') => App::PowerPoint,
        Some(b'v') => App::Visio,
        _ => App::Word,
    }
}

/// The format a main-part content type names.
fn format_for_content_type(ct: &str) -> Option<&'static str> {
    let ct = ct.to_ascii_lowercase();
    Some(match ct.as_str() {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml" => "docx",
        "application/vnd.ms-word.document.macroenabled.main+xml" => "docm",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml" => "dotx",
        "application/vnd.ms-word.template.macroenabledtemplate.main+xml" => "dotm",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml" => "xlsx",
        "application/vnd.ms-excel.sheet.macroenabled.main+xml" => "xlsm",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml" => "xltx",
        "application/vnd.ms-excel.template.macroenabled.main+xml" => "xltm",
        "application/vnd.ms-excel.addin.macroenabled.main+xml" => "xlam",
        "application/vnd.ms-excel.sheet.binary.macroenabled.main" => "xlsb",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml" => "pptx",
        "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml" => "pptm",
        "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml" => "potx",
        "application/vnd.ms-powerpoint.template.macroenabled.main+xml" => "potm",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml" => "ppsx",
        "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml" => "ppsm",
        "application/vnd.ms-visio.drawing.main+xml" => "vsdx",
        "application/vnd.ms-visio.drawing.macroenabled.main+xml" => "vsdm",
        "application/vnd.ms-visio.template.main+xml" => "vstx",
        _ => return None,
    })
}

impl Extractor for Ooxml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 5000);
        let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
        let family = if has("word/document.xml") || names.iter().any(|n| n.starts_with("word/")) {
            App::Word
        } else if has("xl/workbook.xml") || has("xl/workbook.bin") {
            App::Excel
        } else if has("ppt/presentation.xml") {
            App::PowerPoint
        } else if has("visio/document.xml") {
            App::Visio
        } else {
            // Names unknown (central directory outside the tail window): trust
            // the extension of an OPC-looking file.
            let ext = probe.extension?;
            let spec = META.formats.iter().find(|f| f.extensions.contains(&ext))?;
            return (names.is_empty() || has("[Content_Types].xml"))
                .then_some(Sniff { format: spec.id, confidence: 0.6 });
        };
        let ext = probe.extension.unwrap_or("");
        let format =
            META.formats.iter().find(|f| f.extensions.contains(&ext) && app_of(f.id) == family).map(|f| f.id).or_else(
                || {
                    // The extension says nothing: macro-enabled if it has a VBA project.
                    let macros = names.iter().any(|n| n.ends_with("vbaProject.bin"));
                    Some(match (family, macros) {
                        (App::Word, false) => "docx",
                        (App::Word, true) => "docm",
                        (App::Excel, _) if has("xl/workbook.bin") => "xlsb",
                        (App::Excel, false) => "xlsx",
                        (App::Excel, true) => "xlsm",
                        (App::PowerPoint, false) => "pptx",
                        (App::PowerPoint, true) => "pptm",
                        (App::Visio, false) => "vsdx",
                        (App::Visio, true) => "vsdm",
                    })
                },
            )?;
        let confidence = if has("[Content_Types].xml") { 0.95 } else { 0.8 };
        Some(Sniff { format, confidence })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, MAX_ENTRIES)?;
        zip.flag_duplicates(cx);
        let mut pkg = Package { zip, max: cx.parse_limit(), ..Package::default() };
        pkg.run(src, cx)
    }
}

crate::register_extractor!(Ooxml);

/// Whether a part name ends in `.ext` (ASCII case-insensitive).
fn has_ext(name: &str, ext: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, e)| e.eq_ignore_ascii_case(ext))
}

/// A relationship from a `.rels` part.
#[derive(Debug, Clone)]
struct Rel {
    id: String,
    kind: String,
    target: String,
    external: bool,
}

impl Rel {
    /// The last path segment of the relationship type URI.
    fn short(&self) -> &str {
        self.kind.rsplit('/').next().unwrap_or(&self.kind)
    }
}

#[derive(Default)]
struct Package {
    zip: Zip,
    max: usize,
    /// Part name (no leading `/`) → content type.
    types: BTreeMap<String, String>,
    defaults: BTreeMap<String, String>,
}

/// Resolve `target` relative to the part `base` (`word/document.xml`).
fn resolve(base: &str, target: &str) -> String {
    if let Some(abs) = target.strip_prefix('/') {
        return abs.to_string();
    }
    let mut parts: Vec<&str> = base.split('/').collect();
    parts.pop();
    for seg in target.split('/') {
        match seg {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// The `.rels` part of `part`: `word/document.xml` → `word/_rels/document.xml.rels`.
fn rels_path(part: &str) -> String {
    match part.rsplit_once('/') {
        Some((dir, name)) => format!("{dir}/_rels/{name}.rels"),
        None => format!("_rels/{part}.rels"),
    }
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#', ':']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// W3CDTF dates (`2024-05-01T10:00:00Z`): the value and whether a zone is given.
fn w3c_date(v: &str) -> Option<(String, bool)> {
    let v = v.trim();
    if v.len() < 4 || v.starts_with("1601") || v.starts_with("0001") {
        return None;
    }
    let tz = v.ends_with('Z') || v.get(19..).is_some_and(|t| t.contains('+') || t.contains('-'));
    Some((v.to_string(), tz))
}

impl Package {
    fn entry(&self, name: &str) -> Option<ZipEntry> {
        self.zip.find(name).or_else(|| self.zip.find_ci(name)).cloned()
    }

    fn read(&self, src: &mut dyn Source, cx: &mut Context<'_>, name: &str) -> Option<String> {
        let entry = self.entry(name)?;
        match self.zip.read(src, &entry, cx, self.max) {
            Ok(bytes) => Some(crate::plugin::decode_text(&bytes).text),
            Err(e) => {
                cx.warn(format!("{name}: {e}"));
                None
            }
        }
    }

    fn rels(&self, src: &mut dyn Source, cx: &mut Context<'_>, part: &str) -> Vec<Rel> {
        let Some(xml) = self.read(src, cx, &rels_path(part)) else { return Vec::new() };
        let mut out = Vec::new();
        let _ = walk(&xml, cx, |ev| {
            if let Ev::Open(t, _) = ev
                && t.name == "Relationship"
            {
                out.push(Rel {
                    id: t.attr("Id").unwrap_or_default().to_string(),
                    kind: t.attr("Type").unwrap_or_default().to_string(),
                    target: t.attr("Target").unwrap_or_default().to_string(),
                    external: t.attr("TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("external")),
                });
            }
            Flow::Continue
        });
        out
    }

    fn content_type(&self, part: &str) -> Option<&str> {
        self.types.get(part).map(String::as_str).or_else(|| {
            let ext = part.rsplit_once('.')?.1.to_ascii_lowercase();
            self.defaults.get(&ext).map(String::as_str)
        })
    }

    fn run(&mut self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let types = self.read(src, cx, "[Content_Types].xml");
        if let Some(xml) = &types {
            let (mut overrides, mut defaults) = (BTreeMap::new(), BTreeMap::new());
            walk(xml, cx, |ev| {
                if let Ev::Open(t, _) = ev {
                    match t.name.as_str() {
                        "Override" => {
                            if let (Some(p), Some(c)) = (t.attr("PartName"), t.attr("ContentType")) {
                                overrides.insert(p.trim_start_matches('/').to_string(), c.to_string());
                            }
                        }
                        "Default" => {
                            if let (Some(e), Some(c)) = (t.attr("Extension"), t.attr("ContentType")) {
                                defaults.insert(e.to_ascii_lowercase(), c.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                Flow::Continue
            })?;
            self.types = overrides;
            self.defaults = defaults;
        } else {
            cx.warn("no [Content_Types].xml");
        }

        let root = self.rels(src, cx, "");
        let main = root
            .iter()
            .find(|r| r.short() == "officeDocument" || r.kind.ends_with("/document"))
            .map(|r| resolve("", &r.target))
            .or_else(|| {
                [
                    "word/document.xml",
                    "xl/workbook.xml",
                    "xl/workbook.bin",
                    "ppt/presentation.xml",
                    "visio/document.xml",
                ]
                .into_iter()
                .find(|p| self.entry(p).is_some())
                .map(str::to_string)
            })
            .ok_or_else(|| ExtractError::malformed("no main document part"))?;
        let detected = cx.format_id().to_string();
        let declared = self.content_type(&main).and_then(format_for_content_type);
        if let Some(ct) = self.content_type(&main) {
            cx.format_set("content_type", ct.to_string());
        }
        if let Some(d) = declared
            && d != detected
        {
            cx.format_set("declared_format", d);
        }
        cx.format_set("main_part", main.clone());
        cx.format_set("parts", self.zip.entries.len());
        cx.format_set("uncompressed_bytes", self.zip.uncompressed_bytes());

        self.properties(src, cx, &root)?;
        self.inventory(src, cx);
        let app = app_of(declared.unwrap_or(&detected));
        let main_rels = self.rels(src, cx, &main);
        self.relationships(src, cx);
        match app {
            App::Word => self.word(src, cx, &main, &main_rels)?,
            App::Excel => self.excel(src, cx, &main, &main_rels)?,
            App::PowerPoint => self.powerpoint(src, cx, &main, &main_rels)?,
            App::Visio => self.visio(src, cx)?,
        }
        self.embeddings(src, cx);
        Ok(())
    }

    /// `docProps/core.xml`, `app.xml`, `custom.xml` → `metadata.docprops` and the normalised sections.
    fn properties(&self, src: &mut dyn Source, cx: &mut Context<'_>, root: &[Rel]) -> Result<(), ExtractError> {
        let part = |short: &str, fallback: &str| {
            root.iter().find(|r| r.short() == short).map_or_else(|| fallback.to_string(), |r| resolve("", &r.target))
        };
        if let Some(xml) = self.read(src, cx, &part("core-properties", "docProps/core.xml")) {
            let fields = values(
                &xml,
                cx,
                &[
                    "title",
                    "subject",
                    "creator",
                    "keywords",
                    "description",
                    "lastModifiedBy",
                    "revision",
                    "created",
                    "modified",
                    "lastPrinted",
                    "category",
                    "contentStatus",
                    "language",
                    "identifier",
                    "version",
                    "contentType",
                ],
            )?;
            let mut core = Map::new();
            for (name, _, v) in &fields {
                if !v.is_empty() {
                    core.insert(name.clone(), json!(v));
                }
            }
            core_to_normalised(cx, &core, "docprops.core");
            if !core.is_empty() {
                cx.metadata("docprops").insert("core".into(), Value::Object(core));
            }
        }
        if let Some(xml) = self.read(src, cx, &part("extended-properties", "docProps/app.xml")) {
            let app = app_properties(&xml, cx)?;
            if let Some(n) = app.get("Pages").and_then(Value::as_u64) {
                cx.physical().pages(n);
            }
            if let Some(n) = app.get("Words").and_then(Value::as_u64) {
                cx.physical().words(n);
            }
            if let Some(n) = app.get("Slides").and_then(Value::as_u64) {
                cx.physical().slides(n);
            }
            if let Some(c) = app.get("Company").and_then(Value::as_str) {
                cx.rights().source("docprops.app.Company").credit(c);
            }
            if !app.is_empty() {
                cx.metadata("docprops").insert("app".into(), Value::Object(app));
            }
        }
        if let Some(xml) = self.read(src, cx, &part("custom-properties", "docProps/custom.xml")) {
            let custom = custom_properties(&xml, cx)?;
            labels_from_custom(cx, &custom);
            if !custom.is_empty() {
                cx.metadata("docprops").insert("custom".into(), Value::Object(custom));
            }
        }
        if let Some(xml) = self.read(src, cx, "docMetadata/LabelInfo.xml") {
            let mut labels = Vec::new();
            walk(&xml, cx, |ev| {
                if let Ev::Open(t, _) = ev
                    && t.name == "label"
                {
                    let mut l = Map::new();
                    for k in ["id", "enabled", "method", "siteId", "removed"] {
                        if let Some(v) = t.attr(k) {
                            l.insert(k.into(), json!(v));
                        }
                    }
                    labels.push(Value::Object(l));
                }
                Flow::Continue
            })?;
            if !labels.is_empty() {
                cx.format_set("sensitivity_labels", labels);
            }
        }
        if let Some(r) = root.iter().find(|r| r.short() == "thumbnail")
            && let Some(e) = self.entry(&resolve("", &r.target))
        {
            cx.format_set("thumbnail", json!({ "name": e.name, "size_bytes": e.size }));
        }
        let signatures = self.zip.under("_xmlsignatures/").filter(|e| has_ext(&e.name, "xml")).count();
        if signatures > 0 {
            cx.security().signed(true);
            cx.format_set("signatures", signatures);
        }
        Ok(())
    }

    /// Part counts by kind, and the active content they imply.
    fn inventory(&self, src: &mut dyn Source, cx: &mut Context<'_>) {
        let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
        let mut vba = Vec::new();
        for e in &self.zip.entries {
            if e.is_dir() {
                continue;
            }
            let ct = self.content_type(&e.name).unwrap_or("").to_ascii_lowercase();
            let lower = e.name.to_ascii_lowercase();
            let kind = if ct.contains("vbaproject") || lower.ends_with("vbaproject.bin") {
                vba.push(e.clone());
                "vba_projects"
            } else if ct.contains("activex") || lower.contains("/activex/") {
                "activex_controls"
            } else if lower.contains("/embeddings/") {
                "embedded_objects"
            } else if lower.contains("/media/") || ct.starts_with("image/") {
                "media"
            } else if ct.contains("drawingml.chart+") || lower.contains("/charts/chart") {
                "charts"
            } else if ct.contains("pivottable") {
                "pivot_tables"
            } else if ct.contains("spreadsheetml.table+") {
                "tables"
            } else if ct.contains("macrosheet") || ct.contains("dialogsheet") || lower.contains("/macrosheets/") {
                "macro_sheets"
            } else if ct.contains("customui") || lower.starts_with("customui/") {
                "custom_ui"
            } else if ct.contains("font") || lower.contains("/fonts/") {
                "embedded_fonts"
            } else {
                continue;
            };
            if kind == "activex_controls" && !has_ext(&lower, "xml") {
                continue;
            }
            *counts.entry(kind).or_default() += 1;
        }
        if counts.contains_key("activex_controls") {
            cx.security().active_content("activex");
        }
        if counts.contains_key("embedded_objects") {
            cx.security().active_content("ole_objects");
        }
        if let Some(n) = counts.get("macro_sheets") {
            cx.security().active_content("excel4_macros");
            cx.security().risk("xlm_macros", Some(format!("{n} Excel 4.0 macro sheet(s)")));
        }
        if !counts.is_empty() {
            cx.format_set("part_counts", json!(counts));
        }
        let mut projects = Vec::new();
        for e in vba {
            match self.zip.read(src, &e, cx, self.max) {
                Ok(bytes) => {
                    let mut mem = cx.memory_source(&e.name, bytes);
                    let result = Cfb::open(&mut mem).and_then(|cfb| super::vba::analyze(&cfb, &mut mem, "", cx));
                    match result {
                        Ok(v) => projects.push(v),
                        Err(err) => {
                            cx.security().active_content("macros").risk("macros", Some(e.name.clone()));
                            cx.warn(format!("{}: {err}", e.name));
                        }
                    }
                }
                Err(err) => {
                    cx.security().active_content("macros").risk("macros", Some(e.name.clone()));
                    cx.warn(format!("{}: {err}", e.name));
                }
            }
        }
        if !projects.is_empty() {
            cx.format_set("vba", if projects.len() == 1 { projects.remove(0) } else { json!(projects) });
        }
    }

    /// External targets of every part's relationships (remote templates sit
    /// in `word/_rels/settings.xml.rels`, links in headers and notes).
    fn relationships(&self, src: &mut dyn Source, cx: &mut Context<'_>) {
        let parts: Vec<String> = self
            .zip
            .entries
            .iter()
            .filter(|e| has_ext(&e.name, "rels"))
            .take(MAX_PARTS * 4)
            .map(|e| e.name.replace("_rels/", "").trim_end_matches(".rels").to_string())
            .collect();
        let rels: Vec<Rel> = parts.iter().flat_map(|p| self.rels(src, cx, p)).collect();
        let mut hyperlinks = 0u64;
        let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
        let mut external = 0u64;
        for r in rels.iter().filter(|r| r.external) {
            external += 1;
            let t = r.target.trim();
            match r.short() {
                "hyperlink" => {
                    hyperlinks += 1;
                    if let Some(h) = host(t) {
                        *hosts.entry(h).or_default() += 1;
                    }
                }
                "attachedTemplate" => {
                    cx.security().risk("external_template", Some(truncate_chars(t, 200)));
                }
                "oleObject" => {
                    cx.security().active_content("ole_links").risk("external_ole_link", Some(truncate_chars(t, 200)));
                }
                "frame" | "subDocument" => {
                    cx.security().risk("external_content", Some(truncate_chars(t, 200)));
                }
                "image" if t.starts_with("http") => {
                    cx.security().risk("remote_image", Some(truncate_chars(t, 200)));
                }
                _ => {}
            }
        }
        cx.security().external_references(external);
        if hyperlinks > 0 {
            cx.format_set("hyperlinks", hyperlinks);
            let mut top: Vec<(String, u64)> = hosts.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top.truncate(10);
            cx.format_set(
                "link_hosts",
                json!(top.into_iter().map(|(h, n)| json!({ "host": h, "count": n })).collect::<Vec<_>>()),
            );
        }
    }

    #[allow(clippy::too_many_lines)] // one pass over document.xml
    fn word(&self, src: &mut dyn Source, cx: &mut Context<'_>, main: &str, rels: &[Rel]) -> Result<(), ExtractError> {
        let part_of =
            |short: &str| rels.iter().find(|r| r.short() == short && !r.external).map(|r| resolve(main, &r.target));
        // Paragraph styles: id → heading level (0 = Title).
        let mut levels: BTreeMap<String, u8> = BTreeMap::new();
        if let Some(xml) = part_of("styles").and_then(|p| self.read(src, cx, &p)) {
            let mut id: Option<String> = None;
            let mut level: Option<u8> = None;
            walk(&xml, cx, |ev| {
                match ev {
                    Ev::Open(t, _) if t.name == "style" => {
                        id = t.attr("styleId").map(str::to_string);
                        level = None;
                    }
                    Ev::Open(t, _) if t.name == "name" && id.is_some() => {
                        let n = t.attr("val").unwrap_or("").to_ascii_lowercase();
                        if n == "title" {
                            level = Some(0);
                        } else if let Some(d) = n.strip_prefix("heading ").and_then(|d| d.parse::<u8>().ok()) {
                            level = Some(d.clamp(1, 9));
                        }
                    }
                    Ev::Open(t, _) if t.name == "outlineLvl" && id.is_some() && level.is_none() => {
                        level = t.attr("val").and_then(|v| v.parse::<u8>().ok()).map(|v| (v + 1).min(9));
                    }
                    Ev::Close("style") => {
                        if let (Some(i), Some(l)) = (id.take(), level.take()) {
                            levels.insert(i, l);
                        }
                    }
                    _ => {}
                }
                Flow::Continue
            })?;
        }
        let Some(xml) = self.read(src, cx, main) else { return Err(ExtractError::malformed("main part unreadable")) };
        let mut d = WordScan { levels, ..WordScan::default() };
        walk(&xml, cx, |ev| {
            d.event(&ev);
            Flow::Continue
        })?;
        for (level, text) in std::mem::take(&mut d.headings) {
            if level == 0 {
                cx.content().source("docx.Title").title(&text);
                cx.emit_text(TextRole::Title, &text);
            } else {
                cx.emit_heading(level, &text);
            }
        }
        if !d.body.is_empty() {
            cx.emit_text(TextRole::Body, &d.body);
        }
        let mut f = Map::new();
        f.insert("paragraphs".into(), json!(d.paragraphs));
        for (k, v) in [("tables", d.tables), ("images", d.images), ("sections", d.sections)] {
            if v > 0 {
                f.insert(k.into(), json!(v));
            }
        }
        if d.insertions + d.deletions > 0 {
            f.insert(
                "tracked_changes".into(),
                json!({ "insertions": d.insertions, "deletions": d.deletions, "authors": d.change_authors }),
            );
        }
        if !d.fields.is_empty() {
            f.insert("fields".into(), json!(d.fields));
        }
        for (field, detail) in &d.risky_fields {
            cx.security().risk(*field, Some(truncate_chars(detail, 200)));
        }
        if d.dde {
            cx.security().active_content("dde");
        }
        // Comments, footnotes, endnotes.
        if let Some(xml) = part_of("comments").and_then(|p| self.read(src, cx, &p)) {
            let (count, authors, text) = comments(&xml, cx)?;
            if count > 0 {
                f.insert("comments".into(), json!({ "count": count, "authors": authors }));
                cx.emit_text(TextRole::Comment, &text);
            }
        }
        for (short, key) in [("footnotes", "footnotes"), ("endnotes", "endnotes")] {
            if let Some(xml) = part_of(short).and_then(|p| self.read(src, cx, &p)) {
                let mut n = 0u64;
                walk(&xml, cx, |ev| {
                    if let Ev::Open(t, _) = ev
                        && (t.name == "footnote" || t.name == "endnote")
                        && t.attr("type").is_none()
                    {
                        n += 1;
                    }
                    Flow::Continue
                })?;
                if n > 0 {
                    f.insert(key.into(), json!(n));
                }
            }
        }
        if let Some(xml) = part_of("settings").and_then(|p| self.read(src, cx, &p)) {
            walk(&xml, cx, |ev| {
                if let Ev::Open(t, _) = ev {
                    match t.name.as_str() {
                        "documentProtection" | "writeProtection" => {
                            let edit = t.attr("edit").unwrap_or("readOnly").to_string();
                            if t.attr("enforcement").is_none_or(|e| e == "1" || e == "true" || e == "on") {
                                f.insert("protection".into(), json!(edit));
                            }
                        }
                        "trackRevisions" => {
                            f.insert("track_revisions".into(), json!(true));
                        }
                        _ => {}
                    }
                }
                Flow::Continue
            })?;
        }
        for (k, v) in f {
            cx.format().insert(k, v);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // workbook, sheets, names, links
    fn excel(&self, src: &mut dyn Source, cx: &mut Context<'_>, main: &str, rels: &[Rel]) -> Result<(), ExtractError> {
        let by_id: BTreeMap<&str, &Rel> = rels.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut sheets: Vec<Value> = Vec::new();
        let mut paths: Vec<(String, String)> = Vec::new();
        let mut defined = 0u64;
        let mut auto_open = Vec::new();
        if has_ext(main, "xml") {
            let xml = self.read(src, cx, main).ok_or_else(|| ExtractError::malformed("workbook unreadable"))?;
            let mut in_name: Option<String> = None;
            walk(&xml, cx, |ev| {
                match ev {
                    Ev::Open(t, _) if t.name == "sheet" => {
                        let name = t.attr("name").unwrap_or("").to_string();
                        let state = t.attr("state").unwrap_or("visible").to_string();
                        let rid = t.qattr("r:id").or_else(|| t.attr("id")).unwrap_or("");
                        let rel = by_id.get(rid);
                        let kind = rel.map_or("worksheet", |r| r.short());
                        if let Some(r) = rel {
                            paths.push((name.clone(), resolve(main, &r.target)));
                        }
                        if sheets.len() < MAX_LISTED {
                            let mut s = json!({ "name": name, "kind": kind });
                            if state != "visible" {
                                s["state"] = json!(state);
                            }
                            sheets.push(s);
                        }
                    }
                    Ev::Open(t, false) if t.name == "definedName" => {
                        defined += 1;
                        in_name = t.attr("name").map(str::to_string);
                    }
                    Ev::Open(t, true) if t.name == "definedName" => defined += 1,
                    Ev::Close("definedName") => {
                        if let Some(n) = in_name.take() {
                            let lower = n.to_ascii_lowercase();
                            if (lower.starts_with("_xlnm.auto_open") || lower.starts_with("auto_open"))
                                && auto_open.len() < 5
                            {
                                auto_open.push(n);
                            }
                        }
                    }
                    _ => {}
                }
                Flow::Continue
            })?;
        }
        let hidden = sheets.iter().filter(|s| s.get("state").is_some()).count();
        let very_hidden = sheets.iter().any(|s| s["state"] == "veryHidden");
        cx.physical().sheets(paths.len().max(sheets.len()) as u64);
        let mut f = Map::new();
        if !sheets.is_empty() {
            f.insert("sheets".into(), json!(sheets));
        }
        if hidden > 0 {
            f.insert("hidden_sheets".into(), json!(hidden));
        }
        if defined > 0 {
            f.insert("defined_names".into(), json!(defined));
        }
        if !auto_open.is_empty() {
            cx.security().risk("auto_exec_macro", Some(auto_open.join(", ")));
        }
        if very_hidden && cx.format().get("part_counts").and_then(|p| p.get("macro_sheets")).is_some() {
            cx.security().risk("hidden_macro_sheet", None);
        }
        // Sheet contents: dimensions, cells, formulas.
        let mut details = Vec::new();
        let (mut cells, mut formulas) = (0u64, 0u64);
        for (name, path) in paths.iter().take(MAX_PARTS) {
            if !has_ext(path, "xml") {
                continue;
            }
            let Some(xml) = self.read(src, cx, path) else { continue };
            let (mut dim, mut c, mut fm, mut links) = (None, 0u64, 0u64, 0u64);
            walk(&xml, cx, |ev| {
                if let Ev::Open(t, _) = ev {
                    match t.name.as_str() {
                        "dimension" => dim = t.attr("ref").map(str::to_string),
                        "c" => c += 1,
                        "f" => fm += 1,
                        "hyperlink" => links += 1,
                        _ => {}
                    }
                }
                Flow::Continue
            })?;
            cells += c;
            formulas += fm;
            if details.len() < MAX_LISTED {
                let mut d = json!({ "name": name, "cells": c });
                if let Some(dim) = dim {
                    d["dimension"] = json!(dim);
                }
                if fm > 0 {
                    d["formulas"] = json!(fm);
                }
                if links > 0 {
                    d["hyperlinks"] = json!(links);
                }
                details.push(d);
            }
        }
        if !details.is_empty() {
            f.insert("sheet_contents".into(), json!(details));
            f.insert("cells".into(), json!(cells));
            f.insert("formulas".into(), json!(formulas));
        }
        // Shared strings feed the secret / personal-data scan as data.
        let strings = rels.iter().find(|r| r.short() == "sharedStrings").map(|r| resolve(main, &r.target));
        if let Some(xml) = strings.and_then(|p| self.read(src, cx, &p)) {
            let mut n = 0u64;
            let mut buf = String::new();
            let mut cur = String::new();
            walk(&xml, cx, |ev| {
                match ev {
                    Ev::Open(t, _) if t.name == "si" => cur.clear(),
                    Ev::Text(s) => cur.push_str(s),
                    Ev::Close("si") => {
                        n += 1;
                        if buf.len() < (1 << 20) {
                            buf.push_str(cur.trim());
                            buf.push('\n');
                        }
                    }
                    _ => {}
                }
                Flow::Continue
            })?;
            f.insert("shared_strings".into(), json!(n));
            cx.emit_text(TextRole::Data, &buf);
        }
        // Cell notes (`xl/commentsN.xml`) and threaded comments.
        let comment_parts: Vec<String> = self
            .zip
            .entries
            .iter()
            .map(|e| e.name.clone())
            .filter(|n| (n.starts_with("xl/comments") || n.starts_with("xl/threadedComments/")) && has_ext(n, "xml"))
            .take(MAX_PARTS)
            .collect();
        let (mut notes, mut threaded, mut authors, mut text) = (0u64, 0u64, Vec::<String>::new(), String::new());
        for part in &comment_parts {
            let Some(xml) = self.read(src, cx, part) else { continue };
            let (n, t) = cell_comments(&xml, cx, &mut authors, &mut text)?;
            notes += n;
            threaded += t;
        }
        if notes + threaded > 0 {
            let mut c = json!({ "count": notes + threaded });
            if threaded > 0 {
                c["threaded"] = json!(threaded);
            }
            if !authors.is_empty() {
                c["authors"] = json!(authors);
            }
            f.insert("comments".into(), c);
            cx.emit_text(TextRole::Comment, &text);
        }
        // External workbook links.
        let mut targets = Vec::new();
        for r in rels.iter().filter(|r| r.short() == "externalLink") {
            let part = resolve(main, &r.target);
            for er in self.rels(src, cx, &part).into_iter().filter(|r| r.external) {
                if targets.len() < 20 {
                    targets.push(truncate_chars(&er.target, 200));
                }
            }
        }
        if !targets.is_empty() {
            cx.security()
                .external_references(targets.len() as u64)
                .risk("external_workbook_link", Some(targets.join(", ")));
            f.insert("external_links".into(), json!(targets));
        }
        for (k, v) in f {
            cx.format().insert(k, v);
        }
        Ok(())
    }

    fn powerpoint(
        &self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        main: &str,
        rels: &[Rel],
    ) -> Result<(), ExtractError> {
        let by_id: BTreeMap<&str, &Rel> = rels.iter().map(|r| (r.id.as_str(), r)).collect();
        let xml = self.read(src, cx, main).ok_or_else(|| ExtractError::malformed("presentation unreadable"))?;
        let mut slides = Vec::new();
        let mut size = None;
        walk(&xml, cx, |ev| {
            if let Ev::Open(t, _) = ev {
                match t.name.as_str() {
                    "sldId" => {
                        let rid = t.qattr("r:id").or_else(|| t.attr("id")).unwrap_or("");
                        if let Some(r) = by_id.get(rid) {
                            slides.push(resolve(main, &r.target));
                        }
                    }
                    "sldSz" => {
                        let emu = |k| t.attr(k).and_then(|v| v.parse::<f64>().ok());
                        if let (Some(w), Some(h)) = (emu("cx"), emu("cy")) {
                            // 914 400 EMU per inch, 72 points per inch.
                            let mut v =
                                json!({ "width_pt": (w / 12_700.0).round(), "height_pt": (h / 12_700.0).round() });
                            if let Some(kind) = t.attr("type") {
                                v["type"] = json!(kind);
                            }
                            size = Some(v);
                        }
                    }
                    _ => {}
                }
            }
            Flow::Continue
        })?;
        cx.physical().slides(slides.len() as u64);
        let mut titles = Vec::new();
        let (mut hidden, mut with_notes) = (0u64, 0u64);
        for (i, path) in slides.iter().enumerate().take(MAX_PARTS) {
            cx.checkpoint()?;
            let Some(xml) = self.read(src, cx, path) else { continue };
            let s = slide_text(&xml, cx)?;
            if s.hidden {
                hidden += 1;
            }
            let title = s.title.clone().unwrap_or_default();
            if !title.is_empty() {
                cx.emit_heading(1, &title);
            }
            if titles.len() < MAX_LISTED {
                titles.push(
                    json!({ "number": i + 1, "title": if title.is_empty() { Value::Null } else { json!(title) } }),
                );
            }
            if !s.body.trim().is_empty() {
                cx.emit_text(TextRole::Body, &s.body);
            }
            let notes = self
                .rels(src, cx, path)
                .into_iter()
                .find(|r| r.short() == "notesSlide")
                .map(|r| resolve(path, &r.target));
            if let Some(xml) = notes.and_then(|p| self.read(src, cx, &p)) {
                let n = slide_text(&xml, cx)?;
                // The notes page repeats the slide image and number; keep the body placeholder text.
                if !n.notes.trim().is_empty() {
                    with_notes += 1;
                    cx.emit_text(TextRole::Body, &n.notes);
                }
            }
        }
        if let Some(first) = titles.first().and_then(|t| t["title"].as_str()).map(str::to_string) {
            cx.content().source("pptx.slide1.title").title(first);
        }
        let mut f = Map::new();
        f.insert("slides".into(), json!(titles));
        if hidden > 0 {
            f.insert("hidden_slides".into(), json!(hidden));
        }
        if with_notes > 0 {
            f.insert("slides_with_notes".into(), json!(with_notes));
        }
        if let Some(s) = size {
            f.insert("slide_size".into(), s);
        }
        for (k, v) in f {
            cx.format().insert(k, v);
        }
        Ok(())
    }

    fn visio(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut pages = Vec::new();
        if let Some(xml) = self.read(src, cx, "visio/pages/pages.xml") {
            walk(&xml, cx, |ev| {
                if let Ev::Open(t, _) = ev
                    && t.name == "Page"
                    && pages.len() < MAX_LISTED
                {
                    let mut p = json!({ "name": t.attr("NameU").or_else(|| t.attr("Name")).unwrap_or("") });
                    if t.attr("Background") == Some("1") {
                        p["background"] = json!(true);
                    }
                    pages.push(p);
                }
                Flow::Continue
            })?;
        }
        cx.physical().pages(pages.len() as u64);
        let names: Vec<String> = self
            .zip
            .under("visio/pages/")
            .filter(|e| has_ext(&e.name, "xml") && !e.name.ends_with("pages.xml"))
            .map(|e| e.name.clone())
            .collect();
        let mut text = String::new();
        let mut shapes = 0u64;
        for name in names.iter().take(MAX_PARTS) {
            let Some(xml) = self.read(src, cx, name) else { continue };
            let mut in_text = 0usize;
            walk(&xml, cx, |ev| {
                match ev {
                    Ev::Open(t, empty) => {
                        if t.name == "Shape" {
                            shapes += 1;
                        }
                        if t.name == "Text" && !empty {
                            in_text += 1;
                        }
                    }
                    Ev::Close("Text") => {
                        in_text = in_text.saturating_sub(1);
                        text.push('\n');
                    }
                    Ev::Text(s) if in_text > 0 && text.len() < (1 << 20) => text.push_str(s),
                    _ => {}
                }
                Flow::Continue
            })?;
        }
        if !text.trim().is_empty() {
            cx.emit_text(TextRole::Body, &text);
        }
        cx.format_set("pages", json!(pages));
        cx.format_set("shapes", shapes);
        Ok(())
    }

    /// Files under `*/embeddings/` become children (OLE objects, nested
    /// workbooks, packages).
    fn embeddings(&self, src: &mut dyn Source, cx: &mut Context<'_>) {
        let embedded: Vec<ZipEntry> = self
            .zip
            .entries
            .iter()
            .filter(|e| !e.is_dir() && e.name.to_ascii_lowercase().contains("/embeddings/"))
            .cloned()
            .collect();
        if embedded.is_empty() || cx.options().limits.max_depth == 0 {
            return;
        }
        let mut listed = Vec::new();
        for e in &embedded {
            if listed.len() < MAX_LISTED {
                listed.push(json!({ "name": e.name, "size_bytes": e.size }));
            }
            match self.zip.read(src, e, cx, self.max) {
                Ok(data) => {
                    if cx.emit_child(&e.name, data).is_err() {
                        break;
                    }
                }
                Err(err) => cx.warn(format!("{}: {err}", e.name)),
            }
        }
        cx.format_set("embedded", listed);
    }
}

/// Map OPC core properties to the normalised sections.
pub(crate) fn core_to_normalised(cx: &mut Context<'_>, core: &Map, source: &str) {
    let s = |k: &str| core.get(k).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty());
    if let Some(t) = s("title") {
        cx.content().source(format!("{source}.title")).title(t);
        cx.emit_text(TextRole::Title, t);
    }
    if let Some(d) = s("description").or_else(|| s("subject")) {
        cx.content().source(format!("{source}.description")).description(d);
        cx.emit_text(TextRole::Caption, d);
    }
    if let Some(c) = s("creator") {
        for name in c.split(';').map(str::trim).filter(|n| !n.is_empty()) {
            cx.content().source(format!("{source}.creator")).author(name);
            cx.rights().source(format!("{source}.creator")).creator(name);
        }
    }
    if let Some(k) = s("keywords") {
        let sep = if k.contains(';') { ';' } else { ',' };
        for kw in k.split(sep).map(str::trim).filter(|w| !w.is_empty()).take(100) {
            cx.content().source(format!("{source}.keywords")).keyword(kw);
        }
    }
    if let Some(l) = s("language") {
        let lang = l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase();
        if lang.len() == 2 {
            cx.content().source(format!("{source}.language")).language(lang, 1.0);
        }
    }
    for (key, field) in
        [("created", DateField::Created), ("modified", DateField::Modified), ("lastPrinted", DateField::Printed)]
    {
        if let Some((v, tz)) = s(key).and_then(w3c_date) {
            cx.temporal().source(format!("{source}.{key}")).content_date(field, v, tz);
        }
    }
}

/// `docProps/app.xml`: scalar properties plus the sheet / slide names in `TitlesOfParts`.
fn app_properties(xml: &str, cx: &Context<'_>) -> Result<Map, ExtractError> {
    let mut out = Map::new();
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut titles = Vec::new();
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, false) => {
                stack.push(t.name.clone());
                text.clear();
            }
            Ev::Text(s) => text.push_str(s),
            Ev::Close(name) => {
                let in_titles = stack.iter().any(|s| s == "TitlesOfParts");
                if stack.len() == 2 && !matches!(name, "HeadingPairs" | "TitlesOfParts" | "HLinks" | "DigSig") {
                    let v = text.trim();
                    if !v.is_empty() {
                        let value = v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n));
                        let value = if name == "TotalTime" { json!(v.parse::<u64>().unwrap_or(0) * 60) } else { value };
                        let key = if name == "TotalTime" { "TotalTime_s".to_string() } else { name.to_string() };
                        out.insert(key, value);
                    }
                } else if in_titles && name == "lpstr" && titles.len() < MAX_LISTED {
                    titles.push(text.trim().to_string());
                }
                stack.pop();
                text.clear();
            }
            Ev::Open(..) => {}
        }
        Flow::Continue
    })?;
    if !titles.is_empty() {
        out.insert("TitlesOfParts".into(), json!(titles));
    }
    Ok(out)
}

/// `docProps/custom.xml`: name → typed value.
fn custom_properties(xml: &str, cx: &Context<'_>) -> Result<Map, ExtractError> {
    let mut out = Map::new();
    let mut name: Option<String> = None;
    let mut kind = String::new();
    let mut text = String::new();
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, _) if t.name == "property" => name = t.attr("name").map(str::to_string),
            Ev::Open(t, false) if name.is_some() => {
                kind.clone_from(&t.name);
                text.clear();
            }
            Ev::Text(s) => text.push_str(s),
            Ev::Close("property") => name = None,
            Ev::Close(k) if k == kind && name.is_some() => {
                let v = text.trim();
                let value = match k {
                    "bool" => json!(v == "true" || v == "1"),
                    "i1" | "i2" | "i4" | "i8" | "int" | "ui1" | "ui2" | "ui4" | "ui8" | "uint" => {
                        v.parse::<i64>().map_or_else(|_| json!(v), |n| json!(n))
                    }
                    "r4" | "r8" | "decimal" => v.parse::<f64>().map_or_else(|_| json!(v), |n| json!(n)),
                    _ => json!(v),
                };
                if let Some(n) = &name
                    && out.len() < 500
                {
                    out.insert(n.clone(), value);
                }
            }
            _ => {}
        }
        Flow::Continue
    })?;
    Ok(out)
}

/// Microsoft Information Protection labels stored as custom properties
/// (`MSIP_Label_<guid>_Name`, `_Enabled`, `_SiteId`, `_Method`…).
fn labels_from_custom(cx: &mut Context<'_>, custom: &Map) {
    let mut labels: BTreeMap<String, Map> = BTreeMap::new();
    for (k, v) in custom {
        let Some(rest) = k.strip_prefix("MSIP_Label_") else { continue };
        let Some((id, field)) = rest.rsplit_once('_') else { continue };
        let key = match field {
            "Name" => "name",
            "Enabled" => "enabled",
            "SiteId" => "site_id",
            "Method" => "method",
            "SetDate" => "set_date",
            "ContentBits" => "content_bits",
            _ => continue,
        };
        labels.entry(id.to_string()).or_default().insert(key.into(), v.clone());
    }
    if labels.is_empty() {
        return;
    }
    let list: Vec<Value> = labels
        .into_iter()
        .map(|(id, mut m)| {
            m.insert("id".into(), json!(id));
            Value::Object(m)
        })
        .collect();
    if let Some(name) = list.iter().find_map(|l| l.get("name").and_then(Value::as_str)) {
        cx.rights().source("docprops.custom.MSIP_Label").usage_terms(format!("Sensitivity: {name}"));
    }
    cx.format_set("sensitivity_labels", list);
}

/// Comments part: count, authors and text.
fn comments(xml: &str, cx: &Context<'_>) -> Result<(u64, Vec<String>, String), ExtractError> {
    let (mut n, mut authors, mut text) = (0u64, Vec::<String>::new(), String::new());
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, _) if t.name == "comment" => {
                n += 1;
                if let Some(a) = t.attr("author")
                    && !authors.iter().any(|x| x == a)
                    && authors.len() < 50
                {
                    authors.push(a.to_string());
                }
            }
            Ev::Text(s) if text.len() < (256 << 10) => text.push_str(s),
            Ev::Close("p") => text.push('\n'),
            _ => {}
        }
        Flow::Continue
    })?;
    Ok((n, authors, text))
}

/// One spreadsheet comments part: (notes, threaded comments). Note authors
/// that a note refers to are added to `authors`, the text to `text`.
fn cell_comments(
    xml: &str,
    cx: &Context<'_>,
    authors: &mut Vec<String>,
    text: &mut String,
) -> Result<(u64, u64), ExtractError> {
    let (mut notes, mut threaded) = (0u64, 0u64);
    let mut names: Vec<String> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let (mut in_author, mut in_text) = (false, false);
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, empty) if t.name == "author" => {
                in_author = !empty;
                if in_author && names.len() < 1000 {
                    names.push(String::new());
                }
            }
            Ev::Close("author") => in_author = false,
            Ev::Open(t, _) if t.name == "comment" => {
                notes += 1;
                if let Some(id) = t.attr("authorId").and_then(|a| a.parse().ok())
                    && !used.contains(&id)
                {
                    used.push(id);
                }
            }
            Ev::Open(t, _) if t.name == "threadedComment" => threaded += 1,
            Ev::Open(t, false) if t.name == "text" => in_text = true,
            Ev::Close("text") => {
                in_text = false;
                text.push('\n');
            }
            Ev::Text(s) if in_author => {
                if let Some(n) = names.last_mut() {
                    n.push_str(s);
                }
            }
            Ev::Text(s) if in_text && text.len() < (256 << 10) => text.push_str(s),
            _ => {}
        }
        Flow::Continue
    })?;
    for id in used {
        if let Some(a) = names.get(id).map(|a| a.trim())
            && !a.is_empty()
            && !authors.iter().any(|x| x == a)
            && authors.len() < 50
        {
            authors.push(a.to_string());
        }
    }
    Ok((notes, threaded))
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // scanner state flags
struct WordScan {
    levels: BTreeMap<String, u8>,
    in_par: bool,
    par: String,
    style: Option<String>,
    outline: Option<u8>,
    in_t: bool,
    in_instr: bool,
    instr: String,
    in_del: usize,
    body: String,
    headings: Vec<(u8, String)>,
    paragraphs: u64,
    tables: u64,
    images: u64,
    sections: u64,
    insertions: u64,
    deletions: u64,
    change_authors: Vec<String>,
    fields: BTreeMap<String, u64>,
    risky_fields: Vec<(&'static str, String)>,
    dde: bool,
}

impl WordScan {
    fn event(&mut self, ev: &Ev<'_>) {
        match ev {
            Ev::Open(t, empty) => self.open(t, *empty),
            Ev::Close(name) => match *name {
                "t" | "delText" => self.in_t = false,
                "instrText" => {
                    self.in_instr = false;
                    let instr = std::mem::take(&mut self.instr);
                    self.field(&instr);
                }
                "del" => self.in_del = self.in_del.saturating_sub(1),
                "p" => self.end_paragraph(),
                _ => {}
            },
            Ev::Text(s) => {
                if self.in_instr {
                    self.instr.push_str(s);
                } else if self.in_t && self.in_del == 0 && self.par.len() < 64 * 1024 {
                    self.par.push_str(s);
                }
            }
        }
    }

    fn open(&mut self, t: &Tag, empty: bool) {
        match t.name.as_str() {
            "p" if !empty => {
                self.in_par = true;
                self.par.clear();
                self.style = None;
                self.outline = None;
            }
            "pStyle" => self.style = t.attr("val").map(str::to_string),
            "outlineLvl" => self.outline = t.attr("val").and_then(|v| v.parse::<u8>().ok()).map(|v| (v + 1).min(9)),
            "t" if !empty => self.in_t = true,
            "tab" if self.in_par => self.par.push('\t'),
            "br" | "cr" if self.in_par => self.par.push('\n'),
            "tbl" => self.tables += 1,
            "drawing" | "pict" => self.images += 1,
            "sectPr" => self.sections += 1,
            "ins" | "del" => {
                if t.name == "ins" {
                    self.insertions += 1;
                } else {
                    self.deletions += 1;
                    if !empty {
                        self.in_del += 1;
                    }
                }
                if let Some(a) = t.attr("author")
                    && !self.change_authors.iter().any(|x| x == a)
                    && self.change_authors.len() < 50
                {
                    self.change_authors.push(a.to_string());
                }
            }
            "fldSimple" => {
                if let Some(instr) = t.attr("instr").map(str::to_string) {
                    self.field(&instr);
                }
            }
            "instrText" if !empty => {
                self.in_instr = true;
                self.instr.clear();
            }
            _ => {}
        }
    }

    fn field(&mut self, instr: &str) {
        let instr = instr.trim();
        let Some(code) = super::field::code(instr) else { return };
        if self.fields.len() < 50 || self.fields.contains_key(&code) {
            *self.fields.entry(code).or_default() += 1;
        }
        if let Some(risk) = super::field::risk(instr) {
            self.dde |= risk == "dde";
            if self.risky_fields.len() < 10 {
                self.risky_fields.push((risk, instr.to_string()));
            }
        }
    }

    fn end_paragraph(&mut self) {
        if !self.in_par {
            return;
        }
        self.in_par = false;
        self.paragraphs += 1;
        let text = crate::plugin::squash_whitespace(&self.par);
        if text.is_empty() {
            return;
        }
        let level =
            self.outline.or_else(|| self.style.as_ref().and_then(|s| self.levels.get(s).copied())).or_else(|| {
                // Documents without a styles part: built-in ids `Heading1`, `Title`.
                let s = self.style.as_deref()?;
                if s.eq_ignore_ascii_case("title") {
                    Some(0)
                } else {
                    s.strip_prefix("Heading").and_then(|d| d.parse::<u8>().ok()).map(|d| d.clamp(1, 9))
                }
            });
        match level {
            Some(l) if self.headings.len() < 2000 => self.headings.push((l, text)),
            _ => {
                if self.body.len() < (16 << 20) {
                    self.body.push_str(&text);
                    self.body.push('\n');
                }
            }
        }
    }
}

#[derive(Default)]
struct SlideText {
    title: Option<String>,
    body: String,
    notes: String,
    hidden: bool,
}

/// A slide's (or notes page's) title, other text, and the notes body.
fn slide_text(xml: &str, cx: &Context<'_>) -> Result<SlideText, ExtractError> {
    let mut s = SlideText::default();
    let mut ph: Option<String> = None;
    let mut shape = String::new();
    let mut in_shape = false;
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, _) if t.name == "sld" => s.hidden = t.attr("show") == Some("0"),
            Ev::Open(t, false) if t.name == "sp" => {
                in_shape = true;
                ph = None;
                shape.clear();
            }
            Ev::Open(t, _) if t.name == "ph" && in_shape => ph = Some(t.attr("type").unwrap_or("body").to_string()),
            Ev::Text(x) if in_shape && shape.len() < 64 * 1024 => shape.push_str(x),
            Ev::Close("p") if in_shape => shape.push('\n'),
            Ev::Close("sp") => {
                in_shape = false;
                let text = shape.trim().to_string();
                if text.is_empty() {
                    return Flow::Continue;
                }
                match ph.as_deref() {
                    Some("title" | "ctrTitle") if s.title.is_none() => {
                        s.title = Some(crate::plugin::squash_whitespace(&text));
                    }
                    Some("sldNum" | "dt" | "ftr" | "hdr" | "sldImg") => {}
                    Some("body") => {
                        s.notes.push_str(&text);
                        s.notes.push('\n');
                        s.body.push_str(&text);
                        s.body.push('\n');
                    }
                    _ => {
                        s.body.push_str(&text);
                        s.body.push('\n');
                    }
                }
            }
            _ => {}
        }
        Flow::Continue
    })?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_targets() {
        assert_eq!(resolve("word/document.xml", "media/image1.png"), "word/media/image1.png");
        assert_eq!(
            resolve("ppt/slides/slide1.xml", "../notesSlides/notesSlide1.xml"),
            "ppt/notesSlides/notesSlide1.xml"
        );
        assert_eq!(resolve("", "/word/document.xml"), "word/document.xml");
        assert_eq!(rels_path("word/document.xml"), "word/_rels/document.xml.rels");
        assert_eq!(rels_path(""), "_rels/.rels");
        assert_eq!(host("https://Example.org:8080/x"), Some("example.org".into()));
        assert_eq!(format_for_content_type("application/vnd.ms-word.document.macroEnabled.main+xml"), Some("docm"));
    }

    #[test]
    fn an_updated_part_is_read_from_its_last_copy() {
        const TYPES: &[u8] = br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
        const RELS: &[u8] = br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
        let body = |word: &str| {
            format!(
                r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Harbour {word} draft</w:t></w:r></w:p></w:body></w:document>"#
            )
        };
        let (old, new) = (body("outdated"), body("current"));
        let docx = crate::plugin::testing::zip(&[
            ("[Content_Types].xml", TYPES, false),
            ("_rels/.rels", RELS, false),
            ("word/document.xml", old.as_bytes(), true),
            ("word/document.xml", new.as_bytes(), true),
        ]);
        let r = crate::plugin::testing::report_for("notes.docx", &docx);
        assert_eq!(r.identification.format, "docx");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Harbour current draft"), "{json}");
        assert!(!json.contains("outdated"));
        assert!(r.security.risks.iter().any(|x| x.kind == "duplicate_entry_names"));
    }

    #[test]
    fn classifies_field_codes() {
        let mut w = WordScan::default();
        w.field(" DDE Excel \"C:\\\\data\\\\fees.xls\" R1C1 ");
        w.field(" INCLUDEPICTURE \"https://img.example.org/logo.png\" ");
        w.field(" PAGE ");
        assert!(w.dde);
        let kinds: Vec<&str> = w.risky_fields.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, ["dde", "external_content"]);
        assert_eq!(w.fields.get("PAGE"), Some(&1));
    }

    crate::fixture_tests!(
        "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb", "pptx", "pptm", "potx", "potm",
        "ppsx", "ppsm", "vsdx", "vsdm", "vstx"
    );
}
