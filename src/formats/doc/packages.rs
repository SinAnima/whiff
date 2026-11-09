//! Document packages outside the OOXML / ODF mainstream:
//!
//! * XPS and OpenXPS (fixed-layout ZIP packages): documents, pages, fonts,
//!   the OPC core properties and the glyph runs' text;
//! * Word 2003 XML (`w:wordDocument`) and Flat OPC (`pkg:package`, a whole
//!   OOXML package in one XML file): document properties, parts and text;
//! * Apple iWork (Pages, Numbers, Keynote 2013 and later): the document
//!   properties and the application versions that saved the file, from the
//!   `Metadata` property lists (the IWA content is not decoded);
//! * Hancom HWPX (OWPML): the application and version, title and creator,
//!   sections and text;
//! * Adobe InDesign: IDML packages (DOM version, spreads, stories, fonts,
//!   the stories' text) and the `.indd` header (with its XMP packet);
//!   FrameMaker binary files (`<MakerFile …>`) and MIF (version, pages,
//!   text);
//! * Notion and Confluence exports (ZIP): the page tree from the file names;
//! * Kindle KFX containers: version, size and the DRM wrapper.
//!
//! Specifications: ECMA-388 (OpenXPS) and Microsoft's XPS 1.0; the Word 2003
//! XML schema; ECMA-376 part 2 (OPC) for Flat OPC; KS X 6101 (OWPML); Adobe's
//! IDML File Format Specification and MIF Reference; the KFX container notes
//! of the Calibre KFX Input plugin.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::xml::values;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, TextRole, Zip,
    latin1_or_utf8, proplist, xmlwalk, zip_first_stored, zip_names,
};

/// Extractor for XPS, Word 2003 XML, Flat OPC, iWork, HWPX, InDesign,
/// FrameMaker, wiki exports and KFX.
pub struct Packages;

macro_rules! spec {
    ($id:literal, $name:literal, $family:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*], $parent:expr) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: $family,
            mimes: &[$mime],
            extensions: &[$($ext),*],
            magic: &[$($magic),*],
            parent: $parent,
        }
    };
}

const INDD: &[u8] = b"\x06\x06\xed\xf5\xd8\x1d\x46\xe5\xbd\x31\xef\xe7\xfe\x74\xb7\x1d";

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.packages",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("xps", "XPS / OpenXPS document", "doc.ooxml", "application/oxps", ["xps", "oxps"], [], Some("zip")),
        spec!(
            "wordml_2003",
            "Word 2003 XML document",
            "doc.ooxml",
            "application/vnd.ms-word.wordml",
            [],
            [],
            Some("xml")
        ),
        spec!(
            "flat_opc",
            "Flat OPC (single-file OOXML)",
            "doc.ooxml",
            "application/vnd.ms-office.flatopc",
            [],
            [],
            Some("xml")
        ),
        spec!(
            "iwork_pages",
            "Apple Pages document",
            "doc.odf",
            "application/vnd.apple.pages",
            ["pages"],
            [],
            Some("zip")
        ),
        spec!(
            "iwork_numbers",
            "Apple Numbers spreadsheet",
            "doc.odf",
            "application/vnd.apple.numbers",
            ["numbers"],
            [],
            Some("zip")
        ),
        spec!(
            "iwork_keynote",
            "Apple Keynote presentation",
            "doc.odf",
            "application/vnd.apple.keynote",
            [],
            [],
            Some("zip")
        ),
        spec!("hwpx", "Hancom HWPX document", "doc.odf", "application/hwp+zip", ["hwpx"], [], Some("zip")),
        spec!(
            "idml",
            "InDesign Markup Language package",
            "doc.other",
            "application/vnd.adobe.indesign-idml-package",
            ["idml"],
            [],
            Some("zip")
        ),
        spec!(
            "indesign",
            "Adobe InDesign document",
            "doc.other",
            "application/x-indesign",
            ["indd", "indt"],
            [Magic::prefix(INDD)],
            None
        ),
        spec!(
            "framemaker",
            "Adobe FrameMaker document",
            "doc.other",
            "application/vnd.framemaker",
            ["fm", "book"],
            [Magic::prefix(b"<MakerFile "), Magic::prefix(b"<BookFile ")],
            None
        ),
        spec!(
            "framemaker_mif",
            "FrameMaker Interchange Format (MIF)",
            "doc.other",
            "application/vnd.mif",
            [],
            [Magic::prefix(b"<MIFFile ")],
            None
        ),
        spec!("wiki_export", "Notion / Confluence export", "doc.other", "application/zip", [], [], Some("zip")),
        spec!(
            "kfx",
            "Kindle KFX container",
            "doc.ebook",
            "application/x-kfx-ebook",
            ["kfx", "azw8"],
            [Magic::prefix(b"CONT"), Magic::prefix(b"\xeaDRMION\xee")],
            None
        ),
    ],
};

/// Names, fonts and pages listed.
const MAX_LISTED: usize = 50;
const MAX_ENTRIES: usize = 1 << 16;
const MAX_EVENTS: usize = 1_000_000;
/// Text kept per document.
const MAX_TEXT: usize = 1 << 20;

impl Extractor for Packages {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        if let Some(m) = zip_first_stored(probe.head, "mimetype") {
            return match m.trim_ascii() {
                b"application/hwp+zip" => pick("hwpx", 0.98),
                b"application/vnd.adobe.indesign-idml-package" => pick("idml", 0.98),
                _ => None,
            };
        }
        if probe.head.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 4000);
            let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
            if names.iter().any(|n| has_ext(n, "fdseq")) {
                return pick("xps", 0.95);
            }
            if has("Index/Document.iwa") || has("Metadata/Properties.plist") {
                let kind = match probe.extension {
                    Some("numbers") => "iwork_numbers",
                    Some("key") => "iwork_keynote",
                    _ if names.iter().any(|n| n.starts_with("Index/Slide")) => "iwork_keynote",
                    _ if names.iter().any(|n| n.starts_with("Index/Tables/")) => "iwork_numbers",
                    _ => "iwork_pages",
                };
                return pick(kind, 0.95);
            }
            if wiki_kind(&names).is_some() {
                return pick("wiki_export", 0.8);
            }
            return None;
        }
        let head = &probe.head[..probe.head.len().min(4096)];
        let has = |n: &[u8]| head.windows(n.len()).any(|w| w == n);
        if has(b"http://schemas.microsoft.com/office/word/2003/wordml") && has(b"wordDocument") {
            return pick("wordml_2003", 0.95);
        }
        if has(b"http://schemas.microsoft.com/office/2006/xmlPackage") && has(b"package") {
            return pick("flat_opc", 0.95);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let format = cx.format_id().to_string();
        match format.as_str() {
            "xps" => xps(src, cx),
            "wordml_2003" | "flat_opc" | "framemaker_mif" => {
                let (bytes, _) = cx.read_bytes(src)?;
                let text = crate::plugin::decode_text(&bytes).text;
                match format.as_str() {
                    "wordml_2003" => wordml(cx, &text),
                    "flat_opc" => flat_opc(cx, &text),
                    _ => mif(cx, &text),
                }
            }
            "iwork_pages" | "iwork_numbers" | "iwork_keynote" => iwork(src, cx),
            "hwpx" => hwpx(src, cx),
            "idml" => idml(src, cx),
            "indesign" => indesign(src, cx),
            "framemaker" => framemaker(src, cx),
            "wiki_export" => wiki(src, cx),
            _ => kfx(src, cx),
        }
    }
}

crate::register_extractor!(Packages);

/// Whether `name` ends in `.ext`, whatever the case.
fn has_ext(name: &str, ext: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|x| x.eq_ignore_ascii_case(ext))
}

fn strings(v: impl IntoIterator<Item = String>) -> Value {
    Value::Array(v.into_iter().take(MAX_LISTED).map(Value::String).collect())
}

/// OPC core properties (`docProps/core.xml`) to the report.
fn opc_core(cx: &mut Context<'_>, xml: &str, source: &str) -> Result<(), ExtractError> {
    let fields = values(
        xml,
        cx,
        &[
            "title",
            "subject",
            "creator",
            "keywords",
            "description",
            "lastModifiedBy",
            "created",
            "modified",
            "language",
        ],
    )?;
    let mut core = Map::new();
    for (name, _, v) in fields {
        if !v.is_empty() {
            core.insert(name, json!(v));
        }
    }
    super::ooxml::core_to_normalised(cx, &core, source);
    if !core.is_empty() {
        cx.format_set("core_properties", Value::Object(core));
    }
    Ok(())
}

/// A ZIP entry's text, if it is there.
fn zip_text(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, name: &str) -> Option<String> {
    zip.read_text(src, name, cx, cx.parse_limit()).and_then(Result::ok)
}

/// Every attribute `attr` of elements `tag` in `xml`, and the text inside
/// elements named in `text_tags`.
fn collect(
    cx: &mut Context<'_>,
    xml: &str,
    tag: &str,
    attr: &str,
    text_tags: &[&str],
    prose: &mut String,
) -> Result<Vec<String>, ExtractError> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    xmlwalk::walk(xml, cx, MAX_EVENTS, |_, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            if name == tag
                && let Some(v) = xmlwalk::attr(attrs, attr)
            {
                out.push(v.to_string());
            }
            if text_tags.contains(&name) {
                depth += 1;
            }
        }
        xmlwalk::Ev::End(name) => {
            if text_tags.contains(&name) {
                depth = depth.saturating_sub(1);
                prose.push(' ');
            }
        }
        xmlwalk::Ev::Text(t) => {
            if depth > 0 && prose.len() < MAX_TEXT {
                prose.push_str(t);
            }
        }
    })?;
    Ok(out)
}

// --- XPS -----------------------------------------------------------------------

/// Resolve `target` against the folder of the part `base`.
fn resolve(base: &str, target: &str) -> String {
    if let Some(abs) = target.strip_prefix('/') {
        return abs.to_string();
    }
    let dir = base.rsplit_once('/').map_or("", |(d, _)| d);
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for p in target.split('/') {
        match p {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            p => parts.push(p),
        }
    }
    parts.join("/")
}

fn xps(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let rels = zip_text(&zip, src, cx, "_rels/.rels").unwrap_or_default();
    cx.format_set("variant", if rels.contains("schemas.openxps.org") { "OpenXPS" } else { "XPS 1.0" });
    let seq = zip.entries.iter().find(|e| has_ext(&e.name, "fdseq")).map(|e| e.name.clone());
    let mut prose = String::new();
    let (mut documents, mut pages) = (0usize, Vec::new());
    if let Some(seq) = seq {
        let xml = zip_text(&zip, src, cx, &seq).unwrap_or_default();
        for doc in collect(cx, &xml, "DocumentReference", "Source", &[], &mut prose)? {
            documents += 1;
            let doc = resolve(&seq, &doc);
            let fdoc = zip_text(&zip, src, cx, &doc).unwrap_or_default();
            for page in collect(cx, &fdoc, "PageContent", "Source", &[], &mut prose)? {
                pages.push(resolve(&doc, &page));
            }
        }
    }
    cx.format_set("documents", documents);
    cx.physical().pages(pages.len() as u64);
    // The page text: each glyph run's `UnicodeString`.
    for page in pages.iter().take(500) {
        cx.checkpoint()?;
        let xml = zip_text(&zip, src, cx, page).unwrap_or_default();
        for run in collect(cx, &xml, "Glyphs", "UnicodeString", &[], &mut prose)? {
            if prose.len() < MAX_TEXT {
                prose.push_str(run.trim_start_matches("{}"));
                prose.push('\n');
            }
        }
    }
    let fonts: Vec<String> = zip
        .entries
        .iter()
        .filter(|e| ["odttf", "ttf", "otf"].iter().any(|x| has_ext(&e.name, x)))
        .map(|e| e.name.rsplit('/').next().unwrap_or(&e.name).to_string())
        .collect();
    cx.format_set("font_files", fonts.len());
    if !fonts.is_empty() {
        cx.format_set("fonts", strings(fonts));
    }
    if let Some(core) = zip.entries.iter().find(|e| e.name.ends_with("core.xml")).map(|e| e.name.clone())
        && let Some(xml) = zip_text(&zip, src, cx, &core)
    {
        opc_core(cx, &xml, "xps.core")?;
    }
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- Word 2003 XML / Flat OPC -------------------------------------------------------------

fn wordml(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut path, mut props, mut prose) = (Vec::<String>::new(), Map::new(), String::new());
    xmlwalk::walk(text, cx, MAX_EVENTS, |_, ev| match ev {
        xmlwalk::Ev::Start(name, _) => path.push(name.to_string()),
        xmlwalk::Ev::End(name) => {
            if name == "p" {
                prose.push('\n');
            }
            path.pop();
        }
        xmlwalk::Ev::Text(t) => {
            let parent = path.len().checked_sub(2).map(|i| path[i].as_str());
            match (parent, path.last().map(String::as_str)) {
                (Some("DocumentProperties"), Some(k)) => {
                    props.insert(k.to_string(), t.into());
                }
                (_, Some("t")) if prose.len() < MAX_TEXT => prose.push_str(t),
                _ => {}
            }
        }
    })?;
    let s = |k: &str| props.get(k).and_then(Value::as_str).map(str::to_string);
    if let Some(t) = s("Title") {
        cx.content().title(t);
    }
    if let Some(a) = s("Author") {
        cx.content().author(a);
    }
    for k in ["Pages", "Words", "Characters", "Paragraphs"] {
        if let Some(n) = s(k).and_then(|v| v.parse::<u64>().ok()) {
            match k {
                "Pages" => _ = cx.physical().pages(n),
                "Words" => _ = cx.physical().words(n),
                _ => {}
            }
        }
    }
    cx.format_set("document_properties", Value::Object(props));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn flat_opc(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    // Each `pkg:part` holds its XML in `pkg:xmlData` (or base64 in
    // `pkg:binaryData`).
    let mut parts: Vec<(String, String)> = Vec::new();
    let mut from = 0;
    while let Some(p) = text[from..].find("<pkg:part") {
        let at = from + p;
        let end = text[at..].find("</pkg:part>").map_or(text.len(), |e| at + e);
        let head_end = text[at..end].find('>').map_or(end, |e| at + e);
        let head = &text[at..head_end];
        let name = head.split("pkg:name=\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("").to_string();
        let body = text[head_end..end].find("<pkg:xmlData>").map_or("", |x| {
            let s = head_end + x + 13;
            &text[s..text[s..end].find("</pkg:xmlData>").map_or(end, |e| s + e)]
        });
        parts.push((name, body.to_string()));
        from = end.max(at + 1);
        if parts.len() >= 10_000 {
            break;
        }
    }
    let names: Vec<String> = parts.iter().map(|(n, _)| n.clone()).collect();
    cx.format_set("parts", names.len());
    cx.format_set("part_names", strings(names));
    let kind = if parts.iter().any(|(n, _)| n.starts_with("/word/")) {
        "Word"
    } else if parts.iter().any(|(n, _)| n.starts_with("/xl/")) {
        "Excel"
    } else if parts.iter().any(|(n, _)| n.starts_with("/ppt/")) {
        "PowerPoint"
    } else {
        "other"
    };
    cx.format_set("application", kind);
    if let Some((_, core)) = parts.iter().find(|(n, _)| n.ends_with("core.xml")) {
        opc_core(cx, core, "flat_opc.core")?;
    }
    if let Some((_, doc)) = parts.iter().find(|(n, _)| n == "/word/document.xml") {
        let mut prose = String::new();
        collect(cx, doc, "", "", &["t"], &mut prose)?;
        cx.emit_text(TextRole::Body, &prose);
    }
    Ok(())
}

// --- iWork ---------------------------------------------------------------------------

fn iwork(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let read = |zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, name: &str| -> Option<Vec<u8>> {
        let e = zip.entries.iter().find(|e| e.name == name)?.clone();
        zip.read(src, &e, cx, 1 << 20).ok()
    };
    if let Some(b) = read(&zip, src, cx, "Metadata/Properties.plist")
        && let Some((v, _)) = proplist::parse(&b)
    {
        let j = proplist::to_json(&v, 8);
        if let Value::Object(m) = &j {
            for (k, out) in [
                ("fileFormatVersion", "file_format_version"),
                ("revision", "revision"),
                ("isMultiPage", "multi_page"),
                ("documentUUID", "document_uuid"),
            ] {
                if let Some(v) = m.get(k) {
                    cx.format_set(out, v.clone());
                }
            }
        }
    }
    if let Some(b) = read(&zip, src, cx, "Metadata/BuildVersionHistory.plist")
        && let Some((v, _)) = proplist::parse(&b)
        && let Value::Array(a) = proplist::to_json(&v, 4)
    {
        let saved: Vec<String> = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
        if let Some(last) = saved.last() {
            cx.format_set("saved_with", last.clone());
        }
        cx.format_set("build_history", strings(saved));
    }
    let iwa = zip.entries.iter().filter(|e| has_ext(&e.name, "iwa")).count();
    cx.format_set("iwa_objects", iwa);
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    for e in &zip.entries {
        if let Some(rest) = e.name.strip_prefix("Data/") {
            let ext = rest.rsplit_once('.').map_or("(none)", |(_, x)| x);
            *kinds.entry(if ext.len() <= 5 { ext } else { "other" }).or_default() += 1;
        }
    }
    if !kinds.is_empty() {
        cx.format_set("media", json!(kinds));
    }
    if zip.entries.iter().any(|e| e.name.starts_with("preview")) {
        cx.format_set("preview", true);
    }
    Ok(())
}

// --- HWPX -------------------------------------------------------------------------------

fn hwpx(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    if let Some(v) = zip_text(&zip, src, cx, "version.xml") {
        xmlwalk::walk(&v, cx, MAX_EVENTS, |cx, ev| {
            if let xmlwalk::Ev::Start("HCFVersion", attrs) = ev {
                for (k, out) in [
                    ("application", "application"),
                    ("appVersion", "application_version"),
                    ("tagetApplication", "target"),
                    ("targetApplication", "target"),
                ] {
                    if let Some(v) = xmlwalk::attr(attrs, k) {
                        cx.format_set(out, v);
                    }
                }
                let n = |k| xmlwalk::attr(attrs, k).unwrap_or("0");
                cx.format_set("format_version", format!("{}.{}.{}", n("major"), n("minor"), n("micro")));
            }
        })?;
    }
    if let Some(hpf) = zip_text(&zip, src, cx, "Contents/content.hpf") {
        let mut path: Vec<String> = Vec::new();
        let mut meta_name = String::new();
        xmlwalk::walk(&hpf, cx, MAX_EVENTS, |cx, ev| match ev {
            xmlwalk::Ev::Start(name, attrs) => {
                if name == "meta" {
                    meta_name = xmlwalk::attr(attrs, "name").unwrap_or("").to_string();
                }
                path.push(name.to_string());
            }
            xmlwalk::Ev::End(_) => {
                path.pop();
            }
            xmlwalk::Ev::Text(t) => match path.last().map(String::as_str) {
                Some("title") => _ = cx.content().title(t.to_string()),
                Some("meta") => match meta_name.as_str() {
                    "creator" => _ = cx.content().author(t.to_string()),
                    "subject" | "description" => _ = cx.content().description(t.to_string()),
                    "CreatedDate" | "ModifiedDate" | "date" => cx.format_set(&meta_name.to_ascii_lowercase(), t),
                    _ => {}
                },
                _ => {}
            },
        })?;
    }
    let sections: Vec<String> =
        zip.entries.iter().filter(|e| e.name.starts_with("Contents/section")).map(|e| e.name.clone()).collect();
    cx.format_set("sections", sections.len());
    let mut prose = String::new();
    for s in &sections {
        let xml = zip_text(&zip, src, cx, s).unwrap_or_default();
        collect(cx, &xml, "", "", &["t"], &mut prose)?;
        prose.push('\n');
    }
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- InDesign / FrameMaker ----------------------------------------------------------------

fn idml(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let mut prose = String::new();
    if let Some(map) = zip_text(&zip, src, cx, "designmap.xml") {
        xmlwalk::walk(&map, cx, MAX_EVENTS, |cx, ev| {
            if let xmlwalk::Ev::Start("Document", attrs) = ev
                && let Some(v) = xmlwalk::attr(attrs, "DOMVersion")
            {
                cx.format_set("dom_version", v);
            }
        })?;
    }
    let count = |p: &str| zip.entries.iter().filter(|e| e.name.starts_with(p)).count();
    cx.format_set("spreads", count("Spreads/"));
    cx.format_set("master_spreads", count("MasterSpreads/"));
    let stories: Vec<String> =
        zip.entries.iter().filter(|e| e.name.starts_with("Stories/")).map(|e| e.name.clone()).collect();
    cx.format_set("stories", stories.len());
    for s in stories.iter().take(1000) {
        let xml = zip_text(&zip, src, cx, s).unwrap_or_default();
        collect(cx, &xml, "", "", &["Content"], &mut prose)?;
        prose.push('\n');
    }
    if let Some(fonts) = zip_text(&zip, src, cx, "Resources/Fonts.xml") {
        let families = collect(cx, &fonts, "FontFamily", "Name", &[], &mut String::new())?;
        cx.format_set("font_families", strings(families));
    }
    if let Some(xmp) = zip_text(&zip, src, cx, "META-INF/metadata.xml") {
        cx.emit_block(crate::plugin::BlockKind::XMP, xmp.into_bytes());
    }
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

fn indesign(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 40)?;
    // After the GUID: `DOCUMENT` (or `BOOKBOOK`, `LIBRARY4`) and the byte order.
    cx.format_set("kind", latin1_or_utf8(&h[16..24]).trim().to_string());
    cx.format_set("byte_order", if h[24] == 2 { "big-endian" } else { "little-endian" });
    // The XMP packet InDesign writes into the file.
    let n = src.len().min(cx.parse_limit() as u64);
    let data = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
    if let Some(start) = data.windows(9).position(|w| w == b"<x:xmpmet")
        && let Some(end) = data[start..].windows(12).position(|w| w == b"</x:xmpmeta>")
    {
        cx.emit_block(crate::plugin::BlockKind::XMP, data[start..start + end + 12].to_vec());
    }
    Ok(())
}

fn framemaker(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(64)).unwrap_or(0))?;
    let line = latin1_or_utf8(h.split(|&b| b == b'>').next().unwrap_or(&[]));
    let mut words = line.trim_start_matches('<').split_whitespace();
    if let (Some(kind), Some(v)) = (words.next(), words.next()) {
        cx.format_set("kind", if kind == "BookFile" { "book" } else { "document" });
        cx.format_set("version", v);
    }
    Ok(())
}

/// MIF: `<MIFFile 2015>`, then `<Page …>` and `<String …>` statements.
#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn mif(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    if let Some(v) = text.strip_prefix("<MIFFile ").and_then(|r| r.split('>').next()) {
        cx.format_set("version", v.trim());
    }
    if let Some(g) = text.lines().find_map(|l| l.trim().strip_prefix("# Generated by")) {
        cx.format_set("generator", g.trim());
    }
    let opens = |tag: &str| {
        text.lines()
            .filter(|l| l.trim_start().strip_prefix(tag).is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t'])))
            .count()
    };
    cx.physical().pages(opens("<Page") as u64);
    let mut prose = String::new();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("<String `")
            && prose.len() < MAX_TEXT
        {
            prose.push_str(rest.split("'>").next().unwrap_or(""));
            prose.push(' ');
        }
        if line.trim() == "> # end of Para" {
            prose.push('\n');
        }
    }
    cx.format_set("paragraphs", opens("<Para"));
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- Notion / Confluence exports ------------------------------------------------------------

/// Notion names pages `Title <32 hex>.md` (or `.html`); Confluence's HTML
/// export has `index.html` and `styles/site.css` in each space folder.
fn wiki_kind(names: &[String]) -> Option<&'static str> {
    let notion = names
        .iter()
        .filter(|n| {
            let stem = n.rsplit('/').next().unwrap_or(n);
            let stem = stem.strip_suffix(".md").or_else(|| stem.strip_suffix(".html")).unwrap_or("");
            stem.rsplit_once(' ').is_some_and(|(_, id)| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .count();
    if notion >= 1 && notion * 2 >= names.iter().filter(|n| has_ext(n, "md") || has_ext(n, "html")).count() {
        return Some("Notion");
    }
    (names.iter().any(|n| n.ends_with("/index.html")) && names.iter().any(|n| n.ends_with("styles/site.css")))
        .then_some("Confluence")
}

fn wiki(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let names: Vec<String> = zip.entries.iter().map(|e| e.name.clone()).collect();
    let kind = wiki_kind(&names).unwrap_or("unknown");
    cx.format_set("exported_from", kind);
    let page = |n: &str| has_ext(n, "md") || (has_ext(n, "html") && !n.ends_with("index.html"));
    let mut titles = Vec::new();
    let mut depth_max = 0usize;
    for n in names.iter().filter(|n| page(n)) {
        let base = n.rsplit('/').next().unwrap_or(n);
        let stem = base.rsplit_once('.').map_or(base, |(s, _)| s);
        // Notion: `Title <32 hex>`; Confluence: `Title_<page id>`.
        let title = match kind {
            "Notion" => stem.rsplit_once(' ').map_or(stem, |(t, _)| t),
            _ => {
                stem.rsplit_once('_').filter(|(_, id)| id.bytes().all(|b| b.is_ascii_digit())).map_or(stem, |(t, _)| t)
            }
        };
        depth_max = depth_max.max(n.matches('/').count());
        titles.push(title.to_string());
    }
    let attachments = names
        .iter()
        .filter(|n| !page(n) && !n.ends_with('/') && !has_ext(n, "css") && !n.ends_with("index.html"))
        .count();
    cx.format_set("pages", titles.len());
    cx.format_set("depth", depth_max);
    cx.format_set("attachments", attachments);
    cx.format_set("page_titles", strings(titles));
    Ok(())
}

// --- KFX ---------------------------------------------------------------------------------

fn kfx(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(32)).unwrap_or(0))?;
    if h.starts_with(b"\xeaDRMION\xee") {
        cx.format_set("drm", "DRMION");
        cx.security().encrypted(true);
        return Ok(());
    }
    // `CONT`, a version, the header length, then the container info's
    // offset and length.
    let le16 = |at: usize| h.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let le32 = |at: usize| h.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if let Some(v) = le16(4) {
        cx.format_set("container_version", v);
    }
    if let Some(n) = le32(6) {
        cx.format_set("header_bytes", n);
    }
    if let (Some(off), Some(len)) = (le32(10), le32(14)) {
        cx.format_set("container_info_offset", off);
        cx.format_set("container_info_bytes", len);
    }
    cx.format_set("drm", "none");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "xps",
        "wordml_2003",
        "flat_opc",
        "iwork_pages",
        "iwork_numbers",
        "iwork_keynote",
        "hwpx",
        "idml",
        "indesign",
        "framemaker",
        "framemaker_mif",
        "wiki_export",
        "kfx"
    );

    #[test]
    fn helpers() {
        assert_eq!(resolve("Documents/1/FixedDocument.fdoc", "Pages/1.fpage"), "Documents/1/Pages/1.fpage");
        assert_eq!(
            resolve("FixedDocumentSequence.fdseq", "/Documents/1/FixedDocument.fdoc"),
            "Documents/1/FixedDocument.fdoc"
        );
        let notion: Vec<String> =
            ["Harbour 0123456789abcdef0123456789abcdef.md", "Harbour/Tides 0123456789abcdef0123456789abcdee.md"]
                .iter()
                .map(ToString::to_string)
                .collect();
        assert_eq!(wiki_kind(&notion), Some("Notion"));
        let conf: Vec<String> =
            ["SALT/index.html", "SALT/styles/site.css", "SALT/123.html"].iter().map(ToString::to_string).collect();
        assert_eq!(wiki_kind(&conf), Some("Confluence"));
    }
}
