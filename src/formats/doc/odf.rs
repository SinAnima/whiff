//! OpenDocument (ODF 1.0–1.4): text, spreadsheets, presentations, drawings,
//! their templates, formulas, databases and charts, packaged (ZIP) or flat
//! XML (`.fodt`, `.fods`, `.fodp`, `.fodg`).
//!
//! Reads `meta.xml` (title, authors, dates, editing cycles and time,
//! statistics, user-defined fields), the heading outline and text of
//! `content.xml`, sheet and page names, comments, tracked changes, links,
//! embedded objects, StarBasic macros and the event listeners that run
//! them, and per-file encryption from the manifest.
//!
//! Specification: OASIS OpenDocument 1.3, Parts 2 (package) and 3 (schema).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::xml::{Ev, Flow, Tag, walk};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Map, Probe, Sniff, Source, TextRole,
    Zip, truncate_chars, zip_first_stored,
};

/// Extractor for OpenDocument files.
pub struct Odf;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),+], $parent:expr) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "doc.odf",
            mimes: &[$mime],
            extensions: &[$($ext),+],
            magic: &[],
            parent: $parent,
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.odf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("odt", "OpenDocument text", "application/vnd.oasis.opendocument.text", ["odt"], Some("zip")),
        spec!(
            "ott",
            "OpenDocument text template",
            "application/vnd.oasis.opendocument.text-template",
            ["ott"],
            Some("zip")
        ),
        spec!(
            "odm",
            "OpenDocument master document",
            "application/vnd.oasis.opendocument.text-master",
            ["odm"],
            Some("zip")
        ),
        spec!(
            "ods",
            "OpenDocument spreadsheet",
            "application/vnd.oasis.opendocument.spreadsheet",
            ["ods"],
            Some("zip")
        ),
        spec!(
            "ots",
            "OpenDocument spreadsheet template",
            "application/vnd.oasis.opendocument.spreadsheet-template",
            ["ots"],
            Some("zip")
        ),
        spec!(
            "odp",
            "OpenDocument presentation",
            "application/vnd.oasis.opendocument.presentation",
            ["odp"],
            Some("zip")
        ),
        spec!(
            "otp",
            "OpenDocument presentation template",
            "application/vnd.oasis.opendocument.presentation-template",
            ["otp"],
            Some("zip")
        ),
        spec!("odg", "OpenDocument drawing", "application/vnd.oasis.opendocument.graphics", ["odg"], Some("zip")),
        spec!(
            "otg",
            "OpenDocument drawing template",
            "application/vnd.oasis.opendocument.graphics-template",
            ["otg"],
            Some("zip")
        ),
        spec!("odf", "OpenDocument formula", "application/vnd.oasis.opendocument.formula", ["odf"], Some("zip")),
        spec!(
            "sxw",
            "OpenOffice.org 1.x / StarOffice text",
            "application/vnd.sun.xml.writer",
            ["sxw", "sxg"],
            Some("zip")
        ),
        spec!(
            "sxc",
            "OpenOffice.org 1.x / StarOffice spreadsheet",
            "application/vnd.sun.xml.calc",
            ["sxc"],
            Some("zip")
        ),
        spec!(
            "sxi",
            "OpenOffice.org 1.x / StarOffice presentation",
            "application/vnd.sun.xml.impress",
            ["sxi"],
            Some("zip")
        ),
        spec!("sxd", "OpenOffice.org 1.x / StarOffice drawing", "application/vnd.sun.xml.draw", ["sxd"], Some("zip")),
        spec!("odb", "OpenDocument database", "application/vnd.oasis.opendocument.base", ["odb"], Some("zip")),
        spec!("odc", "OpenDocument chart", "application/vnd.oasis.opendocument.chart", ["odc"], Some("zip")),
        spec!(
            "fodt",
            "Flat OpenDocument text",
            "application/vnd.oasis.opendocument.text-flat-xml",
            ["fodt"],
            Some("xml")
        ),
        spec!(
            "fods",
            "Flat OpenDocument spreadsheet",
            "application/vnd.oasis.opendocument.spreadsheet-flat-xml",
            ["fods"],
            Some("xml")
        ),
        spec!(
            "fodp",
            "Flat OpenDocument presentation",
            "application/vnd.oasis.opendocument.presentation-flat-xml",
            ["fodp"],
            Some("xml")
        ),
        spec!(
            "fodg",
            "Flat OpenDocument drawing",
            "application/vnd.oasis.opendocument.graphics-flat-xml",
            ["fodg"],
            Some("xml")
        ),
    ],
};

const MAX_ENTRIES: usize = 20_000;
const MAX_LISTED: usize = 200;

/// The format of an ODF media type (`mimetype` entry or `office:mimetype`).
fn format_for(mime: &str, flat: bool) -> Option<&'static str> {
    // OpenOffice.org 1.x / StarOffice 6–7 packages: the same layout, with
    // the `vnd.sun.xml` types.
    if let Some(old) = mime.trim().strip_prefix("application/vnd.sun.xml.") {
        return match old {
            "writer" | "writer.global" => Some("sxw"),
            "calc" => Some("sxc"),
            "impress" => Some("sxi"),
            "draw" => Some("sxd"),
            _ => None,
        };
    }
    let base = mime.trim().strip_prefix("application/vnd.oasis.opendocument.")?;
    Some(match (base, flat) {
        ("text", false) => "odt",
        ("text-template", _) => "ott",
        ("text-master", _) => "odm",
        ("spreadsheet", false) => "ods",
        ("spreadsheet-template", _) => "ots",
        ("presentation", false) => "odp",
        ("presentation-template", _) => "otp",
        ("graphics", false) => "odg",
        ("graphics-template", _) => "otg",
        ("formula", _) => "odf",
        ("base", _) => "odb",
        ("chart", _) => "odc",
        ("text", true) => "fodt",
        ("spreadsheet", true) => "fods",
        ("presentation", true) => "fodp",
        ("graphics", true) => "fodg",
        _ => return None,
    })
}

impl Extractor for Odf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if let Some(mime) = zip_first_stored(probe.head, "mimetype") {
            let format = format_for(&String::from_utf8_lossy(mime), false)?;
            return Some(Sniff { format, confidence: 0.97 });
        }
        if probe.head.starts_with(b"PK\x03\x04") {
            // Packages written without the `mimetype` entry first.
            let ext = probe.extension?;
            let f = META.formats.iter().find(|f| f.parent == Some("zip") && f.extensions.contains(&ext))?;
            let names = crate::plugin::zip_names(probe, 2000);
            return names
                .iter()
                .any(|n| n == "content.xml" || n == "META-INF/manifest.xml")
                .then_some(Sniff { format: f.id, confidence: 0.85 });
        }
        let root = super::xml::root(probe.head)?;
        if root.name != "document" {
            return None;
        }
        let mime = root.attr("mimetype")?;
        Some(Sniff { format: format_for(mime, true)?, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id().starts_with("fod") {
            let (bytes, _) = cx.read_bytes(src)?;
            let xml = crate::plugin::decode_text(&bytes).text;
            let mut s = Scan::default();
            Scan::meta(&xml, cx)?;
            s.content(&xml, cx)?;
            s.finish(cx);
            return Ok(());
        }
        let zip = Zip::open(src, MAX_ENTRIES)?;
        let max = cx.parse_limit();
        if let Some(e) = zip.entries.first()
            && e.name == "mimetype"
            && let Ok(m) = zip.read(src, &e.clone(), cx, 256)
        {
            cx.format_set("mimetype", String::from_utf8_lossy(&m).trim().to_string());
        }
        let mut s = Scan::default();
        let manifest = zip.read_text(src, "META-INF/manifest.xml", cx, max).transpose()?;
        if let Some(xml) = &manifest {
            s.manifest(xml, cx)?;
        }
        cx.format_set("parts", zip.entries.len());
        if s.encrypted > 0 {
            cx.security().encrypted(true);
            cx.format_set("encrypted_parts", s.encrypted);
        }
        let encrypted = s.encrypted_names.clone();
        let read = |name: &str, cx: &mut Context<'_>, src: &mut dyn Source| -> Option<String> {
            if encrypted.iter().any(|n| n == name) {
                return None;
            }
            match zip.read_text(src, name, cx, max)? {
                Ok(t) => Some(t),
                Err(e) => {
                    cx.warn(format!("{name}: {e}"));
                    None
                }
            }
        };
        if let Some(xml) = read("meta.xml", cx, src) {
            Scan::meta(&xml, cx)?;
        }
        if let Some(xml) = read("content.xml", cx, src) {
            s.content(&xml, cx)?;
        } else if s.encrypted > 0 {
            cx.warn("content.xml is encrypted");
        }
        // StarBasic / scripts: module sources under Basic/.
        let basic: Vec<_> = zip
            .entries
            .iter()
            .filter(|e| {
                (e.name.starts_with("Basic/") || e.name.starts_with("Scripts/"))
                    && e.name.rsplit_once('.').is_some_and(|(_, x)| x.eq_ignore_ascii_case("xml"))
            })
            .filter(|e| !e.name.ends_with("script-lc.xml") && !e.name.ends_with("script-lb.xml"))
            .cloned()
            .collect();
        for e in &basic {
            if let Some(xml) = read(&e.name, cx, src) {
                let mut code = String::new();
                walk(&xml, cx, |ev| {
                    if let Ev::Text(t) = ev {
                        code.push_str(t);
                    }
                    Flow::Continue
                })?;
                if !code.trim().is_empty() {
                    s.modules.push(e.name.clone());
                    super::vba::scan(&code, &mut s.auto, &mut s.suspicious);
                    cx.emit_text(TextRole::Code, &code);
                }
            }
        }
        if zip.entries.iter().any(|e| e.name.starts_with("Scripts/") && !e.is_dir()) {
            s.scripts = true;
        }
        // Embedded objects stored as binary (OLE) streams become children.
        if cx.options().limits.max_depth > 0 {
            for e in zip.entries.iter().filter(|e| {
                e.name.starts_with("Object ") && !e.name.contains('/') || e.name.starts_with("ObjectReplacements/")
            }) {
                if e.name.starts_with("ObjectReplacements/") {
                    continue;
                }
                if let Ok(data) = zip.read(src, &e.clone(), cx, max)
                    && cx.emit_child(&e.name, data).is_err()
                {
                    break;
                }
            }
        }
        if let Some(t) = zip.find("Thumbnails/thumbnail.png") {
            cx.format_set("thumbnail", json!({ "name": t.name, "size_bytes": t.size }));
        }
        s.finish(cx);
        Ok(())
    }
}

crate::register_extractor!(Odf);

/// ISO 8601 durations (`PT1H2M3S`, `P1DT2H`) in seconds.
fn duration_s(v: &str) -> Option<u64> {
    let v = v.trim().strip_prefix('P')?;
    let (mut total, mut num, mut time) = (0f64, String::new(), false);
    for c in v.chars() {
        match c {
            'T' => time = true,
            '0'..='9' | '.' | ',' => num.push(if c == ',' { '.' } else { c }),
            _ => {
                let n: f64 = num.parse().ok()?;
                num.clear();
                total += n * match (c, time) {
                    ('Y', false) => 365.0 * 86_400.0,
                    ('M', false) => 30.0 * 86_400.0,
                    ('W', false) => 7.0 * 86_400.0,
                    ('D', false) => 86_400.0,
                    ('H', true) => 3600.0,
                    ('M', true) => 60.0,
                    ('S', true) => 1.0,
                    _ => return None,
                };
            }
        }
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // non-negative, small
    Some(total.round() as u64)
}

/// An ODF date (`2024-05-01T08:30:00.123456789`, with or without a zone).
fn odf_date(v: &str) -> Option<(String, bool)> {
    let v = v.trim();
    if v.len() < 10 {
        return None;
    }
    let tz = v.ends_with('Z') || v.get(19..).is_some_and(|t| t.contains('+') || t.rfind('-').is_some());
    // Drop fractional seconds (nanoseconds) for a compact value.
    let value = match (v.find('.'), tz) {
        (Some(dot), false) if dot >= 19 => v[..dot].to_string(),
        (Some(dot), true) if dot >= 19 => {
            let zone = v[dot..].find(['Z', '+', '-']).map_or("", |z| &v[dot + z..]);
            format!("{}{zone}", &v[..dot])
        }
        _ => v.to_string(),
    };
    Some((value, tz))
}

#[derive(Default)]
struct Scan {
    encrypted: u64,
    encrypted_names: Vec<String>,
    modules: Vec<String>,
    scripts: bool,
    auto: Vec<String>,
    suspicious: Vec<&'static str>,
    listeners: Vec<String>,
    format: Map,
}

impl Scan {
    fn manifest(&mut self, xml: &str, cx: &Context<'_>) -> Result<(), ExtractError> {
        let mut current: Option<String> = None;
        let mut entries = 0u64;
        let mut version = None;
        walk(xml, cx, |ev| {
            if let Ev::Open(t, _) = ev {
                match t.name.as_str() {
                    "manifest" => version = t.attr("version").map(str::to_string),
                    "file-entry" => {
                        entries += 1;
                        current = t.attr("full-path").map(str::to_string);
                    }
                    "encryption-data" => {
                        self.encrypted += 1;
                        if let Some(p) = &current
                            && self.encrypted_names.len() < 10_000
                        {
                            self.encrypted_names.push(p.clone());
                        }
                    }
                    _ => {}
                }
            }
            Flow::Continue
        })?;
        self.format.insert("manifest_entries".into(), json!(entries));
        if let Some(v) = version {
            self.format.insert("odf_version".into(), json!(v));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // one pass over meta.xml
    fn meta(xml: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut fields: Vec<(String, Tag, String)> = Vec::new();
        let mut open: Option<(String, Tag, String)> = None;
        let mut in_meta = false;
        let mut stats: Option<Tag> = None;
        walk(xml, cx, |ev| {
            match ev {
                Ev::Open(t, empty) => {
                    if t.name == "meta" && !empty {
                        in_meta = true;
                    } else if in_meta && t.name == "document-statistic" {
                        stats = Some(t.clone());
                    } else if in_meta && !empty {
                        open = Some((t.name.clone(), t.clone(), String::new()));
                    } else if in_meta && t.name == "template" {
                        fields.push(("template".into(), t.clone(), String::new()));
                    }
                }
                Ev::Text(s) => {
                    if let Some((_, _, buf)) = open.as_mut()
                        && buf.len() < 64 * 1024
                    {
                        buf.push_str(s);
                    }
                }
                Ev::Close(n) => {
                    if n == "meta" {
                        in_meta = false;
                    } else if open.as_ref().is_some_and(|(o, _, _)| o == n)
                        && let Some((name, t, v)) = open.take()
                    {
                        fields.push((name, t, v.trim().to_string()));
                    }
                }
            }
            Flow::Continue
        })?;
        let mut meta = Map::new();
        let mut keywords = Vec::new();
        let mut user = Map::new();
        for (name, tag, value) in &fields {
            match name.as_str() {
                "keyword" => keywords.push(value.clone()),
                "user-defined" => {
                    if let Some(n) = tag.attr("name") {
                        user.insert(n.to_string(), json!(value));
                    }
                }
                "template" => {
                    if let Some(h) = tag.attr("href") {
                        meta.insert("template".into(), json!(h));
                        if h.starts_with("http") {
                            cx.security().risk("external_template", Some(truncate_chars(h, 200)));
                        }
                    }
                }
                "editing-duration" => {
                    if let Some(s) = duration_s(value) {
                        meta.insert("editing-duration_s".into(), json!(s));
                    }
                }
                _ if !value.is_empty() => {
                    meta.insert(name.clone(), json!(value));
                }
                _ => {}
            }
        }
        if !keywords.is_empty() {
            meta.insert("keywords".into(), json!(keywords));
        }
        if !user.is_empty() {
            meta.insert("user-defined".into(), Value::Object(user));
        }
        if let Some(t) = &stats {
            let mut st = Map::new();
            for (k, v) in &t.attrs {
                let key = k.rsplit(':').next().unwrap_or(k);
                if let Ok(n) = v.parse::<u64>() {
                    st.insert(key.to_string(), json!(n));
                }
            }
            if let Some(n) = st.get("page-count").and_then(Value::as_u64) {
                cx.physical().pages(n);
            }
            if let Some(n) = st.get("word-count").and_then(Value::as_u64) {
                cx.physical().words(n);
            }
            meta.insert("document-statistic".into(), Value::Object(st));
        }
        let get = |k: &str| meta.get(k).and_then(Value::as_str).map(str::to_string);
        if let Some(t) = get("title") {
            cx.content().source("odf.meta.title").title(&t);
            cx.emit_text(TextRole::Title, &t);
        }
        if let Some(d) = get("description").or_else(|| get("subject")) {
            cx.content().source("odf.meta.description").description(&d);
            cx.emit_text(TextRole::Caption, &d);
        }
        for a in [get("initial-creator"), get("creator")].into_iter().flatten() {
            cx.content().source("odf.meta.creator").author(&a);
            cx.rights().source("odf.meta.creator").creator(&a);
        }
        for k in keywords.iter().take(100) {
            cx.content().source("odf.meta.keyword").keyword(k);
        }
        if let Some(l) = get("language") {
            let code = l.split(['-', '_']).next().unwrap_or(&l).to_ascii_lowercase();
            if code.len() == 2 {
                cx.content().source("odf.meta.language").language(code, 1.0);
            }
        }
        for (key, field) in
            [("creation-date", DateField::Created), ("date", DateField::Modified), ("print-date", DateField::Printed)]
        {
            if let Some((v, tz)) = get(key).as_deref().and_then(odf_date) {
                cx.temporal().source(format!("odf.meta.{key}")).content_date(field, v, tz);
            }
        }
        if !meta.is_empty() {
            cx.metadata("odf").extend(meta);
        }
        Ok(())
    }

    fn content(&mut self, xml: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut c = Content::default();
        walk(xml, cx, |ev| {
            c.event(&ev);
            Flow::Continue
        })?;
        for (level, text) in std::mem::take(&mut c.headings) {
            cx.emit_heading(level, &text);
        }
        if let Some(t) = c.title.take() {
            cx.content().source("odf.content.title").title(&t);
        }
        if !c.body.is_empty() {
            cx.emit_text(TextRole::Body, &c.body);
        }
        if !c.notes.is_empty() {
            cx.emit_text(TextRole::Comment, &c.notes);
        }
        let f = &mut self.format;
        f.insert("paragraphs".into(), json!(c.paragraphs));
        if !c.tables.is_empty() {
            f.insert("tables".into(), json!(c.tables));
        }
        if !c.pages.is_empty() {
            f.insert("pages".into(), json!(c.pages));
        }
        for (k, v) in
            [("images", c.images), ("annotations", c.annotations), ("tracked_changes", c.changes), ("forms", c.forms)]
        {
            if v > 0 {
                f.insert(k.into(), json!(v));
            }
        }
        if c.links > 0 {
            f.insert("links".into(), json!(c.links));
            let mut top: Vec<(String, u64)> = c.hosts.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top.truncate(10);
            f.insert(
                "link_hosts".into(),
                json!(top.into_iter().map(|(h, n)| json!({ "host": h, "count": n })).collect::<Vec<_>>()),
            );
            cx.security().external_references(c.external);
        }
        if c.objects > 0 {
            f.insert("embedded_objects".into(), json!(c.objects));
        }
        if c.ole > 0 {
            cx.security().active_content("ole_objects");
        }
        let id = cx.format_id().to_string();
        if id.starts_with("ods") || matches!(id.as_str(), "ots" | "fods" | "sxc") {
            cx.physical().sheets(c.tables.len() as u64);
        } else if matches!(id.as_str(), "odp" | "otp" | "fodp" | "sxi") {
            cx.physical().slides(c.pages.len() as u64);
        }
        self.listeners = c.listeners;
        Ok(())
    }

    fn finish(mut self, cx: &mut Context<'_>) {
        if !self.modules.is_empty() || self.scripts {
            let mut s = cx.security();
            s.active_content("macros");
            s.risk("macros", Some(format!("{} Basic module(s)", self.modules.len())));
            if !self.suspicious.is_empty() {
                s.risk("suspicious_macro", Some(self.suspicious.join(", ")));
            }
            let mut m = json!({ "modules": self.modules });
            if !self.suspicious.is_empty() {
                m["suspicious"] = json!(self.suspicious);
            }
            self.format.insert("macros".into(), m);
        }
        // Event listeners bound to document load run macros by themselves.
        let auto: Vec<&String> = self
            .listeners
            .iter()
            .filter(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("load") || l.contains("open") || l.contains("onfocus")
            })
            .collect();
        if !auto.is_empty() {
            cx.security().risk("auto_exec_macro", Some(auto.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if !self.listeners.is_empty() {
            self.format.insert("event_listeners".into(), json!(self.listeners));
        }
        for (k, v) in std::mem::take(&mut self.format) {
            cx.format().insert(k, v);
        }
    }
}

#[derive(Default)]
struct Content {
    /// Open text containers: (element, heading level or 0 for paragraphs).
    stack: Vec<(String, u8)>,
    buf: String,
    in_annotation: usize,
    /// Inside an annotation's `dc:creator` / `dc:date`.
    in_annotation_meta: bool,
    annotation: String,
    in_title: bool,
    title: Option<String>,
    headings: Vec<(u8, String)>,
    body: String,
    notes: String,
    paragraphs: u64,
    tables: Vec<String>,
    pages: Vec<String>,
    images: u64,
    annotations: u64,
    changes: u64,
    forms: u64,
    links: u64,
    external: u64,
    hosts: BTreeMap<String, u64>,
    objects: u64,
    ole: u64,
    listeners: Vec<String>,
}

impl Content {
    fn event(&mut self, ev: &Ev<'_>) {
        match ev {
            Ev::Open(t, empty) => self.open(t, *empty),
            Ev::Text(s) => {
                if self.in_annotation > 0 {
                    if !self.in_annotation_meta && self.annotation.len() < 64 * 1024 {
                        self.annotation.push_str(s);
                    }
                } else if self.buf.len() < 64 * 1024 && (!self.stack.is_empty() || self.in_title) {
                    self.buf.push_str(s);
                }
            }
            Ev::Close(name) => self.close(name),
        }
    }

    fn open(&mut self, t: &Tag, empty: bool) {
        if self.in_annotation > 0 {
            match t.name.as_str() {
                "creator" | "date" if !empty => self.in_annotation_meta = true,
                "annotation" if !empty => self.in_annotation += 1,
                _ => {}
            }
            return;
        }
        match t.name.as_str() {
            "h" | "p" if !empty => {
                if self.stack.is_empty() {
                    self.buf.clear();
                }
                let level = if t.name == "h" {
                    t.attr("outline-level").and_then(|v| v.parse::<u8>().ok()).unwrap_or(1).clamp(1, 9)
                } else {
                    0
                };
                self.stack.push((t.name.clone(), level));
            }
            "p" => self.paragraphs += 1,
            "s" => self.buf.push(' '),
            "tab" => self.buf.push('\t'),
            "line-break" => self.buf.push('\n'),
            "title" if !empty && self.stack.is_empty() && self.title.is_none() => {
                self.in_title = true;
                self.buf.clear();
            }
            "table" => {
                if let Some(n) = t.attr("name")
                    && self.tables.len() < MAX_LISTED
                {
                    self.tables.push(n.to_string());
                }
            }
            "page" => {
                if self.pages.len() < MAX_LISTED {
                    self.pages.push(t.attr("name").unwrap_or("").to_string());
                }
            }
            "image" => self.images += 1,
            "annotation" => {
                self.annotations += 1;
                if !empty {
                    self.in_annotation += 1;
                }
            }
            "changed-region" => self.changes += 1,
            "form" => self.forms += 1,
            "object" => self.objects += 1,
            "object-ole" => {
                self.objects += 1;
                self.ole += 1;
            }
            "a" => {
                if let Some(h) = t.attr("href") {
                    self.links += 1;
                    if let Some(host) = h.split_once("://").and_then(|(_, r)| r.split(['/', '?', '#', ':']).next()) {
                        self.external += 1;
                        *self.hosts.entry(host.to_ascii_lowercase()).or_default() += 1;
                    }
                }
            }
            "event-listener" => {
                let event = t.attr("event-name").unwrap_or("");
                let target = t.attr("macro-name").or_else(|| t.attr("href")).unwrap_or("");
                if self.listeners.len() < 50 {
                    self.listeners.push(format!("{event} -> {}", truncate_chars(target, 120)));
                }
            }
            _ => {}
        }
    }

    fn close(&mut self, name: &str) {
        if name == "title" && self.in_title {
            self.in_title = false;
            let t = crate::plugin::squash_whitespace(&self.buf);
            if !t.is_empty() {
                self.title = Some(t);
            }
            self.buf.clear();
            return;
        }
        if self.in_annotation > 0 {
            match name {
                "creator" | "date" => self.in_annotation_meta = false,
                "p" | "h" => self.annotation.push('\n'),
                "annotation" => {
                    self.in_annotation -= 1;
                    if self.in_annotation == 0 {
                        let text = std::mem::take(&mut self.annotation);
                        if self.notes.len() < (256 << 10) && !text.trim().is_empty() {
                            self.notes.push_str(text.trim());
                            self.notes.push('\n');
                        }
                    }
                }
                _ => {}
            }
            return;
        }
        if !matches!(name, "h" | "p") || self.stack.last().is_none_or(|(n, _)| n != name) {
            return;
        }
        let (_, level) = self.stack.pop().unwrap_or_default();
        if !self.stack.is_empty() {
            // A paragraph inside another (list item, frame): its text joins the outer one.
            self.buf.push('\n');
            return;
        }
        self.paragraphs += 1;
        let text = crate::plugin::squash_whitespace(&std::mem::take(&mut self.buf));
        if text.is_empty() {
            return;
        }
        if level > 0 && self.headings.len() < 2000 {
            self.headings.push((level, text));
        } else if self.body.len() < (16 << 20) {
            self.body.push_str(&text);
            self.body.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ODT: &str = "application/vnd.oasis.opendocument.text";

    #[test]
    fn durations_and_dates() {
        assert_eq!(duration_s("PT1H2M3S"), Some(3723));
        assert_eq!(duration_s("P1DT0H"), Some(86_400));
        assert_eq!(duration_s("garbage"), None);
        assert_eq!(odf_date("2024-05-01T08:30:00.123456789"), Some(("2024-05-01T08:30:00".into(), false)));
        assert_eq!(odf_date("2024-05-01T08:30:00Z"), Some(("2024-05-01T08:30:00Z".into(), true)));
        assert_eq!(format_for(ODT, false), Some("odt"));
        assert_eq!(format_for(ODT, true), Some("fodt"));
    }

    crate::fixture_tests!(
        "odt", "ott", "odm", "ods", "ots", "odp", "otp", "odg", "otg", "odf", "odb", "odc", "fodt", "fods", "fodp",
        "fodg", "sxw", "sxc", "sxi", "sxd"
    );
}
