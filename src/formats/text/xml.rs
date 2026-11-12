//! Generic XML: declaration, DOCTYPE, root element and namespaces, schema
//! locations, element and attribute counts, depth, most frequent elements,
//! and the vocabulary (XSD, XSLT, `DocBook`, TEI, JATS, XLIFF, Maven, `MSBuild`,
//! XAML, SVG, …). Document vocabularies contribute their title and section
//! outline; entity declarations are flagged.
//!
//! Specification: <https://www.w3.org/TR/xml/>

use std::collections::BTreeMap;

use quick_xml::events::{BytesStart, Event};
use serde_json::{Map, Value, json};

use super::{decode_xml, entity_text, local, xml_root};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    squash_whitespace,
};

/// Extractor for XML documents.
pub struct Xml;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.xml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "xml",
        name: "XML document",
        family: "text.xml",
        mimes: &["application/xml", "text/xml"],
        extensions: &[
            "xml", "xsd", "xsl", "xslt", "xaml", "rng", "wsdl", "xlf", "xliff", "resx", "dbk", "docbook", "tei",
            "nxml", "mml", "smil", "xbrl", "props", "targets", "xul", "rdf",
        ],
        magic: &[],
        parent: Some("text"),
    }],
};

/// Events processed before giving up on statistics.
const MAX_EVENTS: usize = 5_000_000;

/// `(vocabulary id, name, root local name, namespace fragment)`; an empty
/// namespace fragment matches any namespace.
const VOCABULARIES: &[(&str, &str, &str, &str)] = &[
    ("xsd", "XML Schema", "schema", "www.w3.org/2001/XMLSchema"),
    ("xslt", "XSLT stylesheet", "stylesheet", "www.w3.org/1999/XSL/Transform"),
    ("xslt", "XSLT stylesheet", "transform", "www.w3.org/1999/XSL/Transform"),
    ("relax_ng", "RELAX NG schema", "grammar", "relaxng.org/ns/structure"),
    ("docbook", "DocBook", "book", "docbook.org/ns/docbook"),
    ("docbook", "DocBook", "article", "docbook.org/ns/docbook"),
    ("docbook", "DocBook", "chapter", "docbook.org/ns/docbook"),
    ("tei", "TEI", "TEI", "www.tei-c.org/ns"),
    ("xliff", "XLIFF translation", "xliff", ""),
    ("maven_pom", "Maven POM", "project", "maven.apache.org/POM"),
    ("xaml", "XAML", "", "schemas.microsoft.com/winfx/2006/xaml"),
    ("svg", "SVG image", "svg", ""),
    ("plist", "Property list", "plist", ""),
    ("kml", "KML", "kml", ""),
    ("gpx", "GPX track", "gpx", ""),
    ("wsdl", "WSDL", "definitions", "schemas.xmlsoap.org/wsdl"),
    ("rdf", "RDF/XML", "RDF", "www.w3.org/1999/02/22-rdf-syntax-ns"),
    ("vra_core", "VRA Core record", "vra", "vraweb.org"),
    ("mathml", "MathML", "math", "www.w3.org/1998/Math/MathML"),
    ("smil", "SMIL", "smil", ""),
    ("xbrl", "XBRL report", "xbrl", ""),
    ("android_manifest", "Android manifest", "manifest", "schemas.android.com/apk/res/android"),
    ("android_resources", "Android resources", "resources", ""),
    ("resx", ".NET resources", "root", ""),
    ("opc_relationships", "OPC relationships", "Relationships", "schemas.openxmlformats.org"),
    ("dita", "DITA", "topic", ""),
    ("jats", "JATS article", "article", ""),
    ("msbuild", "MSBuild project", "Project", ""),
];

/// Vocabularies whose text is prose (fed to the language and keyword analyzers).
const DOCUMENTS: &[&str] = &["docbook", "tei", "jats", "dita", "xliff"];
/// Elements that open a section, and those that title one.
const SECTIONS: &[&str] =
    &["section", "sect1", "sect2", "sect3", "sect4", "sect5", "chapter", "sec", "div", "part", "appendix"];
const TITLES: &[&str] = &["title", "head", "article-title"];

impl Extractor for Xml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = decode_xml(&probe.head[..probe.head.len().min(1024)]);
        let start = head.trim_start_matches('\u{feff}').trim_start();
        if start.starts_with("<?xml") {
            return Some(Sniff { format: "xml", confidence: 0.6 });
        }
        // Without a declaration, markup is only weak evidence of XML: an
        // extension (`.html` fragments, `.svg`) wins; the text fallback does not.
        let root = xml_root(start.as_bytes())?;
        (!root.eq_ignore_ascii_case("html") && start.starts_with('<'))
            .then_some(Sniff { format: "xml", confidence: 0.32 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let text = decode_xml(&bytes);
        let mut s = Stats::default();
        s.scan(&text, cx)?;
        s.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Xml);

#[derive(Default)]
struct Stats {
    decl: Map<String, Value>,
    doctype: Option<String>,
    root: Option<String>,
    root_ns: Option<String>,
    root_attrs: Map<String, Value>,
    namespaces: BTreeMap<String, String>,
    schema_locations: Vec<String>,
    elements: u64,
    attributes: u64,
    depth: usize,
    max_depth: usize,
    names: BTreeMap<String, u64>,
    pis: BTreeMap<String, u64>,
    comments: u64,
    cdata: u64,
    text_bytes: u64,
    entities: u64,
    external_entities: u64,
    xincludes: u64,
    /// Text of the element being read, and whether it is a title.
    text: String,
    title_level: Option<u8>,
    sections: Vec<usize>,
    titles: Vec<(u8, String)>,
    body: String,
    error: Option<String>,
    truncated: bool,
}

impl Stats {
    fn scan(&mut self, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut reader = quick_xml::Reader::from_str(text);
        reader.config_mut().check_end_names = false;
        for n in 0.. {
            if n % 4096 == 0 {
                cx.checkpoint()?;
            }
            if n >= MAX_EVENTS {
                self.truncated = true;
                break;
            }
            match reader.read_event() {
                Ok(Event::Decl(d)) => {
                    if let Ok(v) = d.version() {
                        self.decl.insert("version".into(), json!(v));
                    }
                    if let Some(Ok(e)) = d.encoding() {
                        self.decl.insert("encoding".into(), json!(e));
                    }
                    if let Some(Ok(sa)) = d.standalone() {
                        self.decl.insert("standalone".into(), json!(sa == "yes"));
                    }
                }
                Ok(Event::DocType(d)) => self.doctype(&d.xml10_content()),
                Ok(Event::Start(e)) => self.open(&e, false),
                Ok(Event::Empty(e)) => self.open(&e, true),
                Ok(Event::End(e)) => self.close(&local(e.name().as_ref())),
                Ok(Event::Text(t)) => self.text(&t.xml10_content()),
                Ok(Event::GeneralRef(r)) => {
                    if let Some(s) = entity_text(&r) {
                        self.text(&s);
                    }
                }
                Ok(Event::CData(c)) => {
                    self.cdata += 1;
                    self.text(&c.xml10_content());
                }
                Ok(Event::Comment(_)) => self.comments += 1,
                Ok(Event::PI(p)) => {
                    let target = p.target().to_string();
                    *self.pis.entry(target).or_default() += 1;
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    self.error = Some(e.to_string());
                    break;
                }
            }
        }
        Ok(())
    }

    fn doctype(&mut self, d: &str) {
        let d = d.trim();
        self.doctype = Some(squash_whitespace(d.split('[').next().unwrap_or(d)));
        self.entities += d.matches("<!ENTITY").count() as u64;
        self.external_entities +=
            d.split("<!ENTITY").skip(1).filter(|e| e.contains("SYSTEM") || e.contains("PUBLIC")).count() as u64;
    }

    fn open(&mut self, e: &BytesStart<'_>, empty: bool) {
        let qname = e.name().as_ref().to_string();
        let name = local(&qname);
        self.elements += 1;
        *self.names.entry(name.clone()).or_default() += 1;
        let first = self.root.is_none();
        for a in e.attributes().flatten() {
            self.attributes += 1;
            let key = a.key.as_ref().to_string();
            let value = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            if key == "xmlns" && first {
                self.root_ns = Some(value.clone());
            }
            if let Some(prefix) = key.strip_prefix("xmlns:") {
                if self.namespaces.len() < 50 {
                    self.namespaces.insert(prefix.to_string(), value.clone());
                }
            } else if key.ends_with("schemaLocation") {
                if self.schema_locations.len() < 10 {
                    self.schema_locations.push(squash_whitespace(&value));
                }
            } else if first && self.root_attrs.len() < 20 && key != "xmlns" {
                self.root_attrs.insert(key, json!(crate::plugin::truncate_chars(&value, 200)));
            }
        }
        if first {
            self.root = Some(qname.clone());
        }
        if name == "include" && qname.starts_with("xi:") {
            self.xincludes += 1;
        }
        if empty {
            return;
        }
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        if SECTIONS.contains(&name.as_str()) {
            self.sections.push(self.depth);
        }
        if TITLES.contains(&name.as_str()) && self.title_level.is_none() {
            let level = u8::try_from(self.sections.len().min(6)).unwrap_or(6);
            self.title_level = Some(level);
            self.text.clear();
        }
    }

    fn close(&mut self, name: &str) {
        if TITLES.contains(&name)
            && let Some(level) = self.title_level.take()
        {
            let t = squash_whitespace(&self.text);
            if !t.is_empty() && self.titles.len() < 2000 {
                self.titles.push((level, t));
            }
        }
        if SECTIONS.contains(&name) && self.sections.last() == Some(&self.depth) {
            self.sections.pop();
        }
        self.depth = self.depth.saturating_sub(1);
        if self.body.len() < 4 << 20 {
            self.body.push('\n');
        }
    }

    fn text(&mut self, t: &str) {
        self.text_bytes += t.len() as u64;
        if self.title_level.is_some() {
            self.text.push_str(t);
        }
        if self.body.len() < 4 << 20 {
            self.body.push_str(t);
        }
    }

    fn vocabulary(&self) -> Option<(&'static str, &'static str)> {
        let root = self.root.as_deref()?;
        let local_root = root.rsplit(':').next().unwrap_or(root);
        let ns = self.root_ns.clone().unwrap_or_default();
        let any_ns: Vec<&String> = self.namespaces.values().chain(self.root_ns.iter()).collect();
        let doctype = self.doctype.as_deref().unwrap_or("").to_ascii_lowercase();
        if doctype.contains("docbook") {
            return Some(("docbook", "DocBook"));
        }
        if doctype.contains("jats")
            || doctype.contains("journal publishing")
            || doctype.contains("archiving and interchange")
        {
            return Some(("jats", "JATS article"));
        }
        VOCABULARIES
            .iter()
            .find(|(_, _, r, n)| {
                let root_ok = r.is_empty() || r.eq_ignore_ascii_case(local_root);
                let ns_ok = n.is_empty() || ns.contains(n) || (r.is_empty() && any_ns.iter().any(|x| x.contains(n)));
                root_ok && ns_ok && !(r.is_empty() && n.is_empty())
            })
            .filter(|(id, ..)| *id != "jats" || self.names.contains_key("article-meta"))
            .filter(|(id, ..)| *id != "resx" || self.names.contains_key("resheader"))
            .filter(|(id, ..)| {
                *id != "msbuild" || self.root_attrs.contains_key("Sdk") || self.names.contains_key("ItemGroup")
            })
            .map(|(id, name, ..)| (*id, *name))
    }

    fn report(&self, cx: &mut Context<'_>) {
        let vocabulary = self.vocabulary();
        let document = vocabulary.is_some_and(|(id, _)| DOCUMENTS.contains(&id));
        let body = self.body.trim();
        if !body.is_empty() {
            cx.emit_text(if document { TextRole::Body } else { TextRole::Data }, body);
        }
        if document {
            let mut titles = self.titles.iter();
            if let Some((_, t)) = titles.next() {
                cx.content().source("xml.title").title(t.clone());
            }
            for (level, t) in titles {
                cx.emit_heading((*level).max(1), t);
            }
        }
        if self.entities > 0 {
            cx.security().risk("xml_entities", Some(format!("{} entity declaration(s) in the DOCTYPE", self.entities)));
        }
        if self.external_entities > 0 {
            cx.security()
                .risk("external_entity", Some(format!("{} external entity declaration(s)", self.external_entities)))
                .external_references(self.external_entities);
        }
        if self.xincludes > 0 {
            cx.security().risk("xinclude", Some(format!("{} xi:include element(s)", self.xincludes)));
        }
        if let Some(e) = &self.error {
            cx.warn(format!("not well-formed: {e}"));
        }

        let mut f = Map::new();
        if !self.decl.is_empty() {
            f.insert("declaration".into(), Value::Object(self.decl.clone()));
        }
        if let Some(d) = &self.doctype {
            f.insert("doctype".into(), json!(crate::plugin::truncate_chars(d, 300)));
        }
        if let Some(r) = &self.root {
            f.insert("root".into(), json!(r));
        }
        if let Some(ns) = &self.root_ns {
            f.insert("namespace".into(), json!(ns));
        }
        if !self.root_attrs.is_empty() {
            f.insert("root_attributes".into(), Value::Object(self.root_attrs.clone()));
        }
        if let Some((id, name)) = vocabulary {
            f.insert("vocabulary".into(), json!({ "id": id, "name": name }));
        }
        if !self.namespaces.is_empty() {
            f.insert("namespaces".into(), json!(self.namespaces));
        }
        if !self.schema_locations.is_empty() {
            f.insert("schema_locations".into(), json!(self.schema_locations));
        }
        f.insert("well_formed".into(), json!(self.error.is_none()));
        f.insert("elements".into(), json!(self.elements));
        f.insert("attributes".into(), json!(self.attributes));
        f.insert("max_depth".into(), json!(self.max_depth));
        f.insert("distinct_elements".into(), json!(self.names.len()));
        let mut top: Vec<(&String, &u64)> = self.names.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let top: Map<String, Value> = top.into_iter().take(20).map(|(k, n)| (k.clone(), json!(n))).collect();
        f.insert("top_elements".into(), Value::Object(top));
        if !self.pis.is_empty() {
            f.insert("processing_instructions".into(), json!(self.pis));
        }
        if self.comments > 0 {
            f.insert("comments".into(), json!(self.comments));
        }
        if self.cdata > 0 {
            f.insert("cdata_sections".into(), json!(self.cdata));
        }
        f.insert("text_bytes".into(), json!(self.text_bytes));
        if self.truncated {
            f.insert("events_examined".into(), json!(MAX_EVENTS));
        }
        let fmt = cx.format();
        for (k, v) in f {
            fmt.insert(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("xml");
}
