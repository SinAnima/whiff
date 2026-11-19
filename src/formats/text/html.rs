//! HTML and XHTML: title, language, meta tags, `OpenGraph` / Twitter cards,
//! link relations, JSON-LD / microdata types, the H1–H6 outline, a census of
//! links, images, forms, scripts and iframes, and the visible text.
//!
//! Specification: <https://html.spec.whatwg.org/>

use std::collections::BTreeMap;

use ego_tree::iter::Edge;
use scraper::{Html, Node};
use serde_json::{Map, Value, json};

use super::{start_tag, url_host, xml_root};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    decode_text, parse_date, truncate_chars,
};

/// Extractor for HTML and XHTML.
pub struct Html5;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.html",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "html",
            name: "HTML document",
            family: "text.html",
            mimes: &["text/html"],
            extensions: &["html", "htm", "shtml"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "xhtml",
            name: "XHTML document",
            family: "text.html",
            mimes: &["application/xhtml+xml"],
            extensions: &["xhtml", "xht"],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

/// Elements whose text is not page content.
const SKIP_TEXT: &[&str] = &["script", "style", "noscript", "template", "nav", "footer", "aside", "svg", "head"];
/// Elements that end a run of text.
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "li",
    "td",
    "th",
    "section",
    "article",
    "main",
    "blockquote",
    "pre",
    "dd",
    "dt",
    "figcaption",
    "tr",
    "br",
    "hr",
    "table",
    "ul",
    "ol",
    "header",
];

impl Extractor for Html5 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = String::from_utf8_lossy(&probe.head[..probe.head.len().min(2048)]).to_ascii_lowercase();
        let start = head.trim_start_matches('\u{feff}').trim_start();
        if start.starts_with("<?xml") {
            let root = xml_root(probe.head)?;
            let tag = start_tag(probe.head, &root).unwrap_or_default();
            return (root.eq_ignore_ascii_case("html") && tag.contains("http://www.w3.org/1999/xhtml"))
                .then_some(Sniff { format: "xhtml", confidence: 0.92 });
        }
        if start.starts_with("<!doctype html") {
            return Some(Sniff { format: "html", confidence: 0.9 });
        }
        if xml_root(probe.head).is_some_and(|r| r.eq_ignore_ascii_case("html")) {
            return Some(Sniff { format: "html", confidence: 0.85 });
        }
        (start.starts_with('<') && (head.contains("<html") || head.contains("<head>") || head.contains("<body")))
            .then_some(Sniff { format: "html", confidence: 0.7 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let (mut text, charset) = decode_html(&bytes);
        if let Some(c) = &charset {
            cx.format_set("declared_charset", c.clone());
        }
        // The HTML tree builder scans its stack of open elements for every
        // start tag, so its cost grows with depth × elements; cap the depth.
        if let Some(cut) = depth_cut(&text, MAX_DEPTH) {
            text.truncate(cut);
            cx.warn(format!("nested deeper than {MAX_DEPTH} elements; parsed the first {cut} bytes"));
            cx.format_set("truncated_at_depth", MAX_DEPTH);
        }
        let doc = Html::parse_document(&text);
        cx.checkpoint()?;
        let mut w = Walk::default();
        w.walk(&doc, cx)?;
        w.finish(cx);
        Ok(())
    }
}

crate::register_extractor!(Html5);

/// Element nesting parsed before the rest of the document is dropped.
const MAX_DEPTH: usize = 512;

/// Elements that never have content.
const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
    "basefont", "bgsound", "frame", "keygen",
];
/// Elements that close an open sibling of their kind, so a run of them does not nest.
const SELF_CLOSING_SIBLINGS: &[&str] =
    &["p", "li", "dt", "dd", "tr", "td", "th", "option", "optgroup", "rt", "rp", "thead", "tbody", "tfoot"];
/// Elements whose content is raw text, not markup.
const RAW_TEXT: &[&str] = &["script", "style", "textarea", "title", "xmp", "plaintext"];

/// Byte offset of the start tag at which nesting first exceeds `max`, by a
/// cheap tag scan (no tree is built).
fn depth_cut(text: &str, max: usize) -> Option<usize> {
    let b = text.as_bytes();
    let (mut i, mut depth) = (0usize, 0usize);
    while let Some(off) = memchr_lt(&b[i..]) {
        let at = i + off;
        let rest = &text[at + 1..];
        if rest.starts_with("!--") {
            i = rest.find("-->").map_or(b.len(), |p| at + 1 + p + 3);
            continue;
        }
        let closing = rest.starts_with('/');
        let name: String = rest
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        // Look for the end of the tag nearby only, so `<<<<…` stays linear.
        let window = &rest.as_bytes()[..rest.len().min(4096)];
        let end = window.iter().position(|&c| c == b'>').map_or(at + 1, |p| at + 1 + p + 1);
        if name.is_empty() {
            i = at + 1;
            continue;
        }
        if closing {
            depth = depth.saturating_sub(1);
        } else if RAW_TEXT.contains(&name.as_str()) {
            i = find_close(text, end, &name);
            continue;
        } else if !VOID.contains(&name.as_str())
            && !SELF_CLOSING_SIBLINGS.contains(&name.as_str())
            && !text[at..end.min(b.len())].ends_with("/>")
        {
            depth += 1;
            if depth > max {
                return Some(at);
            }
        }
        i = end.max(at + 1);
    }
    None
}

/// Offset of the `</name` (any case) that ends a raw-text element, or the end.
fn find_close(text: &str, from: usize, name: &str) -> usize {
    let from = from.min(text.len());
    text[from..]
        .match_indices("</")
        .find(|(p, _)| text.get(from + p + 2..from + p + 2 + name.len()).is_some_and(|n| n.eq_ignore_ascii_case(name)))
        .map_or(text.len(), |(p, _)| from + p)
}

fn memchr_lt(b: &[u8]) -> Option<usize> {
    b.iter().position(|&c| c == b'<')
}

/// Decode with the BOM, then a `<meta charset>` declaration, then detection.
fn decode_html(bytes: &[u8]) -> (String, Option<String>) {
    let declared = declared_charset(&bytes[..bytes.len().min(2048)]);
    if encoding_rs::Encoding::for_bom(bytes).is_none()
        && let Some(enc) = declared.as_deref().and_then(|l| encoding_rs::Encoding::for_label(l.as_bytes()))
        && enc != encoding_rs::UTF_8
    {
        let (t, _) = enc.decode_without_bom_handling(bytes);
        return (t.into_owned(), declared);
    }
    (decode_text(bytes).text, declared)
}

fn declared_charset(head: &[u8]) -> Option<String> {
    let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
    let at = lower.find("charset=")? + "charset=".len();
    let value: String = lower[at..]
        .trim_start_matches(['"', '\''])
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
        .collect();
    (!value.is_empty()).then_some(value)
}

#[derive(Default)]
struct Walk {
    skip: usize,
    title: Option<String>,
    in_title: bool,
    heading: Option<(u8, String)>,
    block: String,
    meta: Map<String, Value>,
    opengraph: Map<String, Value>,
    twitter: Map<String, Value>,
    dublin_core: Map<String, Value>,
    citation: Map<String, Value>,
    canonical: Option<String>,
    alternates: Vec<Value>,
    feeds: Vec<Value>,
    icons: u64,
    manifest: Option<String>,
    license: Option<String>,
    stylesheets: u64,
    style_hosts: BTreeMap<String, u64>,
    links_internal: u64,
    links_external: u64,
    link_hosts: BTreeMap<String, u64>,
    javascript_urls: u64,
    mailto: u64,
    images: u64,
    images_with_alt: u64,
    forms: Vec<Value>,
    password_fields: u64,
    inline_scripts: u64,
    script_hosts: BTreeMap<String, u64>,
    json_ld: Vec<String>,
    in_json_ld: bool,
    json_ld_text: String,
    item_types: BTreeMap<String, u64>,
    iframes: u64,
    iframe_hosts: BTreeMap<String, u64>,
    hidden_iframes: u64,
    event_handlers: u64,
    elements: u64,
    depth: usize,
    max_depth: usize,
    doctype: Option<String>,
    lang: Option<String>,
    refresh: Option<String>,
    form_inputs: BTreeMap<String, u64>,
}

impl Walk {
    fn walk(&mut self, doc: &Html, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        for (n, edge) in doc.tree.root().traverse().enumerate() {
            if n % 8192 == 0 {
                cx.checkpoint()?;
            }
            match edge {
                Edge::Open(node) => match node.value() {
                    Node::Element(e) => {
                        self.elements += 1;
                        self.depth += 1;
                        self.max_depth = self.max_depth.max(self.depth);
                        self.open(e, cx);
                    }
                    Node::Text(t) => self.text(t, cx),
                    Node::Doctype(d) => {
                        let id = d.public_id();
                        self.doctype = Some(if id.is_empty() { d.name().to_string() } else { id.to_string() });
                    }
                    _ => {}
                },
                Edge::Close(node) => {
                    if let Node::Element(e) = node.value() {
                        self.depth = self.depth.saturating_sub(1);
                        self.close(e.name(), cx);
                    }
                }
            }
        }
        Ok(())
    }

    fn open(&mut self, e: &scraper::node::Element, cx: &mut Context<'_>) {
        let name = e.name();
        let attr = |a: &str| e.attr(a).map(str::trim).filter(|v| !v.is_empty());
        let hidden = e.attr("hidden").is_some() || attr("aria-hidden") == Some("true");
        if SKIP_TEXT.contains(&name) || hidden {
            self.skip += 1;
        }
        if BLOCKS.contains(&name) {
            self.flush(cx);
        }
        self.event_handlers += e.attrs().filter(|(k, _)| k.starts_with("on")).count() as u64;
        for key in ["itemtype", "typeof"] {
            if let Some(t) = attr(key) {
                for ty in t.split_whitespace() {
                    let short = ty.rsplit(['/', '#']).next().unwrap_or(ty);
                    *self.item_types.entry(short.to_string()).or_default() += 1;
                }
            }
        }
        match name {
            "html" => self.lang = attr("lang").or_else(|| attr("xml:lang")).map(str::to_string),
            "title" if self.title.is_none() => {
                self.in_title = true;
                self.title = Some(String::new());
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.heading = Some((name.as_bytes()[1] - b'0', String::new()));
            }
            "meta" => self.meta(e),
            "link" => self.link(e),
            "a" => {
                if let Some(href) = attr("href") {
                    self.anchor(href);
                }
            }
            "img" => {
                self.images += 1;
                if let Some(alt) = attr("alt") {
                    self.images_with_alt += 1;
                    cx.emit_text(TextRole::Caption, alt);
                }
            }
            "form" => {
                let action = attr("action").unwrap_or("");
                self.forms.push(json!({
                    "method": attr("method").unwrap_or("get").to_ascii_lowercase(),
                    "action_host": url_host(action),
                }));
            }
            "input" => {
                let ty = attr("type").unwrap_or("text").to_ascii_lowercase();
                if ty == "password" {
                    self.password_fields += 1;
                }
                *self.form_inputs.entry(ty).or_default() += 1;
            }
            "script" => {
                match attr("src") {
                    Some(s) => {
                        if let Some(h) = url_host(s) {
                            *self.script_hosts.entry(h).or_default() += 1;
                        }
                    }
                    None => self.inline_scripts += 1,
                }
                if attr("type").is_some_and(|t| t.eq_ignore_ascii_case("application/ld+json")) {
                    self.in_json_ld = true;
                    self.json_ld_text.clear();
                }
            }
            "iframe" | "frame" => {
                self.iframes += 1;
                if let Some(h) = attr("src").and_then(url_host) {
                    *self.iframe_hosts.entry(h).or_default() += 1;
                }
                let style = attr("style").unwrap_or("").to_ascii_lowercase().replace(' ', "");
                let zero = |a: &str| attr(a).is_some_and(|v| v == "0" || v == "0px" || v == "1");
                if (zero("width") && zero("height"))
                    || style.contains("display:none")
                    || style.contains("visibility:hidden")
                {
                    self.hidden_iframes += 1;
                }
            }
            _ => {}
        }
    }

    fn close(&mut self, name: &str, cx: &mut Context<'_>) {
        match name {
            "title" => self.in_title = false,
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                if let Some((level, text)) = self.heading.take() {
                    cx.emit_heading(level, &text);
                }
            }
            "script" if self.in_json_ld => {
                self.in_json_ld = false;
                if self.json_ld.len() < 20 {
                    self.json_ld.push(std::mem::take(&mut self.json_ld_text));
                }
            }
            _ => {}
        }
        if BLOCKS.contains(&name) {
            self.flush(cx);
        }
        if SKIP_TEXT.contains(&name) {
            self.skip = self.skip.saturating_sub(1);
        }
    }

    fn text(&mut self, t: &str, cx: &mut Context<'_>) {
        if self.in_json_ld {
            if self.json_ld_text.len() < 256 * 1024 {
                self.json_ld_text.push_str(t);
            }
        } else if self.in_title {
            if let Some(title) = &mut self.title {
                title.push_str(t);
            }
        } else if let Some((_, h)) = &mut self.heading {
            h.push_str(t);
        } else if self.skip == 0 {
            self.block.push_str(t);
            if self.block.len() > 64 * 1024 {
                self.flush(cx);
            }
        }
    }

    fn flush(&mut self, cx: &mut Context<'_>) {
        let b = crate::plugin::squash_whitespace(&self.block);
        if !b.is_empty() {
            cx.emit_text(TextRole::Body, &b);
        }
        self.block.clear();
    }

    fn meta(&mut self, e: &scraper::node::Element) {
        if let Some(c) = e.attr("charset") {
            self.meta.insert("charset".into(), json!(c));
        }
        let Some(content) = e.attr("content").map(str::trim) else { return };
        let key = e.attr("property").or_else(|| e.attr("name")).or_else(|| e.attr("itemprop"));
        if let Some(equiv) = e.attr("http-equiv") {
            let equiv = equiv.to_ascii_lowercase();
            if equiv == "refresh" {
                self.refresh = Some(content.to_string());
            }
            self.meta.insert(format!("http-equiv:{equiv}"), json!(truncate_chars(content, 500)));
            return;
        }
        let Some(key) = key else { return };
        let value = json!(truncate_chars(content, 1000));
        let lower = key.to_ascii_lowercase();
        if let Some(k) = lower.strip_prefix("og:") {
            insert_multi(&mut self.opengraph, k, value);
        } else if let Some(k) = lower.strip_prefix("twitter:") {
            self.twitter.insert(k.to_string(), value);
        } else if let Some(k) = lower.strip_prefix("dc.").or_else(|| lower.strip_prefix("dcterms.")) {
            insert_multi(&mut self.dublin_core, k, value);
        } else if let Some(k) = lower.strip_prefix("citation_") {
            insert_multi(&mut self.citation, k, value);
        } else if lower.starts_with("article:") {
            insert_multi(&mut self.meta, &lower, value);
        } else {
            self.meta.insert(lower, value);
        }
    }

    fn link(&mut self, e: &scraper::node::Element) {
        let rel = e.attr("rel").unwrap_or("").to_ascii_lowercase();
        let Some(href) = e.attr("href").map(str::trim).filter(|h| !h.is_empty()) else { return };
        let rels: Vec<&str> = rel.split_whitespace().collect();
        let ty = e.attr("type").unwrap_or("").to_ascii_lowercase();
        if rels.contains(&"canonical") {
            self.canonical = Some(href.to_string());
        }
        if rels.contains(&"alternate") {
            if ty.contains("rss") || ty.contains("atom") || ty.contains("feed+json") {
                self.feeds.push(json!({ "type": ty, "href": href, "title": e.attr("title") }));
            } else if let Some(lang) = e.attr("hreflang") {
                self.alternates.push(json!({ "hreflang": lang, "href": href }));
            }
        }
        if rels.iter().any(|r| r.contains("icon")) {
            self.icons += 1;
        }
        if rels.contains(&"manifest") {
            self.manifest = Some(href.to_string());
        }
        if rels.contains(&"license") {
            self.license = Some(href.to_string());
        }
        if rels.contains(&"stylesheet") {
            self.stylesheets += 1;
            if let Some(h) = url_host(href) {
                *self.style_hosts.entry(h).or_default() += 1;
            }
        }
    }

    fn anchor(&mut self, href: &str) {
        let lower = href.to_ascii_lowercase();
        if lower.starts_with("javascript:") {
            self.javascript_urls += 1;
        } else if lower.starts_with("mailto:") {
            self.mailto += 1;
        } else if let Some(h) = url_host(href) {
            let own = self.canonical.as_deref().and_then(url_host);
            if own.as_deref() == Some(h.as_str()) {
                self.links_internal += 1;
            } else {
                self.links_external += 1;
                *self.link_hosts.entry(h).or_default() += 1;
            }
        } else {
            self.links_internal += 1;
        }
    }

    fn finish(&mut self, cx: &mut Context<'_>) {
        self.flush(cx);
        let title = self.title.take().map(|t| crate::plugin::squash_whitespace(&t)).filter(|t| !t.is_empty());
        let get = |m: &Map<String, Value>, k: &str| m.get(k).and_then(first_str).map(str::to_string);

        // content: social and citation titles come without the site-name
        // suffix that `<title>` usually carries, so they win.
        for (map, key, src) in [
            (&self.opengraph, "title", "og:title"),
            (&self.twitter, "title", "twitter:title"),
            (&self.citation, "title", "citation_title"),
        ] {
            if let Some(t) = get(map, key) {
                cx.content().source(src).title(t);
            }
        }
        if let Some(t) = &title {
            cx.content().source("html.title").title(t.clone());
            cx.emit_text(TextRole::Title, t);
            cx.format_set("title_tag", t.clone());
        }
        for (map, key, src) in [
            (&self.meta, "description", "meta.description"),
            (&self.opengraph, "description", "og:description"),
            (&self.twitter, "description", "twitter:description"),
            (&self.dublin_core, "description", "dc.description"),
        ] {
            if let Some(d) = get(map, key) {
                cx.content().source(src).description(d);
            }
        }
        if let Some(k) = get(&self.meta, "keywords") {
            for kw in k.split(',') {
                cx.content().source("meta.keywords").keyword(kw.trim());
            }
        }
        for (map, key, src) in [
            (&self.meta, "author", "meta.author"),
            (&self.meta, "article:author", "article:author"),
            (&self.citation, "author", "citation_author"),
            (&self.dublin_core, "creator", "dc.creator"),
        ] {
            for a in all_str(map.get(key)) {
                cx.content().source(src).author(a);
            }
        }
        for t in all_str(self.meta.get("article:tag")) {
            cx.content().source("article:tag").tag(t);
        }
        if let Some(lang) = &self.lang {
            let code = lang.split(['-', '_']).next().unwrap_or(lang).to_ascii_lowercase();
            if (2..=3).contains(&code.len()) {
                cx.content().source("html.lang").language(code, 1.0);
            }
            cx.format_set("lang", lang.clone());
        }

        // temporal
        for (map, key, field) in [
            (&self.meta, "article:published_time", DateField::Published),
            (&self.meta, "article:modified_time", DateField::Modified),
            (&self.citation, "publication_date", DateField::Published),
            (&self.dublin_core, "date", DateField::Created),
            (&self.meta, "date", DateField::Published),
            (&self.meta, "last-modified", DateField::Modified),
        ] {
            if let Some(v) = get(map, key)
                && let Some((d, tz)) = parse_date(&v)
            {
                cx.temporal().source(format!("html.{key}")).content_date(field, d, tz);
            }
        }

        // rights
        if let Some(c) = get(&self.meta, "copyright").or_else(|| get(&self.dublin_core, "rights")) {
            cx.rights().source("meta.copyright").copyright(c);
        }
        if let Some(l) = &self.license {
            cx.rights().source("link.license").license(None, Some(l));
        }

        self.linked_data(cx);
        self.security(cx);
        self.format(cx);
        for (name, map) in [
            ("html_meta", &self.meta),
            ("opengraph", &self.opengraph),
            ("twitter", &self.twitter),
            ("dublin_core", &self.dublin_core),
            ("citation", &self.citation),
        ] {
            if !map.is_empty() {
                cx.metadata(name).clone_from(map);
            }
        }
    }

    fn linked_data(&self, cx: &mut Context<'_>) {
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        let mut items = Vec::new();
        for block in &self.json_ld {
            let Ok(v) = serde_json::from_str::<Value>(block.trim()) else { continue };
            let mut nodes: Vec<&Value> = match &v {
                Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            if let Some(Value::Array(graph)) = v.get("@graph") {
                nodes.extend(graph.iter());
            }
            for node in nodes.into_iter().take(50) {
                for t in all_str(node.get("@type")) {
                    *types.entry(t).or_default() += 1;
                }
                if items.len() < 10 {
                    items.push(summarise_ld(node));
                }
                // Articles, pages and products describe the page itself.
                let name = node.get("headline").or_else(|| node.get("name")).and_then(Value::as_str);
                if let Some(n) = name {
                    cx.content().source("json_ld.name").title(n);
                }
                if let Some(d) = node.get("description").and_then(Value::as_str) {
                    cx.content().source("json_ld.description").description(d);
                }
                for (key, field) in [("datePublished", DateField::Published), ("dateModified", DateField::Modified)] {
                    if let Some((d, tz)) = node.get(key).and_then(Value::as_str).and_then(parse_date) {
                        cx.temporal().source(format!("json_ld.{key}")).content_date(field, d, tz);
                    }
                }
                for a in ld_names(node.get("author")) {
                    cx.content().source("json_ld.author").author(a);
                }
            }
        }
        for (t, n) in &self.item_types {
            *types.entry(t.clone()).or_default() += n;
        }
        if !types.is_empty() {
            cx.format_set("schema_types", json!(types));
        }
        if !items.is_empty() {
            cx.metadata_set("json_ld", "items", Value::Array(items));
        }
    }

    fn security(&self, cx: &mut Context<'_>) {
        let mut s = cx.security();
        if self.inline_scripts > 0
            || !self.script_hosts.is_empty()
            || self.event_handlers > 0
            || self.javascript_urls > 0
        {
            s.active_content("javascript");
        }
        if self.iframes > 0 {
            s.active_content("iframes");
        }
        if self.event_handlers > 0 {
            s.risk("inline_event_handlers", Some(format!("{} handler attributes", self.event_handlers)));
        }
        if self.javascript_urls > 0 {
            s.risk("javascript_urls", Some(format!("{} javascript: links", self.javascript_urls)));
        }
        if self.hidden_iframes > 0 {
            s.risk("hidden_iframe", Some(format!("{} hidden iframe(s)", self.hidden_iframes)));
        }
        let own = self.canonical.as_deref().and_then(url_host);
        for f in &self.forms {
            if let Some(h) = f["action_host"].as_str()
                && own.as_deref() != Some(h)
            {
                s.risk("external_form_action", Some(format!("form posts to {h}")));
            }
        }
        if let Some(r) = &self.refresh
            && let Some(h) = r.to_ascii_lowercase().split("url=").nth(1).and_then(url_host)
            && own.as_deref() != Some(h.as_str())
        {
            s.risk("meta_refresh_redirect", Some(format!("redirects to {h}")));
        }
        let external =
            self.links_external + self.script_hosts.values().sum::<u64>() + self.iframe_hosts.values().sum::<u64>();
        s.external_references(external + self.style_hosts.values().sum::<u64>());
    }

    fn format(&self, cx: &mut Context<'_>) {
        let top = |m: &BTreeMap<String, u64>, n: usize| {
            let mut v: Vec<(&String, &u64)> = m.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            Value::Object(v.into_iter().take(n).map(|(k, n)| (k.clone(), json!(n))).collect())
        };
        let mut f = Map::new();
        if let Some(d) = &self.doctype {
            f.insert("doctype".into(), json!(d));
        }
        for (key, value) in [("generator", "generator"), ("robots", "robots"), ("viewport", "viewport")] {
            if let Some(v) = self.meta.get(value) {
                f.insert(key.into(), v.clone());
            }
        }
        if let Some(c) = &self.canonical {
            f.insert("canonical".into(), json!(c));
        }
        if !self.alternates.is_empty() {
            f.insert("alternates".into(), json!(self.alternates.iter().take(50).collect::<Vec<_>>()));
        }
        if !self.feeds.is_empty() {
            f.insert("feeds".into(), json!(self.feeds));
        }
        if let Some(m) = &self.manifest {
            f.insert("manifest".into(), json!(m));
        }
        if let Some(r) = &self.refresh {
            f.insert("refresh".into(), json!(r));
        }
        f.insert("elements".into(), json!(self.elements));
        f.insert("max_depth".into(), json!(self.max_depth));
        f.insert(
            "links".into(),
            json!({ "internal": self.links_internal, "external": self.links_external, "mailto": self.mailto }),
        );
        if !self.link_hosts.is_empty() {
            f.insert("top_link_hosts".into(), top(&self.link_hosts, 10));
        }
        f.insert("images".into(), json!({ "count": self.images, "with_alt": self.images_with_alt }));
        f.insert(
            "scripts".into(),
            json!({ "inline": self.inline_scripts, "external": self.script_hosts.values().sum::<u64>(), "hosts": top(&self.script_hosts, 10) }),
        );
        f.insert("stylesheets".into(), json!(self.stylesheets));
        if self.icons > 0 {
            f.insert("icons".into(), json!(self.icons));
        }
        if !self.forms.is_empty() || !self.form_inputs.is_empty() {
            f.insert(
                "forms".into(),
                json!({ "count": self.forms.len(), "inputs": self.form_inputs, "password_fields": self.password_fields }),
            );
        }
        if self.iframes > 0 {
            f.insert("iframes".into(), json!({ "count": self.iframes, "hosts": top(&self.iframe_hosts, 10) }));
        }
        let fmt = cx.format();
        for (k, v) in f {
            fmt.insert(k, v);
        }
    }
}

/// Repeated meta properties (`og:image`, `article:tag`) become lists.
fn insert_multi(map: &mut Map<String, Value>, key: &str, value: Value) {
    match map.get_mut(key) {
        Some(Value::Array(a)) => {
            if a.len() < 50 {
                a.push(value);
            }
        }
        Some(existing) => {
            let first = existing.take();
            *existing = Value::Array(vec![first, value]);
        }
        None => {
            map.insert(key.to_string(), value);
        }
    }
}

fn first_str(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s.as_str()),
        Value::Array(a) => a.first().and_then(Value::as_str),
        _ => None,
    }
    .filter(|s| !s.trim().is_empty())
}

fn all_str(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// `"author": "Ada"`, `{"name": "Ada"}` or a list of either.
fn ld_names(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Object(o)) => o.get("name").and_then(Value::as_str).map(str::to_string).into_iter().collect(),
        Some(Value::Array(a)) => a.iter().take(20).flat_map(|x| ld_names(Some(x))).collect(),
        _ => Vec::new(),
    }
}

/// A JSON-LD node reduced to its type and a few telling properties.
fn summarise_ld(node: &Value) -> Value {
    let mut m = Map::new();
    for key in [
        "@type",
        "name",
        "headline",
        "description",
        "datePublished",
        "dateModified",
        "url",
        "sku",
        "brand",
        "price",
        "priceCurrency",
        "ratingValue",
        "recipeYield",
        "startDate",
        "location",
    ] {
        if let Some(v) = node.get(key) {
            let v = match v {
                Value::String(s) => json!(truncate_chars(s, 300)),
                Value::Object(o) => o.get("name").cloned().unwrap_or_else(|| json!("…")),
                Value::Array(a) => json!(a.iter().take(5).filter_map(Value::as_str).collect::<Vec<_>>()),
                other => other.clone(),
            };
            m.insert(key.to_string(), v);
        }
    }
    if let Some(a) = node.get("author") {
        m.insert("author".into(), json!(ld_names(Some(a))));
    }
    if let Some(Value::Object(o)) = node.get("offers") {
        for k in ["price", "priceCurrency", "availability"] {
            if let Some(v) = o.get(k) {
                m.insert(k.to_string(), v.clone());
            }
        }
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_cap() {
        assert_eq!(depth_cut(&"<div>".repeat(10), 20), None);
        assert_eq!(depth_cut(&"<div>".repeat(30), 20), Some(100));
        // Unclosed paragraphs and list items, voids and scripts do not nest.
        let flat =
            format!("{}{}<script>{}</script>", "<p>x".repeat(1000), "<br><img src=a>".repeat(500), "<div>".repeat(900));
        assert_eq!(depth_cut(&flat, 20), None);
        assert_eq!(depth_cut(&format!("<!-- {} -->", "<div>".repeat(900)), 20), None);
        assert_eq!(depth_cut(&format!("<SCRIPT>{}</Script>{}", "<div>".repeat(900), "<div>".repeat(3)), 20), None);
        // Hostile shapes stay fast and give the right answer: unterminated
        // `<a` tags still open elements (the 21st, at byte 40, is too deep);
        // an unclosed `<script>` makes the rest raw text, which never nests.
        let start = std::time::Instant::now();
        assert_eq!(depth_cut(&"<a".repeat(200_000), 20), Some(40));
        assert_eq!(depth_cut(&"<script>".repeat(100_000), 20), None);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn charsets() {
        assert_eq!(declared_charset(b"<meta charset=\"ISO-8859-1\">").as_deref(), Some("iso-8859-1"));
        let (t, _) = decode_html(b"<meta charset=\"windows-1252\"><p>caf\xe9</p>");
        assert!(t.contains("café"));
    }

    crate::fixture_tests!("html", "xhtml");
}
