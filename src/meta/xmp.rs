//! XMP packets (RDF/XML): every property, grouped by namespace under its
//! canonical prefix (`dc`, `xmp`, `photoshop`, `Iptc4xmpCore`, `exif`,
//! `vra`, …, chosen by namespace URI, not by the prefix the file used).
//!
//! Handles the attribute and element forms of `rdf:Description`,
//! `rdf:Bag` / `rdf:Seq` (arrays), `rdf:Alt` (language alternatives:
//! a string when there is only `x-default`), nested structures
//! (`rdf:parseType="Resource"` or a nested `rdf:Description`) and
//! `rdf:resource`. Several packets in one file merge (first value wins).
//!
//! Specification: ISO 16684-1 (XMP), RDF 1.1 XML Syntax.

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use serde_json::{Map, Value, json};

use super::text_value;
use crate::plugin::{BlockDecoder, BlockKind, Context, ExtractError, TextRole};

/// Decoder for XMP packets.
pub struct Xmp;

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const XML: &str = "http://www.w3.org/XML/1998/namespace";
/// Elements kept from one packet.
const MAX_NODES: usize = 100_000;
/// Structure nesting converted to JSON; deeper values are summarised.
const MAX_DEPTH: usize = 12;
const MAX_ITEMS: usize = 200;

/// Canonical prefixes by namespace URI.
const PREFIXES: &[(&str, &str)] = &[
    ("http://purl.org/dc/elements/1.1/", "dc"),
    ("http://purl.org/dc/terms/", "dcterms"),
    ("http://ns.adobe.com/xap/1.0/", "xmp"),
    ("http://ns.adobe.com/xap/1.0/rights/", "xmpRights"),
    ("http://ns.adobe.com/xap/1.0/mm/", "xmpMM"),
    ("http://ns.adobe.com/xap/1.0/bj/", "xmpBJ"),
    ("http://ns.adobe.com/xap/1.0/t/pg/", "xmpTPg"),
    ("http://ns.adobe.com/xap/1.0/g/", "xmpG"),
    ("http://ns.adobe.com/xmp/1.0/DynamicMedia/", "xmpDM"),
    ("http://ns.adobe.com/xmp/note/", "xmpNote"),
    ("http://ns.adobe.com/xap/1.0/sType/ResourceEvent#", "stEvt"),
    ("http://ns.adobe.com/xap/1.0/sType/ResourceRef#", "stRef"),
    ("http://ns.adobe.com/photoshop/1.0/", "photoshop"),
    ("http://ns.adobe.com/camera-raw-settings/1.0/", "crs"),
    ("http://ns.adobe.com/lightroom/1.0/", "lr"),
    ("http://ns.adobe.com/illustrator/1.0/", "illustrator"),
    ("http://ns.adobe.com/pdf/1.3/", "pdf"),
    ("http://ns.adobe.com/exif/1.0/", "exif"),
    ("http://ns.adobe.com/exif/1.0/aux/", "aux"),
    ("http://cipa.jp/exif/1.0/", "exifEX"),
    ("http://ns.adobe.com/tiff/1.0/", "tiff"),
    ("http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/", "Iptc4xmpCore"),
    ("http://iptc.org/std/Iptc4xmpExt/2008-02-29/", "Iptc4xmpExt"),
    ("http://ns.useplus.org/ldf/xmp/1.0/", "plus"),
    ("http://creativecommons.org/ns#", "cc"),
    ("http://www.metadataworkinggroup.com/schemas/regions/", "mwg-rs"),
    ("http://www.metadataworkinggroup.com/schemas/keywords/", "mwg-kw"),
    ("http://ns.google.com/photos/1.0/panorama/", "GPano"),
    ("http://ns.google.com/photos/1.0/container/", "GContainer"),
    ("http://ns.google.com/photos/1.0/container/item/", "Item"),
    ("http://ns.google.com/photos/1.0/camera/", "GCamera"),
    ("http://ns.adobe.com/hdr-gain-map/1.0/", "hdrgm"),
    ("http://ns.apple.com/faceinfo/1.0/", "apple-fi"),
    ("http://ns.microsoft.com/photo/1.0/", "MicrosoftPhoto"),
    ("http://www.digikam.org/ns/1.0/", "digiKam"),
];

/// The prefix whiff uses for a namespace URI.
pub fn canonical_prefix(uri: &str, written: &str) -> String {
    if let Some((_, p)) = PREFIXES.iter().find(|(u, _)| *u == uri) {
        return (*p).to_string();
    }
    // VRA Core 4 has been published under several URIs.
    if uri.contains("vraweb.org") {
        return "vra".to_string();
    }
    if written.is_empty() { "ns".to_string() } else { written.to_string() }
}

impl BlockDecoder for Xmp {
    fn kind(&self) -> BlockKind {
        BlockKind::XMP
    }

    fn id(&self) -> &'static str {
        "meta.xmp"
    }

    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = crate::text::decode(data).text;
        let tree = Tree::parse(&text).map_err(ExtractError::malformed)?;
        let props = tree.properties();
        if props.is_empty() {
            return Err(ExtractError::malformed("no rdf:Description properties"));
        }
        emit_texts(&props, cx);
        let target = cx.metadata("xmp");
        for (prefix, fields) in props {
            let Value::Object(fields) = fields else { continue };
            let group = target.entry(prefix).or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(g) = group {
                for (k, v) in fields {
                    g.entry(k).or_insert(v);
                }
            }
        }
        Ok(())
    }
}

crate::register_block_decoder!(Xmp);

/// Hand descriptive values to the text analyzers.
fn emit_texts(props: &Map<String, Value>, cx: &mut Context<'_>) {
    let get = |p: &str, k: &str| props.get(p).and_then(|g| g.get(k));
    for (p, k, role) in [
        ("dc", "title", TextRole::Title),
        ("photoshop", "Headline", TextRole::Title),
        ("dc", "description", TextRole::Caption),
        ("Iptc4xmpCore", "AltTextAccessibility", TextRole::Caption),
        ("Iptc4xmpCore", "ExtDescrAccessibility", TextRole::Caption),
    ] {
        if let Some(t) = get(p, k).and_then(lang_default) {
            cx.emit_text(role, &t);
        }
    }
    if let Some(Value::Array(subjects)) = get("dc", "subject") {
        let words: Vec<&str> = subjects.iter().filter_map(Value::as_str).collect();
        cx.emit_text(TextRole::Metadata, &words.join(", "));
    }
}

/// The `x-default` (or first) text of a language alternative, or a plain string.
pub fn lang_default(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(m) => {
            m.get("x-default").or_else(|| m.values().next()).and_then(Value::as_str).map(str::to_string)
        }
        Value::Array(a) => a.first().and_then(lang_default),
        _ => None,
    }
    .filter(|s| !s.trim().is_empty())
}

#[derive(Default)]
struct Node {
    ns: String,
    local: String,
    prefix: String,
    attrs: Vec<(String, String, String, String)>,
    children: Vec<usize>,
    text: String,
}

#[derive(Default)]
struct Tree {
    nodes: Vec<Node>,
    roots: Vec<usize>,
}

impl Tree {
    fn parse(text: &str) -> Result<Self, String> {
        let mut reader = quick_xml::NsReader::from_str(text);
        let cfg = reader.config_mut();
        cfg.check_end_names = false;
        cfg.expand_empty_elements = true;
        let mut t = Tree::default();
        let mut stack: Vec<usize> = Vec::new();
        loop {
            let event = match reader.read_event() {
                Ok(e) => e,
                Err(e) if t.nodes.is_empty() => return Err(e.to_string()),
                Err(_) => break,
            };
            match event {
                Event::Start(e) => {
                    if t.nodes.len() >= MAX_NODES {
                        break;
                    }
                    let (ns, local) = reader.resolver().resolve_element(e.name());
                    let qname = e.name().as_ref().to_string();
                    let mut node = Node {
                        ns: bound(&ns),
                        local: local.as_ref().to_string(),
                        prefix: qname.split_once(':').map_or("", |(p, _)| p).to_string(),
                        ..Node::default()
                    };
                    for a in e.attributes().flatten().take(256) {
                        let key = a.key.as_ref().to_string();
                        if key == "xmlns" || key.starts_with("xmlns:") {
                            continue;
                        }
                        let (ans, alocal) = reader.resolver().resolve_attribute(a.key);
                        let value = a
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(std::borrow::Cow::into_owned)
                            .unwrap_or_default();
                        let aprefix = key.split_once(':').map_or("", |(p, _)| p).to_string();
                        node.attrs.push((bound(&ans), alocal.as_ref().to_string(), aprefix, value));
                    }
                    let id = t.nodes.len();
                    t.nodes.push(node);
                    match stack.last() {
                        Some(&p) => t.nodes[p].children.push(id),
                        None => t.roots.push(id),
                    }
                    stack.push(id);
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::Text(x) => t.push_text(&stack, &x.xml10_content()),
                Event::CData(x) => t.push_text(&stack, &x.xml10_content()),
                Event::GeneralRef(r) => {
                    let s = match &*r {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    };
                    let s = if r.is_char_ref() {
                        r.resolve_char_ref().ok().flatten().map(String::from).unwrap_or_default()
                    } else {
                        s.to_string()
                    };
                    t.push_text(&stack, &s);
                }
                Event::Eof => break,
                _ => {}
            }
        }
        Ok(t)
    }

    fn push_text(&mut self, stack: &[usize], s: &str) {
        if let Some(&id) = stack.last()
            && self.nodes[id].text.len() < super::MAX_STRING
        {
            self.nodes[id].text.push_str(s);
        }
    }

    fn is(&self, id: usize, ns: &str, local: &str) -> bool {
        self.nodes[id].ns == ns && self.nodes[id].local == local
    }

    fn attr(&self, id: usize, ns: &str, local: &str) -> Option<&str> {
        self.nodes[id].attrs.iter().find(|(n, l, ..)| n == ns && l == local).map(|(.., v)| v.as_str())
    }

    /// Every `rdf:RDF/rdf:Description` property, grouped by prefix.
    fn properties(&self) -> Map<String, Value> {
        let mut out = Map::new();
        // Find rdf:RDF elements without recursion.
        let mut stack: Vec<usize> = self.roots.clone();
        let mut rdfs = Vec::new();
        while let Some(id) = stack.pop() {
            if self.is(id, RDF, "RDF") {
                rdfs.push(id);
            } else {
                stack.extend(self.nodes[id].children.iter().copied());
            }
        }
        rdfs.sort_unstable();
        for rdf in rdfs {
            for &d in &self.nodes[rdf].children {
                if self.is(d, RDF, "Description") || !self.nodes[d].ns.is_empty() {
                    self.description_into(d, &mut out, 0);
                }
            }
        }
        out
    }

    /// Add a description's properties (attributes and child elements) to `out`.
    fn description_into(&self, id: usize, out: &mut Map<String, Value>, depth: usize) {
        for (ns, local, prefix, value) in &self.nodes[id].attrs {
            if ns == RDF || ns == XML || ns.is_empty() {
                continue;
            }
            group(out, &canonical_prefix(ns, prefix)).entry(local.clone()).or_insert_with(|| text_value(value));
        }
        for &c in &self.nodes[id].children {
            let n = &self.nodes[c];
            if n.ns == RDF || n.ns.is_empty() {
                continue;
            }
            let v = self.value(c, depth + 1);
            group(out, &canonical_prefix(&n.ns, &n.prefix)).entry(n.local.clone()).or_insert(v);
        }
    }

    /// The value of a property (or `rdf:li`) element.
    fn value(&self, id: usize, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            return json!("…");
        }
        if let Some(r) = self.attr(id, RDF, "resource") {
            return text_value(r);
        }
        let kids = &self.nodes[id].children;
        if let Some(&c) = kids.first() {
            if self.is(c, RDF, "Bag") || self.is(c, RDF, "Seq") {
                let items: Vec<Value> =
                    self.nodes[c].children.iter().take(MAX_ITEMS).map(|&li| self.value(li, depth + 1)).collect();
                return Value::Array(items);
            }
            if self.is(c, RDF, "Alt") {
                let mut alt = Map::new();
                for &li in self.nodes[c].children.iter().take(MAX_ITEMS) {
                    let lang = self.attr(li, XML, "lang").unwrap_or("x-default").to_string();
                    alt.entry(lang).or_insert_with(|| self.value(li, depth + 1));
                }
                return match (alt.len(), alt.get("x-default")) {
                    (1, Some(v)) => v.clone(),
                    _ => Value::Object(alt),
                };
            }
            if self.is(c, RDF, "Description") {
                return self.structure(c, depth);
            }
        }
        if self.attr(id, RDF, "parseType") == Some("Resource") {
            return self.structure(id, depth);
        }
        let has_fields = self.nodes[id].attrs.iter().any(|(ns, ..)| ns != RDF && ns != XML && !ns.is_empty());
        if has_fields && kids.is_empty() {
            return self.structure(id, depth);
        }
        if !kids.is_empty() {
            return self.structure(id, depth);
        }
        text_value(&self.nodes[id].text)
    }

    /// A structure: its fields by local name.
    fn structure(&self, id: usize, depth: usize) -> Value {
        let mut m = Map::new();
        for (ns, local, _, value) in &self.nodes[id].attrs {
            if ns != RDF && ns != XML && !ns.is_empty() {
                m.entry(local.clone()).or_insert_with(|| text_value(value));
            }
        }
        for &c in self.nodes[id].children.iter().take(MAX_ITEMS) {
            if self.nodes[c].ns != RDF {
                let v = self.value(c, depth + 1);
                m.entry(self.nodes[c].local.clone()).or_insert(v);
            }
        }
        Value::Object(m)
    }
}

fn bound(r: &ResolveResult<'_>) -> String {
    match r {
        ResolveResult::Bound(ns) => ns.0.to_string(),
        _ => String::new(),
    }
}

fn group<'m>(out: &'m mut Map<String, Value>, prefix: &str) -> &'m mut Map<String, Value> {
    let v = out.entry(prefix.to_string()).or_insert_with(|| Value::Object(Map::new()));
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    match v {
        Value::Object(m) => m,
        _ => unreachable!("just made an object"),
    }
}

/// Parse a packet into `metadata.xmp` form (for other decoders and tests).
pub fn parse(text: &str) -> Result<Map<String, Value>, String> {
    Ok(Tree::parse(text)?.properties())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:d="http://purl.org/dc/elements/1.1/"
     xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"
     xmlns:xmpRights="http://ns.adobe.com/xap/1.0/rights/" xmlns:vra="http://www.vraweb.org/vracore4.htm"
     xmp:CreateDate="2026-09-14T17:03:22+02:00" xmpRights:Marked="True">
   <d:title><rdf:Alt><rdf:li xml:lang="x-default">Harbour at dusk</rdf:li><rdf:li xml:lang="fr">Port au crépuscule</rdf:li></rdf:Alt></d:title>
   <d:creator><rdf:Seq><rdf:li>Ada Example</rdf:li></rdf:Seq></d:creator>
   <d:subject><rdf:Bag><rdf:li>harbour</rdf:li><rdf:li>boats</rdf:li></rdf:Bag></d:subject>
   <d:rights><rdf:Alt><rdf:li xml:lang="x-default">© 2026 Ada Example</rdf:li></rdf:Alt></d:rights>
   <Iptc4xmpCore:CreatorContactInfo rdf:parseType="Resource"><Iptc4xmpCore:CiAdrCity>Marseille</Iptc4xmpCore:CiAdrCity></Iptc4xmpCore:CreatorContactInfo>
   <xmpRights:WebStatement rdf:resource="https://example.org/licence"/>
   <vra:titleSet>Port of Marseille</vra:titleSet>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn rdf_forms() {
        let p = parse(PACKET).unwrap();
        assert_eq!(p["dc"]["title"], json!({ "x-default": "Harbour at dusk", "fr": "Port au crépuscule" }));
        assert_eq!(p["dc"]["creator"], json!(["Ada Example"]));
        assert_eq!(p["dc"]["subject"], json!(["harbour", "boats"]));
        assert_eq!(p["dc"]["rights"], json!("© 2026 Ada Example"));
        assert_eq!(p["xmp"]["CreateDate"], json!("2026-09-14T17:03:22+02:00"));
        assert_eq!(p["xmpRights"]["Marked"], json!("True"));
        assert_eq!(p["xmpRights"]["WebStatement"], json!("https://example.org/licence"));
        assert_eq!(p["Iptc4xmpCore"]["CreatorContactInfo"]["CiAdrCity"], json!("Marseille"));
        assert_eq!(p["vra"]["titleSet"], json!("Port of Marseille"));
        assert_eq!(lang_default(&p["dc"]["title"]).as_deref(), Some("Harbour at dusk"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "10,000 nested elements: 3 min under Miri")]
    fn hostile_input() {
        assert!(parse("not xml at all").map_or(true, |p| p.is_empty()));
        let deep = format!(
            r#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:a="urn:a">{}</rdf:Description></rdf:RDF>"#,
            "<a:x>".repeat(10_000)
        );
        let p = parse(&deep).unwrap();
        assert!(p.contains_key("a"));
    }
}
