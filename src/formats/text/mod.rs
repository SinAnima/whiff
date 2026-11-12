//! `text` extractors (feature `common`): plain text, logs, diffs, NFO and
//! hosts files, Markdown, lightweight markup, HTML, XML, feeds, calendars
//! and contacts.

pub(crate) mod calendar;
pub(crate) mod contact;
pub(crate) mod contentline;
pub(crate) mod dialects;
pub(crate) mod feed;
pub(crate) mod html;
pub(crate) mod lightmarkup;
pub(crate) mod markdown;
pub(crate) mod plain;
pub(crate) mod special;
pub(crate) mod xml;

pub(crate) use super::archive::unix_time;

/// The root element name of an XML document, skipping the BOM, XML
/// declaration, comments, processing instructions and DOCTYPE.
pub(crate) fn xml_root(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&head[..head.len().min(8192)]);
    let mut s = text.trim_start_matches('\u{feff}').trim_start();
    loop {
        if let Some(rest) = s.strip_prefix("<?") {
            s = rest.split_once("?>")?.1.trim_start();
        } else if let Some(rest) = s.strip_prefix("<!--") {
            s = rest.split_once("-->")?.1.trim_start();
        } else if s.get(..9).is_some_and(|p| p.eq_ignore_ascii_case("<!doctype")) {
            s = s.split_once('>')?.1.trim_start();
        } else {
            break;
        }
    }
    let rest = s.strip_prefix('<')?;
    let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || matches!(c, ':' | '_' | '-' | '.')).collect();
    (!name.is_empty() && name.chars().next().is_some_and(char::is_alphabetic)).then_some(name)
}

/// Decode XML: BOM first, then the `encoding` of the XML declaration, then
/// detection.
pub(crate) fn decode_xml(bytes: &[u8]) -> String {
    if encoding_rs::Encoding::for_bom(bytes).is_none() {
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
        if let Some(decl) = head.strip_prefix("<?xml").and_then(|r| r.split("?>").next())
            && let Some(at) = decl.find("encoding=")
        {
            let label: String = decl[at + 9..]
                .trim_start_matches(['"', '\''])
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
                .collect();
            if let Some(enc) = encoding_rs::Encoding::for_label(label.as_bytes())
                && enc != encoding_rs::UTF_8
            {
                return enc.decode_without_bom_handling(bytes).0.into_owned();
            }
        }
    }
    crate::plugin::decode_text(bytes).text
}

/// The text an entity or character reference stands for (`&amp;`, `&#233;`).
pub(crate) fn entity_text(r: &quick_xml::events::BytesRef<'_>) -> Option<String> {
    if r.is_char_ref() {
        return r.resolve_char_ref().ok().flatten().map(String::from);
    }
    let s = match &**r {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        _ => return None,
    };
    Some(s.to_string())
}

/// Local part of a qualified name: `dc:creator` → `creator`.
pub(crate) fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

/// A small element tree for documents that are read by structure (feeds,
/// sitemaps, OPML). Built iteratively; capped in size.
#[derive(Debug, Default)]
pub(crate) struct XmlTree {
    nodes: Vec<XmlNode>,
}

#[derive(Debug, Default)]
pub(crate) struct XmlNode {
    /// Qualified name as written (`dc:creator`).
    pub(crate) qname: String,
    /// Local name (`creator`).
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) text: String,
    children: Vec<usize>,
}

/// Elements kept in an [`XmlTree`].
const MAX_TREE_NODES: usize = 200_000;
/// Text kept per element.
const MAX_NODE_TEXT: usize = 64 * 1024;

impl XmlTree {
    /// Parse `text`; errors after the root element opened keep what was read.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        use quick_xml::events::Event;
        let mut reader = quick_xml::Reader::from_str(text);
        let cfg = reader.config_mut();
        cfg.check_end_names = false;
        cfg.expand_empty_elements = true;
        let mut tree = Self::default();
        let mut stack: Vec<usize> = Vec::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    if tree.nodes.len() >= MAX_TREE_NODES {
                        break;
                    }
                    let qname = e.name().as_ref().to_string();
                    let attrs = e
                        .attributes()
                        .flatten()
                        .take(64)
                        .map(|a| {
                            let k = a.key.as_ref().to_string();
                            let v = a
                                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map(std::borrow::Cow::into_owned)
                                .unwrap_or_default();
                            (k, v)
                        })
                        .collect();
                    let id = tree.nodes.len();
                    tree.nodes.push(XmlNode { name: local(&qname), qname, attrs, ..XmlNode::default() });
                    if let Some(&parent) = stack.last() {
                        tree.nodes[parent].children.push(id);
                    }
                    stack.push(id);
                }
                Ok(Event::End(_)) => {
                    stack.pop();
                }
                Ok(Event::Text(t)) => tree.push_text(&stack, &t.xml10_content()),
                Ok(Event::CData(t)) => tree.push_text(&stack, &t.xml10_content()),
                Ok(Event::GeneralRef(r)) => {
                    if let Some(s) = entity_text(&r) {
                        tree.push_text(&stack, &s);
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) if tree.nodes.is_empty() => return Err(e.to_string()),
                Err(_) => break,
            }
        }
        if tree.nodes.is_empty() { Err("no root element".into()) } else { Ok(tree) }
    }

    fn push_text(&mut self, stack: &[usize], t: &str) {
        if let Some(&id) = stack.last() {
            let n = &mut self.nodes[id];
            if n.text.len() < MAX_NODE_TEXT {
                n.text.push_str(t);
            }
        }
    }

    pub(crate) fn root(&self) -> &XmlNode {
        &self.nodes[0]
    }

    /// Child elements of `node` with local name `name` (any name for `*`).
    pub(crate) fn children<'t>(&'t self, node: &'t XmlNode, name: &'t str) -> impl Iterator<Item = &'t XmlNode> + 't {
        node.children.iter().map(|&i| &self.nodes[i]).filter(move |c| name == "*" || c.name.eq_ignore_ascii_case(name))
    }

    /// The first child named `name`.
    pub(crate) fn child<'t>(&'t self, node: &'t XmlNode, name: &'t str) -> Option<&'t XmlNode> {
        self.children(node, name).next()
    }

    /// Trimmed text of the first child named `name`, if not empty.
    pub(crate) fn text<'t>(&'t self, node: &'t XmlNode, name: &'t str) -> Option<&'t str> {
        self.child(node, name).map(|c| c.text.trim()).filter(|t| !t.is_empty())
    }
}

impl XmlNode {
    /// Attribute by qualified or local name.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name || k.rsplit(':').next() == Some(name))
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

/// Lowercase host of an absolute (`https://host/…`) or protocol-relative
/// (`//host/…`) URL; `None` for relative URLs.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let lower = url.trim().to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("//") {
        r
    } else {
        let (scheme, r) = lower.split_once("://")?;
        if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
            return None;
        }
        r
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host =
        if host.starts_with('[') { host.split(']').next()?.trim_start_matches('[') } else { host.split(':').next()? };
    (!host.is_empty()).then(|| host.to_string())
}

/// The text of the first `<tag …>` start tag in `head` (up to `>`), for
/// namespace checks.
pub(crate) fn start_tag(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(&head[..head.len().min(8192)]);
    let start = text.find(&format!("<{name}"))?;
    let end = text[start..].find('>')? + start;
    Some(text[start..=end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots() {
        assert_eq!(xml_root(b"<?xml version=\"1.0\"?>\n<!-- c --><rss version=\"2.0\">").as_deref(), Some("rss"));
        assert_eq!(xml_root(b"\xef\xbb\xbf<!DOCTYPE html><html>").as_deref(), Some("html"));
        assert_eq!(xml_root(b"<svg:svg xmlns:svg=\"x\">").as_deref(), Some("svg:svg"));
        assert_eq!(xml_root(b"plain text"), None);
        assert_eq!(xml_root(b"<?xml unterminated"), None);
        let t = XmlTree::parse("<a x=\"1\"><b>one &amp; two</b><b><![CDATA[three]]></b><c/></a>").unwrap();
        let root = t.root();
        assert_eq!(root.attr("x"), Some("1"));
        assert_eq!(t.children(root, "b").map(|b| b.text.as_str()).collect::<Vec<_>>(), ["one & two", "three"]);
        assert!(t.child(root, "c").is_some());
        assert!(XmlTree::parse("not xml").is_err());
        assert_eq!(
            decode_xml(b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>caf\xe9</a>"),
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>café</a>"
        );
        assert_eq!(url_host("https://User:pw@Example.org:8080/a?b").as_deref(), Some("example.org"));
        assert_eq!(url_host("//cdn.example.com/x.js").as_deref(), Some("cdn.example.com"));
        assert_eq!(url_host("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(url_host("/relative/path"), None);
        assert_eq!(url_host("mailto:a@b.c"), None);
        assert_eq!(start_tag(b"<feed xmlns=\"http://www.w3.org/2005/Atom\"><title>", "feed").unwrap().len(), 42);
    }
}
