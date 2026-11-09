//! EPUB 2 and 3 (OCF container, OPF package, NCX / navigation document).
//!
//! Specification: EPUB 3.3 (W3C), OPF 2.0.1.

use std::collections::HashMap;

use serde_json::json;

use super::super::xml::{Ev, Flow, walk};
use super::Book;
use crate::plugin::{Context, ExtractError, Source, Zip, truncate_chars};

const MAX_ENTRIES: usize = 50_000;
const MAX_DOCS: usize = 2_000;

struct Item {
    href: String,
    media: String,
    properties: String,
}

#[allow(clippy::too_many_lines)] // container, package, manifest, TOC, text
pub(super) fn extract(src: &mut dyn Source, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let max = cx.parse_limit();
    book.format.insert("entries".into(), json!(zip.entries.len()));
    drm(&zip, src, cx, book)?;
    let container = zip
        .read_text(src, "META-INF/container.xml", cx, 1 << 20)
        .transpose()?
        .ok_or_else(|| ExtractError::malformed("no META-INF/container.xml"))?;
    let mut rootfiles = Vec::new();
    walk(&container, cx, |ev| {
        if let Ev::Open(t, _) = ev
            && t.name == "rootfile"
            && let Some(p) = t.attr("full-path")
        {
            let media = t.attr("media-type").unwrap_or("application/oebps-package+xml");
            if media == "application/oebps-package+xml" {
                rootfiles.push(p.to_string());
            }
        }
        Flow::Continue
    })?;
    let opf_path = rootfiles.first().cloned().ok_or_else(|| ExtractError::malformed("no OPF rootfile"))?;
    if rootfiles.len() > 1 {
        book.format.insert("renditions".into(), json!(rootfiles.len()));
    }
    let opf = zip
        .read_text(src, &opf_path, cx, 16 << 20)
        .transpose()?
        .ok_or_else(|| ExtractError::malformed(format!("{opf_path} missing")))?;
    let base = opf_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
    let pkg = package(&opf, cx, book)?;
    let resolve = |href: &str| normalise(&format!("{base}{}", percent_decode(href.split('#').next().unwrap_or(href))));

    // Manifest summary.
    let mut media: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut scripted = false;
    let mut remote = false;
    for item in pkg.manifest.values() {
        let kind = match item.media.as_str() {
            "application/xhtml+xml" | "text/html" => "documents",
            m if m.starts_with("image/") => "images",
            m if m.starts_with("font/") || m.contains("font") => "fonts",
            "text/css" => "stylesheets",
            m if m.starts_with("audio/") || m.starts_with("video/") => "media",
            "application/javascript" | "text/javascript" | "application/ecmascript" => {
                scripted = true;
                "scripts"
            }
            _ => "other",
        };
        *media.entry(kind.into()).or_default() += 1;
        scripted |= item.properties.split_whitespace().any(|p| p == "scripted");
        remote |= item.properties.split_whitespace().any(|p| p == "remote-resources");
    }
    book.format.insert("manifest".into(), json!(media));
    book.format.insert("spine_items".into(), json!(pkg.spine.len()));
    if scripted {
        cx.security().active_content("scripts");
    }
    if remote {
        book.format.insert("remote_resources".into(), json!(true));
    }

    // Cover: EPUB 3 `cover-image`, else EPUB 2 `<meta name="cover">`.
    let cover = pkg
        .manifest
        .values()
        .find(|i| i.properties.split_whitespace().any(|p| p == "cover-image"))
        .or_else(|| pkg.cover_id.as_ref().and_then(|id| pkg.manifest.get(id)));
    if let Some(c) = cover {
        let path = resolve(&c.href);
        let size = zip.find(&path).map(|e| e.size);
        book.cover = Some(json!({ "path": path, "media_type": c.media, "size_bytes": size }));
    }

    // Table of contents: the EPUB 3 nav document, else the NCX.
    let nav = pkg.manifest.values().find(|i| i.properties.split_whitespace().any(|p| p == "nav"));
    let ncx = pkg
        .toc_id
        .as_ref()
        .and_then(|id| pkg.manifest.get(id))
        .or_else(|| pkg.manifest.values().find(|i| i.media == "application/x-dtbncx+xml"));
    if let Some(n) = nav
        && let Some(Ok(xml)) = zip.read_text(src, &resolve(&n.href), cx, 8 << 20)
    {
        book.toc = nav_toc(&xml);
        book.format.insert("toc_source".into(), json!("nav"));
    }
    if book.toc.is_empty()
        && let Some(n) = ncx
        && let Some(Ok(xml)) = zip.read_text(src, &resolve(&n.href), cx, 8 << 20)
    {
        book.toc = ncx_toc(&xml, cx);
        book.format.insert("toc_source".into(), json!("ncx"));
    }

    // Reading-order text.
    if book.drm.is_none() {
        let budget = cx.options().limits.max_text_bytes;
        let mut headings = Vec::new();
        for (i, idref) in pkg.spine.iter().enumerate() {
            if i >= MAX_DOCS {
                break;
            }
            cx.checkpoint()?;
            let Some(item) = pkg.manifest.get(idref) else { continue };
            if !matches!(item.media.as_str(), "application/xhtml+xml" | "text/html") {
                continue;
            }
            let path = resolve(&item.href);
            let Some(Ok(html)) = zip.read_text(src, &path, cx, max.min(16 << 20)) else { continue };
            if !scripted && html.contains("<script") {
                scripted = true;
                cx.security().active_content("scripts");
            }
            let (text, h) = crate::plugin::html_text(&html, budget);
            if headings.len() < 2000 {
                headings.extend(h);
            }
            if !book.add_text(&text, budget) {
                break;
            }
        }
        if book.toc.is_empty() {
            book.toc = headings.into_iter().filter(|(l, _)| *l <= 3).take(crate::plugin::MAX_OUTLINE).collect();
        }
    }
    Ok(())
}

/// A package file on its own (an OEB 1.x / EPUB `.opf` outside its book):
/// its metadata, and the manifest and spine sizes.
pub(super) fn standalone_opf(opf: &str, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    // OEB 1.x capitalises the Dublin Core elements (`dc:Title`).
    let mut lowered = opf.to_string();
    for name in [
        "Title",
        "Creator",
        "Subject",
        "Description",
        "Publisher",
        "Contributor",
        "Date",
        "Type",
        "Format",
        "Identifier",
        "Source",
        "Language",
        "Relation",
        "Coverage",
        "Rights",
    ] {
        let lower = name.to_ascii_lowercase();
        lowered = lowered
            .replace(&format!("<dc:{name}"), &format!("<dc:{lower}"))
            .replace(&format!("</dc:{name}>"), &format!("</dc:{lower}>"));
    }
    let opf = lowered.as_str();
    let pkg = package(opf, cx, book)?;
    cx.format_set("manifest_items", pkg.manifest.len());
    cx.format_set("spine_items", pkg.spine.len());
    if opf.contains("http://openebook.org/namespaces/oeb-package/1.0/") || opf.contains("OEB 1.") {
        cx.format_set("oeb_version", "1.x");
    }
    Ok(())
}

/// A DAISY / EPUB 2 navigation control file (`.ncx`) on its own: its
/// title, authors and table of contents.
pub(super) fn standalone_ncx(xml: &str, cx: &mut Context<'_>, book: &mut Book) {
    book.toc = ncx_toc(xml, cx);
    let between = |open: &str, close: &str| -> Option<String> {
        let a = xml.find(open)? + open.len();
        let b = xml[a..].find(close)? + a;
        let inner = &xml[a..b];
        let t = inner.find("<text>").map_or(inner, |p| &inner[p + 6..]);
        Some(t.split('<').next().unwrap_or("").trim().to_string()).filter(|t| !t.is_empty())
    };
    book.title = book.title.take().or_else(|| between("<docTitle>", "</docTitle>"));
    if let Some(a) = between("<docAuthor>", "</docAuthor>") {
        book.creators.push((a, "aut".into()));
    }
    for (key, name) in [("dtb:uid", "uid"), ("dtb:depth", "depth"), ("dtb:totalPageCount", "page_count")] {
        let needle = format!("name=\"{key}\" content=\"");
        if let Some(p) = xml.find(&needle) {
            let v = &xml[p + needle.len()..];
            cx.format_set(name, v.split('"').next().unwrap_or(""));
        }
    }
    cx.format_set("nav_points", xml.matches("<navPoint").count());
}

/// An open metadata element: (name, id or refines target, text, role / scheme, property).
type OpenMeta = (String, Option<String>, String, Option<String>, Option<String>);

struct Package {
    manifest: HashMap<String, Item>,
    spine: Vec<String>,
    toc_id: Option<String>,
    cover_id: Option<String>,
}

/// The OPF: metadata into `book`, plus manifest and spine.
#[allow(clippy::too_many_lines)] // one pass over the OPF
fn package(opf: &str, cx: &Context<'_>, book: &mut Book) -> Result<Package, ExtractError> {
    let mut pkg = Package { manifest: HashMap::new(), spine: Vec::new(), toc_id: None, cover_id: None };
    let mut in_meta = false;
    let mut open: Option<OpenMeta> = None;
    let mut entries: Vec<(String, Option<String>, String, Option<String>)> = Vec::new(); // (name, id, text, attr)
    let mut refines: Vec<(String, String, String)> = Vec::new(); // (target id, property, value)
    let mut epub2_meta: Vec<(String, String)> = Vec::new();
    walk(opf, cx, |ev| {
        match ev {
            Ev::Open(t, empty) => match t.name.as_str() {
                "package" => {
                    if let Some(v) = t.attr("version") {
                        book.format.insert("epub_version".into(), json!(v));
                    }
                }
                "metadata" => in_meta = true,
                "item" => {
                    if let (Some(id), Some(href)) = (t.attr("id"), t.attr("href"))
                        && pkg.manifest.len() < 50_000
                    {
                        pkg.manifest.insert(
                            id.to_string(),
                            Item {
                                href: href.to_string(),
                                media: t.attr("media-type").unwrap_or("").to_string(),
                                properties: t.attr("properties").unwrap_or("").to_string(),
                            },
                        );
                    }
                }
                "spine" => {
                    pkg.toc_id = t.attr("toc").map(str::to_string);
                    if let Some(d) = t.attr("page-progression-direction") {
                        book.format.insert("page_progression".into(), json!(d));
                    }
                }
                "itemref" => {
                    if let Some(id) = t.attr("idref")
                        && t.attr("linear") != Some("no")
                        && pkg.spine.len() < 50_000
                    {
                        pkg.spine.push(id.to_string());
                    }
                }
                "meta" if in_meta => {
                    if let (Some(name), Some(content)) = (t.attr("name"), t.attr("content")) {
                        epub2_meta.push((name.to_string(), content.to_string()));
                    } else if !empty {
                        open = Some((
                            "meta".into(),
                            t.attr("refines").map(|r| r.trim_start_matches('#').to_string()),
                            String::new(),
                            t.attr("scheme").map(str::to_string),
                            t.attr("property").map(str::to_string),
                        ));
                    }
                }
                name if in_meta && !empty => {
                    let attr = t
                        .qattr("opf:role")
                        .or_else(|| t.qattr("opf:scheme"))
                        .or_else(|| t.attr("role"))
                        .or_else(|| t.attr("scheme"));
                    open = Some((
                        name.to_string(),
                        t.attr("id").map(str::to_string),
                        String::new(),
                        attr.map(str::to_string),
                        None,
                    ));
                }
                _ => {}
            },
            Ev::Text(s) => {
                if let Some(o) = open.as_mut()
                    && o.2.len() < 64 * 1024
                {
                    o.2.push_str(s);
                }
            }
            Ev::Close(name) => {
                if name == "metadata" {
                    in_meta = false;
                }
                if open.as_ref().is_some_and(|o| o.0 == name)
                    && let Some((n, id, text, attr, prop)) = open.take()
                {
                    let text = text.trim().to_string();
                    if n == "meta" {
                        if let (Some(target), Some(p)) = (id, prop.clone()) {
                            refines.push((target, p, text));
                        } else if let Some(p) = prop {
                            epub2_meta.push((p, text));
                        }
                    } else if entries.len() < 2000 {
                        entries.push((n, id, text, attr));
                    }
                }
            }
        }
        Flow::Continue
    })?;
    let refinement = |id: &Option<String>, prop: &str| -> Option<String> {
        let id = id.as_ref()?;
        refines.iter().find(|(t, p, _)| t == id && p == prop).map(|(_, _, v)| v.clone())
    };
    let mut collections: Vec<(String, Option<String>)> = Vec::new();
    for (name, id, text, attr) in &entries {
        if text.is_empty() {
            continue;
        }
        match name.as_str() {
            "title" => {
                let kind = refinement(id, "title-type");
                if book.title.is_none() || kind.as_deref() == Some("main") {
                    book.title = Some(truncate_chars(text, 500));
                }
            }
            "creator" | "contributor" => {
                let role = attr
                    .clone()
                    .or_else(|| refinement(id, "role"))
                    .unwrap_or_else(|| if name == "creator" { "aut".into() } else { "ctb".into() });
                book.creator(text, &role);
            }
            "language" if book.language.is_none() => book.language = Some(text.clone()),
            "identifier" => {
                let scheme = attr.clone().or_else(|| refinement(id, "identifier-type")).unwrap_or_default();
                book.identifier(&scheme, text);
            }
            "publisher" if book.publisher.is_none() => book.publisher = Some(truncate_chars(text, 300)),
            "date" if book.published.is_none() => book.published = Some(text.clone()),
            "subject" if book.subjects.len() < 100 => book.subjects.push(truncate_chars(text, 200)),
            "rights" if book.rights.is_none() => book.rights = Some(truncate_chars(text, 1000)),
            "description" if book.description.is_none() => book.description = Some(truncate_chars(text, 10_000)),
            "source" => {
                book.format.insert("source".into(), json!(truncate_chars(text, 300)));
            }
            _ => {}
        }
    }
    // EPUB 3 collections (`<meta property="belongs-to-collection">`, refined
    // by `group-position`) arrive with the EPUB 2 `<meta name content>` pairs.
    for (k, v) in &epub2_meta {
        match k.as_str() {
            "cover" => pkg.cover_id = Some(v.clone()),
            "calibre:series" | "belongs-to-collection" => collections.push((v.clone(), None)),
            "calibre:series_index" => {
                if let Some(last) = collections.last_mut() {
                    last.1 = Some(v.clone());
                }
            }
            "dcterms:modified" => book.modified = Some(v.clone()),
            _ => {}
        }
    }
    if let Some(pos) = refines.iter().find(|(_, p, _)| p == "group-position").map(|(_, _, v)| v.clone())
        && let Some(first) = collections.first_mut()
        && first.1.is_none()
    {
        first.1 = Some(pos);
    }
    book.series = collections.into_iter().next();
    Ok(pkg)
}

/// DRM and font obfuscation (`META-INF/encryption.xml`, `rights.xml`, LCP, FairPlay).
fn drm(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    if zip.find("META-INF/license.lcpl").is_some() {
        book.drm = Some("readium_lcp".into());
    } else if zip.find("META-INF/rights.xml").is_some() {
        book.drm = Some("adobe_adept".into());
    } else if zip.find("META-INF/sinf.xml").is_some() {
        book.drm = Some("apple_fairplay".into());
    }
    let Some(Ok(xml)) = zip.read_text(src, "META-INF/encryption.xml", cx, 4 << 20) else { return Ok(()) };
    let (mut fonts, mut other) = (0u64, 0u64);
    walk(&xml, cx, |ev| {
        if let Ev::Open(t, _) = ev
            && t.name == "EncryptionMethod"
        {
            match t.attr("Algorithm") {
                Some("http://www.idpf.org/2008/embedding" | "http://ns.adobe.com/pdf/enc#RC") => fonts += 1,
                _ => other += 1,
            }
        }
        Flow::Continue
    })?;
    if fonts > 0 {
        book.format.insert("obfuscated_fonts".into(), json!(fonts));
    }
    if other > 0 {
        book.format.insert("encrypted_resources".into(), json!(other));
        if book.drm.is_none() {
            book.drm = Some("unknown".into());
        }
    }
    Ok(())
}

/// The `toc` `<nav>` of an EPUB 3 navigation document: nested `<ol>` levels.
fn nav_toc(xml: &str) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    let mut in_toc = false;
    let mut ol_depth = 0u8;
    let mut label: Option<String> = None;
    let mut rest = xml;
    // A lenient scan (navigation documents often carry HTML entities).
    while let Some(lt) = rest.find('<') {
        let text = &rest[..lt];
        if let Some(l) = label.as_mut() {
            l.push_str(&crate::plugin::decode_entities(text));
        }
        rest = &rest[lt..];
        let end = rest.find('>').map_or(rest.len(), |e| e + 1);
        // An unterminated tag runs to the end (`rest` starts with the 1-byte `<`).
        let tag = rest.get(1..end.saturating_sub(1)).filter(|_| rest[..end].ends_with('>')).unwrap_or(&rest[1..]);
        rest = &rest[end..];
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == ':')
            .collect::<String>()
            .to_ascii_lowercase();
        match name.as_str() {
            "nav" if !closing => {
                if tag.contains("toc") && (tag.contains("epub:type") || tag.contains("role=\"doc-toc\"")) {
                    in_toc = true;
                    ol_depth = 0;
                }
            }
            "nav" => in_toc = false,
            "ol" if in_toc => {
                if closing {
                    ol_depth = ol_depth.saturating_sub(1);
                } else {
                    ol_depth = ol_depth.saturating_add(1);
                }
            }
            "a" | "span" if in_toc => {
                if closing {
                    if let Some(l) = label.take() {
                        let l = crate::plugin::squash_whitespace(&l);
                        if !l.is_empty() && out.len() < crate::plugin::MAX_OUTLINE {
                            out.push((ol_depth.clamp(1, 9), truncate_chars(&l, 300)));
                        }
                    }
                } else if !tag.ends_with('/') {
                    label = Some(String::new());
                }
            }
            _ => {}
        }
    }
    out
}

/// An NCX `navMap`: nested `navPoint`s.
fn ncx_toc(xml: &str, cx: &Context<'_>) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    let mut depth = 0u8;
    let mut in_label = false;
    let mut label = String::new();
    let _ = walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, false) if t.name == "navPoint" => depth = depth.saturating_add(1),
            Ev::Open(t, false) if t.name == "navLabel" => {
                in_label = true;
                label.clear();
            }
            Ev::Text(s) if in_label => label.push_str(s),
            Ev::Close("navLabel") => {
                in_label = false;
                let l = crate::plugin::squash_whitespace(&label);
                if !l.is_empty() && out.len() < crate::plugin::MAX_OUTLINE {
                    out.push((depth.clamp(1, 9), truncate_chars(&l, 300)));
                }
            }
            Ev::Close("navPoint") => depth = depth.saturating_sub(1),
            _ => {}
        }
        Flow::Continue
    });
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve `.` and `..` segments.
fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_toc() {
        assert_eq!(normalise("OEBPS/text/../images/c%20.jpg"), "OEBPS/images/c%20.jpg");
        assert_eq!(percent_decode("a%20b"), "a b");
        let toc = nav_toc(
            r#"<nav epub:type="toc"><ol><li><a href="a">Tides &amp; Times</a><ol><li><a href="b">Springs</a></li></ol></li></ol></nav><nav epub:type="landmarks"><ol><li><a>Cover</a></li></ol></nav>"#,
        );
        assert_eq!(toc, [(1, "Tides & Times".to_string()), (2, "Springs".to_string())]);
    }

    #[test]
    fn reads_an_epub() {
        let opf = br##"<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="id">
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Saltmere Tides</dc:title><dc:creator id="c1">Ana Lighthouse</dc:creator>
<meta refines="#c1" property="role" scheme="marc:relators">aut</meta><dc:creator id="c2">Ben Gull</dc:creator><meta refines="#c2" property="role">ill</meta>
<dc:identifier id="id">urn:isbn:9780306406157</dc:identifier><dc:language>en</dc:language><dc:date>2024-05-01</dc:date>
<meta property="belongs-to-collection" id="s">Harbour Books</meta><meta refines="#s" property="group-position">2</meta></metadata>
<manifest><item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/><item id="c1" href="text/ch1.xhtml" media-type="application/xhtml+xml"/>
<item id="cov" href="images/cover.jpg" media-type="image/jpeg" properties="cover-image"/></manifest><spine><itemref idref="c1"/></spine></package>"##;
        let nav = br#"<html xmlns:epub="http://www.idpf.org/2007/ops"><body><nav epub:type="toc"><ol><li><a href="text/ch1.xhtml">Spring tides</a></li></ol></nav></body></html>"#;
        let ch1 = b"<html><body><h1>Spring tides</h1><p>High water comes at noon.</p></body></html>";
        let data = crate::plugin::testing::zip(&[
            ("mimetype", b"application/epub+zip", false),
            ("META-INF/container.xml", br#"<container><rootfiles><rootfile full-path="OEBPS/book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>"#, true),
            ("OEBPS/book.opf", opf, true),
            ("OEBPS/nav.xhtml", nav, true),
            ("OEBPS/text/ch1.xhtml", ch1, true),
            ("OEBPS/images/cover.jpg", b"\xFF\xD8\xFF", false),
        ]);
        let r = crate::plugin::testing::report_for("tides.epub", &data);
        assert_eq!(r.identification.format, "epub");
        assert_eq!(r.content.title.as_deref(), Some("Saltmere Tides"));
        assert_eq!(r.content.authors, ["Ana Lighthouse"]);
        assert_eq!(r.content.outline[0].text, "Spring tides");
        let f = &r.format["epub"];
        assert_eq!(f["identifiers"][0]["value"], "9780306406157");
        assert_eq!(f["creators"][1]["role"], "ill");
        assert_eq!(f["series"]["name"], "Harbour Books");
        assert_eq!(f["series"]["index"], "2");
        assert_eq!(f["cover"]["path"], "OEBPS/images/cover.jpg");
        assert!(r.content.excerpt.as_deref().unwrap_or_default().contains("High water comes at noon."));
    }
}
