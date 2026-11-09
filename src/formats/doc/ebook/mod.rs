//! Ebooks and comic archives: EPUB 2/3, Kindle MOBI / AZW / AZW3, PalmDOC,
//! FictionBook (FB2, FBZ) and comic book ZIPs (CBZ, with `ComicInfo.xml`).
//!
//! Each format fills one bibliographic record (title, creators and roles,
//! language, identifiers, publisher, dates, subjects, rights, description,
//! series), the table of contents as headings, the reading-order text, the
//! cover, and DRM / script flags.

mod comic;
mod epub;
mod fb2;
mod mobi;

use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Probe, Sniff, Source,
    TextRole, truncate_chars, zip_first_stored,
};

/// Extractor for ebooks.
pub struct Ebook;

macro_rules! spec {
    ($id:literal, $name:literal, [$($mime:literal),+], [$($ext:literal),+], [$($magic:expr),*], $parent:expr) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "doc.ebook",
            mimes: &[$($mime),+],
            extensions: &[$($ext),+],
            magic: &[$($magic),*],
            parent: $parent,
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.ebook",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("epub", "EPUB ebook", ["application/epub+zip"], ["epub"], [], Some("zip")),
        spec!("ibooks", "Apple iBooks Author book", ["application/x-ibooks+zip"], ["ibooks"], [], Some("zip")),
        spec!("opf", "Open eBook / EPUB package file", ["application/oebps-package+xml"], ["opf"], [], Some("xml")),
        spec!("ncx", "DAISY / EPUB navigation (NCX)", ["application/x-dtbncx+xml"], ["ncx"], [], Some("xml")),
        spec!(
            "mobi",
            "Mobipocket / Kindle ebook",
            ["application/x-mobipocket-ebook"],
            ["mobi", "prc", "azw"],
            [Magic::at(60, b"BOOKMOBI")],
            None
        ),
        spec!("azw3", "Kindle KF8 ebook", ["application/vnd.amazon.mobi8-ebook"], ["azw3", "kf8"], [], Some("mobi")),
        spec!("palmdoc", "PalmDOC ebook", ["application/vnd.palm"], ["pdb"], [Magic::at(60, b"TEXtREAd")], None),
        spec!("fb2", "FictionBook", ["application/x-fictionbook+xml"], ["fb2"], [], Some("xml")),
        spec!("fbz", "Zipped FictionBook", ["application/x-zip-compressed-fb2"], ["fbz", "fb2.zip"], [], Some("zip")),
        spec!("cbz", "Comic book archive (ZIP)", ["application/vnd.comicbook+zip"], ["cbz"], [], Some("zip")),
    ],
};

impl Extractor for Ebook {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if let Some(m) = zip_first_stored(probe.head, "mimetype") {
            return match m.trim_ascii() {
                b"application/epub+zip" => Some(Sniff { format: "epub", confidence: 0.98 }),
                b"application/x-ibooks+zip" => Some(Sniff { format: "ibooks", confidence: 0.98 }),
                _ => None,
            };
        }
        if probe.head.starts_with(b"PK\x03\x04") {
            let ext = probe.extension.unwrap_or_default();
            let names = crate::plugin::zip_names(probe, 4000);
            if names.iter().any(|n| n == "META-INF/container.xml")
                && names.iter().any(|n| n.rsplit_once('.').is_some_and(|(_, x)| x.eq_ignore_ascii_case("opf")))
            {
                return Some(Sniff { format: "epub", confidence: 0.9 });
            }
            if ext == "fbz" || names.len() == 1 && names[0].to_ascii_lowercase().ends_with(".fb2") {
                return Some(Sniff { format: "fbz", confidence: 0.85 });
            }
            if ext == "cbz" || names.iter().any(|n| n.eq_ignore_ascii_case("ComicInfo.xml")) {
                return Some(Sniff { format: "cbz", confidence: if ext == "cbz" { 0.9 } else { 0.8 } });
            }
            return None;
        }
        if probe.head.get(60..68) == Some(b"BOOKMOBI") {
            // KF8-only books (`.azw3`) have MOBI version 8 in record 0.
            return mobi::is_kf8(probe.head).then_some(Sniff { format: "azw3", confidence: 0.9 });
        }
        let root = super::xml::root(probe.head)?;
        let head = String::from_utf8_lossy(&probe.head[..probe.head.len().min(4096)]);
        match root.name.as_str() {
            "FictionBook" => Some(Sniff { format: "fb2", confidence: 0.95 }),
            "package" if head.contains("http://www.idpf.org/2007/opf") || head.contains("oeb-package") => {
                Some(Sniff { format: "opf", confidence: 0.95 })
            }
            "ncx" => Some(Sniff { format: "ncx", confidence: 0.95 }),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut book = Book::default();
        match cx.format_id() {
            // An iBooks Author book is an EPUB 3 with its own media type.
            "epub" | "ibooks" => epub::extract(src, cx, &mut book)?,
            "opf" | "ncx" => {
                let (bytes, _) = cx.read_bytes(src)?;
                let xml = crate::plugin::decode_text(&bytes).text;
                if cx.format_id() == "opf" {
                    epub::standalone_opf(&xml, cx, &mut book)?;
                } else {
                    epub::standalone_ncx(&xml, cx, &mut book);
                }
            }
            "mobi" | "azw3" | "palmdoc" => mobi::extract(src, cx, &mut book)?,
            "fb2" => {
                let (bytes, _) = cx.read_bytes(src)?;
                let xml = crate::plugin::decode_text(&bytes).text;
                fb2::extract(&xml, cx, &mut book)?;
            }
            "fbz" => fb2::extract_zip(src, cx, &mut book)?,
            "cbz" => comic::extract(src, cx, &mut book)?,
            other => return Err(ExtractError::Unsupported(format!("format {other}"))),
        }
        book.write(cx);
        Ok(())
    }
}

crate::register_extractor!(Ebook);

/// The normalised record every ebook format fills.
#[derive(Default)]
pub(crate) struct Book {
    pub(crate) title: Option<String>,
    /// (name, role); role is a MARC relator code or a plain word.
    pub(crate) creators: Vec<(String, String)>,
    pub(crate) language: Option<String>,
    /// (scheme, value).
    pub(crate) identifiers: Vec<(String, String)>,
    pub(crate) publisher: Option<String>,
    pub(crate) published: Option<String>,
    pub(crate) modified: Option<String>,
    pub(crate) subjects: Vec<String>,
    pub(crate) rights: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) series: Option<(String, Option<String>)>,
    pub(crate) toc: Vec<(u8, String)>,
    pub(crate) text: String,
    pub(crate) cover: Option<Value>,
    pub(crate) drm: Option<String>,
    pub(crate) format: Map,
}

const MAX_LISTED: usize = 200;

impl Book {
    pub(crate) fn creator(&mut self, name: &str, role: &str) {
        let name = crate::plugin::squash_whitespace(name);
        if !name.is_empty()
            && self.creators.len() < MAX_LISTED
            && !self.creators.iter().any(|(n, r)| *n == name && r == role)
        {
            self.creators.push((name, role.to_string()));
        }
    }

    pub(crate) fn identifier(&mut self, scheme: &str, value: &str) {
        let value = value.trim();
        if value.is_empty() || self.identifiers.len() >= 50 {
            return;
        }
        let (scheme, value) = classify_identifier(scheme, value);
        if !self.identifiers.iter().any(|(_, v)| *v == value) {
            self.identifiers.push((scheme, value));
        }
    }

    /// Add `text` (one document of the reading order) within `max` bytes.
    pub(crate) fn add_text(&mut self, text: &str, max: usize) -> bool {
        if self.text.len() >= max {
            return false;
        }
        let room = max - self.text.len();
        let t = text.trim();
        if t.is_empty() {
            return true;
        }
        if t.len() > room {
            self.text.push_str(&truncate_chars(t, room));
            return false;
        }
        self.text.push_str(t);
        self.text.push_str("\n\n");
        true
    }

    fn write(self, cx: &mut Context<'_>) {
        if let Some(t) = &self.title {
            cx.content().source("ebook.title").title(t);
            cx.emit_text(TextRole::Title, t);
        }
        let mut creators = Vec::new();
        for (name, role) in &self.creators {
            if matches!(role.as_str(), "aut" | "author" | "" | "writer") {
                cx.content().source("ebook.creator").author(name);
                cx.rights().source("ebook.creator").creator(name);
            }
            let mut m = Map::new();
            m.insert("name".into(), json!(name));
            if !role.is_empty() {
                m.insert("role".into(), json!(role));
            }
            creators.push(Value::Object(m));
        }
        if let Some(d) = &self.description {
            let (text, _) = crate::plugin::html_text(d, 10_000);
            let text = crate::plugin::squash_whitespace(&text);
            if !text.is_empty() {
                cx.content().source("ebook.description").description(&text);
                cx.emit_text(TextRole::Caption, &text);
            }
        }
        if let Some(l) = &self.language {
            let code = l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase();
            if code.len() == 2 {
                cx.content().source("ebook.language").language(code, 1.0);
            }
        }
        for s in self.subjects.iter().take(100) {
            cx.content().source("ebook.subject").tag(s);
        }
        if let Some(r) = &self.rights {
            cx.rights().source("ebook.rights").copyright(r);
        }
        let mut format = self.format;
        match self.published.as_deref().map(str::trim) {
            Some(y) if y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()) => {
                format.insert("published_year".into(), json!(y));
            }
            Some(d) => {
                if let Some((v, tz)) = crate::plugin::parse_date(d) {
                    cx.temporal().source("ebook.date").content_date(DateField::Published, v, tz);
                }
            }
            None => {}
        }
        if let Some((v, tz)) = self.modified.as_deref().and_then(crate::plugin::parse_date) {
            cx.temporal().source("ebook.modified").content_date(DateField::Modified, v, tz);
        }
        for (level, h) in &self.toc {
            cx.emit_heading(*level, h);
        }
        if !self.text.trim().is_empty() {
            cx.emit_text(TextRole::Body, &self.text);
        }
        if !creators.is_empty() {
            format.insert("creators".into(), Value::Array(creators));
        }
        if !self.identifiers.is_empty() {
            let ids: Vec<Value> = self.identifiers.iter().map(|(s, v)| json!({ "scheme": s, "value": v })).collect();
            format.insert("identifiers".into(), Value::Array(ids));
        }
        if let Some(p) = self.publisher {
            format.insert("publisher".into(), json!(p));
        }
        if let Some((name, index)) = self.series {
            let mut m = Map::new();
            m.insert("name".into(), json!(name));
            if let Some(i) = index {
                m.insert("index".into(), json!(i));
            }
            format.insert("series".into(), Value::Object(m));
        }
        if !self.toc.is_empty() {
            format.insert("toc_entries".into(), json!(self.toc.len()));
        }
        if let Some(c) = self.cover {
            format.insert("cover".into(), c);
        }
        if let Some(d) = self.drm {
            cx.security().encrypted(true);
            format.insert("drm".into(), json!(d));
        }
        cx.format().extend(format);
    }
}

/// Recognise ISBN / ASIN / UUID / DOI values; ISBNs are normalised and checked.
fn classify_identifier(scheme: &str, value: &str) -> (String, String) {
    let lower = value.to_ascii_lowercase();
    let stripped = lower.strip_prefix("urn:").unwrap_or(&lower);
    if let Some(rest) =
        stripped.strip_prefix("isbn:").or_else(|| scheme.eq_ignore_ascii_case("isbn").then_some(stripped))
    {
        let digits: String = rest.chars().filter(|c| c.is_ascii_digit() || *c == 'x').collect();
        if isbn_valid(&digits) {
            return ("isbn".into(), digits.to_ascii_uppercase());
        }
    }
    if let Some(rest) = stripped.strip_prefix("uuid:") {
        return ("uuid".into(), rest.to_string());
    }
    if let Some(rest) = stripped.strip_prefix("doi:") {
        return ("doi".into(), rest.to_string());
    }
    let digits: String = value.chars().filter(|c| c.is_ascii_digit() || *c == 'X' || *c == 'x').collect();
    if (digits.len() == 10 || digits.len() == 13)
        && digits.len() + 4 >= value.len()
        && isbn_valid(&digits.to_ascii_lowercase())
    {
        return ("isbn".into(), digits.to_ascii_uppercase());
    }
    let scheme = if scheme.is_empty() { "other" } else { scheme };
    (scheme.to_ascii_lowercase(), value.to_string())
}

fn isbn_valid(d: &str) -> bool {
    let b = d.as_bytes();
    match b.len() {
        10 => {
            let mut sum = 0u32;
            for (weight, &c) in (1..=10u32).rev().zip(b) {
                let v = match c {
                    b'0'..=b'9' => u32::from(c - b'0'),
                    b'x' if weight == 1 => 10,
                    _ => return false,
                };
                sum += v * weight;
            }
            sum.is_multiple_of(11)
        }
        13 => {
            if !b.iter().all(u8::is_ascii_digit) {
                return false;
            }
            let sum: u32 =
                b.iter().enumerate().map(|(i, &c)| u32::from(c - b'0') * if i.is_multiple_of(2) { 1 } else { 3 }).sum();
            sum.is_multiple_of(10)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert_eq!(classify_identifier("", "urn:isbn:978-0-306-40615-7"), ("isbn".into(), "9780306406157".into()));
        assert_eq!(classify_identifier("ISBN", "0-306-40615-2"), ("isbn".into(), "0306406152".into()));
        assert_eq!(classify_identifier("", "urn:uuid:1b4e28ba-2fa1-11d2-883f-0016d3cca427").0, "uuid");
        assert_eq!(classify_identifier("calibre", "1234").0, "calibre");
        assert!(!isbn_valid("9780306406158"));
    }

    crate::fixture_tests!("epub", "ibooks", "opf", "ncx", "mobi", "azw3", "palmdoc", "fb2", "fbz", "cbz");
}
