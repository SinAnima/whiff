//! PDF (1.0–2.0) and FDF, read with an in-house parser.
//!
//! Reads the document information dictionary, the XMP packet (decoded by
//! `meta.xmp`), version, page count and sizes, linearization, incremental
//! updates, encryption and permissions, tagging and `/Lang`, PDF/A, /UA and
//! /X conformance, the outline (as headings), fonts, images, annotations,
//! AcroForm / XFA fields, signatures, and the text of each page. Active
//! content is flagged: JavaScript, automatic actions, launch actions, form
//! submission, remote go-to actions and rich media. Embedded files become
//! children.
//!
//! Specification: ISO 32000-2:2020.

mod crypt;
mod doc;
mod filter;
mod object;
mod text;

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use serde_json::{Value, json};

use self::doc::Doc;
use self::object::{Dict, Obj, text_string};
use crate::plugin::{
    BlockKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Source,
    TextRole, parse_date, redact_secrets, truncate_chars,
};

/// Extractor for PDF and FDF files.
pub struct Pdf;

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.pdf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pdf",
            name: "PDF document",
            family: "doc.pdf",
            mimes: &["application/pdf"],
            extensions: &["pdf"],
            magic: &[Magic::prefix(b"%PDF-")],
            parent: None,
        },
        FormatSpec {
            id: "fdf",
            name: "Forms Data Format",
            family: "doc.pdf",
            mimes: &["application/vnd.fdf"],
            extensions: &["fdf"],
            magic: &[Magic::prefix(b"%FDF-")],
            parent: None,
        },
    ],
};

const MAX_PAGES: usize = 100_000;
const MAX_TEXT_PAGES: usize = 2_000;
const MAX_LISTED: usize = 200;
const MAX_SCANNED: usize = 500_000;

impl Extractor for Pdf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &crate::plugin::Probe<'_>) -> Option<crate::plugin::Sniff> {
        // `%PDF-` after a junk prefix (allowed by readers within 1 KiB).
        let head = &probe.head[..probe.head.len().min(1024)];
        if probe.head.starts_with(b"%PDF-") || probe.head.starts_with(b"%FDF-") {
            return None;
        }
        doc::find(head, b"%PDF-").map(|_| crate::plugin::Sniff { format: "pdf", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let fdf = cx.format_id() == "fdf";
        if fdf {
            return extract_fdf(src, cx);
        }
        let linearized = linearized(src.head());
        let looks_ai = [src.head(), src.tail()]
            .iter()
            .any(|w| doc::find(w, b"Illustrator").is_some() || doc::find(w, b"AIPrivateData").is_some());
        let mut doc = Doc::open(src, cx)?;
        let mut s = Scan::default();
        s.structure(&mut doc, linearized);
        let catalog = doc.key(&doc.trailer.clone(), "Root");
        let catalog = catalog.as_dict().cloned().unwrap_or_default();
        if let Some(c) = &doc.crypt.clone() {
            s.encryption(&mut doc, c);
        }
        let readable = doc.crypt.as_ref().is_none_or(crypt::Decryptor::opened);
        if readable {
            s.info(&mut doc);
        }
        s.catalog(&mut doc, &catalog);
        let pages = s.pages(&mut doc, &catalog)?;
        s.outline(&mut doc, &catalog)?;
        s.names(&mut doc, &catalog)?;
        s.actions(&mut doc, &catalog);
        s.forms(&mut doc, &catalog)?;
        s.objects(&mut doc)?;
        if readable {
            s.text(&mut doc, &pages)?;
        } else {
            doc.cx.warn("encrypted with a user password: text and metadata strings not read");
        }
        s.finish(&mut doc);
        drop(doc);
        if looks_ai {
            illustrator(src, cx)?;
        }
        Ok(())
    }
}

crate::register_extractor!(Pdf);

/// Adobe Illustrator's PDF-compatible files: the `/Illustrator` page piece
/// and the `/AIPrivateData` streams that hold the native artwork.
fn illustrator(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    const WINDOW: u64 = 1 << 20;
    let end = src.len().min(64 << 20);
    let (mut at, mut private, mut piece) = (0u64, 0usize, false);
    while at < end {
        let buf = src.read_vec(at, usize::try_from((end - at).min(WINDOW + 64)).unwrap_or(0))?;
        let slice = &buf[..buf.len().min(usize::try_from(WINDOW).unwrap_or(usize::MAX))];
        private += slice.windows(14).filter(|w| *w == b"/AIPrivateData").count();
        piece |= doc::find(slice, b"/Illustrator").is_some();
        at += WINDOW;
    }
    if private > 0 || piece {
        let mut m = serde_json::Map::new();
        m.insert("page_piece".into(), piece.into());
        m.insert("private_data_streams".into(), private.into());
        cx.format_set("illustrator", serde_json::Value::Object(m));
    }
    Ok(())
}

/// `/Linearized` in the first object.
fn linearized(head: &[u8]) -> bool {
    let window = &head[..head.len().min(1024)];
    doc::find(window, b"/Linearized").is_some()
}

/// A PDF date (`D:20240501083000+02'00'`) as ISO 8601, and whether it has a zone.
#[allow(clippy::many_single_char_names)] // date fields
pub(crate) fn pdf_date(raw: &str) -> Option<(String, bool)> {
    let s = raw.trim().strip_prefix("D:").unwrap_or(raw.trim());
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return None;
    }
    let part = |a: usize, b: usize, d: &str| digits.get(a..b).unwrap_or(d).to_string();
    let (y, mo, d, h, mi, se) =
        (part(0, 4, ""), part(4, 6, "01"), part(6, 8, "01"), part(8, 10, "00"), part(10, 12, "00"), part(12, 14, "00"));
    let rest = &s[digits.len()..];
    let zone = match rest.chars().next() {
        Some('Z') => Some("Z".to_string()),
        Some(sign @ ('+' | '-')) => {
            let z: String = rest[1..].chars().filter(char::is_ascii_digit).collect();
            let zh = z.get(0..2).unwrap_or("00");
            let zm = z.get(2..4).unwrap_or("00");
            Some(format!("{sign}{zh}:{zm}"))
        }
        _ => None,
    };
    let iso = format!("{y}-{mo}-{d}T{h}:{mi}:{se}{}", zone.as_deref().unwrap_or(""));
    parse_date(&iso)
}

fn str_of(o: &Obj) -> Option<String> {
    o.as_str().map(text_string).map(|s| s.trim_matches(char::from(0)).trim().to_string()).filter(|s| !s.is_empty())
}

/// Common paper sizes in points (portrait).
fn paper_name(w: f64, h: f64) -> Option<&'static str> {
    const SIZES: &[(&str, f64, f64)] = &[
        ("A3", 841.89, 1190.55),
        ("A4", 595.28, 841.89),
        ("A5", 419.53, 595.28),
        ("Letter", 612.0, 792.0),
        ("Legal", 612.0, 1008.0),
        ("Tabloid", 792.0, 1224.0),
        ("B5", 498.9, 708.66),
    ];
    let (a, b) = if w <= h { (w, h) } else { (h, w) };
    SIZES.iter().find(|(_, sw, sh)| (a - sw).abs() < 3.0 && (b - sh).abs() < 3.0).map(|(n, _, _)| *n)
}

/// One page: its dictionary and inherited attributes.
struct Page {
    dict: Dict,
    resources: Obj,
}

#[derive(Default)]
struct Scan {
    format: Map,
    info: Map,
    javascript: Vec<String>,
    auto_actions: Vec<String>,
    launch: Vec<String>,
    submit: Vec<String>,
    remote: Vec<String>,
    uris: Vec<String>,
    uri_count: u64,
    embedded: Vec<(String, Obj)>,
    rich_media: u64,
    fonts: BTreeMap<String, Value>,
    images: u64,
    annotations: BTreeMap<String, u64>,
    signatures: Vec<Value>,
    seen_files: HashSet<u32>,
}

impl Scan {
    fn structure(&mut self, doc: &mut Doc<'_, '_>, linearized: bool) {
        if let Some(v) = &doc.version {
            self.format.insert("version".into(), json!(v));
        }
        self.format.insert("objects".into(), json!(doc.xref.len()));
        if doc.sections > 1 {
            self.format.insert("incremental_updates".into(), json!(doc.sections - 1));
        }
        if doc.xref_streams {
            self.format.insert("xref_streams".into(), json!(true));
        }
        if linearized {
            self.format.insert("linearized".into(), json!(true));
        }
        if doc.repaired {
            self.format.insert("repaired".into(), json!(true));
        }
        if let Some(id) = doc.trailer.get("ID").and_then(Obj::as_array) {
            let hex: Vec<String> = id
                .iter()
                .filter_map(Obj::as_str)
                .map(|b| {
                    b.iter().fold(String::new(), |mut hex, x| {
                        let _ = write!(hex, "{x:02x}");
                        hex
                    })
                })
                .collect();
            if !hex.is_empty() {
                self.format.insert("id".into(), json!(hex));
            }
        }
    }

    fn encryption(&mut self, doc: &mut Doc<'_, '_>, c: &crypt::Decryptor) {
        doc.cx.security().encrypted(true);
        let mut e = Map::new();
        e.insert("filter".into(), json!(c.filter));
        if let Some(sf) = &c.sub_filter {
            e.insert("sub_filter".into(), json!(sf));
        }
        e.insert("version".into(), json!(c.v));
        e.insert("revision".into(), json!(c.r));
        e.insert("key_bits".into(), json!(c.bits));
        e.insert("method".into(), json!(c.method));
        e.insert("user_password".into(), json!(if c.opened() { "empty" } else { "required" }));
        if !c.encrypt_metadata {
            e.insert("encrypt_metadata".into(), json!(false));
        }
        if let Some(p) = c.permissions {
            let bit = |n: u32| p & (1 << (n - 1)) != 0;
            let mut perms = Map::new();
            for (name, n) in [
                ("print", 3),
                ("modify", 4),
                ("copy", 5),
                ("annotate", 6),
                ("fill_forms", 9),
                ("extract_for_accessibility", 10),
                ("assemble", 11),
                ("print_high_quality", 12),
            ] {
                perms.insert(name.into(), json!(bit(n)));
            }
            e.insert("permissions".into(), Value::Object(perms));
        }
        self.format.insert("encryption".into(), Value::Object(e));
    }

    fn info(&mut self, doc: &mut Doc<'_, '_>) {
        let trailer = doc.trailer.clone();
        let info = doc.key(&trailer, "Info");
        let Some(info) = info.as_dict() else { return };
        for (k, v) in &info.0 {
            let v = doc.resolve(v);
            let value = match &v {
                Obj::Str(_) => str_of(&v).map(Value::String),
                Obj::Name(n) => Some(json!(n)),
                Obj::Bool(b) => Some(json!(b)),
                _ => None,
            };
            if let Some(value) = value
                && self.info.len() < 100
            {
                let value = match value {
                    Value::String(s) => Value::String(redact_secrets(&truncate_chars(&s, 2000)).into_owned()),
                    other => other,
                };
                self.info.insert(k.clone(), value);
            }
        }
        let s = |k: &str| self.info.get(k).and_then(Value::as_str).map(str::to_string);
        let cx = &mut *doc.cx;
        if let Some(t) = s("Title") {
            cx.content().source("pdf.info.Title").title(&t);
            cx.emit_text(TextRole::Title, &t);
        }
        if let Some(a) = s("Author") {
            let sep = if a.contains(';') { ';' } else { '\u{0}' };
            for name in a.split(sep).map(str::trim).filter(|n| !n.is_empty()).take(20) {
                cx.content().source("pdf.info.Author").author(name);
                cx.rights().source("pdf.info.Author").creator(name);
            }
        }
        if let Some(d) = s("Subject") {
            cx.content().source("pdf.info.Subject").description(&d);
            cx.emit_text(TextRole::Caption, &d);
        }
        if let Some(k) = s("Keywords") {
            let sep = if k.contains(';') { ';' } else { ',' };
            for kw in k.split(sep).map(str::trim).filter(|w| !w.is_empty()).take(100) {
                cx.content().source("pdf.info.Keywords").keyword(kw);
            }
        }
        for (key, field) in [("CreationDate", DateField::Created), ("ModDate", DateField::Modified)] {
            if let Some((v, tz)) = s(key).as_deref().and_then(pdf_date) {
                cx.temporal().source(format!("pdf.info.{key}")).content_date(field, v, tz);
            }
        }
    }

    fn catalog(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) {
        if let Some(v) = catalog.name("Version") {
            self.format.insert("catalog_version".into(), json!(v));
        }
        if let Some(lang) = str_of(&doc.key(catalog, "Lang")) {
            self.format.insert("lang".into(), json!(lang));
            let code = lang.split(['-', '_']).next().unwrap_or(&lang).to_ascii_lowercase();
            if code.len() == 2 {
                doc.cx.content().source("pdf.Lang").language(code, 1.0);
            }
        }
        if let Obj::Dict(mi) = doc.key(catalog, "MarkInfo")
            && mi.get("Marked").and_then(Obj::as_bool) == Some(true)
        {
            self.format.insert("tagged".into(), json!(true));
        }
        if catalog.has("StructTreeRoot") {
            self.format.insert("structure_tree".into(), json!(true));
        }
        for (key, name) in [("PageLayout", "page_layout"), ("PageMode", "page_mode")] {
            if let Some(v) = catalog.name(key) {
                self.format.insert(name.into(), json!(v));
            }
        }
        if catalog.has("Collection") {
            self.format.insert("portfolio".into(), json!(true));
        }
        if catalog.has("Perms") {
            self.format.insert("usage_rights".into(), json!(true));
        }
        if catalog.has("DSS") {
            self.format.insert("long_term_validation".into(), json!(true));
        }
        if let Some(m) = catalog.get("Metadata").cloned()
            && let Ok(xmp) = doc.stream_of(&m, 8 << 20)
        {
            self.conformance(&xmp);
            doc.cx.emit_block(BlockKind::XMP, xmp);
        }
    }

    /// PDF/A, /UA, /X, /E, /VT claims in the XMP packet.
    fn conformance(&mut self, xmp: &[u8]) {
        let x = String::from_utf8_lossy(xmp);
        let prop = |name: &str| -> Option<String> {
            // Attribute (`pdfaid:part="1"`) or element (`<pdfaid:part>1</pdfaid:part>`) form.
            if let Some(i) = x.find(&format!("{name}=")) {
                let rest = &x[i + name.len() + 1..];
                let q = rest.chars().next()?;
                let end = rest[1..].find(q)?;
                return Some(rest[1..=end].trim().to_string());
            }
            let open = format!("<{name}>");
            let i = x.find(&open)?;
            let rest = &x[i + open.len()..];
            Some(rest[..rest.find('<')?].trim().to_string())
        };
        let mut out = Vec::new();
        if let Some(part) = prop("pdfaid:part") {
            out.push(format!("PDF/A-{part}{}", prop("pdfaid:conformance").unwrap_or_default().to_ascii_lowercase()));
        }
        if let Some(part) = prop("pdfuaid:part") {
            out.push(format!("PDF/UA-{part}"));
        }
        if let Some(v) = prop("pdfx:GTS_PDFXVersion").or_else(|| prop("pdfxid:GTS_PDFXVersion")) {
            out.push(v);
        }
        if let Some(v) = prop("pdfe:ISO_PDFEVersion") {
            out.push(v);
        }
        if let Some(v) = prop("pdfvtid:GTS_PDFVTVersion") {
            out.push(v);
        }
        if !out.is_empty() {
            self.format.insert("conformance".into(), json!(out));
        }
    }

    fn pages(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) -> Result<Vec<Page>, ExtractError> {
        let root = doc.key(catalog, "Pages");
        let Some(root) = root.as_dict().cloned() else {
            doc.cx.warn("no page tree");
            return Ok(Vec::new());
        };
        let declared = root.int("Count").and_then(|n| u64::try_from(n).ok());
        let mut pages = Vec::new();
        let mut seen = HashSet::new();
        // (node, inherited Resources, MediaBox, Rotate)
        let mut stack = vec![(root, Obj::Null, Obj::Null, 0i64)];
        let mut sizes: BTreeMap<(i64, i64), u64> = BTreeMap::new();
        let mut rotated = 0u64;
        while let Some((node, res, mbox, inherited_rotate)) = stack.pop() {
            doc.cx.checkpoint()?;
            let res = node.get("Resources").cloned().unwrap_or(res);
            let mbox = node.get("MediaBox").map_or(mbox, |m| doc.resolve(m));
            let rotate = node.int("Rotate").unwrap_or(inherited_rotate);
            let kids = doc.key(&node, "Kids");
            if node.name("Type") == Some("Page") || (kids.as_array().is_none() && node.has("Contents")) {
                let bbox = doc.resolve(node.get("CropBox").unwrap_or(&mbox));
                let bbox = if bbox.as_array().is_some_and(|a| a.len() == 4) { bbox } else { mbox.clone() };
                if let Some(b) = bbox.as_array().filter(|a| a.len() == 4) {
                    let v: Vec<f64> = b.iter().map(|o| doc.resolve(o).as_f64().unwrap_or(0.0)).collect();
                    let (mut w, mut h) = ((v[2] - v[0]).abs(), (v[3] - v[1]).abs());
                    if rotate.rem_euclid(180) == 90 {
                        std::mem::swap(&mut w, &mut h);
                    }
                    #[allow(clippy::cast_possible_truncation)] // page sizes in points
                    let key = ((w * 10.0).round() as i64, (h * 10.0).round() as i64);
                    *sizes.entry(key).or_default() += 1;
                }
                if rotate.rem_euclid(360) != 0 {
                    rotated += 1;
                }
                if pages.len() < MAX_PAGES {
                    pages.push(Page { dict: node, resources: res });
                }
                continue;
            }
            if let Some(kids) = kids.as_array() {
                for k in kids.iter().rev() {
                    let Obj::Ref(n, _) = k else { continue };
                    if !seen.insert(*n) || seen.len() > MAX_PAGES * 2 {
                        continue;
                    }
                    if let Obj::Dict(d) = doc.get(*n) {
                        stack.push((d, res.clone(), mbox.clone(), rotate));
                    }
                }
            }
        }
        let count = declared.filter(|&d| d == pages.len() as u64 || pages.is_empty()).unwrap_or(pages.len() as u64);
        if let Some(d) = declared
            && d != pages.len() as u64
            && !pages.is_empty()
        {
            doc.cx.warn(format!("page tree declares {d} pages but has {}", pages.len()));
        }
        doc.cx.physical().pages(count);
        let mut by_count: Vec<_> = sizes.into_iter().collect();
        by_count.sort_by_key(|e| std::cmp::Reverse(e.1));
        #[allow(clippy::cast_precision_loss)] // tenths of a point
        let listed: Vec<Value> = by_count
            .iter()
            .take(10)
            .map(|((w, h), n)| {
                let (w, h) = (*w as f64 / 10.0, *h as f64 / 10.0);
                let mut m = Map::new();
                m.insert("width_pt".into(), json!(w));
                m.insert("height_pt".into(), json!(h));
                m.insert("width_mm".into(), json!((w * 25.4 / 72.0 * 10.0).round() / 10.0));
                m.insert("height_mm".into(), json!((h * 25.4 / 72.0 * 10.0).round() / 10.0));
                if let Some(p) = paper_name(w, h) {
                    m.insert("paper".into(), json!(p));
                }
                m.insert("orientation".into(), json!(if w > h { "landscape" } else { "portrait" }));
                m.insert("pages".into(), json!(n));
                Value::Object(m)
            })
            .collect();
        if !listed.is_empty() {
            self.format.insert("page_sizes".into(), Value::Array(listed));
        }
        if rotated > 0 {
            self.format.insert("rotated_pages".into(), json!(rotated));
        }
        Ok(pages)
    }

    fn outline(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) -> Result<(), ExtractError> {
        let root = doc.key(catalog, "Outlines");
        let Some(first) = root.as_dict().and_then(|d| d.get("First")).cloned() else { return Ok(()) };
        let mut seen = HashSet::new();
        let mut count = 0usize;
        // (item, level)
        let mut stack = vec![(first, 1u8)];
        while let Some((item, level)) = stack.pop() {
            doc.cx.checkpoint()?;
            let Obj::Ref(n, _) = item else { continue };
            if !seen.insert(n) || count >= 10_000 {
                continue;
            }
            let Obj::Dict(d) = doc.get(n) else { continue };
            count += 1;
            if let Some(next) = d.get("Next") {
                stack.push((next.clone(), level));
            }
            if let Some(child) = d.get("First") {
                stack.push((child.clone(), level.saturating_add(1).min(9)));
            }
            if let Some(title) = str_of(&doc.key(&d, "Title")) {
                doc.cx.emit_heading(level, &truncate_chars(&title, 300));
            }
            if let Some(a) = d.get("A").map(|a| doc.resolve(a)) {
                self.action(doc, &a, "Outline");
            }
        }
        if count > 0 {
            self.format.insert("outline_items".into(), json!(count));
        }
        Ok(())
    }

    /// Entries of a name tree (`/Names [key value …]`, `/Kids`).
    fn name_tree(doc: &mut Doc<'_, '_>, root: &Obj) -> Result<Vec<(String, Obj)>, ExtractError> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![root.clone()];
        while let Some(node) = stack.pop() {
            doc.cx.checkpoint()?;
            if let Obj::Ref(n, _) = node
                && !seen.insert(n)
            {
                continue;
            }
            let node = doc.resolve(&node);
            let Some(d) = node.as_dict() else { continue };
            if let Some(names) = doc.key(d, "Names").as_array() {
                for pair in names.as_chunks::<2>().0 {
                    let key = doc.resolve(&pair[0]).as_str().map(text_string).unwrap_or_default();
                    if out.len() < 10_000 {
                        out.push((key, pair[1].clone()));
                    }
                }
            }
            if let Some(kids) = doc.key(d, "Kids").as_array() {
                stack.extend(kids.iter().take(10_000).cloned());
            }
            if seen.len() > 50_000 {
                break;
            }
        }
        Ok(out)
    }

    fn names(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) -> Result<(), ExtractError> {
        let names = doc.key(catalog, "Names");
        let Some(names) = names.as_dict().cloned() else { return Ok(()) };
        if let Some(root) = names.get("EmbeddedFiles") {
            for (key, spec) in Self::name_tree(doc, root)? {
                self.file_spec(doc, &spec, Some(key));
            }
        }
        if let Some(root) = names.get("JavaScript") {
            for (key, action) in Self::name_tree(doc, root)? {
                let a = doc.resolve(&action);
                let label = if key.is_empty() {
                    "document".to_string()
                } else {
                    format!("document ({})", truncate_chars(&key, 80))
                };
                self.action(doc, &a, &label);
            }
        }
        if let Some(root) = names.get("Dests") {
            let n = Self::name_tree(doc, root)?.len();
            self.format.insert("named_destinations".into(), json!(n));
        }
        Ok(())
    }

    /// Record a file specification (`/EF /F` stream), once per stream.
    fn file_spec(&mut self, doc: &mut Doc<'_, '_>, spec: &Obj, key: Option<String>) {
        let spec = doc.resolve(spec);
        let Some(d) = spec.as_dict() else { return };
        let name = ["UF", "F", "DOS", "Unix"]
            .iter()
            .find_map(|k| str_of(&doc.key(d, k)))
            .or(key)
            .unwrap_or_else(|| "embedded".to_string());
        let ef = doc.key(d, "EF");
        let stream = ef.as_dict().and_then(|e| e.get("UF").or_else(|| e.get("F"))).cloned();
        if let Some(Obj::Ref(n, _)) = &stream
            && !self.seen_files.insert(*n)
        {
            return;
        }
        if self.embedded.len() < 1000 {
            self.embedded.push((name, stream.unwrap_or(Obj::Null)));
        }
    }

    /// Classify an action dictionary (and the `/Next` chain).
    fn action(&mut self, doc: &mut Doc<'_, '_>, a: &Obj, trigger: &str) {
        let mut current = a.clone();
        let mut guard = 0;
        while let Some(d) = current.as_dict().cloned() {
            guard += 1;
            if guard > 32 {
                break;
            }
            match d.name("S") {
                Some("JavaScript") => {
                    let js = match doc.key(&d, "JS") {
                        Obj::Str(s) => Some(text_string(&s)),
                        o @ Obj::Stream(..) => {
                            doc.stream_of(&o, 1 << 20).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
                        }
                        _ => None,
                    };
                    if let Some(js) = js
                        && self.javascript.len() < 100
                    {
                        if !js.trim().is_empty() {
                            doc.cx.emit_text(TextRole::Code, &js);
                        }
                        self.javascript.push(trigger.to_string());
                    }
                    if is_automatic(trigger) {
                        self.auto_actions.push(format!("{trigger}: JavaScript"));
                    }
                }
                Some("Launch") => {
                    let target = str_of(&doc.key(&d, "F"))
                        .or_else(|| doc.key(&d, "F").as_dict().and_then(|f| f.get("F").and_then(str_of)))
                        .or_else(|| doc.key(&d, "Win").as_dict().and_then(|w| w.get("F").and_then(str_of)))
                        .unwrap_or_default();
                    self.launch.push(truncate_chars(&format!("{trigger}: {target}"), 200));
                    if is_automatic(trigger) {
                        self.auto_actions.push(format!("{trigger}: Launch"));
                    }
                }
                Some("SubmitForm" | "ImportData") => {
                    let url = str_of(&doc.key(&d, "F"))
                        .or_else(|| doc.key(&d, "F").as_dict().and_then(|f| f.get("F").and_then(str_of)));
                    self.submit.push(truncate_chars(&redact_secrets(&url.unwrap_or_default()), 200));
                }
                Some("GoToR" | "GoToE") => {
                    let f = str_of(&doc.key(&d, "F"))
                        .or_else(|| doc.key(&d, "F").as_dict().and_then(|f| f.get("F").and_then(str_of)));
                    self.remote.push(truncate_chars(&f.unwrap_or_default(), 200));
                    if is_automatic(trigger) {
                        self.auto_actions.push(format!("{trigger}: {}", d.name("S").unwrap_or_default()));
                    }
                }
                Some("URI") => {
                    self.uri_count += 1;
                    if let Some(u) = doc.key(&d, "URI").as_str().map(|b| String::from_utf8_lossy(b).trim().to_string())
                        && self.uris.len() < MAX_LISTED
                        && !self.uris.contains(&u)
                    {
                        self.uris.push(truncate_chars(&redact_secrets(&u), 300));
                    }
                    if is_automatic(trigger) {
                        self.auto_actions.push(format!("{trigger}: URI"));
                    }
                }
                Some("RichMediaExecute" | "Movie" | "Sound" | "Rendition") => self.rich_media += 1,
                _ => {}
            }
            current = match d.get("Next") {
                Some(n @ Obj::Ref(..)) => doc.resolve(n),
                Some(Obj::Array(a)) => doc.resolve(a.first().unwrap_or(&Obj::Null)),
                _ => Obj::Null,
            };
        }
    }

    fn actions(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) {
        let open = doc.key(catalog, "OpenAction");
        if open.as_dict().is_some() {
            self.action(doc, &open, "OpenAction");
        }
        if let Obj::Dict(aa) = doc.key(catalog, "AA") {
            for (k, v) in &aa.0 {
                let a = doc.resolve(v);
                self.action(doc, &a, &format!("document AA/{k}"));
            }
        }
    }

    fn forms(&mut self, doc: &mut Doc<'_, '_>, catalog: &Dict) -> Result<(), ExtractError> {
        let form = doc.key(catalog, "AcroForm");
        let Some(form) = form.as_dict().cloned() else { return Ok(()) };
        let mut fields = Vec::new();
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        let mut total = 0u64;
        let mut seen = HashSet::new();
        let mut stack: Vec<(Obj, String, Option<String>)> = doc
            .key(&form, "Fields")
            .as_array()
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|f| (f.clone(), String::new(), None))
            .collect();
        while let Some((f, prefix, inherited_ft)) = stack.pop() {
            doc.cx.checkpoint()?;
            if let Obj::Ref(n, _) = f
                && !seen.insert(n)
            {
                continue;
            }
            let obj = doc.resolve(&f);
            let Some(d) = obj.as_dict() else { continue };
            let partial = str_of(&doc.key(d, "T"));
            let name = match (&partial, prefix.is_empty()) {
                (Some(p), true) => p.clone(),
                (Some(p), false) => format!("{prefix}.{p}"),
                (None, _) => prefix.clone(),
            };
            let ft = d.name("FT").map(str::to_string).or(inherited_ft);
            let kids = doc.key(d, "Kids");
            let has_field_kids = kids.as_array().is_some_and(|k| {
                k.iter().any(|kid| {
                    let o = doc.resolve(kid);
                    o.as_dict().is_some_and(|kd| kd.has("T"))
                })
            });
            if let Some(a) = d.get("AA").map(|a| doc.resolve(a))
                && let Some(aa) = a.as_dict()
            {
                for (k, v) in &aa.0 {
                    let act = doc.resolve(v);
                    self.action(doc, &act, &format!("field AA/{k}"));
                }
            }
            if has_field_kids {
                for k in kids.as_array().unwrap_or_default().iter().rev() {
                    stack.push((k.clone(), name.clone(), ft.clone()));
                }
                continue;
            }
            total += 1;
            let kind = match ft.as_deref() {
                Some("Tx") => "text",
                Some("Btn") => "button",
                Some("Ch") => "choice",
                Some("Sig") => "signature",
                _ => "other",
            };
            *types.entry(kind.into()).or_default() += 1;
            if kind == "signature" {
                let v = doc.key(d, "V");
                if let Some(sig) = v.as_dict() {
                    self.signature(doc, sig, &name);
                }
            }
            if fields.len() < MAX_LISTED && !name.is_empty() {
                fields.push(json!({ "name": truncate_chars(&name, 200), "type": kind }));
            }
            if seen.len() > 100_000 {
                break;
            }
        }
        let mut m = Map::new();
        m.insert("fields".into(), json!(total));
        if !types.is_empty() {
            m.insert("field_types".into(), json!(types));
        }
        if !fields.is_empty() {
            m.insert("field_list".into(), Value::Array(fields));
        }
        if let Some(flags) = form.int("SigFlags").filter(|&f| f != 0) {
            m.insert("sig_flags".into(), json!(flags));
        }
        if form.get("NeedAppearances").and_then(Obj::as_bool) == Some(true) {
            m.insert("need_appearances".into(), json!(true));
        }
        if form.has("XFA") {
            m.insert("xfa".into(), json!(true));
            doc.cx.security().active_content("xfa_forms");
        }
        if total > 0 {
            doc.cx.security().active_content("forms");
        }
        self.format.insert("acroform".into(), Value::Object(m));
        Ok(())
    }

    fn signature(&mut self, doc: &mut Doc<'_, '_>, sig: &Dict, field: &str) {
        if self.signatures.len() >= 50 {
            return;
        }
        let mut m = Map::new();
        m.insert("field".into(), json!(truncate_chars(field, 200)));
        if let Some(f) = sig.name("Filter") {
            m.insert("filter".into(), json!(f));
        }
        if let Some(sf) = sig.name("SubFilter") {
            m.insert("sub_filter".into(), json!(sf));
        }
        if let Some((t, _)) = str_of(&doc.key(sig, "M")).as_deref().and_then(pdf_date) {
            m.insert("signing_time".into(), json!(t));
        }
        for (key, out) in [("Reason", "reason"), ("Location", "location")] {
            if let Some(v) = str_of(&doc.key(sig, key)) {
                m.insert(out.into(), json!(truncate_chars(&v, 200)));
            }
        }
        if !doc.cx.privacy_strict()
            && let Some(name) = str_of(&doc.key(sig, "Name"))
        {
            m.insert("signer".into(), json!(truncate_chars(&name, 200)));
        }
        if let Some(c) = sig.get("Contents").and_then(Obj::as_str) {
            m.insert("contents_bytes".into(), json!(c.len()));
        }
        if sig.name("Type") == Some("DocTimeStamp") || sig.name("SubFilter") == Some("ETSI.RFC3161") {
            m.insert("timestamp".into(), json!(true));
        }
        self.signatures.push(Value::Object(m));
    }

    /// One pass over every object: fonts, images, annotations and actions
    /// not reachable from the catalog's usual places.
    fn objects(&mut self, doc: &mut Doc<'_, '_>) -> Result<(), ExtractError> {
        let nums = doc.numbers();
        if nums.len() > MAX_SCANNED {
            doc.cx.warn(format!("{} objects; scanned the first {MAX_SCANNED}", nums.len()));
        }
        for (i, n) in nums.into_iter().take(MAX_SCANNED).enumerate() {
            if i.is_multiple_of(512) {
                doc.cx.checkpoint()?;
            }
            let obj = doc.get(n);
            let Some(d) = obj.as_dict() else { continue };
            let subtype = d.name("Subtype");
            match d.name("Type") {
                Some("Font") | None if d.has("BaseFont") => self.font(doc, d),
                Some("XObject") | None if subtype == Some("Image") && matches!(obj, Obj::Stream(..)) => {
                    self.images += 1;
                }
                Some("Annot") | None if subtype.is_some() && (d.has("Rect") || d.name("Type") == Some("Annot")) => {
                    let st = subtype.unwrap_or_default().to_string();
                    if self.annotations.len() < 64 || self.annotations.contains_key(&st) {
                        *self.annotations.entry(st.clone()).or_default() += 1;
                    }
                    match st.as_str() {
                        "FileAttachment" => {
                            if let Some(fs) = d.get("FS").cloned() {
                                self.file_spec(doc, &fs, None);
                            }
                        }
                        "RichMedia" | "Screen" | "Movie" | "Sound" | "3D" => self.rich_media += 1,
                        _ => {}
                    }
                    if let Some(a) = d.get("A").map(|a| doc.resolve(a)) {
                        self.action(doc, &a, &format!("{st} annotation"));
                    }
                    if let Some(aa) = d.get("AA").map(|a| doc.resolve(a))
                        && let Some(aa) = aa.as_dict()
                    {
                        for (k, v) in &aa.0 {
                            let act = doc.resolve(v);
                            self.action(doc, &act, &format!("{st} annotation AA/{k}"));
                        }
                    }
                }
                Some("Page") => {
                    if let Some(aa) = d.get("AA").map(|a| doc.resolve(a))
                        && let Some(aa) = aa.as_dict()
                    {
                        for (k, v) in &aa.0 {
                            let act = doc.resolve(v);
                            self.action(doc, &act, &format!("page AA/{k}"));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn font(&mut self, doc: &mut Doc<'_, '_>, d: &Dict) {
        let Some(base) = d.name("BaseFont") else { return };
        let (subset, name) = match base.split_once('+') {
            Some((tag, rest)) if tag.len() == 6 && tag.chars().all(|c| c.is_ascii_uppercase()) => (true, rest),
            _ => (false, base),
        };
        if self.fonts.len() >= MAX_LISTED || self.fonts.contains_key(name) {
            return;
        }
        let descriptor = match d.name("Subtype") {
            Some("Type0") => {
                let df = doc.key(d, "DescendantFonts");
                let first = df.as_array().and_then(|a| a.first()).map(|f| doc.resolve(f));
                first.and_then(|f| f.as_dict().map(|fd| doc.key(fd, "FontDescriptor")))
            }
            _ => Some(doc.key(d, "FontDescriptor")),
        };
        let embedded = descriptor
            .as_ref()
            .and_then(Obj::as_dict)
            .is_some_and(|fd| fd.has("FontFile") || fd.has("FontFile2") || fd.has("FontFile3"));
        let mut m = Map::new();
        if let Some(st) = d.name("Subtype") {
            m.insert("type".into(), json!(st));
        }
        m.insert("embedded".into(), json!(embedded));
        if subset {
            m.insert("subset".into(), json!(true));
        }
        self.fonts.insert(name.to_string(), Value::Object(m));
    }

    fn text(&mut self, doc: &mut Doc<'_, '_>, pages: &[Page]) -> Result<(), ExtractError> {
        let mut fonts = text::Fonts::default();
        let budget = doc.cx.options().limits.max_text_bytes;
        let mut total = 0usize;
        let mut with_text = 0u64;
        for (i, p) in pages.iter().enumerate() {
            if i >= MAX_TEXT_PAGES || total > budget {
                doc.cx.warn(format!("text read from the first {i} pages"));
                break;
            }
            doc.cx.checkpoint()?;
            let t = match text::page_text(doc, &mut fonts, &p.dict, &p.resources) {
                Ok(t) => t,
                Err(ExtractError::LimitExceeded(e)) => return Err(ExtractError::LimitExceeded(e)),
                Err(e) => {
                    doc.cx.warn(format!("page {}: {e}", i + 1));
                    continue;
                }
            };
            if !t.trim().is_empty() {
                with_text += 1;
                total += t.len();
                doc.cx.emit_text(TextRole::Body, &t);
            }
        }
        if !pages.is_empty() {
            self.format.insert("pages_with_text".into(), json!(with_text));
            if with_text == 0 && self.images > 0 {
                self.format.insert("scanned".into(), json!(true));
            }
        }
        Ok(())
    }

    fn finish(mut self, doc: &mut Doc<'_, '_>) {
        // Embedded files: children when recursion is on.
        let recurse = doc.cx.options().limits.max_depth > 0;
        let mut names = Vec::new();
        let mut risky = Vec::new();
        for (name, stream) in std::mem::take(&mut self.embedded) {
            if crate::plugin::risky_file_name(&name).is_some() {
                risky.push(name.clone());
            }
            names.push(json!(truncate_chars(&name, 200)));
            if recurse
                && !matches!(stream, Obj::Null)
                && let Ok(data) = doc.stream_of(&stream, doc.cx.parse_limit())
                && doc.cx.emit_child(&name, data).is_err()
            {
                break;
            }
        }
        let cx = &mut *doc.cx;
        if !names.is_empty() {
            cx.security().active_content("embedded_files");
            self.format.insert("embedded_files".into(), Value::Array(names));
        }
        if !risky.is_empty() {
            cx.security().risk("executable_attachment", Some(truncate_chars(&risky.join(", "), 200)));
        }
        if !self.javascript.is_empty() {
            let mut where_: Vec<String> = self.javascript.clone();
            where_.dedup();
            cx.security()
                .active_content("javascript")
                .risk("javascript", Some(truncate_chars(&where_.join(", "), 200)));
            self.format.insert("javascript_actions".into(), json!(self.javascript.len()));
        }
        if !self.auto_actions.is_empty() {
            cx.security().risk("auto_action", Some(truncate_chars(&self.auto_actions.join(", "), 200)));
        }
        if !self.launch.is_empty() {
            cx.security()
                .active_content("launch_actions")
                .risk("launch_action", Some(truncate_chars(&self.launch.join(", "), 200)));
        }
        if !self.submit.is_empty() {
            cx.security().risk("form_submission", Some(truncate_chars(&self.submit.join(", "), 200)));
        }
        if !self.remote.is_empty() {
            cx.security().risk("remote_goto", Some(truncate_chars(&self.remote.join(", "), 200)));
        }
        if self.rich_media > 0 {
            cx.security().active_content("rich_media");
        }
        if self.uri_count > 0 {
            cx.security().external_references(self.uri_count);
            self.format.insert("links".into(), json!(self.uris));
        }
        if !self.signatures.is_empty() {
            cx.security().signed(true);
            self.format.insert("signatures".into(), Value::Array(std::mem::take(&mut self.signatures)));
        }
        if !self.fonts.is_empty() {
            self.format.insert("fonts".into(), json!(self.fonts));
        }
        if self.images > 0 {
            self.format.insert("images".into(), json!(self.images));
        }
        if !self.annotations.is_empty() {
            self.format.insert("annotations".into(), json!(self.annotations));
        }
        if !self.info.is_empty() {
            for k in ["Creator", "Producer"] {
                if let Some(v) = self.info.get(k).and_then(Value::as_str) {
                    self.format.insert(k.to_ascii_lowercase(), json!(v));
                }
            }
            if let Some(t) = self.info.get("Trapped") {
                self.format.insert("trapped".into(), t.clone());
            }
            cx.metadata("pdf_info").extend(std::mem::take(&mut self.info));
        }
        cx.format().extend(self.format);
    }
}

/// Triggers that run without the reader clicking anything.
fn is_automatic(trigger: &str) -> bool {
    trigger == "OpenAction"
        || trigger.starts_with("document AA/")
        || trigger.starts_with("page AA/O")
        || trigger.ends_with("AA/PO")
        || trigger.ends_with("AA/PV")
}

/// FDF: the `/FDF` dictionary's fields and target file.
fn extract_fdf(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut doc = Doc::open(src, cx)?;
    let trailer = doc.trailer.clone();
    let root = doc.key(&trailer, "Root");
    let fdf = root.as_dict().map_or(Obj::Null, |r| doc.key(r, "FDF"));
    let Some(fdf) = fdf.as_dict().cloned() else { return Err(ExtractError::malformed("no /FDF dictionary")) };
    let mut fields = Vec::new();
    let mut total = 0u64;
    let mut stack: Vec<(Obj, String)> = doc
        .key(&fdf, "Fields")
        .as_array()
        .unwrap_or_default()
        .iter()
        .rev()
        .map(|f| (f.clone(), String::new()))
        .collect();
    while let Some((f, prefix)) = stack.pop() {
        if total > 100_000 {
            break;
        }
        let f = doc.resolve(&f);
        let Some(d) = f.as_dict() else { continue };
        let t = str_of(&doc.key(d, "T")).unwrap_or_default();
        let name = if prefix.is_empty() { t } else { format!("{prefix}.{t}") };
        if let Some(kids) = doc.key(d, "Kids").as_array() {
            stack.extend(kids.iter().rev().map(|k| (k.clone(), name.clone())));
            continue;
        }
        total += 1;
        if fields.len() < MAX_LISTED {
            fields.push(json!(truncate_chars(&name, 200)));
        }
    }
    let file =
        str_of(&doc.key(&fdf, "F")).or_else(|| doc.key(&fdf, "F").as_dict().and_then(|d| d.get("F").and_then(str_of)));
    let cx = &mut *doc.cx;
    if let Some(v) = &doc.version {
        cx.format_set("version", v.clone());
    }
    cx.format_set("fields", total);
    if !fields.is_empty() {
        cx.format_set("field_names", Value::Array(fields));
    }
    if let Some(f) = file {
        cx.format_set("target_file", truncate_chars(&f, 300));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_dates() {
        assert_eq!(pdf_date("D:20240501083000+02'00'"), Some(("2024-05-01T08:30:00+02:00".into(), true)));
        assert_eq!(pdf_date("D:20240501083000Z"), Some(("2024-05-01T08:30:00+00:00".into(), true)));
        assert_eq!(pdf_date("D:2024"), Some(("2024-01-01T00:00:00".into(), false)));
    }

    #[test]
    fn paper_sizes() {
        assert_eq!(paper_name(595.0, 842.0), Some("A4"));
        assert_eq!(paper_name(792.0, 612.0), Some("Letter"));
        assert_eq!(paper_name(500.0, 500.0), None);
    }

    #[test]
    fn automatic_triggers() {
        assert!(is_automatic("OpenAction"));
        assert!(is_automatic("page AA/O"));
        assert!(!is_automatic("Link annotation"));
    }

    /// A PDF from object bodies (object `i + 1` is `objects[i]`), catalog = 1.
    fn build(objects: &[&str], xref: bool) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
        }
        let at = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
        for o in &offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        let start = if xref { at } else { at + 7 };
        out.extend_from_slice(
            format!("trailer\n<< /Size {} /Root 1 0 R /Info 2 0 R >>\nstartxref\n{start}\n%%EOF\n", objects.len() + 1)
                .as_bytes(),
        );
        out
    }

    const PAGE: &str = "<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>";
    const FONT: &str = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
    const CONTENT: &str = "<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 700 Td (Harbour notes) Tj ET\nendstream";

    fn risks(r: &crate::plugin::Report) -> Vec<&str> {
        r.security.risks.iter().map(|x| x.kind.as_str()).collect()
    }

    #[test]
    fn flags_document_javascript_and_launch_actions() {
        let pdf = build(
            &[
                "<< /Type /Catalog /Pages 3 0 R /OpenAction 7 0 R >>",
                "<< /Title (Harbour notes) >>",
                "<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
                PAGE,
                FONT,
                CONTENT,
                "<< /S /JavaScript /JS (console.println\\(\"ready\"\\);) /Next 8 0 R >>",
                "<< /S /Launch /F (notes.txt) >>",
            ],
            true,
        );
        let r = crate::plugin::testing::report_for("notes.pdf", &pdf);
        assert_eq!(r.content.title.as_deref(), Some("Harbour notes"));
        let kinds = risks(&r);
        for k in ["javascript", "auto_action", "launch_action"] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
        assert!(r.security.active_content.iter().any(|a| a == "javascript"));
    }

    #[test]
    fn reads_form_fields_and_signatures() {
        let pdf = build(
            &[
                "<< /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [7 0 R 8 0 R] /SigFlags 3 >> >>",
                "<< >>",
                "<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
                PAGE,
                FONT,
                CONTENT,
                "<< /FT /Tx /T (berth) /V (5) >>",
                "<< /FT /Sig /T (harbourmaster) /V 9 0 R >>",
                "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /M (D:20240501083000Z) /Reason (Approved) /Contents <3082> >>",
            ],
            true,
        );
        let r = crate::plugin::testing::report_for("form.pdf", &pdf);
        assert_eq!(r.security.signed, Some(true));
        let pdf_format = &r.format["pdf"];
        assert_eq!(pdf_format["acroform"]["fields"], 2);
        assert_eq!(pdf_format["signatures"][0]["reason"], "Approved");
        assert_eq!(pdf_format["signatures"][0]["signing_time"], "2024-05-01T08:30:00+00:00");
    }

    #[test]
    fn repairs_a_wrong_startxref() {
        let pdf = build(
            &[
                "<< /Type /Catalog /Pages 3 0 R >>",
                "<< /Title (Harbour notes) >>",
                "<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
                PAGE,
                FONT,
                CONTENT,
            ],
            false,
        );
        let r = crate::plugin::testing::report_for("broken.pdf", &pdf);
        assert_eq!(r.format["pdf"]["repaired"], true);
        assert_eq!(r.content.title.as_deref(), Some("Harbour notes"));
        assert_eq!(r.physical.document.as_ref().and_then(|d| d.pages), Some(1));
    }

    crate::fixture_tests!("pdf", "fdf");
}
