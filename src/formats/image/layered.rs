//! Layered image and design documents:
//! * Krita (`.kra`) and OpenRaster (`.ora`), zip packages: canvas size,
//!   resolution, colour space, the layer tree (names, kinds, visibility),
//!   and Krita's document information (title, author, dates, licence);
//! * Paint Shop Pro (`.pspimage`, `.psp`): version, size, resolution, bit
//!   depth, compression, layers (with names), and the creator block (title,
//!   artist, copyright, description, dates);
//! * Paint.NET (`.pdn`): size, layer count, the version that saved it and
//!   the thumbnail, from the XML header;
//! * Procreate (`.procreate`): canvas size, DPI, layers, tracked time, from
//!   the keyed-archive `Document.archive`;
//! * Sketch (`.sketch`): app version, pages and artboards, fonts;
//! * Figma (`.fig`, the raw `fig-kiwi` canvas or the zip export): version,
//!   chunks, the export's file name and thumbnail;
//! * Affinity Photo / Designer / Publisher: by extension only (the format
//!   is undocumented): header bytes and the embedded PNG thumbnail's size.
//!
//! References: Krita "KRA file format" (docs.krita.org); OpenRaster 0.0.6
//! specification; Jasc "Paint Shop Pro File Format Specification" 5/7/8;
//! Paint.NET file header notes; Sketch "File format" developer docs;
//! Procreate keyed archive layout as documented by its community tools.

use plist::Value as Plist;
use serde_json::{Map, Value, json};

use crate::plugin::xmlwalk::{Ev, attr, walk};
use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, Zip, latin1_or_utf8, proplist, truncate_chars, zip_first_stored, zip_names,
};

/// Extractor for layered documents.
pub struct Layered;

const fn layered(
    id: &'static str,
    name: &'static str,
    mimes: &'static [&'static str],
    ext: &'static [&'static str],
    magic: &'static [Magic],
    parent: Option<&'static str>,
) -> FormatSpec {
    FormatSpec { id, name, family: "image.layered", mimes, extensions: ext, magic, parent }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.layered",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        layered("krita", "Krita document", &["application/x-krita"], &["kra", "krz"], &[], Some("zip")),
        layered("openraster", "OpenRaster image", &["image/openraster"], &["ora"], &[], Some("zip")),
        layered(
            "psp",
            "Paint Shop Pro image",
            &["image/x-paintshoppro"],
            &["pspimage", "psp", "pspframe", "psptube", "pspbrush", "tub"],
            &[Magic::prefix(b"Paint Shop Pro Image File\n\x1a")],
            None,
        ),
        layered("pdn", "Paint.NET image", &[], &["pdn"], &[Magic::prefix(b"PDN3")], None),
        layered("procreate", "Procreate artwork", &[], &["procreate"], &[], Some("zip")),
        layered("sketch", "Sketch document", &[], &["sketch"], &[], Some("zip")),
        // The raw canvas (`fig-kiwi`) or a zip export: both found by `sniff`.
        layered("figma", "Figma document", &[], &["fig"], &[], None),
        layered("affinity", "Affinity document", &[], &["afphoto", "afdesign", "afpub"], &[], None),
    ],
};

const MAX_LISTED: usize = 200;
/// XML / JSON parts read at most.
const MAX_PART: usize = 32 << 20;
/// Bytes searched for an Affinity thumbnail.
const MAX_SEARCH: u64 = 8 << 20;

impl Extractor for Layered {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(b"fig-kiwi") {
            return Some(Sniff { format: "figma", confidence: 0.97 });
        }
        if let Some(m) = zip_first_stored(probe.head, "mimetype") {
            let f = match m {
                b"application/x-krita" => "krita",
                b"image/openraster" => "openraster",
                _ => return None,
            };
            return Some(Sniff { format: f, confidence: 0.97 });
        }
        if probe.head.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 4000);
            let has = |n: &str| names.iter().any(|x| x == n);
            if has("Document.archive") {
                return Some(Sniff { format: "procreate", confidence: 0.95 });
            }
            if has("document.json") && has("meta.json") {
                return Some(Sniff { format: "sketch", confidence: 0.95 });
            }
            if has("canvas.fig") {
                return Some(Sniff { format: "figma", confidence: 0.95 });
            }
            if probe.extension == Some("kra") && has("maindoc.xml") {
                return Some(Sniff { format: "krita", confidence: 0.9 });
            }
            if probe.extension == Some("ora") && has("stack.xml") {
                return Some(Sniff { format: "openraster", confidence: 0.9 });
            }
        }
        matches!(probe.extension, Some("afphoto" | "afdesign" | "afpub"))
            .then_some(Sniff { format: "affinity", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "krita" => krita(src, cx),
            "openraster" => openraster(src, cx),
            "psp" => psp(src, cx),
            "pdn" => pdn(src, cx),
            "procreate" => procreate(src, cx),
            "sketch" => sketch(src, cx),
            "figma" => figma(src, cx),
            "affinity" => affinity(src, cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Layered);

fn text_part(
    zip: &Zip,
    src: &mut dyn Source,
    name: &str,
    cx: &mut Context<'_>,
) -> Result<Option<String>, ExtractError> {
    zip.read_text(src, name, cx, MAX_PART).transpose()
}

/// The size of a PNG from its IHDR.
fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if !b.starts_with(b"\x89PNG\r\n\x1a\n") || b.get(12..16)? != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes(b.get(16..20)?.try_into().ok()?);
    let h = u32::from_be_bytes(b.get(20..24)?.try_into().ok()?);
    Some((w, h))
}

fn thumbnail(zip: &Zip, src: &mut dyn Source, names: &[&str], cx: &mut Context<'_>) {
    for n in names {
        if let Some(e) = zip.find(n)
            && let Ok((b, _)) = zip.read_prefix(src, e, cx, 64)
            && let Some((w, h)) = png_size(&b)
        {
            cx.format_set("thumbnail", json!({ "name": n, "width": w, "height": h }));
            return;
        }
    }
}

#[derive(Default)]
struct Layers {
    list: Vec<Value>,
    count: u64,
    hidden: u64,
    groups: u64,
}

impl Layers {
    fn add(&mut self, name: &str, kind: &str, visible: bool, depth: usize) {
        self.count += 1;
        if !visible {
            self.hidden += 1;
        }
        if kind == "group" {
            self.groups += 1;
        }
        if self.list.len() < MAX_LISTED {
            self.list
                .push(json!({ "name": truncate_chars(name, 200), "kind": kind, "visible": visible, "depth": depth }));
        }
    }
    fn report(self, cx: &mut Context<'_>) {
        cx.format_set("layer_count", self.count);
        cx.format_set("hidden_layers", self.hidden);
        cx.format_set("groups", self.groups);
        let names: Vec<String> = self.list.iter().filter_map(|l| l["name"].as_str().map(str::to_string)).collect();
        if !names.is_empty() {
            cx.emit_text(crate::plugin::TextRole::Metadata, &names.join("\n"));
        }
        cx.format_set("layers", Value::Array(self.list));
    }
}

// ---- Krita / OpenRaster ---------------------------------------------------------------

fn krita(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let doc = text_part(&zip, src, "maindoc.xml", cx)?.ok_or_else(|| ExtractError::malformed("no maindoc.xml"))?;
    let mut layers = Layers::default();
    let mut depth = 0usize;
    let mut image = Map::new();
    walk(&doc, cx, 2_000_000, |_, ev| match ev {
        Ev::Start("DOC", a) => {
            for k in ["editor", "kritaVersion", "syntaxVersion"] {
                if let Some(v) = attr(a, k) {
                    image.insert(k.into(), json!(v));
                }
            }
        }
        Ev::Start("IMAGE", a) if !image.contains_key("width") => {
            for k in ["name", "width", "height", "colorspacename", "profile", "x-res", "y-res", "description"] {
                if let Some(v) = attr(a, k) {
                    image.insert(k.into(), json!(v));
                }
            }
        }
        Ev::Start("layers", _) => depth += 1,
        Ev::End("layers") => depth = depth.saturating_sub(1),
        Ev::Start("layer" | "mask", a) => {
            let kind = match attr(a, "nodetype").unwrap_or("") {
                "paintlayer" => "paint",
                "grouplayer" => "group",
                "adjustmentlayer" => "adjustment",
                "shapelayer" => "vector",
                "filelayer" => "file",
                "generatorlayer" => "fill",
                "clonelayer" => "clone",
                "transparencymask" | "filtermask" | "transformmask" | "selectionmask" | "colorizemask" => "mask",
                _ => "other",
            };
            layers.add(attr(a, "name").unwrap_or(""), kind, attr(a, "visible") != Some("0"), depth.saturating_sub(1));
        }
        _ => {}
    })?;
    let num = |k: &str| image.get(k).and_then(Value::as_str).and_then(|v| v.parse::<f64>().ok());
    if let (Some(w), Some(h)) = (num("width"), num("height")) {
        let mut img = cx.physical().image(super::px(w), super::px(h));
        if let Some(cs) = image.get("colorspacename").and_then(Value::as_str) {
            img.color_space(cs);
            let (ch, bits) = colour_model(cs);
            img.channels(ch);
            if bits > 0 {
                img.bit_depth(bits);
            }
        }
        if let (Some(x), Some(y)) = (num("x-res"), num("y-res")) {
            img.dpi(x, y);
        }
    }
    if let Some(n) = image.get("name").and_then(Value::as_str).filter(|n| !n.is_empty() && *n != "Unnamed") {
        cx.content().source("krita.IMAGE.name").title(n);
    }
    cx.format_set("document", Value::Object(image));
    layers.report(cx);
    if let Some(info) = text_part(&zip, src, "documentinfo.xml", cx)? {
        krita_info(&info, cx)?;
    }
    thumbnail(&zip, src, &["preview.png", "mergedimage.png"], cx);
    Ok(())
}

/// Channels and bits per channel of a Krita colour space id (`RGBA`, `RGBA16`, `GRAYAF32`…).
fn colour_model(cs: &str) -> (u8, u8) {
    let ch = if cs.starts_with("CMYK") {
        5
    } else if cs.starts_with("GRAY") {
        2
    } else {
        4
    };
    let bits = if cs.ends_with("F32") {
        32
    } else if cs.ends_with("16") || cs.ends_with("F16") {
        16
    } else if cs.ends_with('U') || cs.ends_with('A') {
        8
    } else {
        0
    };
    (ch, bits)
}

fn krita_info(info: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    walk(info, cx, 100_000, |_, ev| match ev {
        Ev::Start(n, _) => path.push(n.to_string()),
        Ev::End(_) => {
            path.pop();
        }
        Ev::Text(t) => {
            if let Some(k) = path.last()
                && fields.len() < 64
            {
                fields.push((k.clone(), t.to_string()));
            }
        }
    })?;
    let mut out = Map::new();
    for (k, v) in &fields {
        match k.as_str() {
            "title" => {
                cx.content().source("krita.documentinfo.title").title(truncate_chars(v, 300));
            }
            "description" | "abstract" => {
                cx.content().source("krita.documentinfo.description").description(truncate_chars(v, 1000));
            }
            "keyword" => {
                for w in v.split([',', ' ']).filter(|w| !w.is_empty()) {
                    cx.content().source("krita.documentinfo.keyword").keyword(w);
                }
            }
            "full-name" | "initial-creator" => {
                cx.content().source("krita.documentinfo.author").author(truncate_chars(v, 200));
            }
            "creation-date" => {
                cx.temporal().source("krita.documentinfo.creation-date").content_date(DateField::Created, v, false);
            }
            "date" => {
                cx.temporal().source("krita.documentinfo.date").content_date(DateField::Modified, v, false);
            }
            "license" => {
                cx.rights().source("krita.documentinfo.license").license(Some(v), None);
            }
            _ => {}
        }
        if matches!(k.as_str(), "editing-cycles" | "editing-time" | "language" | "subject") {
            out.insert(k.clone(), json!(truncate_chars(v, 200)));
        }
    }
    if !out.is_empty() {
        cx.format_set("document_info", Value::Object(out));
    }
    Ok(())
}

fn openraster(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let stack = text_part(&zip, src, "stack.xml", cx)?.ok_or_else(|| ExtractError::malformed("no stack.xml"))?;
    let mut layers = Layers::default();
    let mut depth = 0usize;
    let mut image = None;
    walk(&stack, cx, 2_000_000, |cx, ev| match ev {
        Ev::Start("image", a) if image.is_none() => {
            let n = |k: &str| attr(a, k).and_then(|v| v.parse::<f64>().ok());
            if let (Some(w), Some(h)) = (n("w"), n("h")) {
                let mut img = cx.physical().image(super::px(w), super::px(h));
                if let (Some(x), Some(y)) = (n("xres"), n("yres")) {
                    img.dpi(x, y);
                }
            }
            image = Some(attr(a, "version").unwrap_or("").to_string());
        }
        Ev::Start("stack", a) => {
            if depth > 0 {
                layers.add(attr(a, "name").unwrap_or(""), "group", attr(a, "visibility") != Some("hidden"), depth - 1);
            }
            depth += 1;
        }
        Ev::End("stack") => depth = depth.saturating_sub(1),
        Ev::Start("layer", a) => {
            let kind = if attr(a, "src").is_some_and(|s| s.to_ascii_lowercase().ends_with(".svg")) {
                "vector"
            } else {
                "raster"
            };
            layers.add(
                attr(a, "name").unwrap_or(""),
                kind,
                attr(a, "visibility") != Some("hidden"),
                depth.saturating_sub(1),
            );
        }
        _ => {}
    })?;
    if let Some(v) = image.filter(|v| !v.is_empty()) {
        cx.format_set("version", v);
    }
    layers.report(cx);
    thumbnail(&zip, src, &["Thumbnails/thumbnail.png", "mergedimage.png"], cx);
    Ok(())
}

// ---- Paint Shop Pro ---------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one walk over the main blocks
fn psp(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let n = usize::try_from(src.len().min(64 << 20)).unwrap_or(0);
    let d = src.read_vec(0, n)?;
    let mut r = ByteReader::new(&d).skip(32)?;
    let (major, minor) = (r.le_u16()?, r.le_u16()?);
    cx.format_set("version", format!("{major}.{minor}"));
    let old = major < 4;
    let mut layers = Layers::default();
    let mut blocks = Vec::new();
    while r.remaining() >= 10 && blocks.len() < 1000 {
        r.tag(b"~BK\0")?;
        let id = r.le_u16()?;
        if old {
            r.advance(4)?;
        }
        let len = r.le_u32()? as usize;
        let body = r.bytes(len.min(r.remaining()))?;
        blocks.push(json!(psp_block(id)));
        match id {
            0 => {
                let mut b = ByteReader::new(body);
                if !old {
                    b.advance(4)?;
                }
                let (w, h) = (b.le_i32()?, b.le_i32()?);
                let res = f64::from_bits(b.le_u64()?);
                let metric = b.u8()?;
                let compression = b.le_u16()?;
                let bits = b.le_u16()?;
                let _planes = b.le_u16()?;
                let _colors = b.le_u32()?;
                let _grey = b.u8()?;
                b.advance(4)?;
                let _active = b.le_i32()?;
                let count = b.le_u16()?;
                let mut img = cx.physical().image(u32::try_from(w).unwrap_or(0), u32::try_from(h).unwrap_or(0));
                img.bit_depth(u8::try_from(bits.min(8)).unwrap_or(8));
                if res.is_finite() && res > 0.0 {
                    let dpi = if metric == 2 { res * 2.54 } else { res };
                    img.dpi(dpi, dpi);
                }
                cx.format_set("bit_depth_code", bits);
                cx.format_set(
                    "compression",
                    match compression {
                        0 => "none",
                        1 => "RLE",
                        2 => "LZ77",
                        3 => "JPEG",
                        _ => "unknown",
                    },
                );
                cx.format_set("layer_count_header", count);
            }
            // Creator block: `~FL\0` fields.
            1 => {
                let mut b = ByteReader::new(body);
                while b.remaining() >= 10 {
                    if b.tag(b"~FL\0").is_err() {
                        break;
                    }
                    let kw = b.le_u16()?;
                    let l = b.le_u32()? as usize;
                    let v = b.bytes(l.min(b.remaining()))?;
                    let text = || truncate_chars(latin1_or_utf8(v).trim_matches(['\0', ' ']), 1000);
                    let le32 = || v.get(..4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
                    match kw {
                        0 => {
                            cx.content().source("psp.creator.title").title(text());
                        }
                        1 | 2 => {
                            if let Some(t) =
                                le32().filter(|t| *t > 0).and_then(|t| super::super::archive::unix_time(i64::from(t)))
                            {
                                let f = if kw == 1 { DateField::Created } else { DateField::Modified };
                                cx.temporal().source("psp.creator.date").content_date(f, t, true);
                            }
                        }
                        3 => {
                            cx.content().source("psp.creator.artist").author(text());
                        }
                        4 => {
                            cx.rights().source("psp.creator.copyright").copyright(text());
                        }
                        5 => {
                            cx.content().source("psp.creator.description").description(text());
                        }
                        6 => cx.format_set(
                            "application",
                            match le32() {
                                Some(1) => "Paint Shop Pro",
                                _ => "unknown",
                            },
                        ),
                        7 => {
                            if let Some(v) = le32() {
                                cx.format_set("application_version", format!("{}.{}", v >> 24, (v >> 16) & 0xff));
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Layer bank: layer blocks (id 4) with their names.
            3 => {
                let mut b = ByteReader::new(body);
                while b.remaining() >= 10 && b.tag(b"~BK\0").is_ok() {
                    let sub = b.le_u16()?;
                    if old {
                        b.advance(4)?;
                    }
                    let l = b.le_u32()? as usize;
                    let lb = b.bytes(l.min(b.remaining()))?;
                    if sub == 4 {
                        let mut x = ByteReader::new(lb);
                        if !old {
                            x.advance(4)?;
                        }
                        let nl = usize::from(x.le_u16()?);
                        let name = latin1_or_utf8(x.bytes(nl.min(x.remaining()))?);
                        let kind = x.u8().unwrap_or(0);
                        // Layer flags follow the rectangles and opacity: keep the kind only.
                        layers.add(name.trim_end_matches('\0'), if kind == 2 { "vector" } else { "raster" }, true, 0);
                    }
                }
            }
            _ => {}
        }
    }
    cx.format_set("blocks", Value::Array(blocks));
    layers.report(cx);
    Ok(())
}

fn psp_block(id: u16) -> &'static str {
    match id {
        0 => "image attributes",
        1 => "creator",
        2 => "colour palette",
        3 => "layer bank",
        4 => "layer",
        5 => "channel",
        6 => "selection",
        7 => "alpha bank",
        8 => "alpha channel",
        9 => "composite image",
        10 => "extended data",
        11 => "tube",
        12 => "adjustment layer extension",
        13 => "vector layer extension",
        14 => "shape",
        15 => "paint style",
        16 => "composite image bank",
        17 => "composite attributes",
        18 => "JPEG",
        19 => "line style",
        20 => "table bank",
        _ => "other",
    }
}

// ---- Paint.NET ------------------------------------------------------------------------------

fn pdn(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head();
    let len = h.get(4..7).map_or(0, |b| u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16) as usize;
    let xml = String::from_utf8_lossy(&src.read_vec(7, len)?).into_owned();
    let mut found = false;
    walk(&xml, cx, 10_000, |cx, ev| match ev {
        Ev::Start("pdnImage", a) => {
            found = true;
            let n = |k: &str| attr(a, k).and_then(|v| v.parse::<u32>().ok());
            if let (Some(w), Some(h)) = (n("width"), n("height")) {
                cx.physical().image(w, h).channels(4).bit_depth(8);
            }
            if let Some(l) = n("layers") {
                cx.format_set("layer_count", l);
            }
            if let Some(v) = attr(a, "savedWithVersion") {
                cx.format_set("saved_with_version", v);
            }
        }
        Ev::Start("thumb", a) => {
            if let Some(png) = attr(a, "png").and_then(super::super::audio::vorbis::base64)
                && let Some((w, h)) = png_size(&png)
            {
                cx.format_set("thumbnail", json!({ "width": w, "height": h }));
            }
        }
        _ => {}
    })?;
    if !found {
        return Err(ExtractError::malformed("no pdnImage header"));
    }
    let after = src.read_vec(7 + len as u64, 2).unwrap_or_default();
    cx.format_set(
        "body",
        match after.as_slice() {
            [0x00, 0x01] => "BinaryFormatter",
            [0x1f, 0x8b] => "gzip",
            _ => "unknown",
        },
    );
    Ok(())
}

// ---- Procreate ------------------------------------------------------------------------------

/// Resolve a keyed-archive UID to its object.
fn deref<'a>(objects: &'a [Plist], v: &'a Plist) -> &'a Plist {
    match v {
        Plist::Uid(u) => objects.get(usize::try_from(u.get()).unwrap_or(usize::MAX)).unwrap_or(v),
        _ => v,
    }
}

fn procreate(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let e = zip.find("Document.archive").ok_or_else(|| ExtractError::malformed("no Document.archive"))?.clone();
    let (data, _) = zip.read_prefix(src, &e, cx, MAX_PART)?;
    let (root, _) = proplist::parse(&data).ok_or_else(|| ExtractError::malformed("Document.archive is not a plist"))?;
    let objects = root
        .as_dictionary()
        .and_then(|d| d.get("$objects"))
        .and_then(Plist::as_array)
        .ok_or_else(|| ExtractError::malformed("no $objects"))?;
    let top = root
        .as_dictionary()
        .and_then(|d| d.get("$top"))
        .and_then(Plist::as_dictionary)
        .and_then(|t| t.get("root"))
        .ok_or_else(|| ExtractError::malformed("no $top root"))?;
    let doc = deref(objects, top).as_dictionary().ok_or_else(|| ExtractError::malformed("root is not a dictionary"))?;
    let get = |k: &str| doc.get(k).map(|v| deref(objects, v));
    if let Some(s) = get("size").and_then(Plist::as_string) {
        let n: Vec<u32> =
            s.trim_matches(['{', '}']).split(',').filter_map(|x| x.trim().parse::<f64>().ok()).map(super::px).collect();
        if let [w, h] = n[..] {
            let mut img = cx.physical().image(w, h);
            if let Some(dpi) = get("SilicaDocumentArchiveDPIKey")
                .and_then(|v| v.as_real().or_else(|| v.as_signed_integer().map(|i| i as f64)))
            {
                img.dpi(dpi, dpi);
            }
        }
    }
    if let Some(n) = get("name").and_then(Plist::as_string).filter(|n| !n.is_empty()) {
        cx.content().source("procreate.name").title(truncate_chars(n, 300));
    }
    for (k, out) in [
        ("SilicaDocumentTrackedTimeKey", "tracked_time_s"),
        ("SilicaDocumentArchiveVersion", "archive_version"),
        ("orientation", "orientation"),
    ] {
        if let Some(v) = get(k).and_then(|v| v.as_real().or_else(|| v.as_signed_integer().map(|i| i as f64))) {
            cx.format_set(out, v);
        }
    }
    if let Some(v) = get("SilicaDocumentVideoPurged").and_then(Plist::as_boolean) {
        cx.format_set("video_purged", v);
    }
    let mut layers = Layers::default();
    if let Some(list) =
        get("layers").and_then(Plist::as_dictionary).and_then(|d| d.get("NS.objects")).and_then(Plist::as_array)
    {
        for l in list {
            let Some(l) = deref(objects, l).as_dictionary() else { continue };
            let name = l.get("name").map(|v| deref(objects, v)).and_then(Plist::as_string).unwrap_or("");
            let hidden = l.get("hidden").and_then(Plist::as_boolean).unwrap_or(false);
            layers.add(name, "raster", !hidden, 0);
        }
    }
    layers.report(cx);
    cx.format_set("time_lapse", zip.entries.iter().any(|e| e.name.starts_with("video/")));
    thumbnail(&zip, src, &["QuickLook/Thumbnail.png"], cx);
    Ok(())
}

// ---- Sketch ---------------------------------------------------------------------------------

fn sketch(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let meta = text_part(&zip, src, "meta.json", cx)?.ok_or_else(|| ExtractError::malformed("no meta.json"))?;
    let m: Value = serde_json::from_str(&meta).map_err(|e| ExtractError::malformed(format!("meta.json: {e}")))?;
    for (k, out) in [("app", "app"), ("appVersion", "app_version"), ("build", "build"), ("version", "format_version")] {
        if let Some(v) = m.get(k).filter(|v| !v.is_null()) {
            cx.format_set(out, v.clone());
        }
    }
    if let Some(c) = m.get("created").and_then(Value::as_object) {
        cx.format_set("created_with", json!({ "app_version": c.get("appVersion"), "build": c.get("build") }));
    }
    let mut pages = Vec::new();
    let mut artboards = 0u64;
    let mut names = Vec::new();
    if let Some(p) = m.get("pagesAndArtboards").and_then(Value::as_object) {
        for page in p.values().take(MAX_LISTED) {
            let name = page.get("name").and_then(Value::as_str).unwrap_or("");
            let boards: Vec<&str> = page
                .get("artboards")
                .and_then(Value::as_object)
                .map(|a| a.values().filter_map(|b| b.get("name").and_then(Value::as_str)).collect())
                .unwrap_or_default();
            artboards += boards.len() as u64;
            names.push(name.to_string());
            names.extend(boards.iter().map(|b| (*b).to_string()));
            pages.push(json!({ "name": name, "artboards": boards.iter().take(MAX_LISTED).collect::<Vec<_>>() }));
        }
    }
    cx.physical().pages(pages.len() as u64);
    cx.format_set("pages", Value::Array(pages));
    cx.format_set("artboards", artboards);
    if let Some(f) = m.get("fonts").and_then(Value::as_array) {
        cx.format_set("fonts", json!(f.iter().take(MAX_LISTED).collect::<Vec<_>>()));
    }
    if !names.is_empty() {
        cx.emit_text(crate::plugin::TextRole::Metadata, &names.join("\n"));
    }
    thumbnail(&zip, src, &["previews/preview.png"], cx);
    Ok(())
}

// ---- Figma / Affinity -----------------------------------------------------------------------

fn figma(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if src.head().starts_with(b"PK") {
        let zip = Zip::open(src, 100_000)?;
        cx.format_set("container", "zip");
        if let Some(meta) = text_part(&zip, src, "meta.json", cx)?
            && let Ok(m) = serde_json::from_str::<Value>(&meta)
        {
            if let Some(n) = m.get("file_name").and_then(Value::as_str) {
                cx.content().source("figma.meta.file_name").title(truncate_chars(n, 300));
            }
            if let Some(t) = m.get("exported_at").and_then(Value::as_str) {
                cx.temporal().source("figma.meta.exported_at").content_date(DateField::Modified, t, t.ends_with('Z'));
            }
        }
        cx.format_set("images", zip.entries.iter().filter(|e| e.name.starts_with("images/")).count());
        thumbnail(&zip, src, &["thumbnail.png"], cx);
        let Some(e) = zip.find("canvas.fig").cloned() else { return Ok(()) };
        let (head, _) = zip.read_prefix(src, &e, cx, 16)?;
        return figma_canvas(&head, e.size, cx);
    }
    let h = src.head().to_vec();
    figma_canvas(&h, src.len(), cx)
}

fn figma_canvas(h: &[u8], len: u64, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if !h.starts_with(b"fig-kiwi") {
        return Err(ExtractError::malformed("no fig-kiwi header"));
    }
    let v = ByteReader::new(h).skip(8)?.le_u32()?;
    cx.format_set("canvas_version", v);
    cx.format_set("canvas_bytes", len);
    Ok(())
}

fn affinity(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head();
    let sig = h.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    cx.format_set("header", sig);
    let n = usize::try_from(src.len().min(MAX_SEARCH)).unwrap_or(0);
    let d = src.read_vec(0, n)?;
    if let Some(i) = d.windows(8).position(|w| w == b"\x89PNG\r\n\x1a\n")
        && let Some((w, h)) = png_size(&d[i..])
    {
        cx.format_set("thumbnail", json!({ "offset": i, "width": w, "height": h }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krita_colour_models() {
        assert_eq!(colour_model("RGBA"), (4, 8));
        assert_eq!(colour_model("RGBA16"), (4, 16));
        assert_eq!(colour_model("GRAYAF32"), (2, 32));
        assert_eq!(colour_model("CMYKA"), (5, 8));
    }

    crate::fixture_tests!("krita", "openraster", "psp", "pdn", "procreate", "sketch", "figma", "affinity");
}
