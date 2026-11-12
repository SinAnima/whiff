//! HEIF / HEIC / AVIF / AVCI (H.264) / HEJ2 (JPEG 2000) still images and
//! sequences: brands, the primary
//! item's size, bit depth, rotation and colour (ICC or nclx), the item
//! catalogue (thumbnails, tiles, alpha / depth / HDR gain-map auxiliaries)
//! and the EXIF and XMP items, read through the item locations.
//!
//! Specifications: ISO/IEC 23008-12 (HEIF), ISO/IEC 14496-12, AV1 Image File Format.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};

use super::{boxes, find_box, fourcc, read_box, top_boxes};
use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source,
};

/// Extractor for HEIF, HEIC and AVIF.
pub struct Heif;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.heif",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "heic",
            name: "HEIC image",
            family: "image.raster",
            mimes: &["image/heic"],
            extensions: &["heic", "heics", "hif"],
            magic: &[
                Magic::at(4, b"ftypheic"),
                Magic::at(4, b"ftypheix"),
                Magic::at(4, b"ftyphevc"),
                Magic::at(4, b"ftyphevx"),
                Magic::at(4, b"ftypheim"),
                Magic::at(4, b"ftypheis"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "heif",
            name: "HEIF image",
            family: "image.raster",
            mimes: &["image/heif"],
            extensions: &["heif"],
            magic: &[Magic::at(4, b"ftypmif1"), Magic::at(4, b"ftypmsf1")],
            parent: None,
        },
        FormatSpec {
            id: "avif",
            name: "AVIF image",
            family: "image.raster",
            mimes: &["image/avif"],
            extensions: &["avif", "avifs"],
            magic: &[Magic::at(4, b"ftypavif"), Magic::at(4, b"ftypavis")],
            parent: None,
        },
        FormatSpec {
            id: "avci",
            name: "AVC-coded HEIF image",
            family: "image.raster",
            mimes: &["image/avci"],
            extensions: &["avci", "avcs"],
            magic: &[Magic::at(4, b"ftypavci"), Magic::at(4, b"ftypavcs")],
            parent: None,
        },
        FormatSpec {
            id: "hej2",
            name: "JPEG 2000 in HEIF",
            family: "image.raster",
            mimes: &["image/hej2k"],
            extensions: &["hej2"],
            magic: &[Magic::at(4, b"ftypj2ki"), Magic::at(4, b"ftypj2is")],
            parent: None,
        },
    ],
};

/// Bytes read for the `meta` box and for one metadata item.
const MAX_META: u64 = 16 << 20;

impl Extractor for Heif {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Generic `mif1` / `msf1` files say what they hold in their compatible brands.
        let ftyp = find_box(probe.head, *b"ftyp")?;
        let brands: Vec<&[u8]> = std::iter::once(ftyp.get(..4)?)
            .chain(ftyp.get(8..)?.as_chunks::<4>().0.iter().map(<[u8; 4]>::as_slice))
            .collect();
        if !brands.iter().any(|b| *b == b"mif1" || *b == b"msf1") {
            return None;
        }
        if brands.iter().any(|b| *b == b"avif" || *b == b"avis") {
            Some(Sniff { format: "avif", confidence: 0.95 })
        } else if brands.iter().any(|b| *b == b"avci" || *b == b"avcs") {
            Some(Sniff { format: "avci", confidence: 0.95 })
        } else if brands.iter().any(|b| *b == b"j2ki" || *b == b"j2is") {
            Some(Sniff { format: "hej2", confidence: 0.95 })
        } else if brands.iter().any(|b| b.starts_with(b"hei") || b.starts_with(b"hev")) {
            Some(Sniff { format: "heic", confidence: 0.95 })
        } else {
            None
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        // Top-level boxes, without reading the media data.
        let (mut ftyp, mut meta, mut sequence) = (None, None, false);
        let mut top = Vec::new();
        for b in top_boxes(src, 64)? {
            top.push(fourcc(&b.kind));
            match &b.kind {
                b"ftyp" => ftyp = read_box(src, &b, 1024),
                b"meta" => meta = read_box(src, &b, MAX_META),
                b"moov" => sequence = true,
                _ => {}
            }
        }
        if let Some(f) = &ftyp {
            let compat: Vec<String> =
                f.get(8..).unwrap_or_default().as_chunks::<4>().0.iter().map(|b| fourcc(b)).collect();
            cx.format_set("major_brand", fourcc(f.get(..4).unwrap_or_default()));
            cx.format_set("compatible_brands", json!(compat));
        }
        cx.format_set("top_level_boxes", json!(top));
        cx.format_set("image_sequence", sequence);
        let meta = meta.ok_or_else(|| ExtractError::malformed("no meta box"))?;
        let m = Meta::parse(meta.get(4..).unwrap_or_default());
        m.report(src, cx);
        Ok(())
    }
}

crate::register_extractor!(Heif);

#[derive(Default)]
struct Item {
    kind: String,
    content_type: String,
    extents: Vec<(u64, u64)>,
    construction: u16,
}

#[derive(Default)]
struct Meta {
    handler: String,
    primary: Option<u32>,
    items: BTreeMap<u32, Item>,
    refs: Vec<(String, u32, Vec<u32>)>,
    properties: Vec<([u8; 4], Vec<u8>)>,
    associations: HashMap<u32, Vec<usize>>,
    idat: Vec<u8>,
}

fn full(b: &[u8]) -> (u8, u32, &[u8]) {
    match b {
        [v, f1, f2, f3, rest @ ..] => (*v, u32::from_be_bytes([0, *f1, *f2, *f3]), rest),
        _ => (0, 0, &[]),
    }
}

fn read_n(r: &mut ByteReader<'_>, size: u8) -> Option<u64> {
    Some(match size {
        0 => 0,
        4 => u64::from(r.be_u32().ok()?),
        8 => r.be_u64().ok()?,
        2 => u64::from(r.be_u16().ok()?),
        _ => return None,
    })
}

impl Meta {
    fn parse(body: &[u8]) -> Self {
        let mut m = Meta::default();
        for (kind, b) in boxes(body) {
            match &kind {
                b"hdlr" => m.handler = fourcc(full(b).2.get(4..8).unwrap_or_default()),
                b"pitm" => {
                    let (v, _, d) = full(b);
                    let mut r = ByteReader::new(d);
                    m.primary = if v == 0 { r.be_u16().ok().map(u32::from) } else { r.be_u32().ok() };
                }
                b"iinf" => m.iinf(b),
                b"iloc" => m.iloc(b),
                b"iref" => m.iref(b),
                b"iprp" => m.iprp(b),
                b"idat" => m.idat = b.to_vec(),
                _ => {}
            }
        }
        m
    }

    fn iinf(&mut self, b: &[u8]) {
        let (v, _, d) = full(b);
        let skip = if v == 0 { 2 } else { 4 };
        for (kind, infe) in boxes(d.get(skip..).unwrap_or_default()).take(10_000) {
            if &kind != b"infe" {
                continue;
            }
            let (iv, _, d) = full(infe);
            if iv < 2 {
                continue;
            }
            let mut r = ByteReader::new(d);
            let Some(id) = (if iv == 2 { r.be_u16().ok().map(u32::from) } else { r.be_u32().ok() }) else { continue };
            if r.advance(2).is_err() {
                continue;
            }
            let Ok(t) = r.bytes(4) else { continue };
            let kind = fourcc(t);
            let rest = r.rest();
            let mut parts = rest.split(|&c| c == 0);
            let _name = parts.next();
            let content_type = if kind == "mime" {
                String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned()
            } else {
                String::new()
            };
            let item = self.items.entry(id).or_default();
            item.kind = kind;
            item.content_type = content_type;
        }
    }

    fn iloc(&mut self, b: &[u8]) {
        let (v, _, d) = full(b);
        let mut r = ByteReader::new(d);
        let parse = |r: &mut ByteReader<'_>, items: &mut BTreeMap<u32, Item>| -> Option<()> {
            let a = r.u8().ok()?;
            let c = r.u8().ok()?;
            let (off_size, len_size, base_size, idx_size) = (a >> 4, a & 15, c >> 4, if v >= 1 { c & 15 } else { 0 });
            let count = if v < 2 { u32::from(r.be_u16().ok()?) } else { r.be_u32().ok()? };
            for _ in 0..count.min(100_000) {
                let id = if v < 2 { u32::from(r.be_u16().ok()?) } else { r.be_u32().ok()? };
                let construction = if v >= 1 { r.be_u16().ok()? & 15 } else { 0 };
                r.advance(2).ok()?;
                let base = read_n(r, base_size)?;
                let extents = r.be_u16().ok()?;
                let item = items.entry(id).or_default();
                item.construction = construction;
                for _ in 0..extents.min(1024) {
                    if idx_size > 0 {
                        read_n(r, idx_size)?;
                    }
                    let off = read_n(r, off_size)?;
                    let len = read_n(r, len_size)?;
                    item.extents.push((base.saturating_add(off), len));
                }
            }
            Some(())
        };
        let _ = parse(&mut r, &mut self.items);
    }

    fn iref(&mut self, b: &[u8]) {
        let (v, _, d) = full(b);
        for (kind, rb) in boxes(d).take(10_000) {
            let mut r = ByteReader::new(rb);
            let id = |r: &mut ByteReader<'_>| if v == 0 { r.be_u16().ok().map(u32::from) } else { r.be_u32().ok() };
            let Some(from) = id(&mut r) else { continue };
            let Ok(n) = r.be_u16() else { continue };
            let to: Vec<u32> = (0..n.min(4096)).filter_map(|_| id(&mut r)).collect();
            self.refs.push((fourcc(&kind), from, to));
        }
    }

    fn iprp(&mut self, b: &[u8]) {
        for (kind, d) in boxes(b) {
            match &kind {
                b"ipco" => self.properties = boxes(d).take(10_000).map(|(k, p)| (k, p.to_vec())).collect(),
                b"ipma" => {
                    let (v, flags, d) = full(d);
                    let mut r = ByteReader::new(d);
                    let Ok(n) = r.be_u32() else { continue };
                    for _ in 0..n.min(100_000) {
                        let id = if v < 1 { r.be_u16().ok().map(u32::from) } else { r.be_u32().ok() };
                        let (Some(id), Ok(count)) = (id, r.u8()) else { break };
                        let list = self.associations.entry(id).or_default();
                        for _ in 0..count {
                            let index = if flags & 1 == 1 {
                                r.be_u16().map(|x| usize::from(x & 0x7fff))
                            } else {
                                r.u8().map(|x| usize::from(x & 0x7f))
                            };
                            match index {
                                Ok(i) if i > 0 => list.push(i - 1),
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn property(&self, item: u32, kind: [u8; 4]) -> Option<&[u8]> {
        self.associations
            .get(&item)?
            .iter()
            .filter_map(|&i| self.properties.get(i))
            .find(|(k, _)| *k == kind)
            .map(|(_, b)| b.as_slice())
    }

    /// An item's bytes (from the file or `idat`), at most `MAX_META`.
    fn data(&self, src: &mut dyn Source, item: &Item) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for &(off, len) in &item.extents {
            if out.len() as u64 + len > MAX_META {
                return None;
            }
            match item.construction {
                0 => out.extend(src.read_vec(off, usize::try_from(len).ok()?).ok()?),
                1 => {
                    out.extend_from_slice(self.idat.get(usize::try_from(off).ok()?..usize::try_from(off + len).ok()?)?);
                }
                _ => return None,
            }
        }
        Some(out)
    }

    fn report(&self, src: &mut dyn Source, cx: &mut Context<'_>) {
        cx.format_set("handler", self.handler.clone());
        let primary = self.primary.or_else(|| self.items.keys().next().copied());
        if let Some(p) = primary {
            let item = self.items.get(&p);
            cx.format_set("primary_item_type", item.map(|i| i.kind.clone()));
            if let Some(ispe) = self.property(p, *b"ispe").map(|b| full(b).2).filter(|d| d.len() >= 8) {
                let w = u32::from_be_bytes([ispe[0], ispe[1], ispe[2], ispe[3]]);
                let h = u32::from_be_bytes([ispe[4], ispe[5], ispe[6], ispe[7]]);
                let mut img = cx.physical().image(w, h);
                if let Some(pixi) = self.property(p, *b"pixi").map(|b| full(b).2).filter(|d| !d.is_empty()) {
                    img.channels(pixi[0]);
                    if let Some(bits) = pixi.get(1) {
                        img.bit_depth(*bits);
                    }
                }
                if let Some(rot) = self.property(p, *b"irot").and_then(<[u8]>::first) {
                    img.orientation(match rot & 3 {
                        1 => 8,
                        2 => 3,
                        3 => 6,
                        _ => 1,
                    });
                }
            }
            if let Some(colr) = self.property(p, *b"colr").filter(|c| c.len() >= 4) {
                match &colr[..4] {
                    b"prof" | b"rICC" => cx.emit_block(BlockKind::ICC, colr[4..].to_vec()),
                    b"nclx" if colr.len() >= 10 => {
                        let primaries = u16::from_be_bytes([colr[4], colr[5]]);
                        let transfer = u16::from_be_bytes([colr[6], colr[7]]);
                        let space = match (primaries, transfer) {
                            (1, 13) => "sRGB",
                            (12, 13) => "Display P3",
                            (9, 16) => "BT.2100 PQ",
                            (9, 18) => "BT.2100 HLG",
                            (9, _) => "BT.2020",
                            (1, _) => "BT.709",
                            _ => "",
                        };
                        cx.format_set("nclx", json!({ "primaries": primaries, "transfer": transfer, "matrix": u16::from_be_bytes([colr[8], colr[9]]), "full_range": colr.get(10).is_some_and(|b| b & 0x80 != 0) }));
                        if !space.is_empty()
                            && let Some(mut img) = cx.physical().existing_image()
                        {
                            img.color_space(space);
                        }
                    }
                    _ => {}
                }
            }
        }
        // Metadata items.
        for item in self.items.values() {
            let kind = match (item.kind.as_str(), item.content_type.as_str()) {
                ("Exif", _) => Some(BlockKind::EXIF),
                ("mime", t) if t.contains("rdf+xml") => Some(BlockKind::XMP),
                _ => None,
            };
            let Some(kind) = kind else { continue };
            let Some(data) = self.data(src, item) else { continue };
            if kind == BlockKind::EXIF {
                // A 4-byte offset to the TIFF header precedes the EXIF data.
                let skip = data.get(..4).map_or(0, |o| u32::from_be_bytes([o[0], o[1], o[2], o[3]]) as usize);
                if let Some(tiff) = data.get(4 + skip..) {
                    cx.emit_block(BlockKind::EXIF, tiff.to_vec());
                }
            } else {
                cx.emit_block(kind, data);
            }
        }
        // Catalogue.
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        for i in self.items.values() {
            *types.entry(i.kind.clone()).or_default() += 1;
        }
        let thumbnails = self.refs.iter().filter(|(k, ..)| k == "thmb").count();
        let mut aux = Vec::new();
        for (from, _) in self.refs.iter().filter(|(k, ..)| k == "auxl").map(|(_, f, t)| (f, t)) {
            if let Some(a) = self.property(*from, *b"auxC") {
                let t = String::from_utf8_lossy(full(a).2.split(|&b| b == 0).next().unwrap_or_default()).into_owned();
                let label = if t.contains("alpha") || t.ends_with("auxid:1") {
                    "alpha"
                } else if t.contains("hdrgainmap") || t.contains("gainmap") {
                    "hdr_gain_map"
                } else if t.contains("depth") || t.ends_with("auxid:2") || t.contains("disparity") {
                    "depth"
                } else if t.contains("matte") {
                    "matte"
                } else {
                    "other"
                };
                aux.push(json!(label));
            }
        }
        cx.format_set("items", self.items.len());
        cx.format_set("item_types", json!(types));
        cx.format_set("thumbnails", thumbnails);
        if !aux.is_empty() {
            cx.format_set("auxiliary_images", Value::Array(aux));
        }
        if types.get("grid").copied().unwrap_or(0) > 0 {
            cx.format_set("tiled", true);
        }
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("heic", "heif", "avif", "avci", "hej2");
}
