//! TIFF and BigTIFF: pages (IFD chain), size, bit depth, samples,
//! compression, photometric interpretation, tiling, resolution, GeoTIFF and
//! DNG markers. EXIF / GPS tags go to the EXIF decoder as a compact TIFF
//! rebuilt from the metadata IFDs (never the whole file); XMP, IPTC, ICC
//! and Photoshop tags go to their decoders.
//!
//! The IFD walker here is shared with the camera-raw extractor.
//!
//! Specifications: TIFF 6.0, BigTIFF, Adobe DNG 1.7.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::plugin::{BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for TIFF.
pub struct Tiff;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.tiff",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "tiff",
        name: "TIFF image",
        family: "image.raster",
        mimes: &["image/tiff"],
        extensions: &["tif", "tiff", "btf", "tf8"],
        magic: &[Magic::prefix(b"II*\0"), Magic::prefix(b"MM\0*"), Magic::prefix(b"II+\0"), Magic::prefix(b"MM\0+")],
        parent: None,
    }],
};

impl Extractor for Tiff {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let layout = layout(src.head()).ok_or_else(|| ExtractError::malformed("no TIFF header"))?;
        let pages = ifd_chain(src, &layout, cx)?;
        let first = pages.first().ok_or_else(|| ExtractError::malformed("no IFD"))?;
        // GeoTIFFs whose first IFD lies outside the sniffed windows.
        #[cfg(feature = "geo")]
        if cx.format_id() == "tiff" && [33550, 33922, 34264, 34735].iter().any(|t| find(first, *t).is_some()) {
            cx.redirect("geotiff");
            return Ok(());
        }
        describe(first, &layout, cx, pages.len());
        let list: Vec<Value> = pages.iter().take(20).map(|p| page_json(p, &layout)).collect();
        cx.format_set("pages", pages.len());
        cx.format_set("page_list", list);
        emit_metadata(src, &layout, first, cx);
        Ok(())
    }
}

crate::register_extractor!(Tiff);

/// Where a TIFF structure starts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) le: bool,
    pub(crate) big: bool,
    pub(crate) first: u64,
}

/// The TIFF header at the start of `head`: classic (42), BigTIFF (43), and
/// the Olympus (`IIRO` / `MMOR`, `IISR`) and Panasonic (`IIU\0`) variants.
pub(crate) fn layout(head: &[u8]) -> Option<Layout> {
    let le = match head.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |o: usize| -> Option<u16> {
        let b = head.get(o..o + 2)?;
        Some(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    };
    let magic = u16_at(2)?;
    match magic {
        42 | 0x4f52 | 0x5352 | 0x55 => {
            let b = head.get(4..8)?;
            let off = if le { u32::from_le_bytes(b.try_into().ok()?) } else { u32::from_be_bytes(b.try_into().ok()?) };
            Some(Layout { le, big: false, first: u64::from(off) })
        }
        43 => {
            if u16_at(4)? != 8 {
                return None;
            }
            let b = head.get(8..16)?;
            let off = if le { u64::from_le_bytes(b.try_into().ok()?) } else { u64::from_be_bytes(b.try_into().ok()?) };
            Some(Layout { le, big: true, first: off })
        }
        _ => None,
    }
}

/// One IFD entry with its value bytes (in the file's byte order).
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) tag: u16,
    pub(crate) typ: u16,
    pub(crate) count: u64,
    /// Empty when the value was too large to load.
    pub(crate) data: Vec<u8>,
}

/// Values larger than this are not loaded (strip offsets of huge images).
const MAX_VALUE: u64 = 1 << 20;
const MAX_ENTRIES: u16 = 4096;
const MAX_PAGES: usize = 1024;

fn type_size(t: u16) -> u64 {
    match t {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 | 16 | 17 | 18 => 8,
        _ => 0,
    }
}

impl Entry {
    /// Unsigned integer values (BYTE, SHORT, LONG, LONG8, IFD, IFD8).
    pub(crate) fn uints(&self, le: bool) -> Vec<u64> {
        let size = usize::try_from(type_size(self.typ)).unwrap_or(0);
        if size == 0 || !matches!(self.typ, 1 | 3 | 4 | 13 | 16 | 18) {
            return Vec::new();
        }
        self.data
            .chunks_exact(size)
            .map(|c| match (size, le) {
                (1, _) => u64::from(c[0]),
                (2, true) => u64::from(u16::from_le_bytes([c[0], c[1]])),
                (2, false) => u64::from(u16::from_be_bytes([c[0], c[1]])),
                (4, true) => u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]])),
                (4, false) => u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]])),
                (_, true) => u64::from_le_bytes(c.try_into().unwrap_or_default()),
                (_, false) => u64::from_be_bytes(c.try_into().unwrap_or_default()),
            })
            .collect()
    }

    pub(crate) fn uint(&self, le: bool) -> Option<u64> {
        self.uints(le).first().copied()
    }

    /// RATIONAL as a decimal.
    pub(crate) fn rational(&self, le: bool) -> Option<f64> {
        if self.typ != 5 || self.data.len() < 8 {
            return None;
        }
        let d = &self.data;
        let (n, dn) = if le {
            (u32::from_le_bytes([d[0], d[1], d[2], d[3]]), u32::from_le_bytes([d[4], d[5], d[6], d[7]]))
        } else {
            (u32::from_be_bytes([d[0], d[1], d[2], d[3]]), u32::from_be_bytes([d[4], d[5], d[6], d[7]]))
        };
        (dn != 0).then(|| f64::from(n) / f64::from(dn))
    }

    pub(crate) fn string(&self) -> String {
        String::from_utf8_lossy(&self.data).trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string()
    }
}

/// Read one IFD at `offset`: its entries and the next IFD's offset.
pub(crate) fn read_ifd(src: &mut dyn Source, l: &Layout, offset: u64) -> Result<(Vec<Entry>, u64), ExtractError> {
    let u16_ = |b: &[u8]| if l.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) };
    let u32_ = |b: &[u8]| {
        if l.le { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
    };
    let u64_ = |b: &[u8]| {
        let a: [u8; 8] = b.try_into().unwrap_or_default();
        if l.le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) }
    };
    let (count_len, entry_len, inline) = if l.big { (8usize, 20usize, 8usize) } else { (2, 12, 4) };
    let count_bytes = src.read_vec(offset, count_len)?;
    let count = if l.big { u64_(&count_bytes) } else { u64::from(u16_(&count_bytes)) };
    let count = match usize::try_from(count) {
        Ok(n) if n > 0 && n <= usize::from(MAX_ENTRIES) => n,
        _ => return Err(ExtractError::malformed(format!("IFD with {count} entries"))),
    };
    let table = src.read_vec(offset + count_len as u64, count * entry_len + inline)?;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let e = &table[i * entry_len..(i + 1) * entry_len];
        let tag = u16_(&e[0..2]);
        let typ = u16_(&e[2..4]);
        let n = if l.big { u64_(&e[4..12]) } else { u64::from(u32_(&e[4..8])) };
        let value_field = if l.big { &e[12..20] } else { &e[8..12] };
        // Values over MAX_VALUE (1 MiB) are not loaded, so `total` fits a usize.
        let total = usize::try_from(n.saturating_mul(type_size(typ))).unwrap_or(usize::MAX);
        let data = if total == 0 || total as u64 > MAX_VALUE {
            Vec::new()
        } else if total <= inline {
            value_field[..total].to_vec()
        } else {
            let at = if l.big { u64_(value_field) } else { u64::from(u32_(value_field)) };
            src.read_vec(at, total).unwrap_or_default()
        };
        entries.push(Entry { tag, typ, count: n, data });
    }
    let tail = &table[count * entry_len..];
    let next = if l.big { u64_(tail) } else { u64::from(u32_(tail)) };
    Ok((entries, next))
}

/// Every IFD in the main chain (pages), stopping at loops and the page cap.
pub(crate) fn ifd_chain(
    src: &mut dyn Source,
    l: &Layout,
    cx: &mut Context<'_>,
) -> Result<Vec<Vec<Entry>>, ExtractError> {
    let mut seen = HashSet::new();
    let mut pages = Vec::new();
    let mut offset = l.first;
    while offset != 0 && seen.insert(offset) && pages.len() < MAX_PAGES {
        cx.checkpoint()?;
        match read_ifd(src, l, offset) {
            Ok((entries, next)) => {
                pages.push(entries);
                offset = next;
            }
            Err(e) if pages.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(pages)
}

pub(crate) fn find(entries: &[Entry], tag: u16) -> Option<&Entry> {
    entries.iter().find(|e| e.tag == tag)
}

/// The IFD a pointer tag (Exif 34665, GPS 34853, Interop 40965, first `SubIFD` 330) points to.
pub(crate) fn sub_ifd(src: &mut dyn Source, l: &Layout, entries: &[Entry], tag: u16) -> Option<Vec<Entry>> {
    let off = find(entries, tag)?.uint(l.le)?;
    read_ifd(src, l, off).ok().map(|(e, _)| e)
}

/// Tags holding image data or pointers: left out of the EXIF block.
const STRUCTURAL: &[u16] =
    &[273, 279, 288, 289, 320, 324, 325, 330, 513, 514, 700, 33723, 34377, 34665, 34675, 34853, 37724, 40965, 50740];

/// Send the metadata of `ifd0` to the decoders: a rebuilt EXIF TIFF and the
/// XMP / IPTC / ICC / Photoshop tags.
pub(crate) fn emit_metadata(src: &mut dyn Source, l: &Layout, ifd0: &[Entry], cx: &mut Context<'_>) {
    let exif = sub_ifd(src, l, ifd0, 34665).unwrap_or_default();
    let gps = sub_ifd(src, l, ifd0, 34853).unwrap_or_default();
    let block = mini_exif(l.le, ifd0, &exif, &gps);
    if !block.is_empty() {
        cx.emit_block(BlockKind::EXIF, block);
    }
    for (tag, kind) in [
        (700, BlockKind::XMP),
        (33723, BlockKind::IPTC_IIM),
        (34675, BlockKind::ICC),
        (34377, BlockKind::PHOTOSHOP_IRB),
    ] {
        if let Some(e) = find(ifd0, tag).filter(|e| !e.data.is_empty()) {
            cx.emit_block(kind, e.data.clone());
        }
    }
}

/// A classic TIFF holding just the metadata entries of IFD0, the Exif IFD
/// and the GPS IFD, in byte order `le`. Empty if there is nothing to keep.
pub(crate) fn mini_exif(le: bool, ifd0: &[Entry], exif: &[Entry], gps: &[Entry]) -> Vec<u8> {
    let keep = |es: &[Entry]| -> Vec<Entry> {
        let mut v: Vec<Entry> = es
            .iter()
            .filter(|e| !STRUCTURAL.contains(&e.tag) && !e.data.is_empty() && type_size(e.typ) > 0 && e.typ < 16)
            .filter(|e| u32::try_from(e.count).is_ok() && e.data.len() <= 64 * 1024)
            .cloned()
            .collect();
        v.sort_by_key(|e| e.tag);
        v.dedup_by_key(|e| e.tag);
        v
    };
    let (mut ifd0, exif, gps) = (keep(ifd0), keep(exif), keep(gps));
    if ifd0.is_empty() && exif.is_empty() && gps.is_empty() {
        return Vec::new();
    }
    let p16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let p32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let pointer = |tag: u16| Entry { tag, typ: 4, count: 1, data: p32(0).to_vec() };
    if !exif.is_empty() {
        ifd0.push(pointer(34665));
    }
    if !gps.is_empty() {
        ifd0.push(pointer(34853));
    }
    ifd0.sort_by_key(|e| e.tag);
    let size = |es: &[Entry]| -> usize {
        2 + 12 * es.len()
            + 4
            + es.iter().map(|e| if e.data.len() > 4 { e.data.len() + e.data.len() % 2 } else { 0 }).sum::<usize>()
    };
    let off0 = 8usize;
    let off_exif = off0 + size(&ifd0);
    let off_gps = off_exif + if exif.is_empty() { 0 } else { size(&exif) };
    for e in &mut ifd0 {
        match e.tag {
            34665 => e.data = p32(u32::try_from(off_exif).unwrap_or(0)).to_vec(),
            34853 => e.data = p32(u32::try_from(off_gps).unwrap_or(0)).to_vec(),
            _ => {}
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(if le { b"II" } else { b"MM" });
    out.extend_from_slice(&p16(42));
    out.extend_from_slice(&p32(8));
    for (offset, es) in [(off0, &ifd0), (off_exif, &exif), (off_gps, &gps)] {
        if es.is_empty() {
            continue;
        }
        debug_assert_eq!(out.len(), offset);
        let mut data_at = offset + 2 + 12 * es.len() + 4;
        let mut data = Vec::new();
        out.extend_from_slice(&p16(u16::try_from(es.len()).unwrap_or(0)));
        for e in es {
            out.extend_from_slice(&p16(e.tag));
            out.extend_from_slice(&p16(e.typ));
            out.extend_from_slice(&p32(u32::try_from(e.count).unwrap_or(0)));
            if e.data.len() <= 4 {
                let mut v = e.data.clone();
                v.resize(4, 0);
                out.extend_from_slice(&v);
            } else {
                out.extend_from_slice(&p32(u32::try_from(data_at).unwrap_or(0)));
                data.extend_from_slice(&e.data);
                if e.data.len() % 2 == 1 {
                    data.push(0);
                }
                data_at += e.data.len() + e.data.len() % 2;
            }
        }
        out.extend_from_slice(&p32(0));
        out.extend_from_slice(&data);
    }
    out
}

const COMPRESSION: &[(u64, &str)] = &[
    (1, "none"),
    (2, "CCITT RLE"),
    (3, "CCITT Group 3"),
    (4, "CCITT Group 4"),
    (5, "LZW"),
    (6, "old JPEG"),
    (7, "JPEG"),
    (8, "Deflate"),
    (32773, "PackBits"),
    (32946, "Deflate"),
    (34712, "JPEG 2000"),
    (34887, "LERC"),
    (34892, "lossy JPEG (DNG)"),
    (50000, "Zstandard"),
    (50001, "WebP"),
    (52546, "JPEG XL"),
];

const PHOTOMETRIC: &[(u64, &str)] = &[
    (0, "WhiteIsZero"),
    (1, "BlackIsZero"),
    (2, "RGB"),
    (3, "palette"),
    (4, "transparency mask"),
    (5, "CMYK"),
    (6, "YCbCr"),
    (8, "CIELab"),
    (32803, "CFA"),
    (34892, "LinearRaw"),
];

fn name(table: &[(u64, &'static str)], v: u64) -> Value {
    table.iter().find(|(k, _)| *k == v).map_or_else(|| json!(v), |(_, n)| json!(n))
}

/// Width, height and sample layout of one IFD.
pub(crate) fn page_json(p: &[Entry], l: &Layout) -> Value {
    let u = |t: u16| find(p, t).and_then(|e| e.uint(l.le));
    let mut m = Map::new();
    for (k, t) in [("width", 256), ("height", 257), ("samples_per_pixel", 277)] {
        if let Some(v) = u(t) {
            m.insert(k.into(), json!(v));
        }
    }
    if let Some(b) = find(p, 258).map(|e| e.uints(l.le)).filter(|v| !v.is_empty()) {
        m.insert("bits_per_sample".into(), json!(b));
    }
    if let Some(c) = u(259) {
        m.insert("compression".into(), name(COMPRESSION, c));
    }
    if let Some(c) = u(262) {
        m.insert("photometric".into(), name(PHOTOMETRIC, c));
    }
    if let Some(s) = u(254) {
        m.insert("subfile_type".into(), json!(s));
    }
    Value::Object(m)
}

/// `physical.image` and `format.*` from the first IFD.
pub(crate) fn describe(p: &[Entry], l: &Layout, cx: &mut Context<'_>, pages: usize) {
    let u = |t: u16| find(p, t).and_then(|e| e.uint(l.le));
    if let (Some(w), Some(h)) = (u(256), u(257))
        && let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h))
    {
        let samples = u(277).unwrap_or(1);
        let bits = u(258).unwrap_or(1);
        let mut img = cx.physical().image(w, h);
        img.channels(u8::try_from(samples).unwrap_or(u8::MAX)).bit_depth(u8::try_from(bits).unwrap_or(u8::MAX));
        if pages > 1 {
            img.frames(u32::try_from(pages).unwrap_or(u32::MAX));
        }
        let res = |t: u16| find(p, t).and_then(|e| e.rational(l.le));
        // ResolutionUnit 1 means no absolute unit (an aspect ratio only).
        if let (Some(x), Some(y)) = (res(282), res(283))
            && u(296) != Some(1)
        {
            let k = if u(296) == Some(3) { 2.54 } else { 1.0 };
            img.dpi((x * k * 100.0).round() / 100.0, (y * k * 100.0).round() / 100.0);
        }
        if u(262) == Some(5) {
            img.color_space("CMYK");
        }
    }
    cx.format_set("byte_order", if l.le { "little-endian" } else { "big-endian" });
    cx.format_set("bigtiff", l.big);
    if let Some(c) = u(259) {
        cx.format_set("compression", name(COMPRESSION, c));
    }
    if let Some(c) = u(262) {
        cx.format_set("photometric", name(PHOTOMETRIC, c));
    }
    cx.format_set("tiled", find(p, 322).is_some());
    if let Some(s) = find(p, 305).map(Entry::string).filter(|s| !s.is_empty()) {
        cx.format_set("software", s);
    }
    if [33550, 33922, 34264, 34735].iter().any(|t| find(p, *t).is_some()) {
        cx.format_set("geotiff", true);
    }
    if let Some(v) = find(p, 50706).filter(|e| e.data.len() == 4) {
        cx.format_set("dng_version", v.data.iter().map(u8::to_string).collect::<Vec<_>>().join("."));
    }
    if let Some(s) = find(p, 330) {
        cx.format_set("sub_ifds", s.count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let l = layout(b"II*\0\x08\0\0\0").unwrap();
        assert!(l.le && !l.big && l.first == 8);
        let b = layout(b"MM\0+\0\x08\0\0\0\0\0\0\0\0\0\x10").unwrap();
        assert!(!b.le && b.big && b.first == 16);
        assert!(layout(b"IIRO\x08\0\0\0").is_some());
        assert!(layout(b"XX*\0").is_none());
    }

    #[test]
    fn mini_exif_round_trips() {
        let e = |tag, typ, count, data: &[u8]| Entry { tag, typ, count, data: data.to_vec() };
        let ifd0 = [e(271, 2, 6, b"Canon\0"), e(273, 4, 1, &[0, 0, 0, 0])];
        let exif = [e(36867, 2, 20, b"2026:09:14 17:03:22\0")];
        let block = mini_exif(true, &ifd0, &exif, &[]);
        let parsed = exif::Reader::new().read_raw(block).unwrap();
        let make = parsed.get_field(exif::Tag::Make, exif::In::PRIMARY).unwrap();
        assert_eq!(make.display_value().to_string(), "\"Canon\"");
        assert!(parsed.get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY).is_some());
        assert!(parsed.get_field(exif::Tag::StripOffsets, exif::In::PRIMARY).is_none());
    }

    crate::fixture_tests!("tiff");
}
