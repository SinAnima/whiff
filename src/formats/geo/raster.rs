//! Georeferenced rasters:
//! * GeoTIFF (classic and BigTIFF) and Cloud Optimized GeoTIFF: size,
//!   bands, sample type, compression, tiling, overviews and masks, the
//!   `GeoKeys` (model and raster type, EPSG codes, citations), the
//!   geotransform (tie point and pixel scale, or the model transformation),
//!   bounds, the GDAL no-data value and metadata items, and the COG layout
//!   (IFDs before the data, the GDAL structural metadata);
//! * DTED levels 0–2: origin, posting intervals, size, accuracy, security
//!   and product level.
//!
//! Specifications: OGC GeoTIFF 1.1 (19-008r4); OGC Cloud Optimized GeoTIFF
//! 1.0 (21-026); TIFF 6.0 and BigTIFF; MIL-PRF-89020B (DTED).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{Bounds, Crs, num, report_bounds, report_native};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for georeferenced rasters.
pub struct Raster;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.raster",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "geotiff",
            name: "GeoTIFF / COG",
            family: "geo",
            mimes: &["image/tiff; application=geotiff"],
            extensions: &[],
            magic: &[],
            parent: Some("tiff"),
        },
        FormatSpec {
            id: "dted",
            name: "DTED / SRTM HGT / ASC grid",
            family: "geo",
            mimes: &[],
            extensions: &["dt0", "dt1", "dt2"],
            magic: &[Magic::at(0, b"UHL1")],
            parent: None,
        },
    ],
};

/// A TIFF directory entry: (type, count, value bytes or their offset).
#[derive(Clone)]
struct Entry {
    typ: u16,
    count: u64,
    inline: Vec<u8>,
    offset: Option<u64>,
}

struct Tiff {
    le: bool,
    big: bool,
}

impl Tiff {
    fn u16(&self, b: &[u8]) -> u16 {
        let r = [b[0], b[1]];
        if self.le { u16::from_le_bytes(r) } else { u16::from_be_bytes(r) }
    }
    fn u32(&self, b: &[u8]) -> u32 {
        let r = [b[0], b[1], b[2], b[3]];
        if self.le { u32::from_le_bytes(r) } else { u32::from_be_bytes(r) }
    }
    fn u64(&self, b: &[u8]) -> u64 {
        let r: [u8; 8] = b[..8].try_into().unwrap_or_default();
        if self.le { u64::from_le_bytes(r) } else { u64::from_be_bytes(r) }
    }
    fn f64(&self, b: &[u8]) -> f64 {
        let r: [u8; 8] = b[..8].try_into().unwrap_or_default();
        if self.le { f64::from_le_bytes(r) } else { f64::from_be_bytes(r) }
    }

    fn size(typ: u16) -> u64 {
        // BYTE, ASCII, SBYTE, UNDEFINED and unknown types: one byte.
        match typ {
            3 | 8 => 2,
            4 | 9 | 11 | 13 => 4,
            5 | 10 | 12 | 16 | 17 | 18 => 8,
            _ => 1,
        }
    }

    /// One IFD: entries by tag, and the next IFD's offset.
    fn ifd(&self, src: &mut dyn Source, at: u64) -> Option<(BTreeMap<u16, Entry>, u64)> {
        let (count_len, entry_len, ptr) = if self.big { (8u64, 20u64, 8u64) } else { (2, 12, 4) };
        let c = src.read_vec(at, usize::try_from(count_len).ok()?).ok()?;
        let n = if self.big { self.u64(&c) } else { u64::from(self.u16(&c)) };
        if n == 0 || n > 4096 {
            return None;
        }
        let raw = src.read_vec(at + count_len, usize::try_from(n * entry_len + ptr).ok()?).ok()?;
        let mut out = BTreeMap::new();
        for e in raw.chunks_exact(usize::try_from(entry_len).ok()?).take(usize::try_from(n).ok()?) {
            let tag = self.u16(&e[0..2]);
            let typ = self.u16(&e[2..4]);
            let (count, value) =
                if self.big { (self.u64(&e[4..12]), &e[12..20]) } else { (u64::from(self.u32(&e[4..8])), &e[8..12]) };
            let bytes = count.saturating_mul(Tiff::size(typ));
            let (inline, offset) = if bytes <= value.len() as u64 {
                (value[..usize::try_from(bytes).ok()?].to_vec(), None)
            } else {
                (Vec::new(), Some(if self.big { self.u64(value) } else { u64::from(self.u32(value)) }))
            };
            out.insert(tag, Entry { typ, count, inline, offset });
        }
        let tail = &raw[raw.len() - usize::try_from(ptr).ok()?..];
        let next = if self.big { self.u64(tail) } else { u64::from(self.u32(tail)) };
        Some((out, next))
    }

    /// An entry's bytes (at most 16 MiB).
    fn bytes(src: &mut dyn Source, e: &Entry) -> Vec<u8> {
        match e.offset {
            None => e.inline.clone(),
            Some(o) => {
                let n = e.count.saturating_mul(Tiff::size(e.typ)).min(16 << 20);
                src.read_vec(o, usize::try_from(n).unwrap_or(0)).unwrap_or_default()
            }
        }
    }

    /// Integer values (BYTE, SHORT, LONG, LONG8).
    fn ints(&self, src: &mut dyn Source, e: &Entry) -> Vec<u64> {
        let b = Tiff::bytes(src, e);
        match e.typ {
            1 | 7 => b.iter().map(|&x| u64::from(x)).collect(),
            3 => b.as_chunks::<2>().0.iter().map(|c| u64::from(self.u16(c))).collect(),
            4 | 13 => b.as_chunks::<4>().0.iter().map(|c| u64::from(self.u32(c))).collect(),
            16 | 18 => b.as_chunks::<8>().0.iter().map(|c| self.u64(c)).collect(),
            _ => Vec::new(),
        }
    }

    fn doubles(&self, src: &mut dyn Source, e: &Entry) -> Vec<f64> {
        if e.typ != 12 {
            return Vec::new();
        }
        Tiff::bytes(src, e).as_chunks::<8>().0.iter().map(|c| self.f64(c)).collect()
    }

    fn ascii(src: &mut dyn Source, e: &Entry) -> String {
        String::from_utf8_lossy(&Tiff::bytes(src, e)).trim_end_matches('\0').to_string()
    }
}

fn header(h: &[u8]) -> Option<(Tiff, u64)> {
    let le = match h.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let t = Tiff { le, big: false };
    match t.u16(h.get(2..4)?) {
        42 => Some((t, u64::from(Tiff { le, big: false }.u32(h.get(4..8)?)))),
        43 => {
            let t = Tiff { le, big: true };
            let first = t.u64(h.get(8..16)?);
            Some((t, first))
        }
        _ => None,
    }
}

fn geokey_name(k: u64) -> Option<&'static str> {
    Some(match k {
        1024 => "GTModelType",
        1025 => "GTRasterType",
        1026 => "GTCitation",
        2048 => "GeographicType",
        2049 => "GeogCitation",
        2050 => "GeogGeodeticDatum",
        2052 => "GeogLinearUnits",
        2054 => "GeogAngularUnits",
        2056 => "GeogEllipsoid",
        3072 => "ProjectedCSType",
        3073 => "PCSCitation",
        3074 => "Projection",
        3075 => "ProjCoordTrans",
        3076 => "ProjLinearUnits",
        4096 => "VerticalCSType",
        4097 => "VerticalCitation",
        4098 => "VerticalDatum",
        4099 => "VerticalUnits",
        _ => return None,
    })
}

fn sample_format(f: u64, bits: u64) -> String {
    let kind = match f {
        2 => "int",
        3 => "float",
        5 => "complex_int",
        6 => "complex_float",
        _ => "uint",
    };
    format!("{kind}{bits}")
}

fn compression(c: u64) -> String {
    match c {
        1 => "none",
        5 => "lzw",
        6 | 7 => "jpeg",
        8 | 32946 => "deflate",
        32773 => "packbits",
        34887 => "lerc",
        34925 => "lzma",
        50000 => "zstd",
        50001 => "webp",
        50002 => "jpegxl",
        _ => return format!("{c}"),
    }
    .into()
}

#[allow(clippy::too_many_lines)] // IFD walk, GeoKeys, transform, COG checks
fn geotiff(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let head = src.read_vec(0, 16).map_err(|_| ExtractError::malformed("TIFF header"))?;
    let (t, first) = header(&head).ok_or_else(|| ExtractError::malformed("TIFF header"))?;
    cx.format_set("bigtiff", t.big);
    cx.format_set("byte_order", if t.le { "little-endian" } else { "big-endian" });
    // Every IFD: the main image, overviews (reduced resolution) and masks.
    let mut ifds = Vec::new();
    let mut offsets = Vec::new();
    let mut at = first;
    let mut seen = std::collections::BTreeSet::new();
    while at != 0 && ifds.len() < 256 && seen.insert(at) {
        let Some((ifd, next)) = t.ifd(src, at) else { break };
        offsets.push(at);
        ifds.push(ifd);
        at = next;
    }
    let main = ifds.first().cloned().ok_or_else(|| ExtractError::malformed("no IFD"))?;
    let int1 = |src: &mut dyn Source, ifd: &BTreeMap<u16, Entry>, tag| {
        ifd.get(&tag).and_then(|e| t.ints(src, e).first().copied())
    };
    let width = int1(src, &main, 256).unwrap_or(0);
    let height = int1(src, &main, 257).unwrap_or(0);
    let bands = int1(src, &main, 277).unwrap_or(1);
    let bits = int1(src, &main, 258).unwrap_or(1);
    let fmt = int1(src, &main, 339).unwrap_or(1);
    cx.format_set("width", width);
    cx.format_set("height", height);
    cx.format_set("bands", bands);
    cx.format_set("data_type", sample_format(fmt, bits));
    cx.format_set("compression", compression(int1(src, &main, 259).unwrap_or(1)));
    if let Some(p) = int1(src, &main, 284) {
        cx.format_set("interleave", if p == 2 { "band" } else { "pixel" });
    }
    let tiled = main.contains_key(&322);
    cx.format_set("tiled", tiled);
    if tiled {
        cx.format_set(
            "block_size",
            Value::Array(vec![int1(src, &main, 322).unwrap_or(0).into(), int1(src, &main, 323).unwrap_or(0).into()]),
        );
    }
    if let (Ok(w), Ok(h)) = (u32::try_from(width), u32::try_from(height)) {
        let mut img = cx.physical().image(w, h);
        if let Ok(b) = u8::try_from(bits) {
            img.bit_depth(b);
        }
    }
    let (mut overviews, mut masks) = (Vec::new(), 0u64);
    for ifd in ifds.iter().skip(1) {
        let kind = int1(src, ifd, 254).unwrap_or(0);
        if kind & 4 != 0 {
            masks += 1;
        } else if kind & 1 != 0 {
            let (w, h) = (int1(src, ifd, 256).unwrap_or(0), int1(src, ifd, 257).unwrap_or(0));
            overviews.push(format!("{w}x{h}"));
        }
    }
    cx.format_set("overviews", overviews.clone());
    if masks > 0 {
        cx.format_set("masks", masks);
    }
    // GeoKeys.
    let mut keys = Map::new();
    let mut model = 0u64;
    let mut raster_type = 1u64;
    let (mut geog, mut proj, mut citation) = (None, None, None::<String>);
    if let Some(dir) = main.get(&34735) {
        let k = t.ints(src, dir);
        let doubles = main.get(&34736).map(|e| t.doubles(src, e)).unwrap_or_default();
        let ascii = main.get(&34737).map(|e| Tiff::ascii(src, e)).unwrap_or_default();
        if k.len() >= 4 {
            cx.format_set("geokey_version", format!("{}.{}.{}", k[0], k[1], k[2]));
            for key in k[4..].as_chunks::<4>().0.iter().take(usize::try_from(k[3]).unwrap_or(0).min(256)) {
                let (id, loc, count, value) = (key[0], key[1], key[2], key[3]);
                let v: Value = match loc {
                    0 => value.into(),
                    34737 => {
                        let s = ascii.get(usize::try_from(value).unwrap_or(usize::MAX)..).unwrap_or("");
                        let n = usize::try_from(count).unwrap_or(0).min(s.len());
                        truncate_chars(s[..n].trim_end_matches('|'), 200).into()
                    }
                    34736 => {
                        doubles.get(usize::try_from(value).unwrap_or(usize::MAX)).map_or(Value::Null, |&d| num(d, 9))
                    }
                    _ => continue,
                };
                match id {
                    1024 => model = value,
                    1025 => raster_type = value,
                    2048 if value != 32767 => geog = u32::try_from(value).ok(),
                    3072 if value != 32767 => proj = u32::try_from(value).ok(),
                    1026 | 3073 | 2049 if citation.is_none() => citation = v.as_str().map(str::to_string),
                    _ => {}
                }
                let name = geokey_name(id).map_or_else(|| format!("key {id}"), str::to_string);
                keys.insert(name, v);
            }
        }
    }
    if !keys.is_empty() {
        cx.format_set("geokeys", Value::Object(keys));
    }
    cx.format_set(
        "model_type",
        match model {
            1 => "projected",
            2 => "geographic",
            3 => "geocentric",
            _ => "unknown",
        },
    );
    cx.format_set("raster_type", if raster_type == 2 { "PixelIsPoint" } else { "PixelIsArea" });
    let epsg = if model == 1 { proj } else { geog.or(proj) };
    let crs = (epsg.is_some() || citation.is_some()).then(|| Crs {
        name: citation.clone(),
        epsg,
        geographic: model == 2 || epsg.is_some_and(|e| Crs::epsg(e).geographic),
    });
    // The geotransform: pixel (i, j) to model (x, y).
    let scale = main.get(&33550).map(|e| t.doubles(src, e)).unwrap_or_default();
    let ties = main.get(&33922).map(|e| t.doubles(src, e)).unwrap_or_default();
    let matrix = main.get(&34264).map(|e| t.doubles(src, e)).unwrap_or_default();
    // PixelIsPoint: the tie point is a pixel's centre, as GDAL reads it.
    let shift = if raster_type == 2 { 0.5 } else { 0.0 };
    let transform: Option<[f64; 6]> = if matrix.len() >= 16 {
        Some([matrix[3], matrix[0], matrix[1], matrix[7], matrix[4], matrix[5]])
    } else if scale.len() >= 2 && ties.len() >= 6 {
        let (sx, sy) = (scale[0], scale[1]);
        Some([ties[3] - (ties[0] + shift) * sx, sx, 0.0, ties[4] + (ties[1] + shift) * sy, 0.0, -sy])
    } else {
        None
    };
    if ties.len() > 6 {
        cx.format_set("tie_points", ties.len() / 6);
    }
    if let Some(g) = transform {
        cx.format_set("geotransform", Value::Array(g.iter().map(|&v| num(v, 9)).collect()));
        let (w, h) = (width as f64, height as f64);
        let mut b = Bounds::default();
        for (i, j) in [(0.0, 0.0), (w, 0.0), (0.0, h), (w, h)] {
            b.add(g[0] + i * g[1] + j * g[2], g[3] + i * g[4] + j * g[5]);
        }
        if crs.is_some() {
            report_bounds(cx, &b, crs.as_ref(), "geotiff");
        } else {
            report_native(cx, &b);
        }
        cx.format_set("pixel_size", Value::Array(vec![num(g[1], 12), num(-g[5], 12)]));
    } else if let Some(c) = &crs {
        cx.format_set("crs", c.json());
    }
    if let Some(e) = main.get(&42113) {
        let nd = Tiff::ascii(src, e);
        cx.format_set("nodata", truncate_chars(nd.trim(), 40));
    }
    if let Some(e) = main.get(&42112) {
        // <GDALMetadata><Item name="…" [sample="…"]>value</Item>…
        let xml = Tiff::ascii(src, e);
        let mut items = Map::new();
        for part in xml.split("<Item ").skip(1).take(200) {
            let name = part.split("name=\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("");
            let value = part.split('>').nth(1).and_then(|r| r.split('<').next()).unwrap_or("");
            if !part.contains("sample=") && !name.is_empty() {
                items.insert(truncate_chars(name, 60), truncate_chars(value, 200).into());
            }
        }
        if !items.is_empty() {
            cx.format_set("gdal_metadata", Value::Object(items));
        }
    }
    if let Some(s) = main.get(&305).map(|e| Tiff::ascii(src, e)).filter(|s| !s.is_empty()) {
        cx.format_set("software", truncate_chars(&s, 100));
    }
    // COG: every IFD before the first block of data.
    let first_data = ifds
        .iter()
        .filter_map(|ifd| ifd.get(&324).or_else(|| ifd.get(&273)).map(|e| t.ints(src, e)))
        .filter_map(|v| v.into_iter().filter(|&o| o > 0).min())
        .min();
    let ifds_first = first_data.is_some_and(|d| offsets.iter().all(|&o| o < d));
    let ghost = src.read_vec(if t.big { 16 } else { 8 }, 300).unwrap_or_default();
    let ghost = String::from_utf8_lossy(&ghost);
    let mut cog = Map::new();
    if let Some(rest) = ghost.strip_prefix("GDAL_STRUCTURAL_METADATA_SIZE=") {
        for line in rest.lines().skip(1).take(10) {
            if let Some((k, v)) = line.split_once('=') {
                cog.insert(truncate_chars(k, 40), truncate_chars(v.trim(), 40).into());
            }
        }
    }
    cog.insert("ifds_before_data".into(), ifds_first.into());
    // As GDAL's validator: IFDs first; tiled, unless the image is at most
    // 512 x 512 and has no overviews.
    let small = width <= 512 && height <= 512;
    let is_cog = ifds_first && (tiled || small && overviews.is_empty());
    cog.insert("conforms".into(), is_cog.into());
    cx.format_set("cog", Value::Object(cog));
    Ok(())
}

/// `DDDMMSSH` to degrees.
fn dms(s: &str) -> Option<f64> {
    let s = s.trim();
    let hemi = s.chars().last()?;
    let d = s.get(..s.len() - 1)?;
    let (deg, rest) = d.split_at(d.len().checked_sub(4)?);
    let v = deg.parse::<f64>().ok()?
        + rest.get(..2)?.parse::<f64>().ok()? / 60.0
        + rest.get(2..)?.parse::<f64>().ok()? / 3600.0;
    Some(if matches!(hemi, 'S' | 'W') { -v } else { v })
}

fn dted(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 80 + 648).map_err(|_| ExtractError::malformed("UHL"))?;
    let text = |a: usize, b: usize| String::from_utf8_lossy(h.get(a..b).unwrap_or_default()).trim().to_string();
    let lon0 = dms(&text(4, 12)).ok_or_else(|| ExtractError::malformed("UHL origin"))?;
    let lat0 = dms(&text(12, 20)).ok_or_else(|| ExtractError::malformed("UHL origin"))?;
    let dlon: f64 = text(20, 24).parse().unwrap_or(0.0) / 10.0;
    let dlat: f64 = text(24, 28).parse().unwrap_or(0.0) / 10.0;
    let ncols: u32 = text(47, 51).parse().unwrap_or(0);
    let nrows: u32 = text(51, 55).parse().unwrap_or(0);
    cx.format_set("interval_arcsec", Value::Array(vec![num(dlon, 1), num(dlat, 1)]));
    cx.format_set("columns", ncols);
    cx.format_set("rows", nrows);
    if let Ok(a) = text(28, 32).parse::<u32>() {
        cx.format_set("vertical_accuracy_m", a);
    }
    cx.format_set("security", text(32, 35));
    if h.get(80..83) == Some(b"DSI") {
        let level = text(80 + 59, 80 + 64);
        if !level.is_empty() {
            cx.format_set("product_level", level);
        }
    }
    cx.physical().image(ncols, nrows);
    let mut b = Bounds::default();
    b.add(lon0, lat0);
    b.add(
        lon0 + f64::from(ncols.saturating_sub(1)) * dlon / 3600.0,
        lat0 + f64::from(nrows.saturating_sub(1)) * dlat / 3600.0,
    );
    report_bounds(cx, &b, Some(&Crs::epsg(4326)), "dted.UHL");
    Ok(())
}

/// Whether the TIFF in `h` carries GeoTIFF tags in an IFD the windows hold.
fn has_geotags(h: &[u8], tail: &[u8], len: u64) -> bool {
    let Some((t, first)) = header(h) else { return false };
    let (count_len, entry_len) = if t.big { (8usize, 20usize) } else { (2, 12) };
    let window = |at: u64| -> Option<&[u8]> {
        if let Some(s) = usize::try_from(at).ok().and_then(|a| h.get(a..)) {
            return Some(s);
        }
        let tail_start = len.checked_sub(tail.len() as u64)?;
        let a = usize::try_from(at.checked_sub(tail_start)?).ok()?;
        tail.get(a..)
    };
    let Some(w) = window(first) else { return false };
    let Some(c) = w.get(..count_len) else { return false };
    let n = if t.big { usize::try_from(t.u64(c)).unwrap_or(0) } else { usize::from(t.u16(c)) };
    (0..n.min(4096)).any(|i| {
        w.get(count_len + i * entry_len..count_len + i * entry_len + 2)
            .is_some_and(|tag| matches!(t.u16(tag), 33550 | 33922 | 34264 | 34735))
    })
}

impl Extractor for Raster {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if (h.starts_with(b"II") || h.starts_with(b"MM")) && has_geotags(h, probe.tail, probe.len) {
            return Some(Sniff { format: "geotiff", confidence: 0.97 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "geotiff" => geotiff(cx, src),
            _ => dted(cx, src),
        }
    }
}

crate::register_extractor!(Raster);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dted_angles() {
        assert!((dms("0070000E").unwrap() - 7.0).abs() < 1e-9);
        assert!((dms("0453000S").unwrap() + 45.5).abs() < 1e-9);
    }

    crate::fixture_tests!("geotiff", "dted");
}
