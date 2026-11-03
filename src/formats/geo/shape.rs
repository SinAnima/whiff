//! Esri vector stores:
//! * shapefiles: the main file (`.shp`: shape type, bounds with Z and M
//!   ranges, records, null shapes) and its index (`.shx`: records);
//!   the CRS and attributes live in the `.prj` and `.dbf` beside them;
//! * File Geodatabase tables (`.gdbtable`): version, rows, geometry type,
//!   fields, and the geometry field's CRS and extent.
//!
//! Specifications: Esri "Shapefile Technical Description" (1998); the
//! `FileGDB` table layout as documented by GDAL's `OpenFileGDB` driver
//! (`gdbtable` header, field descriptors).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Bounds, Crs, hist, num, report_bounds, report_native};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for shapefiles and File Geodatabase tables.
pub struct Shape;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.shape",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "shapefile",
            name: "ESRI Shapefile",
            family: "geo",
            mimes: &["application/vnd.shp"],
            extensions: &["shp"],
            magic: &[Magic::at(0, b"\x00\x00\x27\x0a")],
            parent: None,
        },
        FormatSpec {
            id: "shapefile_index",
            name: "Shapefile index",
            family: "geo",
            mimes: &[],
            extensions: &["shx"],
            magic: &[Magic::at(0, b"\x00\x00\x27\x0a")],
            parent: None,
        },
        FormatSpec {
            id: "filegdb_table",
            name: "Esri File Geodatabase / Personal GDB",
            family: "geo",
            mimes: &[],
            extensions: &["gdbtable"],
            magic: &[],
            parent: None,
        },
    ],
};

fn shape_type(t: u32) -> &'static str {
    match t {
        0 => "Null",
        1 => "Point",
        3 => "PolyLine",
        5 => "Polygon",
        8 => "MultiPoint",
        11 => "PointZ",
        13 => "PolyLineZ",
        15 => "PolygonZ",
        18 => "MultiPointZ",
        21 => "PointM",
        23 => "PolyLineM",
        25 => "PolygonM",
        28 => "MultiPointM",
        31 => "MultiPatch",
        _ => "unknown",
    }
}

fn le_f64(b: &[u8], at: usize) -> f64 {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map_or(f64::NAN, f64::from_le_bytes)
}

fn shp(cx: &mut Context<'_>, src: &mut dyn Source, index: bool) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 100).map_err(|_| ExtractError::malformed("header"))?;
    if h.len() < 100 {
        return Err(ExtractError::malformed("header"));
    }
    let be = |at: usize| u32::from_be_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
    let le = |at: usize| u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
    let declared = u64::from(be(24)) * 2;
    cx.format_set("version", le(28));
    let kind = le(32);
    cx.format_set("shape_type", shape_type(kind));
    if declared != src.len() {
        cx.format_set("declared_length", declared);
    }
    let mut b = Bounds::default();
    b.add(le_f64(&h, 36), le_f64(&h, 44));
    b.add(le_f64(&h, 52), le_f64(&h, 60));
    if matches!(kind, 11 | 13 | 15 | 18 | 31) {
        b.add_z(le_f64(&h, 68));
        b.add_z(le_f64(&h, 76));
    }
    if matches!(kind, 21 | 23 | 25 | 28 | 11 | 13 | 15 | 18 | 31) {
        let (m0, m1) = (le_f64(&h, 84), le_f64(&h, 92));
        // "No data" M values are below -1e38.
        if m0 > -1e38 && m1 > -1e38 && (m0 != 0.0 || m1 != 0.0) {
            cx.format_set("m_range", Value::Array(vec![num(m0, 6), num(m1, 6)]));
        }
    }
    if index {
        // Eight bytes per record after the header.
        cx.format_set("records", src.len().saturating_sub(100) / 8);
    } else {
        let (records, nulls, types) = walk_records(cx, src)?;
        cx.format_set("records", records);
        if nulls > 0 {
            cx.format_set("null_shapes", nulls);
        }
        if types.len() > 1 {
            cx.format_set("record_types", hist(types));
        }
    }
    // The bounds are the header's, not computed from the records.
    if b.min[0] <= b.max[0] && b.min[1] <= b.max[1] {
        report_native(cx, &b);
    }
    Ok(())
}

/// The records of a `.shp`: count, null shapes, types (read in chunks).
fn walk_records(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(u64, u64, BTreeMap<String, u64>), ExtractError> {
    let len = src.len();
    let (mut at, mut records, mut nulls) = (100u64, 0u64, 0u64);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut buf_at = 0u64;
    while at + 12 <= len && records < 50_000_000 {
        if records % 65_536 == 0 {
            cx.checkpoint()?;
        }
        if at < buf_at || at + 12 > buf_at + buf.len() as u64 {
            buf_at = at;
            let n = usize::try_from((len - at).min(1 << 20)).unwrap_or(1 << 20);
            buf = src.read_vec(at, n).map_err(|_| ExtractError::malformed("record"))?;
        }
        let i = usize::try_from(at - buf_at).unwrap_or(0);
        let r = &buf[i..];
        let words = u32::from_be_bytes([r[4], r[5], r[6], r[7]]);
        let kind = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);
        records += 1;
        if kind == 0 {
            nulls += 1;
        } else if types.len() < 20 {
            *types.entry(shape_type(kind).into()).or_default() += 1;
        }
        let next = at + 8 + u64::from(words) * 2;
        if next <= at {
            break;
        }
        at = next;
    }
    Ok((records, nulls, types))
}

/// A cursor over a `.gdbtable` field descriptor section.
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cur<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn f64(&mut self) -> Option<f64> {
        let s = self.take(8)?;
        Some(f64::from_le_bytes(s.try_into().ok()?))
    }
    fn varuint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let c = self.u8()?;
            v |= u64::from(c & 0x7f) << shift;
            if c & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    /// A UTF-16 string of `chars` code units.
    fn utf16(&mut self, chars: usize) -> Option<String> {
        let s = self.take(chars.checked_mul(2)?)?;
        let units: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

fn field_type(t: u8) -> &'static str {
    match t {
        0 => "int16",
        1 => "int32",
        2 => "float32",
        3 => "float64",
        4 => "string",
        5 => "datetime",
        6 => "objectid",
        7 => "geometry",
        8 => "binary",
        9 => "raster",
        10 => "guid",
        11 => "globalid",
        12 => "xml",
        13 => "int64",
        14 => "date",
        15 => "time",
        16 => "datetime_offset",
        _ => "unknown",
    }
}

fn gdb_geometry(t: u32) -> &'static str {
    match t & 0xff {
        0 => "none",
        1 => "point",
        2 => "multipoint",
        3 => "polyline",
        4 => "polygon",
        5 => "multipatch",
        _ => "unknown",
    }
}

/// The geometry field's CRS and extent.
struct GeomField {
    crs: Option<Crs>,
    bounds: Bounds,
}

/// One field descriptor: (name, type, geometry details).
fn gdb_field(c: &mut Cur<'_>) -> Option<(String, u8, Option<GeomField>)> {
    let n = usize::from(c.u8()?);
    let name = c.utf16(n)?;
    let n = usize::from(c.u8()?);
    c.utf16(n)?; // alias
    let t = c.u8()?;
    let mut geom = None;
    match t {
        4 => {
            c.u32()?; // width
            let flag = c.u8()?;
            if flag & 4 != 0 {
                let d = usize::try_from(c.varuint()?).ok()?;
                c.take(d)?;
            }
        }
        7 => {
            c.u8()?;
            c.u8()?; // flag
            let wkt_bytes = usize::from(c.u16()?);
            let wkt = c.utf16(wkt_bytes / 2)?;
            let magic = c.u8()?;
            let (has_m, has_z) = (magic & 2 != 0, magic & 4 != 0);
            for _ in 0..3 {
                c.f64()?; // origin and scale
            }
            if has_m {
                c.f64()?;
                c.f64()?;
            }
            if has_z {
                c.f64()?;
                c.f64()?;
            }
            c.f64()?; // tolerance
            if has_m {
                c.f64()?;
            }
            if has_z {
                c.f64()?;
            }
            let (x0, y0, x1, y1) = (c.f64()?, c.f64()?, c.f64()?, c.f64()?);
            let mut bounds = Bounds::default();
            if x0.is_finite() && x0 <= x1 && y0 <= y1 {
                bounds.add(x0, y0);
                bounds.add(x1, y1);
            }
            // Then the spatial index grid sizes (a zero byte, a count of 1–3),
            // with Z and M extents before them only in some writers' files.
            let at = c.at;
            let grid_count = |c: &mut Cur<'_>| -> Option<u32> {
                (c.u8()? == 0).then_some(())?;
                c.u32().filter(|n| (1..=3).contains(n))
            };
            let grids = if let Some(n) = grid_count(c) {
                n
            } else {
                c.at = at;
                for _ in 0..2 * (usize::from(has_z) + usize::from(has_m)) {
                    c.f64()?;
                }
                grid_count(c)?
            };
            for _ in 0..grids {
                c.f64()?;
            }
            geom = Some(GeomField { crs: Crs::from_wkt(&wkt), bounds });
        }
        6 | 8 | 10 | 11 | 12 => {
            c.take(2)?;
        }
        9 => {
            // Raster: a name, a WKT, then flags; rare outside raster catalogs.
            c.u8()?;
            c.u8()?;
            let n = usize::from(c.u8()?);
            c.utf16(n)?;
            let wkt_bytes = usize::from(c.u16()?);
            c.take(wkt_bytes)?;
            let magic = c.u8()?;
            let extra = 3
                + usize::from(magic & 2 != 0) * 2
                + usize::from(magic & 4 != 0) * 2
                + 1
                + usize::from(magic & 2 != 0)
                + usize::from(magic & 4 != 0);
            c.take(extra * 8)?;
            c.u8()?;
        }
        0..=3 | 5 | 13..=16 => {
            c.u8()?; // width
            let flag = c.u8()?;
            let d = usize::from(c.u8()?);
            if flag & 4 != 0 || d > 0 {
                c.take(d)?;
            }
        }
        _ => return None,
    }
    Some((name, t, geom))
}

fn gdbtable(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("gdbtable header");
    let h = src.read_vec(0, 40).map_err(|_| bad())?;
    let mut c = Cur { b: &h, at: 0 };
    let magic = c.u32().ok_or_else(bad)?;
    let rows = c.u32().ok_or_else(bad)?;
    if magic != 3 && magic != 4 {
        return Err(bad());
    }
    cx.format_set("rows", rows);
    let fields_at = u64::from_le_bytes(h.get(32..40).and_then(|s| s.try_into().ok()).ok_or_else(bad)?);
    let head = src.read_vec(fields_at, 14).map_err(|_| bad())?;
    let mut c = Cur { b: &head, at: 0 };
    let section = c.u32().ok_or_else(bad)?;
    let version = c.u32().ok_or_else(bad)?;
    let flags = c.u32().ok_or_else(bad)?;
    let count = c.u16().ok_or_else(bad)?;
    cx.format_set(
        "table_version",
        match version {
            3 => "10.x".to_string(),
            4 => "Pro 3.2+ (64-bit object IDs)".to_string(),
            v => format!("{v}"),
        },
    );
    cx.format_set("geometry_type", gdb_geometry(flags));
    let body = src.read_vec(fields_at + 4, usize::try_from(section).unwrap_or(0).min(16 << 20)).map_err(|_| bad())?;
    let mut c = Cur { b: &body, at: 10 };
    let mut fields = Vec::new();
    let mut geom = None;
    for _ in 0..count.min(2000) {
        let Some((name, t, g)) = gdb_field(&mut c) else {
            cx.warn("field descriptors not fully read");
            break;
        };
        fields.push(format!("{} ({})", truncate_chars(&name, 60), field_type(t)));
        if g.is_some() {
            geom = g;
        }
    }
    cx.format_set("field_count", count);
    cx.format_set("fields", fields);
    if let Some(g) = geom {
        if let Some(c) = &g.crs {
            cx.format_set("crs", c.json());
        }
        if g.crs.is_some() {
            report_bounds(cx, &g.bounds, g.crs.as_ref(), "gdbtable.extent");
        } else {
            report_native(cx, &g.bounds);
        }
    }
    Ok(())
}

impl Extractor for Shape {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"\x00\x00\x27\x0a") && h.len() >= 100 && h[28..32] == 1000u32.to_le_bytes() {
            let index = probe.extension == Some("shx")
                || u64::from(u32::from_be_bytes([h[24], h[25], h[26], h[27]])) * 2 == probe.len
                    && probe.len >= 100
                    && (probe.len - 100).is_multiple_of(8)
                    && probe.extension != Some("shp");
            return Some(Sniff { format: if index { "shapefile_index" } else { "shapefile" }, confidence: 0.95 });
        }
        let gdb = probe.extension == Some("gdbtable")
            && h.len() >= 40
            && matches!(h[0..4], [3 | 4, 0, 0, 0])
            && u64::from_le_bytes(h[32..40].try_into().unwrap_or_default()) < probe.len;
        gdb.then_some(Sniff { format: "filegdb_table", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "shapefile" => shp(cx, src, false),
            "shapefile_index" => shp(cx, src, true),
            _ => gdbtable(cx, src),
        }
    }
}

crate::register_extractor!(Shape);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdb_varuint_and_strings() {
        let mut c = Cur { b: &[0x96, 0x01, 3, b'a', 0, b'b', 0, b'c', 0], at: 0 };
        assert_eq!(c.varuint(), Some(150));
        let n = usize::from(c.u8().unwrap());
        assert_eq!(c.utf16(n).as_deref(), Some("abc"));
        assert_eq!(c.u8(), None);
    }

    crate::fixture_tests!("shapefile", "shapefile_index", "filegdb_table");
}
