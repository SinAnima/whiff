//! Point clouds:
//! * LAS 1.0–1.4, LAZ (`LASzip`) and COPC: version, system and software,
//!   creation day, point format and record length, point counts (by
//!   return), scale and offset, bounds, the variable length records, the
//!   CRS (OGC WKT or `GeoKeys` records), compression, and the COPC info
//!   record (octree centre, spacing, GPS time range);
//! * ASTM E57: version, library, creation time, scans with their names,
//!   point counts, bounds and sensors, images, the coordinate metadata;
//!   sensor serial numbers only with privacy off.
//!
//! Specifications: ASPRS LAS 1.4 R15; `LASzip` (rapidlasso, the `laszip
//! encoded` VLR); COPC 1.0; ASTM E2807-11 (E57).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{Bounds, Crs, Ev, attr, num, report_bounds, report_native, walk_xml};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for point clouds.
pub struct Points;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.points",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "las",
            name: "LAS / LAZ point cloud",
            family: "geo",
            mimes: &["application/vnd.las"],
            extensions: &["las"],
            magic: &[Magic::at(0, b"LASF")],
            parent: None,
        },
        FormatSpec {
            id: "laz",
            name: "LAZ point cloud",
            family: "geo",
            mimes: &["application/vnd.laszip"],
            extensions: &["laz"],
            magic: &[Magic::at(0, b"LASF")],
            parent: None,
        },
        FormatSpec {
            id: "copc",
            name: "Cloud Optimized Point Cloud",
            family: "geo",
            mimes: &[],
            extensions: &["copc"],
            magic: &[Magic::at(0, b"LASF")],
            parent: None,
        },
        FormatSpec {
            id: "e57",
            name: "E57 point cloud",
            family: "geo",
            mimes: &["model/e57"],
            extensions: &["e57"],
            magic: &[Magic::at(0, b"ASTM-E57")],
            parent: None,
        },
    ],
};

fn le_u16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}
fn le_u32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map_or(0, u64::from_le_bytes)
}
fn le_f64(b: &[u8], at: usize) -> f64 {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map_or(f64::NAN, f64::from_le_bytes)
}
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

/// The CRS from `GeoKeys` VLR data (`ProjectedCSType`, else `GeographicType`).
fn geokeys_crs(k: &[u8]) -> Option<Crs> {
    let n = usize::from(le_u16(k, 6));
    let mut epsg = (None, None);
    for i in 0..n.min(256) {
        let at = 8 + i * 8;
        let (id, loc, value) = (le_u16(k, at), le_u16(k, at + 2), le_u16(k, at + 6));
        if loc != 0 || value == 32767 {
            continue;
        }
        match id {
            3072 => epsg.0 = Some(u32::from(value)),
            2048 => epsg.1 = Some(u32::from(value)),
            _ => {}
        }
    }
    epsg.0.or(epsg.1).map(Crs::epsg)
}

#[allow(clippy::too_many_lines)] // the header, then the records
fn las(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 375).map_err(|_| ExtractError::malformed("LAS header"))?;
    if h.len() < 227 || !h.starts_with(b"LASF") {
        return Err(ExtractError::malformed("LAS header"));
    }
    let (major, minor) = (h[24], h[25]);
    cx.format_set("las_version", format!("{major}.{minor}"));
    let system = cstr(&h[26..58]);
    let software = cstr(&h[58..90]);
    if !system.is_empty() {
        cx.format_set("system_identifier", truncate_chars(&system, 32));
    }
    if !software.is_empty() {
        cx.format_set("generating_software", truncate_chars(&software, 32));
    }
    let (doy, year) = (le_u16(&h, 90), le_u16(&h, 92));
    if year > 1900
        && (1..=366).contains(&doy)
        && let Ok(d) = jiff::civil::Date::new(i16::try_from(year).unwrap_or(1970), 1, 1)
            .and_then(|d| d.checked_add(jiff::Span::new().days(i64::from(doy) - 1)))
    {
        let s = d.to_string();
        cx.format_set("creation_date", s.clone());
        cx.temporal().source("las.header").content_date(DateField::Created, s, false);
    }
    let header_size = le_u16(&h, 94);
    let point_offset = le_u32(&h, 96);
    let vlrs = le_u32(&h, 100);
    let format = h[104];
    let compressed = format & 0xc0 != 0;
    cx.format_set("point_format", format & 0x3f);
    cx.format_set("point_record_length", le_u16(&h, 105));
    cx.format_set("compressed", compressed);
    let global = le_u16(&h, 6);
    if global & 0x10 != 0 {
        cx.format_set("crs_encoding", "wkt");
    }
    let mut points = u64::from(le_u32(&h, 107));
    if (major, minor) >= (1, 4) && h.len() >= 255 {
        let p64 = le_u64(&h, 247);
        if p64 > 0 {
            points = p64;
        }
    }
    cx.format_set("points", points);
    let by_return: Vec<u64> = if (major, minor) >= (1, 4) && h.len() >= 375 {
        (0..15).map(|i| le_u64(&h, 255 + i * 8)).collect()
    } else {
        (0..5).map(|i| u64::from(le_u32(&h, 111 + i * 4))).collect()
    };
    let last = by_return.iter().rposition(|&n| n > 0).map_or(0, |i| i + 1);
    cx.format_set("points_by_return", by_return[..last].to_vec());
    let s = |i: usize| num(le_f64(&h, 131 + i * 8), 12);
    cx.format_set("scale", Value::Array(vec![s(0), s(1), s(2)]));
    cx.format_set("offset", Value::Array(vec![s(3), s(4), s(5)]));
    let mut b = Bounds::default();
    b.add(le_f64(&h, 187), le_f64(&h, 203));
    b.add(le_f64(&h, 179), le_f64(&h, 195));
    b.add_z(le_f64(&h, 219));
    b.add_z(le_f64(&h, 211));
    // The variable length records.
    let mut list = Vec::new();
    let mut crs = None;
    let mut copc = None;
    let mut at = u64::from(header_size);
    for _ in 0..vlrs.min(1000) {
        let Ok(r) = src.read_vec(at, 54) else { break };
        if r.len() < 54 {
            break;
        }
        let user = cstr(&r[2..18]);
        let id = le_u16(&r, 18);
        let len = le_u16(&r, 20);
        let desc = cstr(&r[22..54]);
        let data_at = at + 54;
        match (user.as_str(), id) {
            ("LASF_Projection", 2112) => {
                let d = src.read_vec(data_at, usize::from(len)).unwrap_or_default();
                crs = Crs::from_wkt(&cstr(&d)).or(crs);
            }
            ("LASF_Projection", 34735) if crs.is_none() => {
                let d = src.read_vec(data_at, usize::from(len)).unwrap_or_default();
                crs = geokeys_crs(&d);
            }
            ("copc", 1) => copc = src.read_vec(data_at, usize::from(len).min(160)).ok(),
            _ => {}
        }
        if list.len() < 50 {
            list.push(format!(
                "{user}/{id}{}",
                if desc.is_empty() { String::new() } else { format!(" ({})", truncate_chars(&desc, 32)) }
            ));
        }
        at = data_at + u64::from(len);
        if at > u64::from(point_offset) {
            break;
        }
    }
    cx.format_set("vlrs", list);
    if let Some(c) = copc.filter(|c| c.len() >= 80) {
        let mut m = Map::new();
        m.insert("center".into(), Value::Array((0..3).map(|i| num(le_f64(&c, i * 8), 6)).collect()));
        m.insert("halfsize".into(), num(le_f64(&c, 24), 6));
        m.insert("spacing".into(), num(le_f64(&c, 32), 6));
        m.insert("gpstime_range".into(), Value::Array(vec![num(le_f64(&c, 56), 6), num(le_f64(&c, 64), 6)]));
        cx.format_set("copc", Value::Object(m));
    }
    if crs.is_some() {
        report_bounds(cx, &b, crs.as_ref(), "las.header");
    } else {
        report_native(cx, &b);
    }
    Ok(())
}

/// The logical bytes of an E57 file: each 1024-byte page ends in a CRC.
fn e57_logical(src: &mut dyn Source, physical: u64, logical_len: usize, page: u64) -> Option<Vec<u8>> {
    let payload = page.checked_sub(4)?;
    let mut out = Vec::with_capacity(logical_len.min(16 << 20));
    let mut at = physical;
    while out.len() < logical_len {
        let in_page = at % page;
        if in_page >= payload {
            // Inside a page's CRC: skip to the next page.
            at += page - in_page;
            continue;
        }
        let n = usize::try_from((payload - in_page).min((logical_len - out.len()) as u64)).ok()?;
        let chunk = src.read_vec(at, n).ok()?;
        if chunk.len() != n {
            return None;
        }
        out.extend(chunk);
        at += n as u64;
    }
    Some(out)
}

/// An E57 element name in snake case (`e57LibraryVersion`).
fn snake(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// GPS seconds (E57 `dateTimeValue`) to RFC 3339 UTC.
fn gps_time(s: f64) -> Option<String> {
    // GPS epoch 1980-01-06; leap seconds since then: 18 (2017 onwards).
    let unix = 315_964_800.0 + s - if s > 1_167_264_018.0 { 18.0 } else { 0.0 };
    #[allow(clippy::cast_possible_truncation)] // seconds
    super::unix_time(unix as i64)
}

#[allow(clippy::too_many_lines)] // the header, then the XML tree
fn e57(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 48).map_err(|_| ExtractError::malformed("E57 header"))?;
    if h.len() < 48 {
        return Err(ExtractError::malformed("E57 header"));
    }
    cx.format_set("e57_version", format!("{}.{}", le_u32(&h, 8), le_u32(&h, 12)));
    let xml_at = le_u64(&h, 24);
    let xml_len = usize::try_from(le_u64(&h, 32)).unwrap_or(0).min(64 << 20);
    let page = le_u64(&h, 40);
    if !(64..=1 << 20).contains(&page) {
        return Err(ExtractError::malformed("E57 page size"));
    }
    let xml = e57_logical(src, xml_at, xml_len, page).ok_or_else(|| ExtractError::malformed("E57 XML section"))?;
    let text = String::from_utf8_lossy(&xml).into_owned();
    let mut path: Vec<String> = Vec::new();
    let mut root = Map::new();
    let mut scans: Vec<Map<String, Value>> = Vec::new();
    let mut images = 0u64;
    let mut total = Bounds::default();
    let mut bounds_parts: BTreeMap<String, f64> = BTreeMap::new();
    let mut points_total = 0u64;
    walk_xml(&text, cx, 10_000_000, |cx, ev| match ev {
        Ev::Start(n, a) => {
            let parent = path.last().map_or("", String::as_str);
            if parent == "data3D" && n == "vectorChild" {
                scans.push(Map::new());
                bounds_parts.clear();
            }
            if parent == "images2D" && n == "vectorChild" {
                images += 1;
            }
            if n == "points"
                && path.len() == 3
                && path[1] == "data3D"
                && let Some(c) = attr(a, "recordCount").and_then(|c| c.parse::<u64>().ok())
                && let Some(s) = scans.last_mut()
            {
                s.insert("points".into(), c.into());
                points_total += c;
            }
            path.push(n.to_string());
            let _ = cx;
        }
        Ev::End(n) => {
            if n == "vectorChild"
                && path.len() == 3
                && path[1] == "data3D"
                && let Some(s) = scans.last_mut()
            {
                let g = |k: &str| bounds_parts.get(k).copied();
                if let (Some(x0), Some(x1), Some(y0), Some(y1)) =
                    (g("xMinimum"), g("xMaximum"), g("yMinimum"), g("yMaximum"))
                {
                    let mut b = Bounds::default();
                    b.add(x0, y0);
                    b.add(x1, y1);
                    if let (Some(z0), Some(z1)) = (g("zMinimum"), g("zMaximum")) {
                        b.add_z(z0);
                        b.add_z(z1);
                    }
                    s.insert("bounds".into(), b.json());
                    total.merge(&b);
                }
            }
            path.pop();
        }
        Ev::Text(t) => {
            let p: Vec<&str> = path.iter().map(String::as_str).collect();
            match p.as_slice() {
                [
                    "e57Root",
                    k @ ("guid" | "versionMajor" | "versionMinor" | "e57LibraryVersion" | "coordinateMetadata"),
                ] => {
                    root.insert(snake(k), truncate_chars(t, 300).into());
                }
                ["e57Root", "creationDateTime", "dateTimeValue"] => {
                    if let Some(d) = t.parse::<f64>().ok().and_then(gps_time) {
                        root.insert("creation_time".into(), d.into());
                    }
                }
                [
                    "e57Root",
                    "data3D",
                    "vectorChild",
                    k @ ("name" | "description" | "sensorVendor" | "sensorModel" | "sensorSoftwareVersion"),
                ] => {
                    if let Some(s) = scans.last_mut() {
                        s.insert(snake(k), truncate_chars(t, 120).into());
                    }
                }
                ["e57Root", "data3D", "vectorChild", "sensorSerialNumber"] if !cx.privacy_strict() => {
                    if let Some(s) = scans.last_mut() {
                        s.insert("sensor_serial_number".into(), truncate_chars(t, 60).into());
                    }
                }
                ["e57Root", "data3D", "vectorChild", "acquisitionStart", "dateTimeValue"] => {
                    if let (Some(s), Some(d)) = (scans.last_mut(), t.parse::<f64>().ok().and_then(gps_time)) {
                        s.insert("acquisition_start".into(), d.into());
                    }
                }
                ["e57Root", "data3D", "vectorChild", "cartesianBounds", k] => {
                    if let Ok(v) = t.parse::<f64>() {
                        bounds_parts.insert((*k).to_string(), v);
                    }
                }
                _ => {}
            }
        }
    })?;
    let crs = root.get("coordinate_metadata").and_then(Value::as_str).and_then(Crs::from_ref);
    if let Some(d) = root.get("creation_time").and_then(Value::as_str) {
        cx.temporal().source("e57.creationDateTime").content_date(DateField::Created, d.to_string(), true);
    }
    for (k, v) in root {
        cx.format_set(&k, v);
    }
    cx.format_set("scans", scans.len());
    cx.format_set("points", points_total);
    cx.format_set("images", images);
    if let Some(t) = scans.first().and_then(|s| s.get("name")).and_then(Value::as_str) {
        cx.content().source("e57.data3D.name").title(t.to_string());
    }
    cx.format_set("scan_list", Value::Array(scans.into_iter().take(100).map(Value::Object).collect()));
    if crs.is_some() {
        report_bounds(cx, &total, crs.as_ref(), "e57.cartesianBounds");
    } else {
        report_native(cx, &total);
    }
    Ok(())
}

impl Extractor for Points {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if !h.starts_with(b"LASF") || h.len() < 227 {
            return None;
        }
        // COPC: the `copc` info VLR right after a 1.4 header.
        let header = usize::from(le_u16(h, 94));
        if h.get(header + 2..header + 6) == Some(b"copc") {
            return Some(Sniff { format: "copc", confidence: 0.98 });
        }
        Some(Sniff { format: if h[104] & 0xc0 != 0 { "laz" } else { "las" }, confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "e57" { e57(cx, src) } else { las(cx, src) }
    }
}

crate::register_extractor!(Points);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geokeys_and_gps_time() {
        // Version 1.1.0, 1 key: ProjectedCSType 32633.
        let mut k = Vec::new();
        for v in [1u16, 1, 0, 1, 3072, 0, 1, 32633] {
            k.extend(v.to_le_bytes());
        }
        assert_eq!(geokeys_crs(&k).unwrap().epsg, Some(32633));
        assert_eq!(gps_time(0.0).as_deref(), Some("1980-01-06T00:00:00Z"));
    }

    crate::fixture_tests!("las", "laz", "copc", "e57");
}
