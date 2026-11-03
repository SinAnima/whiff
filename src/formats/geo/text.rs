//! Plain-text geodata and small sidecars:
//! * WKT geometry files (with EWKT `SRID=`), and binary WKB / EWKB files:
//!   geometries, types, dimensions, SRID, bounds;
//! * Esri ASCII grids (`.asc`): size, cell size, origin, no-data value,
//!   bounds;
//! * world files (`.tfw`, `.jgw`, `.pgw`, `.wld`, …): pixel size, rotation,
//!   origin; `.prj` files: the CRS;
//! * `MapInfo` TAB and MIF: table type, fields, CRS (`CoordSys`), MIF objects
//!   by type and their bounds;
//! * CSV with coordinates: latitude / longitude or WKT columns, rows,
//!   geometry types and bounds.
//!
//! Specifications: OGC Simple Features 1.2.1 (WKT, WKB), `PostGIS` EWKB /
//! EWKT; Esri "ASCII raster format"; Esri world file; `MapInfo` Interchange
//! Format (`MapInfo` Professional reference, appendix).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Bounds, Crs, hist, num, report_bounds, report_native};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for plain-text geodata.
pub struct GeoText;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.text",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "wkt",
            name: "WKT / WKB / EWKB",
            family: "geo",
            mimes: &[],
            extensions: &["wkt", "ewkt"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "wkb",
            name: "WKB geometry",
            family: "geo",
            mimes: &[],
            extensions: &["wkb", "ewkb"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ascii_grid",
            name: "ESRI ASCII / Grid / ArcInfo coverage",
            family: "geo",
            mimes: &[],
            // `.asc` is also armoured PGP and LTspice: content sniff only.
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "world_file",
            name: "CZML / world file / .prj",
            family: "geo",
            mimes: &[],
            extensions: &["tfw", "jgw", "pgw", "wld", "gfw", "bpw", "tifw", "jpgw", "pngw", "j2w"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "prj",
            name: "Projection file",
            family: "geo",
            mimes: &[],
            extensions: &["prj"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mapinfo",
            name: "MapInfo TAB / MIF",
            family: "geo",
            mimes: &[],
            extensions: &["tab", "mif"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "csv_geo",
            name: "CSV with coordinates (WKT/lat-lon columns)",
            family: "geo",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("csv"),
        },
    ],
};

/// Geometry keywords of WKT, longest first where one prefixes another.
const WKT_TYPES: [&str; 17] = [
    "GEOMETRYCOLLECTION",
    "MULTIPOLYGON",
    "MULTILINESTRING",
    "MULTIPOINT",
    "MULTICURVE",
    "MULTISURFACE",
    "POLYHEDRALSURFACE",
    "COMPOUNDCURVE",
    "CURVEPOLYGON",
    "CIRCULARSTRING",
    "POLYGON",
    "LINESTRING",
    "POINT",
    "TRIANGLE",
    "TIN",
    "CURVE",
    "SURFACE",
];

/// The WKT type at the start of `s` (after `SRID=n;`), with its dimension
/// suffix.
fn wkt_type(s: &str) -> Option<(String, Option<u32>)> {
    let mut s = s.trim_start();
    let mut srid = None;
    if s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("SRID=")) {
        let (n, rest) = s[5..].split_once(';')?;
        srid = n.trim().parse().ok();
        s = rest.trim_start();
    }
    let upper: String = s.chars().take(24).collect::<String>().to_ascii_uppercase();
    let t = WKT_TYPES.iter().find(|t| upper.starts_with(**t))?;
    let rest = upper[t.len()..].trim_start();
    let dim = if rest.starts_with("ZM") {
        " ZM"
    } else if rest.starts_with('Z') {
        " Z"
    } else if rest.starts_with('M') && !rest.starts_with("MULTI") {
        " M"
    } else {
        ""
    };
    // The coordinates (or EMPTY) must follow: `POINTLESS` is not a point.
    let body = rest[dim.trim().len()..].trim_start();
    if !(body.starts_with('(') || body.starts_with("EMPTY") || body.is_empty() && upper.len() < 24) {
        return None;
    }
    Some((format!("{t}{dim}"), srid))
}

/// Points of a WKT geometry: each comma-separated group of numbers inside
/// the parentheses is one coordinate.
fn wkt_points(s: &str, b: &mut Bounds, measured: bool) {
    let body = s.find('(').map_or("", |i| &s[i..]);
    for group in body.split([',', '(', ')']).take(50_000_000) {
        let v: Vec<f64> = group.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if v.len() >= 2 {
            b.add(v[0], v[1]);
            // `x y m` carries a measure, not a height.
            if v.len() >= 3 && !(measured && v.len() == 3) {
                b.add_z(v[2]);
            }
        }
    }
}

fn wkt(cx: &mut Context<'_>, text: &str) {
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Bounds::default();
    let mut srids = std::collections::BTreeSet::new();
    let mut count = 0u64;
    // One geometry per line, or one spanning lines: split at type keywords
    // that start a line.
    let mut current = String::new();
    let mut flush = |g: &str, types: &mut BTreeMap<String, u64>, b: &mut Bounds| {
        if let Some((t, srid)) = wkt_type(g) {
            count += 1;
            if let Some(s) = srid {
                srids.insert(s);
            }
            wkt_points(g, b, t.ends_with(" M"));
            *types.entry(t).or_default() += 1;
        }
    };
    for line in text.lines().take(10_000_000) {
        if wkt_type(line).is_some() && !current.is_empty() {
            flush(&current, &mut types, &mut b);
            current.clear();
        }
        current.push_str(line);
        current.push('\n');
    }
    flush(&current, &mut types, &mut b);
    cx.format_set("geometries", count);
    cx.format_set("geometry_types", hist(types));
    let crs = (srids.len() == 1).then(|| Crs::epsg(*srids.first().unwrap_or(&0)));
    if !srids.is_empty() {
        cx.format_set("srids", srids.iter().copied().collect::<Vec<_>>());
    }
    if crs.is_some() { report_bounds(cx, &b, crs.as_ref(), "wkt") } else { report_native(cx, &b) }
}

/// A WKB reader: ISO and EWKB type codes, both byte orders.
struct Wkb<'a> {
    b: &'a [u8],
    at: usize,
    steps: u64,
}

impl Wkb<'_> {
    fn u32(&mut self, le: bool) -> Option<u32> {
        let r: [u8; 4] = self.b.get(self.at..self.at + 4)?.try_into().ok()?;
        self.at += 4;
        Some(if le { u32::from_le_bytes(r) } else { u32::from_be_bytes(r) })
    }

    fn f64(&mut self, le: bool) -> Option<f64> {
        let r: [u8; 8] = self.b.get(self.at..self.at + 8)?.try_into().ok()?;
        self.at += 8;
        Some(if le { f64::from_le_bytes(r) } else { f64::from_be_bytes(r) })
    }

    /// One geometry: (type name, SRID).
    fn geometry(&mut self, b: &mut Bounds, depth: usize) -> Option<(String, Option<u32>)> {
        self.steps += 1;
        if depth > 16 || self.steps > 10_000_000 {
            return None;
        }
        let le = match *self.b.get(self.at)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        self.at += 1;
        let raw = self.u32(le)?;
        let (mut z, mut m) = (raw & 0x8000_0000 != 0, raw & 0x4000_0000 != 0);
        let srid = if raw & 0x2000_0000 != 0 { Some(self.u32(le)?) } else { None };
        let iso = raw & 0x0fff_ffff;
        let base = iso % 1000;
        match iso / 1000 {
            1 => z = true,
            2 => m = true,
            3 => (z, m) = (true, true),
            _ => {}
        }
        let dims = 2 + usize::from(z) + usize::from(m);
        let point = |w: &mut Self, b: &mut Bounds| -> Option<()> {
            let x = w.f64(le)?;
            let y = w.f64(le)?;
            b.add(x, y);
            if z {
                b.add_z(w.f64(le)?);
            }
            if m {
                w.f64(le)?;
            }
            Some(())
        };
        let name = match base {
            1 => {
                point(self, b)?;
                "Point"
            }
            2 | 8 => {
                let n = self.u32(le)?;
                self.check(n, dims)?;
                for _ in 0..n {
                    point(self, b)?;
                }
                if base == 2 { "LineString" } else { "CircularString" }
            }
            3 | 17 => {
                let rings = self.u32(le)?;
                self.check(rings, 1)?;
                for _ in 0..rings {
                    let n = self.u32(le)?;
                    self.check(n, dims)?;
                    for _ in 0..n {
                        point(self, b)?;
                    }
                }
                if base == 3 { "Polygon" } else { "Triangle" }
            }
            4..=7 | 9..=12 | 15 | 16 => {
                let n = self.u32(le)?;
                self.check(n, 1)?;
                for _ in 0..n {
                    self.geometry(b, depth + 1)?;
                }
                match base {
                    4 => "MultiPoint",
                    5 => "MultiLineString",
                    6 => "MultiPolygon",
                    7 => "GeometryCollection",
                    9 => "CompoundCurve",
                    10 => "CurvePolygon",
                    11 => "MultiCurve",
                    12 => "MultiSurface",
                    15 => "PolyhedralSurface",
                    _ => "TIN",
                }
            }
            _ => return None,
        };
        let suffix = match (z, m) {
            (true, true) => " ZM",
            (true, false) => " Z",
            (false, true) => " M",
            _ => "",
        };
        Some((format!("{name}{suffix}"), srid))
    }

    /// `n` items of at least `doubles` doubles each must fit.
    fn check(&self, n: u32, doubles: usize) -> Option<()> {
        let need = usize::try_from(n).ok()?.checked_mul(doubles.max(1) * 4)?;
        (self.at.checked_add(need)? <= self.b.len()).then_some(())
    }
}

fn wkb(cx: &mut Context<'_>, data: &[u8]) -> Result<(), ExtractError> {
    let mut w = Wkb { b: data, at: 0, steps: 0 };
    let mut b = Bounds::default();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut srid = None;
    let mut count = 0u64;
    // Concatenated geometries: read until the bytes run out.
    while w.at < data.len() && count < 1_000_000 {
        let Some((t, s)) = w.geometry(&mut b, 0) else { break };
        count += 1;
        srid = srid.or(s);
        *types.entry(t).or_default() += 1;
    }
    if count == 0 {
        return Err(ExtractError::malformed("WKB geometry"));
    }
    if w.at < data.len() {
        cx.format_set("trailing_bytes", data.len() - w.at);
    }
    cx.format_set("byte_order", if data[0] == 1 { "little-endian" } else { "big-endian" });
    cx.format_set("geometries", count);
    cx.format_set("geometry_types", hist(types));
    if let Some(s) = srid {
        cx.format_set("srid", s);
        report_bounds(cx, &b, Some(&Crs::epsg(s)), "wkb");
    } else {
        report_native(cx, &b);
    }
    Ok(())
}

fn ascii_grid(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut h: BTreeMap<String, f64> = BTreeMap::new();
    let mut header_lines = 0;
    for line in text.lines().take(10) {
        let mut it = line.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else { break };
        if !k.chars().next().is_some_and(char::is_alphabetic) {
            break;
        }
        let Ok(v) = v.parse::<f64>() else { break };
        h.insert(k.to_ascii_lowercase(), v);
        header_lines += 1;
    }
    let (Some(&cols), Some(&rows)) = (h.get("ncols"), h.get("nrows")) else {
        return Err(ExtractError::malformed("ASCII grid header"));
    };
    let (dx, dy) = match (h.get("cellsize"), h.get("dx"), h.get("dy")) {
        (Some(&c), _, _) => (c, c),
        (None, Some(&x), Some(&y)) => (x, y),
        _ => return Err(ExtractError::malformed("ASCII grid cell size")),
    };
    // Corner or centre registration.
    let (x0, y0) = match (h.get("xllcorner"), h.get("yllcorner"), h.get("xllcenter"), h.get("yllcenter")) {
        (Some(&x), Some(&y), _, _) => (x, y),
        (_, _, Some(&x), Some(&y)) => (x - dx / 2.0, y - dy / 2.0),
        _ => return Err(ExtractError::malformed("ASCII grid origin")),
    };
    cx.format_set("columns", num(cols, 0));
    cx.format_set("rows", num(rows, 0));
    cx.format_set(
        "cell_size",
        if (dx - dy).abs() < f64::EPSILON { num(dx, 9) } else { Value::Array(vec![num(dx, 9), num(dy, 9)]) },
    );
    cx.format_set("registration", if h.contains_key("xllcorner") { "corner" } else { "center" });
    if let Some(nd) = h.get("nodata_value") {
        cx.format_set("nodata", num(*nd, 6));
    }
    cx.format_set("header_lines", header_lines);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // grid sizes from the header
    if cols > 0.0 && rows > 0.0 && cols < 4e9 && rows < 4e9 {
        cx.physical().image(cols as u32, rows as u32);
    }
    let mut b = Bounds::default();
    b.add(x0, y0);
    b.add(x0 + cols * dx, y0 + rows * dy);
    report_native(cx, &b);
    Ok(())
}

fn world_file(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let v: Vec<f64> = text.split_whitespace().take(7).filter_map(|x| x.parse().ok()).collect();
    let [a, d, b, e, c, f] = v[..] else {
        return Err(ExtractError::malformed("world file: six numbers"));
    };
    cx.format_set("pixel_size", Value::Array(vec![num(a, 12), num(e, 12)]));
    cx.format_set("rotation", Value::Array(vec![num(d, 12), num(b, 12)]));
    // C, F: the centre of the upper-left pixel.
    cx.format_set("upper_left_center", Value::Array(vec![num(c, 9), num(f, 9)]));
    cx.format_set("rotated", d != 0.0 || b != 0.0);
    Ok(())
}

fn prj(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let c = Crs::from_wkt(text).ok_or_else(|| ExtractError::malformed("WKT"))?;
    let kind = text.trim_start().split(['[', '(']).next().unwrap_or("").trim().to_ascii_uppercase();
    cx.format_set("wkt_kind", truncate_chars(&kind, 20));
    cx.format_set("crs", c.json());
    if let Some(p) = text.split("PROJECTION[\"").nth(1).and_then(|r| r.split('"').next()) {
        cx.format_set("projection", truncate_chars(p, 60));
    }
    Ok(())
}

/// `MapInfo` `CoordSys Earth Projection 1, 104` and friends.
fn coordsys(line: &str) -> Option<(String, bool)> {
    let i = line.to_ascii_lowercase().find("coordsys")?;
    let cs = line[i + 8..].trim().to_string();
    let lower = cs.to_ascii_lowercase();
    // Projection type 1 is longitude / latitude.
    let geographic = lower.starts_with("earth projection 1,") || lower.starts_with("earth projection 1 ,");
    Some((truncate_chars(&cs, 200), geographic))
}

fn mapinfo(cx: &mut Context<'_>, text: &str, tab: bool) {
    let mut fields = Vec::new();
    let mut objects: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Bounds::default();
    let mut geographic = false;
    let mut in_columns = 0usize;
    let mut data = false;
    for line in text.lines().take(50_000_000) {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        let word = lower.split_whitespace().next().unwrap_or("");
        if let Some((cs, g)) = coordsys(t).filter(|_| !data) {
            cx.format_set("coordsys", cs);
            geographic = g;
            continue;
        }
        if in_columns > 0 {
            if let Some(name) = t.split_whitespace().next() {
                let kind = t[name.len()..].trim().trim_end_matches(';');
                fields.push(format!("{} ({})", truncate_chars(name, 60), truncate_chars(kind, 30)));
            }
            in_columns -= 1;
            continue;
        }
        match word {
            "!version" | "version" if !data => {
                cx.format_set("version", truncate_chars(t.split_whitespace().nth(1).unwrap_or(""), 10));
            }
            "!charset" | "charset" if !data => {
                cx.format_set(
                    "charset",
                    truncate_chars(t.split_whitespace().nth(1).unwrap_or("").trim_matches('"'), 30),
                );
            }
            "type" if tab && !data => {
                cx.format_set("table_type", truncate_chars(t.split_whitespace().nth(1).unwrap_or(""), 20));
            }
            "fields" | "columns" if !data => {
                in_columns = t.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0).min(10_000);
            }
            "data" if !tab => data = true,
            "point" | "line" | "pline" | "region" | "text" | "rect" | "roundrect" | "ellipse" | "arc"
            | "multipoint" | "collection"
                if data =>
            {
                *objects.entry(word.to_string()).or_default() += 1;
                // Point x y; Line / Rect x1 y1 x2 y2 on the same line.
                let v: Vec<f64> = t.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
                if matches!(word, "point" | "line" | "rect" | "roundrect" | "ellipse" | "arc") {
                    for p in v.as_chunks::<2>().0.iter().take(2) {
                        b.add(p[0], p[1]);
                    }
                }
            }
            _ if data => {
                // Vertex lines of plines and regions: exactly two numbers.
                let v: Vec<f64> = t.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                if v.len() == 2 && t.split_whitespace().count() == 2 {
                    b.add(v[0], v[1]);
                }
            }
            _ => {}
        }
    }
    cx.format_set("fields", fields);
    if !tab {
        cx.format_set("objects", hist(objects));
    }
    if geographic {
        report_bounds(cx, &b, Some(&Crs { name: None, epsg: None, geographic: true }), "mif");
    } else {
        report_native(cx, &b);
    }
}

/// Coordinate columns of a CSV header: (latitude, longitude) or WKT.
fn coord_columns(header: &[String]) -> (Option<usize>, Option<usize>, Option<usize>) {
    let find = |names: &[&str]| header.iter().position(|h| names.contains(&h.trim().to_ascii_lowercase().as_str()));
    let lat = find(&["lat", "latitude", "lat_deg", "y_lat", "decimallatitude"]);
    let lon = find(&["lon", "lng", "long", "longitude", "lon_deg", "x_lon", "decimallongitude"]);
    let wkt = find(&["wkt", "geometry", "geom", "the_geom", "shape"]);
    (lat, lon, wkt)
}

fn csv_geo(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let delim = if text.lines().next().is_some_and(|l| l.matches('\t').count() > l.matches(',').count()) {
        b'\t'
    } else {
        b','
    };
    let mut r = csv::ReaderBuilder::new().delimiter(delim).flexible(true).from_reader(text.as_bytes());
    let header: Vec<String> =
        r.headers().map_err(|e| ExtractError::malformed(format!("CSV: {e}")))?.iter().map(str::to_string).collect();
    let (lat, lon, wkt_col) = coord_columns(&header);
    cx.format_set("columns", header.iter().take(200).map(|h| truncate_chars(h, 60)).collect::<Vec<_>>());
    let mut coord = Vec::new();
    if let (Some(a), Some(o)) = (lat, lon) {
        coord.push(header[a].clone());
        coord.push(header[o].clone());
    }
    if let Some(w) = wkt_col {
        coord.push(header[w].clone());
    }
    cx.format_set("coordinate_columns", coord);
    let mut b = Bounds::default();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut rows = 0u64;
    for rec in r.records().take(50_000_000) {
        let Ok(rec) = rec else { continue };
        rows += 1;
        if let (Some(a), Some(o)) = (lat, lon)
            && let (Some(Ok(la)), Some(Ok(lo))) =
                (rec.get(a).map(|v| v.trim().parse::<f64>()), rec.get(o).map(|v| v.trim().parse::<f64>()))
            && la.abs() <= 90.0
            && lo.abs() <= 180.0
        {
            b.add(lo, la);
        }
        if let Some(g) = wkt_col.and_then(|w| rec.get(w))
            && let Some((t, _)) = wkt_type(g)
        {
            wkt_points(g, &mut b, t.ends_with(" M"));
            *types.entry(t).or_default() += 1;
        }
    }
    cx.format_set("rows", rows);
    if !types.is_empty() {
        cx.format_set("geometry_types", hist(types));
    }
    if lat.is_some() {
        report_bounds(cx, &b, None, "csv.latlon");
    } else {
        report_native(cx, &b);
    }
    Ok(())
}

impl Extractor for GeoText {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if ext == "wkb" || ext == "ewkb" {
            let ok = h.len() >= 5 && h[0] <= 1 && {
                let t = if h[0] == 1 {
                    u32::from_le_bytes([h[1], h[2], h[3], h[4]])
                } else {
                    u32::from_be_bytes([h[1], h[2], h[3], h[4]])
                };
                (1..=17).contains(&((t & 0x0fff_ffff) % 1000))
            };
            return ok.then_some(Sniff { format: "wkb", confidence: 0.95 });
        }
        let text = std::str::from_utf8(&h[..h.len().min(8192)])
            .ok()
            .or_else(|| std::str::from_utf8(&h[..h.len().min(4096)]).ok())?;
        let first = text.trim_start().lines().next().unwrap_or("");
        let lower = first.to_ascii_lowercase();
        if lower.starts_with("ncols") && text.to_ascii_lowercase().contains("nrows") {
            return sure("ascii_grid");
        }
        if lower.starts_with("!table")
            || (lower.starts_with("version") && text.to_ascii_lowercase().contains("\ncolumns"))
        {
            return sure("mapinfo");
        }
        if ext == "prj" && Crs::from_wkt(text).is_some() {
            return sure("prj");
        }
        if META.formats[3].extensions.contains(&ext)
            && text.split_whitespace().filter(|v| v.parse::<f64>().is_ok()).count() == 6
        {
            return sure("world_file");
        }
        if wkt_type(first).is_some() && first.contains('(') {
            return sure("wkt");
        }
        if matches!(ext, "csv" | "tsv" | "txt") {
            let header: Vec<String> =
                first.split([',', '\t', ';']).map(|s| s.trim().trim_matches('"').to_string()).collect();
            let (lat, lon, wkt) = coord_columns(&header);
            let wkt_rows = wkt.is_some()
                && text.lines().nth(1).is_some_and(|l| WKT_TYPES.iter().any(|t| l.to_ascii_uppercase().contains(t)));
            if (lat.is_some() && lon.is_some()) || wkt_rows {
                return Some(Sniff { format: "csv_geo", confidence: 0.95 });
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "wkb" {
            let (data, _) = cx.read_bytes(src)?;
            return wkb(cx, &data);
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "wkt" => {
                wkt(cx, &text);
                Ok(())
            }
            "ascii_grid" => ascii_grid(cx, &text),
            "world_file" => world_file(cx, &text),
            "prj" => prj(cx, &text),
            "mapinfo" => {
                let tab = text.trim_start().to_ascii_lowercase().starts_with("!table");
                cx.format_set("kind", if tab { "TAB" } else { "MIF" });
                mapinfo(cx, &text, tab);
                Ok(())
            }
            _ => csv_geo(cx, &text),
        }
    }
}

crate::register_extractor!(GeoText);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wkt_types_and_points() {
        assert_eq!(wkt_type("SRID=4326;POINT Z (1 2 3)"), Some(("POINT Z".into(), Some(4326))));
        assert_eq!(wkt_type("MultiPolygon (((0 0, 1 0, 1 1, 0 0)))"), Some(("MULTIPOLYGON".into(), None)));
        assert_eq!(wkt_type("pointless"), None);
        assert_eq!(wkt_type("POLYGON EMPTY"), Some(("POLYGON".into(), None)));
        let mut b = Bounds::default();
        wkt_points("LINESTRING M (1 2 9, 3 4 9)", &mut b, true);
        assert_eq!((b.points, b.has_z), (2, false));
    }

    #[test]
    fn wkb_points() {
        // Little-endian EWKB POINT Z with SRID 4326.
        let mut g = vec![1u8];
        g.extend((1u32 | 0x8000_0000 | 0x2000_0000).to_le_bytes());
        g.extend(4326u32.to_le_bytes());
        for v in [10.0f64, 50.0, 7.0] {
            g.extend(v.to_le_bytes());
        }
        let mut b = Bounds::default();
        let mut w = Wkb { b: &g, at: 0, steps: 0 };
        assert_eq!(w.geometry(&mut b, 0), Some(("Point Z".into(), Some(4326))));
        // A claimed count larger than the bytes is refused, not allocated.
        let mut big = vec![0u8, 0, 0, 0, 2];
        big.extend(u32::MAX.to_be_bytes());
        assert_eq!(Wkb { b: &big, at: 0, steps: 0 }.geometry(&mut b, 0), None);
    }

    crate::fixture_tests!("wkt", "wkb", "ascii_grid", "world_file", "prj", "mapinfo", "csv_geo");
}
