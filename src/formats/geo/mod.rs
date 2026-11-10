//! `geo` extractors (feature `geo`): vector data (`GeoJSON`, KML, GPX, GML,
//! shapefiles, `MapInfo`, OpenStreetMap, …), tracks (FIT, IGC, NMEA, TCX),
//! rasters (GeoTIFF and COG, DTED, SRTM, ASCII grids, `MrSID`, ECW), point
//! clouds (LAS, LAZ, COPC, E57), tiles (`PMTiles`, vector tiles, 3D Tiles),
//! nautical charts, map styles and projects.
//!
//! Shared here: bounds, coordinate reference systems (WKT 1 and 2,
//! PROJJSON, URNs), reprojection of bounds to WGS84 for the content extent
//! (geographic CRSs, Web Mercator and UTM; others keep their native
//! bounds only), track distances, and an XML event walker.

#![allow(clippy::many_single_char_names, clippy::similar_names)] // coordinates and field offsets

pub(crate) mod json;
pub(crate) mod mrsid;
pub(crate) mod points;
pub(crate) mod raster;
pub(crate) mod shape;
pub(crate) mod text;
pub(crate) mod tiles;
pub(crate) mod tracks;
pub(crate) mod vector;
pub(crate) mod xml;

use std::collections::BTreeMap;

use serde_json::{Map, Value};

pub(crate) use super::archive::unix_time;
pub(crate) use crate::plugin::xmlwalk::{Ev, attr, walk as walk_xml, xml_root};
use crate::plugin::{Context, truncate_chars};

/// A float as JSON, rounded to `places` decimals (non-finite values as text).
pub(crate) fn num(v: f64, places: i32) -> Value {
    let f = 10f64.powi(places);
    let r = (v * f).round() / f;
    serde_json::Number::from_f64(r).map_or_else(|| Value::String(v.to_string()), Value::Number)
}

/// A bounding box accumulated from points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Bounds {
    pub min: [f64; 3],
    pub max: [f64; 3],
    pub points: u64,
    pub has_z: bool,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds { min: [f64::INFINITY; 3], max: [f64::NEG_INFINITY; 3], points: 0, has_z: false }
    }
}

impl Bounds {
    /// Add a point (non-finite coordinates are ignored).
    pub fn add(&mut self, x: f64, y: f64) {
        if x.is_finite() && y.is_finite() {
            self.min[0] = self.min[0].min(x);
            self.min[1] = self.min[1].min(y);
            self.max[0] = self.max[0].max(x);
            self.max[1] = self.max[1].max(y);
            self.points += 1;
        }
    }

    /// Add an elevation (or any third coordinate).
    pub fn add_z(&mut self, z: f64) {
        if z.is_finite() {
            self.min[2] = self.min[2].min(z);
            self.max[2] = self.max[2].max(z);
            self.has_z = true;
        }
    }

    /// Merge another box.
    pub fn merge(&mut self, o: &Bounds) {
        if o.points > 0 {
            let before = self.points;
            self.add(o.min[0], o.min[1]);
            self.add(o.max[0], o.max[1]);
            self.points = before + o.points;
        }
        if o.has_z {
            self.add_z(o.min[2]);
            self.add_z(o.max[2]);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.points == 0
    }

    /// `[minx, miny, maxx, maxy]`, rounded for the report.
    pub fn json(&self) -> Value {
        Value::Array([self.min[0], self.min[1], self.max[0], self.max[1]].iter().map(|&v| num(v, 7)).collect())
    }
}

/// A coordinate reference system as named in a file.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Crs {
    pub name: Option<String>,
    pub epsg: Option<u32>,
    /// Longitude / latitude in degrees (OGC CRS84 order) whatever the EPSG
    /// axis order says.
    pub geographic: bool,
}

impl Crs {
    pub fn epsg(code: u32) -> Self {
        Crs { name: None, epsg: Some(code), geographic: is_geographic(code) }
    }

    /// From a WKT 1 or WKT 2 string: the name and the top-level authority
    /// code (the last `AUTHORITY` / `ID` of the string).
    pub fn from_wkt(wkt: &str) -> Option<Self> {
        let w = wkt.trim();
        let kind_end = w.find(['[', '('])?;
        let kind = w[..kind_end].trim().to_ascii_uppercase();
        let known = [
            "GEOGCS",
            "PROJCS",
            "GEOCCS",
            "COMPD_CS",
            "VERT_CS",
            "LOCAL_CS",
            "GEOGCRS",
            "GEODCRS",
            "PROJCRS",
            "COMPOUNDCRS",
            "VERTCRS",
            "BOUNDCRS",
            "ENGCRS",
            "GEOGRAPHICCRS",
            "PROJECTEDCRS",
        ];
        if !known.contains(&kind.as_str()) {
            return None;
        }
        let name =
            w[kind_end + 1..].trim_start().strip_prefix('"').and_then(|r| r.split('"').next()).map(str::to_string);
        let mut epsg = None;
        for key in ["AUTHORITY[\"EPSG\",", "ID[\"EPSG\","] {
            if let Some(i) = w.rfind(key) {
                let code = w[i + key.len()..].trim_start().trim_start_matches('"');
                let digits: String = code.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(c) = digits.parse::<u32>() {
                    // The top-level one closes just before the string's end.
                    let tail = &w[i..];
                    let count = |p: [char; 2]| i64::try_from(tail.matches(p).count()).unwrap_or(0);
                    let depth = count(['[', '(']) - count([']', ')']);
                    if depth <= -1 || epsg.is_none() {
                        epsg = Some(c);
                    }
                }
            }
        }
        // Esri WKT names the CRS without an authority code.
        let epsg = epsg.or_else(|| name.as_deref().and_then(esri_epsg));
        let geographic = kind.starts_with("GEOG") || epsg.is_some_and(is_geographic);
        Some(Crs { name: name.map(|n| truncate_chars(&n, 120)), epsg, geographic })
    }

    /// From a reference: `EPSG:4326`, `urn:ogc:def:crs:EPSG::4326`,
    /// `http://www.opengis.net/def/crs/EPSG/0/4326`, `CRS84`, or WKT.
    pub fn from_ref(r: &str) -> Option<Self> {
        let t = r.trim();
        if t.ends_with("CRS84") || t.ends_with("CRS:84") {
            return Some(Crs { name: Some("WGS 84 (CRS84)".into()), epsg: Some(4326), geographic: true });
        }
        if let Some(c) = Crs::from_wkt(t) {
            return Some(c);
        }
        // The code is the last component: `EPSG:4326`, `…EPSG::4326`,
        // `…/EPSG/0/4326`.
        if !t.to_ascii_lowercase().contains("epsg") {
            return None;
        }
        t.rsplit([':', '/', '#']).find(|p| !p.is_empty())?.trim().parse().ok().map(Crs::epsg)
    }

    pub fn json(&self) -> Value {
        let mut m = Map::new();
        if let Some(n) = &self.name {
            m.insert("name".into(), n.clone().into());
        }
        if let Some(e) = self.epsg {
            m.insert("epsg".into(), e.into());
        }
        Value::Object(m)
    }
}

/// The EPSG code of an Esri CRS name (`WGS_1984_UTM_Zone_31N`, …).
fn esri_epsg(name: &str) -> Option<u32> {
    if name == "WGS_1984_Web_Mercator_Auxiliary_Sphere" {
        return Some(3857);
    }
    for (prefix, north, south) in
        [("WGS_1984_UTM_Zone_", 32600, 32700), ("ETRS_1989_UTM_Zone_", 25800, 0), ("NAD_1983_UTM_Zone_", 26900, 0)]
    {
        if let Some(z) = name.strip_prefix(prefix) {
            let (zone, hemi) = z.split_at(z.len().checked_sub(1)?);
            let zone: u32 = zone.parse().ok().filter(|z| (1..=60).contains(z))?;
            return match hemi {
                "N" => Some(north + zone),
                "S" if south > 0 => Some(south + zone),
                _ => None,
            };
        }
    }
    None
}

/// Common geographic CRSs (degrees; datum differences are below a
/// bounding box's precision).
fn is_geographic(code: u32) -> bool {
    matches!(
        code,
        4326 | 4258
            | 4269
            | 4283
            | 4167
            | 4617
            | 4612
            | 6318
            | 4979
            | 4937
            | 7844
            | 4674
            | 4148
            | 4152
            | 4019
            | 4030
            | 4047
            | 4267
    )
}

/// WGS84 / GRS80 transverse Mercator inverse (Krüger series to the 4th
/// order): projected metres to degrees.
fn tm_inverse(x: f64, y: f64, lon0: f64, k0: f64, fe: f64, fn_: f64) -> (f64, f64) {
    let a = 6_378_137.0_f64;
    let f = 1.0_f64 / 298.257_223_563;
    let n = f / (2.0 - f);
    let big_a = a / (1.0 + n) * (1.0 + n * n / 4.0 + n.powi(4) / 64.0);
    let beta = [
        n / 2.0 - 2.0 * n * n / 3.0 + 37.0 * n.powi(3) / 96.0,
        n * n / 48.0 + n.powi(3) / 15.0,
        17.0 * n.powi(3) / 480.0,
    ];
    let delta = [
        2.0 * n - 2.0 * n * n / 3.0 - 2.0 * n.powi(3),
        7.0 * n * n / 3.0 - 8.0 * n.powi(3) / 5.0,
        56.0 * n.powi(3) / 15.0,
    ];
    let xi = (y - fn_) / (k0 * big_a);
    let eta = (x - fe) / (k0 * big_a);
    let (mut xi1, mut eta1) = (xi, eta);
    for (j, b) in beta.iter().enumerate() {
        let k = 2.0 * (j as f64 + 1.0);
        xi1 -= b * (k * xi).sin() * (k * eta).cosh();
        eta1 -= b * (k * xi).cos() * (k * eta).sinh();
    }
    let chi = (xi1.sin() / eta1.cosh()).asin();
    let mut phi = chi;
    for (j, d) in delta.iter().enumerate() {
        phi += d * (2.0 * (j as f64 + 1.0) * chi).sin();
    }
    let lam = lon0.to_radians() + eta1.sinh().atan2(xi1.cos());
    (lam.to_degrees(), phi.to_degrees())
}

/// One point in `epsg` to WGS84 longitude / latitude, for the CRSs whose
/// inverse is in-house.
pub(crate) fn to_wgs84(epsg: u32, x: f64, y: f64) -> Option<(f64, f64)> {
    let utm = |zone: u32, south: bool| {
        let lon0 = f64::from(zone) * 6.0 - 183.0;
        tm_inverse(x, y, lon0, 0.9996, 500_000.0, if south { 10_000_000.0 } else { 0.0 })
    };
    let (lon, lat) = match epsg {
        c if is_geographic(c) => (x, y),
        3857 | 900_913 | 3785 | 102_100 => {
            let r = 6_378_137.0;
            ((x / r).to_degrees(), (y / r).sinh().atan().to_degrees())
        }
        32601..=32660 => utm(epsg - 32600, false),
        32701..=32760 => utm(epsg - 32700, true),
        25828..=25838 => utm(epsg - 25800, false),
        26901..=26923 => utm(epsg - 26900, false),
        3044..=3051 => utm(epsg - 3044 + 28, false), // ETRS89 / ETRS-TM28..35
        _ => return None,
    };
    (lon.is_finite() && lat.is_finite() && lon.abs() <= 180.0 + 1e-9 && lat.abs() <= 90.0 + 1e-9).then_some((lon, lat))
}

/// Write the native bounds and CRS into the format section and, when they
/// can be brought to WGS84, the content extent.
pub(crate) fn report_bounds(cx: &mut Context<'_>, b: &Bounds, crs: Option<&Crs>, source: &str) {
    if b.is_empty() {
        return;
    }
    cx.format_set("bbox", b.json());
    if b.has_z {
        cx.format_set("z_range", Value::Array(vec![num(b.min[2], 3), num(b.max[2], 3)]));
    }
    if let Some(c) = crs {
        cx.format_set("crs", c.json());
    }
    let wgs84 = match crs {
        None => b.min[0] >= -180.0 && b.max[0] <= 180.0 && b.min[1] >= -90.0 && b.max[1] <= 90.0,
        Some(c) => c.geographic,
    };
    let corners = if wgs84 {
        Some(((b.min[0], b.min[1]), (b.max[0], b.max[1])))
    } else {
        crs.and_then(|c| c.epsg).and_then(|e| {
            // The corners and edge midpoints: projected boxes are not
            // rectangles in degrees.
            let xs = [b.min[0], f64::midpoint(b.min[0], b.max[0]), b.max[0]];
            let ys = [b.min[1], f64::midpoint(b.min[1], b.max[1]), b.max[1]];
            let mut d = Bounds::default();
            for x in xs {
                for y in ys {
                    let (lon, lat) = to_wgs84(e, x, y)?;
                    d.add(lon, lat);
                }
            }
            Some(((d.min[0], d.min[1]), (d.max[0], d.max[1])))
        })
    };
    if let Some(((w, s), (e, n))) = corners {
        cx.content().source(source.to_string()).extent(w, s, e, n);
    }
}

/// Native bounds only, for files whose CRS lies elsewhere (a sidecar
/// `.prj`, a project): no extent is guessed from the numbers.
pub(crate) fn report_native(cx: &mut Context<'_>, b: &Bounds) {
    if !b.is_empty() {
        cx.format_set("bbox", b.json());
        if b.has_z {
            cx.format_set("z_range", Value::Array(vec![num(b.min[2], 3), num(b.max[2], 3)]));
        }
    }
}

/// Great-circle distance in metres (haversine, mean Earth radius).
pub(crate) fn haversine(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * 6_371_008.8 * a.sqrt().min(1.0).asin()
}

/// A track's fixes: count, bounds, distance, elevation and time span.
#[derive(Default)]
pub(crate) struct Track {
    pub bounds: Bounds,
    pub distance_m: f64,
    last: Option<(f64, f64)>,
    pub first_time: Option<String>,
    pub last_time: Option<String>,
}

impl Track {
    pub fn fix(&mut self, lat: f64, lon: f64, ele: Option<f64>, time: Option<&str>) {
        if !(lat.is_finite() && lon.is_finite() && lat.abs() <= 90.0 && lon.abs() <= 180.0) {
            return;
        }
        if let Some((plat, plon)) = self.last {
            self.distance_m += haversine(plat, plon, lat, lon);
        }
        self.last = Some((lat, lon));
        self.bounds.add(lon, lat);
        if let Some(z) = ele {
            self.bounds.add_z(z);
        }
        if let Some(t) = time.filter(|t| !t.is_empty()) {
            if self.first_time.is_none() {
                self.first_time = Some(t.to_string());
            }
            self.last_time = Some(t.to_string());
        }
    }

    /// Start a new segment: no distance across the gap.
    pub fn break_segment(&mut self) {
        self.last = None;
    }

    pub fn report(&self, cx: &mut Context<'_>, source: &str) {
        cx.format_set("fixes", self.bounds.points);
        if self.bounds.points > 1 {
            cx.format_set("distance_km", num(self.distance_m / 1000.0, 3));
        }
        report_bounds(cx, &self.bounds, None, source);
        if let (Some(a), Some(b)) = (&self.first_time, &self.last_time) {
            cx.format_set("start", a.clone());
            cx.format_set("end", b.clone());
        }
    }
}

/// A histogram as a JSON object.
pub(crate) fn hist(m: BTreeMap<String, u64>) -> Value {
    Value::Object(m.into_iter().map(|(k, v)| (k, v.into())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crs_from_wkt_and_refs() {
        let wkt = r#"PROJCS["WGS 84 / UTM zone 33N",GEOGCS["WGS 84",DATUM["WGS_1984",SPHEROID["WGS 84",6378137,298.257223563,AUTHORITY["EPSG","7030"]],AUTHORITY["EPSG","6326"]],AUTHORITY["EPSG","4326"]],PROJECTION["Transverse_Mercator"],AUTHORITY["EPSG","32633"]]"#;
        let c = Crs::from_wkt(wkt).unwrap();
        assert_eq!((c.name.as_deref(), c.epsg, c.geographic), (Some("WGS 84 / UTM zone 33N"), Some(32633), false));
        let g = Crs::from_wkt(r#"GEOGCRS["WGS 84",DATUM["World Geodetic System 1984"],ID["EPSG",4326]]"#).unwrap();
        assert_eq!((g.epsg, g.geographic), (Some(4326), true));
        assert_eq!(Crs::from_ref("urn:ogc:def:crs:EPSG::3857").unwrap().epsg, Some(3857));
        assert_eq!(Crs::from_ref("http://www.opengis.net/def/crs/EPSG/0/25832").unwrap().epsg, Some(25832));
        assert!(Crs::from_ref("urn:ogc:def:crs:OGC:1.3:CRS84").unwrap().geographic);
        assert!(Crs::from_wkt("hello").is_none());
        let esri = Crs::from_wkt(r#"PROJCS["WGS_1984_UTM_Zone_31N",GEOGCS["GCS_WGS_1984"]]"#).unwrap();
        assert_eq!(esri.epsg, Some(32631));
        assert_eq!(esri_epsg("ETRS_1989_UTM_Zone_32S"), None);
    }

    #[test]
    fn reprojection() {
        // UTM 33N: 500000 E on the central meridian (15° E).
        let (lon, lat) = to_wgs84(32633, 500_000.0, 5_000_000.0).unwrap();
        assert!((lon - 15.0).abs() < 1e-9 && (lat - 45.1535).abs() < 1e-3, "{lon} {lat}");
        let (lon, lat) = to_wgs84(3857, 1_113_194.9, 0.0).unwrap();
        assert!((lon - 10.0).abs() < 1e-5 && lat.abs() < 1e-9);
        let (_, lat) = to_wgs84(32733, 500_000.0, 10_000_000.0).unwrap();
        assert!(lat.abs() < 1e-9);
        assert!(to_wgs84(2056, 2_600_000.0, 1_200_000.0).is_none());
    }

    #[test]
    fn distances() {
        // One degree of latitude is about 111.2 km.
        let d = haversine(0.0, 0.0, 1.0, 0.0);
        assert!((d - 111_195.0).abs() < 50.0, "{d}");
    }
}
