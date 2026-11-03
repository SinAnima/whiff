//! JSON-based geodata:
//! * `GeoJSON` (RFC 7946, and the 2008 `crs` member): features, geometry
//!   types, property keys, bounds, the `name` / `description` members;
//!   `GeoJSON` text sequences (RFC 8142) and newline-delimited `GeoJSON`;
//! * `TopoJSON`: objects with their geometry types, arcs, quantization,
//!   bounds (delta-decoded through the transform);
//! * CZML: the document packet (name, version, clock), packets, positions;
//! * Mapbox / `MapLibre` style JSON: name, sources by type, layers by type,
//!   center and zoom; `ArcGIS` layer files (`.lyrx`): layer names and types;
//! * Entwine Point Tiles `ept.json`: points, bounds, schema, SRS.
//!
//! Specifications: RFC 7946, RFC 8142; `TopoJSON` 1.0; CZML (Cesium) packet
//! and document guide; `MapLibre` style specification v8; Esri CIM
//! (`CIMLayerDocument`); Entwine `ept.json` 1.1.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{Bounds, Crs, hist, num, report_bounds};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for JSON-based geodata.
pub struct GeoJson;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.json",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "geojson",
            name: "GeoJSON",
            family: "geo",
            mimes: &["application/geo+json"],
            extensions: &["geojson"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "geojson_seq",
            name: "GeoJSON-seq / NDGeoJSON",
            family: "geo",
            mimes: &["application/geo+json-seq"],
            extensions: &["geojsons", "geojsonl", "geojsonseq"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "topojson",
            name: "TopoJSON",
            family: "geo",
            mimes: &[],
            extensions: &["topojson"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "czml",
            name: "CZML",
            family: "geo",
            mimes: &[],
            extensions: &["czml"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "map_style",
            name: "Map styles (Mapbox style JSON / SLD / lyrx)",
            family: "geo",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "lyrx",
            name: "ArcGIS layer file",
            family: "geo",
            mimes: &[],
            extensions: &["lyrx"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "ept",
            name: "COPC / EPT point cloud index",
            family: "geo",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
    ],
};

const MAX_FEATURES: u64 = 10_000_000;

/// Coordinates nested at any depth: `[x, y, z?]` leaves.
fn coords(v: &Value, b: &mut Bounds, depth: usize) {
    let Some(a) = v.as_array() else { return };
    if depth > 8 {
        return;
    }
    match (a.first().and_then(Value::as_f64), a.get(1).and_then(Value::as_f64)) {
        (Some(x), Some(y)) => {
            b.add(x, y);
            if let Some(z) = a.get(2).and_then(Value::as_f64) {
                b.add_z(z);
            }
        }
        _ => {
            for c in a {
                coords(c, b, depth + 1);
            }
        }
    }
}

#[derive(Default)]
struct Features {
    count: u64,
    types: BTreeMap<String, u64>,
    keys: BTreeSet<String>,
    bounds: Bounds,
    null_geometry: u64,
}

impl Features {
    fn geometry(&mut self, g: &Value, depth: usize) {
        if depth > 8 {
            return;
        }
        let Some(t) = g.get("type").and_then(Value::as_str) else {
            self.null_geometry += 1;
            return;
        };
        *self.types.entry(truncate_chars(t, 40)).or_default() += 1;
        if t == "GeometryCollection" {
            for c in g.get("geometries").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
                let mut sub = Features::default();
                sub.geometry(c, depth + 1);
                self.bounds.merge(&sub.bounds);
            }
        } else if let Some(c) = g.get("coordinates") {
            coords(c, &mut self.bounds, 0);
        }
    }

    fn feature(&mut self, f: &Value) {
        if self.count >= MAX_FEATURES {
            return;
        }
        self.count += 1;
        match f.get("geometry") {
            Some(g) if !g.is_null() => self.geometry(g, 0),
            _ => self.null_geometry += 1,
        }
        if let Some(p) = f.get("properties").and_then(Value::as_object) {
            for k in p.keys() {
                if self.keys.len() < 200 {
                    self.keys.insert(truncate_chars(k, 100));
                }
            }
        }
    }

    fn report(self, cx: &mut Context<'_>, crs: Option<&Crs>, source: &str) {
        cx.format_set("features", self.count);
        cx.format_set("geometry_types", hist(self.types));
        if self.null_geometry > 0 {
            cx.format_set("null_geometries", self.null_geometry);
        }
        if !self.keys.is_empty() {
            cx.format_set("property_keys", self.keys.into_iter().collect::<Vec<_>>());
        }
        report_bounds(cx, &self.bounds, crs, source);
    }
}

/// The 2008 `crs` member: named (`urn:…`) or linked.
fn crs_member(v: &Value) -> Option<Crs> {
    let c = v.get("crs")?;
    c.pointer("/properties/name").and_then(Value::as_str).and_then(Crs::from_ref)
}

fn geojson(cx: &mut Context<'_>, v: &Value) {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
    cx.format_set("type", truncate_chars(kind, 40));
    for key in ["name", "title"] {
        if let Some(n) = v.get(key).and_then(Value::as_str) {
            cx.format_set("name", truncate_chars(n, 200));
            cx.content().source(format!("geojson.{key}")).title(truncate_chars(n, 200));
            break;
        }
    }
    if let Some(d) = v.get("description").and_then(Value::as_str) {
        cx.content().source("geojson.description").description(truncate_chars(d, 500));
    }
    let crs = crs_member(v);
    let mut f = Features::default();
    match kind {
        "FeatureCollection" => {
            for feat in v.get("features").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
                f.feature(feat);
            }
        }
        "Feature" => f.feature(v),
        _ => {
            f.count = 1;
            f.geometry(v, 0);
        }
    }
    if let Some(b) = v.get("bbox").and_then(Value::as_array).filter(|b| b.len() >= 4) {
        cx.format_set(
            "declared_bbox",
            Value::Array(b.iter().map(|x| num(x.as_f64().unwrap_or(f64::NAN), 7)).collect()),
        );
    }
    f.report(cx, crs.as_ref(), "geojson");
}

fn geojson_seq(cx: &mut Context<'_>, text: &str) {
    let mut f = Features::default();
    let mut bad = 0u64;
    for line in text.split(['\n', '\u{1e}']).map(str::trim).filter(|l| !l.is_empty()).take(10_000_000) {
        match serde_json::from_str::<Value>(line) {
            Ok(v) if v.get("type").and_then(Value::as_str) == Some("Feature") => f.feature(&v),
            Ok(v) if v.get("type").is_some() => {
                f.count += 1;
                f.geometry(&v, 0);
            }
            _ => bad += 1,
        }
    }
    if bad > 0 {
        cx.format_set("unreadable_lines", bad);
    }
    f.report(cx, None, "geojson_seq");
}

fn topojson(cx: &mut Context<'_>, v: &Value) {
    let mut objects = serde_json::Map::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    for (name, o) in v.get("objects").and_then(Value::as_object).into_iter().flatten().take(500) {
        let geoms = o.get("geometries").and_then(Value::as_array);
        let n = geoms.map_or(1, Vec::len);
        for g in geoms.map_or(std::slice::from_ref(o), Vec::as_slice) {
            if let Some(t) = g.get("type").and_then(Value::as_str) {
                *types.entry(truncate_chars(t, 40)).or_default() += 1;
            }
        }
        objects.insert(truncate_chars(name, 100), n.into());
    }
    cx.format_set("objects", Value::Object(objects));
    cx.format_set("geometry_types", hist(types));
    let arcs = v.get("arcs").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    cx.format_set("arcs", arcs.len());
    // Quantized arcs are delta-encoded integers, scaled by the transform.
    let t = v.get("transform");
    let f = |k: &str, i: usize, d: f64| {
        t.and_then(|t| t.get(k)).and_then(|a| a.get(i)).and_then(Value::as_f64).unwrap_or(d)
    };
    let (sx, sy, tx, ty) = (f("scale", 0, 1.0), f("scale", 1, 1.0), f("translate", 0, 0.0), f("translate", 1, 0.0));
    if t.is_some() {
        cx.format_set("quantized", true);
    }
    let mut b = Bounds::default();
    for arc in arcs.iter().take(10_000_000) {
        let (mut x, mut y) = (0.0, 0.0);
        for p in arc.as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(px), Some(py)) = (p.get(0).and_then(Value::as_f64), p.get(1).and_then(Value::as_f64)) else {
                continue;
            };
            if t.is_some() {
                x += px;
                y += py;
                b.add(x * sx + tx, y * sy + ty);
            } else {
                b.add(px, py);
            }
        }
    }
    report_bounds(cx, &b, None, "topojson");
}

fn czml(cx: &mut Context<'_>, v: &Value) {
    let packets = v.as_array().map(Vec::as_slice).unwrap_or_default();
    cx.format_set("packets", packets.len());
    if let Some(doc) = packets.first().filter(|p| p.get("id").and_then(Value::as_str) == Some("document")) {
        if let Some(n) = doc.get("name").and_then(Value::as_str) {
            cx.format_set("name", truncate_chars(n, 200));
            cx.content().source("czml.document").title(truncate_chars(n, 200));
        }
        if let Some(ver) = doc.get("version").and_then(Value::as_str) {
            cx.format_set("version", truncate_chars(ver, 20));
        }
        if let Some(i) = doc.pointer("/clock/interval").and_then(Value::as_str) {
            cx.format_set("clock_interval", truncate_chars(i, 80));
        }
    }
    let mut b = Bounds::default();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for p in packets.iter().take(1_000_000) {
        for k in [
            "billboard",
            "point",
            "polyline",
            "polygon",
            "model",
            "label",
            "path",
            "ellipse",
            "box",
            "corridor",
            "wall",
        ] {
            if p.get(k).is_some() {
                *kinds.entry(k.into()).or_default() += 1;
            }
        }
        if let Some(c) = p.pointer("/position/cartographicDegrees").and_then(Value::as_array) {
            // [lon, lat, h] or time-tagged [t, lon, lat, h, …].
            let step = if c.len() == 3 { 3 } else { 4 };
            let off = usize::from(step == 4);
            for chunk in c.chunks(step).take(1_000_000) {
                if let (Some(lon), Some(lat)) =
                    (chunk.get(off).and_then(Value::as_f64), chunk.get(off + 1).and_then(Value::as_f64))
                {
                    b.add(lon, lat);
                    if let Some(h) = chunk.get(off + 2).and_then(Value::as_f64) {
                        b.add_z(h);
                    }
                }
            }
        }
    }
    cx.format_set("graphics", hist(kinds));
    report_bounds(cx, &b, None, "czml");
}

fn map_style(cx: &mut Context<'_>, v: &Value) {
    if let Some(n) = v.get("name").and_then(Value::as_str) {
        cx.format_set("name", truncate_chars(n, 200));
        cx.content().source("style.name").title(truncate_chars(n, 200));
    }
    if let Some(ver) = v.get("version").and_then(Value::as_u64) {
        cx.format_set("style_version", ver);
    }
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    for s in v.get("sources").and_then(Value::as_object).into_iter().flatten().map(|(_, s)| s).take(1000) {
        *sources.entry(truncate_chars(s.get("type").and_then(Value::as_str).unwrap_or("?"), 30)).or_default() += 1;
    }
    cx.format_set("sources", hist(sources));
    let layers = v.get("layers").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    for l in layers.iter().take(100_000) {
        *types.entry(truncate_chars(l.get("type").and_then(Value::as_str).unwrap_or("?"), 30)).or_default() += 1;
    }
    cx.format_set("layer_count", layers.len());
    cx.format_set("layer_types", hist(types));
    if let Some(c) = v.get("center").and_then(Value::as_array).filter(|c| c.len() >= 2) {
        let (lon, lat) = (c[0].as_f64().unwrap_or(f64::NAN), c[1].as_f64().unwrap_or(f64::NAN));
        cx.format_set("center", Value::Array(vec![num(lon, 6), num(lat, 6)]));
        cx.content().source("style.center").location(lat, lon, None);
    }
    if let Some(z) = v.get("zoom").and_then(Value::as_f64) {
        cx.format_set("zoom", num(z, 2));
    }
    for key in ["sprite", "glyphs"] {
        if let Some(u) = v.get(key).and_then(Value::as_str) {
            cx.format_set(key, truncate_chars(u, 200));
        }
    }
}

fn lyrx(cx: &mut Context<'_>, v: &Value) {
    if let Some(ver) = v.get("version").and_then(Value::as_str) {
        cx.format_set("version", truncate_chars(ver, 20));
    }
    if let Some(b) = v.get("build").and_then(Value::as_u64) {
        cx.format_set("build", b);
    }
    let defs = v.get("layerDefinitions").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut layers = Vec::new();
    for d in defs.iter().take(500) {
        let name = d.get("name").and_then(Value::as_str).unwrap_or("");
        let kind = d.get("type").and_then(Value::as_str).unwrap_or("?").trim_start_matches("CIM");
        layers.push(format!("{} ({kind})", truncate_chars(name, 100)));
    }
    cx.format_set("layers", layers);
    if let Some(t) = defs.first().and_then(|d| d.get("name")).and_then(Value::as_str) {
        cx.content().source("lyrx.name").title(truncate_chars(t, 200));
    }
}

fn ept(cx: &mut Context<'_>, v: &Value) {
    if let Some(p) = v.get("points").and_then(Value::as_u64) {
        cx.format_set("points", p);
    }
    for (key, out) in [("version", "version"), ("dataType", "data_type"), ("hierarchyType", "hierarchy_type")] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            cx.format_set(out, truncate_chars(s, 30));
        }
    }
    if let Some(s) = v.get("span").and_then(Value::as_u64) {
        cx.format_set("span", s);
    }
    let dims: Vec<String> = v
        .get("schema")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|d| d.get("name").and_then(Value::as_str))
        .take(100)
        .map(|n| truncate_chars(n, 40))
        .collect();
    cx.format_set("dimensions", dims);
    let srs = v.get("srs");
    let crs = srs.and_then(|s| s.get("wkt").and_then(Value::as_str).and_then(Crs::from_wkt)).or_else(|| {
        let code = srs?.get("horizontal")?.as_str()?.parse().ok()?;
        Some(Crs::epsg(code))
    });
    // `boundsConforming` is the data's box; `bounds` the cube around it.
    let b = v.get("boundsConforming").or_else(|| v.get("bounds")).and_then(Value::as_array).filter(|b| b.len() == 6);
    if let Some(b) = b {
        let g = |i: usize| b[i].as_f64().unwrap_or(f64::NAN);
        let mut bounds = Bounds::default();
        bounds.add(g(0), g(1));
        bounds.add(g(3), g(4));
        bounds.add_z(g(2));
        bounds.add_z(g(5));
        report_bounds(cx, &bounds, crs.as_ref(), "ept.bounds");
    }
}

fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

impl Extractor for GeoJson {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = &probe.head[..probe.head.len().min(16 << 10)];
        let start = h.iter().position(|c| !c.is_ascii_whitespace() && *c != 0xef && *c != 0xbb && *c != 0xbf)?;
        let first = h[start];
        let name = probe.name.unwrap_or("").to_ascii_lowercase();
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if first == 0x1e || (matches!(probe.extension, Some("geojsons" | "geojsonl" | "geojsonseq"))) {
            return sure("geojson_seq");
        }
        if first == b'[' && has(h, b"\"document\"") && has(h, b"\"version\"") {
            return sure("czml");
        }
        if first != b'{' {
            return None;
        }
        if has(h, b"\"Topology\"") && has(h, b"\"arcs\"") {
            return sure("topojson");
        }
        if has(h, b"\"CIMLayerDocument\"") {
            return sure("lyrx");
        }
        if name == "ept.json" || (has(h, b"\"dataType\"") && has(h, b"\"span\"") && has(h, b"\"schema\"")) {
            return sure("ept");
        }
        if (has(h, b"\"version\": 8") || has(h, b"\"version\":8")) && has(h, b"\"sources\"") && has(h, b"\"layers\"") {
            return sure("map_style");
        }
        // Newline-delimited features: the first line is a whole Feature.
        if let Some(nl) = h.iter().position(|&c| c == b'\n')
            && h[nl..].iter().any(|c| !c.is_ascii_whitespace())
            && serde_json::from_slice::<Value>(&h[..nl])
                .ok()
                .and_then(|v| v.get("type")?.as_str().map(str::to_string))
                .as_deref()
                == Some("Feature")
        {
            return sure("geojson_seq");
        }
        let fc = has(h, b"\"FeatureCollection\"") && has(h, b"\"features\"");
        let feature = has(h, b"\"Feature\"") && has(h, b"\"geometry\"");
        (fc || feature || probe.extension == Some("geojson")).then_some(Sniff { format: "geojson", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let id = cx.format_id().to_string();
        if id == "geojson_seq" {
            geojson_seq(cx, &text);
            return Ok(());
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| ExtractError::malformed(format!("JSON: {e}")))?;
        match id.as_str() {
            "geojson" => geojson(cx, &v),
            "topojson" => topojson(cx, &v),
            "czml" => czml(cx, &v),
            "map_style" => map_style(cx, &v),
            "lyrx" => lyrx(cx, &v),
            _ => ept(cx, &v),
        }
        Ok(())
    }
}

crate::register_extractor!(GeoJson);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_coordinates() {
        let v: Value = serde_json::from_str("[[[1,2],[3,-4,10]],[[5,6]]]").unwrap();
        let mut b = Bounds::default();
        coords(&v, &mut b, 0);
        assert_eq!((b.min, b.max, b.points), ([1.0, -4.0, 10.0], [5.0, 6.0, 10.0], 3));
    }

    crate::fixture_tests!("geojson", "geojson_seq", "topojson", "czml", "map_style", "lyrx", "ept");
}
