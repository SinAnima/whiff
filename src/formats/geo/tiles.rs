//! Tiles and tiled datasets:
//! * `PMTiles` v3: tile type and compression, zoom range, bounds and centre,
//!   tile counts, the JSON metadata (name, description, attribution,
//!   vector layers); v2 archives by version;
//! * Mapbox vector tiles (`.mvt`, `.pbf`): layers with their feature
//!   counts, geometry types, keys and extent;
//! * OpenStreetMap PBF: the header block (bounds, required and optional
//!   features, writing program, replication time and sequence) and the
//!   data blocks with node, way and relation counts;
//! * OGC 3D Tiles: `tileset.json` (version, generator, geometric error,
//!   tiles, content types, the root region as bounds) and tile payloads
//!   (`b3dm`, `i3dm`, `pnts`, `cmpt`): feature, instance or point counts,
//!   batch table properties, the embedded glTF.
//!
//! Specifications: `PMTiles` v3 specification; Mapbox Vector Tile 2.1;
//! OSM PBF format (`fileformat.proto`, `osmformat.proto`); OGC 3D Tiles
//! 1.0 / 1.1 (22-025r4).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{Bounds, Crs, hist, num, report_bounds};
use crate::plugin::{
    Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, protowire,
    truncate_chars,
};

/// Extractor for tiles and tiled datasets.
pub struct Tiles;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.tiles",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pmtiles",
            name: "MBTiles / PMTiles",
            family: "geo",
            mimes: &["application/vnd.pmtiles"],
            extensions: &["pmtiles"],
            magic: &[Magic::at(0, b"PMTiles")],
            parent: None,
        },
        FormatSpec {
            id: "mvt",
            name: "Mapbox Vector Tile",
            family: "geo",
            mimes: &["application/vnd.mapbox-vector-tile"],
            extensions: &["mvt"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "osm_pbf",
            name: "OpenStreetMap PBF",
            family: "geo",
            mimes: &[],
            extensions: &["pbf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "tiles3d",
            name: "OGC 3D Tiles / I3S",
            family: "geo",
            mimes: &[],
            extensions: &["b3dm", "i3dm", "pnts", "cmpt"],
            magic: &[Magic::at(0, b"b3dm"), Magic::at(0, b"i3dm"), Magic::at(0, b"pnts"), Magic::at(0, b"cmpt")],
            parent: None,
        },
        FormatSpec {
            id: "tileset3d",
            name: "3D Tiles tileset",
            family: "geo",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
    ],
};

fn le_u32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_i32(b: &[u8], at: usize) -> i32 {
    b.get(at..at + 4).map_or(0, |s| i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map_or(0, u64::from_le_bytes)
}

fn pm_compression(c: u8) -> &'static str {
    match c {
        1 => "none",
        2 => "gzip",
        3 => "brotli",
        4 => "zstd",
        _ => "unknown",
    }
}

fn pmtiles(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 127).map_err(|_| ExtractError::malformed("PMTiles header"))?;
    let version = *h.get(7).ok_or_else(|| ExtractError::malformed("PMTiles header"))?;
    cx.format_set("pmtiles_version", version);
    if version != 3 || h.len() < 127 {
        return Ok(());
    }
    cx.format_set(
        "tile_type",
        match h[99] {
            1 => "mvt",
            2 => "png",
            3 => "jpeg",
            4 => "webp",
            5 => "avif",
            _ => "unknown",
        },
    );
    cx.format_set("tile_compression", pm_compression(h[98]));
    cx.format_set("internal_compression", pm_compression(h[97]));
    cx.format_set("clustered", h[96] == 1);
    cx.format_set("zoom_range", Value::Array(vec![h[100].into(), h[101].into()]));
    for (key, at) in [("addressed_tiles", 72), ("tile_entries", 80), ("tile_contents", 88)] {
        cx.format_set(key, le_u64(&h, at));
    }
    let e7 = |at| f64::from(le_i32(&h, at)) / 1e7;
    let mut b = Bounds::default();
    b.add(e7(102), e7(106));
    b.add(e7(110), e7(114));
    report_bounds(cx, &b, Some(&Crs::epsg(4326)), "pmtiles.header");
    cx.format_set("center", Value::Array(vec![num(e7(119), 7), num(e7(123), 7), h[118].into()]));
    // The metadata JSON, compressed with the internal compression.
    let (off, len) = (le_u64(&h, 24), le_u64(&h, 32));
    if len > 0 && len <= 16 << 20 {
        let raw = src.read_vec(off, usize::try_from(len).unwrap_or(0)).unwrap_or_default();
        let limit = cx.parse_limit();
        let json = match h[97] {
            2 => cx.decompress(&raw, Codec::Gzip, limit).map(|d| d.data).ok(),
            3 => cx.decompress(&raw, Codec::Brotli, limit).map(|d| d.data).ok(),
            4 => cx.decompress(&raw, Codec::Zstd, limit).map(|d| d.data).ok(),
            _ => Some(raw),
        };
        if let Some(v) = json.and_then(|j| serde_json::from_slice::<Value>(&j).ok()) {
            tile_metadata(cx, &v, "pmtiles.metadata");
        }
    }
    Ok(())
}

/// TileJSON-like metadata: name, description, attribution, vector layers.
fn tile_metadata(cx: &mut Context<'_>, v: &Value, source: &str) {
    for key in ["name", "description", "attribution", "version", "type", "generator"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            cx.format_set(key, truncate_chars(s, 300));
        }
    }
    if let Some(n) = v.get("name").and_then(Value::as_str) {
        cx.content().source(source.to_string()).title(truncate_chars(n, 200));
    }
    if let Some(d) = v.get("description").and_then(Value::as_str) {
        cx.content().source(source.to_string()).description(truncate_chars(d, 500));
    }
    if let Some(a) = v.get("attribution").and_then(Value::as_str) {
        cx.rights().source(source.to_string()).credit(truncate_chars(a, 300));
    }
    let layers: Vec<String> = v
        .get("vector_layers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|l| l.get("id").and_then(Value::as_str))
        .take(200)
        .map(|s| truncate_chars(s, 60))
        .collect();
    if !layers.is_empty() {
        cx.format_set("vector_layers", layers);
    }
}

fn mvt(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut layers = Map::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut total = 0u64;
    for (n, w) in protowire::fields(b).take(10_000) {
        let (3, Some(layer)) = (n, w.bytes()) else {
            return Err(ExtractError::malformed("not a vector tile"));
        };
        let name = protowire::first(layer, 1).and_then(protowire::Wire::text).unwrap_or_default();
        let features: Vec<&[u8]> = protowire::all(layer, 2).filter_map(protowire::Wire::bytes).collect();
        for f in &features {
            let t = protowire::first(f, 3).and_then(protowire::Wire::int).unwrap_or(0);
            let kind = match t {
                1 => "point",
                2 => "linestring",
                3 => "polygon",
                _ => "unknown",
            };
            *types.entry(kind.into()).or_default() += 1;
        }
        total += features.len() as u64;
        let keys = protowire::all(layer, 3).count();
        let mut m = Map::new();
        m.insert("features".into(), features.len().into());
        m.insert("keys".into(), keys.into());
        m.insert("extent".into(), protowire::first(layer, 5).and_then(protowire::Wire::int).unwrap_or(4096).into());
        m.insert("version".into(), protowire::first(layer, 15).and_then(protowire::Wire::int).unwrap_or(1).into());
        layers.insert(truncate_chars(&name, 60), Value::Object(m));
    }
    if layers.is_empty() {
        return Err(ExtractError::malformed("no layers"));
    }
    cx.format_set("layers", Value::Object(layers));
    cx.format_set("features", total);
    cx.format_set("geometry_types", hist(types));
    Ok(())
}

/// One OSM PBF blob's data (raw, zlib or zstd).
fn blob_data(cx: &mut Context<'_>, blob: &[u8]) -> Option<Vec<u8>> {
    if let Some(raw) = protowire::first(blob, 1).and_then(protowire::Wire::bytes) {
        return Some(raw.to_vec());
    }
    let size = usize::try_from(protowire::first(blob, 2).and_then(protowire::Wire::int).unwrap_or(0)).ok()?;
    let max = size.min(64 << 20);
    if let Some(z) = protowire::first(blob, 3).and_then(protowire::Wire::bytes) {
        return cx.decompress(z, Codec::Zlib, max).ok().map(|d| d.data);
    }
    if let Some(z) = protowire::first(blob, 7).and_then(protowire::Wire::bytes) {
        return cx.decompress(z, Codec::Zstd, max).ok().map(|d| d.data);
    }
    None
}

/// Zigzag-decoded sint64.
fn zigzag(v: u64) -> i64 {
    (v >> 1).cast_signed() ^ -(v & 1).cast_signed()
}

/// The nodes' bounds of one primitive block (plain and dense nodes).
fn block_bounds(block: &[u8], b: &mut Bounds) {
    let int = |n| protowire::first(block, n).and_then(protowire::Wire::int);
    let gran = int(17).unwrap_or(100) as f64;
    // The offsets are plain int64.
    let (lat0, lon0) = (int(19).map_or(0, u64::cast_signed) as f64, int(20).map_or(0, u64::cast_signed) as f64);
    let deg = |off: f64, v: i64| (off + gran * v as f64) * 1e-9;
    for g in protowire::all(block, 2).filter_map(protowire::Wire::bytes) {
        for (n, w) in protowire::fields(g) {
            let Some(d) = w.bytes() else { continue };
            match n {
                1 => {
                    let f = |k| protowire::first(d, k).and_then(protowire::Wire::int).map(zigzag);
                    if let (Some(la), Some(lo)) = (f(8), f(9)) {
                        b.add(deg(lon0, lo), deg(lat0, la));
                    }
                }
                2 => {
                    let lats = protowire::first(d, 8).map(protowire::packed).unwrap_or_default();
                    let lons = protowire::first(d, 9).map(protowire::packed).unwrap_or_default();
                    let (mut la, mut lo) = (0i64, 0i64);
                    for (a, o) in lats.into_iter().zip(lons) {
                        la = la.wrapping_add(zigzag(a));
                        lo = lo.wrapping_add(zigzag(o));
                        b.add(deg(lon0, lo), deg(lat0, la));
                    }
                }
                _ => {}
            }
        }
    }
}

fn osm_pbf(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let mut at = 0u64;
    let (mut blocks, mut nodes, mut ways, mut relations) = (0u64, 0u64, 0u64, 0u64);
    let mut header_seen = false;
    let mut header_box = false;
    let mut counted = true;
    let mut nodes_box = Bounds::default();
    while at + 4 <= len && blocks < 10_000_000 {
        cx.checkpoint()?;
        let l = src.read_vec(at, 4).map_err(|_| ExtractError::malformed("blob header length"))?;
        let hl = u64::from(u32::from_be_bytes([l[0], l[1], l[2], l[3]]));
        if hl == 0 || hl > 64 * 1024 {
            return Err(ExtractError::malformed("blob header length"));
        }
        let bh = src
            .read_vec(at + 4, usize::try_from(hl).unwrap_or(0))
            .map_err(|_| ExtractError::malformed("blob header"))?;
        let kind = protowire::first(&bh, 1).and_then(protowire::Wire::text).unwrap_or_default();
        let size = protowire::first(&bh, 3).and_then(protowire::Wire::int).unwrap_or(0);
        if size > 32 << 20 {
            return Err(ExtractError::malformed("blob size"));
        }
        let blob_at = at + 4 + hl;
        match kind.as_str() {
            "OSMHeader" if !header_seen => {
                header_seen = true;
                let blob = src
                    .read_vec(blob_at, usize::try_from(size).unwrap_or(0))
                    .map_err(|_| ExtractError::malformed("blob"))?;
                if let Some(data) = blob_data(cx, &blob) {
                    header_box = osm_header(cx, &data);
                }
            }
            "OSMData" => {
                blocks += 1;
                // Count primitives while the decompression budget allows.
                if counted {
                    let blob = src
                        .read_vec(blob_at, usize::try_from(size).unwrap_or(0))
                        .map_err(|_| ExtractError::malformed("blob"))?;
                    match blob_data(cx, &blob) {
                        Some(block) => {
                            block_bounds(&block, &mut nodes_box);
                            for g in protowire::all(&block, 2).filter_map(protowire::Wire::bytes) {
                                for (n, w) in protowire::fields(g) {
                                    match n {
                                        1 => nodes += 1,
                                        2 => {
                                            let ids = w.bytes().and_then(|d| protowire::first(d, 1));
                                            nodes += ids.map_or(0, |v| protowire::packed(v).len() as u64);
                                        }
                                        3 => ways += 1,
                                        4 => relations += 1,
                                        _ => {}
                                    }
                                }
                            }
                        }
                        None => counted = false,
                    }
                }
            }
            _ => {}
        }
        at = blob_at + size;
    }
    cx.format_set("data_blocks", blocks);
    if counted {
        let mut m = Map::new();
        m.insert("nodes".into(), nodes.into());
        m.insert("ways".into(), ways.into());
        m.insert("relations".into(), relations.into());
        cx.format_set("elements", Value::Object(m));
    } else {
        cx.warn("data blocks not counted: decompression limit reached");
    }
    // Without a header box, the nodes' bounds.
    if !header_box {
        report_bounds(cx, &nodes_box, Some(&Crs::epsg(4326)), "osm.nodes");
    }
    Ok(())
}

/// The header block; whether it gave a bounding box.
fn osm_header(cx: &mut Context<'_>, h: &[u8]) -> bool {
    let strings =
        |n| protowire::all(h, n).filter_map(protowire::Wire::text).map(|s| truncate_chars(&s, 60)).collect::<Vec<_>>();
    cx.format_set("required_features", strings(4));
    cx.format_set("optional_features", strings(5));
    if let Some(p) = protowire::first(h, 16).and_then(protowire::Wire::text) {
        cx.format_set("writing_program", truncate_chars(&p, 100));
    }
    if let Some(s) = protowire::first(h, 17).and_then(protowire::Wire::text) {
        cx.format_set("source", truncate_chars(&s, 200));
    }
    if let Some(t) =
        protowire::first(h, 32).and_then(protowire::Wire::int).and_then(|t| super::unix_time(i64::try_from(t).ok()?))
    {
        cx.format_set("replication_timestamp", t);
    }
    if let Some(s) = protowire::first(h, 33).and_then(protowire::Wire::int) {
        cx.format_set("replication_sequence", s);
    }
    if let Some(bb) = protowire::first(h, 1).and_then(protowire::Wire::bytes) {
        // sint64 nanodegrees, zigzag-encoded.
        let g = |n| protowire::first(bb, n).and_then(protowire::Wire::int).map(|v| zigzag(v) as f64 / 1e9);
        if let (Some(l), Some(r), Some(t), Some(bo)) = (g(1), g(2), g(3), g(4)) {
            let mut b = Bounds::default();
            b.add(l, bo);
            b.add(r, t);
            report_bounds(cx, &b, Some(&Crs::epsg(4326)), "osm.header.bbox");
            return true;
        }
    }
    false
}

fn tile3d(cx: &mut Context<'_>, b: &[u8]) {
    let magic = String::from_utf8_lossy(b.get(..4).unwrap_or_default()).into_owned();
    cx.format_set("tile_format", magic.clone());
    cx.format_set("version", le_u32(b, 4));
    if le_u32(b, 8) as usize != b.len() {
        cx.format_set("declared_length", le_u32(b, 8));
    }
    if magic == "cmpt" {
        let n = le_u32(b, 12);
        let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
        let mut at = 16usize;
        for _ in 0..n.min(10_000) {
            let Some(m) = b.get(at..at + 4) else { break };
            *kinds.entry(String::from_utf8_lossy(m).into_owned()).or_default() += 1;
            let l = le_u32(b, at + 8) as usize;
            if l == 0 {
                break;
            }
            at += l;
        }
        cx.format_set("inner_tiles", hist(kinds));
        return;
    }
    let header = if magic == "i3dm" { 32 } else { 28 };
    let (ftj, ftb, btj, btb) =
        (le_u32(b, 12) as usize, le_u32(b, 16) as usize, le_u32(b, 20) as usize, le_u32(b, 24) as usize);
    let table =
        |at: usize, n: usize| b.get(at..at.checked_add(n)?).and_then(|s| serde_json::from_slice::<Value>(s).ok());
    if let Some(ft) = table(header, ftj) {
        for key in ["BATCH_LENGTH", "INSTANCES_LENGTH", "POINTS_LENGTH"] {
            if let Some(v) = ft.get(key) {
                cx.format_set(&key.to_ascii_lowercase(), v.clone());
            }
        }
        let attrs: Vec<String> = ft
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k.clone())
            .filter(|k| !k.ends_with("_LENGTH"))
            .take(50)
            .collect();
        cx.format_set("feature_table", attrs);
    }
    let bt_at = header + ftj + ftb;
    if let Some(bt) = table(bt_at, btj) {
        cx.format_set(
            "batch_properties",
            bt.as_object().into_iter().flatten().map(|(k, _)| truncate_chars(k, 60)).take(100).collect::<Vec<_>>(),
        );
    }
    let glb_at = bt_at + btj + btb;
    if let Some(g) = b.get(glb_at..glb_at + 12).filter(|g| g.starts_with(b"glTF")) {
        cx.format_set("gltf", format!("glTF {} binary, {} bytes", le_u32(g, 4), le_u32(g, 8)));
    } else if magic == "i3dm" && le_u32(b, 28) == 0 {
        let uri =
            String::from_utf8_lossy(b.get(glb_at..).unwrap_or_default()).trim_end_matches(['\0', ' ']).to_string();
        cx.format_set("gltf_uri", truncate_chars(&uri, 200));
    }
}

fn tileset(cx: &mut Context<'_>, v: &Value) {
    for key in ["version", "tilesetVersion", "generator"] {
        if let Some(s) = v.pointer(&format!("/asset/{key}")).and_then(Value::as_str) {
            cx.format_set(key, truncate_chars(s, 60));
        }
    }
    if let Some(g) = v.get("geometricError").and_then(Value::as_f64) {
        cx.format_set("geometric_error", num(g, 3));
    }
    // Walk the tile tree.
    let mut stack = vec![(v.get("root"), 0usize)];
    let (mut tiles, mut depth) = (0u64, 0usize);
    let mut content: BTreeMap<String, u64> = BTreeMap::new();
    while let Some((Some(t), d)) = stack.pop() {
        tiles += 1;
        depth = depth.max(d);
        if tiles > 1_000_000 {
            break;
        }
        for c in [t.get("content"), t.get("contents").and_then(|c| c.get(0))].into_iter().flatten() {
            if let Some(uri) = c.get("uri").or_else(|| c.get("url")).and_then(Value::as_str) {
                let ext = uri.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                *content.entry(truncate_chars(&ext, 10)).or_default() += 1;
            }
        }
        for c in t.get("children").and_then(Value::as_array).into_iter().flatten() {
            stack.push((Some(c), d + 1));
        }
    }
    cx.format_set("tiles", tiles);
    cx.format_set("depth", depth);
    cx.format_set("content_types", hist(content));
    // A `box` in ECEF (through the root's transform), as degrees.
    if let Some(bx) = v.pointer("/root/boundingVolume/box").and_then(Value::as_array).filter(|b| b.len() >= 12) {
        let g: Vec<f64> = bx.iter().map(|x| x.as_f64().unwrap_or(f64::NAN)).collect();
        let m: Vec<f64> = v.pointer("/root/transform").and_then(Value::as_array).map_or_else(
            || vec![1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0],
            |t| t.iter().map(|x| x.as_f64().unwrap_or(f64::NAN)).collect(),
        );
        let mut b = Bounds::default();
        for sx in [-1.0, 1.0] {
            for sy in [-1.0, 1.0] {
                for sz in [-1.0, 1.0] {
                    let p: Vec<f64> = (0..3).map(|i| g[i] + sx * g[3 + i] + sy * g[6 + i] + sz * g[9 + i]).collect();
                    let w: Vec<f64> =
                        (0..3).map(|i| m[i] * p[0] + m[4 + i] * p[1] + m[8 + i] * p[2] + m[12 + i]).collect();
                    // Only boxes on the globe are geographic.
                    if w[0].hypot(w[1]).hypot(w[2]) > 6.0e6 {
                        let (lon, lat, h) = ecef_to_geodetic(w[0], w[1], w[2]);
                        b.add(lon, lat);
                        b.add_z(h);
                    }
                }
            }
        }
        if b.points == 8 {
            report_bounds(cx, &b, Some(&Crs::epsg(4326)), "tileset.box");
        }
    }
    // A `region` is west, south, east, north in radians, then heights.
    if let Some(r) = v.pointer("/root/boundingVolume/region").and_then(Value::as_array).filter(|r| r.len() >= 6) {
        let d = |i: usize| r[i].as_f64().unwrap_or(f64::NAN).to_degrees();
        let mut b = Bounds::default();
        b.add(d(0), d(1));
        b.add(d(2), d(3));
        b.add_z(r[4].as_f64().unwrap_or(f64::NAN));
        b.add_z(r[5].as_f64().unwrap_or(f64::NAN));
        report_bounds(cx, &b, Some(&Crs::epsg(4326)), "tileset.region");
    }
}

/// ECEF metres to WGS84 longitude, latitude (degrees) and height
/// (Bowring's method).
fn ecef_to_geodetic(x: f64, y: f64, z: f64) -> (f64, f64, f64) {
    let a = 6_378_137.0_f64;
    let f = 1.0 / 298.257_223_563;
    let b = a * (1.0 - f);
    let e2 = f * (2.0 - f);
    let ep2 = (a * a - b * b) / (b * b);
    let p = x.hypot(y);
    let th = (z * a).atan2(p * b);
    let lat = (z + ep2 * b * th.sin().powi(3)).atan2(p - e2 * a * th.cos().powi(3));
    let n = a / (1.0 - e2 * lat.sin().powi(2)).sqrt();
    (y.atan2(x).to_degrees(), lat.to_degrees(), p / lat.cos() - n)
}

/// Whether `b` parses as a vector tile: layers (field 3) each with a name.
fn looks_like_mvt(b: &[u8]) -> bool {
    let mut n = 0;
    for (k, w) in protowire::fields(b).take(64) {
        let Some(layer) = w.bytes().filter(|_| k == 3) else { return false };
        if protowire::first(layer, 1).and_then(protowire::Wire::text).is_none() {
            return false;
        }
        n += 1;
    }
    n > 0
}

impl Extractor for Tiles {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if h.len() > 16 && h[..4] == [0, 0, 0, h[3]] && h.get(4..15) == Some(b"\x0a\x09OSMHeader") {
            return sure("osm_pbf");
        }
        if h.first() == Some(&b'{') && {
            let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
            has(b"\"asset\"") && has(b"\"geometricError\"") && has(b"\"root\"")
        } {
            return sure("tileset3d");
        }
        // Whole small tiles only: the head must hold the tile.
        let whole = probe.len <= h.len() as u64;
        (matches!(probe.extension, Some("mvt" | "pbf")) && whole && h.first() == Some(&0x1a) && looks_like_mvt(h))
            .then_some(Sniff { format: "mvt", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            "pmtiles" => pmtiles(cx, src),
            "osm_pbf" => osm_pbf(cx, src),
            id => {
                let (b, _) = cx.read_bytes(src)?;
                match id {
                    "mvt" => mvt(cx, &b),
                    "tileset3d" => {
                        let v: Value =
                            serde_json::from_slice(&b).map_err(|_| ExtractError::malformed("tileset JSON"))?;
                        tileset(cx, &v);
                        Ok(())
                    }
                    _ => {
                        tile3d(cx, &b);
                        Ok(())
                    }
                }
            }
        }
    }
}

crate::register_extractor!(Tiles);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_tile_shape() {
        // Layer "a" with one point feature.
        let feature = [0x18, 0x01];
        let mut layer = vec![0x0a, 0x01, b'a', 0x12, u8::try_from(feature.len()).unwrap()];
        layer.extend(feature);
        layer.extend([0x78, 0x02]);
        let mut tile = vec![0x1a, u8::try_from(layer.len()).unwrap()];
        tile.extend(&layer);
        assert!(looks_like_mvt(&tile));
        assert!(!looks_like_mvt(b"\x0a\x01a"));
    }

    #[test]
    fn ecef() {
        let (lon, lat, h) = ecef_to_geodetic(6_378_137.0, 0.0, 0.0);
        assert!(lon.abs() < 1e-9 && lat.abs() < 1e-9 && h.abs() < 1e-6);
        assert_eq!(zigzag(3), -2);
        assert_eq!(zigzag(4), 2);
    }

    crate::fixture_tests!("pmtiles", "mvt", "osm_pbf", "tiles3d", "tileset3d");
}
