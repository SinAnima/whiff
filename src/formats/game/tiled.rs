//! Tiled maps and tilesets: TMX and TSX (XML), TMJ and TSJ (JSON):
//! format and Tiled versions, orientation, render order, map and tile
//! size, infinite maps, layers by type and name (groups followed), object
//! counts, tilesets (external or embedded), images, tile data encoding and
//! compression, custom properties; tilesets: name, tile size and count,
//! columns, image, tiles with properties, animations and Wang sets.
//!
//! Specification: Tiled documentation, "TMX Map Format" and "JSON Map
//! Format" (1.11).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
    xmlwalk::{Ev, attr, walk, xml_root},
};

/// Extractor for Tiled maps and tilesets.
pub struct Tiled;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.tiled",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "tiled_map",
            name: "Tiled map (TMX / TMJ)",
            family: "game",
            mimes: &["application/x-tiled-tmx"],
            extensions: &["tmx", "tmj"],
            magic: &[],
            parent: Some("xml"),
        },
        // `.tsx` is also TypeScript: tilesets are sniffed.
        FormatSpec {
            id: "tiled_tileset",
            name: "Tiled tileset (TSX / TSJ)",
            family: "game",
            mimes: &["application/x-tiled-tsx"],
            extensions: &["tsj"],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

/// What the map or tileset holds.
#[derive(Default)]
struct Summary {
    m: Map<String, Value>,
    layer_types: BTreeMap<String, u64>,
    layer_names: Vec<String>,
    objects: u64,
    tilesets: Vec<String>,
    images: BTreeSet<String>,
    encodings: BTreeSet<String>,
    properties: BTreeSet<String>,
    tiles: u64,
    animated: u64,
    wang_sets: u64,
}

impl Summary {
    fn layer(&mut self, kind: &str, name: Option<&str>) {
        bump(&mut self.layer_types, kind, 10);
        if let Some(n) = name
            && self.layer_names.len() < 100
        {
            self.layer_names.push(truncate_chars(n, 200));
        }
    }
    fn image(&mut self, src: &str) {
        if self.images.len() < 100 {
            self.images.insert(truncate_chars(src, 300));
        }
    }
    fn report(mut self, cx: &mut Context<'_>) {
        if !self.layer_types.is_empty() {
            let n: u64 = self.layer_types.values().sum();
            self.m.insert("layer_count".into(), n.into());
            self.m.insert("layer_types".into(), hist(std::mem::take(&mut self.layer_types)));
            self.m.insert("layers".into(), std::mem::take(&mut self.layer_names).into());
        }
        if self.objects > 0 {
            self.m.insert("object_count".into(), self.objects.into());
        }
        if !self.tilesets.is_empty() {
            self.m.insert("tilesets".into(), std::mem::take(&mut self.tilesets).into());
        }
        if !self.images.is_empty() {
            cx.security().external_references(self.images.len() as u64);
            self.m.insert("images".into(), self.images.iter().cloned().collect::<Vec<_>>().into());
        }
        if !self.encodings.is_empty() {
            self.m.insert("tile_data".into(), self.encodings.iter().cloned().collect::<Vec<_>>().into());
        }
        if !self.properties.is_empty() {
            self.m.insert("properties".into(), self.properties.iter().cloned().collect::<Vec<_>>().into());
        }
        for (k, v) in
            [("tiles_with_data", self.tiles), ("animated_tiles", self.animated), ("wang_sets", self.wang_sets)]
        {
            if v > 0 {
                self.m.insert(k.into(), v.into());
            }
        }
        for (k, v) in self.m {
            cx.format_set(&k, v);
        }
    }
}

/// Map or tileset attributes worth keeping, renamed.
const ATTRS: [(&str, &str); 14] = [
    ("version", "version"),
    ("tiledversion", "tiled_version"),
    ("orientation", "orientation"),
    ("renderorder", "render_order"),
    ("width", "width"),
    ("height", "height"),
    ("tilewidth", "tile_width"),
    ("tileheight", "tile_height"),
    ("infinite", "infinite"),
    ("staggeraxis", "stagger_axis"),
    ("name", "name"),
    ("tilecount", "tile_count"),
    ("columns", "columns"),
    ("class", "class"),
];

fn typed(k: &str, v: &str) -> Value {
    match k {
        "infinite" => (v == "1" || v == "true").into(),
        "version" | "tiled_version" => v.into(),
        _ => v.parse::<i64>().map_or_else(|_| truncate_chars(v, 200).into(), Value::from),
    }
}

fn tmx(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut s = Summary::default();
    let mut stack: Vec<String> = Vec::new();
    walk(text, cx, 2_000_000, |_, ev| match ev {
        Ev::Start(name, a) => {
            let parent = stack.last().map_or("", String::as_str);
            match name {
                "map" | "tileset" if stack.is_empty() => {
                    for (k, out) in ATTRS {
                        if let Some(v) = attr(a, k) {
                            s.m.insert(out.into(), typed(out, v));
                        }
                    }
                }
                "tileset" => {
                    let label = attr(a, "source").or_else(|| attr(a, "name")).unwrap_or("(unnamed)");
                    if s.tilesets.len() < 100 {
                        s.tilesets.push(truncate_chars(label, 300));
                    }
                }
                "layer" => s.layer("tile", attr(a, "name")),
                "objectgroup" => s.layer("object", attr(a, "name")),
                "imagelayer" => s.layer("image", attr(a, "name")),
                "group" => s.layer("group", attr(a, "name")),
                "object" if parent == "objectgroup" => s.objects += 1,
                "image" => {
                    if let Some(src) = attr(a, "source") {
                        s.image(src);
                    }
                }
                "data" if parent == "layer" => {
                    let enc = attr(a, "encoding").unwrap_or("xml");
                    let label = attr(a, "compression").map_or_else(|| enc.to_string(), |c| format!("{enc} + {c}"));
                    s.encodings.insert(label);
                }
                "property" if matches!(parent, "properties") && stack.len() == 2 => {
                    if let Some(n) = attr(a, "name")
                        && s.properties.len() < 100
                    {
                        s.properties.insert(truncate_chars(n, 100));
                    }
                }
                "tile" if parent == "tileset" => s.tiles += 1,
                "animation" if parent == "tile" => s.animated += 1,
                "wangset" => s.wang_sets += 1,
                _ => {}
            }
            stack.push(name.to_string());
        }
        Ev::End(_) => {
            stack.pop();
        }
        Ev::Text(_) => {}
    })?;
    s.report(cx);
    Ok(())
}

fn json_layers(s: &mut Summary, layers: &[Value], depth: usize) {
    for l in layers {
        let kind = match l.get("type").and_then(Value::as_str).unwrap_or("") {
            "tilelayer" => "tile",
            "objectgroup" => "object",
            "imagelayer" => "image",
            "group" => "group",
            _ => "other",
        };
        s.layer(kind, l.get("name").and_then(Value::as_str));
        if let Some(o) = l.get("objects").and_then(Value::as_array) {
            s.objects += o.len() as u64;
        }
        if let Some(img) = l.get("image").and_then(Value::as_str) {
            s.image(img);
        }
        if kind == "tile" {
            let enc = l.get("encoding").and_then(Value::as_str).unwrap_or("csv");
            let label = l
                .get("compression")
                .and_then(Value::as_str)
                .filter(|c| !c.is_empty())
                .map_or_else(|| enc.to_string(), |c| format!("{enc} + {c}"));
            s.encodings.insert(label);
        }
        if depth < 32
            && let Some(sub) = l.get("layers").and_then(Value::as_array)
        {
            json_layers(s, sub, depth + 1);
        }
    }
}

fn tmj(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let v: Value = serde_json::from_str(text).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    let mut s = Summary::default();
    for (k, out) in ATTRS {
        match v.get(k) {
            Some(Value::String(x)) => {
                s.m.insert(out.into(), typed(out, x));
            }
            Some(n @ (Value::Number(_) | Value::Bool(_))) => {
                s.m.insert(out.into(), n.clone());
            }
            _ => {}
        }
    }
    if let Some(l) = v.get("layers").and_then(Value::as_array) {
        json_layers(&mut s, l, 0);
    }
    for t in v.get("tilesets").and_then(Value::as_array).map_or(&[][..], Vec::as_slice).iter().take(100) {
        let label = t.get("source").or_else(|| t.get("name")).and_then(Value::as_str).unwrap_or("(unnamed)");
        s.tilesets.push(truncate_chars(label, 300));
        if let Some(img) = t.get("image").and_then(Value::as_str) {
            s.image(img);
        }
    }
    if let Some(img) = v.get("image").and_then(Value::as_str) {
        s.image(img);
    }
    for p in v.get("properties").and_then(Value::as_array).map_or(&[][..], Vec::as_slice).iter().take(100) {
        if let Some(n) = p.get("name").and_then(Value::as_str) {
            s.properties.insert(truncate_chars(n, 100));
        }
    }
    if let Some(t) = v.get("tiles").and_then(Value::as_array) {
        s.tiles = t.len() as u64;
        s.animated = t.iter().filter(|t| t.get("animation").is_some()).count() as u64;
    }
    if let Some(w) = v.get("wangsets").and_then(Value::as_array) {
        s.wang_sets = w.len() as u64;
    }
    s.report(cx);
    Ok(())
}

/// A Tiled JSON document: (`map` or `tileset`).
fn json_kind(head: &[u8]) -> Option<&'static str> {
    let t = std::str::from_utf8(&head[..head.len().min(4096)]).ok()?;
    if !t.trim_start().starts_with('{') || !t.contains("\"tiledversion\"") {
        return None;
    }
    if t.contains("\"type\":\"tileset\"") || t.contains("\"type\": \"tileset\"") {
        Some("tiled_tileset")
    } else {
        Some("tiled_map")
    }
}

impl Extractor for Tiled {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let ext = probe.extension.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if matches!(ext, "tmx" | "tsx" | "xml") {
            let (root, tag) = xml_root(probe.head)?;
            return match root.as_str() {
                "map" if tag.contains("orientation=") => sure("tiled_map"),
                "tileset" if tag.contains("tilewidth=") || ext == "tsx" => sure("tiled_tileset"),
                _ => None,
            };
        }
        if matches!(ext, "tmj" | "tsj" | "json") {
            return json_kind(probe.head).and_then(sure);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        if text.trim_start().starts_with('{') { tmj(cx, &text) } else { tmx(cx, &text) }
    }
}

crate::register_extractor!(Tiled);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("tiled_map", "tiled_tileset");
}
