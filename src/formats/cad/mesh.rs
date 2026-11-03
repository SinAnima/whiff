//! Mesh files:
//! * Wavefront OBJ (vertices, texture coordinates, normals, faces,
//!   triangles, lines, objects, groups, materials, material libraries, the
//!   exporter's comment) and MTL (materials, texture maps);
//! * STL, ASCII and binary (solid name, header text, triangles, bounds);
//! * PLY, ASCII and binary (format, comments, elements and properties,
//!   bounds); OFF;
//! * AMF and 3MF (unit, metadata, objects, vertices, triangles, build
//!   items, thumbnail); COLLADA (contributor, tool, dates, unit, up axis,
//!   geometries, triangles, images, materials, scenes, controllers,
//!   animations, bounds); X3D and VRML 2 (profile, metadata, shapes,
//!   geometry nodes, bounds);
//! * Draco (version, encoder, method).
//!
//! Specifications: Wavefront OBJ and MTL (Alias|Wavefront, appendix B of
//! the Advanced Visualizer manual); 3D Systems STL; PLY (Turk, 1994); OFF
//! (Geomview); ISO/ASTM 52915 (AMF); 3MF core specification 1.3; COLLADA
//! 1.4.1 / 1.5; ISO/IEC 19775 (X3D) and 14772 (VRML97); Draco bitstream
//! specification 2.2.

use std::collections::{BTreeMap, BTreeSet};

use super::{Box3, bump, hist};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    parse_date, truncate_chars,
    xmlwalk::{Ev, attr, walk, xml_root},
    zip_names,
};

/// Extractor for mesh files.
pub struct Mesh;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.mesh",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        // `.obj` and `.stl` are also COFF objects and Spruce subtitles:
        // these are sniffed from their content.
        FormatSpec {
            id: "obj",
            name: "Wavefront OBJ / MTL",
            family: "3d",
            mimes: &["model/obj"],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mtl",
            name: "Wavefront material library",
            family: "3d",
            mimes: &["model/mtl"],
            extensions: &["mtl"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "stl",
            name: "STL",
            family: "3d",
            mimes: &["model/stl"],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ply",
            name: "PLY",
            family: "3d",
            mimes: &["model/ply"],
            extensions: &["ply"],
            magic: &[Magic::at(0, b"ply\n"), Magic::at(0, b"ply\r\n")],
            parent: None,
        },
        FormatSpec {
            id: "off",
            name: "OFF / AMF / Stanford",
            family: "3d",
            mimes: &[],
            extensions: &["off"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "amf",
            name: "Additive Manufacturing File",
            family: "3d",
            mimes: &["application/x-amf"],
            extensions: &["amf"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "3mf",
            name: "3D Manufacturing Format",
            family: "3d",
            mimes: &["model/3mf"],
            extensions: &["3mf"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "collada",
            name: "Collada DAE",
            family: "3d",
            mimes: &["model/vnd.collada+xml"],
            extensions: &["dae"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "x3d",
            name: "X3D / VRML",
            family: "3d",
            mimes: &["model/x3d+xml"],
            extensions: &["x3d"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "vrml",
            name: "VRML",
            family: "3d",
            mimes: &["model/vrml"],
            extensions: &["wrl", "vrml"],
            magic: &[Magic::at(0, b"#VRML ")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "draco",
            name: "Draco compressed mesh",
            family: "3d",
            mimes: &[],
            extensions: &["drc"],
            magic: &[Magic::at(0, b"DRACO")],
            parent: None,
        },
    ],
};

/// The first numbers of a whitespace-separated line.
fn floats(s: &str, n: usize) -> Vec<f64> {
    s.split_whitespace().take(n).filter_map(|v| v.parse().ok()).collect()
}

/// Leading comment lines: the exporter usually names itself there.
fn header_comment(text: &str, prefix: char) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .take(10)
        .map_while(|l| l.trim().strip_prefix(prefix))
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    (!lines.is_empty()).then(|| truncate_chars(&lines.join(" | "), 300))
}

fn obj(cx: &mut Context<'_>, text: &str) {
    let (mut v, mut vt, mut vn, mut faces, mut tris, mut lines, mut points) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut b = Box3::default();
    let (mut objects, mut groups, mut materials, mut libs) = (Vec::new(), BTreeSet::new(), BTreeSet::new(), Vec::new());
    for line in text.lines().take(100_000_000) {
        let t = line.trim_start();
        let (k, rest) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
        match k {
            "v" => {
                v += 1;
                let p = floats(rest, 3);
                if p.len() == 3 {
                    b.add([p[0], p[1], p[2]]);
                }
            }
            "vt" => vt += 1,
            "vn" => vn += 1,
            "f" => {
                faces += 1;
                tris += rest.split_whitespace().count().saturating_sub(2) as u64;
            }
            "l" => lines += 1,
            "p" => points += 1,
            "o" if objects.len() < 200 => objects.push(truncate_chars(rest.trim(), 100)),
            "g" if groups.len() < 200 => {
                groups.insert(truncate_chars(rest.trim(), 100));
            }
            "usemtl" if materials.len() < 500 => {
                materials.insert(truncate_chars(rest.trim(), 100));
            }
            "mtllib" if libs.len() < 50 => libs.push(truncate_chars(rest.trim(), 200)),
            _ => {}
        }
    }
    if let Some(c) = header_comment(text, '#') {
        cx.format_set("comment", c);
    }
    cx.format_set("vertices", v);
    cx.format_set("texture_coordinates", vt);
    cx.format_set("normals", vn);
    cx.format_set("faces", faces);
    cx.format_set("triangles", tris);
    if lines > 0 {
        cx.format_set("lines", lines);
    }
    if points > 0 {
        cx.format_set("points", points);
    }
    cx.format_set("objects", objects);
    cx.format_set("groups", groups.into_iter().collect::<Vec<_>>());
    cx.format_set("materials", materials.into_iter().collect::<Vec<_>>());
    cx.format_set("material_libraries", libs);
    b.report(cx, "bounds");
}

fn mtl(cx: &mut Context<'_>, text: &str) {
    let mut materials = Vec::new();
    let mut maps: BTreeMap<String, u64> = BTreeMap::new();
    let mut textures = BTreeSet::new();
    for line in text.lines().take(10_000_000) {
        let t = line.trim_start();
        let (k, rest) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
        if k == "newmtl" && materials.len() < 1000 {
            materials.push(truncate_chars(rest.trim(), 100));
        } else if k.starts_with("map_") || matches!(k, "bump" | "disp" | "decal" | "refl" | "norm") {
            bump(&mut maps, k, 50);
            // The file is the last word; options come before it.
            if let Some(f) = rest.split_whitespace().last()
                && textures.len() < 500
            {
                textures.insert(truncate_chars(f.rsplit(['/', '\\']).next().unwrap_or(f), 100));
            }
        }
    }
    if let Some(c) = header_comment(text, '#') {
        cx.format_set("comment", c);
    }
    cx.format_set("material_count", materials.len());
    cx.format_set("materials", materials);
    cx.format_set("texture_maps", hist(maps));
    cx.format_set("textures", textures.into_iter().collect::<Vec<_>>());
}

/// Whether `b` is a binary STL: 84 + 50 bytes per triangle.
fn binary_stl(head: &[u8], len: u64) -> bool {
    head.len() >= 84 && 84 + 50 * u64::from(u32::from_le_bytes([head[80], head[81], head[82], head[83]])) == len
}

fn stl(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let head = src
        .read_vec(0, 84.min(usize::try_from(len).unwrap_or(0)))
        .map_err(|_| ExtractError::malformed("STL header"))?;
    let mut b = Box3::default();
    if binary_stl(&head, len) {
        cx.format_set("encoding", "binary");
        let hdr = String::from_utf8_lossy(&head[..80]).trim_end_matches(['\0', ' ']).to_string();
        if !hdr.is_empty() && hdr.chars().all(|c| !c.is_control()) {
            cx.format_set("header", truncate_chars(&hdr, 80));
        }
        let n = u64::from(u32::from_le_bytes([head[80], head[81], head[82], head[83]]));
        cx.format_set("triangles", n);
        // Vertices in chunks, bounded by the parse limit.
        let max = u64::try_from(cx.parse_limit()).unwrap_or(u64::MAX) / 50;
        let mut at = 84u64;
        let mut left = n.min(max);
        while left > 0 {
            cx.checkpoint()?;
            let k = left.min(20_000);
            let data = src
                .read_vec(at, usize::try_from(k * 50).unwrap_or(0))
                .map_err(|_| ExtractError::malformed("triangles"))?;
            for t in data.as_chunks::<50>().0 {
                for v in 0..3 {
                    let f = |i: usize| {
                        f64::from(f32::from_le_bytes([
                            t[12 + v * 12 + i * 4],
                            t[13 + v * 12 + i * 4],
                            t[14 + v * 12 + i * 4],
                            t[15 + v * 12 + i * 4],
                        ]))
                    };
                    b.add([f(0), f(1), f(2)]);
                }
            }
            at += k * 50;
            left -= k;
        }
        if n > max {
            cx.warn("bounds from the first triangles only (parse limit)");
        }
    } else {
        cx.format_set("encoding", "ascii");
        let text = cx.read_text(src)?.text;
        let mut tris = 0u64;
        let mut solids = Vec::new();
        for line in text.lines().take(100_000_000) {
            let t = line.trim_start();
            if let Some(r) = t.strip_prefix("vertex") {
                let p = floats(r, 3);
                if p.len() == 3 {
                    b.add([p[0], p[1], p[2]]);
                }
            } else if t.starts_with("facet") {
                tris += 1;
            } else if let Some(n) = t.strip_prefix("solid")
                && solids.len() < 100
            {
                solids.push(truncate_chars(n.trim(), 100));
            }
        }
        cx.format_set("triangles", tris);
        if let Some(n) = solids.first().filter(|n| !n.is_empty()) {
            cx.content().source("stl.solid").title(n.clone());
        }
        cx.format_set("solids", solids);
    }
    b.report(cx, "bounds");
    Ok(())
}

/// PLY property type sizes.
fn ply_size(t: &str) -> Option<usize> {
    Some(match t {
        "char" | "uchar" | "int8" | "uint8" => 1,
        "short" | "ushort" | "int16" | "uint16" => 2,
        "int" | "uint" | "float" | "int32" | "uint32" | "float32" => 4,
        "double" | "float64" => 8,
        _ => return None,
    })
}

fn ply_value(b: &[u8], t: &str, big: bool) -> f64 {
    macro_rules! read {
        ($ty:ty, $n:expr) => {{
            let r: [u8; $n] = b[..$n].try_into().unwrap_or([0; $n]);
            f64::from(if big { <$ty>::from_be_bytes(r) } else { <$ty>::from_le_bytes(r) })
        }};
    }
    match t {
        "char" | "int8" => f64::from(b[0].cast_signed()),
        "uchar" | "uint8" => f64::from(b[0]),
        "short" | "int16" => read!(i16, 2),
        "ushort" | "uint16" => read!(u16, 2),
        "int" | "int32" => read!(i32, 4),
        "uint" | "uint32" => read!(u32, 4),
        "float" | "float32" => read!(f32, 4),
        _ => {
            let r: [u8; 8] = b[..8].try_into().unwrap_or([0; 8]);
            if big { f64::from_be_bytes(r) } else { f64::from_le_bytes(r) }
        }
    }
}

/// A PLY element: name, count, properties (type, name, list count type).
type PlyElement = (String, u64, Vec<(String, String, Option<String>)>);

#[allow(clippy::too_many_lines)] // the header, then the vertex data
fn ply(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let head = src
        .read_vec(0, usize::try_from(src.len()).unwrap_or(0).min(64 << 10))
        .map_err(|_| ExtractError::malformed("header"))?;
    let end =
        head.windows(10).position(|w| w == b"end_header").ok_or_else(|| ExtractError::malformed("no end_header"))?;
    let body_at = end + 10 + head[end + 10..].iter().take(2).take_while(|&&c| c == b'\r' || c == b'\n').count();
    let header = String::from_utf8_lossy(&head[..end]).into_owned();
    let mut format = String::new();
    let mut comments = Vec::new();
    let mut elements: Vec<PlyElement> = Vec::new();
    for line in header.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w.as_slice() {
            ["format", f, ..] => format = (*f).to_string(),
            ["comment" | "obj_info", ..] if comments.len() < 20 => {
                comments.push(truncate_chars(line.split_once(' ').map_or("", |x| x.1), 200));
            }
            ["element", name, n] => elements.push(((*name).to_string(), n.parse().unwrap_or(0), Vec::new())),
            ["property", "list", c, t, name] => {
                if let Some(e) = elements.last_mut() {
                    e.2.push(((*t).to_string(), (*name).to_string(), Some((*c).to_string())));
                }
            }
            ["property", t, name] => {
                if let Some(e) = elements.last_mut() {
                    e.2.push(((*t).to_string(), (*name).to_string(), None));
                }
            }
            _ => {}
        }
    }
    cx.format_set("encoding", format.clone());
    if !comments.is_empty() {
        cx.format_set("comments", comments);
    }
    let mut list = serde_json::Map::new();
    for (name, n, props) in &elements {
        let mut m = serde_json::Map::new();
        m.insert("count".into(), (*n).into());
        m.insert("properties".into(), props.iter().take(50).map(|p| p.1.clone()).collect::<Vec<_>>().into());
        list.insert(truncate_chars(name, 40), serde_json::Value::Object(m));
    }
    cx.format_set("elements", serde_json::Value::Object(list));
    for (name, key) in [("vertex", "vertices"), ("face", "faces")] {
        if let Some(e) = elements.iter().find(|e| e.0 == name) {
            cx.format_set(key, e.1);
        }
    }
    // Bounds: the vertex element, when it comes first and has only scalars.
    let Some((_, nv, props)) = elements.first().filter(|e| e.0 == "vertex") else { return Ok(()) };
    let idx = |n: &str| props.iter().position(|p| p.1 == n);
    let (Some(ix), Some(iy), Some(iz)) = (idx("x"), idx("y"), idx("z")) else { return Ok(()) };
    let mut b = Box3::default();
    let limit = (*nv).min(50_000_000);
    if format == "ascii" {
        let text = cx.read_text(src)?.text;
        let body = text.get(body_at..).unwrap_or("");
        for line in body.lines().take(usize::try_from(limit).unwrap_or(0)) {
            let v: Vec<f64> = line.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if let (Some(&x), Some(&y), Some(&z)) = (v.get(ix), v.get(iy), v.get(iz)) {
                b.add([x, y, z]);
            }
        }
    } else if props.iter().all(|p| p.2.is_none()) {
        let sizes: Option<Vec<usize>> = props.iter().map(|p| ply_size(&p.0)).collect();
        let Some(sizes) = sizes else { return Ok(()) };
        let stride: usize = sizes.iter().sum();
        let off = |i: usize| sizes[..i].iter().sum::<usize>();
        let big = format == "binary_big_endian";
        let max = u64::try_from(cx.parse_limit() / stride.max(1)).unwrap_or(u64::MAX);
        let mut at = body_at as u64;
        let mut left = limit.min(max);
        while left > 0 {
            cx.checkpoint()?;
            let k = left.min(50_000);
            let data = src
                .read_vec(at, usize::try_from(k).unwrap_or(0) * stride)
                .map_err(|_| ExtractError::malformed("vertices"))?;
            for r in data.chunks_exact(stride) {
                let g = |i: usize| ply_value(&r[off(i)..], &props[i].0, big);
                b.add([g(ix), g(iy), g(iz)]);
            }
            at += k * stride as u64;
            left -= k;
        }
    }
    b.report(cx, "bounds");
    Ok(())
}

fn off(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut lines = text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty());
    let kind = lines.next().unwrap_or("");
    cx.format_set("variant", truncate_chars(kind.split_whitespace().next().unwrap_or(""), 10));
    // The counts may share the keyword's line.
    let rest = kind.split_once(char::is_whitespace).map(|x| x.1).filter(|r| !r.trim().is_empty());
    let counts_line = rest.map(str::to_string).or_else(|| lines.next().map(str::to_string)).unwrap_or_default();
    let c: Vec<u64> = counts_line.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    let [nv, nf, ..] = c[..] else {
        return Err(ExtractError::malformed("OFF counts"));
    };
    cx.format_set("vertices", nv);
    cx.format_set("faces", nf);
    let mut b = Box3::default();
    for l in lines.take(usize::try_from(nv.min(50_000_000)).unwrap_or(0)) {
        let p = floats(l, 3);
        if p.len() == 3 {
            b.add([p[0], p[1], p[2]]);
        }
    }
    b.report(cx, "bounds");
    Ok(())
}

/// AMF and 3MF models: unit, metadata, objects, vertices, triangles.
fn xml_model(cx: &mut Context<'_>, text: &str, threemf: bool) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let (mut objects, mut vertices, mut triangles, mut items, mut materials) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut meta: Vec<(String, String)> = Vec::new();
    let mut unit = None;
    let mut b = Box3::default();
    let mut xyz = [f64::NAN; 3];
    let mut meta_key = None::<String>;
    walk(text, cx, 50_000_000, |_, ev| match ev {
        Ev::Start(n, a) => {
            match n {
                "model" | "amf" => unit = attr(a, "unit").map(str::to_string),
                "object" => objects += 1,
                "vertex" => {
                    vertices += 1;
                    if threemf {
                        let f = |k| attr(a, k).and_then(|v| v.parse().ok()).unwrap_or(f64::NAN);
                        b.add([f("x"), f("y"), f("z")]);
                    } else {
                        xyz = [f64::NAN; 3];
                    }
                }
                "triangle" => triangles += 1,
                "item" => items += 1,
                "material" | "basematerials" | "base" => materials += 1,
                "metadata" => meta_key = attr(a, "name").or_else(|| attr(a, "type")).map(str::to_string),
                _ => {}
            }
            path.push(n.to_string());
        }
        Ev::End(n) => {
            if n == "vertex" && !threemf {
                b.add(xyz);
            }
            if n == "metadata" {
                meta_key = None;
            }
            path.pop();
        }
        Ev::Text(t) => match path.last().map(String::as_str) {
            Some(k @ ("x" | "y" | "z")) if !threemf => {
                xyz[usize::from(k.as_bytes()[0] - b'x')] = t.parse().unwrap_or(f64::NAN);
            }
            Some("metadata") => {
                if let Some(k) = &meta_key
                    && meta.len() < 50
                {
                    meta.push((truncate_chars(k, 60), truncate_chars(t, 300)));
                }
            }
            _ => {}
        },
    })?;
    if let Some(u) = unit {
        cx.format_set("unit", u);
    }
    let mut m = serde_json::Map::new();
    for (k, v) in &meta {
        m.insert(k.clone(), v.clone().into());
        match k.to_ascii_lowercase().as_str() {
            "title" | "name" => {
                cx.content().source(format!("model.metadata.{k}")).title(v.clone());
            }
            "designer" | "author" => {
                cx.content().source(format!("model.metadata.{k}")).author(v.clone());
            }
            "description" => {
                cx.content().source("model.metadata.description").description(v.clone());
            }
            "copyright" => {
                cx.rights().source("model.metadata.copyright").copyright(v.clone());
            }
            "creationdate" => {
                if let Some((d, tz)) = parse_date(v) {
                    cx.temporal().source("model.metadata.CreationDate").content_date(DateField::Created, d, tz);
                }
            }
            _ => {}
        }
    }
    if !m.is_empty() {
        cx.format_set("metadata", serde_json::Value::Object(m));
    }
    cx.format_set("objects", objects);
    cx.format_set("vertices", vertices);
    cx.format_set("triangles", triangles);
    if threemf {
        cx.format_set("build_items", items);
    }
    if materials > 0 {
        cx.format_set("materials", materials);
    }
    b.report(cx, "bounds");
    Ok(())
}

fn threemf(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let names: Vec<String> = zip.entries.iter().map(|e| e.name.clone()).collect();
    cx.format_set("entries", names.len());
    let models: Vec<&String> = names.iter().filter(|n| n.to_ascii_lowercase().ends_with(".model")).collect();
    cx.format_set("model_parts", models.len());
    cx.format_set("thumbnail", names.iter().any(|n| n.to_ascii_lowercase().contains("thumbnail")));
    let main = names
        .iter()
        .find(|n| n.eq_ignore_ascii_case("3D/3dmodel.model"))
        .or(models.first().copied())
        .cloned()
        .ok_or_else(|| ExtractError::malformed("no model part"))?;
    let limit = cx.parse_limit();
    let text = zip.read_text(src, &main, cx, limit).ok_or_else(|| ExtractError::malformed("model part"))??;
    xml_model(cx, &text, true)
}

/// COLLADA: asset, libraries and the positions' bounds.
#[allow(clippy::too_many_lines)] // the walk, then the report
fn collada(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut asset: BTreeMap<String, String> = BTreeMap::new();
    let mut version = None;
    let mut arrays: BTreeMap<String, String> = BTreeMap::new();
    let mut array_id: Option<String> = None;
    let mut positions: BTreeSet<String> = BTreeSet::new();
    let mut source_of_array: BTreeMap<String, String> = BTreeMap::new();
    let mut source: Option<String> = None;
    let mut triangles = 0u64;
    walk(text, cx, 50_000_000, |_, ev| match ev {
        Ev::Start(n, a) => {
            match n {
                "COLLADA" => version = attr(a, "version").map(str::to_string),
                "geometry" | "image" | "material" | "effect" | "light" | "camera" | "controller" | "animation"
                | "visual_scene" => {
                    bump(&mut counts, n, 20);
                }
                "node" => bump(&mut counts, "node", 20),
                "unit" => {
                    if let Some(m) = attr(a, "meter") {
                        asset.insert("unit_meter".into(), m.to_string());
                    }
                    if let Some(m) = attr(a, "name") {
                        asset.insert("unit".into(), m.to_string());
                    }
                }
                "source" => source = attr(a, "id").map(str::to_string),
                "float_array" => {
                    array_id = attr(a, "id").map(str::to_string);
                    if let (Some(s), Some(id)) = (&source, &array_id) {
                        source_of_array.insert(id.clone(), s.clone());
                    }
                }
                "input"
                    if path.last().map(String::as_str) == Some("vertices")
                        && attr(a, "semantic") == Some("POSITION") =>
                {
                    if let Some(s) = attr(a, "source") {
                        positions.insert(s.trim_start_matches('#').to_string());
                    }
                }
                "triangles" | "polylist" | "polygons" => {
                    let c: u64 = attr(a, "count").and_then(|c| c.parse().ok()).unwrap_or(0);
                    // Polylists count polygons; triangles are counted from vcount below.
                    if n == "triangles" {
                        triangles += c;
                    }
                }
                _ => {}
            }
            path.push(n.to_string());
        }
        Ev::End(n) => {
            if n == "float_array" {
                array_id = None;
            }
            if n == "source" {
                source = None;
            }
            path.pop();
        }
        Ev::Text(t) => {
            let p: Vec<&str> = path.iter().map(String::as_str).collect();
            match p.as_slice() {
                [.., "asset", "contributor", k @ ("author" | "authoring_tool" | "copyright")] => {
                    asset.entry((*k).to_string()).or_insert_with(|| truncate_chars(t, 200));
                }
                [.., "asset", k @ ("created" | "modified" | "up_axis" | "title" | "subject" | "keywords")] => {
                    asset.entry((*k).to_string()).or_insert_with(|| truncate_chars(t, 200));
                }
                [.., "float_array"] => {
                    if let Some(id) = &array_id
                        && arrays.len() < 10_000
                    {
                        arrays.insert(id.clone(), t.to_string());
                    }
                }
                [.., "polylist", "vcount"] => {
                    triangles += t
                        .split_whitespace()
                        .filter_map(|c| c.parse::<u64>().ok())
                        .map(|c| c.saturating_sub(2))
                        .sum::<u64>();
                }
                _ => {}
            }
        }
    })?;
    if let Some(v) = version {
        cx.format_set("collada_version", v);
    }
    for (k, v) in &asset {
        cx.format_set(k, v.clone());
    }
    if let Some(a) = asset.get("author") {
        cx.content().source("collada.contributor.author").author(a.clone());
    }
    if let Some(t) = asset.get("title") {
        cx.content().source("collada.asset.title").title(t.clone());
    }
    for (k, f) in [("created", DateField::Created), ("modified", DateField::Modified)] {
        if let Some((d, tz)) = asset.get(k).and_then(|v| parse_date(v)) {
            cx.temporal().source(format!("collada.asset.{k}")).content_date(f, d, tz);
        }
    }
    cx.format_set("counts", hist(counts));
    cx.format_set("triangles", triangles);
    let mut b = Box3::default();
    let mut vertices = 0u64;
    for (id, values) in &arrays {
        let is_pos = source_of_array
            .get(id)
            .is_some_and(|s| positions.contains(s) || s.to_ascii_lowercase().contains("position"));
        if is_pos {
            let v: Vec<f64> = values.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            vertices += (v.len() / 3) as u64;
            b.add_all(&v);
        }
    }
    cx.format_set("vertices", vertices);
    b.report(cx, "bounds");
    Ok(())
}

fn x3d(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut nodes: BTreeMap<String, u64> = BTreeMap::new();
    let mut meta: Vec<(String, String)> = Vec::new();
    let mut b = Box3::default();
    let mut root: BTreeMap<&str, String> = BTreeMap::new();
    walk(text, cx, 50_000_000, |_, ev| {
        if let Ev::Start(n, a) = ev {
            match n {
                "X3D" => {
                    for k in ["profile", "version"] {
                        if let Some(v) = attr(a, k) {
                            root.insert(k, truncate_chars(v, 30));
                        }
                    }
                }
                "meta" => {
                    if let (Some(k), Some(v)) = (attr(a, "name"), attr(a, "content"))
                        && meta.len() < 50
                    {
                        meta.push((truncate_chars(k, 60), truncate_chars(v, 300)));
                    }
                }
                "Coordinate" => {
                    let v: Vec<f64> = attr(a, "point")
                        .unwrap_or("")
                        .split([' ', ',', '\n', '\t'])
                        .filter_map(|x| x.parse().ok())
                        .collect();
                    b.add_all(&v);
                }
                "Shape" | "Transform" | "Group" | "IndexedFaceSet" | "IndexedTriangleSet" | "TriangleSet" | "Box"
                | "Sphere" | "Cylinder" | "Cone" | "IndexedLineSet" | "PointSet" | "ImageTexture" | "Material"
                | "Viewpoint" => {
                    bump(&mut nodes, n, 40);
                }
                _ => {}
            }
        }
    })?;
    for (k, v) in root {
        cx.format_set(if k == "version" { "x3d_version" } else { k }, v);
    }
    xmeta(cx, &meta, "x3d.meta");
    cx.format_set("nodes", hist(nodes));
    b.report(cx, "bounds");
    Ok(())
}

/// `meta name / content` pairs: title, creator, description, copyright.
fn xmeta(cx: &mut Context<'_>, meta: &[(String, String)], source: &str) {
    let mut m = serde_json::Map::new();
    for (k, v) in meta {
        m.insert(k.clone(), v.clone().into());
        match k.to_ascii_lowercase().as_str() {
            "title" => {
                cx.content().source(source.to_string()).title(v.clone());
            }
            "creator" | "author" => {
                cx.content().source(source.to_string()).author(v.clone());
            }
            "description" => {
                cx.content().source(source.to_string()).description(v.clone());
            }
            "copyright" => {
                cx.rights().source(source.to_string()).copyright(v.clone());
            }
            _ => {}
        }
    }
    if !m.is_empty() {
        cx.format_set("metadata", serde_json::Value::Object(m));
    }
}

fn vrml(cx: &mut Context<'_>, text: &str) {
    let first = text.lines().next().unwrap_or("");
    cx.format_set("header", truncate_chars(first.trim(), 60));
    let mut nodes: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Box3::default();
    let mut in_point = false;
    let mut pending: Vec<f64> = Vec::new();
    for line in text.lines().skip(1).take(50_000_000) {
        let t = line.split('#').next().unwrap_or("");
        for word in t.split(|c: char| c.is_whitespace() || c == '{').filter(|w| !w.is_empty()) {
            if matches!(
                word,
                "Shape"
                    | "Transform"
                    | "Group"
                    | "IndexedFaceSet"
                    | "IndexedLineSet"
                    | "PointSet"
                    | "Box"
                    | "Sphere"
                    | "Cylinder"
                    | "Cone"
                    | "Material"
                    | "ImageTexture"
                    | "Viewpoint"
                    | "WorldInfo"
            ) {
                bump(&mut nodes, word, 40);
            }
        }
        // `point [ x y z, … ]` lists hold the coordinates.
        if let Some(i) = t.find("point") {
            in_point = t[i..].contains('[');
            pending.clear();
        }
        if in_point {
            let after = t.split_once('[').map_or(t, |x| x.1);
            let body = after.split(']').next().unwrap_or("");
            pending.extend(body.split([' ', ',', '\t']).filter_map(|x| x.parse::<f64>().ok()));
            let whole = pending.len() / 3 * 3;
            b.add_all(&pending[..whole]);
            pending.drain(..whole);
            if t.contains(']') {
                in_point = false;
            }
        }
    }
    cx.format_set("nodes", hist(nodes));
    if let Some(tl) =
        text.split("title").nth(1).and_then(|r| r.split('"').nth(1)).filter(|_| text.contains("WorldInfo"))
    {
        cx.content().source("vrml.WorldInfo.title").title(truncate_chars(tl, 200));
    }
    b.report(cx, "bounds");
}

fn draco(cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let g = |i: usize| h.get(i).copied().ok_or_else(|| ExtractError::malformed("Draco header"));
    cx.format_set("draco_version", format!("{}.{}", g(5)?, g(6)?));
    cx.format_set(
        "geometry",
        match g(7)? {
            0 => "point cloud",
            1 => "triangular mesh",
            _ => "unknown",
        },
    );
    cx.format_set(
        "encoder",
        match g(8)? {
            0 => "sequential",
            1 => "edgebreaker",
            _ => "unknown",
        },
    );
    let flags = u16::from_le_bytes([g(9)?, g(10)?]);
    cx.format_set("metadata", flags & 0x8000 != 0);
    Ok(())
}

impl Extractor for Mesh {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if h.starts_with(b"PK\x03\x04") {
            return zip_names(probe, 100)
                .iter()
                .any(|n| n.eq_ignore_ascii_case("3D/3dmodel.model"))
                .then_some(Sniff { format: "3mf", confidence: 0.98 });
        }
        if ext == "stl" && binary_stl(h, probe.len) {
            return sure("stl");
        }
        let text = std::str::from_utf8(&h[..h.len().min(8192)])
            .ok()
            .or_else(|| std::str::from_utf8(&h[..h.len().min(4096)]).ok())?;
        if text.starts_with("solid") && text.contains("facet normal") {
            return sure("stl");
        }
        if let Some((root, tag)) = xml_root(h) {
            return match root.as_str() {
                "COLLADA" => sure("collada"),
                "X3D" => sure("x3d"),
                "amf" => sure("amf"),
                _ => {
                    let _ = tag;
                    None
                }
            };
        }
        let first = text.trim_start().lines().next().unwrap_or("").trim();
        if matches!(first.split_whitespace().next(), Some("OFF" | "COFF" | "NOFF" | "CNOFF" | "STOFF" | "4OFF")) {
            return sure("off");
        }
        // OBJ: statements only (a large mesh's first lines are all vertices).
        let lines: Vec<&str> =
            text.lines().take(200).map(str::trim_start).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        let has = |p: &str| lines.iter().any(|l| l.starts_with(p));
        let statement = |l: &&str| {
            let k = l.split_whitespace().next().unwrap_or("");
            matches!(
                k,
                "v" | "vt"
                    | "vn"
                    | "vp"
                    | "f"
                    | "l"
                    | "p"
                    | "o"
                    | "g"
                    | "s"
                    | "usemtl"
                    | "mtllib"
                    | "cstype"
                    | "deg"
                    | "curv"
                    | "surf"
                    | "parm"
                    | "end"
            )
        };
        let vertices = lines.iter().filter(|l| l.starts_with("v ")).count();
        let complete = text.len() < h.len() || lines.len() >= 20;
        if vertices >= 3 && complete && lines.iter().take(lines.len().saturating_sub(1)).all(statement) {
            return sure("obj");
        }
        (has("newmtl ")).then_some(Sniff { format: "mtl", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "stl" => return stl(cx, src),
            "ply" => return ply(cx, src),
            "3mf" => return threemf(cx, src),
            "draco" => {
                let h = src.read_vec(0, 16).map_err(|_| ExtractError::malformed("Draco header"))?;
                return draco(cx, &h);
            }
            _ => {}
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "obj" => obj(cx, &text),
            "mtl" => mtl(cx, &text),
            "off" => return off(cx, &text),
            "amf" => return xml_model(cx, &text, false),
            "collada" => return collada(cx, &text),
            "x3d" => return x3d(cx, &text),
            _ => vrml(cx, &text),
        }
        Ok(())
    }
}

crate::register_extractor!(Mesh);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stl_and_ply_helpers() {
        let mut h = vec![0u8; 84];
        h[80] = 2;
        assert!(binary_stl(&h, 184));
        assert!(!binary_stl(&h, 185));
        assert_eq!(ply_size("float"), Some(4));
        assert!((ply_value(&1.5f32.to_be_bytes(), "float", true) - 1.5).abs() < 1e-9);
        assert_eq!(
            header_comment("# Blender 4.3\n# www.blender.org\nv 1 2 3", '#').as_deref(),
            Some("Blender 4.3 | www.blender.org")
        );
    }

    crate::fixture_tests!("obj", "mtl", "stl", "ply", "off", "amf", "3mf", "collada", "x3d", "vrml", "draco");
}
