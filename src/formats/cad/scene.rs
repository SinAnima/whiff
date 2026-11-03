//! Scene, asset and capture files:
//! * FBX, binary and ASCII: version, creator, creation time, the original
//!   and last-saved applications, up axis and unit scale, objects by type,
//!   geometry vertices and polygons, embedded and external media;
//! * Blender `.blend` (plain, gzip or zstd): version, pointer size, byte
//!   order, data blocks by ID type, the thumbnail;
//! * USD: USDA text (layer metadata, prims by type, referenced assets),
//!   USDC (crate version and sections), USDZ (entries and its first layer);
//! * 3DS (version, objects, vertices, faces, materials, cameras, lights,
//!   bounds); `MagicaVoxel` (models, sizes, voxels, scene nodes); `OpenVDB`
//!   (versions, metadata, grids);
//! * BVH and C3D motion capture (joints, channels, points, analog
//!   channels, frames, rate, duration, labels, manufacturer);
//! * IES LM-63 and EULUMDAT photometry (keywords, luminaire, lamps,
//!   lumens, wattage, angles, dimensions); `LDraw` models (title, author,
//!   licence, sub-files, part references, colours).
//!
//! Specifications: the FBX binary layout as documented by Blender's
//! importer (`io_scene_fbx`); Blender `BHead` (DNA, `BLO_read`); `OpenUSD`
//! crate file format and USDZ; Autodesk 3DS chunk
//! reference; `MagicaVoxel` `.vox` 150 / 200; `OpenVDB` `io/File`;
//! Biovision BVH; C3D User Guide (2008); ANSI/IES LM-63-2019; EULUMDAT
//! (1990); `LDraw` File Format 1.0.2 and MPD.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{Box3, bump, hist, num};
use crate::plugin::{
    Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    Zip, truncate_chars, zip_names,
};

/// Extractor for scene, asset and capture files.
pub struct Scene;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.scene",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "fbx",
            name: "FBX",
            family: "3d",
            mimes: &["application/vnd.autodesk.fbx"],
            extensions: &["fbx"],
            // ASCII FBX has no magic: both are sniffed.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "blend",
            name: "Blender",
            family: "3d",
            mimes: &["application/x-blender"],
            extensions: &["blend"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "usda",
            name: "USD / USDZ / USDA / USDC",
            family: "3d",
            mimes: &[],
            extensions: &["usda"],
            magic: &[Magic::at(0, b"#usda ")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "usdc",
            name: "USD crate file",
            family: "3d",
            mimes: &[],
            extensions: &["usdc", "usd"],
            magic: &[Magic::at(0, b"PXR-USDC")],
            parent: None,
        },
        FormatSpec {
            id: "usdz",
            name: "USDZ package",
            family: "3d",
            mimes: &["model/vnd.usdz+zip"],
            extensions: &["usdz"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "3ds",
            name: "Autodesk 3DS / MAX",
            family: "3d",
            mimes: &[],
            extensions: &["3ds"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "vox",
            name: "MagicaVoxel / Qubicle",
            family: "3d",
            mimes: &[],
            extensions: &["vox"],
            magic: &[Magic::at(0, b"VOX ")],
            parent: None,
        },
        FormatSpec {
            id: "openvdb",
            name: "OpenVDB volume",
            family: "3d",
            mimes: &[],
            extensions: &["vdb"],
            magic: &[Magic::at(0, b" BDV\0\0\0\0")],
            parent: None,
        },
        FormatSpec {
            id: "bvh",
            name: "Motion capture BVH / C3D",
            family: "3d",
            mimes: &[],
            extensions: &["bvh"],
            magic: &[Magic::at(0, b"HIERARCHY")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "c3d",
            name: "C3D motion capture",
            family: "3d",
            mimes: &[],
            extensions: &["c3d"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ies",
            name: "IES photometric",
            family: "3d",
            mimes: &[],
            extensions: &["ies"],
            magic: &[Magic::at(0, b"IESNA")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ldt",
            name: "EULUMDAT photometric",
            family: "3d",
            mimes: &[],
            extensions: &["ldt"],
            magic: &[],
            parent: Some("text"),
        },
        // `.mpd` is also a DASH manifest: MPD files are sniffed.
        FormatSpec {
            id: "ldraw",
            name: "LDraw brick models",
            family: "3d",
            mimes: &[],
            extensions: &["ldr"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

// ---------------------------------------------------------------- FBX

/// One FBX property value (arrays by length only).
#[derive(Debug)]
enum Prop {
    Int(i64),
    Float(f64),
    Str(String),
    Raw(usize),
    Array(usize),
}

/// An FBX node: name, properties, children range and end.
struct FbxNode {
    name: String,
    props: Vec<Prop>,
    children: (usize, usize),
    end: usize,
}

fn fbx_node(b: &[u8], at: usize, wide: bool) -> Option<FbxNode> {
    let u32_at = |i: usize| Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?));
    let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
    let (end, n, plen, head) = if wide {
        (usize::try_from(u64_at(at)?).ok()?, u64_at(at + 8)?, usize::try_from(u64_at(at + 16)?).ok()?, at + 24)
    } else {
        (u32_at(at)? as usize, u64::from(u32_at(at + 4)?), u32_at(at + 8)? as usize, at + 12)
    };
    if end == 0 {
        return None;
    }
    let nl = usize::from(*b.get(head)?);
    let name = String::from_utf8_lossy(b.get(head + 1..head + 1 + nl)?).into_owned();
    let mut p = head + 1 + nl;
    let props_end = p.checked_add(plen)?;
    let mut props = Vec::new();
    for _ in 0..n.min(10_000) {
        let t = *b.get(p)?;
        p += 1;
        let prop = match t {
            b'Y' => Prop::Int(i64::from(i16::from_le_bytes(b.get(p..p + 2)?.try_into().ok()?))),
            b'C' => Prop::Int(i64::from(*b.get(p)?)),
            b'I' => Prop::Int(i64::from(i32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))),
            b'F' => Prop::Float(f64::from(f32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))),
            b'D' => Prop::Float(f64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?)),
            b'L' => Prop::Int(i64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?)),
            b'f' | b'd' | b'l' | b'i' | b'b' => Prop::Array(u32_at(p)? as usize),
            b'S' => Prop::Str(String::from_utf8_lossy(b.get(p + 4..p + 4 + u32_at(p)? as usize)?).into_owned()),
            b'R' => Prop::Raw(u32_at(p)? as usize),
            _ => return None,
        };
        p += match t {
            b'Y' => 2,
            b'C' => 1,
            b'I' | b'F' => 4,
            b'D' | b'L' => 8,
            b'f' | b'd' | b'l' | b'i' | b'b' => 12 + u32_at(p + 8)? as usize,
            _ => 4 + u32_at(p)? as usize,
        };
        props.push(prop);
    }
    Some(FbxNode { name, props, children: (props_end, end), end })
}

/// The child nodes of the range `[at, end)` (stopping at the null record).
fn fbx_children(b: &[u8], mut at: usize, end: usize, wide: bool) -> Vec<FbxNode> {
    let mut out = Vec::new();
    while at < end && out.len() < 1_000_000 {
        let Some(n) = fbx_node(b, at, wide) else { break };
        if n.end <= at || n.end > end {
            break;
        }
        at = n.end;
        out.push(n);
    }
    out
}

fn prop_str(p: &[Prop], i: usize) -> Option<String> {
    match p.get(i)? {
        Prop::Str(s) => Some(s.replace("\0\u{1}", "::")),
        _ => None,
    }
}

/// `Properties70` `P` records: name → value.
fn props70(b: &[u8], node: &FbxNode, wide: bool) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for p70 in fbx_children(b, node.children.0, node.children.1, wide).into_iter().filter(|c| c.name == "Properties70")
    {
        for p in fbx_children(b, p70.children.0, p70.children.1, wide).into_iter().filter(|c| c.name == "P").take(1000)
        {
            let Some(name) = prop_str(&p.props, 0) else { continue };
            let v = match p.props.get(4) {
                Some(Prop::Str(s)) => Value::String(truncate_chars(s, 200)),
                Some(Prop::Int(i)) => Value::from(*i),
                Some(Prop::Float(f)) => num(*f, 6),
                _ => continue,
            };
            out.insert(name, v);
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // header, then one block per top-level node
fn fbx_binary(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let version = u32::from_le_bytes(
        b.get(23..27).and_then(|s| s.try_into().ok()).ok_or_else(|| ExtractError::malformed("FBX header"))?,
    );
    cx.format_set("encoding", "binary");
    cx.format_set("fbx_version", format!("{}.{}", version / 1000, version % 1000 / 100));
    let wide = version >= 7500;
    let top = fbx_children(b, 27, b.len(), wide);
    let mut app = Map::new();
    for n in &top {
        match n.name.as_str() {
            "FBXHeaderExtension" => {
                for c in fbx_children(b, n.children.0, n.children.1, wide) {
                    match c.name.as_str() {
                        "Creator" => {
                            if let Some(s) = prop_str(&c.props, 0) {
                                cx.format_set("creator", truncate_chars(&s, 200));
                            }
                        }
                        "CreationTimeStamp" => {
                            let mut t: BTreeMap<String, i64> = BTreeMap::new();
                            for f in fbx_children(b, c.children.0, c.children.1, wide) {
                                if let Some(Prop::Int(v)) = f.props.first() {
                                    t.insert(f.name.clone(), *v);
                                }
                            }
                            let g = |k: &str| t.get(k).copied().unwrap_or(0);
                            if g("Year") > 0 {
                                let s = format!(
                                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                                    g("Year"),
                                    g("Month"),
                                    g("Day"),
                                    g("Hour"),
                                    g("Minute"),
                                    g("Second")
                                );
                                cx.format_set("created", s.clone());
                                cx.temporal().source("fbx.CreationTimeStamp").content_date(
                                    DateField::Created,
                                    s,
                                    false,
                                );
                            }
                        }
                        "SceneInfo" => {
                            for (k, v) in props70(b, &c, wide) {
                                if k.starts_with("Original|") || k.starts_with("LastSaved|") || k == "DocumentUrl" {
                                    if k == "DocumentUrl" || k.ends_with("FileName") {
                                        continue; // paths on the author's machine
                                    }
                                    app.insert(k, v);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            "Creator" => {
                if let Some(s) = prop_str(&n.props, 0) {
                    cx.format_set("creator", truncate_chars(&s, 200));
                }
            }
            "GlobalSettings" => {
                let p = props70(b, n, wide);
                for (k, out) in [
                    ("UpAxis", "up_axis"),
                    ("FrontAxis", "front_axis"),
                    ("UnitScaleFactor", "unit_scale_cm"),
                    ("OriginalUpAxis", "original_up_axis"),
                ] {
                    if let Some(v) = p.get(k) {
                        cx.format_set(out, v.clone());
                    }
                }
            }
            "Objects" => {
                let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
                let (mut vertices, mut embedded, mut external) = (0u64, 0u64, Vec::new());
                for o in fbx_children(b, n.children.0, n.children.1, wide) {
                    // `Model` / `Geometry` carry a class in their third property.
                    let class = prop_str(&o.props, 2).unwrap_or_default();
                    let key = if class.is_empty() { o.name.clone() } else { format!("{}:{class}", o.name) };
                    bump(&mut kinds, &key, 100);
                    match o.name.as_str() {
                        "Geometry" => {
                            for g in fbx_children(b, o.children.0, o.children.1, wide) {
                                if let ("Vertices", Some(Prop::Array(n))) = (g.name.as_str(), g.props.first()) {
                                    vertices += (*n / 3) as u64;
                                }
                            }
                        }
                        "Video" => {
                            for g in fbx_children(b, o.children.0, o.children.1, wide) {
                                match (g.name.as_str(), g.props.first()) {
                                    ("Content", Some(Prop::Raw(n))) if *n > 0 => embedded += 1,
                                    ("RelativeFilename", Some(Prop::Str(s)))
                                        if !s.is_empty() && external.len() < 100 =>
                                    {
                                        external.push(truncate_chars(s.rsplit(['/', '\\']).next().unwrap_or(s), 100));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                cx.format_set("objects", hist(kinds));
                cx.format_set("vertices", vertices);
                cx.format_set("embedded_media", embedded);
                if !external.is_empty() {
                    cx.format_set("external_media", external);
                }
            }
            _ => {}
        }
    }
    if !app.is_empty() {
        cx.format_set("application", Value::Object(app));
    }
    cx.format_set("top_level_nodes", top.iter().map(|n| n.name.clone()).take(40).collect::<Vec<_>>());
    Ok(())
}

fn fbx_ascii(cx: &mut Context<'_>, text: &str) {
    cx.format_set("encoding", "ascii");
    if let Some(v) = text.lines().next().and_then(|l| l.split("FBX ").nth(1)).and_then(|r| r.split_whitespace().next())
    {
        cx.format_set("fbx_version", truncate_chars(v, 10));
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut in_objects = false;
    for line in text.lines().take(50_000_000) {
        if line.starts_with("Objects:") {
            in_objects = true;
            continue;
        }
        if in_objects && line.starts_with('}') {
            in_objects = false;
        }
        let t = line.trim_start();
        if let Some(c) = t.strip_prefix("Creator: ") {
            cx.format_set("creator", truncate_chars(c.trim_matches('"'), 200));
        }
        // Objects' direct children are indented by one tab.
        if in_objects
            && line.starts_with('\t')
            && !line.starts_with("\t\t")
            && let Some((name, _)) = t.split_once(':')
        {
            bump(&mut kinds, name, 100);
        }
    }
    cx.format_set("objects", hist(kinds));
}

// ---------------------------------------------------------------- Blender

fn blend_id(code: &str) -> Option<&'static str> {
    Some(match code {
        "OB" => "objects",
        "ME" => "meshes",
        "MA" => "materials",
        "SC" => "scenes",
        "CA" => "cameras",
        "LA" => "lights",
        "IM" => "images",
        "TE" => "textures",
        "AC" => "actions",
        "GR" => "collections",
        "WO" => "worlds",
        "NT" => "node_trees",
        "BR" => "brushes",
        "LI" => "libraries",
        "CU" => "curves",
        "AR" => "armatures",
        "TX" => "texts",
        "SO" => "sounds",
        "MC" => "movie_clips",
        "KE" => "shape_keys",
        "WS" => "workspaces",
        "SN" => "screens",
        "WM" => "window_managers",
        "PA" => "particle_settings",
        "GD" | "GP" => "grease_pencils",
        "LT" => "lattices",
        "MB" => "metaballs",
        "VF" => "fonts",
        "PC" => "paint_curves",
        "PL" => "palettes",
        "LS" => "line_styles",
        "CF" => "cache_files",
        "LP" => "light_probes",
        "SP" => "speakers",
        "VO" => "volumes",
        "PT" => "point_clouds",
        "CV" => "curves_new",
        _ => return None,
    })
}

fn blend(cx: &mut Context<'_>, raw: &[u8]) -> Result<(), ExtractError> {
    let limit = cx.parse_limit();
    let inflated;
    let b: &[u8] = match raw {
        [0x28, 0xb5, 0x2f, 0xfd, ..] => {
            cx.format_set("compression", "zstd");
            inflated = cx.decompress(raw, Codec::Zstd, limit)?.data;
            &inflated
        }
        [0x1f, 0x8b, ..] => {
            cx.format_set("compression", "gzip");
            inflated = cx.decompress(raw, Codec::Gzip, limit)?.data;
            &inflated
        }
        _ => {
            cx.format_set("compression", "none");
            raw
        }
    };
    if !b.starts_with(b"BLENDER") || b.len() < 12 {
        return Err(ExtractError::malformed("Blender header"));
    }
    // 4.x and earlier: BLENDER_v403 (12 bytes); 5.0: BLENDER17-01v0500.
    let (ptr, little, version, mut at, large) = if b[7].is_ascii_digit() {
        let hs = std::str::from_utf8(&b[7..9])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| ExtractError::malformed("Blender header"))?;
        let v = std::str::from_utf8(b.get(13..17).unwrap_or_default()).unwrap_or("").to_string();
        (8usize, b.get(12) == Some(&b'v'), v, hs, true)
    } else {
        let ptr = if b[7] == b'-' { 8 } else { 4 };
        (ptr, b[8] == b'v', String::from_utf8_lossy(&b[9..12]).into_owned(), 12usize, false)
    };
    let v: u32 = version.parse().unwrap_or(0);
    cx.format_set("blender_version", format!("{}.{}", v / 100, v % 100));
    cx.format_set("pointer_size", ptr);
    cx.format_set("byte_order", if little { "little-endian" } else { "big-endian" });
    let i32_at = |i: usize| -> Option<i64> {
        let r: [u8; 4] = b.get(i..i + 4)?.try_into().ok()?;
        Some(i64::from(if little { i32::from_le_bytes(r) } else { i32::from_be_bytes(r) }))
    };
    let i64_at = |i: usize| -> Option<i64> {
        let r: [u8; 8] = b.get(i..i + 8)?.try_into().ok()?;
        Some(if little { i64::from_le_bytes(r) } else { i64::from_be_bytes(r) })
    };
    let mut ids: BTreeMap<String, u64> = BTreeMap::new();
    let (mut blocks, mut thumbnail) = (0u64, None);
    while at + 8 <= b.len() && blocks < 10_000_000 {
        let code = &b[at..at + 4];
        // BHead: code, len, old pointer, SDNA index, count (5.0: code,
        // SDNA, old, len, count, all 64-bit but the first two).
        let (len, head) = if large { (i64_at(at + 16), 32) } else { (i32_at(at + 4), 16 + ptr) };
        let Some(len) = len.and_then(|l| usize::try_from(l).ok()) else { break };
        blocks += 1;
        if code == b"ENDB" {
            break;
        }
        if code == b"TEST" && thumbnail.is_none() {
            let d = at + head;
            if let (Some(w), Some(h)) = (i32_at(d), i32_at(d + 4)) {
                thumbnail = Some(format!("{w}x{h}"));
            }
        }
        if code[2] == 0 && code[3] == 0 {
            let id = String::from_utf8_lossy(&code[..2]).into_owned();
            let key = blend_id(&id).map_or_else(|| id.clone(), str::to_string);
            bump(&mut ids, &key, 60);
        }
        let Some(next) = at.checked_add(head).and_then(|x| x.checked_add(len)) else { break };
        at = next;
    }
    cx.format_set("blocks", blocks);
    cx.format_set("data_blocks", hist(ids));
    if let Some(t) = thumbnail {
        cx.format_set("thumbnail", t);
    }
    Ok(())
}

// ---------------------------------------------------------------- USD

fn usda(cx: &mut Context<'_>, text: &str) {
    if let Some(v) = text.lines().next().and_then(|l| l.strip_prefix("#usda ")) {
        cx.format_set("usda_version", truncate_chars(v.trim(), 10));
    }
    // The layer's metadata: the parenthesised block after the header.
    let body = text.split_once('\n').map_or("", |x| x.1).trim_start();
    if let Some(meta) = body.strip_prefix('(').and_then(|r| r.split("\n)").next()) {
        let mut m = Map::new();
        for line in meta.lines().take(200) {
            let t = line.trim();
            if let Some((k, v)) = t.split_once('=') {
                let k = k.trim().rsplit(' ').next().unwrap_or("").to_string();
                let v = v.trim().trim_matches('"');
                if matches!(
                    k.as_str(),
                    "defaultPrim"
                        | "metersPerUnit"
                        | "upAxis"
                        | "startTimeCode"
                        | "endTimeCode"
                        | "framesPerSecond"
                        | "timeCodesPerSecond"
                        | "doc"
                        | "creator"
                        | "kilogramsPerUnit"
                ) {
                    m.insert(k, truncate_chars(v, 300).into());
                }
            } else if t.starts_with('"') && !t.contains('=') && m.get("doc").is_none() {
                m.insert("doc".into(), truncate_chars(t.trim_matches('"'), 300).into());
            }
        }
        if let Some(d) = m.get("doc").and_then(Value::as_str) {
            cx.content().source("usd.doc").description(d.to_string());
        }
        cx.format_set("layer_metadata", Value::Object(m));
    }
    let mut prims: BTreeMap<String, u64> = BTreeMap::new();
    let mut assets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut count = 0u64;
    for line in text.lines().take(50_000_000) {
        let t = line.trim_start();
        let mut w = t.split_whitespace();
        if let Some(spec @ ("def" | "over" | "class")) = w.next() {
            count += 1;
            let kind =
                w.next().filter(|k| !k.starts_with('"')).unwrap_or(if spec == "def" { "(untyped)" } else { spec });
            bump(&mut prims, kind, 100);
        }
        for a in t.split('@').skip(1).step_by(2).take(10) {
            if !a.is_empty() && assets.len() < 200 {
                assets.insert(truncate_chars(a, 200));
            }
        }
    }
    cx.format_set("prims", count);
    cx.format_set("prim_types", hist(prims));
    if !assets.is_empty() {
        cx.format_set("asset_paths", assets.into_iter().collect::<Vec<_>>());
    }
}

fn usdc(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("USDC header");
    let v = b.get(8..11).ok_or_else(bad)?;
    cx.format_set("crate_version", format!("{}.{}.{}", v[0], v[1], v[2]));
    let toc = usize::try_from(u64::from_le_bytes(b.get(16..24).ok_or_else(bad)?.try_into().map_err(|_| bad())?))
        .map_err(|_| bad())?;
    let n = u64::from_le_bytes(b.get(toc..toc + 8).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    let mut sections = Map::new();
    for i in 0..usize::try_from(n.min(64)).unwrap_or(0) {
        let at = toc + 8 + i * 32;
        let Some(s) = b.get(at..at + 32) else { break };
        let name = String::from_utf8_lossy(&s[..16]).trim_end_matches('\0').to_string();
        let size = u64::from_le_bytes(s[24..32].try_into().unwrap_or_default());
        sections.insert(truncate_chars(&name, 16), size.into());
    }
    cx.format_set("sections", Value::Object(sections));
    Ok(())
}

/// Whether a file name is a USD layer (`.usd`, `.usda`, `.usdc`).
fn usd_layer(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ["usd", "usda", "usdc"].iter().any(|x| e.eq_ignore_ascii_case(x)))
}

fn usdz(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let names: Vec<String> = zip.entries.iter().map(|e| e.name.clone()).collect();
    cx.format_set("entries", names.len());
    let layers: Vec<&String> = names.iter().filter(|n| usd_layer(n)).collect();
    cx.format_set("layers", layers.iter().map(|n| truncate_chars(n, 100)).collect::<Vec<_>>());
    let images = names
        .iter()
        .filter(|n| {
            n.to_ascii_lowercase().ends_with(".png")
                || n.to_ascii_lowercase().ends_with(".jpg")
                || n.to_ascii_lowercase().ends_with(".jpeg")
        })
        .count();
    cx.format_set("images", images);
    // The first file is the root layer.
    let Some(first) = zip.entries.first().cloned() else { return Ok(()) };
    cx.format_set("root_layer", truncate_chars(&first.name, 100));
    let limit = cx.parse_limit();
    let data = zip.read(src, &first, cx, limit)?;
    if data.starts_with(b"PXR-USDC") {
        usdc(cx, &data)?;
    } else if data.starts_with(b"#usda") {
        usda(cx, &String::from_utf8_lossy(&data));
    }
    Ok(())
}

// ---------------------------------------------------------------- 3DS

#[derive(Default)]
struct Max3ds {
    version: Option<u32>,
    objects: Vec<String>,
    vertices: u64,
    faces: u64,
    materials: Vec<String>,
    cameras: u64,
    lights: u64,
    bounds: Box3,
}

fn walk_3ds(b: &[u8], start: usize, end: usize, depth: usize, s: &mut Max3ds) {
    let mut at = start;
    while at + 6 <= end && depth < 16 {
        let id = u16::from_le_bytes([b[at], b[at + 1]]);
        let len = u32::from_le_bytes([b[at + 2], b[at + 3], b[at + 4], b[at + 5]]) as usize;
        if len < 6 || at + len > end {
            break;
        }
        let body = at + 6;
        let stop = at + len;
        let cstr = |p: usize| {
            let e = b[p..stop].iter().position(|&c| c == 0).map_or(stop, |i| p + i);
            (String::from_utf8_lossy(&b[p..e]).into_owned(), e + 1)
        };
        match id {
            0x4D4D | 0x3D3D | 0x4100 | 0xB000 | 0xAFFF => walk_3ds(b, body, stop, depth + 1, s),
            0x0002 if stop - body >= 4 => {
                s.version = Some(u32::from_le_bytes([b[body], b[body + 1], b[body + 2], b[body + 3]]));
            }
            0x4000 => {
                let (name, next) = cstr(body);
                if s.objects.len() < 500 {
                    s.objects.push(truncate_chars(&name, 60));
                }
                walk_3ds(b, next, stop, depth + 1, s);
            }
            0x4110 if stop - body >= 2 => {
                let n = usize::from(u16::from_le_bytes([b[body], b[body + 1]]));
                s.vertices += n as u64;
                for v in b[body + 2..stop].as_chunks::<12>().0.iter().take(n) {
                    let f = |i: usize| f64::from(f32::from_le_bytes([v[i], v[i + 1], v[i + 2], v[i + 3]]));
                    s.bounds.add([f(0), f(4), f(8)]);
                }
            }
            0x4120 if stop - body >= 2 => s.faces += u64::from(u16::from_le_bytes([b[body], b[body + 1]])),
            0x4700 => s.cameras += 1,
            0x4600 => s.lights += 1,
            0xA000 if s.materials.len() < 500 => {
                s.materials.push(truncate_chars(&cstr(body).0, 60));
            }
            _ => {}
        }
        at = stop;
    }
}

fn max3ds(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    if b.get(..2) != Some(&[0x4D, 0x4D]) {
        return Err(ExtractError::malformed("3DS main chunk"));
    }
    let mut s = Max3ds::default();
    walk_3ds(b, 0, b.len(), 0, &mut s);
    if let Some(v) = s.version {
        cx.format_set("version", v);
    }
    cx.format_set("objects", s.objects);
    cx.format_set("vertices", s.vertices);
    cx.format_set("faces", s.faces);
    cx.format_set("materials", s.materials);
    cx.format_set("cameras", s.cameras);
    cx.format_set("lights", s.lights);
    s.bounds.report(cx, "bounds");
    Ok(())
}

// ---------------------------------------------------------------- VOX

fn vox(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let u32_at = |i: usize| b.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    cx.format_set("vox_version", u32_at(4).ok_or_else(|| ExtractError::malformed("VOX header"))?);
    let (mut sizes, mut voxels, mut palette) = (Vec::new(), 0u64, false);
    let mut chunks: BTreeMap<String, u64> = BTreeMap::new();
    // MAIN's children follow its 12-byte header.
    let mut at = 8 + 12;
    while at + 12 <= b.len() && chunks.values().sum::<u64>() < 1_000_000 {
        let id = String::from_utf8_lossy(&b[at..at + 4]).into_owned();
        let (Some(n), Some(m)) = (u32_at(at + 4), u32_at(at + 8)) else { break };
        let body = at + 12;
        bump(&mut chunks, &id, 40);
        match id.as_str() {
            "SIZE" if sizes.len() < 1000 => {
                if let (Some(x), Some(y), Some(z)) = (u32_at(body), u32_at(body + 4), u32_at(body + 8)) {
                    sizes.push(format!("{x}x{y}x{z}"));
                }
            }
            "XYZI" => voxels += u64::from(u32_at(body).unwrap_or(0)),
            "RGBA" => palette = true,
            _ => {}
        }
        let Some(next) = body.checked_add(n as usize).and_then(|x| x.checked_add(m as usize)) else { break };
        at = next;
    }
    cx.format_set("models", sizes.len());
    cx.format_set("model_sizes", sizes);
    cx.format_set("voxels", voxels);
    cx.format_set("custom_palette", palette);
    cx.format_set("chunks", hist(chunks));
    Ok(())
}

// ---------------------------------------------------------------- OpenVDB

fn vdb(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("VDB header");
    let u32_at = |i: usize| b.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    let file_version = u32_at(8).ok_or_else(bad)?;
    cx.format_set("file_version", file_version);
    cx.format_set("library_version", format!("{}.{}", u32_at(12).ok_or_else(bad)?, u32_at(16).ok_or_else(bad)?));
    let offsets = *b.get(20).ok_or_else(bad)? != 0;
    let mut at = 21;
    if file_version >= 220 {
        at += 36; // the UUID, as text
    }
    let string = |at: &mut usize| -> Option<String> {
        let n = u32_at(*at)? as usize;
        let s = String::from_utf8_lossy(b.get(*at + 4..*at + 4 + n)?).into_owned();
        *at += 4 + n;
        Some(s)
    };
    let mut meta = Map::new();
    let n = u32_at(at).ok_or_else(bad)?;
    at += 4;
    for _ in 0..n.min(1000) {
        let (Some(name), Some(kind)) = (string(&mut at), string(&mut at)) else { break };
        let size = u32_at(at).ok_or_else(bad)? as usize;
        let v = b.get(at + 4..at + 4 + size).ok_or_else(bad)?;
        at += 4 + size;
        let value: Value = match kind.as_str() {
            "string" => truncate_chars(&String::from_utf8_lossy(v), 200).into(),
            "int32" if v.len() == 4 => i32::from_le_bytes([v[0], v[1], v[2], v[3]]).into(),
            "float" if v.len() == 4 => num(f64::from(f32::from_le_bytes([v[0], v[1], v[2], v[3]])), 6),
            "bool" => (v.first() == Some(&1)).into(),
            _ => kind.into(),
        };
        meta.insert(truncate_chars(&name, 60), value);
    }
    if !meta.is_empty() {
        cx.format_set("metadata", Value::Object(meta));
    }
    if !offsets {
        return Ok(());
    }
    let grids = u32_at(at).ok_or_else(bad)?;
    at += 4;
    let mut list = Vec::new();
    for _ in 0..grids.min(1000) {
        let (Some(name), Some(kind)) = (string(&mut at), string(&mut at)) else { break };
        if file_version >= 216 && string(&mut at).is_none() {
            break; // instance parent
        }
        // Grid, block and end positions: the next descriptor is at the end.
        let end = b
            .get(at + 16..at + 24)
            .and_then(|s| s.try_into().ok())
            .map(i64::from_le_bytes)
            .and_then(|e| usize::try_from(e).ok());
        let Some(end) = end.filter(|&e| e > at) else { break };
        at = end;
        list.push(format!(
            "{} ({})",
            truncate_chars(name.split('\u{1e}').next().unwrap_or(&name), 60),
            truncate_chars(&kind, 40)
        ));
    }
    cx.format_set("grid_count", grids);
    cx.format_set("grids", list);
    Ok(())
}

// ---------------------------------------------------------------- BVH

fn bvh(cx: &mut Context<'_>, text: &str) {
    let (mut joints, mut ends, mut channels) = (0u64, 0u64, 0u64);
    let mut root = None;
    let (mut frames, mut frame_time) = (None, None);
    for line in text.lines().take(10_000_000) {
        let t = line.trim();
        let mut w = t.split_whitespace();
        match w.next() {
            Some("ROOT") => {
                joints += 1;
                root.get_or_insert_with(|| truncate_chars(w.next().unwrap_or(""), 60));
            }
            Some("JOINT") => joints += 1,
            Some("End") => ends += 1,
            Some("CHANNELS") => channels += w.next().and_then(|n| n.parse::<u64>().ok()).unwrap_or(0),
            Some("Frames:") => frames = w.next().and_then(|n| n.parse::<u64>().ok()),
            Some("Frame") => frame_time = t.split(':').nth(1).and_then(|n| n.trim().parse::<f64>().ok()),
            Some("MOTION") if frames.is_some() => break,
            _ => {}
        }
        if frames.is_some() && frame_time.is_some() {
            break;
        }
    }
    if let Some(r) = root {
        cx.format_set("root", r);
    }
    cx.format_set("joints", joints);
    cx.format_set("end_sites", ends);
    cx.format_set("channels", channels);
    if let Some(f) = frames {
        cx.format_set("frames", f);
    }
    if let Some(t) = frame_time.filter(|t| *t > 0.0) {
        cx.format_set("frame_time", num(t, 6));
        cx.format_set("frame_rate", num(1.0 / t, 3));
        if let Some(f) = frames {
            cx.format_set("duration_s", num(f as f64 * t, 3));
        }
    }
}

// ---------------------------------------------------------------- C3D

/// C3D numbers by processor: 84 Intel, 85 DEC, 86 MIPS (big-endian).
struct C3d {
    big: bool,
    dec: bool,
}

impl C3d {
    fn u16(&self, b: &[u8], at: usize) -> Option<u16> {
        let r = [*b.get(at)?, *b.get(at + 1)?];
        Some(if self.big { u16::from_be_bytes(r) } else { u16::from_le_bytes(r) })
    }
    fn i16(&self, b: &[u8], at: usize) -> Option<i16> {
        self.u16(b, at).map(u16::cast_signed)
    }
    fn f32(&self, b: &[u8], at: usize) -> Option<f64> {
        let r: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.dec {
            // DEC (VAX F): swapped 16-bit halves, exponent bias 2 higher.
            f64::from(f32::from_le_bytes([r[2], r[3], r[0], r[1]])) / 4.0
        } else if self.big {
            f64::from(f32::from_be_bytes(r))
        } else {
            f64::from(f32::from_le_bytes(r))
        })
    }
}

#[allow(clippy::too_many_lines)] // the header, then the parameter section
fn c3d(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("C3D header");
    let pblock = usize::from(*b.first().ok_or_else(bad)?);
    if b.get(1) != Some(&0x50) || pblock == 0 {
        return Err(bad());
    }
    let p = (pblock - 1) * 512;
    let proc_type = *b.get(p + 3).ok_or_else(bad)?;
    let c = C3d { big: proc_type == 86, dec: proc_type == 85 };
    cx.format_set(
        "processor",
        match proc_type {
            84 => "Intel",
            85 => "DEC",
            86 => "MIPS",
            _ => "unknown",
        },
    );
    let points = c.u16(b, 2).ok_or_else(bad)?;
    let analog = c.u16(b, 4).ok_or_else(bad)?;
    let first = c.u16(b, 6).ok_or_else(bad)?;
    let last = c.u16(b, 8).ok_or_else(bad)?;
    let rate = c.f32(b, 20).ok_or_else(bad)?;
    cx.format_set("points", points);
    cx.format_set("analog_samples_per_frame", analog);
    let frames = u64::from(last.saturating_sub(first)) + 1;
    cx.format_set("frames", frames);
    if rate.is_finite() && rate > 0.0 {
        cx.format_set("frame_rate", num(rate, 3));
        cx.format_set("duration_s", num(frames as f64 / rate, 3));
    }
    // Parameters: groups (negative IDs) and their parameters.
    let mut groups: BTreeMap<i8, String> = BTreeMap::new();
    let mut params: BTreeMap<String, Value> = BTreeMap::new();
    let mut at = p + 4;
    for _ in 0..10_000 {
        let Some(&nl) = b.get(at) else { break };
        let len = usize::from(nl.cast_signed().unsigned_abs());
        if len == 0 {
            break;
        }
        let gid = b.get(at + 1).copied().ok_or_else(bad)?.cast_signed();
        let name = String::from_utf8_lossy(b.get(at + 2..at + 2 + len).ok_or_else(bad)?).trim().to_string();
        let off_at = at + 2 + len;
        let next = c.i16(b, off_at).ok_or_else(bad)?;
        if gid < 0 {
            groups.insert(-gid, name);
        } else {
            let d = off_at + 2;
            let dtype = b.get(d).copied().unwrap_or(0).cast_signed();
            let ndims = usize::from(b.get(d + 1).copied().unwrap_or(0));
            let dims: Vec<usize> = (0..ndims).map(|i| usize::from(b.get(d + 2 + i).copied().unwrap_or(0))).collect();
            let data = d + 2 + ndims;
            let key = format!("{}:{name}", groups.get(&gid).cloned().unwrap_or_else(|| gid.to_string()));
            let value = match (dtype, ndims) {
                (-1, 2) => {
                    let (w, n) = (dims[0], dims[1]);
                    let items: Vec<String> = (0..n.min(200))
                        .filter_map(|i| b.get(data + i * w..data + (i + 1) * w))
                        .map(|s| String::from_utf8_lossy(s).trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    Some(Value::from(items))
                }
                (-1, _) => {
                    let n = dims.first().copied().unwrap_or(0);
                    b.get(data..data + n).map(|s| Value::from(String::from_utf8_lossy(s).trim().to_string()))
                }
                (2, 0) => c.i16(b, data).map(Value::from),
                (4, 0) => c.f32(b, data).map(|f| num(f, 6)),
                _ => None,
            };
            if let Some(v) = value {
                params.insert(key, v);
            }
        }
        if next <= 0 {
            break;
        }
        at = off_at + usize::from(next.unsigned_abs());
    }
    cx.format_set("groups", groups.values().cloned().collect::<Vec<_>>());
    for (k, out) in [
        ("POINT:LABELS", "point_labels"),
        ("POINT:UNITS", "point_units"),
        ("ANALOG:LABELS", "analog_labels"),
        ("MANUFACTURER:COMPANY", "manufacturer"),
        ("MANUFACTURER:SOFTWARE", "software"),
        ("MANUFACTURER:VERSION_LABEL", "software_version"),
        ("TRIAL:CAMERA_RATE", "camera_rate"),
    ] {
        if let Some(v) = params.get(k) {
            cx.format_set(out, v.clone());
        }
    }
    // Subjects are people: their names only with privacy off.
    if !cx.privacy_strict()
        && let Some(v) = params.get("SUBJECTS:NAMES")
    {
        cx.format_set("subjects", v.clone());
    }
    Ok(())
}

// ---------------------------------------------------------------- photometry

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // counts written as decimals
fn ies(cx: &mut Context<'_>, text: &str) {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").trim();
    cx.format_set("standard", truncate_chars(first, 40));
    let mut keywords = Map::new();
    let mut rest = String::new();
    let mut tilt = None;
    for line in lines.by_ref() {
        let t = line.trim();
        if let Some(r) = t.strip_prefix('[') {
            let (k, v) = r.split_once(']').unwrap_or((r, ""));
            if keywords.len() < 40 {
                keywords.insert(truncate_chars(k, 30), truncate_chars(v.trim(), 200).into());
            }
        } else if let Some(v) = t.strip_prefix("TILT=") {
            tilt = Some(v.trim().to_string());
            break;
        }
    }
    for line in lines.take(100_000) {
        rest.push_str(line);
        rest.push(' ');
    }
    let mut nums = rest.split([' ', ',', '\t']).filter_map(|x| x.trim().parse::<f64>().ok());
    if tilt.as_deref() == Some("INCLUDE") {
        let _geometry = nums.next();
        let n = nums.next().unwrap_or(0.0) as usize;
        for _ in 0..2 * n.min(10_000) {
            nums.next();
        }
    }
    let v: Vec<f64> = nums.by_ref().take(13).collect();
    for (k, out) in [
        ("MANUFAC", "manufacturer"),
        ("LUMINAIRE", "luminaire"),
        ("LUMCAT", "catalogue"),
        ("LAMP", "lamp"),
        ("TEST", "test"),
        ("ISSUEDATE", "issue_date"),
    ] {
        if let Some(s) = keywords.get(k).and_then(Value::as_str) {
            cx.format_set(out, s.to_string());
        }
    }
    if let Some(l) = keywords.get("LUMINAIRE").and_then(Value::as_str) {
        cx.content().source("ies.LUMINAIRE").title(l.to_string());
    }
    cx.format_set("keywords", Value::Object(keywords));
    if let Some(t) = tilt {
        cx.format_set("tilt", truncate_chars(&t, 60));
    }
    if v.len() == 13 {
        cx.format_set("lamps", num(v[0], 0));
        if v[1] > 0.0 {
            cx.format_set("lumens_per_lamp", num(v[1], 1));
        }
        cx.format_set("vertical_angles", num(v[3], 0));
        cx.format_set("horizontal_angles", num(v[4], 0));
        cx.format_set(
            "photometric_type",
            match v[5] as i64 {
                1 => "C",
                2 => "B",
                3 => "A",
                _ => "unknown",
            },
        );
        let unit = if v[6] as i64 == 1 { "feet" } else { "meters" };
        cx.format_set("dimensions", Value::Array(vec![num(v[7], 3), num(v[8], 3), num(v[9], 3)]));
        cx.format_set("dimension_unit", unit);
        cx.format_set("input_watts", num(v[12], 2));
        // Candela values follow the angle lists.
        let (nv, nh) = (v[3].max(0.0) as usize, v[4].max(0.0) as usize);
        let candela: Vec<f64> = nums.skip(nv + nh).take(nv.saturating_mul(nh).min(10_000_000)).collect();
        if let Some(max) = candela.iter().copied().reduce(f64::max) {
            cx.format_set("max_candela", num(max * v[2], 1));
        }
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // counts written as decimals
fn ldt(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let l: Vec<&str> = text.lines().map(str::trim).collect();
    if l.len() < 26 {
        return Err(ExtractError::malformed("EULUMDAT: too few lines"));
    }
    let s = |i: usize| truncate_chars(l.get(i).copied().unwrap_or(""), 200);
    let f = |i: usize| l.get(i).and_then(|x| x.parse::<f64>().ok());
    cx.format_set("manufacturer", s(0));
    cx.format_set("luminaire", s(8));
    cx.format_set("luminaire_number", s(9));
    cx.format_set("measurement_report", s(7));
    cx.format_set("date_user", s(11));
    if !s(8).is_empty() {
        cx.content().source("ldt.luminaire").title(s(8));
    }
    cx.format_set("c_planes", f(3).map_or(Value::Null, |v| num(v, 0)));
    cx.format_set("gamma_angles", f(5).map_or(Value::Null, |v| num(v, 0)));
    cx.format_set(
        "dimensions_mm",
        Value::Array([12, 13, 14].iter().map(|&i| f(i).map_or(Value::Null, |v| num(v, 1))).collect()),
    );
    let sets = f(25).unwrap_or(0.0).max(0.0) as usize;
    let mut lamps = Vec::new();
    for k in 0..sets.min(20) {
        let g = |field: usize| l.get(26 + field * sets + k).copied().unwrap_or("");
        let mut m = Map::new();
        m.insert("count".into(), g(0).into());
        m.insert("type".into(), truncate_chars(g(1), 100).into());
        m.insert("flux_lm".into(), g(2).into());
        m.insert("colour".into(), truncate_chars(g(3), 40).into());
        m.insert("watts".into(), g(5).into());
        lamps.push(Value::Object(m));
    }
    cx.format_set("lamp_sets", lamps);
    Ok(())
}

// ---------------------------------------------------------------- LDraw

fn ldraw(cx: &mut Context<'_>, text: &str) {
    let mut files = Vec::new();
    let mut parts: BTreeMap<String, u64> = BTreeMap::new();
    let mut colours = std::collections::BTreeSet::new();
    let mut prims: BTreeMap<String, u64> = BTreeMap::new();
    let (mut refs, mut title, mut author) = (0u64, None, None);
    for (i, line) in text.lines().take(10_000_000).enumerate() {
        let t = line.trim();
        let mut w = t.split_whitespace();
        match w.next() {
            Some("0") => {
                let rest = t[1..].trim();
                if let Some(f) = rest.strip_prefix("FILE ") {
                    if files.len() < 500 {
                        files.push(truncate_chars(f.trim(), 100));
                    }
                } else if let Some(n) = rest.strip_prefix("Name:") {
                    cx.format_set("name", truncate_chars(n.trim(), 100));
                } else if let Some(a) = rest.strip_prefix("Author:") {
                    author.get_or_insert_with(|| truncate_chars(a.trim(), 100));
                } else if let Some(l) = rest.strip_prefix("!LICENSE") {
                    cx.rights().source("ldraw.!LICENSE").license(Some(&truncate_chars(l.trim(), 200)), None);
                } else if let Some(o) = rest.strip_prefix("!LDRAW_ORG") {
                    cx.format_set("ldraw_org", truncate_chars(o.trim(), 100));
                } else if (i == 0 || files.len() == 1 && title.is_none())
                    && !rest.starts_with('!')
                    && !rest.is_empty()
                    && title.is_none()
                    && !rest.starts_with("FILE")
                {
                    title = Some(truncate_chars(rest, 200));
                }
            }
            Some("1") => {
                refs += 1;
                let f: Vec<&str> = w.collect();
                if let Some(c) = f.first() {
                    colours.insert((*c).to_string());
                }
                if let Some(p) = f.get(13) {
                    bump(&mut parts, &p.to_ascii_lowercase(), 2000);
                }
            }
            Some(k @ ("2" | "3" | "4" | "5")) => {
                let name = match k {
                    "2" => "lines",
                    "3" => "triangles",
                    "4" => "quads",
                    _ => "optional_lines",
                };
                *prims.entry(name.into()).or_default() += 1;
            }
            _ => {}
        }
    }
    if let Some(t) = title {
        cx.format_set("title", t.clone());
        cx.content().source("ldraw.title").title(t);
    }
    if let Some(a) = author {
        cx.content().source("ldraw.Author").author(a);
    }
    if !files.is_empty() {
        cx.format_set("files", files);
    }
    cx.format_set("part_references", refs);
    cx.format_set("distinct_parts", parts.len());
    let mut top: Vec<(String, u64)> = parts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    cx.format_set("top_parts", hist(top.into_iter().take(20).collect()));
    cx.format_set("colours", colours.len());
    cx.format_set("primitives", hist(prims));
}

impl Extractor for Scene {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if h.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 20);
            let first = names.first().map_or("", String::as_str);
            return usd_layer(first).then_some(Sniff { format: "usdz", confidence: 0.97 });
        }
        if h.starts_with(b"Kaydara FBX Binary") {
            return sure("fbx");
        }
        // Blender files: plain, or zstd / gzip compressed with the extension.
        if h.starts_with(b"BLENDER")
            || ext == "blend" && (h.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) || h.starts_with(&[0x1f, 0x8b]))
        {
            return sure("blend");
        }
        if ext == "3ds" && h.starts_with(&[0x4D, 0x4D]) && h.get(6..8) == Some(&[0x02, 0x00]) {
            return sure("3ds");
        }
        if ext == "c3d" && h.get(1) == Some(&0x50) {
            return sure("c3d");
        }
        let text = std::str::from_utf8(&h[..h.len().min(4096)]).ok()?;
        if text.starts_with("; FBX ") && text.contains("FBXHeaderExtension") {
            return sure("fbx");
        }
        let first = text.lines().next().unwrap_or("").trim();
        if first.starts_with("IESNA") || ext == "ies" && text.contains("TILT=") {
            return sure("ies");
        }
        // LDraw: meta commands and type-1 references; MPD files start with FILE.
        let ld = text.lines().take(50).filter(|l| {
            let t = l.trim_start();
            t.starts_with("0 Name:")
                || t.starts_with("0 Author:")
                || t.starts_with("0 FILE ")
                || t.starts_with("0 !LDRAW_ORG")
        });
        if ld.count() >= 1 && (matches!(ext, "ldr" | "mpd" | "dat") || text.starts_with("0 FILE ")) {
            return sure("ldraw");
        }
        (ext == "ldt" && text.lines().count() > 26).then_some(Sniff { format: "ldt", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "usdz" => return usdz(cx, src),
            "usda" | "bvh" | "ies" | "ldt" | "ldraw" => {
                let text = cx.read_text(src)?.text;
                return match id.as_str() {
                    "usda" => {
                        usda(cx, &text);
                        Ok(())
                    }
                    "bvh" => {
                        bvh(cx, &text);
                        Ok(())
                    }
                    "ies" => {
                        ies(cx, &text);
                        Ok(())
                    }
                    "ldt" => ldt(cx, &text),
                    _ => {
                        ldraw(cx, &text);
                        Ok(())
                    }
                };
            }
            _ => {}
        }
        let (b, _) = cx.read_bytes(src)?;
        match id.as_str() {
            "fbx" if b.starts_with(b"Kaydara FBX Binary") => fbx_binary(cx, &b),
            "fbx" => {
                fbx_ascii(cx, &String::from_utf8_lossy(&b));
                Ok(())
            }
            "blend" => blend(cx, &b),
            "usdc" => usdc(cx, &b),
            "3ds" => max3ds(cx, &b),
            "vox" => vox(cx, &b),
            "openvdb" => vdb(cx, &b),
            _ => c3d(cx, &b),
        }
    }
}

crate::register_extractor!(Scene);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fbx_nodes() {
        // A 7400 node "Creator" with one string property, then the null record.
        let name = b"Creator";
        let mut props = vec![b'S'];
        props.extend(3u32.to_le_bytes());
        props.extend(b"abc");
        let end = 13 + name.len() + props.len();
        let mut b = Vec::new();
        b.extend(u32::try_from(end).unwrap().to_le_bytes());
        b.extend(1u32.to_le_bytes());
        b.extend(u32::try_from(props.len()).unwrap().to_le_bytes());
        b.push(u8::try_from(name.len()).unwrap());
        b.extend(name);
        b.extend(&props);
        b.extend([0u8; 13]);
        let kids = fbx_children(&b, 0, b.len(), false);
        assert_eq!(kids.len(), 1);
        assert_eq!((kids[0].name.as_str(), prop_str(&kids[0].props, 0).as_deref()), ("Creator", Some("abc")));
    }

    #[test]
    fn c3d_dec_floats() {
        let c = C3d { big: false, dec: true };
        // 1.0 as DEC F: IEEE 0x40800000 (4.0) with swapped halves.
        assert!((c.f32(&[0x80, 0x40, 0x00, 0x00], 0).unwrap() - 1.0).abs() < 1e-9);
    }

    crate::fixture_tests!(
        "fbx", "blend", "usda", "usdc", "usdz", "3ds", "vox", "openvdb", "bvh", "c3d", "ies", "ldt", "ldraw"
    );
}
