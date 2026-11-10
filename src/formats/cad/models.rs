//! More 3D formats:
//!
//! * Alembic archives (Ogawa or HDF5 back end): version, the application
//!   and Alembic library that wrote them, the write date and the objects
//!   named in the archive;
//! * point clouds: PCL's PCD (fields, size, points, data encoding),
//!   Leica PTS and plain XYZ text (points, columns, bounds);
//! * Maya ASCII scenes (`.ma`): Maya version, `requires` plug-ins, units,
//!   file info, nodes by type, references;
//! * SketchUp models: the version and the embedded thumbnail's size;
//! * MikuMikuDance models (PMX 2.0 / 2.1, PMD): names, comment, vertices,
//!   faces, textures, materials, bones;
//! * Valve models (GoldSrc / Source `.mdl`, StudioMDL `.smd`): name,
//!   version, bones, sequences, textures, skins, body parts, triangles;
//! * Gaussian splats (`.splat`, compressed `.spz`): point count, bounds,
//!   spherical-harmonics degree;
//! * MaterialX documents and Substance Designer packages: version,
//!   materials, node graphs, nodes, inputs.
//!
//! Specifications: Alembic's Ogawa layout; the PCD file format (PCL);
//! Leica's PTS; Autodesk's Maya ASCII syntax; the PMX 2.1 and PMD layouts
//! (as MMD tools read them); Valve's `studiohdr_t` and SMD reference;
//! antimatter15's `.splat` and Niantic's SPZ; the `MaterialX` 1.38
//! specification. The SketchUp and Substance layouts are read as their
//! applications write them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{Box3, bump, hist, num};
use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    xmlwalk,
};

/// Extractor for the 3D formats above.
pub struct Models;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "3d", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.models",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("alembic", "Alembic archive", "application/x-alembic", [], [Magic::prefix(b"Ogawa")]),
        // No `.pcd`: Photo CD's, and the candidates would differ between builds.
        spec!("pcd", "PCD point cloud", "application/x-pcd", [], []),
        spec!("pts_points", "PTS point cloud", "text/x-pts", ["pts"], []),
        spec!("xyz_points", "XYZ point cloud", "text/x-xyz-points", [], []),
        spec!("maya", "Maya ASCII scene", "application/x-maya-ascii", ["ma"], [Magic::prefix(b"//Maya ASCII")]),
        spec!(
            "sketchup",
            "SketchUp model",
            "application/vnd.sketchup.skp",
            ["skp"],
            [Magic::prefix(b"\xff\xfe\xff\x0eS\0k\0e\0t\0c\0h\0U\0p\0")]
        ),
        spec!("pmx", "MikuMikuDance PMX model", "application/x-pmx", ["pmx"], [Magic::prefix(b"PMX ")]),
        spec!("pmd", "MikuMikuDance PMD model", "application/x-pmd", ["pmd"], [Magic::prefix(b"Pmd")]),
        spec!("valve_mdl", "Valve studio model", "application/x-valve-mdl", ["mdl"], [Magic::prefix(b"IDST")]),
        spec!("valve_smd", "Valve StudioMDL data", "text/x-smd", ["smd"], []),
        spec!("gaussian_splat", "Gaussian splat", "application/x-gaussian-splat", ["splat", "spz"], []),
        spec!("materialx", "MaterialX document", "application/x-materialx", ["mtlx"], []),
        spec!("substance", "Substance Designer package", "application/x-substance", ["sbs"], []),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Models {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        if h.starts_with(b"\x89HDF\r\n\x1a\n") && ext == "abc" {
            return pick("alembic", 0.95);
        }
        if ext == "spz" && h.starts_with(b"\x1f\x8b") {
            return pick("gaussian_splat", 0.9);
        }
        let text = String::from_utf8_lossy(&h[..h.len().min(8192)]);
        let t = text.trim_start_matches('\u{feff}').trim_start();
        if t.starts_with("# .PCD") || (t.starts_with("VERSION") && t.contains("\nFIELDS") && t.contains("\nDATA")) {
            return pick("pcd", 0.95);
        }
        if t.contains("<materialx") {
            return pick("materialx", 0.95);
        }
        if t.contains("<package>") && t.contains("<formatVersion") {
            return pick("substance", 0.9);
        }
        if t.starts_with("version 1") && (t.contains("\nnodes") || t.contains("\nskeleton")) {
            return pick("valve_smd", 0.9);
        }
        // XYZ / PTS: rows of numbers (PTS starts with a point count).
        let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).take(50).collect();
        let numeric = |l: &&str| {
            let w: Vec<&str> = l.split([' ', '\t', ',']).filter(|w| !w.is_empty()).collect();
            (3..=10).contains(&w.len()) && w.iter().all(|x| x.parse::<f64>().is_ok())
        };
        if lines.len() >= 3 && lines[1..].iter().all(numeric) {
            let first_count = lines[0].trim().parse::<u64>().is_ok();
            if ext == "pts" && first_count {
                return pick("pts_points", 0.9);
            }
            if ext == "xyz" && !first_count && numeric(&lines[0]) {
                return pick("xyz_points", 0.9);
            }
        }
        if ext == "splat" && probe.len > 0 && probe.len.is_multiple_of(32) {
            return pick("gaussian_splat", 0.8);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        let len = src.len();
        match cx.format_id() {
            "alembic" => alembic(cx, &b),
            "pcd" => pcd(cx, &b),
            "pts_points" | "xyz_points" => points(cx, &String::from_utf8_lossy(&b)),
            "maya" => maya(cx, &String::from_utf8_lossy(&b)),
            "sketchup" => sketchup(cx, &b),
            "pmx" => pmx(cx, &b),
            "pmd" => pmd(cx, &b),
            "valve_mdl" => mdl(cx, &b),
            "valve_smd" => smd(cx, &String::from_utf8_lossy(&b)),
            "gaussian_splat" => splat(cx, &b, len)?,
            "materialx" => materialx(cx, &String::from_utf8_lossy(&b))?,
            _ => substance(cx, &String::from_utf8_lossy(&b))?,
        }
        Ok(())
    }
}

crate::register_extractor!(Models);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn i32le(b: &[u8], at: usize) -> i32 {
    le32(b, at).cast_signed()
}

fn f32le(b: &[u8], at: usize) -> f32 {
    f32::from_bits(le32(b, at))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    crate::plugin::latin1_or_utf8(&b[..end]).trim().to_string()
}

// --- Alembic ----------------------------------------------------------------------------------

fn alembic(cx: &mut Context<'_>, b: &[u8]) {
    if b.starts_with(b"Ogawa") {
        cx.format_set("backend", "Ogawa");
        cx.format_set("frozen", b.get(5) == Some(&0xff));
        cx.format_set("ogawa_version", u32::from(le16(b, 6).swap_bytes()));
    } else {
        cx.format_set("backend", "HDF5");
    }
    // Ogawa data blocks (sized); for HDF5, the whole file.
    let blocks = if b.starts_with(b"Ogawa") { ogawa_blocks(b) } else { vec![b] };
    // Archive metadata: `key=value;key=value` strings with `_ai_` keys.
    let mut meta = BTreeMap::new();
    for block in &blocks {
        let Some(p) = block.windows(4).position(|w| w == b"_ai_") else { continue };
        let end = block[p..].iter().position(|&c| c == 0).map_or(block.len(), |e| p + e);
        for pair in String::from_utf8_lossy(&block[p..end]).split(';') {
            if let Some((k, v)) = pair.split_once('=')
                && k.starts_with("_ai_")
                && meta.len() < 50
            {
                meta.entry(k.trim_start_matches("_ai_").to_string()).or_insert_with(|| v.to_string());
            }
        }
    }
    for (k, key) in [
        ("AlembicVersion", "alembic_version"),
        ("Application", "application"),
        ("DateWritten", "written"),
        ("Description", "description"),
    ] {
        if let Some(v) = meta.get(k) {
            cx.format_set(key, v.clone());
        }
    }
    // Object schemas (`schema=AbcGeom_PolyMesh_v1`) reveal the object kinds.
    let mut schemas: BTreeMap<String, u64> = BTreeMap::new();
    for block in &blocks {
        let mut at = 0;
        while let Some(p) = block[at..].windows(15).position(|w| w == b"schema=AbcGeom_").map(|p| p + at + 15) {
            let end =
                block[p..].iter().position(|c| !c.is_ascii_alphanumeric() && *c != b'_').map_or(block.len(), |e| p + e);
            let name = String::from_utf8_lossy(&block[p..end]).to_string();
            let name = name.rsplit_once("_v").map_or(name.as_str(), |(n, _)| n).to_string();
            bump(&mut schemas, &name, 50);
            at = end;
        }
    }
    cx.format_set("schemas", hist(schemas));
}

/// The data blocks of an Ogawa archive: groups hold child offsets (the
/// high bit marks data), data blocks a size and bytes. Walked breadth
/// first, at most 100 000 blocks.
fn ogawa_blocks(b: &[u8]) -> Vec<&[u8]> {
    let u64at = |at: usize| b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])));
    let (mut out, mut queue, mut seen) = (Vec::new(), std::collections::VecDeque::new(), BTreeSet::new());
    queue.push_back(u64at(8).unwrap_or(0));
    while let Some(off) = queue.pop_front() {
        if out.len() + seen.len() > 100_000 || !seen.insert(off) {
            continue;
        }
        let data = off >> 63 == 1;
        let Ok(at) = usize::try_from(off & !(1 << 63)) else { continue };
        let Some(n) = u64at(at).and_then(|n| usize::try_from(n).ok()) else { continue };
        if data {
            if let Some(d) = b.get(at + 8..(at + 8).saturating_add(n)) {
                out.push(d);
            }
        } else if at != 0 {
            for i in 0..n.min(10_000) {
                if let Some(c) = u64at(at + 8 + i * 8) {
                    queue.push_back(c);
                }
            }
        }
    }
    out
}

// --- point clouds ----------------------------------------------------------------------------------

fn pcd(cx: &mut Context<'_>, b: &[u8]) {
    let head_end = b
        .windows(5)
        .position(|w| w == b"DATA ")
        .map_or(b.len(), |p| p + b[p..].iter().position(|&c| c == b'\n').unwrap_or(0) + 1);
    let head = String::from_utf8_lossy(&b[..head_end.min(b.len())]);
    let (mut fields, mut data, mut points) = (Vec::new(), String::new(), 0u64);
    for line in head.lines() {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("VERSION") => cx.format_set("version", w.next().unwrap_or("")),
            Some("FIELDS") => fields = w.map(str::to_string).collect(),
            Some("WIDTH") => cx.format_set("width", w.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)),
            Some("HEIGHT") => cx.format_set("height", w.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)),
            Some("POINTS") => points = w.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            Some("DATA") => data = w.next().unwrap_or("").to_string(),
            Some("VIEWPOINT") => cx.format_set("viewpoint", w.collect::<Vec<_>>().join(" ")),
            _ => {}
        }
    }
    cx.format_set("fields", fields.clone());
    cx.format_set("points", points);
    cx.format_set("data", data.clone());
    if data == "ascii" {
        let (ix, iy, iz) = (
            fields.iter().position(|f| f == "x"),
            fields.iter().position(|f| f == "y"),
            fields.iter().position(|f| f == "z"),
        );
        if let (Some(ix), Some(iy), Some(iz)) = (ix, iy, iz) {
            let mut bb = Box3::default();
            for line in String::from_utf8_lossy(&b[head_end.min(b.len())..]).lines().take(5_000_000) {
                let v: Vec<f64> = line.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                if let (Some(x), Some(y), Some(z)) = (v.get(ix), v.get(iy), v.get(iz)) {
                    bb.add([*x, *y, *z]);
                }
            }
            bb.report(cx, "bounds");
        }
    }
}

fn points(cx: &mut Context<'_>, text: &str) {
    let mut bb = Box3::default();
    let (mut rows, mut columns, mut declared) = (0u64, BTreeMap::<usize, u64>::new(), None::<u64>);
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        let v: Vec<f64> = t.split([' ', '\t', ',']).filter(|w| !w.is_empty()).filter_map(|x| x.parse().ok()).collect();
        if i == 0 && v.len() == 1 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // a count, checked below
            let n = v[0].max(0.0) as u64;
            declared = Some(n);
            continue;
        }
        if v.len() >= 3 {
            rows += 1;
            *columns.entry(v.len()).or_default() += 1;
            bb.add([v[0], v[1], v[2]]);
        }
    }
    if let Some(d) = declared {
        cx.format_set("declared_points", d);
    }
    cx.format_set("points", rows);
    cx.format_set("columns", columns.into_iter().max_by_key(|(_, n)| *n).map_or(0, |(c, _)| c));
    bb.report(cx, "bounds");
}

// --- Maya ASCII ---------------------------------------------------------------------------------------

fn maya(cx: &mut Context<'_>, text: &str) {
    let (mut requires, mut nodes, mut references, mut info) =
        (Vec::new(), BTreeMap::new(), 0u64, serde_json::Map::new());
    if let Some(first) = text.lines().next() {
        // `//Maya ASCII 2024 scene`
        cx.format_set("header", first.trim_start_matches("//").trim());
    }
    for line in text.lines() {
        let t = line.trim();
        let quoted: Vec<&str> = t.split('"').skip(1).step_by(2).collect();
        let word = t.split_whitespace().next().unwrap_or("");
        match word {
            "requires" => {
                // `requires maya "2024";` / `requires -nodeType … "mtoa" "5.3.1";`
                if quoted.len() >= 2 {
                    requires.push(format!("{} {}", quoted[quoted.len() - 2], quoted[quoted.len() - 1]));
                } else if let Some(v) = quoted.first() {
                    requires.push((*v).to_string());
                }
            }
            "currentUnit" => {
                for (flag, key) in [("-l", "linear_unit"), ("-a", "angular_unit"), ("-t", "time_unit")] {
                    if let Some(v) = t.split_whitespace().skip_while(|w| *w != flag).nth(1) {
                        cx.format_set(key, v.trim_end_matches(';'));
                    }
                }
            }
            "fileInfo" if quoted.len() >= 2 && info.len() < 50 => {
                info.insert(quoted[0].to_string(), json!(quoted[1]));
            }
            "createNode" => {
                if let Some(kind) = t.split_whitespace().nth(1) {
                    bump(&mut nodes, kind, 500);
                }
            }
            "file" if t.contains("-r") || t.contains("-rdi") => references += 1,
            _ => {}
        }
    }
    // `fileInfo "UUID"` and the OS are fine; nothing personal is kept by Maya.
    cx.format_set("file_info", Value::Object(info));
    cx.format_set("requires", requires.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("nodes", nodes.values().sum::<u64>());
    cx.format_set("node_types", hist(nodes));
    cx.format_set("references", references);
}

// --- SketchUp ------------------------------------------------------------------------------------------

fn sketchup(cx: &mut Context<'_>, b: &[u8]) {
    // UTF-16LE "SketchUp Model", then a length-prefixed "{major.minor.build}".
    if let Some(p) = b.windows(2).take(512).position(|w| w == b"{\0") {
        let rest = &b[p..b.len().min(p + 80)];
        let u: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let s = String::from_utf16_lossy(&u);
        if let Some(v) = s.strip_prefix('{').and_then(|r| r.split('}').next()) {
            cx.format_set("version", v);
            if let Some(major) = v.split('.').next().and_then(|m| m.parse::<u32>().ok()) {
                cx.format_set(
                    "release",
                    if major >= 13 { format!("SketchUp 20{major}") } else { format!("SketchUp {major}") },
                );
            }
        }
    }
    if let Some(p) = b.windows(8).position(|w| w == b"\x89PNG\r\n\x1a\n")
        && let Some(ihdr) = b.get(p + 16..p + 24)
    {
        let (w, h) = (
            u32::from_be_bytes([ihdr[0], ihdr[1], ihdr[2], ihdr[3]]),
            u32::from_be_bytes([ihdr[4], ihdr[5], ihdr[6], ihdr[7]]),
        );
        cx.format_set("thumbnail", json!({ "format": "png", "width": w, "height": h }));
    }
}

// --- MikuMikuDance -------------------------------------------------------------------------------------

struct Pmx<'a> {
    b: &'a [u8],
    at: usize,
    utf8: bool,
}

impl Pmx<'_> {
    fn i32(&mut self) -> Option<i32> {
        let v = self.b.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(i32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.at = self.at.checked_add(n).filter(|a| *a <= self.b.len())?;
        Some(())
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }
    fn text(&mut self) -> Option<String> {
        let n = usize::try_from(self.i32()?).ok()?;
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(if self.utf8 {
            String::from_utf8_lossy(s).into_owned()
        } else {
            let u: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&u)
        })
    }
}

fn pmx(cx: &mut Context<'_>, b: &[u8]) {
    cx.format_set("version", num(f64::from(f32le(b, 4)), 2));
    let globals = usize::from(b.get(8).copied().unwrap_or(0)).min(16);
    let g = |i: usize| b.get(9 + i).copied().unwrap_or(1);
    let utf8 = g(0) == 1;
    let (extra_uv, vertex_idx, texture_idx, material_idx, bone_idx) =
        (usize::from(g(1)), usize::from(g(2)), usize::from(g(3)), usize::from(g(4)), usize::from(g(5)));
    cx.format_set("encoding", if utf8 { "UTF-8" } else { "UTF-16LE" });
    let _ = material_idx;
    let mut r = Pmx { b, at: 9 + globals, utf8 };
    let mut read = || -> Option<()> {
        let (name, name_en, comment, comment_en) = (r.text()?, r.text()?, r.text()?, r.text()?);
        if !name.is_empty() {
            cx.content().title(name.clone());
        }
        cx.format_set("name", name);
        cx.format_set("name_english", name_en);
        cx.format_set("comment", comment.lines().next().unwrap_or("").to_string());
        let _ = comment_en;
        let vertices = r.i32()?;
        cx.format_set("vertices", vertices);
        for _ in 0..vertices.clamp(0, 10_000_000) {
            r.skip(32 + 16 * extra_uv)?;
            let skin = match r.u8()? {
                0 => bone_idx,
                1 => bone_idx * 2 + 4,
                2 | 4 => bone_idx * 4 + 16,
                3 => bone_idx * 2 + 4 + 36,
                _ => return None,
            };
            r.skip(skin + 4)?;
        }
        let indices = r.i32()?;
        cx.format_set("faces", indices / 3);
        r.skip(usize::try_from(indices).ok()? * vertex_idx)?;
        let textures = r.i32()?;
        let mut names = Vec::new();
        for _ in 0..textures.clamp(0, 100_000) {
            names.push(r.text()?.replace('\\', "/"));
        }
        cx.format_set("textures", names.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
        let materials = r.i32()?;
        let mut mats = Vec::new();
        for _ in 0..materials.clamp(0, 100_000) {
            mats.push(r.text()?);
            r.text()?;
            r.skip(16 + 12 + 4 + 12 + 1 + 16 + 4 + 2 * texture_idx + 1)?;
            let shared = r.u8()?;
            r.skip(if shared == 1 { 1 } else { texture_idx })?;
            r.text()?;
            r.skip(4)?;
        }
        cx.format_set("materials", mats.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
        cx.format_set("bones", r.i32()?);
        Some(())
    };
    if read().is_none() {
        cx.warn("the model was read only in part");
    }
}

fn pmd(cx: &mut Context<'_>, b: &[u8]) {
    cx.format_set("version", num(f64::from(f32le(b, 3)), 2));
    let text = |s: &[u8]| {
        let end = s.iter().position(|&c| c == 0 || c == 0xfd).unwrap_or(s.len());
        crate::plugin::decode_text(&s[..end]).text.trim().to_string()
    };
    let name = text(b.get(7..27).unwrap_or_default());
    if !name.is_empty() {
        cx.content().title(name.clone());
    }
    cx.format_set("name", name);
    cx.format_set("comment", text(b.get(27..283).unwrap_or_default()).lines().next().unwrap_or("").to_string());
    let mut at = 283usize;
    let vertices = le32(b, at) as usize;
    cx.format_set("vertices", vertices);
    at = at.saturating_add(4).saturating_add(vertices.saturating_mul(38));
    let indices = le32(b, at) as usize;
    cx.format_set("faces", indices / 3);
    at = at.saturating_add(4).saturating_add(indices.saturating_mul(2));
    let materials = le32(b, at) as usize;
    cx.format_set("materials", materials);
    at = at.saturating_add(4).saturating_add(materials.saturating_mul(70));
    if at + 2 <= b.len() {
        cx.format_set("bones", le16(b, at));
    }
}

// --- Valve ---------------------------------------------------------------------------------------------

fn mdl(cx: &mut Context<'_>, b: &[u8]) {
    let version = le32(b, 4);
    cx.format_set("version", version);
    // GoldSrc (10) has no checksum before the name; Source (44+) does.
    let (name_at, flags_at) = if version <= 10 { (8, 136) } else { (12, 152) };
    let name = cstr(b.get(name_at..name_at + 64).unwrap_or_default());
    cx.format_set("engine", if version <= 10 { "GoldSrc" } else { "Source" });
    cx.format_set("name", name.replace('\\', "/"));
    let n = |at: usize| i32le(b, flags_at + at).max(0);
    if version <= 10 {
        cx.format_set("bones", n(4));
        cx.format_set("hitboxes", n(20));
        cx.format_set("sequences", n(28));
        cx.format_set("textures", n(44));
        cx.format_set("skin_families", n(60));
        cx.format_set("body_parts", n(68));
    } else {
        cx.format_set("bones", n(4));
        cx.format_set("hitbox_sets", n(20));
        cx.format_set("animations", n(28));
        cx.format_set("sequences", n(36));
        cx.format_set("textures", n(52));
        cx.format_set("skin_families", n(72));
        cx.format_set("body_parts", n(80));
    }
}

fn smd(cx: &mut Context<'_>, text: &str) {
    let (mut section, mut nodes, mut frames, mut triangles, mut materials) =
        (String::new(), Vec::new(), 0u64, 0u64, BTreeSet::new());
    let mut line_in_tri = 0;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t == "end" {
            section.clear();
            continue;
        }
        if section.is_empty() {
            if let Some(v) = t.strip_prefix("version") {
                cx.format_set("smd_version", v.trim());
            } else {
                section = t.to_string();
            }
            continue;
        }
        match section.as_str() {
            "nodes" => nodes.extend(t.split('"').nth(1).map(str::to_string)),
            "skeleton" if t.starts_with("time") => frames += 1,
            "triangles" => {
                if line_in_tri == 0 {
                    triangles += 1;
                    if materials.len() < 1000 {
                        materials.insert(t.to_string());
                    }
                }
                line_in_tri = (line_in_tri + 1) % 4;
            }
            _ => {}
        }
    }
    cx.format_set("nodes", nodes.len());
    cx.format_set("node_names", nodes.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("frames", frames);
    cx.format_set("triangles", triangles);
    cx.format_set("materials", materials.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
}

// --- Gaussian splats ------------------------------------------------------------------------------------

fn splat(cx: &mut Context<'_>, b: &[u8], len: u64) -> Result<(), ExtractError> {
    if b.starts_with(b"\x1f\x8b") {
        let d = cx.inflate(b, Compression::Gzip, 64 << 20)?;
        cx.format_set("variant", "SPZ");
        if d.get(..4) != Some(b"NGSP") {
            cx.warn("no SPZ header");
            return Ok(());
        }
        cx.format_set("spz_version", le32(&d, 4));
        cx.format_set("points", le32(&d, 8));
        cx.format_set("sh_degree", d.get(12).copied().unwrap_or(0));
        cx.format_set("fractional_bits", d.get(13).copied().unwrap_or(0));
        cx.format_set("antialiased", d.get(14).is_some_and(|f| f & 1 != 0));
        return Ok(());
    }
    // antimatter15 `.splat`: 32-byte records (position, scale, RGBA, rotation).
    cx.format_set("variant", "splat");
    cx.format_set("points", len / 32);
    let mut bb = Box3::default();
    for r in b.as_chunks::<32>().0.iter().take(5_000_000) {
        bb.add([f64::from(f32le(r, 0)), f64::from(f32le(r, 4)), f64::from(f32le(r, 8))]);
    }
    bb.report(cx, "bounds");
    Ok(())
}

// --- MaterialX / Substance ----------------------------------------------------------------------------------

fn materialx(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut kinds, mut materials, mut graphs, mut inputs) = (BTreeMap::new(), Vec::new(), Vec::new(), 0u64);
    let mut depth = 0usize;
    xmlwalk::walk(text, cx, 5_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            depth += 1;
            match name {
                "materialx" => {
                    for (k, key) in [("version", "version"), ("colorspace", "colorspace"), ("namespace", "namespace")] {
                        if let Some(v) = xmlwalk::attr(a, k) {
                            cx.format_set(key, v);
                        }
                    }
                }
                "nodegraph" => graphs.extend(xmlwalk::attr(a, "name").map(str::to_string)),
                "input" => inputs += 1,
                "surfacematerial" | "volumematerial" => {
                    materials.extend(xmlwalk::attr(a, "name").map(str::to_string));
                    bump(&mut kinds, name, 200);
                }
                "output" | "look" | "materialassign" | "collection" => {}
                other if depth >= 2 => bump(&mut kinds, other, 200),
                _ => {}
            }
        }
        xmlwalk::Ev::End(_) => depth = depth.saturating_sub(1),
        xmlwalk::Ev::Text(_) => {}
    })?;
    cx.format_set("materials", materials.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("node_graphs", graphs.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("node_types", hist(kinds));
    cx.format_set("inputs", inputs);
    Ok(())
}

fn substance(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut graphs, mut nodes, mut deps, mut path) = (Vec::new(), 0u64, BTreeSet::new(), Vec::<String>::new());
    xmlwalk::walk(text, cx, 20_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            let parent = path.last().cloned().unwrap_or_default();
            path.push(name.to_string());
            let v = xmlwalk::attr(a, "v");
            match (parent.as_str(), name) {
                ("package", "formatVersion") => cx.format_set("format_version", v.unwrap_or("")),
                ("updaterVersion" | "package", "updaterVersion") => cx.format_set("updater_version", v.unwrap_or("")),
                ("graph", "identifier") => graphs.extend(v.map(str::to_string)),
                ("dependency", "filename") => {
                    if let Some(f) = v {
                        deps.insert(f.rsplit(['/', '\\']).next().unwrap_or(f).to_string());
                    }
                }
                (_, "compNode") => nodes += 1,
                _ => {}
            }
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
        xmlwalk::Ev::Text(_) => {}
    })?;
    cx.format_set("graphs", graphs.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("nodes", nodes);
    cx.format_set("dependencies", deps.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!(
        "alembic",
        "pcd",
        "pts_points",
        "xyz_points",
        "maya",
        "sketchup",
        "pmx",
        "pmd",
        "valve_mdl",
        "valve_smd",
        "gaussian_splat",
        "materialx",
        "substance"
    );
}
