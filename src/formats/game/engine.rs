//! Game engine files:
//! * Unity asset bundles (`UnityFS`; `UnityWeb` / `UnityRaw` headers):
//!   format version, the Unity version and revision that built them,
//!   compression, blocks, the files inside (names and sizes);
//! * Unity serialized files (`.assets`, `globalgamemanagers`, `level0`,
//!   bundle members): format version, Unity version, target platform, type
//!   tree, classes and objects per class;
//! * Unreal Engine packages (`.uasset`, `.umap`, and the UE1–3 `.upk` /
//!   `.utx` header: versions, flags, table sizes): legacy, UE4 and UE5
//!   versions, licensee version, custom versions, folder name, flags,
//!   names, exports, imports, the engine version that saved it;
//! * `GameMaker` projects (`.yyp`): name, IDE version, resources by kind,
//!   folders, rooms, configurations;
//! * Godot projects (`project.godot`): config version, name, engine
//!   features, main scene, renderer, autoloads, plugins;
//! * Paradox mod descriptors (`.mod`): name, version, supported game
//!   version, tags, dependencies, Steam Workshop ID.
//!
//! Specifications: `UnityPy` and `AssetStudio` notes on `BundleFile` and
//! `SerializedFile`; Unreal Engine `PackageFileSummary.cpp` and
//! `ObjectVersion.h`; `GameMaker` manual (project format 2.3+); Godot
//! `project_settings.cpp`; the Paradox wiki (mod structure).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    AnyValue, ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Magic,
    Probe, Sniff, Source, nesting_depth, truncate_chars,
};

/// Extractor for game engine files.
pub struct Engine;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.engine",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        // `.bundle` is also a macOS bundle binary: the signature decides.
        FormatSpec {
            id: "unity_bundle",
            name: "Unity asset bundle",
            family: "game",
            mimes: &[],
            extensions: &["unity3d"],
            magic: &[Magic::prefix(b"UnityFS\0"), Magic::prefix(b"UnityWeb\0"), Magic::prefix(b"UnityRaw\0")],
            parent: None,
        },
        // No signature: the header is checked against the file size.
        FormatSpec {
            id: "unity_assets",
            name: "Unity serialized file",
            family: "game",
            mimes: &[],
            extensions: &["assets"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "uasset",
            name: "Unreal Engine package",
            family: "game",
            mimes: &[],
            extensions: &["uasset", "umap", "upk", "utx"],
            magic: &[Magic::prefix(&[0xC1, 0x83, 0x2A, 0x9E])],
            parent: None,
        },
        FormatSpec {
            id: "gamemaker_project",
            name: "GameMaker project",
            family: "game",
            mimes: &[],
            extensions: &["yyp"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "godot_project",
            name: "Godot project",
            family: "game",
            mimes: &[],
            extensions: &["godot"],
            magic: &[],
            parent: Some("text"),
        },
        // `.mod` is also a tracker module: descriptors are sniffed.
        FormatSpec {
            id: "paradox_mod",
            name: "Paradox mod descriptor",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

const MAX_NODES: usize = 100_000;

fn cstr(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    Ok(truncate_chars(&String::from_utf8_lossy(r.cstr()?), 200))
}

fn unity_compression(c: u32) -> &'static str {
    match c {
        0 => "none",
        1 => "LZMA",
        2 => "LZ4",
        3 => "LZ4HC",
        4 => "LZHAM",
        _ => "unknown",
    }
}

/// Decompress a Unity block (`flags & 0x3F`).
fn unity_block(cx: &mut Context<'_>, data: &[u8], flags: u32, size: usize) -> Result<Vec<u8>, ExtractError> {
    match flags & 0x3F {
        0 => Ok(data.to_vec()),
        1 => {
            // Five bytes of LZMA properties, then the stream.
            let p = data.get(..5).ok_or(ExtractError::Malformed("short LZMA block".into()))?;
            let codec = Codec::Lzma {
                props: p[0],
                dict_size: u32::from_le_bytes([p[1], p[2], p[3], p[4]]),
                size: Some(size as u64),
            };
            Ok(cx.decompress(&data[5..], codec, size)?.data)
        }
        2 | 3 => Ok(cx.decompress(data, Codec::Lz4Block { max: size }, size)?.data),
        _ => Err(ExtractError::Unsupported(format!("Unity compression {}", flags & 0x3F))),
    }
}

fn unity_bundle(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let head = src.read_vec(0, 512.min(usize::try_from(len).unwrap_or(0)))?;
    let mut r = ByteReader::new(&head);
    let sig = cstr(&mut r)?;
    let version = r.be_u32()?;
    let player = cstr(&mut r)?;
    let revision = cstr(&mut r)?;
    cx.format_set("signature", sig.clone());
    cx.format_set("format_version", version);
    if player != "5.x.x" && !player.is_empty() {
        cx.format_set("player_version", player);
    }
    cx.format_set("unity_version", revision.clone());
    if sig != "UnityFS" {
        // UnityWeb / UnityRaw: header only.
        return Ok(());
    }
    let _size = r.be_u64()?;
    let compressed = r.be_u32()? as usize;
    let uncompressed = r.be_u32()? as usize;
    let flags = r.be_u32()?;
    cx.format_set("blocks_info_compression", unity_compression(flags & 0x3F));
    // Version 7 aligns the blocks info to 16 bytes; so do some version 6
    // bundles from Unity 2019.4.15 on.
    let engine: Vec<u32> =
        revision.split(|c: char| !c.is_ascii_digit()).take(3).filter_map(|p| p.parse().ok()).collect();
    if version >= 7 || engine.len() == 3 && engine[0] == 2019 && engine[1..] >= [4, 15][..] {
        let at = r.position().div_ceil(16) * 16;
        r.seek(at.min(head.len()))?;
    }
    let info_at = if flags & 0x80 != 0 { len.saturating_sub(compressed as u64) } else { r.position() as u64 };
    let raw = src.read_vec(info_at, compressed.min(16 << 20))?;
    let info = unity_block(cx, &raw, flags, uncompressed.min(64 << 20))?;
    let mut r = ByteReader::new(&info);
    r.advance(16)?;
    let blocks = usize::try_from(r.be_i32()?).unwrap_or(0);
    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let (mut data_in, mut data_out) = (0u64, 0u64);
    for _ in 0..blocks.min(MAX_NODES) {
        data_out += u64::from(r.be_u32()?);
        data_in += u64::from(r.be_u32()?);
        let f = u32::from(r.be_u16()?);
        bump(&mut methods, unity_compression(f & 0x3F), 10);
    }
    cx.format_set("block_count", blocks);
    cx.format_set("block_compression", hist(methods));
    let nodes = usize::try_from(r.be_i32()?).unwrap_or(0);
    let mut files = Vec::new();
    for _ in 0..nodes.min(MAX_NODES) {
        r.advance(8)?;
        let size = r.be_u64()?;
        let f = r.be_u32()?;
        let path = cstr(&mut r)?;
        if files.len() < 100 {
            let mut m = Map::new();
            m.insert("path".into(), path.into());
            m.insert("size".into(), size.into());
            // Bit 2: a serialized file.
            if f & 4 != 0 {
                m.insert("serialized".into(), true.into());
            }
            files.push(Value::Object(m));
        }
    }
    cx.format_set("file_count", nodes);
    cx.format_set("files", files);
    cx.physical().entries(nodes as u64).uncompressed_bytes(data_out);
    if data_in > 0 && data_in < data_out {
        cx.format_set("compressed_bytes", data_in);
    }
    Ok(())
}

fn platform(p: i32) -> Option<&'static str> {
    Some(match p {
        2 => "macOS",
        5 => "Windows (32-bit)",
        9 => "iOS",
        13 => "Android",
        17 | 24 | 25 => "Linux",
        19 => "Windows (64-bit)",
        20 => "WebGL",
        21 => "Universal Windows Platform",
        31 => "PlayStation 4",
        33 => "Xbox One",
        37 => "tvOS",
        38 => "Nintendo Switch",
        44 => "PlayStation 5",
        47 => "visionOS",
        _ => return None,
    })
}

/// The serialized-file header: (version, metadata size, file size, data
/// offset, big-endian, header length).
fn unity_header(h: &[u8]) -> Option<(u32, u64, u64, u64, bool, usize)> {
    let be = |i: usize| h.get(i..i + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]));
    let be64 = |i: usize| h.get(i..i + 8).map(|s| u64::from_be_bytes(s.try_into().unwrap_or_default()));
    let version = be(8)?;
    if !(9..=50).contains(&version) {
        return None;
    }
    let big = *h.get(16)? != 0;
    if version >= 22 {
        Some((version, u64::from(be(20)?), be64(24)?, be64(32)?, big, 48))
    } else {
        Some((version, u64::from(be(0)?), u64::from(be(4)?), u64::from(be(12)?), big, 20))
    }
}

/// Little- or big-endian reads for the metadata.
struct Meta<'a> {
    r: ByteReader<'a>,
    big: bool,
}

impl Meta<'_> {
    fn u32(&mut self) -> Result<u32, ExtractError> {
        if self.big { self.r.be_u32() } else { self.r.le_u32() }
    }
    fn i32(&mut self) -> Result<i32, ExtractError> {
        if self.big { self.r.be_i32() } else { self.r.le_i32() }
    }
}

fn unity_assets(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let (version, _meta, size, data, big, header) =
        unity_header(b).ok_or(ExtractError::Malformed("not a Unity serialized file".into()))?;
    cx.format_set("format_version", version);
    cx.format_set("declared_size", size);
    cx.format_set("data_offset", data);
    let mut m = Meta { r: ByteReader::new(b), big };
    m.r.seek(header)?;
    let unity = cstr(&mut m.r)?;
    cx.format_set("unity_version", unity);
    let target = m.i32()?;
    cx.format_set("target_platform", platform(target).map_or_else(|| target.to_string(), str::to_string));
    let tree = version >= 13 && m.r.u8()? != 0;
    cx.format_set("type_tree", tree);
    let types = usize::try_from(m.i32()?).unwrap_or(0);
    let mut classes = Vec::new();
    for _ in 0..types.min(MAX_NODES) {
        let class = m.i32()?;
        if version >= 16 {
            m.r.advance(1)?;
        }
        if version >= 17 {
            m.r.advance(2)?;
        }
        if (version < 16 && class < 0) || (version >= 16 && class == 114) {
            m.r.advance(16)?;
        }
        m.r.advance(16)?;
        if tree {
            let nodes = m.u32()? as usize;
            let strings = m.u32()? as usize;
            m.r.advance(nodes.saturating_mul(if version >= 19 { 32 } else { 24 }).saturating_add(strings))?;
            if version >= 21 {
                let deps = m.u32()? as usize;
                m.r.advance(deps.saturating_mul(4))?;
            }
        }
        classes.push(class);
    }
    if (7..14).contains(&version) {
        m.r.advance(4)?;
    }
    let objects = m.u32()? as usize;
    cx.format_set("object_count", objects);
    let name = |c: i32| {
        u32::try_from(c)
            .ok()
            .and_then(super::super::data::binser::unity::class_name)
            .map_or_else(|| format!("class {c}"), str::to_string)
    };
    let mut per: BTreeMap<String, u64> = BTreeMap::new();
    if version >= 17 {
        for _ in 0..objects.min(MAX_NODES) {
            let at = m.r.position().div_ceil(4) * 4;
            if m.r.seek(at).is_err() {
                break;
            }
            let ok = (|| -> Result<i32, ExtractError> {
                m.r.advance(8)?;
                m.r.advance(if version >= 22 { 8 } else { 4 })?;
                m.r.advance(4)?;
                m.i32()
            })();
            match ok {
                Ok(t) => bump(
                    &mut per,
                    &name(usize::try_from(t).ok().and_then(|t| classes.get(t)).copied().unwrap_or(-1)),
                    200,
                ),
                Err(_) => break,
            }
        }
    }
    if per.is_empty() {
        for c in &classes {
            bump(&mut per, &name(*c), 200);
        }
        cx.format_set("classes", per.into_keys().collect::<Vec<_>>());
    } else {
        cx.format_set("objects_by_class", hist(per));
    }
    Ok(())
}

fn fstring(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    let n = r.le_i32()?;
    if n == 0 {
        return Ok(String::new());
    }
    if n < 0 {
        let units: Vec<u16> = r
            .bytes(n.unsigned_abs() as usize * 2)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        return Ok(truncate_chars(&String::from_utf16_lossy(&units), 300));
    }
    let b = r.bytes(n.unsigned_abs() as usize)?;
    Ok(truncate_chars(&String::from_utf8_lossy(&b[..b.len().saturating_sub(1)]), 300))
}

/// `major.minor.patch-changelist+branch`, if plausible.
fn engine_version(r: &mut ByteReader<'_>) -> Result<Option<String>, ExtractError> {
    let (major, minor, patch) = (r.le_u16()?, r.le_u16()?, r.le_u16()?);
    let cl = r.le_u32()? & 0x7FFF_FFFF;
    let branch = fstring(r)?;
    Ok(((4..=9).contains(&major) && minor < 100).then(|| {
        let mut v = format!("{major}.{minor}.{patch}");
        if cl > 0 {
            v.push('-');
            v.push_str(&cl.to_string());
        }
        if !branch.is_empty() {
            v.push('+');
            v.push_str(&branch);
        }
        v
    }))
}

/// Unreal Engine 1–3 packages (`.utx`, `.upk`, `.u`): file and licensee
/// versions, flags, and the name / export / import table sizes.
fn classic_package(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b).skip(4)?;
    let (version, licensee) = (r.le_u16()?, r.le_u16()?);
    cx.format_set("engine_generation", if version >= 249 { "Unreal Engine 3" } else { "Unreal Engine 1 / 2" });
    cx.format_set("file_version", version);
    cx.format_set("licensee_version", licensee);
    if version >= 249 {
        // Header size, then the folder name (an FString).
        r.advance(4)?;
        let n = r.le_i32()?;
        let len = usize::try_from(n.unsigned_abs()).unwrap_or(0) * if n < 0 { 2 } else { 1 };
        let folder = r.bytes(len)?;
        let folder = String::from_utf8_lossy(folder).trim_end_matches('\0').to_string();
        if !folder.is_empty() && folder != "None" {
            cx.format_set("folder", folder);
        }
    }
    let flags = r.le_u32()?;
    let (names, _) = (r.le_u32()?, r.le_u32()?);
    let (exports, _) = (r.le_u32()?, r.le_u32()?);
    let (imports, _) = (r.le_u32()?, r.le_u32()?);
    cx.format_set("package_flags", flags);
    cx.format_set("names", names);
    cx.format_set("exports", exports);
    cx.format_set("imports", imports);
    Ok(())
}

#[allow(clippy::too_many_lines)] // the package summary, field by field
fn uasset(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.advance(4)?;
    let legacy = r.le_i32()?;
    if legacy > 0 {
        return classic_package(cx, b);
    }
    if !(-9..=-1).contains(&legacy) {
        return Err(ExtractError::Unsupported(format!("package file version {legacy}")));
    }
    cx.format_set("legacy_file_version", legacy);
    if legacy != -4 {
        r.advance(4)?;
    }
    let ue4 = r.le_i32()?;
    let ue5 = if legacy <= -8 { r.le_i32()? } else { 0 };
    let licensee = r.le_i32()?;
    cx.format_set("ue4_version", ue4);
    if legacy <= -8 {
        cx.format_set("ue5_version", ue5);
    }
    if licensee != 0 {
        cx.format_set("licensee_version", licensee);
    }
    // Unversioned packages (cooked) store zeros: nothing more is certain.
    if ue4 == 0 && ue5 == 0 {
        cx.format_set("unversioned", true);
        return Ok(());
    }
    if legacy <= -2 {
        let n = usize::try_from(r.le_i32()?).unwrap_or(0);
        cx.format_set("custom_version_count", n);
        for _ in 0..n.min(10_000) {
            match legacy {
                -2 => r.advance(8)?,
                -5..=-3 => {
                    r.advance(20)?;
                    let _ = fstring(&mut r)?;
                }
                _ => r.advance(20)?,
            }
        }
    }
    // UE5 1016+ (PACKAGE_SAVED_HASH): the saved hash precedes the header size.
    if ue5 >= 1016 {
        r.advance(20)?;
    }
    let header = r.le_i32()?;
    cx.format_set("header_bytes", header);
    let folder = fstring(&mut r)?;
    if !folder.is_empty() && folder != "None" {
        cx.format_set("package_name", folder);
    }
    let flags = r.le_u32()?;
    cx.format_set("package_flags", format!("0x{flags:08x}"));
    let editor_only_filtered = flags & 0x8000_0000 != 0;
    cx.format_set("cooked", flags & 0x0000_0200 != 0);
    if flags & 0x0002_0000 != 0 {
        cx.format_set("contains_map", true);
    }
    let names = r.le_i32()?;
    r.advance(4)?;
    cx.format_set("name_count", names);
    if ue5 >= 1008 {
        r.advance(8)?;
    }
    if !editor_only_filtered && ue4 >= 516 {
        let _ = fstring(&mut r)?;
    }
    if ue4 >= 459 {
        r.advance(8)?;
    }
    let exports = r.le_i32()?;
    r.advance(4)?;
    let imports = r.le_i32()?;
    r.advance(4)?;
    cx.format_set("export_count", exports);
    cx.format_set("import_count", imports);
    // The rest of the summary changed shape across UE 5.x: the engine
    // version is read for UE4 and UE5 packages before 5.3 (version 1014).
    if ue5 >= 1014 {
        return Ok(());
    }
    let tail = (|| -> Result<Option<String>, ExtractError> {
        r.advance(4)?; // depends
        if ue4 >= 384 {
            r.advance(8)?;
        }
        if ue4 >= 510 {
            r.advance(4)?;
        }
        r.advance(4)?; // thumbnails
        r.advance(16)?; // guid
        if !editor_only_filtered && ue4 >= 518 {
            r.advance(16)?;
            if ue4 < 520 {
                r.advance(16)?;
            }
        }
        let generations = usize::try_from(r.le_i32()?).unwrap_or(0);
        r.advance(generations.min(100_000) * 8)?;
        if ue4 >= 336 { engine_version(&mut r) } else { Ok(None) }
    })();
    if let Ok(Some(v)) = tail {
        cx.format_set("saved_by_engine", v);
    }
    Ok(())
}

fn gamemaker(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    // The JSON5 parser recurses: refuse deep nesting first.
    if nesting_depth(text) > MAX_NESTING {
        return Err(ExtractError::LimitExceeded("nested too deeply".into()));
    }
    let v = json5::from_str::<AnyValue>(text).map(|v| v.0).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(|s| truncate_chars(s, 300));
    if let Some(n) = s("name") {
        cx.content().title(n.clone());
        cx.format_set("name", n);
    }
    if let Some(ide) = v.pointer("/MetaData/IDEVersion").and_then(Value::as_str) {
        cx.format_set("ide_version", ide);
    }
    if let Some(rv) = s("resourceVersion") {
        cx.format_set("resource_version", rv);
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let resources = v.get("resources").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    for res in resources {
        let path = res.pointer("/id/path").and_then(Value::as_str).unwrap_or("");
        bump(&mut kinds, path.split('/').next().unwrap_or("other"), 50);
    }
    cx.format_set("resource_count", resources.len());
    cx.format_set("resources", hist(kinds));
    for (k, key) in [("Folders", "folder_count"), ("RoomOrderNodes", "room_count")] {
        if let Some(a) = v.get(k).and_then(Value::as_array) {
            cx.format_set(key, a.len());
        }
    }
    if let Some(c) = v.pointer("/configs/children").and_then(Value::as_array) {
        let names: Vec<Value> = c.iter().filter_map(|c| c.get("name").cloned()).take(50).collect();
        cx.format_set("configurations", names);
    }
    Ok(())
}

/// A Godot settings value without its quotes.
fn unquote(v: &str) -> String {
    truncate_chars(v.trim().trim_matches('"'), 300)
}

fn godot_project(cx: &mut Context<'_>, text: &str) {
    let mut section = String::new();
    let mut sections = Vec::new();
    let mut autoloads = Vec::new();
    for line in text.lines().take(100_000) {
        let t = line.trim();
        if t.starts_with(';') || t.is_empty() {
            continue;
        }
        if let Some(s) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.to_string();
            if sections.len() < 100 {
                sections.push(section.clone());
            }
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match (section.as_str(), k) {
            ("", "config_version") => {
                cx.format_set("config_version", v.parse::<u64>().map_or_else(|_| Value::from(v), Value::from));
                let engine = match v {
                    "5" => Some("Godot 4"),
                    "4" => Some("Godot 3"),
                    "3" => Some("Godot 3.0"),
                    _ => None,
                };
                if let Some(e) = engine {
                    cx.format_set("engine", e);
                }
            }
            ("application", "config/name") => {
                let n = unquote(v);
                cx.content().title(n.clone());
                cx.format_set("name", n);
            }
            ("application", "config/description") => {
                let d = unquote(v);
                cx.content().description(d.clone());
                cx.format_set("description", d);
            }
            ("application", "config/version") => cx.format_set("version", unquote(v)),
            ("application", "run/main_scene") => cx.format_set("main_scene", unquote(v)),
            ("application", "config/features") => {
                let inner = v.trim_start_matches("PackedStringArray(").trim_end_matches(')');
                let f: Vec<Value> = inner.split(',').map(unquote).filter(|s| !s.is_empty()).map(Value::from).collect();
                if let Some(ver) =
                    f.iter().filter_map(Value::as_str).find(|s| s.starts_with(|c: char| c.is_ascii_digit()))
                {
                    cx.format_set("engine_version", ver.to_string());
                }
                cx.format_set("features", f);
            }
            ("autoload", name) => {
                if autoloads.len() < 100 {
                    autoloads.push(name.to_string());
                }
            }
            ("rendering", "renderer/rendering_method") => cx.format_set("renderer", unquote(v)),
            ("editor_plugins", "enabled") => {
                let inner = v.trim_start_matches("PackedStringArray(").trim_end_matches(')');
                let p: Vec<Value> = inner.split(',').map(unquote).filter(|s| !s.is_empty()).map(Value::from).collect();
                cx.format_set("plugins", p);
            }
            _ => {}
        }
    }
    if !autoloads.is_empty() {
        cx.format_set("autoloads", autoloads);
    }
    cx.format_set("sections", sections);
}

/// `key="value"` and `key={ "a" "b" }` lines of a Paradox descriptor.
fn paradox_pairs(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim().rsplit(char::is_whitespace).next().unwrap_or("").to_string();
        rest = rest[eq + 1..].trim_start();
        let values = if let Some(body) = rest.strip_prefix('{') {
            let end = body.find('}').unwrap_or(body.len());
            let inner = &body[..end];
            rest = body.get(end + 1..).unwrap_or("");
            inner.split('"').skip(1).step_by(2).map(str::to_string).collect()
        } else if let Some(body) = rest.strip_prefix('"') {
            let end = body.find('"').unwrap_or(body.len());
            let v = body[..end].to_string();
            rest = body.get(end + 1..).unwrap_or("");
            vec![v]
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let v = rest[..end].to_string();
            rest = &rest[end..];
            vec![v]
        };
        if out.len() < 200 && !key.is_empty() {
            out.push((key, values));
        }
    }
    out
}

fn paradox(cx: &mut Context<'_>, text: &str) {
    for (k, v) in paradox_pairs(text) {
        let one = || v.first().map(|s| truncate_chars(s, 300)).unwrap_or_default();
        match k.as_str() {
            "name" => {
                cx.content().title(one());
                cx.format_set("name", one());
            }
            "version" => cx.format_set("version", one()),
            "supported_version" => cx.format_set("supported_version", one()),
            "remote_file_id" => cx.format_set("workshop_id", one()),
            "path" | "archive" => cx.format_set("path", one()),
            "picture" => cx.format_set("picture", one()),
            "tags" => {
                for t in &v {
                    cx.content().keyword(t.clone());
                }
                cx.format_set("tags", v.clone());
            }
            "dependencies" => cx.format_set("dependencies", v.clone()),
            _ => {}
        }
    }
}

impl Extractor for Engine {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let name = probe.name.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        // Serialized files: a plausible version and a size matching the file.
        if let Some((_, meta, size, data, _, header)) = unity_header(h)
            && size == probe.len
            && data <= size
            && meta < size
            && h.get(header).is_some_and(u8::is_ascii_digit)
            && (ext == "assets" || ext.is_empty() || name.starts_with("level") || name.starts_with("CAB-"))
        {
            return sure("unity_assets");
        }
        let text = std::str::from_utf8(&h[..h.len().min(4096)]).ok()?;
        if ext == "yyp" && text.contains("\"GMProject\"") {
            return sure("gamemaker_project");
        }
        if name == "project.godot" || ext == "godot" && text.contains("config_version=") {
            return sure("godot_project");
        }
        // Paradox descriptors: `name="…"` with a version, path or tags.
        if ext == "mod" || name == "descriptor.mod" {
            let keys: Vec<String> = paradox_pairs(text).into_iter().map(|(k, _)| k).collect();
            let has = |k: &str| keys.iter().any(|x| x == k);
            if has("name") && (has("supported_version") || has("path") || has("tags") || has("remote_file_id")) {
                return sure("paradox_mod");
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "unity_bundle" => unity_bundle(cx, src),
            "unity_assets" | "uasset" => {
                // Headers and type tables: the first megabytes.
                let (b, _) = src.read_prefix(cx.parse_limit().min(16 << 20))?;
                if id == "uasset" { uasset(cx, &b) } else { unity_assets(cx, &b) }
            }
            _ => {
                let text = cx.read_text(src)?.text;
                match id.as_str() {
                    "gamemaker_project" => gamemaker(cx, &text),
                    "godot_project" => {
                        godot_project(cx, &text);
                        Ok(())
                    }
                    _ => {
                        paradox(cx, &text);
                        Ok(())
                    }
                }
            }
        }
    }
}

crate::register_extractor!(Engine);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paradox_descriptor() {
        let p = paradox_pairs(
            "name=\"Harbour Lights\"\ntags={\n\t\"Graphics\"\n\t\"Map\"\n}\nsupported_version=\"1.37.*\"",
        );
        assert_eq!(p[0], ("name".to_string(), vec!["Harbour Lights".to_string()]));
        assert_eq!(p[1].1, vec!["Graphics", "Map"]);
        assert_eq!(p[2].0, "supported_version");
    }

    crate::fixture_tests!(
        "unity_bundle",
        "unity_assets",
        "uasset",
        "gamemaker_project",
        "godot_project",
        "paradox_mod"
    );
}
