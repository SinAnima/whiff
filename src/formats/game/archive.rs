//! Game archives and level files, from their directories (no member is
//! extracted):
//! * Doom WAD (IWAD, PWAD) and Quake / Half-Life WAD2 / WAD3: lumps, maps,
//!   sprite / flat / patch namespaces, notable lumps, texture types;
//! * Quake PAK: files, extensions, maps;
//! * BSP levels (Quake, Half-Life, BSP2, Quake II, Quake III, Source):
//!   version, the entities (classes, the worldspawn's title, WADs, sky),
//!   counts of models, faces, vertices and textures, Source map revision;
//! * Valve VPK (v1, v2): files, extensions, archive chunks, preload data,
//!   signature;
//! * Bethesda BSA (Morrowind, Oblivion to Skyrim SE) and BA2 (Fallout 4,
//!   Starfield): version, flags, content types, folders, files, names;
//! * RPG Maker RGSSAD / RGSS2A / RGSS3A: version, files (the scrambled
//!   index is descrambled; contents are not read);
//! * Ren'Py RPA: version, files (the index is a pickle, walked, never
//!   loaded);
//! * Godot PCK: pack format, engine version, encryption, files;
//! * Unreal Engine `.pak`: version, mount point, encryption, compression
//!   methods, files.
//!
//! Specifications: the Unofficial Doom Specs and the Doom wiki (WAD, map
//! lumps); the Quake specs (PAK, BSP 29, WAD2), Valve developer wiki
//! (WAD3, VBSP, VPK); `id` Quake II and Quake III BSP notes; UESP
//! (BSA, BA2); RPG Maker archive notes; Ren'Py `archiver.py`; Godot
//! `file_access_pack.cpp`; Unreal Engine `IPlatformFilePak.h`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{bump, fixed, hist, member_ext};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, truncate_chars,
};

/// Extractor for game archives.
pub struct Archive;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.archive",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "wad",
            name: "Doom / Quake WAD",
            family: "game",
            mimes: &["application/x-doom"],
            extensions: &["wad"],
            magic: &[Magic::prefix(b"IWAD"), Magic::prefix(b"PWAD"), Magic::prefix(b"WAD2"), Magic::prefix(b"WAD3")],
            parent: None,
        },
        FormatSpec {
            id: "quake_pak",
            name: "Quake PAK",
            family: "game",
            mimes: &[],
            extensions: &["pak"],
            magic: &[Magic::prefix(b"PACK")],
            parent: None,
        },
        // Quake and Half-Life BSPs start with a bare version number: all
        // BSPs are sniffed.
        FormatSpec {
            id: "bsp",
            name: "BSP map (Quake, Half-Life, Source)",
            family: "game",
            mimes: &[],
            extensions: &["bsp"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "vpk",
            name: "Valve VPK",
            family: "game",
            mimes: &[],
            extensions: &["vpk"],
            magic: &[Magic::prefix(&[0x34, 0x12, 0xAA, 0x55])],
            parent: None,
        },
        FormatSpec {
            id: "bsa",
            name: "Bethesda archive (BSA)",
            family: "game",
            mimes: &[],
            extensions: &["bsa"],
            magic: &[Magic::prefix(b"BSA\0")],
            parent: None,
        },
        FormatSpec {
            id: "ba2",
            name: "Bethesda archive 2 (BA2)",
            family: "game",
            mimes: &[],
            extensions: &["ba2"],
            magic: &[Magic::prefix(b"BTDX")],
            parent: None,
        },
        FormatSpec {
            id: "rgssad",
            name: "RPG Maker archive (RGSSAD)",
            family: "game",
            mimes: &[],
            extensions: &["rgssad", "rgss2a", "rgss3a"],
            magic: &[Magic::prefix(b"RGSSAD\0")],
            parent: None,
        },
        FormatSpec {
            id: "rpa",
            name: "Ren'Py archive (RPA)",
            family: "game",
            mimes: &[],
            extensions: &["rpa"],
            magic: &[Magic::prefix(b"RPA-")],
            parent: None,
        },
        FormatSpec {
            id: "godot_pck",
            name: "Godot pack (PCK)",
            family: "game",
            mimes: &[],
            extensions: &["pck"],
            magic: &[Magic::prefix(b"GDPC")],
            parent: None,
        },
        // The signature is in the footer: sniffed from the tail.
        FormatSpec {
            id: "unreal_pak",
            name: "Unreal Engine pak",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: usize = 1_000_000;
const MAX_NAMES: usize = 50;
/// Directory bytes read at most.
const MAX_DIR: usize = 64 << 20;

/// File list summary: count, extensions, a sample of names.
#[derive(Default)]
struct Files {
    count: u64,
    bytes: u64,
    exts: BTreeMap<String, u64>,
    names: Vec<String>,
    folders: BTreeSet<String>,
}

impl Files {
    fn add(&mut self, name: &str, size: u64) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(size);
        bump(&mut self.exts, &member_ext(name), 100);
        if self.names.len() < MAX_NAMES {
            self.names.push(truncate_chars(name, 300));
        }
        if let Some((dir, _)) = name.replace('\\', "/").split_once('/')
            && self.folders.len() < 100
        {
            self.folders.insert(dir.to_string());
        }
    }

    fn report(self, cx: &mut Context<'_>) {
        cx.format_set("file_count", self.count);
        if self.count > 0 {
            cx.format_set("extensions", hist(self.exts));
            cx.format_set("files", self.names);
        }
        if !self.folders.is_empty() {
            cx.format_set("top_folders", self.folders.into_iter().collect::<Vec<_>>());
        }
        cx.physical().entries(self.count);
        if self.bytes > 0 {
            cx.physical().uncompressed_bytes(self.bytes);
        }
    }
}

/// Read `n` bytes at `at`, capped.
fn read_at(src: &mut dyn Source, at: u64, n: u64) -> Result<Vec<u8>, ExtractError> {
    if at >= src.len() {
        return Err(ExtractError::Malformed("directory past the end of the file".into()));
    }
    let n = n.min(src.len() - at).min(MAX_DIR as u64);
    Ok(src.read_vec(at, usize::try_from(n).unwrap_or(0))?)
}

fn le32(b: &[u8], i: usize) -> u32 {
    b.get(i..i + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], i: usize) -> u64 {
    b.get(i..i + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap_or_default()))
}

/// Doom map lumps that follow a map's marker.
const MAP_LUMPS: [&str; 11] = [
    "THINGS", "LINEDEFS", "SIDEDEFS", "VERTEXES", "SEGS", "SSECTORS", "NODES", "SECTORS", "REJECT", "BLOCKMAP",
    "BEHAVIOR",
];

/// Lumps that say what a WAD changes or which engine it targets.
const NOTABLE: [&str; 18] = [
    "PLAYPAL", "COLORMAP", "ENDOOM", "TEXTURE1", "TEXTURE2", "PNAMES", "GENMIDI", "DMXGUS", "DEHACKED", "MAPINFO",
    "ZMAPINFO", "UMAPINFO", "DECORATE", "ZSCRIPT", "GAMEINFO", "SNDINFO", "LANGUAGE", "ANIMDEFS",
];

fn wad(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 12)?;
    let kind = String::from_utf8_lossy(&h[..4]).into_owned();
    let count = le32(&h, 4) as usize;
    let dir = u64::from(le32(&h, 8));
    let quake = kind.starts_with("WAD");
    let entry = if quake { 32 } else { 16 };
    let d = read_at(src, dir, (count.min(MAX_ENTRIES) * entry) as u64)?;
    cx.format_set(
        "kind",
        match kind.as_str() {
            "IWAD" => "IWAD (game data)",
            "PWAD" => "PWAD (patch)",
            "WAD2" => "WAD2 (Quake textures)",
            _ => "WAD3 (Half-Life textures)",
        },
    );
    let mut lumps = 0u64;
    if quake {
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        let mut names = Vec::new();
        for e in d.as_chunks::<32>().0 {
            lumps += 1;
            let t = match e[12] {
                0x40 => "palette",
                0x42 => "picture",
                0x43 => "mip texture",
                0x44 => "raw",
                0x45 => "console picture",
                0x46 => "font",
                _ => "other",
            };
            bump(&mut types, t, 20);
            if names.len() < MAX_NAMES
                && let Some(n) = fixed(&e[16..32])
            {
                names.push(n);
            }
        }
        cx.format_set("lump_count", lumps);
        cx.format_set("lump_types", hist(types));
        cx.format_set("lumps", names);
        cx.physical().entries(lumps);
        return Ok(());
    }
    let names: Vec<String> =
        d.as_chunks::<16>().0.iter().map(|e| fixed(&e[8..16]).unwrap_or_default().to_ascii_uppercase()).collect();
    lumps = names.len() as u64;
    let mut maps = Vec::new();
    let mut notable = BTreeSet::new();
    let mut spaces: BTreeMap<String, u64> = BTreeMap::new();
    let mut space: Option<&str> = None;
    let mut udmf = false;
    for (i, n) in names.iter().enumerate() {
        let next = names.get(i + 1).map_or("", String::as_str);
        if MAP_LUMPS[..1].contains(&next) || next == "TEXTMAP" {
            udmf |= next == "TEXTMAP";
            if maps.len() < 500 {
                maps.push(n.clone());
            }
            continue;
        }
        match n.as_str() {
            "S_START" | "SS_START" => space = Some("sprites"),
            "F_START" | "FF_START" => space = Some("flats"),
            "P_START" | "PP_START" => space = Some("patches"),
            "TX_START" => space = Some("textures"),
            "S_END" | "SS_END" | "F_END" | "FF_END" | "P_END" | "PP_END" | "TX_END" => space = None,
            n if n.ends_with("_START") || n.ends_with("_END") || n.starts_with("P1_") || n.starts_with("P2_") => {}
            n => {
                if let Some(s) = space {
                    *spaces.entry(s.to_string()).or_default() += 1;
                }
                if NOTABLE.contains(&n) {
                    notable.insert(n.to_string());
                }
            }
        }
    }
    cx.format_set("lump_count", lumps);
    if !maps.is_empty() {
        cx.format_set("map_count", maps.len());
        cx.format_set("maps", maps);
        if udmf {
            cx.format_set("udmf", true);
        }
    }
    if !spaces.is_empty() {
        cx.format_set("namespaces", hist(spaces));
    }
    if !notable.is_empty() {
        cx.format_set("notable_lumps", notable.into_iter().collect::<Vec<_>>());
    }
    cx.physical().entries(lumps);
    Ok(())
}

fn quake_pak(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 12)?;
    let (dir, len) = (u64::from(le32(&h, 4)), u64::from(le32(&h, 8)));
    let d = read_at(src, dir, len)?;
    let mut files = Files::default();
    let mut maps = Vec::new();
    for e in d.as_chunks::<64>().0.iter().take(MAX_ENTRIES) {
        let name = fixed(&e[..56]).unwrap_or_default();
        if let Some(m) = name.strip_prefix("maps/").and_then(|m| m.strip_suffix(".bsp"))
            && maps.len() < 500
        {
            maps.push(m.to_string());
        }
        files.add(&name, u64::from(le32(e, 60)));
    }
    if !maps.is_empty() {
        cx.format_set("maps", maps);
    }
    files.report(cx);
    Ok(())
}

/// Parse the entity lump: `{ "key" "value" … }` blocks.
fn entities(text: &str) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<(String, String)>> = None;
    let mut key: Option<String> = None;
    let mut rest = text;
    while let Some(i) = rest.find(['{', '}', '"']) {
        let c = rest.as_bytes()[i];
        rest = &rest[i + 1..];
        match c {
            b'{' => cur = Some(Vec::new()),
            b'}' => {
                if let Some(e) = cur.take()
                    && out.len() < 100_000
                {
                    out.push(e);
                }
                key = None;
            }
            _ => {
                let end = rest.find('"').unwrap_or(rest.len());
                let s = rest[..end].to_string();
                rest = rest.get(end + 1..).unwrap_or("");
                if let Some(e) = cur.as_mut() {
                    match key.take() {
                        None => key = Some(s),
                        Some(k) => {
                            if e.len() < 200 {
                                e.push((k, s));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// (game, lump table offset, lump count, then (lump, element size) for
/// models, faces, vertices and textures); lump 0 is the entities.
type Layout = (&'static str, usize, usize, [(usize, usize); 4]);

fn bsp(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, 0x410.min(usize::try_from(len).unwrap_or(0)))?;
    let magic = h.get(..4).unwrap_or(&[]);
    let version = le32(&h, 4);
    let (game, table, lumps, counts): Layout = match magic {
        b"IBSP" if version == 38 => ("Quake II", 8, 19, [(13, 48), (6, 20), (2, 12), (5, 76)]),
        b"IBSP" => ("Quake III", 8, 17, [(7, 40), (13, 104), (10, 44), (1, 72)]),
        b"VBSP" => ("Source", 8, 64, [(14, 48), (7, 56), (3, 12), (2, 32)]),
        b"BSP2" | b"2PSB" => ("Quake (BSP2)", 4, 15, [(14, 64), (7, 28), (3, 12), (2, 0)]),
        _ => {
            let v = le32(&h, 0);
            let game = if v == 30 { "Half-Life" } else { "Quake" };
            (game, 4, 15, [(14, 64), (7, 20), (3, 12), (2, 0)])
        }
    };
    cx.format_set("game", game);
    match magic {
        b"IBSP" | b"VBSP" => cx.format_set("version", version),
        b"BSP2" | b"2PSB" => {}
        _ => cx.format_set("version", le32(&h, 0)),
    }
    let stride = if magic == b"VBSP" { 16 } else { 8 };
    let lump = |i: usize| -> (u64, u64) {
        let at = table + i * stride;
        (u64::from(le32(&h, at)), u64::from(le32(&h, at + 4)))
    };
    if magic == b"VBSP" {
        cx.format_set("map_revision", le32(&h, 8 + 64 * 16));
    }
    let names = ["models", "faces", "vertices", "textures"];
    for ((i, size), name) in counts.into_iter().zip(names) {
        if i >= lumps {
            continue;
        }
        let (off, n) = lump(i);
        if size > 0 {
            cx.format_set(&format!("{name}_count"), n / size as u64);
        } else if n >= 4 && off < len {
            // Quake textures: the lump starts with the count.
            let c = src.read_vec(off, 4)?;
            cx.format_set(&format!("{name}_count"), le32(&c, 0));
        }
    }
    let (off, n) = lump(0);
    if n == 0 || off >= len {
        return Ok(());
    }
    let raw = read_at(src, off, n)?;
    if raw.starts_with(b"LZMA") {
        cx.format_set("entities_compressed", true);
        return Ok(());
    }
    let text = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())]).into_owned();
    let ents = entities(&text);
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    for e in &ents {
        if let Some((_, c)) = e.iter().find(|(k, _)| k == "classname") {
            bump(&mut classes, c, 200);
        }
    }
    cx.format_set("entity_count", ents.len());
    cx.format_set("entity_classes", hist(classes));
    if let Some(world) = ents.iter().find(|e| e.iter().any(|(k, v)| k == "classname" && v == "worldspawn")) {
        let mut w = Map::new();
        for (k, v) in world {
            let key = match k.as_str() {
                "message" => "title",
                "wad" => "wads",
                "sky" | "skyname" => "sky",
                "_generator" | "mapversion" | "worldtype" | "sounds" | "music" | "author" | "maxrange" => k.as_str(),
                _ => continue,
            };
            let v = truncate_chars(v, 500);
            if key == "title" {
                let t = v.replace("\\n", " ").trim().to_string();
                cx.emit_text(TextRole::Title, &t);
                cx.content().title(t);
            }
            if key == "wads" {
                // Paths of the texture WADs: only their file names.
                let wads: Vec<Value> = v
                    .split(';')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.rsplit(['/', '\\']).next().unwrap_or(s).to_string().into())
                    .collect();
                w.insert(key.into(), wads.into());
            } else {
                w.insert(key.into(), v.into());
            }
        }
        if !w.is_empty() {
            cx.format_set("worldspawn", w);
        }
    }
    Ok(())
}

fn vpk(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 28.min(usize::try_from(src.len()).unwrap_or(0)))?;
    let version = le32(&h, 4);
    let tree = u64::from(le32(&h, 8));
    let header = if version == 2 { 28 } else { 12 };
    cx.format_set("version", version);
    if version == 2 && le32(&h, 24) > 0 {
        cx.security().signed(true);
        cx.format_set("signed", true);
    }
    let t = read_at(src, header, tree)?;
    let mut r = ByteReader::new(&t);
    let mut files = Files::default();
    let mut chunks = BTreeSet::new();
    let mut preload = 0u64;
    let s = |r: &mut ByteReader<'_>| r.cstr().map(|b| String::from_utf8_lossy(b).into_owned());
    'ext: loop {
        let ext = s(&mut r)?;
        if ext.is_empty() {
            break;
        }
        loop {
            let path = s(&mut r)?;
            if path.is_empty() {
                break;
            }
            loop {
                let name = s(&mut r)?;
                if name.is_empty() {
                    break;
                }
                r.advance(4)?;
                let pre = r.le_u16()?;
                let index = r.le_u16()?;
                r.advance(4)?;
                let size = r.le_u32()?;
                r.advance(2)?;
                r.advance(usize::from(pre))?;
                preload += u64::from(pre);
                if index != 0x7FFF && chunks.len() < 10_000 {
                    chunks.insert(index);
                }
                let full = if path.trim() == "" { format!("{name}.{ext}") } else { format!("{path}/{name}.{ext}") };
                files.add(&full, u64::from(size) + u64::from(pre));
                if files.count >= MAX_ENTRIES as u64 {
                    break 'ext;
                }
            }
        }
    }
    cx.format_set("archive_chunks", chunks.len());
    if preload > 0 {
        cx.format_set("preload_bytes", preload);
    }
    files.report(cx);
    Ok(())
}

fn bsa(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 36)?;
    let version = le32(&h, 4);
    let flags = le32(&h, 12);
    let (folders, count) = (le32(&h, 16) as usize, le32(&h, 20) as usize);
    let (folder_names, file_names) = (u64::from(le32(&h, 24)), u64::from(le32(&h, 28)));
    let file_flags = u32::from(u16::from_le_bytes([h[32], h[33]]));
    cx.format_set(
        "version",
        match version {
            103 => "103 (Oblivion)",
            104 => "104 (Fallout 3, New Vegas, Skyrim)",
            105 => "105 (Skyrim Special Edition)",
            _ => "unknown",
        },
    );
    cx.format_set("folder_count", folders);
    let mut f = Vec::new();
    for (bit, name) in [
        (1, "folder names"),
        (2, "file names"),
        (4, "compressed"),
        (0x40, "Xbox 360"),
        (0x100, "embedded file names"),
        (0x200, "XMem codec"),
    ] {
        if flags & bit != 0 {
            f.push(name);
        }
    }
    cx.format_set("flags", f);
    let kinds: Vec<&str> = ["meshes", "textures", "menus", "sounds", "voices", "shaders", "trees", "fonts", "misc"]
        .iter()
        .enumerate()
        .filter(|(i, _)| file_flags & (1 << i) != 0)
        .map(|(_, k)| *k)
        .collect();
    if !kinds.is_empty() {
        cx.format_set("content_types", kinds);
    }
    let folder_rec: usize = if version == 105 { 24 } else { 16 };
    let records = 36 + (folders as u64) * folder_rec as u64;
    // The folder records give each folder's file count; then each folder:
    // its name (when stored, a length-prefixed string) and 16-byte file
    // records; then the file names, NUL-separated.
    let table = read_at(src, 36, (folders.min(MAX_ENTRIES) * folder_rec) as u64)?;
    let counts: Vec<usize> = table.chunks_exact(folder_rec).map(|r| le32(r, 8) as usize).collect();
    let block_len = (if flags & 1 != 0 { folder_names + folders as u64 } else { 0 }) + count as u64 * 16;
    let block = read_at(src, records, block_len)?;
    let mut dirs = Vec::new();
    let mut at = 0usize;
    for n in &counts {
        let mut name = String::new();
        if flags & 1 != 0
            && let Some(&len) = block.get(at)
        {
            let raw = block.get(at + 1..at + 1 + usize::from(len)).unwrap_or(&[]);
            name = String::from_utf8_lossy(raw.strip_suffix(&[0]).unwrap_or(raw)).into_owned();
            at += 1 + usize::from(len);
        }
        at = at.saturating_add(n.saturating_mul(16));
        dirs.push((name, *n));
    }
    let mut files = Files::default();
    if flags & 2 != 0 {
        let names = read_at(src, records + block_len, file_names)?;
        let mut names = names.split(|&c| c == 0).filter(|n| !n.is_empty());
        'all: for (dir, n) in &dirs {
            for _ in 0..*n {
                let Some(f) = names.next() else { break 'all };
                let f = String::from_utf8_lossy(f);
                files.add(&if dir.is_empty() { f.into_owned() } else { format!("{dir}\\{f}") }, 0);
                if files.count >= MAX_ENTRIES as u64 {
                    break 'all;
                }
            }
        }
    }
    if files.count == 0 {
        files.count = count as u64;
    }
    files.report(cx);
    Ok(())
}

fn ba2(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 24)?;
    let version = le32(&h, 4);
    let kind = String::from_utf8_lossy(&h[8..12]).into_owned();
    let count = le32(&h, 12) as usize;
    let names_at = le64(&h, 16);
    cx.format_set("version", version);
    cx.format_set(
        "archive_type",
        match kind.as_str() {
            "GNRL" => "general",
            "DX10" => "textures (DirectX 10)",
            "GNMF" => "textures (GNM, PlayStation 4)",
            _ => "unknown",
        },
    );
    let mut files = Files::default();
    if names_at > 0 && names_at < src.len() {
        let rest = src.len() - names_at;
        let d = read_at(src, names_at, rest)?;
        let mut r = ByteReader::new(&d);
        for _ in 0..count.min(MAX_ENTRIES) {
            let Ok(n) = r.le_u16() else { break };
            let Ok(name) = r.bytes(usize::from(n)) else { break };
            files.add(&String::from_utf8_lossy(name), 0);
        }
    }
    if files.count == 0 {
        files.count = count as u64;
    }
    files.report(cx);
    Ok(())
}

/// RGSS3A index: offset, size, file key and name length scrambled with the
/// archive key; names with its bytes in turn.
fn rgss3(b: &[u8], files: &mut Files) {
    let Some(k) = b.get(8..12) else { return };
    let key = u32::from_le_bytes(k.try_into().unwrap_or_default()).wrapping_mul(9).wrapping_add(3);
    let mut at = 12usize;
    while files.count < MAX_ENTRIES as u64 {
        let Some(e) = b.get(at..at + 16) else { break };
        let word = |i: usize| u32::from_le_bytes(e[i..i + 4].try_into().unwrap_or_default()) ^ key;
        let (offset, size, len) = (word(0), word(4), word(12) as usize);
        if offset == 0 || len > 4096 {
            break;
        }
        at += 16;
        let Some(n) = b.get(at..at + len) else { break };
        let name: Vec<u8> = n.iter().enumerate().map(|(i, &c)| c ^ key.to_le_bytes()[i % 4]).collect();
        at += len;
        files.add(&String::from_utf8_lossy(&name), u64::from(size));
    }
}

fn rgssad(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 8)?;
    let version = h[7];
    cx.format_set("version", version);
    let engine = match (version, cx.format_id()) {
        (3, _) => "RPG Maker VX Ace",
        _ => match src.name_hint().and_then(|n| n.rsplit('.').next()).map(str::to_ascii_lowercase).as_deref() {
            Some("rgss2a") => "RPG Maker VX",
            _ => "RPG Maker XP",
        },
    };
    cx.format_set("engine", engine);
    let mut files = Files::default();
    if version == 3 {
        // The index comes first; read it whole up to the directory cap.
        let (b, _) = src.read_prefix(MAX_DIR)?;
        rgss3(&b, &mut files);
    } else {
        // v1 interleaves names and data: walk it entry by entry.
        let len = src.len();
        let mut key: u32 = 0xDEAD_CAFE;
        let step = |k: &mut u32| *k = k.wrapping_mul(7).wrapping_add(3);
        let mut at = 8u64;
        while at + 8 <= len && files.count < MAX_ENTRIES as u64 {
            cx.checkpoint()?;
            let n = src.read_vec(at, 4)?;
            let name_len = u64::from(le32(&n, 0) ^ key);
            step(&mut key);
            if name_len > 4096 || at + 8 + name_len > len {
                break;
            }
            let raw = src.read_vec(at + 4, usize::try_from(name_len + 4).unwrap_or(0))?;
            let name: Vec<u8> = raw[..raw.len() - 4]
                .iter()
                .map(|&c| {
                    let v = c ^ (key & 0xFF) as u8;
                    step(&mut key);
                    v
                })
                .collect();
            let size = le32(&raw, raw.len() - 4) ^ key;
            step(&mut key);
            files.add(&String::from_utf8_lossy(&name), u64::from(size));
            at += 8 + name_len + u64::from(size);
        }
    }
    files.report(cx);
    Ok(())
}

fn rpa(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 64.min(usize::try_from(src.len()).unwrap_or(0)))?;
    let line = String::from_utf8_lossy(&h[..h.iter().position(|&c| c == b'\n').unwrap_or(h.len())]).into_owned();
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("").trim_start_matches("RPA-").to_string();
    cx.format_set("version", version.clone());
    let offset = parts.next().and_then(|o| u64::from_str_radix(o, 16).ok());
    let Some(offset) = offset else {
        return Err(ExtractError::Malformed("RPA header without an index offset".into()));
    };
    let rest = src.len().saturating_sub(offset);
    let z = read_at(src, offset, rest)?;
    let max = cx.parse_limit();
    let index = cx.decompress(&z, Codec::Zlib, max)?.data;
    let names: Vec<String> = super::super::data::binser::pickle::strings(&index)
        .into_iter()
        .filter(|s| !s.is_empty() && s != "latin1" && s.contains('.'))
        .collect();
    let mut files = Files::default();
    for n in &names {
        files.add(n, 0);
    }
    files.report(cx);
    Ok(())
}

fn godot_pck(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let (b, _) = src.read_prefix(MAX_DIR)?;
    let mut r = ByteReader::new(&b);
    r.tag(b"GDPC")?;
    let format = r.le_u32()?;
    let (major, minor, patch) = (r.le_u32()?, r.le_u32()?, r.le_u32()?);
    cx.format_set("pack_format", format);
    cx.format_set("engine_version", format!("{major}.{minor}.{patch}"));
    let mut dir_at = None;
    if format >= 2 {
        let flags = r.le_u32()?;
        r.advance(8)?;
        if format >= 3 {
            dir_at = Some(r.le_u64()?);
        }
        if flags & 1 != 0 {
            cx.format_set("encrypted_directory", true);
            cx.security().encrypted(true);
            return Ok(());
        }
    }
    r.advance(16 * 4)?;
    if let Some(at) = dir_at {
        r.seek(usize::try_from(at).map_err(|_| ExtractError::Malformed("directory offset".into()))?)?;
    }
    let count = r.le_u32()? as usize;
    let mut files = Files::default();
    let mut encrypted = 0u64;
    for _ in 0..count.min(MAX_ENTRIES) {
        let n = r.le_u32()? as usize;
        let path = r.bytes(n)?;
        let path =
            String::from_utf8_lossy(&path[..path.iter().position(|&c| c == 0).unwrap_or(path.len())]).into_owned();
        r.advance(8)?;
        let size = r.le_u64()?;
        r.advance(16)?;
        if format >= 2 && r.le_u32()? & 1 != 0 {
            encrypted += 1;
        }
        files.add(path.strip_prefix("res://").unwrap_or(&path), size);
    }
    if encrypted > 0 {
        cx.format_set("encrypted_files", encrypted);
        cx.physical().encrypted_entries(encrypted);
    }
    files.report(cx);
    Ok(())
}

/// The Unreal pak footer magic (little-endian).
const PAK_MAGIC: [u8; 4] = [0xE1, 0x12, 0x6F, 0x5A];

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
        return Ok(String::from_utf16_lossy(&units));
    }
    let b = r.bytes(n.unsigned_abs() as usize)?;
    Ok(String::from_utf8_lossy(&b[..b.len().saturating_sub(1)]).into_owned())
}

fn unreal_pak(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let tail_len = len.min(512);
    let tail = src.read_vec(len - tail_len, usize::try_from(tail_len).unwrap_or(0))?;
    // The footer ends with the index hash (20 bytes), sometimes a frozen
    // index flag and compression method names: find the last magic.
    let at = tail.windows(4).rposition(|w| w == PAK_MAGIC).ok_or(ExtractError::Malformed("no pak footer".into()))?;
    let f = &tail[at..];
    let version = le32(f, 4);
    let index_at = le64(f, 8);
    let index_len = le64(f, 16);
    cx.format_set("version", version);
    let encrypted = version >= 4 && at > 0 && tail[at - 1] == 1;
    if version >= 7 && at >= 17 && tail[at - 17..at - 1].iter().any(|&c| c != 0) {
        cx.format_set("encryption_key_guid", super::hex(&tail[at - 17..at - 1]));
    }
    if version >= 8 {
        let names: Vec<String> =
            f.get(44 + usize::from(version == 9)..).unwrap_or(&[]).chunks(32).filter_map(fixed).collect();
        if !names.is_empty() {
            cx.format_set("compression_methods", names);
        }
    }
    if encrypted {
        cx.format_set("encrypted_index", true);
        cx.security().encrypted(true);
        return Ok(());
    }
    let d = read_at(src, index_at, index_len)?;
    let mut r = ByteReader::new(&d);
    let mount = fstring(&mut r)?;
    cx.format_set("mount_point", truncate_chars(&mount, 300));
    let count = r.le_u32()? as usize;
    let mut files = Files::default();
    if version >= 10 {
        // The path hash index and the full directory index live elsewhere.
        r.advance(8)?;
        if r.le_u32()? != 0 {
            r.advance(8 + 8 + 20)?;
        }
        if r.le_u32()? != 0 {
            let (off, size) = (r.le_u64()?, r.le_u64()?);
            let dir = read_at(src, off, size)?;
            let mut dr = ByteReader::new(&dir);
            let dirs = dr.le_u32()?;
            for _ in 0..dirs.min(1_000_000) {
                let dname = fstring(&mut dr)?;
                let n = dr.le_u32()?;
                for _ in 0..n.min(1_000_000) {
                    let fname = fstring(&mut dr)?;
                    dr.advance(4)?;
                    files.add(&format!("{}{fname}", dname.trim_start_matches('/')), 0);
                }
            }
        }
        if files.count == 0 {
            files.count = count as u64;
        }
    } else {
        // Each entry: its name, then a record whose size depends on the
        // version and on compression blocks.
        for _ in 0..count.min(MAX_ENTRIES) {
            let Ok(name) = fstring(&mut r) else { break };
            let Ok(_offset) = r.le_u64() else { break };
            let Ok(_size) = r.le_u64() else { break };
            let Ok(raw) = r.le_u64() else { break };
            let Ok(method) = r.le_u32() else { break };
            if version <= 1 && r.advance(8).is_err() {
                break;
            }
            if r.advance(20).is_err() {
                break;
            }
            if version >= 3 {
                if method != 0 {
                    let Ok(blocks) = r.le_u32() else { break };
                    if r.advance(blocks as usize * 16).is_err() {
                        break;
                    }
                }
                if r.advance(1 + 4).is_err() {
                    break;
                }
            }
            files.add(&name, raw);
        }
    }
    files.report(cx);
    Ok(())
}

impl Extractor for Archive {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        // Quake (29) and Half-Life (30) BSPs: the version, then a lump table
        // whose first lump (entities) starts right after it.
        let lumps_fit = || {
            (0..15).all(|i| {
                let (off, n) = (u64::from(le32(h, 4 + i * 8)), u64::from(le32(h, 8 + i * 8)));
                (n == 0 || off >= 4 + 15 * 8) && off + n <= probe.len
            })
        };
        if [b"IBSP", b"VBSP", b"BSP2", b"2PSB"].iter().any(|m| h.starts_with(*m)) {
            return Some(Sniff { format: "bsp", confidence: 0.97 });
        }
        if ext == "bsp" && h.len() >= 124 && matches!(le32(h, 0), 29 | 30) && lumps_fit() {
            return Some(Sniff { format: "bsp", confidence: 0.97 });
        }
        if ext == "pak" && !h.starts_with(b"PACK") && probe.tail.windows(4).any(|w| w == PAK_MAGIC) {
            return Some(Sniff { format: "unreal_pak", confidence: 0.97 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "wad" => wad(cx, src),
            "quake_pak" => quake_pak(cx, src),
            "bsp" => bsp(cx, src),
            "vpk" => vpk(cx, src),
            "bsa" => bsa(cx, src),
            "ba2" => ba2(cx, src),
            "rgssad" => rgssad(cx, src),
            "rpa" => rpa(cx, src),
            "godot_pck" => godot_pck(cx, src),
            _ => unreal_pak(cx, src),
        }
    }
}

crate::register_extractor!(Archive);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_lump() {
        let e = entities("{\n\"classname\" \"worldspawn\"\n\"message\" \"Tide Pools\"\n}\n{ \"classname\" \"light\" }");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0][1], ("message".to_string(), "Tide Pools".to_string()));
    }

    crate::fixture_tests!("wad", "quake_pak", "bsp", "vpk", "bsa", "ba2", "rgssad", "rpa", "godot_pck", "unreal_pak");
}
