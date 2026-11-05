//! Minecraft files:
//! * region files (`.mca`, `.mcr`): chunks present, the region's
//!   coordinates, when chunks were last saved, chunk compression, and from
//!   the first chunk its data version and status;
//! * Sponge schematics (`.schem`, v1–v3), Litematica (`.litematic`) and
//!   `MCEdit` / Schematica (`.schematic`) schematics: name, author,
//!   description, dates, size, regions, blocks, palette, entities, the
//!   game's data version;
//! * `level.dat` (Java gzip NBT and Bedrock little-endian NBT): world
//!   name, game version, data version, game mode, difficulty, hardcore,
//!   last played, spawn, server brands, modded.
//!
//! The NBT is read with limits on depth and size. Specifications: the
//! Minecraft wiki (NBT format, Region file format, Java Edition level
//! format, Bedrock level format); Sponge Schematic Specification v1–v3;
//! Litematica `LitematicaSchematic`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for Minecraft files.
pub struct Minecraft;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.minecraft",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        // No signature: the chunk location table is checked.
        FormatSpec {
            id: "mca",
            name: "Minecraft region file",
            family: "game",
            mimes: &[],
            extensions: &["mca", "mcr"],
            magic: &[],
            parent: None,
        },
        // Gzip-compressed NBT: sniffed (`.schematic` and `.litematic`
        // otherwise go to the generic NBT reader).
        FormatSpec {
            id: "minecraft_schematic",
            name: "Minecraft schematic (Sponge, Litematica, MCEdit)",
            family: "game",
            mimes: &[],
            extensions: &["schem"],
            magic: &[],
            parent: Some("gzip"),
        },
        FormatSpec {
            id: "minecraft_level",
            name: "Minecraft world (level.dat)",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_DEPTH: usize = 64;
const MAX_TAGS: u64 = 2_000_000;
const MAX_LIST: usize = 256;

/// A parsed NBT value (arrays as their length, floats without their value;
/// lists capped).
#[derive(Debug, Clone)]
enum Tag {
    Int(i64),
    Float,
    Str(String),
    Array(u64),
    List(Vec<Tag>, u64),
    Compound(Vec<(String, Tag)>),
}

impl Tag {
    fn get(&self, key: &str) -> Option<&Tag> {
        match self {
            Tag::Compound(v) => v.iter().find(|(k, _)| k == key).map(|(_, t)| t),
            _ => None,
        }
    }
    fn int(&self) -> Option<i64> {
        match self {
            Tag::Int(i) => Some(*i),
            _ => None,
        }
    }
    fn str(&self) -> Option<&str> {
        match self {
            Tag::Str(s) => Some(s),
            _ => None,
        }
    }
    fn len(&self) -> u64 {
        match self {
            Tag::Array(n) | Tag::List(_, n) => *n,
            Tag::Compound(v) => v.len() as u64,
            _ => 0,
        }
    }
    fn path(&self, keys: &[&str]) -> Option<&Tag> {
        keys.iter().try_fold(self, |t, k| t.get(k))
    }
}

struct Nbt<'a> {
    b: &'a [u8],
    at: usize,
    little: bool,
    tags: u64,
}

impl Nbt<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], ExtractError> {
        let s = self
            .b
            .get(self.at..self.at.saturating_add(n))
            .ok_or(ExtractError::Truncated { offset: self.at as u64, needed: n as u64 })?;
        self.at += n;
        Ok(s)
    }
    fn int(&mut self, n: usize) -> Result<i64, ExtractError> {
        let little = self.little;
        let s = self.take(n)?;
        let mut v: i64 = 0;
        if little {
            for &c in s.iter().rev() {
                v = v << 8 | i64::from(c);
            }
        } else {
            for &c in s {
                v = v << 8 | i64::from(c);
            }
        }
        // Sign-extend.
        let shift = 64 - 8 * u32::try_from(n).unwrap_or(8);
        Ok(if n < 8 { (v << shift) >> shift } else { v })
    }
    fn string(&mut self) -> Result<String, ExtractError> {
        let n = usize::try_from(self.int(2)? & 0xFFFF).unwrap_or(0);
        Ok(truncate_chars(&String::from_utf8_lossy(self.take(n)?), 1000))
    }
    fn len(&mut self) -> Result<usize, ExtractError> {
        Ok(usize::try_from(self.int(4)?.max(0)).unwrap_or(0))
    }
    fn payload(&mut self, t: u8, depth: usize) -> Result<Tag, ExtractError> {
        self.tags += 1;
        if self.tags > MAX_TAGS || depth > MAX_DEPTH {
            return Err(ExtractError::LimitExceeded("NBT nesting or size".into()));
        }
        Ok(match t {
            1 => Tag::Int(self.int(1)?),
            2 => Tag::Int(self.int(2)?),
            3 => Tag::Int(self.int(4)?),
            4 => Tag::Int(self.int(8)?),
            // Floats are not reported.
            5 => {
                self.take(4)?;
                Tag::Float
            }
            6 => {
                self.take(8)?;
                Tag::Float
            }
            7 | 11 | 12 => {
                let n = self.len()?;
                let w = match t {
                    7 => 1,
                    11 => 4,
                    _ => 8,
                };
                self.take(n.saturating_mul(w))?;
                Tag::Array(n as u64)
            }
            8 => Tag::Str(self.string()?),
            9 => {
                let et = self.take(1)?[0];
                let n = self.len()?;
                let mut items = Vec::new();
                for i in 0..n {
                    let v = self.payload(et, depth + 1)?;
                    if i < MAX_LIST {
                        items.push(v);
                    }
                }
                Tag::List(items, n as u64)
            }
            10 => {
                let mut items = Vec::new();
                loop {
                    let ct = self.take(1)?[0];
                    if ct == 0 {
                        break;
                    }
                    let name = self.string()?;
                    let v = self.payload(ct, depth + 1)?;
                    items.push((name, v));
                }
                Tag::Compound(items)
            }
            _ => return Err(ExtractError::Malformed(format!("NBT tag type {t}"))),
        })
    }
    /// The root: a named compound.
    fn root(&mut self) -> Result<(String, Tag), ExtractError> {
        let t = self.take(1)?[0];
        if t != 10 {
            return Err(ExtractError::Malformed("NBT root is not a compound".into()));
        }
        let name = self.string()?;
        Ok((name, self.payload(10, 0)?))
    }
}

fn parse(b: &[u8], little: bool) -> Result<(String, Tag), ExtractError> {
    Nbt { b, at: 0, little, tags: 0 }.root()
}

fn ms_date(ms: i64) -> Option<String> {
    super::unix_time(ms.div_euclid(1000))
}

fn region(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, 8192)?;
    let mut chunks = 0u64;
    let (mut oldest, mut newest) = (i64::MAX, 0i64);
    let mut first = None;
    for i in 0..1024 {
        let loc = &h[i * 4..i * 4 + 4];
        let offset = u64::from(u32::from_be_bytes([0, loc[0], loc[1], loc[2]])) * 4096;
        if offset == 0 || loc[3] == 0 {
            continue;
        }
        chunks += 1;
        let ts = i64::from(u32::from_be_bytes(h[4096 + i * 4..4100 + i * 4].try_into().unwrap_or_default()));
        if ts > 0 {
            oldest = oldest.min(ts);
            newest = newest.max(ts);
        }
        if first.is_none() && offset + 5 <= len {
            first = Some(offset);
        }
    }
    cx.format_set("chunk_count", chunks);
    if let Some(name) = src.name_hint()
        && let Some(rest) = name.strip_prefix("r.")
    {
        let mut p = rest.split('.');
        if let (Some(x), Some(z)) =
            (p.next().and_then(|v| v.parse::<i64>().ok()), p.next().and_then(|v| v.parse::<i64>().ok()))
        {
            cx.format_set("region", vec![x, z]);
            cx.format_set("block_range", vec![x * 512, z * 512, x * 512 + 511, z * 512 + 511]);
        }
    }
    if newest > 0 {
        if let Some(d) = ms_date(oldest * 1000) {
            cx.format_set("oldest_chunk_saved", d);
        }
        if let Some(d) = ms_date(newest * 1000) {
            cx.temporal().content_date(DateField::Modified, d.clone(), true);
            cx.format_set("newest_chunk_saved", d);
        }
    }
    let Some(at) = first else { return Ok(()) };
    let head = src.read_vec(at, 5)?;
    let n = u64::from(u32::from_be_bytes([head[0], head[1], head[2], head[3]]));
    let method = head[4];
    cx.format_set(
        "chunk_compression",
        match method {
            1 => "gzip",
            2 => "zlib",
            3 => "none",
            4 => "LZ4",
            127 => "custom",
            _ => "unknown",
        },
    );
    if n < 1 || at + 4 + n > len || n > 16 << 20 {
        return Ok(());
    }
    let data = src.read_vec(at + 5, usize::try_from(n - 1).unwrap_or(0))?;
    let nbt = match method {
        1 => cx.decompress(&data, Codec::Gzip, 64 << 20)?.data,
        2 => cx.decompress(&data, Codec::Zlib, 64 << 20)?.data,
        3 => data,
        _ => return Ok(()),
    };
    let (_, root) = parse(&nbt, false)?;
    // Before 1.18 the chunk sits under `Level`.
    let level = root.get("Level").unwrap_or(&root);
    if let Some(v) = root.get("DataVersion").and_then(Tag::int) {
        cx.format_set("data_version", v);
    }
    if let Some(s) = level.get("Status").and_then(Tag::str) {
        cx.format_set("first_chunk_status", s);
    }
    Ok(())
}

fn size3(t: &Tag) -> Option<Vec<i64>> {
    ["x", "y", "z"].iter().map(|k| t.get(k).and_then(Tag::int).map(i64::abs)).collect()
}

fn schematic(cx: &mut Context<'_>, name: &str, root: &Tag) {
    let mut m = Map::new();
    let set = |m: &mut Map<String, Value>, k: &str, v: Option<Value>| {
        if let Some(v) = v {
            m.insert(k.into(), v);
        }
    };
    let (kind, meta) = if root.get("Regions").is_some() {
        ("Litematica", root.get("Metadata"))
    } else if root.get("Materials").is_some()
        || name == "Schematic" && root.get("Version").is_none() && root.get("Schematic").is_none()
    {
        ("MCEdit / Schematica", None)
    } else {
        ("Sponge", None)
    };
    // Sponge v3 nests everything under `Schematic`.
    let s = root.get("Schematic").unwrap_or(root);
    m.insert("kind".into(), kind.into());
    match kind {
        "Litematica" => {
            set(&mut m, "version", root.get("Version").and_then(Tag::int).map(Value::from));
            set(&mut m, "data_version", root.get("MinecraftDataVersion").and_then(Tag::int).map(Value::from));
            if let Some(md) = meta {
                let regions = root.get("Regions").map_or(0, Tag::len);
                m.insert("region_count".into(), regions.into());
                if let Some(Tag::Compound(r)) = root.get("Regions") {
                    let names: Vec<Value> = r.iter().take(50).map(|(k, _)| k.clone().into()).collect();
                    m.insert("regions".into(), names.into());
                }
                set(&mut m, "size", md.get("EnclosingSize").and_then(size3).map(Value::from));
                set(&mut m, "total_blocks", md.get("TotalBlocks").and_then(Tag::int).map(Value::from));
                set(&mut m, "total_volume", md.get("TotalVolume").and_then(Tag::int).map(Value::from));
                meta_fields(cx, &mut m, md, ["Name", "Author", "Description", "TimeCreated", "TimeModified"]);
            }
        }
        "Sponge" => {
            let version = s.get("Version").and_then(Tag::int);
            set(&mut m, "version", version.map(Value::from));
            set(&mut m, "data_version", s.get("DataVersion").and_then(Tag::int).map(Value::from));
            let dims: Option<Vec<i64>> =
                ["Width", "Height", "Length"].iter().map(|k| s.get(k).and_then(Tag::int)).collect();
            set(&mut m, "size", dims.map(Value::from));
            // v3 moves the palette and block entities under `Blocks`.
            let blocks = s.get("Blocks").unwrap_or(s);
            if let Some(p) = blocks.get("Palette") {
                m.insert("palette_size".into(), p.len().into());
                if let Tag::Compound(entries) = p {
                    let mut ns: BTreeMap<String, u64> = BTreeMap::new();
                    for (k, _) in entries {
                        bump(&mut ns, k.split(':').next().unwrap_or("minecraft"), 50);
                    }
                    m.insert("block_namespaces".into(), hist(ns));
                }
            }
            if let Some(e) = blocks.get("BlockEntities").or_else(|| s.get("TileEntities")) {
                m.insert("block_entity_count".into(), e.len().into());
            }
            if let Some(e) = s.get("Entities") {
                m.insert("entity_count".into(), e.len().into());
            }
            if let Some(md) = s.get("Metadata") {
                meta_fields(cx, &mut m, md, ["Name", "Author", "", "Date", ""]);
                if let Some(Tag::List(mods, _)) = md.get("RequiredMods") {
                    let v: Vec<Value> = mods.iter().filter_map(Tag::str).map(Value::from).collect();
                    m.insert("required_mods".into(), v.into());
                }
            }
        }
        _ => {
            let dims: Option<Vec<i64>> =
                ["Width", "Height", "Length"].iter().map(|k| s.get(k).and_then(Tag::int)).collect();
            set(&mut m, "size", dims.map(Value::from));
            set(&mut m, "materials", s.get("Materials").and_then(Tag::str).map(Value::from));
            if let Some(e) = s.get("Entities") {
                m.insert("entity_count".into(), e.len().into());
            }
            if let Some(e) = s.get("TileEntities") {
                m.insert("block_entity_count".into(), e.len().into());
            }
        }
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
}

/// Name, author, description and dates from a metadata compound.
/// `keys`: name, author, description, created and modified ("" when absent).
fn meta_fields(cx: &mut Context<'_>, m: &mut Map<String, Value>, md: &Tag, keys: [&str; 5]) {
    let [name, author, desc, created, modified] = keys;
    if let Some(n) = md.get(name).and_then(Tag::str).filter(|s| !s.is_empty()) {
        cx.content().title(n.to_string());
        m.insert("name".into(), n.into());
    }
    if let Some(a) = md.get(author).and_then(Tag::str).filter(|s| !s.is_empty()) {
        cx.content().author(a.to_string());
        m.insert("author".into(), a.into());
    }
    if !desc.is_empty()
        && let Some(d) = md.get(desc).and_then(Tag::str).filter(|s| !s.is_empty())
    {
        cx.content().description(d.to_string());
        m.insert("description".into(), d.into());
    }
    for (key, field, out) in [(created, DateField::Created, "created"), (modified, DateField::Modified, "modified")] {
        if key.is_empty() {
            continue;
        }
        if let Some(d) = md.get(key).and_then(Tag::int).filter(|&t| t > 0).and_then(ms_date) {
            cx.temporal().content_date(field, d.clone(), true);
            m.insert(out.into(), d.into());
        }
    }
}

fn level(cx: &mut Context<'_>, root: &Tag, bedrock: bool) {
    let d = root.get("Data").unwrap_or(root);
    let mut m = Map::new();
    m.insert("edition".into(), if bedrock { "Bedrock" } else { "Java" }.into());
    if let Some(n) = d.get("LevelName").and_then(Tag::str) {
        cx.content().title(n.to_string());
        m.insert("level_name".into(), n.into());
    }
    if let Some(v) = d.path(&["Version", "Name"]).and_then(Tag::str) {
        m.insert("game_version".into(), v.into());
    }
    if bedrock && let Some(Tag::List(v, _)) = d.get("lastOpenedWithVersion") {
        let parts: Vec<String> = v.iter().filter_map(Tag::int).map(|i| i.to_string()).collect();
        m.insert("game_version".into(), parts.join(".").into());
    }
    if let Some(v) = d.path(&["Version", "Snapshot"]).and_then(Tag::int) {
        m.insert("snapshot".into(), (v != 0).into());
    }
    if let Some(v) = d.get("DataVersion").and_then(Tag::int) {
        m.insert("data_version".into(), v.into());
    }
    if let Some(g) = d.get("GameType").and_then(Tag::int) {
        let mode = ["survival", "creative", "adventure", "spectator"].get(usize::try_from(g).unwrap_or(9)).copied();
        m.insert("game_mode".into(), mode.map_or_else(|| Value::from(g), Value::from));
    }
    if let Some(v) = d.get("Difficulty").and_then(Tag::int) {
        let diff = ["peaceful", "easy", "normal", "hard"].get(usize::try_from(v).unwrap_or(9)).copied();
        m.insert("difficulty".into(), diff.map_or_else(|| Value::from(v), Value::from));
    }
    for (k, out) in
        [("hardcore", "hardcore"), ("allowCommands", "commands_allowed"), ("commandsEnabled", "commands_allowed")]
    {
        if let Some(v) = d.get(k).and_then(Tag::int) {
            m.insert(out.into(), (v != 0).into());
        }
    }
    if let Some(t) = d.get("LastPlayed").and_then(Tag::int) {
        // Java stores milliseconds, Bedrock seconds.
        if let Some(date) = ms_date(if bedrock { t * 1000 } else { t }) {
            cx.temporal().content_date(DateField::Modified, date.clone(), true);
            m.insert("last_played".into(), date.into());
        }
    }
    let spawn: Option<Vec<i64>> = ["SpawnX", "SpawnY", "SpawnZ"].iter().map(|k| d.get(k).and_then(Tag::int)).collect();
    if let Some(s) = spawn {
        m.insert("spawn".into(), s.into());
    }
    if let Some(Tag::List(b, _)) = d.get("ServerBrands") {
        let v: Vec<Value> = b.iter().filter_map(Tag::str).map(Value::from).collect();
        m.insert("server_brands".into(), v.into());
    }
    if let Some(v) = d.get("WasModded").and_then(Tag::int) {
        m.insert("modded".into(), (v != 0).into());
    }
    if let Some(e) = d.path(&["DataPacks", "Enabled"]) {
        m.insert("data_packs_enabled".into(), e.len().into());
    }
    // A single-player world embeds its player (not reported).
    if d.get("Player").is_some() {
        m.insert("single_player".into(), true.into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
}

/// Gzip-wrapped NBT whose root looks like one of the schematic layouts.
fn schematic_root(t: &Tag) -> bool {
    t.get("Regions").is_some()
        || t.get("Schematic").is_some()
        || (t.get("Width").is_some() && t.get("Length").is_some())
        || t.get("Materials").is_some()
}

impl Extractor for Minecraft {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let gz = h.starts_with(&[0x1F, 0x8B]);
        if matches!(ext, "schem" | "schematic" | "litematic") && gz {
            return Some(Sniff { format: "minecraft_schematic", confidence: 0.97 });
        }
        let name = probe.name.unwrap_or("");
        if (name.ends_with("level.dat") || name == "level.dat_old") && (gz || h.get(8) == Some(&10)) {
            return Some(Sniff { format: "minecraft_level", confidence: 0.97 });
        }
        // Region files: sector-aligned, the location table pointing past
        // the two header sectors.
        if matches!(ext, "mca" | "mcr") && probe.len >= 8192 && probe.len.is_multiple_of(4096) && h.len() >= 4096 {
            let ok = h[..4096].as_chunks::<4>().0.iter().all(|l| {
                let off = u32::from_be_bytes([0, l[0], l[1], l[2]]);
                (off == 0 && l[3] == 0) || (off >= 2 && u64::from(off + u32::from(l[3])) * 4096 <= probe.len)
            });
            return ok.then_some(Sniff { format: "mca", confidence: 0.97 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "mca" {
            return region(cx, src);
        }
        let (b, _) = cx.read_bytes(src)?;
        let (data, bedrock) = if b.starts_with(&[0x1F, 0x8B]) {
            let max = cx.parse_limit();
            (cx.decompress(&b, Codec::Gzip, max)?.data, false)
        } else if id == "minecraft_level" && b.len() > 8 {
            // Bedrock: storage version and length, then little-endian NBT.
            cx.format_set("storage_version", u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            (b[8..].to_vec(), true)
        } else {
            (b, false)
        };
        let (name, root) = parse(&data, bedrock)?;
        if id == "minecraft_level" {
            level(cx, &root, bedrock);
        } else {
            if !schematic_root(&root) {
                cx.warn("the NBT root is not a known schematic layout");
            }
            schematic(cx, &name, &root);
        }
        Ok(())
    }
}

crate::register_extractor!(Minecraft);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbt_and_dates() {
        // {"": {"Width": short 4, "Name": "Pier"}}
        let b = [
            10, 0, 0, //
            2, 0, 5, b'W', b'i', b'd', b't', b'h', 0, 4, //
            8, 0, 4, b'N', b'a', b'm', b'e', 0, 4, b'P', b'i', b'e', b'r', //
            0,
        ];
        let (_, t) = parse(&b, false).unwrap();
        assert_eq!(t.get("Width").and_then(Tag::int), Some(4));
        assert_eq!(t.get("Name").and_then(Tag::str), Some("Pier"));
        assert_eq!(ms_date(1_700_000_000_000).as_deref(), Some("2023-11-14T22:13:20Z"));
        let mut deep = vec![10u8, 0, 0];
        for _ in 0..100 {
            deep.extend([10, 0, 1, b'a']);
        }
        assert!(parse(&deep, false).is_err());
    }

    crate::fixture_tests!("mca", "minecraft_schematic", "minecraft_level");
}
