//! More database and storage files, from their headers and record
//! framing (no record contents are copied):
//!
//! * Realm databases: file format version, the active top reference;
//! * Firebird / InterBase databases: page size, on-disk structure version,
//!   pages, next transaction, creation time;
//! * SQL Server backups (Microsoft Tape Format): media and software name,
//!   media date, MTF version, backup sets (name, description, date); the
//!   backup's user only with `--privacy off`;
//! * Kafka log segments (record batches v0 – v2: batches, records, offset
//!   and timestamp ranges, compression, transactional and control
//!   batches) and their offset / time indexes;
//! * Prometheus TSDB index and chunk files: version, symbols, chunks by
//!   encoding;
//! * Anki decks (`.apkg`, `.colpkg`): collection kind, media files; the
//!   collection is handed on to the SQLite reader.
//!
//! Specifications: Realm Core's file header; Firebird `ods.h`
//! (`header_page`); Microsoft Tape Format 1.00a; Kafka's message format
//! (KIP-98 record batches); Prometheus `tsdb/docs/format` (index, chunks).
//! Anki's package layout is read as Anki writes it.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for the storage files above.
pub struct Stores;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "db", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "db.stores",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("realm", "Realm database", "application/x-realm", ["realm"], [Magic::at(16, b"T-DB")]),
        spec!("firebird", "Firebird / InterBase database", "application/x-firebird", ["fdb", "gdb", "ib"], []),
        spec!("mssql_backup", "SQL Server backup (MTF)", "application/x-mtf", ["bak", "trn"], [Magic::prefix(b"TAPE")]),
        spec!("kafka_log", "Kafka log segment", "application/x-kafka-log", [], []),
        spec!("kafka_index", "Kafka offset / time index", "application/x-kafka-index", ["index", "timeindex"], []),
        spec!(
            "prometheus_tsdb",
            "Prometheus TSDB index / chunks",
            "application/x-prometheus-tsdb",
            [],
            [Magic::prefix(b"\xba\xaa\xd7\x00"), Magic::prefix(b"\x01\x30\xbc\x91")]
        ),
        spec!("anki", "Anki deck package", "application/x-anki", ["apkg", "colpkg"], []),
    ],
};

/// Kafka batches walked at most.
const MAX_BATCHES: u64 = 1_000_000;

impl Extractor for Stores {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        if h.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 100);
            if names.iter().any(|n| n.starts_with("collection.anki2") || n.starts_with("collection.anki21")) {
                return pick("anki", 0.95);
            }
        }
        // Firebird header page: page type 1, then the ODS version (Firebird
        // sets 0x8000) and a power-of-two page size.
        if h.len() >= 64 && h[0] == 1 {
            let size = u16::from_le_bytes([h[16], h[17]]);
            let ods = u16::from_le_bytes([h[18], h[19]]);
            if matches!(size, 1024 | 2048 | 4096 | 8192 | 16_384 | 32_768)
                && matches!(ods & 0x7fff, 8..=13)
                && (ods & 0x8000 != 0 || matches!(ext.as_str(), "gdb" | "ib"))
            {
                return pick("firebird", 0.9);
            }
        }
        // Kafka: a record batch (base offset, length, epoch, magic 2) at 0.
        if h.len() >= 61 && h[16] == 2 {
            let len = i32::from_be_bytes([h[8], h[9], h[10], h[11]]);
            if (49..=16 << 20).contains(&len) && i64::from_be_bytes(h[..8].try_into().ok()?) >= 0 {
                return pick("kafka_log", if ext == "log" { 0.95 } else { 0.7 });
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "anki" {
            return anki(src, cx);
        }
        let name = src.name_hint().map(str::to_string);
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "realm" => realm(cx, &b),
            "firebird" => firebird(cx, &b),
            "mssql_backup" => mtf(cx, &b),
            "kafka_log" => kafka(cx, &b, name.as_deref()),
            "kafka_index" => kafka_index(cx, &b, name.as_deref()),
            _ => tsdb(cx, &b),
        }
        Ok(())
    }
}

crate::register_extractor!(Stores);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
}

/// A UTC timestamp from milliseconds since 1970.
fn millis(ms: i64) -> Option<String> {
    let ticks = (ms.checked_mul(10_000)?).checked_add(116_444_736_000_000_000)?;
    crate::plugin::filetime(u64::try_from(ticks).ok()?)
}

// --- Realm / Firebird ----------------------------------------------------------------------------

fn realm(cx: &mut Context<'_>, b: &[u8]) {
    let flags = b.get(23).copied().unwrap_or(0);
    let slot = usize::from(flags & 1);
    cx.format_set("file_format_version", b.get(20 + slot).copied().unwrap_or(0));
    cx.format_set(
        "top_ref",
        u64::from_le_bytes(b.get(slot * 8..slot * 8 + 8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8])),
    );
    cx.format_set("selected_slot", slot);
}

fn firebird(cx: &mut Context<'_>, b: &[u8]) {
    let ods = le16(b, 18);
    let firebird = ods & 0x8000 != 0;
    cx.format_set("engine", if firebird { "Firebird" } else { "InterBase" });
    cx.format_set("page_size", le16(b, 16));
    let minor = le16(b, 64);
    cx.format_set("ods_version", format!("{}.{minor}", ods & 0x7fff));
    let release = match (ods & 0x7fff, minor) {
        (11, 0) => "Firebird 2.0",
        (11, 1) => "Firebird 2.1",
        (11, 2) => "Firebird 2.5",
        (12, _) => "Firebird 3",
        (13, 0) => "Firebird 4",
        (13, 1) => "Firebird 5",
        _ => "",
    };
    if firebird && !release.is_empty() {
        cx.format_set("release", release);
    }
    cx.format_set("next_transaction", le32(b, 36));
    // Creation time: days since 1858-11-17 (modified Julian), then 1/10 000 s.
    let (days, frac) = (le32(b, 44).cast_signed(), le32(b, 48));
    if days > 0 {
        let unix = (i64::from(days) - 40_587) * 86_400 + i64::from(frac / 10_000);
        if let Some(t) = millis(unix * 1000) {
            cx.format_set("created", t);
        }
    }
}

// --- Microsoft Tape Format -------------------------------------------------------------------------

/// An MTF string at a (size, offset) address within the block; type 2 is UTF-16LE.
fn mtf_str(block: &[u8], at: usize, kind: u8) -> String {
    let (size, off) = (usize::from(le16(block, at)), usize::from(le16(block, at + 2)));
    let Some(s) = block.get(off..off + size) else { return String::new() };
    let text = if kind == 2 {
        let u: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&u)
    } else {
        crate::plugin::latin1_or_utf8(s)
    };
    text.trim_end_matches('\0').trim().to_string()
}

/// A 40-bit packed MTF date: year 14, month 4, day 5, hour 5, minute 6, second 6.
fn mtf_date(b: &[u8]) -> Option<String> {
    let v = b.get(..5)?.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let (y, mo, d, h, mi, s) = (v >> 26, (v >> 22) & 15, (v >> 17) & 31, (v >> 12) & 31, (v >> 6) & 63, v & 63);
    (y > 1900 && (1..=12).contains(&mo) && (1..=31).contains(&d))
        .then(|| format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}"))
}

fn mtf(cx: &mut Context<'_>, b: &[u8]) {
    let kind = b.get(48).copied().unwrap_or(1);
    let t = &b[..b.len().min(64 * 1024)];
    let tape = t.get(52..).unwrap_or_default();
    let _ = tape;
    let media = mtf_str(t, 52 + 16, kind);
    if !media.is_empty() {
        cx.format_set("media_name", media);
    }
    let software = mtf_str(t, 52 + 28, kind);
    if !software.is_empty() {
        cx.format_set("software", software);
    }
    if let Some(d) = t.get(52 + 36..).and_then(mtf_date) {
        cx.format_set("media_date", d);
    }
    cx.format_set("mtf_major_version", t.get(52 + 41).copied().unwrap_or(0));
    // Backup sets: SSET blocks, scanned on 4-byte boundaries.
    let strict = cx.privacy_strict();
    let mut sets = Vec::new();
    let mut at = 4;
    while let Some(p) = b.get(at..).and_then(|r| r.windows(4).position(|w| w == b"SSET")).map(|p| p + at) {
        at = p + 4;
        if p % 4 != 0 || sets.len() >= 50 {
            continue;
        }
        let s = &b[p..b.len().min(p + 4096)];
        let kind = s.get(48).copied().unwrap_or(1);
        let body = 52;
        let mut set = serde_json::Map::new();
        set.insert("number".into(), json!(le16(s, body + 10)));
        for (off, key) in [(12, "name"), (16, "description")] {
            let v = mtf_str(s, body + off, kind);
            if !v.is_empty() {
                set.insert(key.into(), json!(v));
            }
        }
        if !strict {
            let user = mtf_str(s, body + 24, kind);
            if !user.is_empty() {
                set.insert("user".into(), json!(user));
            }
        }
        if let Some(d) = s.get(body + 36..).and_then(mtf_date) {
            set.insert("written".into(), json!(d));
        }
        set.insert(
            "software_version".into(),
            json!(format!("{}.{}", s.get(body + 41).copied().unwrap_or(0), s.get(body + 42).copied().unwrap_or(0))),
        );
        sets.push(Value::Object(set));
    }
    cx.format_set("backup_sets", sets);
}

// --- Kafka -------------------------------------------------------------------------------------------------

/// The base offset in a segment or index file name (`00000000000000000042.log`).
fn base_offset(name: Option<&str>) -> Option<u64> {
    let stem = name?.rsplit(['/', '\\']).next()?.split('.').next()?;
    (stem.len() == 20 && stem.bytes().all(|b| b.is_ascii_digit())).then(|| stem.parse().ok()).flatten()
}

fn kafka(cx: &mut Context<'_>, b: &[u8], name: Option<&str>) {
    if let Some(o) = base_offset(name) {
        cx.format_set("segment_base_offset", o);
    }
    let (mut at, mut batches, mut records, mut magic) = (0usize, 0u64, 0u64, BTreeMap::<u8, u64>::new());
    let (mut first, mut last, mut ts, mut codecs) =
        (None::<i64>, None::<i64>, Vec::<i64>::new(), BTreeMap::<String, u64>::new());
    let (mut transactional, mut control) = (0u64, 0u64);
    while at + 17 <= b.len() && batches < MAX_BATCHES {
        let offset = i64::from_be_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
        let Ok(len) = usize::try_from(i32::from_be_bytes(b[at + 8..at + 12].try_into().unwrap_or([0; 4]))) else {
            break;
        };
        if len < 14 || at + 12 + len > b.len() {
            break;
        }
        let m = b[at + 16];
        *magic.entry(m).or_default() += 1;
        batches += 1;
        if m == 2 && len >= 49 {
            let attrs = u16::from_be_bytes([b[at + 21], b[at + 22]]);
            let delta = i64::from(i32::from_be_bytes(b[at + 23..at + 27].try_into().unwrap_or([0; 4])));
            let (base_ts, max_ts) = (be64(b, at + 27).cast_signed(), be64(b, at + 35).cast_signed());
            let count = i32::from_be_bytes(b[at + 57..at + 61].try_into().unwrap_or([0; 4]));
            records += u64::try_from(count).unwrap_or(0);
            first = Some(first.map_or(offset, |f| f.min(offset)));
            last = Some(last.map_or(offset + delta, |l| l.max(offset + delta)));
            ts.extend([base_ts, max_ts].into_iter().filter(|t| *t > 0));
            let codec =
                ["none", "gzip", "snappy", "lz4", "zstd"].get(usize::from(attrs & 7)).copied().unwrap_or("unknown");
            *codecs.entry(codec.to_string()).or_default() += 1;
            transactional += u64::from(attrs & 0x10 != 0);
            control += u64::from(attrs & 0x20 != 0);
        } else {
            // v0 / v1: one message per entry.
            records += 1;
            first = Some(first.map_or(offset, |f| f.min(offset)));
            last = Some(last.map_or(offset, |l| l.max(offset)));
            if m == 1 {
                ts.push(be64(b, at + 18).cast_signed());
            }
        }
        at += 12 + len;
    }
    cx.format_set("batches", batches);
    cx.format_set("records", records);
    cx.format_set("magic", json!(magic.into_iter().map(|(k, v)| (format!("v{k}"), v)).collect::<BTreeMap<_, _>>()));
    if let (Some(a), Some(z)) = (first, last) {
        cx.format_set("offset_range", json!([a, z]));
    }
    ts.sort_unstable();
    if let (Some(a), Some(z)) = (ts.first().and_then(|t| millis(*t)), ts.last().and_then(|t| millis(*t))) {
        cx.format_set("timestamp_range", json!([a, z]));
    }
    cx.format_set("compression", json!(codecs));
    if transactional > 0 {
        cx.format_set("transactional_batches", transactional);
    }
    if control > 0 {
        cx.format_set("control_batches", control);
    }
    if at < b.len() {
        cx.format_set("trailing_bytes", b.len() - at);
    }
}

fn kafka_index(cx: &mut Context<'_>, b: &[u8], name: Option<&str>) {
    let time = name.is_some_and(|n| n.to_ascii_lowercase().ends_with(".timeindex"));
    let base = base_offset(name);
    if let Some(o) = base {
        cx.format_set("segment_base_offset", o);
    }
    cx.format_set("kind", if time { "time index" } else { "offset index" });
    let size = if time { 12 } else { 8 };
    // Index files are preallocated: entries end at the first all-zero one
    // (after the first, whose relative offset may be 0).
    let entries: Vec<&[u8]> = b
        .chunks_exact(size)
        .enumerate()
        .take_while(|(i, e)| *i == 0 || e.iter().any(|&x| x != 0))
        .map(|(_, e)| e)
        .collect();
    let entries: Vec<&[u8]> = entries.into_iter().filter(|e| e.iter().any(|&x| x != 0)).collect();
    cx.format_set("entries", entries.len());
    if let (Some(f), Some(l)) = (entries.first(), entries.last()) {
        if time {
            if let (Some(a), Some(z)) = (millis(be64(f, 0).cast_signed()), millis(be64(l, 0).cast_signed())) {
                cx.format_set("timestamp_range", json!([a, z]));
            }
        } else {
            let o = base.unwrap_or(0);
            cx.format_set("offset_range", json!([o + u64::from(be32(f, 0)), o + u64::from(be32(l, 0))]));
            cx.format_set("last_position", be32(l, 4));
        }
    }
}

// --- Prometheus TSDB --------------------------------------------------------------------------------------

fn uvarint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*at)?;
        *at += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn tsdb(cx: &mut Context<'_>, b: &[u8]) {
    if b.starts_with(b"\xba\xaa\xd7\x00") {
        cx.format_set("kind", "index");
        cx.format_set("version", b.get(4).copied().unwrap_or(0));
        // TOC: six big-endian offsets and a CRC at the end of the file.
        if b.len() >= 5 + 52 {
            let toc = b.len() - 52;
            let symbols = usize::try_from(be64(b, toc)).unwrap_or(0);
            let count = be32(b, symbols + 4);
            cx.format_set("symbols", count);
            let mut at = symbols + 8;
            let mut names = Vec::new();
            for _ in 0..count.min(50) {
                let Some(n) = uvarint(b, &mut at).and_then(|n| usize::try_from(n).ok()) else { break };
                let Some(s) = b.get(at..at + n) else { break };
                names.push(String::from_utf8_lossy(s).into_owned());
                at += n;
            }
            cx.format_set("first_symbols", names);
            let series = usize::try_from(be64(b, toc + 8)).unwrap_or(0);
            cx.format_set("series_offset", series);
        }
    } else {
        cx.format_set("kind", "chunks");
        cx.format_set("version", b.get(4).copied().unwrap_or(0));
        let (mut at, mut kinds) = (8usize, BTreeMap::<String, u64>::new());
        while at < b.len() && kinds.values().sum::<u64>() < 10_000_000 {
            let Some(n) = uvarint(b, &mut at).and_then(|n| usize::try_from(n).ok()) else { break };
            let Some(&enc) = b.get(at) else { break };
            let name = match enc {
                1 => "XOR",
                2 => "histogram",
                3 => "float histogram",
                _ => break,
            };
            *kinds.entry(name.to_string()).or_default() += 1;
            at = at.saturating_add(1 + n + 4);
        }
        cx.format_set("chunks", json!(kinds));
    }
}

// --- Anki ----------------------------------------------------------------------------------------------------

fn anki(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 1_000_000)?;
    let names: Vec<String> = zip.entries.iter().map(|e| e.name.clone()).collect();
    let collection = ["collection.anki21b", "collection.anki21", "collection.anki2"]
        .into_iter()
        .find(|n| names.iter().any(|x| x == n));
    if let Some(c) = collection {
        cx.format_set(
            "collection",
            match c {
                "collection.anki21b" => "anki21b (zstd, Anki 2.1.50+)",
                "collection.anki21" => "anki21 (Anki 2.1)",
                _ => "anki2 (legacy)",
            },
        );
    }
    let media_files = names.iter().filter(|n| n.bytes().all(|b| b.is_ascii_digit())).count();
    cx.format_set("media_files", media_files);
    if let Some(Ok(m)) = zip.read_text(src, "media", cx, 4 << 20)
        && let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&m)
    {
        let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
        for v in map.values().filter_map(Value::as_str) {
            let ext = v.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
            *kinds.entry(ext).or_default() += 1;
        }
        cx.format_set("media_types", json!(kinds));
    }
    // The SQLite collection (anki2 / anki21) as a child; anki21b is zstd.
    if let Some(c) = collection.filter(|c| *c != "collection.anki21b")
        && cx.options().limits.max_depth > 0
        && let Some(e) = zip.entries.iter().find(|e| e.name == c).cloned()
    {
        let data = zip.read(src, &e, cx, 64 << 20)?;
        cx.emit_child(c, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("realm", "firebird", "mssql_backup", "kafka_log", "kafka_index", "prometheus_tsdb", "anki");

    #[test]
    fn helpers() {
        assert_eq!(base_offset(Some("00000000000000000042.log")), Some(42));
        assert_eq!(base_offset(Some("server.log")), None);
        let mut at = 0;
        assert_eq!(uvarint(&[0xac, 0x02], &mut at), Some(300));
        assert_eq!(millis(1_756_728_000_000).as_deref(), Some("2025-09-01T12:00:00Z"));
    }
}
