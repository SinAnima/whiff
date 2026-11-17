//! Files of other database engines, described from their headers:
//! DuckDB (storage version, the DuckDB release that wrote it, block
//! count), LMDB (map size, page size, entries, transaction), Berkeley DB
//! (access method, version, page size, pages, key count), LevelDB / RocksDB
//! sorted tables (format and, for RocksDB, the properties block: entries,
//! sizes, column family, comparator, compression, creation time), Redis
//! RDB snapshots (version, server version, keys per database), PostgreSQL
//! `pg_dump` custom archives (versions, database, creation time, table of
//! contents by object type), MySQL / MariaDB table files (`.frm` engine and
//! server version, InnoDB `.ibd` tablespaces, MyISAM `.MYI` indexes) and H2
//! MVStore files. No record is read.
//!
//! Specifications: DuckDB `storage/storage_info.hpp`; LMDB `mdb.c`
//! (`MDB_meta`); Berkeley DB `dbinc/db_page.h` (`DBMETA`); LevelDB
//! `table_format.md` and the RocksDB block-based table format; Redis
//! "RDB File Format"; PostgreSQL `pg_backup_archiver.c`; MySQL `.frm` and
//! InnoDB `fil0fil.h` / `fsp0fsp.h`; H2 `MVStore` file header.

use std::fmt::Write as _;

use serde_json::{Map, Value};

use super::unix_time;
use crate::plugin::{
    Codec, Context, Cost, End, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, codec,
    redact_sensitive, truncate_chars,
};

/// Extractor for database engine files read from their headers.
pub struct Engines;

static META: ExtractorMeta = ExtractorMeta {
    id: "db.engines",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "duckdb",
            name: "DuckDB database",
            family: "db",
            mimes: &[],
            extensions: &["duckdb", "ddb"],
            magic: &[Magic::at(8, b"DUCK")],
            parent: None,
        },
        FormatSpec {
            id: "lmdb",
            name: "LMDB database",
            family: "db",
            mimes: &[],
            extensions: &["mdb"],
            magic: &[Magic::at(16, b"\xde\xc0\xef\xbe")],
            parent: None,
        },
        FormatSpec {
            id: "berkeley_db",
            name: "Berkeley DB database",
            family: "db",
            mimes: &["application/x-berkeley-db"],
            // Found by `sniff`: `.db` is every engine's extension.
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "leveldb_table",
            name: "LevelDB / RocksDB sorted table",
            family: "db",
            mimes: &[],
            extensions: &["ldb", "sst"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "redis_rdb",
            name: "Redis RDB snapshot",
            family: "db",
            mimes: &[],
            extensions: &["rdb"],
            magic: &[Magic::prefix(b"REDIS0")],
            parent: None,
        },
        FormatSpec {
            id: "pg_dump",
            name: "PostgreSQL custom-format dump",
            family: "db",
            mimes: &[],
            extensions: &["dump", "backup", "pgdump"],
            magic: &[Magic::prefix(b"PGDMP")],
            parent: None,
        },
        FormatSpec {
            id: "mysql_frm",
            name: "MySQL / MariaDB table definition",
            family: "db",
            mimes: &[],
            extensions: &["frm"],
            magic: &[Magic::prefix(b"\xfe\x01")],
            parent: None,
        },
        FormatSpec {
            id: "innodb_tablespace",
            name: "InnoDB tablespace",
            family: "db",
            mimes: &[],
            extensions: &["ibd", "ibdata1"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "myisam_index",
            name: "MyISAM / Aria index",
            family: "db",
            mimes: &[],
            extensions: &["myi", "mai"],
            magic: &[Magic::prefix(b"\xfe\xfe\x07"), Magic::prefix(b"\xfe\xfe\x09")],
            parent: None,
        },
        FormatSpec {
            id: "h2",
            name: "H2 database (MVStore)",
            family: "db",
            mimes: &[],
            extensions: &["db"],
            magic: &[Magic::prefix(b"H:2,")],
            parent: None,
        },
    ],
};

fn le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

fn read(src: &mut dyn Source, at: u64, n: usize) -> Option<Vec<u8>> {
    let len = usize::try_from(src.len().saturating_sub(at)).ok()?.min(n);
    let mut b = vec![0; len];
    src.read_exact_at(at, &mut b).ok()?;
    Some(b)
}

/// The Berkeley DB access method of a metadata page, and its byte order.
fn bdb_magic(b: &[u8]) -> Option<(&'static str, bool)> {
    let m = b.get(12..16)?;
    for (big, v) in [(false, le(m)), (true, be(m))] {
        let kind = match v {
            0x0005_3162 => "btree",
            0x0006_1561 => "hash",
            0x0004_2253 => "queue",
            0x0007_4582 => "heap",
            _ => continue,
        };
        return Some((kind, big));
    }
    None
}

const LEVELDB_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const ROCKSDB_MAGIC: u64 = 0x88e2_41b7_85f4_cff7;
const ROCKSDB_PLAIN_MAGIC: u64 = 0x8242_2296_63bf_9564;

fn innodb(b: &[u8]) -> Option<(u64, u64, usize)> {
    // FIL header: page number 0, page type FSP_HDR; FSP header space id
    // equal to the FIL header's.
    if be(b.get(4..8)?) != 0 || be(b.get(24..26)?) != 8 {
        return None;
    }
    let space = be(b.get(34..38)?);
    if be(b.get(38..42)?) != space {
        return None;
    }
    let flags = be(b.get(54..58)?);
    // Page size: MariaDB's full_crc32 format (bit 4 set) keeps it in bits
    // 0–3, MySQL in bits 6–9; 0 means 16 KiB.
    let ssize = if flags & 0x10 != 0 { flags & 0xf } else { (flags >> 6) & 0xf };
    let page = if ssize == 0 { 16384 } else { 512usize << ssize };
    Some((space, be(b.get(46..50)?), page))
}

impl Extractor for Engines {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (h, t) = (probe.head, probe.tail);
        if t.len() >= 8 && probe.len >= 48 {
            let magic = le(&t[t.len() - 8..]);
            if [LEVELDB_MAGIC, ROCKSDB_MAGIC, ROCKSDB_PLAIN_MAGIC].contains(&magic) {
                return Some(Sniff { format: "leveldb_table", confidence: 0.85 });
            }
        }
        if let Some((_, big)) = bdb_magic(h) {
            let size = if big { be(h.get(20..24)?) } else { le(h.get(20..24)?) };
            if (512..=65536).contains(&size) && size.is_power_of_two() {
                return Some(Sniff { format: "berkeley_db", confidence: 0.8 });
            }
        }
        innodb(h).filter(|_| probe.len >= 16384).map(|_| Sniff { format: "innodb_tablespace", confidence: 0.7 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = read(src, 0, 64 << 10).ok_or_else(|| ExtractError::malformed("header"))?;
        let id = cx.format_id().to_string();
        let bad = || ExtractError::malformed(format!("{id} header"));
        match id.as_str() {
            "duckdb" => duckdb(&head, cx).ok_or_else(bad),
            "lmdb" => lmdb(src, &head, cx).ok_or_else(bad),
            "berkeley_db" => berkeley(&head, cx).ok_or_else(bad),
            "leveldb_table" => sorted_table(src, cx).ok_or_else(bad),
            "redis_rdb" => rdb(src, cx).ok_or_else(bad),
            "pg_dump" => pg_dump(src, cx).ok_or_else(bad),
            "mysql_frm" => frm(&head, cx).ok_or_else(bad),
            "innodb_tablespace" => {
                let (space, pages, page) = innodb(&head).ok_or_else(bad)?;
                cx.format_set("space_id", space);
                cx.format_set("page_size", page);
                cx.format_set("pages", pages);
                Ok(())
            }
            "myisam_index" => {
                let kind = *head.get(2).ok_or_else(bad)?;
                cx.format_set("engine", if kind == 9 { "Aria" } else { "MyISAM" });
                cx.format_set("keys", head.get(18).copied().unwrap_or(0));
                Ok(())
            }
            _ => h2(&head, cx).ok_or_else(bad),
        }
    }
}

fn text_field(b: &[u8]) -> Option<String> {
    let s: String = b.iter().take_while(|&&c| c != 0).map(|&c| char::from(c)).collect();
    (!s.is_empty() && s.chars().all(|c| c.is_ascii_graphic())).then_some(s)
}

/// DuckDB: the main header, then two database headers (the one with the
/// higher iteration is current).
fn duckdb(b: &[u8], cx: &mut Context<'_>) -> Option<()> {
    let storage = le(b.get(12..20)?);
    cx.format_set("storage_version", storage);
    // Since 1.2 the main header names the library that wrote the file.
    if let Some(v) = b.get(52..84).and_then(text_field) {
        cx.format_set("library_version", v);
    }
    if let Some(v) = b.get(84..116).and_then(text_field) {
        cx.format_set("source_id", v);
    }
    let headers: Vec<&[u8]> = [4096usize, 8192].iter().filter_map(|&at| b.get(at..at + 64)).collect();
    if let Some(cur) = headers.iter().max_by_key(|h| le(&h[8..16])) {
        cx.format_set("iteration", le(&cur[8..16]));
        cx.format_set("block_count", le(&cur[32..40]));
        let alloc = le(&cur[40..48]);
        if alloc.is_power_of_two() && alloc >= 4096 {
            cx.format_set("block_size", alloc);
        }
    }
    Some(())
}

/// LMDB: two meta pages; the one with the higher transaction ID is current.
fn lmdb(src: &mut dyn Source, head: &[u8], cx: &mut Context<'_>) -> Option<()> {
    // The second meta page sits one page in; the page size is the OS's.
    let mut metas = vec![(0usize, head.get(16..160)?.to_vec())];
    let mut page_size = None;
    for size in [4096usize, 8192, 16384, 65536] {
        if let Some(m) = read(src, size as u64 + 16, 144).filter(|m| m.starts_with(b"\xde\xc0\xef\xbe")) {
            metas.push((size, m));
            page_size = Some(size);
            break;
        }
    }
    let (_, m) = metas.iter().max_by_key(|(_, m)| le(&m[128..136]))?;
    cx.format_set("version", le(&m[4..8]));
    cx.format_set("map_size", le(&m[16..24]));
    if let Some(p) = page_size {
        cx.format_set("page_size", p);
    }
    // MDB_db for the main database at 72: flags, depth, page counts, entries.
    let db = &m[72..120];
    cx.format_set("entries", le(&db[32..40]));
    cx.format_set("depth", le(&db[6..8]));
    cx.format_set("leaf_pages", le(&db[16..24]));
    cx.format_set("last_page", le(&m[120..128]));
    cx.format_set("transaction", le(&m[128..136]));
    Some(())
}

fn berkeley(b: &[u8], cx: &mut Context<'_>) -> Option<()> {
    let (kind, big) = bdb_magic(b)?;
    let n = |at: usize, len: usize| b.get(at..at + len).map(|v| if big { be(v) } else { le(v) });
    cx.format_set("access_method", kind);
    cx.format_set("byte_order", if big { "big_endian" } else { "little_endian" });
    cx.format_set("version", n(16, 4)?);
    cx.format_set("page_size", n(20, 4)?);
    cx.format_set("pages", n(32, 4)? + 1);
    let alg = b.get(24).copied().unwrap_or(0);
    if alg != 0 {
        cx.format_set("encrypted", true);
        cx.security().encrypted(true);
    }
    // Key and record counts are cached only after `db_stat`; 0 is "unknown".
    let keys = n(40, 4)?;
    if keys > 0 {
        cx.format_set("keys", keys);
    }
    Some(())
}

fn varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u64::from(x & 0x7f) << shift;
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The key / value entries of an uncompressed block (prefix-compressed
/// keys, restart array at the end), at most 4096.
fn block_entries(b: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    block_entries_up_to(b, 4096)
}

/// [`block_entries`], at most `max`.
fn block_entries_up_to(b: &[u8], max: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(n) = b.len().checked_sub(4).and_then(|at| usize::try_from(le(&b[at..])).ok()) else { return out };
    let n = n.min(b.len() / 4);
    let end = b.len().saturating_sub(4 + 4 * n);
    let mut at = 0;
    let mut key: Vec<u8> = Vec::new();
    while at < end && out.len() < max {
        let (Some(shared), Some(unshared), Some(vlen)) = (varint(b, &mut at), varint(b, &mut at), varint(b, &mut at))
        else {
            break;
        };
        let (Ok(shared), Ok(unshared), Ok(vlen)) =
            (usize::try_from(shared), usize::try_from(unshared), usize::try_from(vlen))
        else {
            break;
        };
        if shared > key.len() {
            break;
        }
        key.truncate(shared);
        let Some(k) = b.get(at..at + unshared) else { break };
        key.extend_from_slice(k);
        at += unshared;
        let Some(v) = b.get(at..at + vlen) else { break };
        at += vlen;
        out.push((key.clone(), v.to_vec()));
    }
    out
}

/// LevelDB and RocksDB block-based tables: the footer, then RocksDB's
/// properties block found through the metaindex.
fn sorted_table(src: &mut dyn Source, cx: &mut Context<'_>) -> Option<()> {
    let len = src.len();
    let tail = read(src, len.checked_sub(53.min(len))?, 53)?;
    let magic = le(tail.get(tail.len().checked_sub(8)?..)?);
    let (kind, footer) = match magic {
        LEVELDB_MAGIC => ("leveldb", tail.get(tail.len().checked_sub(48)?..)?),
        ROCKSDB_MAGIC if tail.len() == 53 => ("rocksdb_block_based", &tail[..]),
        ROCKSDB_PLAIN_MAGIC if tail.len() == 53 => ("rocksdb_plain", &tail[..]),
        _ => return None,
    };
    cx.format_set("table_format", kind);
    if magic == LEVELDB_MAGIC {
        let footer = footer.to_vec();
        if leveldb(src, cx, &footer).is_none() {
            cx.warn("LevelDB index block unreadable");
        }
        return Some(());
    }
    let version = le(&footer[footer.len() - 12..footer.len() - 8]);
    cx.format_set("format_version", version);
    // Format 6+: an extended footer; the metaindex block sits right before
    // it with its size in the footer. Before: handles after the checksum type.
    let (meta_off, meta_len) = if version >= 6 {
        let size = le(&footer[13..17]);
        (len.checked_sub(53 + size + 5)?, size)
    } else {
        let mut at = 1;
        (varint(footer, &mut at)?, varint(footer, &mut at)?)
    };
    let meta = read(src, meta_off, usize::try_from(meta_len).ok()?.min(1 << 20))?;
    let props = block_entries(&meta).into_iter().find(|(k, _)| k == b"rocksdb.properties")?;
    let mut at = 0;
    let (off, size) = (varint(&props.1, &mut at)?, varint(&props.1, &mut at)?);
    let block = read(src, off, usize::try_from(size).ok()?.min(4 << 20))?;
    let mut out = Map::new();
    for (k, v) in block_entries(&block) {
        let key = String::from_utf8_lossy(&k).into_owned();
        let Some(name) = key.strip_prefix("rocksdb.") else { continue };
        let num = |v: &[u8]| {
            let mut at = 0;
            varint(v, &mut at)
        };
        let value: Value = match name {
            "num.entries" | "raw.key.size" | "raw.value.size" | "data.size" | "index.size" | "filter.size"
            | "num.data.blocks" | "num.deletions" | "num.merge.operands" | "column.family.id" => num(&v).into(),
            "creation.time" | "oldest.key.time" | "file.creation.time" => {
                num(&v).and_then(|t| unix_time(i64::try_from(t).ok()?)).map_or(Value::Null, Value::from)
            }
            "column.family.name"
            | "comparator"
            | "compression"
            | "filter.policy"
            | "merge.operator"
            | "prefix.extractor.name"
            | "creating.db.identity"
            | "creating.host.identity" => String::from_utf8_lossy(&v).into_owned().into(),
            _ => continue,
        };
        if !value.is_null() {
            out.insert(name.replace('.', "_"), value);
        }
    }
    cx.format_set("properties", Value::Object(out));
    Some(())
}

/// A table block by its handle: `size` bytes of contents, then a trailer
/// whose first byte is the compression (0 none, 1 Snappy).
fn table_block(src: &mut dyn Source, off: u64, size: u64, max: usize) -> Option<Vec<u8>> {
    let size = usize::try_from(size).ok().filter(|&s| s <= max)?;
    let raw = read(src, off, size.checked_add(1)?)?;
    let (contents, kind) = (raw.get(..size)?, *raw.get(size)?);
    match kind {
        0 => Some(contents.to_vec()),
        1 => {
            let d = codec::decode(contents, Codec::SnappyBlock, max, src.budget()).ok()?;
            (d.end == End::Complete).then_some(d.data)
        }
        _ => None,
    }
}

/// A LevelDB key for the report: the user key (the internal key less its
/// 8-byte sequence and type), as text when it is text, else hex.
fn leveldb_key(cx: &Context<'_>, internal: &[u8]) -> String {
    let user = &internal[..internal.len().saturating_sub(8)];
    let shown = match std::str::from_utf8(user) {
        Ok(t) if !t.chars().any(char::is_control) => truncate_chars(t, 200),
        _ => user.iter().take(64).fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        }),
    };
    if cx.privacy_strict() { redact_sensitive(&shown).into_owned() } else { shown }
}

/// A LevelDB table past its magic: the footer's metaindex and index
/// handles, the index block (one entry per data block), the first and last
/// keys, and the entry count when the data blocks fit the parse limit.
fn leveldb(src: &mut dyn Source, cx: &mut Context<'_>, footer: &[u8]) -> Option<()> {
    let mut at = 0;
    let handles: Vec<u64> = (0..4).map(|_| varint(footer, &mut at)).collect::<Option<_>>()?;
    let handle = |o: u64, s: u64| serde_json::json!({ "offset": o, "size": s });
    cx.format_set("metaindex_handle", handle(handles[0], handles[1]));
    cx.format_set("index_handle", handle(handles[2], handles[3]));
    let max = cx.parse_limit();
    let index = table_block(src, handles[2], handles[3], max)?;
    let blocks: Vec<(u64, u64)> = block_entries_up_to(&index, 1 << 20)
        .into_iter()
        .filter_map(|(_, v)| {
            let mut at = 0;
            Some((varint(&v, &mut at)?, varint(&v, &mut at)?))
        })
        .collect();
    cx.format_set("data_blocks", blocks.len());
    let (&(first_off, first_size), &(last_off, last_size)) = (blocks.first()?, blocks.last()?);
    if let Some((k, _)) =
        table_block(src, first_off, first_size, max).and_then(|b| block_entries(&b).into_iter().next())
    {
        cx.format_set("first_key", leveldb_key(cx, &k));
    }
    if let Some((k, _)) = table_block(src, last_off, last_size, max).and_then(|b| block_entries(&b).pop()) {
        cx.format_set("last_key", leveldb_key(cx, &k));
    }
    // Every entry, while the data blocks fit the parse limit.
    let data: u64 = blocks.iter().map(|(_, s)| s).sum();
    if data <= max as u64 {
        let mut entries = 0usize;
        for &(o, s) in &blocks {
            cx.checkpoint().ok()?;
            entries += block_entries(&table_block(src, o, s, max)?).len();
        }
        cx.format_set("entries", entries);
    }
    Some(())
}

/// An RDB length or integer-encoded string.
enum Rdb {
    Len(u64),
    Int(i64),
}

fn rdb_len(b: &[u8], at: &mut usize) -> Option<Rdb> {
    let x = *b.get(*at)?;
    *at += 1;
    Some(match x >> 6 {
        0 => Rdb::Len(u64::from(x & 0x3f)),
        1 => {
            let y = *b.get(*at)?;
            *at += 1;
            Rdb::Len(u64::from(x & 0x3f) << 8 | u64::from(y))
        }
        2 => {
            let n = if x == 0x80 { 4 } else { 8 };
            let v = be(b.get(*at..*at + n)?);
            *at += n;
            Rdb::Len(v)
        }
        _ => {
            let n = match x & 0x3f {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return None, // LZF-compressed string
            };
            let v = b.get(*at..*at + n)?;
            *at += n;
            let shift = 64 - 8 * u32::try_from(n).unwrap_or(8);
            #[allow(clippy::cast_possible_wrap)] // two's complement, sign-extended
            Rdb::Int(((le(v) << shift) as i64) >> shift)
        }
    })
}

fn rdb_string(b: &[u8], at: &mut usize) -> Option<String> {
    match rdb_len(b, at)? {
        Rdb::Int(i) => Some(i.to_string()),
        Rdb::Len(n) => {
            let n = usize::try_from(n).ok()?;
            let s = b.get(*at..*at + n)?;
            *at += n;
            Some(String::from_utf8_lossy(s).into_owned())
        }
    }
}

/// RDB: auxiliary fields, then per database a `SELECTDB` and (RDB 7+) a
/// `RESIZEDB` with its key count. The keys themselves are not read.
fn rdb(src: &mut dyn Source, cx: &mut Context<'_>) -> Option<()> {
    let b = read(src, 0, 1 << 20)?;
    let version: u64 = std::str::from_utf8(b.get(5..9)?).ok()?.parse().ok()?;
    cx.format_set("rdb_version", version);
    let mut at = 9;
    let mut aux = Map::new();
    let mut dbs = Vec::new();
    let mut current: Option<u64> = None;
    loop {
        match *b.get(at)? {
            0xfa => {
                at += 1;
                let k = rdb_string(&b, &mut at)?;
                let v = rdb_string(&b, &mut at)?;
                match k.as_str() {
                    "redis-ver" | "valkey-ver" | "redis-bits" | "used-mem" | "aof-base" => {
                        aux.insert(k.replace('-', "_"), v.parse::<u64>().map_or_else(|_| Value::from(v), Value::from));
                    }
                    "ctime" => {
                        if let Some(t) = v.parse::<i64>().ok().and_then(unix_time) {
                            aux.insert("created".into(), t.into());
                        }
                    }
                    _ => {}
                }
            }
            0xfe => {
                at += 1;
                let Rdb::Len(n) = rdb_len(&b, &mut at)? else { return None };
                current = Some(n);
            }
            0xfb => {
                at += 1;
                let (Rdb::Len(keys), Rdb::Len(expires)) = (rdb_len(&b, &mut at)?, rdb_len(&b, &mut at)?) else {
                    return None;
                };
                dbs.push(serde_json::json!({ "db": current.unwrap_or(0), "keys": keys, "expires": expires }));
            }
            // Keys follow (or the end): nothing more is read but the next
            // databases' counts would need every value decoded.
            _ => break,
        }
    }
    for (k, v) in aux {
        cx.format_set(&k, v);
    }
    cx.format_set("databases", dbs);
    Some(())
}

/// `pg_dump -Fc`: header, then the table of contents.
#[allow(clippy::too_many_lines)] // the TOC entry layout changes with the archive version
fn pg_dump(src: &mut dyn Source, cx: &mut Context<'_>) -> Option<()> {
    let b = read(src, 0, cx.parse_limit().min(64 << 20))?;
    let (vmaj, vmin, vrev) = (*b.get(5)?, *b.get(6)?, *b.get(7)?);
    let v = (u32::from(vmaj) << 16) | (u32::from(vmin) << 8) | u32::from(vrev);
    let ver = |maj: u32, min: u32| (maj << 16) | (min << 8);
    let int_size = usize::from(*b.get(8)?);
    let mut at = 9;
    if v >= ver(1, 7) {
        at += 1; // offset size
    }
    let format = *b.get(at)?;
    at += 1;
    if !(1..=8).contains(&int_size) {
        return None;
    }
    cx.format_set("archive_version", format!("{vmaj}.{vmin}.{vrev}"));
    cx.format_set(
        "archive_format",
        match format {
            1 => "custom",
            2 => "files",
            3 => "tar",
            4 => "null",
            5 => "directory",
            _ => "unknown",
        },
    );
    let int = |at: &mut usize| -> Option<i64> {
        let sign = *b.get(*at)?;
        let v = le(b.get(*at + 1..*at + 1 + int_size)?);
        *at += 1 + int_size;
        let v = i64::try_from(v).ok()?;
        Some(if sign == 0 { v } else { -v })
    };
    let string = |at: &mut usize| -> Option<Option<String>> {
        let n = int(at)?;
        if n < 0 {
            return Some(None);
        }
        let n = usize::try_from(n).ok()?;
        let s = b.get(*at..*at + n)?;
        *at += n;
        Some(Some(String::from_utf8_lossy(s).into_owned()))
    };
    if v >= ver(1, 15) {
        let c = *b.get(at)?;
        at += 1;
        cx.format_set(
            "compression",
            match c {
                0 => "none",
                1 => "gzip",
                2 => "lz4",
                3 => "zstd",
                _ => "unknown",
            },
        );
    } else if v >= ver(1, 4) {
        let level = int(&mut at)?;
        cx.format_set("compression", if level == 0 { "none".to_string() } else { format!("gzip level {level}") });
    }
    if v >= ver(1, 4) {
        let mut tm = [0i64; 7];
        for t in &mut tm {
            *t = int(&mut at)?;
        }
        // Local time of the dumping machine: no time zone is recorded.
        cx.format_set(
            "created",
            format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", tm[5] + 1900, tm[4] + 1, tm[3], tm[2], tm[1], tm[0]),
        );
        if let Some(Some(db)) = string(&mut at) {
            cx.format_set("database", db);
        }
    }
    if v >= ver(1, 10) {
        if let Some(Some(s)) = string(&mut at) {
            cx.format_set("server_version", s);
        }
        if let Some(Some(s)) = string(&mut at) {
            cx.format_set("pg_dump_version", s);
        }
    }
    let count = int(&mut at)?;
    cx.format_set("toc_entries", count);
    let mut kinds: Map<String, Value> = Map::new();
    let mut schemas: Vec<String> = Vec::new();
    let mut tables: Vec<Value> = Vec::new();
    let off_size = usize::from(*b.get(9)?);
    for _ in 0..count.clamp(0, 1_000_000) {
        let entry = (|| -> Option<()> {
            int(&mut at)?; // dump id
            int(&mut at)?; // had dumper
            if v >= ver(1, 8) {
                string(&mut at)?;
                string(&mut at)?;
            }
            let tag = string(&mut at)?.unwrap_or_default();
            let desc = string(&mut at)?.unwrap_or_default();
            if v >= ver(1, 11) {
                int(&mut at)?;
            }
            string(&mut at)?; // definition
            string(&mut at)?; // drop statement
            if v >= ver(1, 3) {
                string(&mut at)?;
            }
            let namespace = if v >= ver(1, 6) { string(&mut at)? } else { None };
            if v >= ver(1, 10) {
                string(&mut at)?;
            }
            if v >= ver(1, 14) {
                string(&mut at)?;
            }
            if v >= ver(1, 16) {
                int(&mut at)?;
            }
            string(&mut at)?; // owner
            if v >= ver(1, 9) {
                string(&mut at)?; // "with oids"
            }
            if v >= ver(1, 5) {
                while string(&mut at)?.is_some() {}
            }
            // Custom format: the data position (a flag byte and an offset).
            if format == 1 {
                at += 1 + off_size;
            }
            let n = kinds.get(&desc).and_then(Value::as_u64).unwrap_or(0);
            kinds.insert(desc.clone(), (n + 1).into());
            if let Some(ns) = &namespace
                && !ns.is_empty()
                && !schemas.contains(ns)
            {
                schemas.push(ns.clone());
            }
            if desc == "TABLE" && tables.len() < 256 {
                let name = namespace.filter(|n| !n.is_empty()).map_or(tag.clone(), |n| format!("{n}.{tag}"));
                tables.push(name.into());
            }
            Some(())
        })();
        if entry.is_none() {
            cx.warn("the table of contents could not be read to the end");
            break;
        }
    }
    cx.format_set("object_types", Value::Object(kinds));
    if !schemas.is_empty() {
        cx.format_set("schemas", schemas);
    }
    cx.format_set("tables", tables);
    Some(())
}

/// `.frm`: the storage engine and the server version that wrote it.
fn frm(b: &[u8], cx: &mut Context<'_>) -> Option<()> {
    let engine = match *b.get(3)? {
        6 => "ISAM",
        9 => "MyISAM",
        10 => "MRG_MyISAM",
        12 => "InnoDB",
        14 => "HEAP",
        16 => "BLACKHOLE",
        17 => "CSV",
        19 => "ARCHIVE",
        42 => "Aria",
        _ => "other",
    };
    cx.format_set("frm_version", *b.get(2)?);
    cx.format_set("engine", engine);
    let v = le(b.get(0x33..0x37)?);
    if v > 0 {
        cx.format_set("server_version", format!("{}.{}.{}", v / 10000, v / 100 % 100, v % 100));
    }
    Some(())
}

/// H2 MVStore: a text header of `key:value` pairs (hex numbers).
fn h2(b: &[u8], cx: &mut Context<'_>) -> Option<()> {
    let line = b.split(|&c| c == b'\n' || c == 0).next()?;
    let text = std::str::from_utf8(line).ok()?;
    for pair in text.split(',') {
        let Some((k, v)) = pair.split_once(':') else { continue };
        let num = || u64::from_str_radix(v, 16).ok();
        match k {
            "H" => cx.format_set("header_version", v),
            "format" => cx.format_set("format", num()?),
            "blockSize" => cx.format_set("block_size", num()?),
            "created" => {
                if let Some(t) = num().and_then(|ms| unix_time(i64::try_from(ms / 1000).ok()?)) {
                    cx.format_set("created", t);
                }
            }
            "chunk" => cx.format_set("last_chunk", num()?),
            _ => {}
        }
    }
    Some(())
}

crate::register_extractor!(Engines);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdb_lengths_and_integers() {
        let mut at = 0;
        assert!(matches!(rdb_len(&[0x40, 0x10], &mut at), Some(Rdb::Len(16))));
        let mut at = 0;
        assert!(matches!(rdb_len(&[0xc1, 0x39, 0x30], &mut at), Some(Rdb::Int(12345))));
    }

    #[test]
    fn innodb_page_size_in_both_flag_layouts() {
        let mut page = vec![0u8; 64];
        page[24..26].copy_from_slice(&8u16.to_be_bytes());
        page[34..38].copy_from_slice(&5u32.to_be_bytes());
        page[38..42].copy_from_slice(&5u32.to_be_bytes());
        // MariaDB full_crc32: marker bit 4, size in bits 0–3 (3: 4 KiB).
        page[54..58].copy_from_slice(&0x13u32.to_be_bytes());
        assert_eq!(innodb(&page).map(|t| t.2), Some(4096));
        // MySQL: size in bits 6–9 (4: 8 KiB); 0 is 16 KiB.
        page[54..58].copy_from_slice(&(4u32 << 6).to_be_bytes());
        assert_eq!(innodb(&page).map(|t| t.2), Some(8192));
        page[54..58].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(innodb(&page).map(|t| t.2), Some(16384));
    }

    #[test]
    fn prefix_compressed_block() {
        // "tide" → "v1", "tides" → "v2" (shared 4), one restart at 0.
        let mut b = vec![0, 4, 2];
        b.extend(b"tidev1");
        b.extend([4, 1, 2]);
        b.extend(b"sv2");
        b.extend(0u32.to_le_bytes());
        b.extend(1u32.to_le_bytes());
        let e = block_entries(&b);
        assert_eq!(e[1].0, b"tides");
        assert_eq!(e[1].1, b"v2");
    }

    crate::fixture_tests!(
        "duckdb",
        "lmdb",
        "berkeley_db",
        "leveldb_table",
        "redis_rdb",
        "pg_dump",
        "mysql_frm",
        "innodb_tablespace",
        "myisam_index",
        "h2"
    );
}
