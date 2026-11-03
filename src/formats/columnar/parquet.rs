//! Apache Parquet files, from the footer (`FileMetaData`, read through the
//! source, so the file's size does not matter): format version, writer,
//! rows, row groups, the schema as a type tree (physical and logical types,
//! nesting), codecs, encodings, compressed and uncompressed sizes, column
//! statistics (min, max, nulls across row groups) and the key-value
//! metadata (pandas index, Spark, Arrow); GeoParquet files also report
//! their geometry columns (encoding, geometry types, CRS, bounding box).
//! Encrypted footers (`PARE`) are reported as such.
//!
//! Specifications: Apache Parquet format 2.11 (`parquet.thrift`);
//! GeoParquet 1.1.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::thrift::{self, TValue};
use super::{epoch_text, number};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for Parquet and GeoParquet files.
pub struct Parquet;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.parquet",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "parquet",
            name: "Apache Parquet",
            family: "columnar",
            mimes: &["application/vnd.apache.parquet"],
            extensions: &["parquet", "pq", "parq"],
            magic: &[Magic::at(0, b"PAR1")],
            parent: None,
        },
        FormatSpec {
            id: "geoparquet",
            name: "GeoParquet",
            family: "geo",
            mimes: &[],
            extensions: &["parquet", "geoparquet"],
            magic: &[],
            parent: Some("parquet"),
        },
    ],
};

/// Columns listed in the schema and statistics.
const MAX_COLUMNS: usize = 500;
/// Characters kept of a type description.
const MAX_TYPE: usize = 300;

fn physical(t: i64, len: Option<i64>) -> String {
    match t {
        0 => "boolean".into(),
        1 => "int32".into(),
        2 => "int64".into(),
        3 => "int96".into(),
        4 => "float".into(),
        5 => "double".into(),
        6 => "binary".into(),
        7 => format!("fixed_len_byte_array({})", len.unwrap_or(0)),
        _ => format!("type {t}"),
    }
}

fn unit(u: Option<&TValue<'_>>) -> &'static str {
    match u.map(TValue::ids).as_deref() {
        Some([1, ..]) => "ms",
        Some([2, ..]) => "us",
        Some([3, ..]) => "ns",
        _ => "?",
    }
}

/// The logical type of a schema element, from `logicalType` or the older
/// `converted_type`.
fn logical(e: &TValue<'_>) -> Option<String> {
    if let Some(l) = e.get(10) {
        let ids = l.ids();
        let id = *ids.first()?;
        let inner = l.get(id);
        return Some(match id {
            1 => "string".into(),
            2 => "map".into(),
            3 => "list".into(),
            4 => "enum".into(),
            5 => format!(
                "decimal({},{})",
                inner.and_then(|d| d.int(2)).unwrap_or(0),
                inner.and_then(|d| d.int(1)).unwrap_or(0)
            ),
            6 => "date".into(),
            7 => format!("time[{}]", unit(inner.and_then(|t| t.get(2)))),
            8 => {
                let utc = inner.and_then(|t| t.get(1)) == Some(&TValue::Bool(true));
                format!("timestamp[{}{}]", unit(inner.and_then(|t| t.get(2))), if utc { ", UTC" } else { "" })
            }
            10 => {
                let bits = inner.and_then(|i| i.int(1)).unwrap_or(0);
                let signed = inner.and_then(|i| i.get(2)) != Some(&TValue::Bool(false));
                format!("{}int{bits}", if signed { "" } else { "u" })
            }
            11 => "null".into(),
            12 => "json".into(),
            13 => "bson".into(),
            14 => "uuid".into(),
            15 => "float16".into(),
            16 => "variant".into(),
            17 => "geometry".into(),
            18 => "geography".into(),
            _ => format!("logical {id}"),
        });
    }
    Some(match e.int(6)? {
        0 => "string".into(),
        1 | 2 => "map".into(),
        3 => "list".into(),
        4 => "enum".into(),
        5 => format!("decimal({},{})", e.int(8).unwrap_or(0), e.int(7).unwrap_or(0)),
        6 => "date".into(),
        7 => "time[ms]".into(),
        8 => "time[us]".into(),
        9 => "timestamp[ms]".into(),
        10 => "timestamp[us]".into(),
        c @ 11..=14 => format!("uint{}", 8 << (c - 11)),
        c @ 15..=18 => format!("int{}", 8 << (c - 15)),
        19 => "json".into(),
        20 => "bson".into(),
        21 => "interval".into(),
        c => format!("converted {c}"),
    })
}

/// A schema node: its name, type description, and the leaves under it
/// (`(path, physical type, logical type)`).
struct Node {
    name: String,
    kind: String,
}

/// Read the node at `*i` and its children (depth-first order).
fn node(
    elems: &[TValue<'_>],
    i: &mut usize,
    path: &str,
    leaves: &mut Vec<(String, i64, Option<String>)>,
    depth: usize,
) -> Option<Node> {
    let e = elems.get(*i)?;
    *i += 1;
    let name = e.text(4).unwrap_or_default();
    let full = if path.is_empty() { name.clone() } else { format!("{path}.{name}") };
    let children = usize::try_from(e.int(5).unwrap_or(0)).unwrap_or(0);
    let repeated = e.int(3) == Some(2);
    let log = logical(e);
    if children == 0 || depth > 64 {
        let t = e.int(1).unwrap_or(-1);
        leaves.push((full, t, log.clone()));
        let base = log.unwrap_or_else(|| physical(t, e.int(2)));
        return Some(Node { name, kind: if repeated { format!("repeated {base}") } else { base } });
    }
    let mut kids = Vec::with_capacity(children.min(1000));
    for _ in 0..children.min(10_000) {
        kids.push(node(elems, i, &full, leaves, depth + 1)?);
    }
    let kind = match log.as_deref() {
        // LIST: a repeated group holding the element.
        Some("list") => {
            // LIST > repeated group (one field: the element) > element.
            let inner = kids.first().map_or("?", |k| k.kind.as_str()).trim_start_matches("repeated ");
            let inner = inner
                .strip_prefix("struct<")
                .and_then(|s| s.strip_suffix('>'))
                .filter(|s| !s.contains(", "))
                .map_or(inner, |s| s.split_once(": ").map_or(s, |(_, t)| t));
            format!("list<{inner}>")
        }
        Some("map") => {
            let inner = kids.first().map_or("?", |k| k.kind.as_str());
            let inner = inner.strip_prefix("repeated ").unwrap_or(inner);
            let kv = inner.strip_prefix("struct<").and_then(|s| s.strip_suffix('>')).unwrap_or(inner);
            let types: Vec<&str> = kv.split(", ").map(|p| p.split_once(": ").map_or(p, |(_, t)| t)).collect();
            format!("map<{}>", types.join(", "))
        }
        _ => {
            let body = kids.iter().map(|k| format!("{}: {}", k.name, k.kind)).collect::<Vec<_>>().join(", ");
            if repeated { format!("repeated struct<{body}>") } else { format!("struct<{body}>") }
        }
    };
    Some(Node { name, kind: truncate_chars(&kind, MAX_TYPE) })
}

/// A statistics value as JSON, by physical and logical type.
fn stat(raw: &[u8], t: i64, log: Option<&str>) -> Option<Value> {
    let le = |n: usize| raw.get(..n).map(|b| b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)));
    Some(match t {
        0 => Value::Bool(*raw.first()? != 0),
        1 => {
            let v = u32::try_from(le(4)?).ok()?;
            match log {
                Some("date") => epoch_text(i64::from(v.cast_signed()) * 86_400, "s")?.into(),
                Some(l) if l.starts_with("uint") => v.into(),
                _ => v.cast_signed().into(),
            }
        }
        2 => {
            let v = le(8)?;
            match log {
                Some(l) if l.starts_with("timestamp[") => {
                    let u = l.trim_start_matches("timestamp[").split([',', ']']).next().unwrap_or("us");
                    epoch_text(v.cast_signed(), u)?.into()
                }
                Some(l) if l.starts_with("uint") => v.into(),
                _ => v.cast_signed().into(),
            }
        }
        4 => number(f64::from(f32::from_bits(u32::try_from(le(4)?).ok()?))),
        5 => number(f64::from_bits(le(8)?)),
        6 if matches!(log, Some("string" | "json" | "enum")) => {
            Value::String(truncate_chars(&redact_sensitive(&String::from_utf8_lossy(raw)), 100))
        }
        _ => return None,
    })
}

fn less(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() < y.as_f64(),
        (Value::String(x), Value::String(y)) => x < y,
        (Value::Bool(x), Value::Bool(y)) => !x & y,
        _ => false,
    }
}

/// GeoParquet `geo` metadata.
fn geo(cx: &mut Context<'_>, v: &Value) {
    if let Some(s) = v.get("version").and_then(Value::as_str) {
        cx.format_set("geo_version", s);
    }
    if let Some(s) = v.get("primary_column").and_then(Value::as_str) {
        cx.format_set("primary_column", truncate_chars(s, 200));
    }
    let Some(cols) = v.get("columns").and_then(Value::as_object) else { return };
    let mut out = Map::new();
    for (name, c) in cols.iter().take(50) {
        let mut m = Map::new();
        for k in ["encoding", "geometry_types", "bbox", "edges", "orientation"] {
            if let Some(x) = c.get(k) {
                m.insert(k.into(), x.clone());
            }
        }
        // PROJJSON's identifier, else its name; absent means OGC:CRS84.
        let crs = match c.get("crs") {
            None => Some("OGC:CRS84".to_string()),
            Some(Value::Null) => Some("unknown".to_string()),
            Some(crs) => crs
                .get("id")
                .and_then(|id| Some(format!("{}:{}", id.get("authority")?.as_str()?, id.get("code")?)))
                .or_else(|| crs.get("name").and_then(Value::as_str).map(|n| truncate_chars(n, 100))),
        };
        if let Some(crs) = crs {
            m.insert("crs".into(), crs.replace('"', "").into());
        }
        out.insert(truncate_chars(name, 200), Value::Object(m));
    }
    cx.format_set("geometry_columns", Value::Object(out));
}

/// Describe a `FileMetaData`.
#[allow(clippy::too_many_lines)] // one pass over the footer, in report order
fn describe(cx: &mut Context<'_>, meta: &TValue<'_>) {
    if let Some(v) = meta.int(1) {
        cx.format_set("format_version", v);
    }
    if let Some(w) = meta.text(6) {
        cx.format_set("created_by", truncate_chars(&w, 300));
    }
    let rows = meta.int(3).unwrap_or(0);
    cx.format_set("rows", rows);
    let groups = meta.list(4);
    cx.format_set("row_groups", groups.len());

    // Schema.
    let elems = meta.list(2);
    let mut leaves = Vec::new();
    if let Some(root) = elems.first() {
        let mut i = 1;
        let mut cols = Map::new();
        let top = usize::try_from(root.int(5).unwrap_or(0)).unwrap_or(0);
        for _ in 0..top.min(10_000) {
            let Some(n) = node(elems, &mut i, "", &mut leaves, 0) else { break };
            if cols.len() < MAX_COLUMNS {
                cols.insert(truncate_chars(&n.name, 200), Value::String(n.kind));
            }
        }
        cx.format_set("column_count", top);
        cx.format_set("columns", Value::Object(cols));
        cx.format_set("leaf_columns", leaves.len());
    }

    // Column chunks: codecs, encodings, sizes, statistics.
    let mut codecs = BTreeSet::new();
    let mut encodings = BTreeSet::new();
    let (mut compressed, mut uncompressed) = (0i64, 0i64);
    let mut stats: BTreeMap<String, (Option<Value>, Option<Value>, i64)> = BTreeMap::new();
    let kinds: BTreeMap<&str, (i64, Option<&str>)> =
        leaves.iter().map(|(p, t, l)| (p.as_str(), (*t, l.as_deref()))).collect();
    for g in groups {
        for c in g.list(1) {
            let Some(m) = c.get(3) else { continue };
            let codec = match m.int(4) {
                Some(0) => "uncompressed",
                Some(1) => "snappy",
                Some(2) => "gzip",
                Some(3) => "lzo",
                Some(4) => "brotli",
                Some(5) => "lz4",
                Some(6) => "zstd",
                Some(7) => "lz4_raw",
                _ => "other",
            };
            codecs.insert(codec);
            for e in m.list(2) {
                if let TValue::Int(e) = e {
                    encodings.insert(match e {
                        0 => "plain",
                        2 => "plain_dictionary",
                        3 => "rle",
                        4 => "bit_packed",
                        5 => "delta_binary_packed",
                        6 => "delta_length_byte_array",
                        7 => "delta_byte_array",
                        8 => "rle_dictionary",
                        9 => "byte_stream_split",
                        _ => "other",
                    });
                }
            }
            uncompressed = uncompressed.saturating_add(m.int(6).unwrap_or(0));
            compressed = compressed.saturating_add(m.int(7).unwrap_or(0));
            let path: Vec<String> = m
                .list(3)
                .iter()
                .filter_map(|p| match p {
                    TValue::Binary(b) => Some(String::from_utf8_lossy(b).into_owned()),
                    _ => None,
                })
                .collect();
            let path = path.join(".");
            let Some(s) = m.get(12) else { continue };
            let Some(&(t, log)) = kinds.get(path.as_str()) else { continue };
            if stats.len() >= MAX_COLUMNS && !stats.contains_key(&path) {
                continue;
            }
            let min = s.bytes(6).or_else(|| s.bytes(2)).and_then(|b| stat(b, t, log));
            let max = s.bytes(5).or_else(|| s.bytes(1)).and_then(|b| stat(b, t, log));
            let entry = stats.entry(path).or_insert((None, None, 0));
            if let Some(v) = min
                && entry.0.as_ref().is_none_or(|cur| less(&v, cur))
            {
                entry.0 = Some(v);
            }
            if let Some(v) = max
                && entry.1.as_ref().is_none_or(|cur| less(cur, &v))
            {
                entry.1 = Some(v);
            }
            entry.2 = entry.2.saturating_add(s.int(3).unwrap_or(0));
        }
    }
    if !codecs.is_empty() {
        cx.format_set("codecs", codecs.into_iter().collect::<Vec<_>>());
    }
    if !encodings.is_empty() {
        cx.format_set("encodings", encodings.into_iter().collect::<Vec<_>>());
    }
    if compressed > 0 {
        cx.format_set("compressed_bytes", compressed);
        cx.format_set("uncompressed_bytes", uncompressed);
    }
    let stats: Map<String, Value> = stats
        .into_iter()
        .filter(|(_, (a, b, _))| a.is_some() || b.is_some())
        .map(|(k, (min, max, nulls))| {
            let mut m = Map::new();
            if let Some(v) = min {
                m.insert("min".into(), v);
            }
            if let Some(v) = max {
                m.insert("max".into(), v);
            }
            m.insert("nulls".into(), nulls.into());
            (k, Value::Object(m))
        })
        .collect();
    if !stats.is_empty() {
        cx.format_set("statistics", Value::Object(stats));
    }

    // Key-value metadata.
    let mut keys = Vec::new();
    let mut small = Map::new();
    for kv in meta.list(5) {
        let Some(k) = kv.text(1) else { continue };
        let v = kv.text(2).unwrap_or_default();
        match k.as_str() {
            "pandas" => {
                if let Ok(p) = serde_json::from_str::<Value>(&v) {
                    if let Some(ver) = p.get("pandas_version").and_then(Value::as_str) {
                        cx.format_set("pandas_version", ver);
                    }
                    if let Some(ix) = p.get("index_columns").and_then(Value::as_array).filter(|a| !a.is_empty()) {
                        cx.format_set("pandas_index", Value::Array(ix.iter().take(20).cloned().collect()));
                    }
                }
            }
            "geo" => {
                if let Ok(g) = serde_json::from_str::<Value>(&v) {
                    geo(cx, &g);
                }
            }
            _ if v.len() <= 200 && !k.starts_with("ARROW:") && v.chars().all(|c| !c.is_control()) => {
                small.insert(truncate_chars(&k, 100), redact_sensitive(&v).into_owned().into());
            }
            _ => {}
        }
        if keys.len() < 100 {
            keys.push(truncate_chars(&k, 100));
        }
    }
    if !keys.is_empty() {
        cx.format_set("metadata_keys", keys);
    }
    if !small.is_empty() {
        cx.format_set("metadata", Value::Object(small));
    }
}

impl Extractor for Parquet {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // GeoParquet: a Parquet footer with `geo` metadata naming a primary column.
        let geo = probe.head.starts_with(b"PAR1")
            && probe.tail.ends_with(b"PAR1")
            && probe.tail.windows(16).any(|w| w == b"\"primary_column\"");
        geo.then_some(Sniff { format: "geoparquet", confidence: 0.98 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let tail = src.read_vec(len.saturating_sub(8), 8).map_err(|_| ExtractError::malformed("footer"))?;
        if &tail[4..] == b"PARE" {
            cx.format_set("encrypted_footer", true);
            cx.security().encrypted(true);
            return Ok(());
        }
        if &tail[4..] != b"PAR1" {
            return Err(ExtractError::malformed("no PAR1 footer (truncated file?)"));
        }
        let n = u64::from(u32::from_le_bytes(tail[..4].try_into().map_err(|_| ExtractError::malformed("footer"))?));
        let start = len.checked_sub(8 + n).ok_or_else(|| ExtractError::malformed("footer length"))?;
        let size = usize::try_from(n).map_err(|_| ExtractError::malformed("footer length"))?;
        if size > cx.parse_limit() {
            return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
        }
        let footer = src.read_vec(start, size).map_err(|_| ExtractError::malformed("footer"))?;
        cx.format_set("footer_bytes", n);
        let meta = thrift::read(&footer).ok_or_else(|| ExtractError::malformed("FileMetaData"))?;
        if meta.get(8).is_some() {
            cx.format_set("encrypted_columns", true);
        }
        describe(cx, &meta);
        Ok(())
    }
}

crate::register_extractor!(Parquet);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics_values() {
        assert_eq!(stat(&7i32.to_le_bytes(), 1, None), Some(Value::from(7)));
        assert_eq!(stat(&2.5f64.to_le_bytes(), 5, None), Some(Value::from(2.5)));
        assert_eq!(stat(b"Pier", 6, Some("string")), Some(Value::from("Pier")));
        assert_eq!(stat(b"\x01\x02", 6, None), None);
        assert_eq!(stat(&20_000i32.to_le_bytes(), 1, Some("date")), Some(Value::from("2024-10-04T00:00:00Z")));
        assert!(less(&Value::from(1), &Value::from(2.5)));
    }

    crate::fixture_tests!("parquet", "geoparquet");
}
