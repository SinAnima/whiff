//! Apache ORC files, from the postscript and footer (read through the
//! source): file version, writer and its version, compression and block
//! size, rows, stripes, row index stride, the schema as a type tree,
//! column statistics (counts, nulls, min / max for numbers, strings, dates
//! and timestamps) and user metadata. Encrypted columns are noted.
//!
//! Specification: Apache ORC v1 specification (`orc_proto.proto`):
//! "File Tail", "Compression".

use serde_json::{Map, Value};

use super::{epoch_text, number};
use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Codec, Context, Cost, End, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for ORC files.
pub struct Orc;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.orc",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "orc",
        name: "Apache ORC",
        family: "columnar",
        mimes: &["application/vnd.apache.orc"],
        extensions: &["orc"],
        magic: &[Magic::at(0, b"ORC")],
        parent: None,
    }],
};

/// Columns described.
const MAX_COLUMNS: usize = 500;

fn kind_name(k: u64) -> &'static str {
    match k {
        0 => "boolean",
        1 => "tinyint",
        2 => "smallint",
        3 => "int",
        4 => "bigint",
        5 => "float",
        6 => "double",
        7 => "string",
        8 => "binary",
        9 => "timestamp",
        10 => "array",
        11 => "map",
        12 => "struct",
        13 => "uniontype",
        14 => "decimal",
        15 => "date",
        16 => "varchar",
        17 => "char",
        18 => "timestamp with local time zone",
        _ => "unknown",
    }
}

/// The type tree from the flattened `types` list (column 0 is the root).
fn type_text(types: &[&[u8]], i: usize, depth: usize) -> String {
    let Some(t) = types.get(i) else { return "?".into() };
    let kind = protowire::first(t, 1).and_then(Wire::int).unwrap_or(99);
    let subs: Vec<usize> =
        protowire::all(t, 2).flat_map(protowire::packed).filter_map(|s| usize::try_from(s).ok()).collect();
    let names: Vec<String> = protowire::all(t, 3).filter_map(Wire::text).collect();
    let sub = |j: usize| {
        if depth > 32 {
            "…".into()
        } else {
            subs.get(j).map_or_else(|| "?".into(), |&s| type_text(types, s, depth + 1))
        }
    };
    let s = match kind {
        10 => format!("array<{}>", sub(0)),
        11 => format!("map<{}, {}>", sub(0), sub(1)),
        12 => {
            let fields: Vec<String> =
                names.iter().enumerate().take(100).map(|(j, n)| format!("{n}: {}", sub(j))).collect();
            format!("struct<{}>", fields.join(", "))
        }
        13 => format!("uniontype<{}>", (0..subs.len().min(20)).map(sub).collect::<Vec<_>>().join(", ")),
        14 => format!(
            "decimal({},{})",
            protowire::first(t, 5).and_then(Wire::int).unwrap_or(0),
            protowire::first(t, 6).and_then(Wire::int).unwrap_or(0)
        ),
        16 | 17 => format!("{}({})", kind_name(kind), protowire::first(t, 4).and_then(Wire::int).unwrap_or(0)),
        k => kind_name(k).to_string(),
    };
    truncate_chars(&s, 300)
}

fn zigzag(v: u64) -> i64 {
    (v >> 1).cast_signed() ^ -((v & 1).cast_signed())
}

/// Min and max of one column's statistics, by kind.
fn min_max(s: &[u8]) -> (Option<Value>, Option<Value>) {
    let pick = |n: u32| protowire::first(s, n).and_then(Wire::bytes);
    if let Some(i) = pick(2) {
        let get = |k| protowire::first(i, k).and_then(Wire::int).map(|v| Value::from(zigzag(v)));
        return (get(1), get(2));
    }
    if let Some(d) = pick(3) {
        let get = |k| protowire::first(d, k).and_then(Wire::int).map(|v| number(f64::from_bits(v)));
        return (get(1), get(2));
    }
    if let Some(t) = pick(4) {
        let get = |k| {
            protowire::first(t, k)
                .and_then(Wire::text)
                .map(|v| Value::String(truncate_chars(&redact_sensitive(&v), 100)))
        };
        return (get(1), get(2));
    }
    if let Some(d) = pick(7) {
        let get = |k| {
            protowire::first(d, k)
                .and_then(Wire::int)
                .and_then(|v| epoch_text(zigzag(v) * 86_400, "s"))
                .map(Value::from)
        };
        return (get(1), get(2));
    }
    if let Some(t) = pick(9) {
        // minimumUtc / maximumUtc (ms) when present, else local ms.
        let get = |utc, local| {
            protowire::first(t, utc)
                .or_else(|| protowire::first(t, local))
                .and_then(Wire::int)
                .and_then(|v| epoch_text(zigzag(v), "ms"))
                .map(Value::from)
        };
        return (get(3, 1), get(4, 2));
    }
    (None, None)
}

/// Undo ORC's chunked compression (3-byte headers: length << 1 | original).
fn decompress(cx: &mut Context<'_>, b: &[u8], kind: u64, block: usize) -> Result<Vec<u8>, ExtractError> {
    if kind == 0 {
        return Ok(b.to_vec());
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at + 3 <= b.len() {
        let h = usize::from(b[at]) | usize::from(b[at + 1]) << 8 | usize::from(b[at + 2]) << 16;
        let (len, original) = (h >> 1, h & 1 == 1);
        at += 3;
        let chunk = b.get(at..at + len).ok_or_else(|| ExtractError::malformed("compressed chunk"))?;
        at += len;
        if original {
            out.extend_from_slice(chunk);
            continue;
        }
        let codec = match kind {
            1 => Codec::Deflate,
            2 => Codec::SnappyBlock,
            4 => Codec::Lz4Block { max: block },
            5 => Codec::Zstd,
            _ => return Err(ExtractError::Unsupported(format!("ORC compression {kind}"))),
        };
        let d = cx.decompress(chunk, codec, block.max(1 << 16))?;
        if !matches!(d.end, End::Complete) {
            return Err(ExtractError::malformed("compressed footer"));
        }
        out.extend_from_slice(&d.data);
        if out.len() > cx.parse_limit() {
            return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
        }
    }
    Ok(out)
}

impl Extractor for Orc {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // postscript, footer, schema and statistics in report order
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let last = src.read_vec(len.saturating_sub(1), 1).map_err(|_| ExtractError::malformed("postscript"))?;
        let ps_len = u64::from(last[0]);
        let ps_at = len.checked_sub(1 + ps_len).ok_or_else(|| ExtractError::malformed("postscript"))?;
        let ps = src.read_vec(ps_at, usize::from(last[0])).map_err(|_| ExtractError::malformed("postscript"))?;
        if protowire::first(&ps, 8000).and_then(Wire::text).as_deref() != Some("ORC") {
            return Err(ExtractError::malformed("postscript magic"));
        }
        let int = |n| protowire::first(&ps, n).and_then(Wire::int);
        let footer_len = int(1).unwrap_or(0);
        let compression = int(2).unwrap_or(0);
        let block = usize::try_from(int(3).unwrap_or(256 * 1024)).unwrap_or(1 << 18).min(16 << 20);
        let version: Vec<String> = protowire::all(&ps, 4).flat_map(protowire::packed).map(|v| v.to_string()).collect();
        if !version.is_empty() {
            cx.format_set("file_version", version.join("."));
        }
        cx.format_set(
            "compression",
            match compression {
                0 => "none",
                1 => "zlib",
                2 => "snappy",
                3 => "lzo",
                4 => "lz4",
                5 => "zstd",
                _ => "other",
            },
        );
        if compression != 0 {
            cx.format_set("compression_block_size", block);
        }
        if let Some(w) = int(6) {
            cx.format_set("writer_version", w);
        }
        let size = usize::try_from(footer_len).map_err(|_| ExtractError::malformed("footer length"))?;
        if size > cx.parse_limit() {
            return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
        }
        let at = ps_at.checked_sub(footer_len).ok_or_else(|| ExtractError::malformed("footer length"))?;
        let raw = src.read_vec(at, size).map_err(|_| ExtractError::malformed("footer"))?;
        let footer = decompress(cx, &raw, compression, block)?;
        let fint = |n| protowire::first(&footer, n).and_then(Wire::int);
        cx.format_set("rows", fint(6).unwrap_or(0));
        let stripes: Vec<&[u8]> = protowire::all(&footer, 3).filter_map(Wire::bytes).collect();
        cx.format_set("stripes", stripes.len());
        if let Some(s) = fint(8) {
            cx.format_set("row_index_stride", s);
        }
        let writer = match fint(9) {
            Some(0) | None => "ORC Java",
            Some(1) => "ORC C++",
            Some(2) => "Presto",
            Some(3) => "Go",
            Some(4) => "Trino",
            Some(5) => "cuDF",
            Some(_) => "other",
        };
        cx.format_set("writer", writer);
        if let Some(v) = protowire::first(&footer, 12).and_then(Wire::text) {
            cx.format_set("software_version", truncate_chars(&v, 100));
        }
        let types: Vec<&[u8]> = protowire::all(&footer, 4).filter_map(Wire::bytes).collect();
        let stats: Vec<&[u8]> = protowire::all(&footer, 7).filter_map(Wire::bytes).collect();
        if let Some(root) = types.first() {
            let names: Vec<String> = protowire::all(root, 3).filter_map(Wire::text).collect();
            let subs: Vec<usize> =
                protowire::all(root, 2).flat_map(protowire::packed).filter_map(|s| usize::try_from(s).ok()).collect();
            let mut cols = Map::new();
            let mut st = Map::new();
            for (name, &col) in names.iter().zip(&subs).take(MAX_COLUMNS) {
                let key = truncate_chars(name, 200);
                cols.insert(key.clone(), Value::String(type_text(&types, col, 0)));
                if let Some(s) = stats.get(col) {
                    let mut m = Map::new();
                    if let Some(n) = protowire::first(s, 1).and_then(Wire::int) {
                        m.insert("values".into(), n.into());
                    }
                    let (min, max) = min_max(s);
                    if let Some(v) = min {
                        m.insert("min".into(), v);
                    }
                    if let Some(v) = max {
                        m.insert("max".into(), v);
                    }
                    if protowire::first(s, 10).and_then(Wire::int) == Some(1) {
                        m.insert("has_nulls".into(), true.into());
                    }
                    st.insert(key, Value::Object(m));
                }
            }
            cx.format_set("column_count", names.len());
            cx.format_set("columns", Value::Object(cols));
            if !st.is_empty() {
                cx.format_set("statistics", Value::Object(st));
            }
        }
        let meta: Map<String, Value> = protowire::all(&footer, 5)
            .filter_map(Wire::bytes)
            .take(100)
            .filter_map(|kv| {
                let k = protowire::first(kv, 1).and_then(Wire::text)?;
                let v = protowire::first(kv, 2).and_then(Wire::bytes).unwrap_or_default();
                let v = std::str::from_utf8(v)
                    .ok()
                    .filter(|s| s.len() <= 300)
                    .map_or_else(|| format!("({} bytes)", v.len()), |s| redact_sensitive(s).into_owned());
                Some((truncate_chars(&k, 100), Value::String(v)))
            })
            .collect();
        if !meta.is_empty() {
            cx.format_set("metadata", Value::Object(meta));
        }
        if protowire::first(&footer, 10).is_some() {
            cx.format_set("encrypted_columns", true);
        }
        Ok(())
    }
}

crate::register_extractor!(Orc);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics_kinds() {
        // intStatistics {min: -3, max: 7} (zig-zag 5 and 14).
        let s = [0x08, 4, 0x12, 4, 0x08, 5, 0x10, 14];
        assert_eq!(min_max(&s), (Some(Value::from(-3)), Some(Value::from(7))));
        assert_eq!(zigzag(1), -1);
        assert_eq!(kind_name(12), "struct");
    }

    crate::fixture_tests!("orc");
}
