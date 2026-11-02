//! Apache Arrow IPC and Feather:
//! * the IPC file format (`ARROW1`, also Feather 2): the schema from the
//!   footer (fields with their types, nullability, dictionaries, nested
//!   children, custom metadata), the record batch and dictionary counts,
//!   rows (from each batch's message) and body compression;
//! * the IPC stream format (`.arrows`): the same, walking the messages;
//! * Feather 1 (`FEA1`): columns with their types and encodings, rows, the
//!   description.
//!
//! Specifications: Apache Arrow columnar format 1.5 ("Serialization and
//! Interprocess Communication", `Schema.fbs`, `Message.fbs`, `File.fbs`);
//! Feather 1 `feather.fbs`.

use serde_json::{Map, Value};

use crate::plugin::flatbuf::FlatBuf;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for Arrow IPC and Feather files.
pub struct Arrow;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.arrow",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "arrow",
            name: "Apache Arrow IPC / Feather",
            family: "columnar",
            mimes: &["application/vnd.apache.arrow.file"],
            extensions: &["arrow", "feather", "ipc"],
            magic: &[Magic::at(0, b"ARROW1\0\0")],
            parent: None,
        },
        FormatSpec {
            id: "arrow_stream",
            name: "Apache Arrow IPC stream",
            family: "columnar",
            mimes: &["application/vnd.apache.arrow.stream"],
            extensions: &["arrows"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "feather_v1",
            name: "Feather v1",
            family: "columnar",
            mimes: &[],
            extensions: &["feather"],
            magic: &[Magic::at(0, b"FEA1")],
            parent: None,
        },
    ],
};

/// Fields described.
const MAX_FIELDS: usize = 500;
/// Batches whose messages are read for their row counts.
const MAX_BATCHES: usize = 100_000;
/// Bytes of one message's metadata.
const MAX_MESSAGE: usize = 16 << 20;

fn time_unit(u: Option<u16>) -> &'static str {
    match u {
        Some(0) => "s",
        Some(1) | None => "ms",
        Some(2) => "us",
        Some(3) => "ns",
        _ => "?",
    }
}

/// A field's type, as text (`int32`, `timestamp[ms, UTC]`, `list<string>` …).
fn field_type(fb: &FlatBuf<'_>, f: usize, depth: usize) -> String {
    let kind = fb.u8_field(f, 2).unwrap_or(0);
    let t = fb.table(f, 3);
    let children = || -> Vec<String> {
        if depth > 32 {
            return vec!["…".into()];
        }
        fb.tables(f, 5)
            .iter()
            .take(100)
            .map(|&c| {
                let name = fb.string(c, 0).unwrap_or_default();
                format!("{name}: {}", field_type(fb, c, depth + 1))
            })
            .collect()
    };
    let child_type = || fb.tables(f, 5).first().map_or_else(|| "?".into(), |&c| field_type(fb, c, depth + 1));
    let base = match kind {
        1 => "null".into(),
        2 => {
            let bits = t.and_then(|t| fb.u32_field(t, 0)).unwrap_or(0);
            let signed = t.is_some_and(|t| fb.bool(t, 1));
            format!("{}int{bits}", if signed { "" } else { "u" })
        }
        3 => match t.and_then(|t| fb.u16_field(t, 0)) {
            Some(0) => "float16".into(),
            Some(1) => "float32".into(),
            _ => "float64".into(),
        },
        4 => "binary".into(),
        5 => "string".into(),
        6 => "bool".into(),
        7 => format!(
            "decimal({},{})",
            t.and_then(|t| fb.u32_field(t, 0)).unwrap_or(0),
            t.and_then(|t| fb.u32_field(t, 1)).unwrap_or(0)
        ),
        8 => {
            if t.and_then(|t| fb.u16_field(t, 0)) == Some(0) {
                "date32".into()
            } else {
                "date64".into()
            }
        }
        9 => format!("time[{}]", time_unit(t.and_then(|t| fb.u16_field(t, 0)))),
        10 => {
            let unit = time_unit(t.and_then(|t| fb.u16_field(t, 0)));
            match t.and_then(|t| fb.string(t, 1)) {
                Some(tz) => format!("timestamp[{unit}, {}]", truncate_chars(&tz, 50)),
                None => format!("timestamp[{unit}]"),
            }
        }
        11 => "interval".into(),
        12 => format!("list<{}>", child_type()),
        13 => format!("struct<{}>", children().join(", ")),
        14 => format!("union<{}>", children().join(", ")),
        15 => format!("fixed_size_binary({})", t.and_then(|t| fb.u32_field(t, 0)).unwrap_or(0)),
        16 => format!("fixed_size_list<{}>[{}]", child_type(), t.and_then(|t| fb.u32_field(t, 0)).unwrap_or(0)),
        17 => format!("map<{}>", child_type()),
        18 => format!("duration[{}]", time_unit(t.and_then(|t| fb.u16_field(t, 0)))),
        19 => "large_binary".into(),
        20 => "large_string".into(),
        21 => format!("large_list<{}>", child_type()),
        22 => "run_end_encoded".into(),
        23 => "binary_view".into(),
        24 => "string_view".into(),
        25 => format!("list_view<{}>", child_type()),
        26 => format!("large_list_view<{}>", child_type()),
        k => format!("type {k}"),
    };
    let base = if fb.table(f, 4).is_some() { format!("dictionary<{base}>") } else { base };
    truncate_chars(&base, 300)
}

/// `KeyValue` metadata as a JSON object (small text values only).
fn key_values(fb: &FlatBuf<'_>, t: usize, n: usize) -> Map<String, Value> {
    fb.tables(t, n)
        .iter()
        .take(100)
        .filter_map(|&kv| {
            let k = fb.string(kv, 0)?;
            let v = fb.string(kv, 1).unwrap_or_default();
            let v = if v.len() > 300 { format!("({} bytes)", v.len()) } else { redact_sensitive(&v).into_owned() };
            Some((truncate_chars(&k, 100), Value::String(v)))
        })
        .collect()
}

/// Describe a `Schema` table.
pub(crate) fn schema(cx: &mut Context<'_>, fb: &FlatBuf<'_>, s: usize) {
    let fields = fb.tables(s, 1);
    cx.format_set("column_count", fields.len());
    let mut cols = Map::new();
    let mut nullable = 0;
    for &f in fields.iter().take(MAX_FIELDS) {
        let name = fb.string(f, 0).unwrap_or_default();
        nullable += usize::from(fb.bool(f, 1));
        cols.insert(truncate_chars(&name, 200), Value::String(field_type(fb, f, 0)));
    }
    cx.format_set("columns", Value::Object(cols));
    cx.format_set("nullable_columns", nullable);
    if fb.u16_field(s, 0) == Some(1) {
        cx.format_set("endianness", "big");
    }
    let meta = key_values(fb, s, 2);
    if !meta.is_empty() {
        cx.format_set("metadata", Value::Object(meta));
    }
}

/// A message (`0xFFFFFFFF`, length, flatbuffer) at `at`: its flatbuffer and
/// the offset after its metadata.
fn message(src: &mut dyn Source, at: u64) -> Option<(Vec<u8>, u64)> {
    let head = src.read_vec(at, 8).ok()?;
    let (len, start) = if head[..4] == [0xff; 4] {
        (u32::from_le_bytes(head[4..8].try_into().ok()?), at + 8)
    } else {
        // Pre-0.15 streams: no continuation marker.
        (u32::from_le_bytes(head[..4].try_into().ok()?), at + 4)
    };
    let len = usize::try_from(len).ok()?;
    if len == 0 || len > MAX_MESSAGE {
        return None;
    }
    Some((src.read_vec(start, len).ok()?, start + len as u64))
}

/// Header kind, body length, rows and compression of a message.
fn message_facts(fb: &FlatBuf<'_>) -> Option<(u8, u64, Option<u64>, Option<u16>)> {
    let root = fb.root()?;
    let kind = fb.u8_field(root, 1)?;
    let body = fb.u64_field(root, 3).unwrap_or(0);
    let header = fb.table(root, 2);
    let rows = if kind == 3 { header.and_then(|h| fb.u64_field(h, 0)) } else { None };
    let codec =
        header.filter(|_| kind == 3).and_then(|h| fb.table(h, 3)).map(|c| fb.u8_field(c, 0).map_or(0, u16::from));
    Some((kind, body, rows, codec))
}

fn codec_name(c: u16) -> &'static str {
    if c == 1 { "zstd" } else { "lz4_frame" }
}

fn file(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let tail = src.read_vec(len.saturating_sub(10), 10).map_err(|_| ExtractError::malformed("footer"))?;
    if &tail[4..] != b"ARROW1" {
        return Err(ExtractError::malformed("no ARROW1 footer (truncated file?)"));
    }
    let n = u64::from(u32::from_le_bytes(tail[..4].try_into().map_err(|_| ExtractError::malformed("footer"))?));
    let size = usize::try_from(n).map_err(|_| ExtractError::malformed("footer length"))?;
    if size > cx.parse_limit() {
        return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
    }
    let start = len.checked_sub(10 + n).ok_or_else(|| ExtractError::malformed("footer length"))?;
    let footer = src.read_vec(start, size).map_err(|_| ExtractError::malformed("footer"))?;
    let fb = FlatBuf(&footer);
    let root = fb.root().ok_or_else(|| ExtractError::malformed("footer"))?;
    if let Some(v) = fb.u16_field(root, 0) {
        cx.format_set("metadata_version", format!("V{}", v + 1));
    }
    if let Some(s) = fb.table(root, 1) {
        schema(cx, &fb, s);
    }
    let dictionaries = fb.vector(root, 2).map_or(0, |(_, n)| n);
    let batches = fb.vector(root, 3).map_or(0, |(_, n)| n);
    cx.format_set("record_batches", batches);
    cx.format_set("dictionary_batches", dictionaries);
    // Rows: each block's message holds its record batch length.
    let mut rows = 0u64;
    let mut codec = None;
    for i in 0..batches.min(MAX_BATCHES) {
        if i % 1024 == 0 {
            cx.checkpoint()?;
        }
        let Some(block) = fb.element(root, 3, i, 24) else { break };
        let off = u64::from_le_bytes(block[..8].try_into().map_err(|_| ExtractError::malformed("block"))?);
        let Some((m, _)) = message(src, off) else { continue };
        if let Some((_, _, r, c)) = message_facts(&FlatBuf(&m)) {
            rows = rows.saturating_add(r.unwrap_or(0));
            codec = codec.or(c);
        }
    }
    cx.format_set("rows", rows);
    if let Some(c) = codec {
        cx.format_set("compression", codec_name(c));
    }
    let meta = key_values(&fb, root, 4);
    if !meta.is_empty() {
        cx.format_set("footer_metadata", Value::Object(meta));
    }
    Ok(())
}

fn stream(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let mut at = 0u64;
    let (mut batches, mut dictionaries, mut rows, mut codec) = (0u64, 0u64, 0u64, None);
    let mut have_schema = false;
    while at.checked_add(8).is_some_and(|e| e <= len) {
        if batches % 1024 == 0 {
            cx.checkpoint()?;
        }
        let head = src.read_vec(at, 8).map_err(|_| ExtractError::malformed("message"))?;
        if head == [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0] {
            cx.format_set("end_of_stream", true);
            break;
        }
        let Some((m, after)) = message(src, at) else { break };
        let fb = FlatBuf(&m);
        let Some((kind, body, r, c)) = message_facts(&fb) else { break };
        match kind {
            1 if !have_schema => {
                if let Some(s) = fb.root().and_then(|root| fb.table(root, 2)) {
                    schema(cx, &fb, s);
                }
                have_schema = true;
            }
            2 => dictionaries += 1,
            3 => {
                batches += 1;
                rows = rows.saturating_add(r.unwrap_or(0));
                codec = codec.or(c);
            }
            _ => {}
        }
        // Metadata is padded to 8 bytes; the body follows.
        match after.checked_next_multiple_of(8).and_then(|a| a.checked_add(body)) {
            Some(next) if next > at => at = next,
            _ => break,
        }
        if usize::try_from(batches).is_ok_and(|b| b >= MAX_BATCHES) {
            break;
        }
    }
    cx.format_set("record_batches", batches);
    cx.format_set("dictionary_batches", dictionaries);
    cx.format_set("rows", rows);
    if let Some(c) = codec {
        cx.format_set("compression", codec_name(c));
    }
    if !have_schema {
        return Err(ExtractError::malformed("no schema message"));
    }
    Ok(())
}

fn feather_v1(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let tail = src.read_vec(len.saturating_sub(8), 8).map_err(|_| ExtractError::malformed("footer"))?;
    if &tail[4..] != b"FEA1" {
        return Err(ExtractError::malformed("no FEA1 footer"));
    }
    let n = u64::from(u32::from_le_bytes(tail[..4].try_into().map_err(|_| ExtractError::malformed("footer"))?));
    let size = usize::try_from(n).map_err(|_| ExtractError::malformed("footer length"))?;
    if size > cx.parse_limit() {
        return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
    }
    let start = len.checked_sub(8 + n).ok_or_else(|| ExtractError::malformed("footer length"))?;
    let meta = src.read_vec(start, size).map_err(|_| ExtractError::malformed("metadata"))?;
    let fb = FlatBuf(&meta);
    let root = fb.root().ok_or_else(|| ExtractError::malformed("metadata"))?;
    if let Some(d) = fb.string(root, 0).filter(|d| !d.is_empty()) {
        cx.format_set("description", truncate_chars(&d, 500));
    }
    cx.format_set("rows", fb.u64_field(root, 1).unwrap_or(0));
    if let Some(v) = fb.u32_field(root, 3) {
        cx.format_set("feather_version", v);
    }
    let cols = fb.tables(root, 2);
    cx.format_set("column_count", cols.len());
    let mut out = Map::new();
    for &c in cols.iter().take(MAX_FIELDS) {
        let name = fb.string(c, 0).unwrap_or_default();
        let values = fb.table(c, 1);
        let base = match values.and_then(|v| fb.u8_field(v, 0)).unwrap_or(0) {
            0 => "bool",
            1 => "int8",
            2 => "int16",
            3 => "int32",
            4 => "int64",
            5 => "uint8",
            6 => "uint16",
            7 => "uint32",
            8 => "uint64",
            9 => "float32",
            10 => "float64",
            11 => "string",
            12 => "binary",
            13 => "category",
            14 => "timestamp",
            15 => "date",
            16 => "time",
            17 => "large_string",
            18 => "large_binary",
            _ => "other",
        };
        // Category, timestamp, date and time columns say what they hold in `metadata`.
        let kind = match fb.u8_field(c, 2) {
            Some(1) => "category".to_string(),
            Some(2) => {
                let m = fb.table(c, 3);
                let unit = time_unit(m.and_then(|m| fb.u8_field(m, 0)).map(u16::from));
                match m.and_then(|m| fb.string(m, 1)) {
                    Some(tz) => format!("timestamp[{unit}, {}]", truncate_chars(&tz, 50)),
                    None => format!("timestamp[{unit}]"),
                }
            }
            Some(3) => "date".into(),
            Some(4) => "time".into(),
            _ => base.to_string(),
        };
        out.insert(truncate_chars(&name, 200), Value::String(kind));
    }
    cx.format_set("columns", Value::Object(out));
    Ok(())
}

impl Extractor for Arrow {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // A stream starts with a schema message: continuation, length, then a
        // flatbuffer whose header type (union tag 1) is `Schema`.
        let h = probe.head;
        if h.len() < 16 || h[..4] != [0xff; 4] {
            return None;
        }
        let m = h.get(8..)?;
        let fb = FlatBuf(m);
        let root = fb.root()?;
        let is_schema = fb.u8_field(root, 1) == Some(1) && fb.u16_field(root, 0).is_some_and(|v| v <= 4);
        is_schema.then_some(Sniff { format: "arrow_stream", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "arrow" => file(cx, src),
            "arrow_stream" => stream(cx, src),
            _ => feather_v1(cx, src),
        }
    }
}

crate::register_extractor!(Arrow);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("arrow", "arrow_stream", "feather_v1");
}
