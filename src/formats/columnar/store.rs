//! Columnar files of newer table stores:
//! * Lance data files (v2): format version, columns, rows and the schema
//!   (fields with their logical types and nesting) from the file
//!   descriptor in the first global buffer; Lance 0.x files report their
//!   version only;
//! * Vortex files: format version and postscript size (the layout and
//!   type FlatBuffers are not read);
//! * F3 (Future-proof File Format) files: format version, footer
//!   compression, checksum type, the Arrow schema, rows and row groups, the
//!   optional sections and the WebAssembly decoders embedded in the file.
//!
//! Specifications: Lance file format v2 (`lance/file/v2/file2.proto`,
//! `lance/file.proto`); Vortex file format (`VTXF` header and trailer);
//! F3 `format/File.fbs` (postscript and footer, commit bd92506).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::arrow::schema as arrow_schema;
use crate::plugin::flatbuf::FlatBuf;
use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for Lance and Vortex files.
pub struct Store;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.store",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "lance",
            name: "Lance",
            family: "columnar",
            mimes: &[],
            extensions: &["lance"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "vortex",
            name: "Vortex",
            family: "columnar",
            mimes: &[],
            extensions: &["vortex", "vtx"],
            magic: &[Magic::at(0, b"VTXF")],
            parent: None,
        },
        FormatSpec {
            id: "f3",
            name: "F3 (Future-proof File Format)",
            family: "columnar",
            mimes: &[],
            extensions: &["f3"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Fields described.
const MAX_FIELDS: usize = 500;

/// A Lance field: name, logical type, parent id.
struct Field {
    name: String,
    kind: String,
    parent: i64,
}

fn lance_type(id: i64, fields: &BTreeMap<i64, Field>, depth: usize) -> String {
    let Some(f) = fields.get(&id) else { return "?".into() };
    let children: Vec<(&i64, &Field)> = fields.iter().filter(|(_, c)| c.parent == id).collect();
    let s = match f.kind.as_str() {
        "list" | "large_list" | "fixed_size_list" if depth < 32 => {
            let inner = children.first().map_or_else(|| "?".into(), |(cid, _)| lance_type(**cid, fields, depth + 1));
            format!("{}<{inner}>", f.kind)
        }
        "struct" if depth < 32 => {
            let body: Vec<String> = children
                .iter()
                .take(100)
                .map(|(cid, c)| format!("{}: {}", c.name, lance_type(**cid, fields, depth + 1)))
                .collect();
            format!("struct<{}>", body.join(", "))
        }
        k => k.to_string(),
    };
    truncate_chars(&s, 300)
}

fn lance(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let tail = src.read_vec(len.saturating_sub(40), 40).map_err(|_| ExtractError::malformed("footer"))?;
    let u64_at = |i: usize| u64::from_le_bytes(tail[i..i + 8].try_into().unwrap_or_default());
    let u32_at = |i: usize| u32::from_le_bytes(tail[i..i + 4].try_into().unwrap_or_default());
    let u16_at = |i: usize| u16::from_le_bytes(tail[i..i + 2].try_into().unwrap_or_default());
    let (major, minor) = (u16_at(32), u16_at(34));
    cx.format_set("format_version", format!("{major}.{minor}"));
    if major < 2 {
        // Lance 0.x: a different footer; the version is all that is read.
        return Ok(());
    }
    let (gbo, buffers, columns) = (u64_at(16), u32_at(24), u32_at(28));
    cx.format_set("column_count", columns);
    cx.format_set("global_buffers", buffers);
    if buffers == 0 {
        return Ok(());
    }
    let entry = src.read_vec(gbo, 16).map_err(|_| ExtractError::malformed("global buffer table"))?;
    let pos = u64::from_le_bytes(entry[..8].try_into().map_err(|_| ExtractError::malformed("global buffer"))?);
    let size = u64::from_le_bytes(entry[8..].try_into().map_err(|_| ExtractError::malformed("global buffer"))?);
    let size = usize::try_from(size)
        .ok()
        .filter(|&s| s <= cx.parse_limit())
        .ok_or_else(|| ExtractError::LimitExceeded("max_parse_bytes".into()))?;
    let desc = src.read_vec(pos, size).map_err(|_| ExtractError::malformed("file descriptor"))?;
    if let Some(rows) = protowire::first(&desc, 2).and_then(Wire::int) {
        cx.format_set("rows", rows);
    }
    let Some(schema) = protowire::first(&desc, 1).and_then(Wire::bytes) else { return Ok(()) };
    let mut fields = BTreeMap::new();
    for (i, f) in protowire::all(schema, 1).filter_map(Wire::bytes).take(10_000).enumerate() {
        let id = protowire::first(f, 3).and_then(Wire::int).map_or(0, u64::cast_signed);
        let parent = protowire::first(f, 4).and_then(Wire::int).map_or(-1, u64::cast_signed);
        let name = protowire::first(f, 2).and_then(Wire::text).unwrap_or_default();
        let kind = protowire::first(f, 5).and_then(Wire::text).unwrap_or_default();
        // Ids are unique; fall back to the position for malformed ones.
        let key = if fields.contains_key(&id) { -2 - i64::try_from(i).unwrap_or(0) } else { id };
        fields.insert(key, Field { name, kind, parent });
    }
    let mut cols = Map::new();
    for (id, f) in fields.iter().filter(|(_, f)| f.parent < 0).take(MAX_FIELDS) {
        cols.insert(truncate_chars(&f.name, 200), Value::String(lance_type(*id, &fields, 0)));
    }
    cx.format_set("columns", Value::Object(cols));
    let meta: Map<String, Value> = protowire::all(schema, 5)
        .filter_map(Wire::bytes)
        .take(100)
        .filter_map(|kv| {
            let k = protowire::first(kv, 1).and_then(Wire::text)?;
            let v = protowire::first(kv, 2).and_then(Wire::bytes).unwrap_or_default();
            Some((truncate_chars(&k, 100), Value::String(format!("({} bytes)", v.len()))))
        })
        .collect();
    if !meta.is_empty() {
        cx.format_set("metadata", Value::Object(meta));
    }
    Ok(())
}

fn vortex(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let tail = src.read_vec(len.saturating_sub(8), 8).map_err(|_| ExtractError::malformed("trailer"))?;
    if &tail[4..] != b"VTXF" {
        return Err(ExtractError::malformed("no VTXF trailer (truncated file?)"));
    }
    cx.format_set("format_version", u16::from_le_bytes([tail[0], tail[1]]));
    cx.format_set("postscript_bytes", u16::from_le_bytes([tail[2], tail[3]]));
    Ok(())
}

/// The F3 postscript (the last 32 bytes, little-endian).
const F3_POSTSCRIPT: u64 = 32;

fn f3(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let ps = src.read_vec(len.saturating_sub(F3_POSTSCRIPT), 32).map_err(|_| ExtractError::malformed("postscript"))?;
    if &ps[30..] != b"F3" {
        return Err(ExtractError::malformed("no F3 postscript (truncated file?)"));
    }
    let u32_at = |i: usize| u32::from_le_bytes(ps[i..i + 4].try_into().unwrap_or_default());
    let (major, minor) = (u16::from_le_bytes([ps[26], ps[27]]), u16::from_le_bytes([ps[28], ps[29]]));
    cx.format_set("format_version", format!("{major}.{minor}"));
    cx.format_set("metadata_bytes", u32_at(0));
    let footer_size = u64::from(u32_at(4));
    let compression = match ps[8] {
        0 => None,
        1 => Some(Codec::Zstd),
        2 => Some(Codec::Lz4),
        _ => return Err(ExtractError::Unsupported("footer compression".into())),
    };
    cx.format_set("footer_compression", ["none", "zstd", "lz4"][usize::from(ps[8].min(2))]);
    cx.format_set(
        "checksum",
        match ps[9] {
            0 => "none",
            1 => "xxhash",
            2 => "crc32",
            _ => "other",
        },
    );
    let size = usize::try_from(footer_size)
        .ok()
        .filter(|&n| n <= cx.parse_limit())
        .ok_or_else(|| ExtractError::LimitExceeded("max_parse_bytes".into()))?;
    let at = len.checked_sub(F3_POSTSCRIPT + footer_size).ok_or_else(|| ExtractError::malformed("footer size"))?;
    let raw = src.read_vec(at, size).map_err(|_| ExtractError::malformed("footer"))?;
    let footer = match compression {
        None => raw,
        Some(c) => cx.decompress(&raw, c, cx.parse_limit())?.data,
    };
    let fb = FlatBuf(&footer);
    let root = fb.root().ok_or_else(|| ExtractError::malformed("footer"))?;
    // The Arrow schema, as an IPC message (with or without its prefix).
    if let Some(mut msg) = fb.bytes(root, 0) {
        if msg.starts_with(&[0xff; 4]) {
            msg = msg.get(8..).unwrap_or_default();
        }
        let m = FlatBuf(msg);
        if let Some(s) = m.root().and_then(|r| m.table(r, 2)) {
            arrow_schema(cx, &m, s);
        }
    }
    if let Some(rg) = fb.table(root, 2) {
        let n = fb.vector(rg, 0).map_or(0, |(_, n)| n);
        let rows: u64 = (0..n)
            .filter_map(|i| fb.element(rg, 0, i, 4))
            .map(|b| u64::from(u32::from_le_bytes(b.try_into().unwrap_or_default())))
            .sum();
        cx.format_set("row_groups", n);
        cx.format_set("rows", rows);
    }
    if let Some(opt) = fb.table(root, 3) {
        let names = fb.strings(opt, 0);
        if let Some(i) = names.iter().position(|n| n == "WASMBinaries") {
            let off = fb.element(opt, 1, i, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()));
            let sz = fb.element(opt, 2, i, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap_or_default()));
            if let (Some(off), Some(sz)) = (off, sz.and_then(|s| usize::try_from(s).ok()))
                && sz <= cx.parse_limit()
                && let Ok(sec) = src.read_vec(off, sz)
            {
                let w = FlatBuf(&sec);
                let wasm = w.root().and_then(|r| w.vector(r, 0)).map_or(0, |(_, n)| n);
                cx.format_set("wasm_decoders", wasm);
            }
        }
        if !names.is_empty() {
            cx.format_set(
                "optional_sections",
                names.into_iter().take(50).map(|n| truncate_chars(&n, 100)).collect::<Vec<_>>(),
            );
        }
    }
    if let Some((_, n)) = fb.vector(root, 4) {
        cx.format_set("encoding_versions", n);
    }
    Ok(())
}

impl Extractor for Store {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Lance files have no header; the 40-byte footer ends with `LANC`.
        let t = probe.tail;
        let ok = t.ends_with(b"LANC") && t.len() >= 40 && {
            let major = u16::from_le_bytes([t[t.len() - 8], t[t.len() - 7]]);
            major <= 8
        };
        if ok {
            return Some(Sniff {
                format: "lance",
                confidence: if probe.extension == Some("lance") { 0.95 } else { 0.8 },
            });
        }
        // F3: a 32-byte postscript ending in `F3` whose footer fits the file.
        let f3 = t.ends_with(b"F3") && t.len() >= 32 && {
            let ps = &t[t.len() - 32..];
            let footer = u64::from(u32::from_le_bytes(ps[4..8].try_into().unwrap_or_default()));
            footer > 0 && footer + 32 <= probe.len && ps[8] <= 2 && ps[9] <= 2
        };
        f3.then_some(Sniff { format: "f3", confidence: if probe.extension == Some("f3") { 0.95 } else { 0.7 } })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "lance" => lance(cx, src),
            "f3" => f3(cx, src),
            _ => vortex(cx, src),
        }
    }
}

crate::register_extractor!(Store);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    /// An F3 file from the `File.fbs` layout: a footer whose row groups
    /// hold 50 and 70 rows, then the postscript.
    fn f3_file() -> Vec<u8> {
        let mut b = vec![16, 0, 0, 0];
        b.extend([10, 0, 12, 0, 0, 0, 0, 0, 4, 0, 0, 0]); // Footer vtable: field 2 at +4 (padded)
        b.extend(12i32.to_le_bytes()); // Footer table at 16 → vtable at 4
        b.extend(12u32.to_le_bytes()); // field 2 → RowGroups at 32
        b.extend([6, 0, 8, 0, 4, 0, 0, 0]); // RowGroups vtable at 24: field 0 at +4
        b.extend(8i32.to_le_bytes()); // RowGroups table at 32 → vtable at 24
        b.extend(4u32.to_le_bytes()); // field 0 → vector at 40
        b.extend(2u32.to_le_bytes());
        b.extend(50u32.to_le_bytes());
        b.extend(70u32.to_le_bytes());
        let footer = u32::try_from(b.len()).unwrap();
        b.extend(footer.to_le_bytes()); // metadata size
        b.extend(footer.to_le_bytes()); // footer size
        b.extend([0, 1]); // uncompressed, xxhash
        b.extend([0; 16]); // checksums
        b.extend([0, 0, 1, 0]); // version 0.1
        b.extend(b"F3");
        b
    }

    #[test]
    fn f3_footer() {
        let r = report_for("readings.f3", &f3_file());
        assert_eq!(r.identification.format, "f3");
        let f = &r.format["f3"];
        assert_eq!(f["rows"], 120);
        assert_eq!(f["row_groups"], 2);
        assert_eq!(f["format_version"], "0.1");
        assert_eq!(f["checksum"], "xxhash");
    }

    crate::fixture_tests!("lance", "vortex");
}
