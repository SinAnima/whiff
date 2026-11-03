//! R data files written by the `fst` and `qs` packages:
//! * fst tables: format version, columns with their types (factor,
//!   timestamp, date, double, integer, logical, character …), rows, key
//!   columns and the column names;
//! * qs, qs2 and qdata serialisations: format version, compression,
//!   byte shuffling, endianness and checksum (the serialised object is
//!   not decoded).
//!
//! Specifications: the fstcore sources (`fststore.cpp`, "Table header",
//! "Chunkset header"; `character_v6.cpp`); the qs sources (`qs_common.h`,
//! `QsMetadata`) and qs2's `file_headers.h`.

use serde_json::{Map, Value};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for fst and qs files.
pub struct RData;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.rdata",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "fst",
            name: "R fst table",
            family: "columnar",
            mimes: &[],
            extensions: &["fst"],
            magic: &[Magic::at(44, b"PAAP")],
            parent: None,
        },
        FormatSpec {
            id: "qs",
            name: "R qs / qs2 serialisation",
            family: "columnar",
            mimes: &[],
            extensions: &["qs", "qs2", "qdata"],
            magic: &[
                Magic::at(0, b"\x0b\x0e\x0a\x0c"),
                Magic::at(0, b"\x0b\x0e\x0a\xc1"),
                Magic::at(0, b"\x0b\x0e\x0a\xcd"),
            ],
            parent: None,
        },
    ],
};

/// Columns described.
const MAX_COLUMNS: usize = 500;

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// fst column attributes (`FstColumnAttribute`).
fn fst_type(a: u16) -> &'static str {
    match a {
        2 => "character",
        3 => "factor",
        4 => "ordered factor",
        5 => "integer",
        6 => "timestamp (integer seconds)",
        7 => "time interval (integer seconds)",
        8 => "date (integer days)",
        9 => "time of day (integer seconds)",
        10 => "double",
        11 => "date",
        12 => "timestamp",
        13 => "time interval",
        14 => "time of day",
        15 => "logical",
        16 => "integer64",
        17 => "time (integer64 seconds)",
        18 => "raw",
        _ => "unknown",
    }
}

/// The column names: an uncompressed character block of the column-names
/// vector (one block; cumulative end offsets, NA bits, then the text).
fn fst_names(b: &[u8], at: usize, n: usize) -> Option<Vec<String>> {
    let flags = le32(b, at)?;
    if flags & 1 != 0 {
        return None; // compressed: not decoded
    }
    let sizes = at + 16;
    let ends: Vec<usize> =
        (0..n).map(|i| le32(b, sizes + 4 * i).and_then(|e| usize::try_from(e).ok())).collect::<Option<_>>()?;
    let text = sizes + 4 * n + 4 * (1 + n / 32);
    let mut start = 0;
    let mut out = Vec::with_capacity(n);
    for e in ends {
        let s = b.get(text + start..text + e)?;
        out.push(String::from_utf8_lossy(s).into_owned());
        start = e;
    }
    Some(out)
}

fn fst(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    cx.format_set("fst_version", le32(b, 8)?);
    let cols = usize::try_from(le32(b, 28)?).ok()?;
    let keys = usize::try_from(le32(b, 40)?).ok()?;
    cx.format_set("column_count", cols);
    let key_bytes = if keys == 0 { 0 } else { (keys % 2) * 4 + 4 * (keys + 2) };
    let cs = 48 + key_bytes;
    cx.format_set("rows", le64(b, cs + 64)?);
    let n = cols.min(MAX_COLUMNS);
    let attrs: Vec<u16> = (0..n).filter_map(|i| le16(b, cs + 80 + 2 * i)).collect();
    let names = fst_names(b, cs + 80 + 8 * cols + 24, cols).unwrap_or_default();
    let mut m = Map::new();
    for (i, a) in attrs.iter().enumerate() {
        let name = names.get(i).cloned().unwrap_or_else(|| format!("column {}", i + 1));
        m.insert(truncate_chars(&name, 200), Value::from(fst_type(*a)));
    }
    cx.format_set("columns", Value::Object(m));
    if keys > 0 {
        let pos: Vec<String> = (0..keys.min(50))
            .filter_map(|i| le32(b, 56 + 4 * i))
            .filter_map(|p| names.get(usize::try_from(p).ok()?).cloned())
            .collect();
        cx.format_set("key_columns", pos);
    }
    Some(())
}

fn qs(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    match *b.get(3)? {
        0x0c => {
            // qs: magic, 4 empty bytes, then format / hash / algorithm + shuffle / endian.
            let r = b.get(8..12)?;
            cx.format_set("package", "qs");
            cx.format_set("format_version", r[0]);
            cx.format_set("checksum", r[1] != 0);
            cx.format_set(
                "compression",
                match r[2] >> 4 {
                    0 => "zstd",
                    1 => "lz4",
                    2 => "lz4hc",
                    3 => "zstd_stream",
                    4 => "uncompressed",
                    _ => "other",
                },
            );
            let shuffle: Vec<&str> = [(1, "logical"), (2, "integer"), (4, "double"), (8, "complex")]
                .iter()
                .filter(|(bit, _)| r[2] & bit != 0)
                .map(|(_, n)| *n)
                .collect();
            cx.format_set("shuffled", shuffle);
            cx.format_set("endianness", if r[3] == 1 { "big" } else { "little" });
            cx.format_set("blocks", le64(b, 12)?);
        }
        tag @ (0xc1 | 0xcd) => {
            cx.format_set("package", if tag == 0xc1 { "qs2" } else { "qdata" });
            cx.format_set("format_version", *b.get(4)?);
            cx.format_set("compression", if *b.get(5)? == 1 { "zstd" } else { "other" });
            cx.format_set("endianness", if *b.get(6)? == 1 { "big" } else { "little" });
            cx.format_set("shuffled", *b.get(7)? == 1);
            cx.format_set("checksum", le64(b, 16)? != 0);
        }
        _ => return None,
    }
    Some(())
}

impl Extractor for RData {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        // Both headers sit in the first kilobytes (fst names past them are not needed).
        let n = usize::try_from(src.len()).unwrap_or(usize::MAX).min(cx.parse_limit()).min(1 << 20);
        let b = src.read_vec(0, n).map_err(|_| ExtractError::malformed("header"))?;
        let ok = if cx.format_id() == "fst" { fst(cx, &b) } else { qs(cx, &b) };
        ok.ok_or_else(|| ExtractError::malformed("header"))
    }
}

crate::register_extractor!(RData);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fst_type_names() {
        assert_eq!(fst_type(12), "timestamp");
        assert_eq!(fst_type(3), "factor");
        assert_eq!(fst_type(99), "unknown");
    }

    crate::fixture_tests!("fst", "qs");
}
