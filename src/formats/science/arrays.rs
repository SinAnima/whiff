//! Array files:
//! * NumPy `.npy`: format version, dtype, shape, memory order, the data
//!   size, and whether it holds pickled objects; `.npz`: every array
//!   member with its dtype and shape (compressed or not);
//! * MATLAB MAT-files v4 and v5 (v7.3 is HDF5, read there): the header
//!   text, platform and creation date, byte order, and every variable with
//!   its class, size and (structs) field names, through compressed
//!   elements too.
//!
//! Specifications: NumPy NEP 1 ("A simple file format for NumPy arrays",
//! versions 1.0–3.0); MathWorks "MAT-File Format" (v4, v5 / v7).

#![allow(clippy::many_single_char_names)] // header field offsets

use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    truncate_chars, zip_names,
};

/// Extractor for NumPy and MATLAB array files.
pub struct Arrays;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.arrays",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "npy",
            name: "NumPy NPY / NPZ",
            family: "sci",
            mimes: &[],
            extensions: &["npy"],
            magic: &[Magic::at(0, b"\x93NUMPY")],
            parent: None,
        },
        FormatSpec {
            id: "npz",
            name: "NumPy NPZ archive",
            family: "sci",
            mimes: &[],
            extensions: &["npz"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "mat",
            name: "MATLAB MAT v5",
            family: "sci",
            mimes: &["application/x-matlab-data"],
            extensions: &[],
            magic: &[Magic::at(0, b"MATLAB 5.0 MAT-file")],
            parent: None,
        },
        FormatSpec {
            id: "mat_v4",
            name: "MATLAB MAT v4",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
    ],
};

/// Variables and arrays listed.
const MAX_VARS: usize = 500;

/// A NumPy dtype descriptor (`<f4`, `|S10`, `<U3` …) in words.
fn descr(d: &str) -> String {
    let (order, code) = d.split_at(d.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(0));
    let kind = code.get(..1).unwrap_or("");
    let n: usize = code.get(1..).and_then(|s| s.parse().ok()).unwrap_or(0);
    let base = match kind {
        "f" => format!("float{}", n * 8),
        "i" => format!("int{}", n * 8),
        "u" => format!("uint{}", n * 8),
        "c" => format!("complex{}", n * 8),
        "b" => "bool".into(),
        "S" => format!("bytes[{n}]"),
        "U" => format!("unicode[{n}]"),
        "M" => format!("datetime64{}", code.get(2..).unwrap_or("")),
        "m" => format!("timedelta64{}", code.get(2..).unwrap_or("")),
        "O" => "object".into(),
        "V" => format!("void[{n}]"),
        _ => d.to_string(),
    };
    if order == ">" && n > 1 { format!("{base} (big-endian)") } else { base }
}

/// The header dictionary of a `.npy`: (version, descr, fortran order, shape, data offset).
fn npy_header(b: &[u8]) -> Option<(String, String, bool, Vec<u64>, usize)> {
    if !b.starts_with(b"\x93NUMPY") {
        return None;
    }
    let major = *b.get(6)?;
    let (len, start) = if major == 1 {
        (usize::from(u16::from_le_bytes([*b.get(8)?, *b.get(9)?])), 10)
    } else {
        (usize::try_from(u32::from_le_bytes(b.get(8..12)?.try_into().ok()?)).ok()?, 12)
    };
    let text = String::from_utf8_lossy(b.get(start..start + len.min(b.len().saturating_sub(start)))?).into_owned();
    let value = |key: &str| -> Option<String> {
        let i = text.find(&format!("'{key}'"))? + key.len() + 2;
        let rest = text[i..].trim_start().strip_prefix(':')?.trim_start();
        Some(match rest.chars().next()? {
            '\'' => rest[1..].split('\'').next()?.to_string(),
            '(' => rest[1..].split(')').next()?.to_string(),
            '[' => rest[..=rest.find(']')?].to_string(),
            _ => rest.split([',', '}']).next()?.trim().to_string(),
        })
    };
    let d = value("descr")?;
    let fortran = value("fortran_order").is_some_and(|v| v == "True");
    let shape: Vec<u64> = value("shape")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().trim_end_matches('L').parse().ok())
        .collect(); // Python 2: `2L`
    Some((format!("{}.{}", major, b.get(7)?), d, fortran, shape, start + len))
}

fn npy_text(d: &str, shape: &[u64]) -> String {
    let dims =
        if shape.is_empty() { "scalar".into() } else { shape.iter().map(u64::to_string).collect::<Vec<_>>().join("x") };
    let d = if d.starts_with('[') { "structured".into() } else { descr(d) };
    format!("{d} {dims}")
}

fn mat_class(c: u8) -> &'static str {
    match c {
        1 => "cell",
        2 => "struct",
        3 => "object",
        4 => "char",
        5 => "sparse",
        6 => "double",
        7 => "single",
        8 => "int8",
        9 => "uint8",
        10 => "int16",
        11 => "uint16",
        12 => "int32",
        13 => "uint32",
        14 => "int64",
        15 => "uint64",
        16 => "function",
        17 => "opaque",
        _ => "unknown",
    }
}

/// A MAT v5 reader (byte order from the header).
struct Mat {
    big: bool,
}

impl Mat {
    fn u32(&self, b: &[u8], at: usize) -> Option<u32> {
        let r: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) })
    }

    /// A data element at `at`: (type, data, next offset), with the small
    /// element format (size in the upper half of the tag).
    fn element<'a>(&self, b: &'a [u8], at: usize) -> Option<(u32, &'a [u8], usize)> {
        let tag = self.u32(b, at)?;
        if tag >> 16 != 0 {
            let n = usize::try_from(tag >> 16).ok()?;
            return Some((tag & 0xffff, b.get(at + 4..at + 4 + n.min(4))?, at + 8));
        }
        let n = usize::try_from(self.u32(b, at + 4)?).ok()?;
        let data = b.get(at + 8..at.checked_add(8)?.checked_add(n)?)?;
        // Elements are 8-byte aligned (compressed ones are not padded).
        let next = at + 8 + if tag == 15 { n } else { n.div_ceil(8) * 8 };
        Some((tag, data, next))
    }

    /// A matrix (`miMATRIX`): (name, description).
    fn matrix(&self, m: &[u8]) -> Option<(String, String)> {
        let (_, flags, at) = self.element(m, 0)?;
        let class = u8::try_from(self.u32(flags, 0)? & 0xff).ok()?;
        let fl = self.u32(flags, 0)?;
        let (_, dims, at) = self.element(m, at)?;
        let dims: Vec<String> =
            dims.as_chunks::<4>().0.iter().take(32).map(|c| self.u32(c, 0).unwrap_or(0).to_string()).collect();
        let (_, name, at) = self.element(m, at)?;
        let name = String::from_utf8_lossy(name).trim_end_matches('\0').to_string();
        let mut desc = format!("{} {}", mat_class(class), dims.join("x"));
        if fl & 0x800 != 0 {
            desc.push_str(" complex");
        }
        if fl & 0x200 != 0 {
            desc = desc.replacen("uint8", "logical", 1);
        }
        if class == 2 {
            // Struct: field name length, then the names.
            if let Some((_, len, at)) = self.element(m, at)
                && let Some((_, names, _)) = self.element(m, at)
            {
                let w = usize::try_from(self.u32(len, 0).unwrap_or(32)).unwrap_or(32).max(1);
                let fields: Vec<String> = names
                    .chunks(w)
                    .take(64)
                    .map(|f| String::from_utf8_lossy(f).trim_end_matches('\0').to_string())
                    .filter(|f| !f.is_empty())
                    .collect();
                let _ = write!(desc, " (fields: {})", fields.join(", "));
            }
        }
        Some((name, truncate_chars(&desc, 300)))
    }
}

fn mat_v5(cx: &mut Context<'_>, b: &[u8]) {
    let text = String::from_utf8_lossy(&b[..116.min(b.len())]).trim_end_matches(['\0', ' ']).to_string();
    cx.format_set("header", truncate_chars(&text, 116));
    if let Some(p) = text.split("Platform: ").nth(1).and_then(|r| r.split(',').next()) {
        cx.format_set("platform", truncate_chars(p.trim(), 50));
    }
    if let Some(c) = text.split("Created on: ").nth(1) {
        cx.format_set("created_on", truncate_chars(c.trim(), 50));
    }
    let big = b.get(126..128) == Some(b"MI");
    cx.format_set("byte_order", if big { "big-endian" } else { "little-endian" });
    let m = Mat { big };
    let mut vars = Map::new();
    let mut compressed = 0u64;
    let mut at = 128;
    while let Some((kind, data, next)) = m.element(b, at) {
        let inner;
        let body = if kind == 15 {
            compressed += 1;
            inner = cx.inflate_prefix(data, Compression::Zlib, cx.parse_limit()).unwrap_or_default();
            let Some((14, d, _)) = m.element(&inner, 0) else {
                at = next;
                continue;
            };
            d
        } else if kind == 14 {
            data
        } else {
            at = next;
            continue;
        };
        if let Some((name, desc)) = m.matrix(body)
            && vars.len() < MAX_VARS
        {
            // The unnamed matrix holds function-handle workspaces (SciPy's name).
            let name = if name.is_empty() { "__function_workspace__".into() } else { truncate_chars(&name, 100) };
            vars.insert(name, Value::String(desc));
        }
        if next <= at {
            break;
        }
        at = next;
    }
    cx.format_set("variable_count", vars.len());
    cx.format_set("variables", Value::Object(vars));
    if compressed > 0 {
        cx.format_set("compressed_variables", compressed);
    }
}

/// A MAT v4 matrix header at `at`: (name, description, next offset).
fn mat_v4_matrix(b: &[u8], at: usize) -> Option<(String, String, usize)> {
    // MOPT's M digit is the byte order: 0 little-endian, 1 big-endian
    // (written in that order).
    let raw: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    let big = u32::from_le_bytes(raw) >= 1000;
    let mopt = if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) };
    let (m, rest) = (mopt / 1000, mopt % 1000);
    let (o, p, t) = (rest / 100, (rest % 100) / 10, rest % 10);
    if m != u32::from(big) || o != 0 || p > 5 || t > 2 {
        return None;
    }
    let rd = |i: usize| -> Option<u32> {
        let r: [u8; 4] = b.get(at + i..at + i + 4)?.try_into().ok()?;
        Some(if big { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) })
    };
    let (rows, cols, imag, namlen) = (rd(4)?, rd(8)?, rd(12)?, rd(16)?);
    let n = usize::try_from(namlen).ok().filter(|&n| (1..=64).contains(&n))?;
    let name = b.get(at + 20..at + 20 + n)?;
    if name.last() != Some(&0) || !name[..n - 1].iter().all(u8::is_ascii_graphic) {
        return None;
    }
    let size = [8usize, 4, 4, 2, 2, 1][usize::try_from(p).ok()?];
    let class = match (t, p) {
        (1, _) => "char",
        (2, _) => "sparse",
        (_, 0) => "double",
        (_, 1) => "single",
        (_, 2) => "int32",
        (_, 3) => "int16",
        (_, 4) => "uint16",
        _ => "uint8",
    };
    let cells = u64::from(rows) * u64::from(cols) * if imag != 0 { 2 } else { 1 };
    let next = (at + 20 + n).checked_add(usize::try_from(cells).ok()?.checked_mul(size)?)?;
    // A sparse matrix is stored as (row, column, value) triplets; the last
    // row holds the logical size.
    let (rows, cols) = match (t, p, rows) {
        (2, 0, r @ 1..) => {
            let f = |col: u32| -> Option<u32> {
                let i = at + 20 + n + 8 * usize::try_from(u64::from(col) * u64::from(r) + u64::from(r - 1)).ok()?;
                let raw: [u8; 8] = b.get(i..i + 8)?.try_into().ok()?;
                let v = if big { f64::from_be_bytes(raw) } else { f64::from_le_bytes(raw) };
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // checked range
                (v.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&v)).then_some(v as u32)
            };
            f(0).zip(f(1)).unwrap_or((rows, cols))
        }
        _ => (rows, cols),
    };
    let desc = format!("{class} {rows}x{cols}{}", if imag != 0 { " complex" } else { "" });
    Some((String::from_utf8_lossy(&name[..n - 1]).into_owned(), desc, next))
}

impl Extractor for Arrays {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.extension == Some("npz")
            || zip_names(probe, 50).iter().any(|n| n.to_ascii_lowercase().ends_with(".npy"))
        {
            let names = zip_names(probe, 2000);
            if !names.is_empty() && names.iter().all(|n| n.to_ascii_lowercase().ends_with(".npy")) {
                return Some(Sniff { format: "npz", confidence: 0.97 });
            }
        }
        // MAT v4 has no header: a plausible first matrix and the extension.
        if probe.extension == Some("mat")
            && mat_v4_matrix(probe.head, 0).is_some_and(|(_, _, next)| next as u64 <= probe.len)
        {
            return Some(Sniff { format: "mat_v4", confidence: 0.9 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            "npy" => {
                let head = src
                    .read_vec(0, usize::try_from(src.len()).unwrap_or(0).min(1 << 20))
                    .map_err(|_| ExtractError::malformed("header"))?;
                let (version, d, fortran, shape, offset) =
                    npy_header(&head).ok_or_else(|| ExtractError::malformed("NPY header"))?;
                cx.format_set("npy_version", version);
                cx.format_set("dtype", if d.starts_with('[') { "structured".into() } else { descr(&d) });
                cx.format_set("descr", truncate_chars(&d, 300));
                cx.format_set("shape", shape.clone());
                cx.format_set("elements", super::product(&shape));
                cx.format_set("order", if fortran { "F" } else { "C" });
                cx.format_set("data_bytes", src.len().saturating_sub(offset as u64));
                if d.contains('O') {
                    // Object arrays are pickles: loading them (allow_pickle) runs code.
                    cx.format_set("pickled_objects", true);
                }
            }
            "npz" => {
                let zip = Zip::open(src, 100_000)?;
                let mut arrays = Map::new();
                let entries: Vec<_> = zip
                    .entries
                    .iter()
                    .filter(|e| e.name.to_ascii_lowercase().ends_with(".npy"))
                    .take(MAX_VARS)
                    .cloned()
                    .collect();
                cx.format_set(
                    "arrays_count",
                    zip.entries.iter().filter(|e| e.name.to_ascii_lowercase().ends_with(".npy")).count(),
                );
                cx.format_set("compressed", entries.iter().any(|e| e.method != 0));
                for e in entries {
                    let name = e.name.trim_end_matches(".npy").to_string();
                    let desc = match zip.read_prefix(src, &e, cx, 4096) {
                        Ok((h, _)) => npy_header(&h).map_or_else(|| "?".into(), |(_, d, _, s, _)| npy_text(&d, &s)),
                        Err(_) => "?".into(),
                    };
                    arrays.insert(truncate_chars(&name, 200), Value::String(desc));
                }
                cx.format_set("arrays", Value::Object(arrays));
            }
            "mat" => {
                let (b, _) = cx.read_bytes(src)?;
                mat_v5(cx, &b);
            }
            _ => {
                let (b, _) = cx.read_bytes(src)?;
                let mut vars = Map::new();
                let mut at = 0;
                while let Some((name, desc, next)) = mat_v4_matrix(&b, at) {
                    if vars.len() < MAX_VARS {
                        vars.insert(truncate_chars(&name, 100), Value::String(desc));
                    }
                    at = next;
                }
                cx.format_set("variable_count", vars.len());
                cx.format_set("variables", Value::Object(vars));
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Arrays);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numpy_headers() {
        let mut b = b"\x93NUMPY\x01\x00".to_vec();
        let h = b"{'descr': '<f4', 'fortran_order': False, 'shape': (48, 3), }";
        b.extend(u16::try_from(h.len()).unwrap().to_le_bytes());
        b.extend(h);
        let (v, d, f, s, _) = npy_header(&b).unwrap();
        assert_eq!((v.as_str(), d.as_str(), f, s), ("1.0", "<f4", false, vec![48, 3]));
        assert_eq!(descr(">i8"), "int64 (big-endian)");
        assert_eq!(descr("<U3"), "unicode[3]");
        // Python 2 wrote long integers in the shape: `(2L,)`.
        let mut b = b"\x93NUMPY\x01\x00".to_vec();
        let h = b"{'descr': '<i8', 'fortran_order': True, 'shape': (2L, 3L), }";
        b.extend(u16::try_from(h.len()).unwrap().to_le_bytes());
        b.extend(h);
        let (_, _, f, s, _) = npy_header(&b).unwrap();
        assert_eq!((f, s), (true, vec![2, 3]));
    }

    /// A MAT v4 matrix header: MOPT, rows, columns, imaginary flag, name.
    fn v4(big: bool, mopt: u32, rows: u32, cols: u32, data: &[f64]) -> Vec<u8> {
        let int = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut b = Vec::new();
        for v in [mopt, rows, cols, 0, 2] {
            b.extend(int(v));
        }
        b.extend(b"a\0");
        for d in data {
            b.extend(if big { d.to_be_bytes() } else { d.to_le_bytes() });
        }
        b
    }

    #[test]
    fn mat_v4_byte_orders() {
        let six = [0.0; 6];
        assert_eq!(mat_v4_matrix(&v4(false, 0, 2, 3, &six), 0).unwrap().1, "double 2x3");
        assert_eq!(mat_v4_matrix(&v4(true, 1000, 2, 3, &six), 0).unwrap().1, "double 2x3");
        // M must match the byte order the header is written in.
        assert!(mat_v4_matrix(&v4(true, 0, 2, 3, &six), 0).is_none());
        // Sparse (type 2): two triplets, then the logical size in the last row.
        let sparse = [1.0, 2.0, 7.0, 1.0, 3.0, 9.0, 5.0, 6.0, 0.0];
        assert_eq!(mat_v4_matrix(&v4(false, 2, 3, 3, &sparse), 0).unwrap().1, "sparse 7x9");
    }

    crate::fixture_tests!("npy", "npz", "mat", "mat_v4");
}
