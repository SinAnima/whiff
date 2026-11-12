//! Binary data of no known format: printable strings (ASCII and UTF-16LE),
//! URLs among them, signatures of embedded files (ZIP, PDF, PNG, ELF, PE,
//! gzip, …) and a per-block entropy profile that separates structured data
//! from compressed or encrypted payloads, and the zero bytes (ratio,
//! all-zero 4 KiB blocks, trailing zeros) that show sparse, preallocated
//! or wiped regions.

use std::collections::BTreeMap;

use aho_corasick::AhoCorasick;
use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Source, TextRole, truncate_chars,
};

/// Extractor for unidentified binary data.
pub struct Unknown;

static META: ExtractorMeta = ExtractorMeta {
    id: "binary.unknown",
    version: 1,
    cost: Cost::Scan,
    priority: -10,
    formats: &[FormatSpec {
        id: "binary",
        name: "Binary data",
        family: "binary.unknown",
        mimes: &["application/octet-stream"],
        extensions: &["bin", "dat"],
        magic: &[],
        parent: None,
    }],
};

/// Shortest run counted as a string.
const MIN_STRING: usize = 6;
const SAMPLE_STRINGS: usize = 40;
const BLOCK: usize = 64 * 1024;

/// `(kind, signature)` of files that are often embedded in others.
const SIGNATURES: &[(&str, &[u8])] = &[
    ("zip", b"PK\x03\x04"),
    ("pdf", b"%PDF-"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xFF\xD8\xFF\xE0"),
    ("jpeg", b"\xFF\xD8\xFF\xE1"),
    ("gif", b"GIF89a"),
    ("gif", b"GIF87a"),
    ("elf", b"\x7FELF"),
    ("pe", b"This program cannot be run in DOS mode"),
    ("gzip", b"\x1F\x8B\x08"),
    ("7z", b"7z\xBC\xAF\x27\x1C"),
    ("rar", b"Rar!\x1A\x07"),
    ("xz", b"\xFD7zXZ\x00"),
    ("zstd", b"\x28\xB5\x2F\xFD"),
    ("sqlite", b"SQLite format 3\x00"),
    ("ogg", b"OggS\x00"),
    ("pem", b"-----BEGIN "),
    ("xml", b"<?xml version="),
    ("postscript", b"%!PS-Adobe"),
    ("mach_o", b"\xCF\xFA\xED\xFE"),
    ("java_class", b"\xCA\xFE\xBA\xBE"),
    ("wasm", b"\x00asm\x01\x00\x00\x00"),
];

impl Extractor for Unknown {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        let strings = strings(&data);
        cx.checkpoint()?;
        let mut text = String::new();
        for s in &strings.all {
            if text.len() > 1 << 20 {
                break;
            }
            text.push_str(s);
            text.push('\n');
        }
        if !text.is_empty() {
            cx.emit_text(TextRole::Data, &text);
        }
        let mut urls: BTreeMap<String, u64> = BTreeMap::new();
        for s in &strings.all {
            for part in s.split_whitespace() {
                if let Some(rest) = part.strip_prefix("https://").or_else(|| part.strip_prefix("http://")) {
                    let host = rest.split(['/', '?', '#', ':', '"', '\'']).next().unwrap_or("").to_ascii_lowercase();
                    if !host.is_empty() {
                        *urls.entry(host).or_default() += 1;
                    }
                }
            }
        }
        let embedded = embedded(&data);
        cx.checkpoint()?;
        let profile = entropy_profile(&data);

        let mut f = Map::new();
        f.insert("bytes_examined".into(), json!(data.len()));
        if cut {
            f.insert("examined_prefix_only".into(), json!(true));
        }
        f.insert("strings".into(), json!({ "ascii": strings.ascii, "utf16le": strings.utf16 }));
        // Every printable run is counted, but only word-like ones are shown:
        // random bytes produce plenty of six-character noise.
        let sample: Vec<String> =
            strings.all.iter().filter(|s| word_like(s)).take(SAMPLE_STRINGS).map(|s| truncate_chars(s, 120)).collect();
        f.insert("strings_sample".into(), json!(sample));
        if !urls.is_empty() {
            let mut top: Vec<(String, u64)> = urls.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            f.insert(
                "url_hosts".into(),
                json!(top.into_iter().take(10).map(|(h, n)| json!({ "host": h, "count": n })).collect::<Vec<_>>()),
            );
        }
        if !embedded.is_empty() {
            f.insert("embedded_signatures".into(), Value::Object(embedded));
        }
        f.insert("entropy_profile".into(), profile);
        if !data.is_empty() {
            let zeros = data.iter().fold(0usize, |n, &b| n + usize::from(b == 0));
            f.insert("zero_ratio".into(), json!((zeros as f64 / data.len() as f64 * 1000.0).round() / 1000.0));
            let blocks = data.as_chunks::<4096>().0;
            let empty = blocks.iter().filter(|b| b.iter().all(|&x| x == 0)).count();
            if empty > 0 {
                f.insert("zero_blocks".into(), json!({ "empty": empty, "of": blocks.len(), "block_bytes": 4096 }));
            }
            let trailing = data.iter().rev().take_while(|&&b| b == 0).count();
            if !cut && trailing >= 512 {
                f.insert("trailing_zero_bytes".into(), json!(trailing));
            }
        }
        let fmt = cx.format();
        for (k, v) in f {
            fmt.insert(k, v);
        }
        Ok(())
    }
}

crate::register_extractor!(Unknown);

#[derive(Default)]
struct Strings {
    ascii: u64,
    utf16: u64,
    /// Distinct strings in order of appearance, capped.
    all: Vec<String>,
}

/// Mostly letters, digits and spaces, with at least one run of four letters.
fn word_like(s: &str) -> bool {
    let n = s.chars().count();
    let good = s.chars().filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '/' | ':')).count();
    let mut run = 0;
    let letters = s.chars().any(|c| {
        run = if c.is_alphabetic() { run + 1 } else { 0 };
        run >= 4
    });
    letters && good * 10 >= n * 8
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

fn strings(data: &[u8]) -> Strings {
    let mut out = Strings::default();
    let mut seen = std::collections::HashSet::new();
    let mut keep = |s: String, out: &mut Strings| {
        if out.all.len() < 20_000 && seen.insert(s.clone()) {
            out.all.push(s);
        }
    };
    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_STRING {
                    out.ascii += 1;
                    keep(String::from_utf8_lossy(&data[s..i]).into_owned(), &mut out);
                }
                start = None;
            }
            _ => {}
        }
    }
    // UTF-16LE: printable byte, then NUL, repeated. A run cannot start right
    // after a printable byte: that byte ends an ASCII string instead.
    let mut i = 0;
    while i + 1 < data.len() {
        if i > 0 && printable(data[i - 1]) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < data.len() && printable(data[j]) && data[j + 1] == 0 {
            j += 2;
        }
        if (j - i) / 2 >= MIN_STRING {
            out.utf16 += 1;
            let s: String = data[i..j].iter().step_by(2).map(|&b| char::from(b)).collect();
            keep(s, &mut out);
            i = j;
        } else {
            i += if j > i { j - i } else { 1 };
        }
    }
    out
}

/// Signature kind → `{count, first_offsets}`, ignoring offset 0 (that is the file itself).
fn embedded(data: &[u8]) -> Map<String, Value> {
    let Ok(ac) = AhoCorasick::new(SIGNATURES.iter().map(|(_, s)| *s)) else { return Map::new() };
    let mut found: BTreeMap<&str, (u64, Vec<usize>)> = BTreeMap::new();
    for m in ac.find_overlapping_iter(data) {
        if m.start() == 0 {
            continue;
        }
        let kind = SIGNATURES[m.pattern().as_usize()].0;
        let e = found.entry(kind).or_default();
        e.0 += 1;
        if e.1.len() < 5 {
            e.1.push(m.start());
        }
    }
    found.into_iter().map(|(k, (n, offs))| (k.to_string(), json!({ "count": n, "first_offsets": offs }))).collect()
}

fn entropy(block: &[u8]) -> f64 {
    let mut h = [0u64; 256];
    for &b in block {
        h[b as usize] += 1;
    }
    let n = block.len() as f64;
    h.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// Entropy per 64 KiB block: min, max, mean, and how many blocks look compressed or encrypted.
fn entropy_profile(data: &[u8]) -> Value {
    let values: Vec<f64> = data.chunks(BLOCK).take(4096).filter(|b| b.len() >= 256).map(entropy).collect();
    if values.is_empty() {
        return json!({ "blocks": 0 });
    }
    let round = |x: f64| (x * 1000.0).round() / 1000.0;
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(0.0, f64::max);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let high = values.iter().filter(|&&e| e > 7.5).count();
    json!({
        "block_bytes": BLOCK,
        "blocks": values.len(),
        "min": round(min),
        "max": round(max),
        "mean": round(mean),
        "high_entropy_blocks": high,
        "likely_compressed_or_encrypted": high * 10 >= values.len() * 9,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_and_signatures() {
        let mut data = vec![0u8, 1, 2];
        data.extend_from_slice(b"hello world");
        data.push(0);
        for c in "wide string".bytes() {
            data.extend_from_slice(&[c, 0]);
        }
        data.extend_from_slice(b"\x00PK\x03\x04rest");
        let s = strings(&data);
        assert_eq!((s.ascii, s.utf16), (1, 1));
        assert_eq!(s.all, ["hello world", "wide string"]);
        let e = embedded(&data);
        assert_eq!(e["zip"]["count"], 1);
        assert!((entropy(&[7; 100])).abs() < 1e-9);
    }

    crate::fixture_tests!("binary");
}
