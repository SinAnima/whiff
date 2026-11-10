//! Format detection.
//!
//! Signatures come from the [`FormatSpec`]s of every registered extractor, so
//! a new format brings its own magic and nothing central needs editing. The
//! steps are:
//!
//! 1. magic signatures (longer signatures score higher);
//! 2. extractor sniffers ([`Extractor::sniff`](crate::plugin::Extractor::sniff));
//! 3. extension: a small boost for a candidate it agrees with, or a weak
//!    candidate for magic-less formats such as CSV;
//! 4. the `file-format` signature database, which names formats this build
//!    has no extractor for (`extractor: null`, plus `available_with_feature`
//!    when an opt-in feature would add one);
//! 5. built-in fallbacks: `empty`, `text` (with encoding), `binary`. A
//!    registered extractor declaring the fallback id (`text.plain` declares
//!    `text`) handles it.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::plugin::{FormatSpec, Probe, Registry};
use crate::report::{Candidate, DetectedBy, Identification};

/// Formats in the catalogue (`data/formats.tsv`), by extension and MIME type.
mod catalogue {
    include!(concat!(env!("OUT_DIR"), "/catalogue.rs"));
}

/// Confidence given to a `file-format` database match: above extension-only
/// candidates and the text fallback, below registered magic and sniffers.
const DATABASE_CONFIDENCE: f64 = 0.5;

/// Detection result before it is written into the report.
#[derive(Debug, Clone)]
pub struct Detection {
    /// The chosen format; `None` when no registered extractor handles it.
    pub spec: Option<&'static FormatSpec>,
    /// Identification to write into the report.
    pub identification: Identification,
}

struct Scored {
    spec: &'static FormatSpec,
    confidence: f64,
    by: DetectedBy,
}

/// Detect the format of the input described by `probe`.
pub fn detect(registry: &Registry, probe: &Probe<'_>, forced: Option<&str>) -> Detection {
    let ext = probe.extension;
    let mut scored: Vec<Scored> = Vec::new();

    if let Some(id) = forced
        && let Some((spec, _)) = registry.formats().find(|(f, _)| f.id == id)
    {
        scored.push(Scored { spec, confidence: 1.0, by: DetectedBy::Forced });
    }

    if scored.is_empty() {
        for (spec, _) in registry.formats() {
            let best = spec.magic.iter().filter(|m| m.matches(probe.head)).map(|m| m.bytes.len()).max();
            if let Some(len) = best {
                let confidence = 0.6 + 0.04 * len.min(8) as f64;
                upsert(&mut scored, spec, confidence, DetectedBy::Magic);
            }
        }
        for e in registry.extractors() {
            // A sniffer is contributor code: contain its panics like the extractor's.
            let Ok(Some(sniff)) = catch_unwind(AssertUnwindSafe(|| e.sniff(probe))) else { continue };
            if let Some(spec) = e.meta().formats.iter().find(|f| f.id == sniff.format) {
                upsert(&mut scored, spec, sniff.confidence.clamp(0.0, 1.0), DetectedBy::Sniff);
            }
        }
        if let Some(ext) = ext {
            for (spec, _) in registry.formats() {
                if !spec.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    continue;
                }
                if let Some(s) = scored.iter_mut().find(|s| s.spec.id == spec.id) {
                    s.confidence = (s.confidence + 0.05).min(0.99);
                } else if spec.magic.is_empty() {
                    scored.push(Scored { spec, confidence: 0.35, by: DetectedBy::Extension });
                }
            }
        }
    }

    scored.sort_by(|a, b| b.confidence.total_cmp(&a.confidence).then_with(|| a.spec.id.cmp(b.spec.id)));
    let mut candidates: Vec<Candidate> = scored
        .iter()
        .take(5)
        .map(|s| Candidate { format: s.spec.id.to_string(), confidence: round3(s.confidence) })
        .collect();

    let fallback = fallback(probe);
    // Magic databases are unreliable on text, so for text content any
    // registered candidate (even extension-only) is preferred over them.
    let registered_wins = scored.first().is_some_and(|s| s.confidence > DATABASE_CONFIDENCE)
        || (fallback.format == "text" && !scored.is_empty());
    let mut database = if registered_wins { None } else { database(probe, fallback.encoding.clone()) };
    // The database named a format a registered extractor declares: use it.
    if let Some(db) = &database
        && let Some((spec, _)) = registry.formats().find(|(f, _)| f.mimes.contains(&db.mime.as_str()))
    {
        scored.retain(|s| s.spec.id != spec.id);
        scored.insert(0, Scored { spec, confidence: DATABASE_CONFIDENCE + 0.01, by: DetectedBy::Magic });
        database = None;
    }
    if let Some(top) = scored.first().filter(|s| s.confidence > fallback.confidence && database.is_none()) {
        let spec = top.spec;
        let extension_matches =
            ext.map(|e| spec.extensions.is_empty() || spec.extensions.iter().any(|x| x.eq_ignore_ascii_case(e)));
        return Detection {
            spec: Some(spec),
            identification: Identification {
                format: spec.id.to_string(),
                name: spec.name.to_string(),
                mime: spec.mimes.first().copied().unwrap_or("application/octet-stream").to_string(),
                family: Some(spec.family.to_string()),
                confidence: round3(top.confidence),
                detected_by: top.by,
                extension_matches,
                candidates: if candidates.len() > 1 { candidates } else { Vec::new() },
                encoding: fallback.encoding,
                extractor: None,
                available_with_feature: None,
            },
        };
    }
    if let Some(mut id) = database {
        candidates.insert(0, Candidate { format: id.format.clone(), confidence: DATABASE_CONFIDENCE });
        candidates.truncate(5);
        id.candidates = if candidates.len() > 1 { candidates } else { Vec::new() };
        id.extension_matches = ext.map(|e| {
            let listed = file_format::FileFormat::from_extension(e);
            listed.is_empty() || listed.iter().any(|f| f.media_type() == id.mime)
        });
        return Detection { spec: None, identification: id };
    }
    // The built-in fallback, handed to the extractor that declares its id.
    let spec = registry.formats().map(|(f, _)| f).find(|f| f.id == fallback.format);
    let identification = match spec {
        Some(spec) => Identification {
            name: spec.name.to_string(),
            family: Some(spec.family.to_string()),
            candidates,
            ..fallback
        },
        None => Identification { candidates, ..fallback },
    };
    Detection { spec, identification }
}

/// The `file-format` database's verdict, unless it only says text or binary.
fn database(probe: &Probe<'_>, encoding: Option<String>) -> Option<Identification> {
    if probe.head.is_empty() {
        return None;
    }
    let ff = catch_unwind(|| file_format::FileFormat::from_bytes(probe.head)).ok()?;
    if matches!(
        ff,
        file_format::FileFormat::ArbitraryBinaryData
            | file_format::FileFormat::PlainText
            | file_format::FileFormat::Empty
    ) {
        return None;
    }
    let id = ff
        .short_name()
        .map(str::to_ascii_lowercase)
        .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| ff.extension().to_string());
    let (family, feature) = catalogue_entry(ff.media_type(), ff.extension()).unzip();
    let available_with_feature = feature.filter(|f| !crate::enabled_features().contains(f)).map(str::to_string);
    Some(Identification {
        format: id,
        name: ff.name().to_string(),
        mime: ff.media_type().to_string(),
        family: family.map(str::to_string),
        confidence: DATABASE_CONFIDENCE,
        detected_by: DetectedBy::Magic,
        encoding,
        extractor: None,
        available_with_feature,
        ..Identification::default()
    })
}

/// `(family, feature)` of a catalogue format, by MIME type, then extension.
pub(crate) fn catalogue_entry(mime: &str, extension: &str) -> Option<(&'static str, &'static str)> {
    let find = |table: &'static [(&'static str, &'static str, &'static str)], key: &str| {
        let key = key.to_ascii_lowercase();
        table.binary_search_by(|(k, _, _)| (*k).cmp(key.as_str())).ok().map(|i| (table[i].1, table[i].2))
    };
    find(catalogue::BY_MIME, mime).or_else(|| find(catalogue::BY_EXTENSION, extension))
}

fn upsert(scored: &mut Vec<Scored>, spec: &'static FormatSpec, confidence: f64, by: DetectedBy) {
    match scored.iter_mut().find(|s| s.spec.id == spec.id) {
        Some(s) if confidence > s.confidence => {
            s.confidence = confidence;
            s.by = by;
        }
        Some(_) => {}
        None => scored.push(Scored { spec, confidence, by }),
    }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Identification for filesystem objects that are not regular files.
pub fn special(format: &str, name: &str, mime: &str) -> Identification {
    Identification {
        format: format.to_string(),
        name: name.to_string(),
        mime: mime.to_string(),
        confidence: 1.0,
        detected_by: DetectedBy::None,
        ..Identification::default()
    }
}

/// Built-in fallback: `empty`, `text` or `binary`.
fn fallback(probe: &Probe<'_>) -> Identification {
    if probe.len == 0 {
        return Identification {
            format: "empty".into(),
            name: "Empty file".into(),
            mime: "inode/x-empty".into(),
            confidence: 1.0,
            detected_by: DetectedBy::Heuristic,
            ..Identification::default()
        };
    }
    match text_encoding(probe.head, probe.len == probe.head.len() as u64) {
        Some(encoding) => Identification {
            format: "text".into(),
            name: "Text".into(),
            mime: "text/plain".into(),
            family: Some("text.plain".into()),
            confidence: 0.3,
            detected_by: DetectedBy::Heuristic,
            encoding: Some(encoding),
            ..Identification::default()
        },
        None => Identification {
            format: "binary".into(),
            name: "Binary data".into(),
            mime: "application/octet-stream".into(),
            family: Some("binary.unknown".into()),
            confidence: 0.1,
            detected_by: DetectedBy::Heuristic,
            ..Identification::default()
        },
    }
}

/// Guess whether `head` is text, and in which encoding (a lowercase WHATWG
/// name such as `utf-8`, `us-ascii`, `utf-16le` or `windows-1252`).
/// `complete` says whether `head` is the whole input (otherwise a multi-byte
/// character may be cut).
pub fn text_encoding(head: &[u8], complete: bool) -> Option<String> {
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some("utf-8".into());
    }
    // A UTF-16 byte-order mark, then mostly text: binary formats that start
    // with `FF FE` (SketchUp models, …) are not text.
    let utf16_text = |little: bool| {
        let units: Vec<u16> = head[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| if little { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) })
            .collect();
        let control = char::decode_utf16(units.iter().copied())
            .filter(|c| c.as_ref().map_or(true, |c| (*c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r' | '\x0c')))
            .count();
        control * 100 <= units.len()
    };
    if head.starts_with(&[0xFF, 0xFE]) {
        return utf16_text(true).then(|| "utf-16le".into());
    }
    if head.starts_with(&[0xFE, 0xFF]) {
        return utf16_text(false).then(|| "utf-16be".into());
    }
    if head.contains(&0) {
        return None;
    }
    let control = head.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)).count();
    if control * 100 > head.len() {
        return None;
    }
    let utf8_ok = match std::str::from_utf8(head) {
        Ok(_) => true,
        // A character cut at the end of a partial head is fine.
        Err(e) => !complete && e.error_len().is_none() && head.len() - e.valid_up_to() < 4,
    };
    if utf8_ok {
        return Some(if head.is_ascii() { "us-ascii" } else { "utf-8" }.into());
    }
    // Legacy 8-bit text: mostly printable ASCII with some high bytes.
    let printable = head.iter().filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')).count();
    (printable * 100 >= head.len() * 90).then(|| crate::text::decode::guess_legacy(head).name().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        let enc = |b: &[u8], complete| text_encoding(b, complete);
        assert_eq!(enc(b"hello\n", true).as_deref(), Some("us-ascii"));
        assert_eq!(enc("héllo".as_bytes(), true).as_deref(), Some("utf-8"));
        assert_eq!(enc(&[0xFF, 0xFE, b'h', 0], true).as_deref(), Some("utf-16le"));
        // A BOM followed by binary data is not text.
        assert_eq!(enc(&[0xFF, 0xFE, b'h', 0, 0, 0, 0, 0, 1, 0, 2, 0], true), None);
        assert_eq!(enc(&[0x7f, b'E', b'L', b'F', 0, 1], true), None);
        // Cut multi-byte char at the end of a partial head is still text.
        assert_eq!(enc(&"é".as_bytes()[..1], false).as_deref(), Some("utf-8"));
        assert_eq!(enc(b"caf\xe9 au lait", true).as_deref(), Some("windows-1252"));
    }

    #[test]
    fn catalogue_lookup() {
        assert_eq!(catalogue_entry("image/png", "png").map(|e| e.0), Some("image.raster"));
        assert_eq!(catalogue_entry("application/x-unknown", "shp").map(|e| e.1), Some("geo"));
        assert_eq!(catalogue_entry("application/x-unknown", "nope"), None);
    }

    #[test]
    fn database_names_formats_without_extractors() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89";
        let probe = Probe { head: png, tail: png, len: png.len() as u64, name: Some("a.png"), extension: Some("png") };
        let d = detect(&Registry::empty(), &probe, None);
        assert!(d.spec.is_none());
        assert_eq!(d.identification.format, "png");
        assert_eq!(d.identification.mime, "image/png");
        assert_eq!(d.identification.family.as_deref(), Some("image.raster"));
        assert_eq!(d.identification.extension_matches, Some(true));
    }
}
