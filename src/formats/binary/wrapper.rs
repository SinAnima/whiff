//! Partial downloads (`.part`, `.crdownload`, `.partial`, `.opdownload`)
//! and backup copies (`.bak`, `.old`, `.orig`) whose content no other
//! extractor recognises. Names with an extension underneath
//! (`report.pdf.crdownload`) never reach this extractor: the engine
//! detects them by that extension and records the wrapper in
//! `identification.wrapper`.
//!
//! Text is handed to the text extractor; binary data gets the generic
//! analysis of `binary.unknown` (strings, embedded signatures, entropy,
//! zero runs; a long run of zeros at the end of a partial download is
//! space reserved for the rest of the file).

use super::unknown::Unknown;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Source};

/// Extractor for unrecognised partial downloads and backup copies.
pub struct Wrapped;

static META: ExtractorMeta = ExtractorMeta {
    id: "binary.wrapper",
    version: 1,
    cost: Cost::Scan,
    priority: -5,
    formats: &[
        FormatSpec {
            id: "partial_download",
            name: "Partial download",
            family: "binary.unknown",
            mimes: &[],
            extensions: &["part", "crdownload", "partial", "opdownload", "!ut"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "backup_copy",
            name: "Backup copy",
            family: "binary.unknown",
            mimes: &[],
            extensions: &["bak", "old", "orig", "bkp"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Whether `head` reads as text: no NUL, few control bytes, UTF-8.
fn texty(head: &[u8]) -> bool {
    if head.is_empty() || head.contains(&0) {
        return false;
    }
    let control = head.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)).count();
    let valid = match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && head.len() - e.valid_up_to() < 4,
    };
    control * 100 <= head.len() && valid
}

impl Extractor for Wrapped {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if texty(src.head()) {
            cx.redirect("text");
            return Ok(());
        }
        Unknown.extract(src, cx)
    }
}

crate::register_extractor!(Wrapped);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("partial_download", "backup_copy");

    #[test]
    fn text_is_handed_on() {
        let r = crate::plugin::testing::report_for("notes.bak", b"high water 06:12\nlow water 12:30\n");
        assert_eq!(r.identification.format, "text");
        assert_eq!(r.identification.wrapper.as_ref().map(|w| w.kind.as_str()), Some("backup_copy"));
        let r = crate::plugin::testing::report_for("tides.csv.bak", b"time,height\n06:12,4.1\n");
        assert_eq!(r.identification.format, "csv");
        assert_eq!(r.identification.wrapper.and_then(|w| w.inner_extension).as_deref(), Some("csv"));
    }
}
