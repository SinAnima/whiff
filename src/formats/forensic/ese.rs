//! Extensible Storage Engine (JET Blue) databases (`.edb`, `.dat`: SRUM,
//! `WebCache`, Windows Search, Exchange, Active Directory): file type, format
//! version and revision, page size, database state (clean or dirty
//! shutdown), creation time and the last consistent and attach times.
//! The tables are not read.
//!
//! Specification: libyal "Extensible Storage Engine (ESE) Database File
//! (EDB) format", file header.

use super::le;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for ESE databases.
pub struct Ese;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.ese",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "ese",
        name: "Windows ESE database",
        family: "db",
        mimes: &[],
        extensions: &["edb", "dat", "jfm"],
        magic: &[Magic::at(4, b"\xef\xcd\xab\x89")],
        parent: None,
    }],
};

/// A `JET_LOGTIME` (seconds, minutes, hours, day, month, year − 1900).
fn logtime(b: &[u8]) -> Option<String> {
    let [s, mi, h, d, mo, y, ..] = *b else { return None };
    if mo == 0 || d == 0 || mo > 12 || d > 31 || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(format!("{:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}", 1900 + u32::from(y)))
}

impl Extractor for Ese {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut h = vec![0u8; 668.min(usize::try_from(src.len()).unwrap_or(0))];
        src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("ESE header"))?;
        let u = |at: usize| h.get(at..at + 4).map_or(0, le);
        cx.format_set("file_type", if u(12) == 1 { "streaming" } else { "database" });
        cx.format_set("format_version", format!("{:#x}", u(8)));
        cx.format_set("format_revision", format!("{:#x}", u(232)));
        let page = u(236);
        if page > 0 {
            cx.format_set("page_size", page);
        }
        cx.format_set(
            "state",
            match u(52) {
                1 => "just_created",
                2 => "dirty_shutdown",
                3 => "clean_shutdown",
                4 => "being_converted",
                5 => "force_detach",
                _ => "unknown",
            },
        );
        // Local times of the machine that wrote them: no time zone recorded.
        for (at, key) in [(28, "created"), (64, "last_consistent"), (72, "last_attached"), (88, "last_detached")] {
            if let Some(t) = h.get(at..at + 8).and_then(logtime) {
                cx.format_set(key, t);
            }
        }
        if src.len() >= u64::from(u32::try_from(page).unwrap_or(0)) && page > 0 {
            // Two header pages, then data pages.
            cx.format_set("pages", (src.len() / page).saturating_sub(2));
        }
        Ok(())
    }
}

crate::register_extractor!(Ese);

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("ese");

    #[test]
    fn jet_logtime() {
        assert_eq!(logtime(&[5, 4, 3, 1, 9, 125, 0, 0]).as_deref(), Some("2025-09-01T03:04:05"));
        assert_eq!(logtime(&[0; 8]), None);
    }
}
