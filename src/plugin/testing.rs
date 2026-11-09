//! Helpers behind [`fixture_tests!`](crate::fixture_tests) and the conformance suite.

use std::path::{Path, PathBuf};

use crate::Engine;
use crate::report::{FsTimes, Report};

/// Strip fields that differ between machines and runs (paths, inodes,
/// filesystem times, ownership, timings) so reports can be snapshotted.
pub fn redact(report: &mut Report) {
    report.whiff.version = "[version]".into();
    report.source.path = None;
    let s = &mut report.system;
    s.device = None;
    s.inode = None;
    s.links = None;
    s.allocated_bytes = None;
    s.readonly = None;
    s.hidden = None;
    report.temporal.filesystem = FsTimes::default();
    let sec = &mut report.security;
    sec.mode = None;
    sec.permissions = None;
    sec.owner = None;
    sec.setuid = None;
    sec.setgid = None;
    sec.sticky = None;
    sec.acl = None;
    sec.xattrs.clear();
    report.diagnostics.elapsed_ms = 0.0;
    for run in &mut report.diagnostics.extractors {
        run.ms = 0.0;
    }
    for child in &mut report.embedded {
        redact(child);
    }
}

/// Sample files in `<manifest_dir>/tests/fixtures/<format_id>/`, sorted.
/// `SOURCE.md`, `README.md` and dot-files are not fixtures.
pub fn fixture_files(manifest_dir: &Path, format_id: &str) -> Vec<PathBuf> {
    let dir = manifest_dir.join("tests").join("fixtures").join(format_id);
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            !name.starts_with('.') && name != "SOURCE.md" && name != "README.md"
        })
        .collect();
    files.sort();
    files
}

/// Redacted reports for every fixture of `format_id`, keyed by file name.
pub fn fixture_reports(manifest_dir: &str, format_id: &str) -> Vec<(String, Report)> {
    let engine = Engine::new();
    fixture_files(Path::new(manifest_dir), format_id)
        .into_iter()
        .map(|path| {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mut report =
                engine.extract_path(&path).unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", path.display()));
            redact(&mut report);
            (name, report)
        })
        .collect()
}

/// The report for in-memory `bytes` named `name`, with embedded files
/// analysed one level deep: for unit tests over small synthetic inputs.
pub fn report_for(name: &str, bytes: &[u8]) -> Report {
    let engine = Engine::builder().limits(crate::engine::Limits::default().max_depth(1)).build();
    engine.extract_bytes(Some(name), bytes.to_vec())
}

/// [`report_for`] with `--privacy off`: for tests that check what the
/// strict mode keeps back.
pub fn report_without_privacy(name: &str, bytes: &[u8]) -> Report {
    let engine = Engine::builder()
        .limits(crate::engine::Limits::default().max_depth(1))
        .privacy(crate::engine::Privacy::Off)
        .build();
    engine.extract_bytes(Some(name), bytes.to_vec())
}

/// A ZIP archive of `(name, data, deflate?)` entries, for unit tests of
/// ZIP-based formats.
#[cfg(test)]
pub(crate) fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    crate::container::zip::tests::build(entries)
}

/// A compound file of `(path, data)` streams at the root or one storage
/// deep, for unit tests of OLE-based formats.
#[cfg(test)]
pub(crate) fn cfb(streams: &[(&str, &[u8])]) -> Vec<u8> {
    crate::container::cfb::tests::build(streams)
}

/// Snapshot-test every fixture of one or more formats:
/// `whiff::fixture_tests!("qoi");` or `fixture_tests!("json", "ndjson");`
/// inside a `#[cfg(test)] mod tests`.
///
/// Fixtures live in `tests/fixtures/<format>/`, snapshots in
/// `tests/snapshots/`. Requires `insta` as a dev-dependency.
#[macro_export]
macro_rules! fixture_tests {
    ($($format_id:literal),+ $(,)?) => {
        #[test]
        fn fixtures() {
            let mut settings = ::insta::Settings::clone_current();
            settings.set_snapshot_path(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"));
            settings.set_prepend_module_to_snapshot(false);
            $(
                let reports = $crate::plugin::testing::fixture_reports(env!("CARGO_MANIFEST_DIR"), $format_id);
                assert!(!reports.is_empty(), "no fixtures in tests/fixtures/{}/", $format_id);
                settings.bind(|| {
                    for (name, report) in reports {
                        ::insta::assert_json_snapshot!(format!("{}__{}", $format_id, name), report);
                    }
                });
            )+
        }
    };
}
