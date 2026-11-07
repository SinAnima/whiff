//! The conformance suite: checks every registered extractor without the
//! contributor writing any test code. `tests/conformance.rs` runs it over
//! [`Registry::builtin`](super::Registry::builtin).
//!
//! For each extractor and each declared format:
//!
//! * **fixtures** — at least one sample in `tests/fixtures/<format>/`;
//! * **detection** — each fixture is detected as that format, both with
//!   this extractor alone and with every registered extractor competing;
//! * **schema** — reports round-trip through the `whiff/1` model;
//! * **determinism** — two runs give identical (redacted) JSON;
//! * **field names** — keys in `format.<id>` are `snake_case`;
//! * **risk kinds** — every reported risk is in the vocabulary
//!   (`src/report/risk.rs`, listed in `docs/risks.md`);
//! * **robustness** — empty, 1-byte, magic-only, random, deeply nested,
//!   truncated and bit-flipped inputs never panic;
//! * **performance** — none of those inputs makes an extractor hit its
//!   deadline (a sign of super-linear work);
//! * **budget** — a 4 KiB read budget never causes a panic;
//! * **magic** — the declared magic matches all own fixtures and at most 5 %
//!   of other formats' fixtures (formats declaring it as their parent
//!   excepted).

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Extractor, FormatSpec, Registry};
use crate::report::{Report, RunStatus};
use crate::{Engine, Limits, Options};

use super::testing::{fixture_files, redact};

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Extractor id.
    pub extractor: String,
    /// Format id.
    pub format: String,
    /// Check name.
    pub check: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} / {}: {}", self.check, self.extractor, self.format, self.detail)
    }
}

/// Result of a conformance run.
#[derive(Debug, Default)]
pub struct Outcome {
    /// (extractor, format) pairs checked.
    pub checked: usize,
    /// Everything that failed.
    pub failures: Vec<Failure>,
}

/// Check every extractor in `registry`. `manifest_dir` holds `tests/fixtures/`.
pub fn check_registry(registry: &Registry, manifest_dir: &Path) -> Outcome {
    let all_fixtures: Vec<(&'static str, PathBuf)> = registry
        .formats()
        .flat_map(|(spec, _)| fixture_files(manifest_dir, spec.id).into_iter().map(move |p| (spec.id, p)))
        .collect();
    // Spread each extractor's formats evenly over the run (by their relative
    // position among its formats), so the many formats of one extractor
    // (`code.source` has 40) are not checked side by side: run at once they
    // contend for the same code, which under coverage instrumentation pushes
    // slow inputs past their deadlines. The order stays deterministic.
    let mut pairs: Vec<(usize, &dyn Extractor, &'static FormatSpec)> = registry
        .extractors()
        .flat_map(|e| {
            let n = e.meta().formats.len().max(1);
            e.meta().formats.iter().enumerate().map(move |(i, f)| (i * 1_000_000 / n, e, f))
        })
        .collect();
    pairs.sort_by_key(|(at, _, _)| *at);
    let pairs: Vec<(&dyn Extractor, &'static FormatSpec)> = pairs.into_iter().map(|(_, e, f)| (e, f)).collect();
    // Pairs are independent; check them on all cores, in a stable order.
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get).min(pairs.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut results: Vec<(usize, Vec<Failure>)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                std::thread::Builder::new()
                    .stack_size(16 * 1024 * 1024)
                    .spawn_scoped(scope, || {
                        let mut done = Vec::new();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(&(extractor, spec)) = pairs.get(i) else { break };
                            done.push((i, check_format(registry, extractor, spec, manifest_dir, &all_fixtures)));
                        }
                        done
                    })
                    .expect("spawn conformance worker")
            })
            .collect();
        workers.into_iter().flat_map(|w| w.join().unwrap_or_else(|p| std::panic::resume_unwind(p))).collect()
    });
    results.sort_by_key(|(i, _)| *i);
    Outcome { checked: pairs.len(), failures: results.into_iter().flat_map(|(_, f)| f).collect() }
}

fn engine_for(registry: &Registry, extractor_id: &str, options: Options) -> Engine {
    let only_this = registry.clone().retain_extractors(|id| id == extractor_id);
    Engine::builder().registry(only_this).options(options).build()
}

/// 5 s per extractor, 10 s per file; four times that in a coverage build.
///
/// The deadlines are wall-clock time, and instrumented code checked on every
/// core at once runs 20–30 times slower than a normal test build, so linear
/// work on the large inputs can pass the normal deadline. Super-linear work is
/// still caught: by the normal `cargo test` run, and here at the longer
/// deadline.
fn test_limits() -> Limits {
    let scale = if std::env::var_os("LLVM_PROFILE_FILE").is_some() { 4 } else { 1 };
    Limits::default()
        .file_timeout(Some(Duration::from_secs(10 * scale)))
        .extractor_timeout(Some(Duration::from_secs(5 * scale)))
}

fn check_format(
    registry: &Registry,
    extractor: &dyn Extractor,
    spec: &'static FormatSpec,
    manifest_dir: &Path,
    all_fixtures: &[(&'static str, PathBuf)],
) -> Vec<Failure> {
    let id = extractor.meta().id;
    let mut failures = Vec::new();
    let mut fail = |check: &'static str, detail: String| {
        failures.push(Failure { extractor: id.into(), format: spec.id.into(), check, detail });
    };

    let fixtures = fixture_files(manifest_dir, spec.id);
    if fixtures.is_empty() {
        fail("fixtures", format!("no files in tests/fixtures/{}/", spec.id));
    }

    let natural = engine_for(registry, id, Options { limits: test_limits(), ..Options::default() });
    // Every other extractor's sniffer competes in real use.
    let everyone = Engine::builder()
        .registry(registry.clone())
        .options(Options { limits: test_limits(), profile: crate::Profile::Minimal, ..Options::default() })
        .build();
    let forced = engine_for(
        registry,
        id,
        Options { limits: test_limits(), format: Some(spec.id.to_string()), ..Options::default() },
    );

    let mut fixture_bytes = Vec::new();
    for path in &fixtures {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (Ok(a), Ok(b)) = (natural.extract_path(path), natural.extract_path(path)) else {
            fail("fixtures", format!("{name}: unreadable"));
            continue;
        };
        if a.identification.format != spec.id {
            fail("detection", format!("{name}: detected as `{}`", a.identification.format));
        } else if let Ok(all) = everyone.extract_path(path)
            && all.identification.format != spec.id
        {
            fail(
                "detection",
                format!("{name}: detected as `{}` when all extractors compete", all.identification.format),
            );
        }
        if let Some(run) = panicked(&a) {
            fail("robustness", format!("{name}: {run}"));
        }
        for r in a.security.risks.iter().filter(|r| r.category == crate::report::RiskCategory::Other) {
            fail("risk_kinds", format!("{name}: risk kind `{}` is not in src/report/risk.rs", r.kind));
        }
        if serde_json::to_value(&a).ok().and_then(|v| serde_json::from_value::<Report>(v).ok()).as_ref() != Some(&a) {
            fail("schema", format!("{name}: report does not round-trip through the whiff/1 model"));
        }
        let (mut ra, mut rb) = (a.clone(), b);
        redact(&mut ra);
        redact(&mut rb);
        if ra != rb {
            fail("determinism", format!("{name}: two runs differ"));
        }
        if let Some(serde_json::Value::Object(map)) = a.format.get(spec.id) {
            for key in map.keys().filter(|k| !is_snake_case(k)) {
                fail("field_names", format!("{name}: format.{}.{key} is not snake_case", spec.id));
            }
        }
        if !spec.magic.is_empty() {
            if let Ok(data) = std::fs::read(path) {
                if !spec.magic.iter().any(|m| m.matches(&data)) {
                    fail("magic", format!("{name}: declared magic does not match"));
                }
                fixture_bytes.push((name, data));
            }
        } else if let Ok(data) = std::fs::read(path) {
            fixture_bytes.push((name, data));
        }
    }

    robustness(&forced, spec, &fixture_bytes, &mut fail);

    // Budget honesty: a tiny read budget must end in an error, not a panic.
    let tight = engine_for(
        registry,
        id,
        Options { limits: test_limits().max_read_bytes(4096), format: Some(spec.id.to_string()), ..Options::default() },
    );
    for (name, data) in &fixture_bytes {
        if let Some(run) = panicked(&tight.extract_bytes(Some(name), data.clone())) {
            fail("budget", format!("{name} with 4 KiB budget: {run}"));
        }
    }

    // Magic sanity: not matching (almost) everything else.
    if !spec.magic.is_empty() {
        // Formats declared as children of this one (xls inside cfb) share its
        // magic by design.
        let child = |f: &str| registry.formats().any(|(s, _)| s.id == f && s.parent == Some(spec.id));
        let others: Vec<&PathBuf> =
            all_fixtures.iter().filter(|(f, _)| *f != spec.id && !child(f)).map(|(_, p)| p).collect();
        let hits =
            others.iter().filter(|p| std::fs::read(p).is_ok_and(|d| spec.magic.iter().any(|m| m.matches(&d)))).count();
        if !others.is_empty() && hits * 20 > others.len() {
            fail("magic", format!("matches {hits} of {} other formats' fixtures", others.len()));
        }
    }
    failures
}

/// Hostile variants, with the format forced so the extractor runs.
fn robustness(
    forced: &Engine,
    spec: &'static FormatSpec,
    fixture_bytes: &[(String, Vec<u8>)],
    fail: &mut impl FnMut(&'static str, String),
) {
    let mut inputs: Vec<(String, Vec<u8>)> = vec![("empty".into(), Vec::new()), ("one byte".into(), vec![0])];
    if let Some(m) = spec.magic.first() {
        let mut v = vec![0u8; m.offset];
        v.extend_from_slice(m.bytes);
        inputs.push(("magic only".into(), v));
    }
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15 ^ spec.id.len() as u64);
    inputs.push(("random 256 KiB".into(), (0..256 * 1024).map(|_| rng.next_u8()).collect()));
    // Deep nesting: recursive parsers overflow the stack (which no
    // `catch_unwind` can contain) and some tree builders go quadratic.
    for (label, unit, n) in [
        ("nested brackets", "[", 100_000),
        ("nested objects", "{\"a\":", 50_000),
        ("nested elements", "<a>", 60_000),
        ("nested blocks", "<div>", 60_000),
        ("nested quotes", ">", 100_000),
        ("nested parentheses", "(", 100_000),
        ("nested list items", "- ", 50_000),
    ] {
        inputs.push((format!("{label} ×{n}"), unit.repeat(n).into_bytes()));
    }
    for (name, data) in fixture_bytes {
        for i in 1..=16usize {
            let cut = data.len() * i / 17;
            inputs.push((format!("{name} truncated at {cut}"), data[..cut].to_vec()));
        }
        for i in 0..16 {
            let mut v = data.clone();
            if !v.is_empty() {
                let pos = usize::try_from(rng.next() % v.len() as u64).unwrap_or(0);
                v[pos] ^= 1 << (i % 8);
            }
            inputs.push((format!("{name} bit-flip #{i}"), v));
        }
    }
    for (label, data) in inputs {
        let report = forced.extract_bytes(Some(&format!("input.{}", spec.extensions.first().unwrap_or(&"bin"))), data);
        if let Some(run) = panicked(&report) {
            fail("robustness", format!("{label}: {run}"));
        }
        // Inputs this small never need a deadline: hitting one means
        // pathological (super-linear) work.
        if let Some(run) = timed_out(&report) {
            fail("performance", format!("{label}: {run}"));
        }
    }
}

fn panicked(report: &Report) -> Option<String> {
    report
        .diagnostics
        .extractors
        .iter()
        .find(|r| r.status == RunStatus::Internal)
        .map(|r| format!("{}: {}", r.id, r.error.as_deref().unwrap_or("internal error")))
        .or_else(|| report.embedded.iter().find_map(panicked))
}

fn timed_out(report: &Report) -> Option<String> {
    if report.diagnostics.warnings.iter().any(|w| w.contains("abandoned")) {
        return Some("did not stop at the deadline; abandoned by the watchdog".into());
    }
    report
        .diagnostics
        .extractors
        .iter()
        .find(|r| r.error_kind.as_deref() == Some("timeout"))
        .map(|r| format!("{} hit its deadline", r.id))
        .or_else(|| report.embedded.iter().find_map(timed_out))
}

fn is_snake_case(key: &str) -> bool {
    key.starts_with(|c: char| c.is_ascii_lowercase())
        && key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Deterministic PRNG so failures reproduce.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[cfg(test)]
mod tests {
    use super::is_snake_case;

    #[test]
    fn snake_case() {
        assert!(is_snake_case("quality_estimate"));
        assert!(is_snake_case("mpf_images2"));
        assert!(!is_snake_case("QualityEstimate"));
        assert!(!is_snake_case("_x"));
        assert!(!is_snake_case("has-dash"));
    }
}
