//! Generic fuzz target. With `WHIFF_FUZZ_EXTRACTOR=<id>` only that extractor
//! runs, with its format forced. With `WHIFF_FUZZ_EXTRACTORS=<id>,<id>,…`
//! only those extractors are registered (a shard of the nightly job), with
//! detection. Otherwise the whole engine (detection included) is fuzzed. The
//! first input byte picks the file extension of one registered format so
//! every extractor gets reached. Run via `whiff-dev fuzz`.
#![no_main]

use std::sync::LazyLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use whiff::report::RunStatus;
use whiff::{Engine, Hashes, Limits, Registry};

static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    // No file deadline: the watchdog would hide a hang from libFuzzer, whose
    // own `-timeout` should report it instead. Extractor deadlines stay on.
    let limits =
        Limits::default().max_read_bytes(16 << 20).file_timeout(None).extractor_timeout(Some(Duration::from_secs(2)));
    let mut builder = Engine::builder().limits(limits).hashes(Hashes::NONE);
    if let Ok(id) = std::env::var("WHIFF_FUZZ_EXTRACTOR") {
        let registry = Registry::builtin().retain_extractors(|e| e == id);
        let format = registry
            .extractors()
            .next()
            .and_then(|e| e.meta().formats.first())
            .unwrap_or_else(|| panic!("no extractor `{id}` in this build"))
            .id;
        builder = builder.registry(registry).format(format);
    } else if let Ok(ids) = std::env::var("WHIFF_FUZZ_EXTRACTORS") {
        let ids: Vec<&str> = ids.split(',').map(str::trim).filter(|id| !id.is_empty()).collect();
        let registry = Registry::builtin().retain_extractors(|e| ids.contains(&e));
        assert!(registry.extractors().next().is_some(), "none of `{}` in this build", ids.join(","));
        builder = builder.registry(registry);
    }
    builder.build()
});

/// One file extension per registered format, so the extension tie-break and
/// extension-only formats (CSV, INI, source code) are reached.
static EXTENSIONS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut v: Vec<&'static str> =
        ENGINE.registry().formats().filter_map(|(f, _)| f.extensions.first().copied()).collect();
    v.sort_unstable();
    v.dedup();
    v.push("bin");
    v
});

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else { return };
    let name = format!("fuzz.{}", EXTENSIONS[usize::from(pick) % EXTENSIONS.len()]);
    let report = ENGINE.extract_bytes(Some(&name), body.to_vec());
    // The engine contains panics; turn them back into crashes for libFuzzer.
    for run in &report.diagnostics.extractors {
        assert!(run.status != RunStatus::Internal, "{}: {:?}", run.id, run.error);
    }
});
