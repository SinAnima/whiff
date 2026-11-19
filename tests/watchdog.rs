//! The file watchdog with a sniffer that ignores deadlines. In its own test
//! binary: the count of abandoned workers is process-wide.

use std::time::{Duration, Instant};

use whiff::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Registry, Sniff, Source,
};
use whiff::{Engine, Limits};

/// A sniffer that sleeps 4 s on every input: detection itself overruns.
struct SleepySniffer;
impl Extractor for SleepySniffer {
    fn meta(&self) -> &'static ExtractorMeta {
        static META: ExtractorMeta = ExtractorMeta {
            id: "test.sleepy_sniffer",
            version: 1,
            cost: Cost::Header,
            priority: 0,
            formats: &[FormatSpec {
                id: "sleepy_sniffer",
                name: "Sleepy sniffer",
                family: "test",
                mimes: &["application/x-sleepy-sniffer"],
                extensions: &["zzz"],
                magic: &[Magic::prefix(b"ZZZZ")],
                parent: None,
            }],
        };
        &META
    }
    fn sniff(&self, _: &Probe<'_>) -> Option<Sniff> {
        std::thread::sleep(Duration::from_secs(4));
        None
    }
    fn extract(&self, _: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        Ok(())
    }
}

#[test]
fn overrunning_detection_is_not_rerun_and_abandoned_workers_are_capped() {
    let limits = Limits::default().file_timeout(Some(Duration::from_millis(200)));
    let engine = Engine::builder().registry(Registry::builtin_analyzers().with(SleepySniffer)).limits(limits).build();
    let mut skipped = 0;
    for _ in 0..12 {
        let start = Instant::now();
        let r = engine.extract_bytes(Some("note.txt"), b"plain text\n".to_vec());
        // The fallback never runs the 4 s sniffer on the caller.
        assert!(start.elapsed() < Duration::from_secs(1), "took {:?}", start.elapsed());
        assert_eq!(r.identification.format, "text", "built-in fallback only");
        assert!(r.diagnostics.limits_hit.contains(&"timeout".to_string()));
        assert!(r.diagnostics.truncated);
        let w = &r.diagnostics.warnings;
        if w.iter().any(|w| w.starts_with("extraction skipped")) {
            skipped += 1;
        } else {
            assert!(w.iter().any(|w| w.starts_with("extraction abandoned")), "{w:?}");
        }
    }
    // Eight workers were abandoned; the next four calls started none.
    assert_eq!(skipped, 4);
}
