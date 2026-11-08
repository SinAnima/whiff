//! Engine behaviour, exercised with small test-only extractors.

use std::time::{Duration, Instant};

use whiff::plugin::{
    BlockDecoder, BlockKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic,
    Registry, Source, TextRole,
};
use whiff::report::{DetectedBy, FileKind, RunStatus};
use whiff::{Engine, Limits, Options, Profile, RiskCategory, Severity};

const DEMO_BLOCK: BlockKind = BlockKind("demo_block");

macro_rules! meta {
    ($id:literal, $format:literal, $magic:literal, $cost:expr) => {{
        static FORMATS: [FormatSpec; 1] = [FormatSpec {
            id: $format,
            name: "Test format",
            family: "test",
            mimes: &["application/x-test"],
            extensions: &["tst"],
            magic: &[Magic::prefix($magic)],
            parent: None,
        }];
        static META: ExtractorMeta = ExtractorMeta { id: $id, version: 1, formats: &FORMATS, cost: $cost, priority: 0 };
        &META
    }};
}

/// Writes through every writer, emits a block, text and a child.
struct Demo;
impl Extractor for Demo {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.demo", "demo", b"DEMO", Cost::Header)
    }
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut header = [0u8; 4];
        src.read_exact_at(0, &mut header)?;
        cx.content().title("Demo title").author("Ada").keyword("demo").heading(1, "Intro").language("en", 0.9);
        cx.content().title("ignored: first write wins");
        cx.temporal().source("demo.created").content_date(DateField::Created, "2026-01-02T03:04:05+02:00", true);
        cx.temporal().content_date(DateField::Modified, "2026-03-01T00:00:00Z", true);
        cx.rights().copyright("© 2026 Ada").license(Some("CC BY 4.0"), None);
        cx.security().active_content("macros").risk("demo_risk", Some("just a test".into()));
        cx.physical().image(640, 480).channels(3).bit_depth(8).color_space("sRGB");
        cx.format_set("header_bytes", 4);
        cx.emit_block(DEMO_BLOCK, b"key=value".to_vec());
        cx.emit_block(BlockKind("nobody_decodes_this"), vec![1, 2, 3]);
        cx.emit_text(TextRole::Body, "Some body text.");
        if src.len() > 4 {
            let rest = src.read_vec(4, usize::try_from(src.len() - 4).unwrap())?;
            cx.emit_child("inner.tst", rest)?;
        }
        Ok(())
    }
}

struct DemoDecoder;
impl BlockDecoder for DemoDecoder {
    fn kind(&self) -> BlockKind {
        DEMO_BLOCK
    }
    fn id(&self) -> &'static str {
        "meta.demo"
    }
    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = std::str::from_utf8(data).map_err(|e| ExtractError::malformed(e.to_string()))?;
        let (k, v) = text.split_once('=').ok_or_else(|| ExtractError::malformed("no ="))?;
        cx.metadata_set("demo", k, v);
        Ok(())
    }
}

struct Boom;
impl Extractor for Boom {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.boom", "boom", b"BOOM", Cost::Header)
    }
    fn extract(&self, _: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        panic!("boom goes the extractor")
    }
}

/// Reads the same bytes forever: must be stopped by the read budget.
struct Greedy;
impl Extractor for Greedy {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.greedy", "greedy", b"GRDY", Cost::Header)
    }
    fn extract(&self, src: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut buf = [0u8; 4];
        loop {
            src.read_exact_at(0, &mut buf)?;
        }
    }
}

/// Spins without reading: must be stopped by the deadline via `checkpoint`.
struct Sleepy;
impl Extractor for Sleepy {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.sleepy", "sleepy", b"SLPY", Cost::Header)
    }
    fn extract(&self, _: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        loop {
            cx.checkpoint()?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct Expensive;
impl Extractor for Expensive {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.expensive", "expensive", b"EXPN", Cost::Decode)
    }
    fn extract(&self, _: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        cx.format_set("decoded", true);
        Ok(())
    }
}

/// An extractor from another crate, added with `Registry::with`.
struct Registered;
impl Extractor for Registered {
    fn meta(&self) -> &'static ExtractorMeta {
        meta!("test.registered", "registered", b"REGD", Cost::Header)
    }
    fn extract(&self, _: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        cx.format_set("registered", true);
        Ok(())
    }
}

fn registry() -> Registry {
    Registry::builtin_analyzers()
        .with(Demo)
        .with(Boom)
        .with(Greedy)
        .with(Sleepy)
        .with(Expensive)
        .with_block_decoder(DemoDecoder)
}

fn engine() -> Engine {
    Engine::builder().registry(registry()).build()
}

fn redacted(mut r: whiff::Report) -> whiff::Report {
    whiff::plugin::testing::redact(&mut r);
    r
}

#[test]
fn builtin_registry_and_third_party_extractors() {
    let builtin = Registry::builtin();
    assert!(builtin.analyzers().any(|a| a.id() == "temporal.range"), "generated built-in list is complete");
    assert!(builtin.extractor("test.registered").is_none());
    let engine = Engine::builder().registry(Registry::builtin().with(Registered)).build();
    let r = engine.extract_bytes(Some("x.bin"), b"REGD".to_vec());
    assert_eq!(r.identification.extractor.as_deref(), Some("test.registered"));
    assert_eq!(r.format["registered"]["registered"], true);
}

#[test]
fn demo_report_snapshot() {
    let r = engine().extract_bytes(Some("demo.tst"), b"DEMO".to_vec());
    insta::assert_json_snapshot!("demo_report", redacted(r));
}

#[test]
fn writers_fill_normalised_sections() {
    let r = engine().extract_bytes(Some("demo.tst"), b"DEMO".to_vec());
    assert_eq!(r.identification.format, "demo");
    assert_eq!(r.identification.detected_by, DetectedBy::Magic);
    assert_eq!(r.identification.extension_matches, Some(true));
    assert_eq!(r.content.title.as_deref(), Some("Demo title"), "first write wins");
    assert_eq!(r.metadata["demo"]["key"], "value", "block routed to its decoder");
    assert_eq!(r.diagnostics.undecoded_blocks, vec!["nobody_decodes_this".to_string()]);
    assert_eq!(r.temporal.earliest.as_deref(), Some("2026-01-02T01:04:05Z"), "temporal.range analyzer ran");
    assert_eq!(r.temporal.latest.as_deref(), Some("2026-03-01T00:00:00Z"));
    assert_eq!(r.temporal.content[0].source, "demo.created");
    assert_eq!(r.physical.image.as_ref().map(|i| (i.width, i.height)), Some((640, 480)));
    assert!(r.integrity.sha256.is_some() && r.integrity.blake3.is_some());
    let ids: Vec<_> = r.diagnostics.extractors.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "test.demo",
            "meta.demo",
            "meta.mwg",
            "text.language",
            "text.excerpt",
            "text.keywords",
            "text.summary",
            "temporal.range",
            "privacy.scan"
        ]
    );
}

#[test]
fn panics_are_contained() {
    let r = engine().extract_bytes(Some("x.tst"), b"BOOM".to_vec());
    let run = &r.diagnostics.extractors[0];
    assert_eq!(run.status, RunStatus::Internal);
    assert!(run.error.as_deref().unwrap().contains("boom goes the extractor"));
    assert_eq!(r.identification.format, "boom");
    assert!(r.integrity.sha256.is_some(), "the rest of the pipeline still ran");
}

#[test]
fn read_budget_stops_runaway_reads() {
    let limits = Limits::default().max_read_bytes(1 << 20);
    let r = Engine::builder().registry(registry()).limits(limits).build().extract_bytes(None, b"GRDY".to_vec());
    let run = &r.diagnostics.extractors[0];
    assert_eq!(run.status, RunStatus::Error);
    assert_eq!(run.error_kind.as_deref(), Some("limit_exceeded"));
    assert!(r.diagnostics.limits_hit.contains(&"read_bytes".to_string()));
    assert!(r.diagnostics.truncated);
}

#[test]
fn deadline_stops_spinning_extractors() {
    let limits = Limits::default().extractor_timeout(Some(Duration::from_millis(100)));
    let start = Instant::now();
    let r = Engine::builder().registry(registry()).limits(limits).build().extract_bytes(None, b"SLPY".to_vec());
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(r.diagnostics.extractors[0].error_kind.as_deref(), Some("timeout"));
    assert!(r.diagnostics.limits_hit.contains(&"timeout".to_string()));
}

/// Spins without reading or checking the deadline (like a parser stuck in a
/// pathological input) for a bounded time, so the abandoned thread ends.
struct Stuck;
impl Extractor for Stuck {
    fn meta(&self) -> &'static ExtractorMeta {
        static META: ExtractorMeta = ExtractorMeta {
            id: "test.stuck",
            version: 1,
            cost: Cost::Header,
            priority: 0,
            formats: &[FormatSpec {
                id: "stuck",
                name: "Stuck",
                family: "test",
                mimes: &["application/x-stuck"],
                extensions: &["stuck"],
                magic: &[Magic::prefix(b"STCK")],
                parent: None,
            }],
        };
        &META
    }
    fn extract(&self, _: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(6) {
            std::hint::spin_loop();
        }
        Ok(())
    }
}

#[test]
fn watchdog_abandons_extractors_that_ignore_deadlines() {
    let limits = Limits::default().file_timeout(Some(Duration::from_millis(200)));
    let engine = Engine::builder().registry(Registry::builtin_analyzers().with(Stuck)).limits(limits).build();
    let start = Instant::now();
    let r = engine.extract_bytes(Some("x.stuck"), b"STCK".to_vec());
    let waited = start.elapsed();
    assert!(waited < Duration::from_secs(5), "returned after {waited:?}");
    assert_eq!(r.identification.format, "stuck", "detection still reported");
    assert!(r.diagnostics.limits_hit.contains(&"timeout".to_string()));
    assert!(r.diagnostics.warnings.iter().any(|w| w.contains("abandoned")));
    assert!(r.diagnostics.extractors.iter().all(|e| e.id != "test.stuck"), "the stuck extractor is not re-run");

    // Files go through the same watchdog.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("y.stuck");
    std::fs::write(&p, b"STCK").unwrap();
    let r = engine.extract_path(&p).unwrap();
    assert!(r.diagnostics.limits_hit.contains(&"timeout".to_string()));
    assert_eq!(r.system.size_bytes, Some(4));

    // The abandoned workers are still spinning; the next file gets a new one
    // instead of queuing behind them.
    let start = Instant::now();
    let r = engine.extract_bytes(Some("z.txt"), b"plain text\n".to_vec());
    assert!(start.elapsed() < Duration::from_secs(1), "queued behind the stuck worker");
    assert!(!r.diagnostics.truncated && r.diagnostics.warnings.is_empty(), "{:?}", r.diagnostics.warnings);
}

/// Records the thread each extraction runs on.
struct WhichThread;
static THREADS: std::sync::Mutex<Vec<std::thread::ThreadId>> = std::sync::Mutex::new(Vec::new());
impl Extractor for WhichThread {
    fn meta(&self) -> &'static ExtractorMeta {
        static META: ExtractorMeta = ExtractorMeta {
            id: "test.which_thread",
            version: 1,
            cost: Cost::Header,
            priority: 0,
            formats: &[FormatSpec {
                id: "which_thread",
                name: "Which thread",
                family: "test",
                mimes: &["application/x-which-thread"],
                extensions: &["which"],
                magic: &[Magic::prefix(b"WHCH")],
                parent: None,
            }],
        };
        &META
    }
    fn extract(&self, _: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        THREADS.lock().unwrap().push(std::thread::current().id());
        Ok(())
    }
}

#[test]
fn one_worker_thread_serves_successive_files() {
    let limits = Limits::default().file_timeout(Some(Duration::from_secs(10)));
    let engine = Engine::builder().registry(Registry::builtin_analyzers().with(WhichThread)).limits(limits).build();
    std::thread::spawn(move || {
        for _ in 0..3 {
            engine.extract_bytes(Some("a.which"), b"WHCH".to_vec());
        }
    })
    .join()
    .unwrap();
    let seen = THREADS.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|t| *t == seen[0]), "{seen:?}");
}

#[test]
fn children_recurse_until_max_depth() {
    // DEMO + DEMO + DEMO: root → child → grandchild (not analysed at depth 1).
    let r = engine().extract_bytes(Some("outer.tst"), b"DEMODEMODEMO".to_vec());
    assert_eq!(r.embedded.len(), 1);
    let child = &r.embedded[0];
    assert_eq!(child.source.name.as_deref(), Some("inner.tst"));
    assert_eq!(child.identification.format, "demo");
    assert_eq!(child.system.kind, FileKind::Memory);
    assert_eq!(child.embedded.len(), 1);
    assert!(child.embedded[0].diagnostics.warnings[0].contains("max_depth"));
    assert!(r.diagnostics.limits_hit.contains(&"max_depth".to_string()));

    // Risks roll up: the child's own risk is counted in the parent, and a
    // kind outside the vocabulary is `other` / `medium`.
    let risk = &child.security.risks[0];
    assert_eq!(
        (risk.kind.as_str(), risk.category, risk.severity),
        ("demo_risk", RiskCategory::Other, Severity::Medium)
    );
    assert_eq!(child.security.risk_level, Some(Severity::Medium));
    assert_eq!(r.security.embedded_risks.get("demo_risk"), Some(&1));
    assert_eq!(r.security.risk_level, Some(Severity::Medium));
}

#[test]
fn profile_filters_by_cost() {
    let standard = engine().extract_bytes(None, b"EXPN".to_vec());
    assert!(standard.diagnostics.extractors.iter().all(|r| r.id != "test.expensive"));
    assert!(standard.diagnostics.warnings.iter().any(|w| w.contains("skipped by the Standard profile")));
    let full =
        Engine::builder().registry(registry()).profile(Profile::Full).build().extract_bytes(None, b"EXPN".to_vec());
    assert_eq!(full.format["expensive"]["decoded"], true);
}

#[test]
fn only_and_skip() {
    let only = Engine::builder().registry(registry()).only(["test.boom"]).build();
    let r = only.extract_bytes(None, b"DEMO".to_vec());
    assert!(r.identification.extractor.is_none(), "demo extractor filtered out by --only");
    let skip = Engine::builder().registry(registry()).skip(["meta"]).build();
    let r = skip.extract_bytes(None, b"DEMO".to_vec());
    assert!(r.metadata.get("demo").is_none(), "decoder group skipped");
    assert_eq!(r.diagnostics.undecoded_blocks.len(), 2);
}

/// A format without magic, found by extension only.
struct Csvish;
impl Extractor for Csvish {
    fn meta(&self) -> &'static ExtractorMeta {
        static F: [FormatSpec; 1] = [FormatSpec {
            id: "csvish",
            name: "CSV-ish",
            family: "data.csv",
            mimes: &["text/csv"],
            extensions: &["csv"],
            magic: &[],
            parent: None,
        }];
        static M: ExtractorMeta =
            ExtractorMeta { id: "test.csvish", version: 1, formats: &F, cost: Cost::Header, priority: 0 };
        &M
    }
    fn extract(&self, _: &mut dyn Source, _: &mut Context<'_>) -> Result<(), ExtractError> {
        Ok(())
    }
}

#[test]
fn forced_format_and_extension_only_detection() {
    let forced = Engine::builder().registry(registry()).format("demo").build();
    let r = forced.extract_bytes(None, b"DEMO-but-not-really".to_vec());
    assert_eq!(r.identification.detected_by, DetectedBy::Forced);

    // A magic-less format is found by extension alone.
    let e = Engine::builder().registry(Registry::empty().with(Csvish)).build();
    let r = e.extract_bytes(Some("table.csv"), b"a,b\n1,2\n".to_vec());
    assert_eq!(r.identification.format, "csvish");
    assert_eq!(r.identification.detected_by, DetectedBy::Extension);
    let r = e.extract_bytes(Some("table.txt"), b"a,b\n1,2\n".to_vec());
    assert_eq!(r.identification.format, "text");
}

#[test]
fn extension_mismatch_is_flagged() {
    let r = engine().extract_bytes(Some("photo.jpg"), b"DEMO".to_vec());
    assert_eq!(r.identification.format, "demo");
    assert_eq!(r.identification.extension_matches, Some(false));
}

#[test]
fn provenance_records_sources() {
    let e = Engine::builder().registry(registry()).provenance(true).build();
    let r = e.extract_bytes(None, b"DEMO".to_vec());
    let prov = r.diagnostics.provenance.expect("provenance requested");
    assert_eq!(prov["content.title"], "test.demo");
    assert_eq!(prov["temporal.content"], "demo.created");
    let off = engine().extract_bytes(None, b"DEMO".to_vec());
    assert!(off.diagnostics.provenance.is_none());
}

#[test]
fn builtin_fallbacks() {
    let e = Engine::builder().registry(Registry::empty()).build();
    assert_eq!(e.extract_bytes(None, Vec::new()).identification.format, "empty");
    assert_eq!(e.extract_bytes(None, b"plain words\n".to_vec()).identification.format, "text");
    let bin = e.extract_bytes(None, vec![0, 159, 146, 150, 0, 1]);
    assert_eq!(bin.identification.format, "binary");
    assert_eq!(bin.identification.extractor, None);
}

#[test]
fn paths_directories_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::new();
    let r = e.extract_path(dir.path()).unwrap();
    assert_eq!(r.identification.format, "directory");
    assert_eq!(r.system.kind, FileKind::Directory);
    assert!(r.integrity.sha256.is_none());

    let empty = dir.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    let r = e.extract_path(&empty).unwrap();
    assert_eq!(r.identification.format, "empty");
    assert_eq!(r.system.size_bytes, Some(0));
    assert!(r.temporal.filesystem.modified.is_some());

    assert!(e.extract_path(dir.path().join("missing")).is_err());

    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&empty, &link).unwrap();
        let r = e.extract_path(&link).unwrap();
        assert_eq!(r.system.kind, FileKind::Symlink);
        assert!(r.system.symlink_target.as_deref().unwrap().ends_with("empty"));
        assert_eq!(r.identification.format, "empty", "content of the target is described");
        let broken = dir.path().join("broken");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &broken).unwrap();
        let r = e.extract_path(&broken).unwrap();
        assert_eq!(r.identification.format, "symlink");
    }
}

#[test]
fn file_and_bytes_agree() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("demo.tst");
    std::fs::write(&p, b"DEMO").unwrap();
    let from_file = engine().extract_path(&p).unwrap();
    let from_bytes = engine().extract_bytes(Some("demo.tst"), b"DEMO".to_vec());
    assert_eq!(from_file.content, from_bytes.content);
    assert_eq!(from_file.integrity, from_bytes.integrity);
    assert_eq!(from_file.physical.entropy, from_bytes.physical.entropy);
}

#[test]
fn minimal_profile_skips_hashing() {
    let e = Engine::builder().registry(registry()).profile(Profile::Minimal).build();
    let r = e.extract_bytes(None, b"DEMO".to_vec());
    assert!(r.integrity.sha256.is_none());
    assert_eq!(r.integrity.skipped.as_deref(), Some("profile"));
    assert!(r.physical.entropy.is_some());
}

#[test]
fn reader_input_is_bounded() {
    let options = Options { limits: Limits::default().max_read_bytes(8), ..Options::default() };
    let e = Engine::builder().registry(Registry::empty()).options(options).build();
    let r = e.extract_reader(Some("-"), &b"0123456789abcdef"[..]).unwrap();
    assert_eq!(r.system.size_bytes, Some(8));
    assert!(r.diagnostics.truncated);
}

#[test]
fn random_input_never_breaks_the_engine() {
    let e = Engine::builder().registry(registry().retain_extractors(|id| id != "test.boom")).build();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for len in [0usize, 1, 3, 4, 5, 63, 64, 4096, 70_000] {
        let data: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        let r = e.extract_bytes(Some("random.bin"), data);
        assert!(r.diagnostics.extractors.iter().all(|run| run.status != RunStatus::Internal));
        let json = serde_json::to_value(&r).unwrap();
        let back: whiff::Report = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
    }
}

/// Fuzz crash (CA 9A 3B under `image.pnm`): a two-byte character where the
/// Netpbm magic should be was sliced inside the character.
#[test]
fn pnm_rejects_a_non_ascii_header() {
    let engine = Engine::builder().only(["image.pnm"]).build();
    let r = engine.extract_bytes(Some("x.pnm"), b"\xca\x9a;".to_vec());
    let pnm = r.diagnostics.extractors.iter().find(|e| e.id == "image.pnm").expect("image.pnm ran");
    assert_eq!(pnm.status, RunStatus::Error, "rejected, not a panic");
}
