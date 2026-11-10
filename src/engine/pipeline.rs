use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;

use super::Engine;
use super::universal::{file_kind, fill_from_metadata, integrity_for_bytes, integrity_for_file, text_encoding};
use crate::Error;
use crate::detect;
use crate::io::{Budget, BytesSource, FileSource, Source};
use crate::plugin::context::{PendingBlock, PendingChild};
use crate::plugin::{Context, Probe, TextStore};
use crate::report::{ExtractorRun, FileKind, Map, Report, RunStatus, SourceInfo};

/// Wall-clock stopwatch; reads 0 on `wasm32-unknown-unknown` (no clock).
struct Stopwatch(#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] std::time::Instant);

impl Stopwatch {
    fn start() -> Self {
        Self(
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            std::time::Instant::now(),
        )
    }

    fn ms(&self) -> f64 {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            (self.0.elapsed().as_secs_f64() * 1e6).round() / 1e3
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            0.0
        }
    }
}

fn new_report(engine: &Engine, source: SourceInfo) -> Report {
    let mut report = Report::new(engine.options.profile);
    report.source = source;
    if engine.options.provenance {
        report.diagnostics.provenance = Some(Map::new());
    }
    report
}

fn budget_for(engine: &Engine) -> Budget {
    let l = &engine.options.limits;
    Budget::new(l.max_read_bytes, l.max_decompressed_bytes, l.file_timeout)
}

pub(super) fn extract_path(engine: &Engine, path: &Path) -> Result<Report, Error> {
    let clock = Stopwatch::start();
    let io_err = |source| Error::Io { path: path.to_path_buf(), source };
    let lmeta = std::fs::symlink_metadata(path).map_err(io_err)?;
    let name =
        path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |n| n.to_string_lossy().into_owned());
    let mut report = new_report(engine, SourceInfo::from_name(Some(path.to_string_lossy().into_owned()), &name));
    let budget = budget_for(engine);

    let mut meta = lmeta.clone();
    if lmeta.file_type().is_symlink() {
        report.system.kind = FileKind::Symlink;
        report.system.symlink_target = std::fs::read_link(path).ok().map(|t| t.to_string_lossy().into_owned());
        match std::fs::metadata(path) {
            Ok(m) => meta = m,
            Err(e) => {
                fill_from_metadata(&mut report, &lmeta, path);
                report.identification = detect::special("symlink", "Symbolic link (broken)", "inode/symlink");
                report.diagnostics.warnings.push(format!("broken symlink: {e}"));
                finish(&mut report, &budget, &TextStore::default(), &clock);
                return Ok(report);
            }
        }
    }
    fill_from_metadata(&mut report, &meta, path);
    super::xattrs::fill(&mut report, path);

    let special = match file_kind(&meta) {
        FileKind::Regular => None,
        FileKind::Directory => Some(("directory", "Directory", "inode/directory")),
        FileKind::Fifo => Some(("fifo", "Named pipe", "inode/fifo")),
        FileKind::Socket => Some(("socket", "Socket", "inode/socket")),
        FileKind::BlockDevice => Some(("block_device", "Block device", "inode/blockdevice")),
        FileKind::CharDevice => Some(("char_device", "Character device", "inode/chardevice")),
        FileKind::Symlink | FileKind::Memory | FileKind::Other => {
            Some(("other", "Special file", "application/octet-stream"))
        }
    };
    if let Some((id, label, mime)) = special {
        // Never opened: reading a FIFO or device could block or be endless.
        report.identification = detect::special(id, label, mime);
        finish(&mut report, &budget, &TextStore::default(), &clock);
        return Ok(report);
    }

    let text = match FileSource::open(path, budget.clone()) {
        Ok(mut src) => {
            let text = extract_source(engine, &mut report, &mut src, Level::ROOT);
            if engine.detect_only {
                report.integrity.skipped = Some("extraction abandoned".into());
            } else {
                let encoding = text_encoding(&report, &engine.options, meta.len());
                integrity_for_file(&mut report, path, meta.len(), src.head(), &engine.options, encoding);
            }
            text
        }
        Err(e) => {
            report.identification = detect::special("unreadable", "Unreadable file", "application/octet-stream");
            report.integrity.skipped = Some("unreadable".into());
            report.diagnostics.warnings.push(format!("cannot open: {e}"));
            TextStore::default()
        }
    };
    run_analyzers(engine, &mut report, &text, &budget);
    finish(&mut report, &budget, &text, &clock);
    Ok(report)
}

pub(super) fn extract_bytes(engine: &Engine, name: Option<&str>, data: &Arc<[u8]>) -> Report {
    let clock = Stopwatch::start();
    let budget = budget_for(engine);
    let source = name.map_or_else(SourceInfo::default, |n| SourceInfo::from_name(None, n));
    let mut report = bytes_report(engine, source, data, Level::ROOT, &budget);
    finish_clock(&mut report, &clock);
    report
}

/// Where an input sits among the inputs embedded in the root one.
#[derive(Debug, Clone, Copy)]
struct Level {
    /// Recursion depth (children of children…).
    depth: u32,
    /// Decompressed streams nested at this depth (`.tar.gz` → `.tar`).
    layers: u32,
}

impl Level {
    const ROOT: Self = Self { depth: 0, layers: 0 };
}

/// Decompressed streams that may nest without using up recursion depth
/// (`.tar.gz.xz` is two). Beyond this they count as ordinary children, so a
/// file that decompresses to itself stops at `max_depth`.
const MAX_LAYERS: u32 = 3;

/// Full pipeline over in-memory data (root bytes input or an embedded child).
fn bytes_report(engine: &Engine, source: SourceInfo, data: &Arc<[u8]>, level: Level, budget: &Budget) -> Report {
    let clock = Stopwatch::start();
    let mut report = new_report(engine, source);
    report.system.kind = FileKind::Memory;
    report.system.size_bytes = Some(data.len() as u64);
    report.physical.size_bytes = Some(data.len() as u64);
    let mut src = BytesSource::new(report.source.name.clone(), Arc::clone(data), budget.clone());
    let text = extract_source(engine, &mut report, &mut src, level);
    if engine.detect_only {
        report.integrity.skipped = Some("extraction abandoned".into());
    } else {
        let encoding = text_encoding(&report, &engine.options, data.len() as u64);
        integrity_for_bytes(&mut report, data, &engine.options, encoding);
    }
    run_analyzers(engine, &mut report, &text, budget);
    finish(&mut report, budget, &text, &clock);
    report
}

/// Detection, extractors, block decoders and children for one source.
fn extract_source(engine: &Engine, report: &mut Report, src: &mut dyn Source, level: Level) -> TextStore {
    let options = &engine.options;
    let registry = &engine.registry;
    let mut text = TextStore::with_limit(options.limits.max_text_bytes);

    let name = src.name_hint().map(str::to_string);
    let wrapper = name.as_deref().and_then(detect::wrapper_of);
    // `report.pdf.crdownload` is detected as a PDF.
    let extension = wrapper.as_ref().and_then(|w| w.inner_extension.clone()).or_else(|| {
        name.as_deref().and_then(|n| Path::new(n).extension()).map(|e| e.to_string_lossy().to_ascii_lowercase())
    });
    let probe = Probe {
        head: src.head(),
        tail: src.tail(),
        len: src.len(),
        name: name.as_deref(),
        extension: extension.as_deref(),
    };
    let detection = detect::detect(registry, &probe, options.format.as_deref());
    report.identification = detection.identification;
    // `.bak` is SQL Server's own extension: not a wrapper there.
    let native = |w: &crate::report::Wrapper| {
        detection.spec.is_some_and(|s| s.extensions.iter().any(|e| e.eq_ignore_ascii_case(&w.extension)))
    };
    report.identification.wrapper = wrapper.filter(|w| {
        !native(w) || matches!(detection.spec.map(|s| s.id), Some("partial_download" | "backup_copy"))
    });
    if let Some(forced) = options.format.as_deref()
        && detection.spec.is_none_or(|s| s.id != forced)
    {
        report.diagnostics.warnings.push(format!("--format {forced}: no extractor declares this format"));
    }
    let Some(spec) = detection.spec.filter(|_| !engine.detect_only) else { return text };
    let budget = src.budget().clone();

    let mut blocks: VecDeque<PendingBlock> = VecDeque::new();
    let mut children: Vec<PendingChild> = Vec::new();
    let max_cost = options.profile.max_cost();
    let mut skipped_by_profile = false;
    let mut spec = spec;
    // A container extractor may redirect once to the format it found inside.
    for hop in 0..2 {
        let mut redirect: Option<String> = None;
        for extractor in registry.extractors_for(spec.id) {
            let meta = extractor.meta();
            if !options.allows(meta.id) {
                continue;
            }
            if meta.cost > max_cost {
                skipped_by_profile = true;
                continue;
            }
            report.identification.extractor.get_or_insert_with(|| meta.id.to_string());
            let mut pending = Vec::new();
            let run = run_stage(meta.id, meta.version, options.limits.extractor_timeout, &budget, || {
                let mut cx = Context {
                    report: &mut *report,
                    text: &mut text,
                    blocks: &mut pending,
                    children: &mut children,
                    options,
                    budget: &budget,
                    format_id: spec.id,
                    emitter: meta.id,
                    redirect: &mut redirect,
                };
                extractor.extract(&mut *src, &mut cx)
            });
            report.diagnostics.extractors.push(run);
            blocks.extend(pending);
            if redirect.is_some() {
                break;
            }
        }
        let target =
            redirect.filter(|_| hop == 0).and_then(|id| registry.formats().map(|(f, _)| f).find(|f| f.id == id));
        let Some(target) = target.filter(|t| t.id != spec.id) else { break };
        reidentify(report, spec, target);
        spec = target;
    }
    if skipped_by_profile && report.identification.extractor.is_none() {
        report
            .diagnostics
            .warnings
            .push(format!("extractors for `{}` skipped by the {:?} profile", spec.id, options.profile));
    }

    decode_blocks(engine, report, &mut text, &mut blocks, &mut children, spec.id, &budget);
    extract_children(engine, report, children, level, &budget);
    text
}

/// Identification after an extractor found that `from` (a container) holds `to`.
fn reidentify(report: &mut Report, from: &crate::plugin::FormatSpec, to: &'static crate::plugin::FormatSpec) {
    let id = &mut report.identification;
    id.candidates.retain(|c| c.format != to.id);
    if !id.candidates.iter().any(|c| c.format == from.id) {
        id.candidates.insert(0, crate::report::Candidate { format: from.id.to_string(), confidence: id.confidence });
    }
    id.format = to.id.to_string();
    id.name = to.name.to_string();
    id.mime = to.mimes.first().copied().unwrap_or("application/octet-stream").to_string();
    id.family = Some(to.family.to_string());
    id.detected_by = crate::report::DetectedBy::Content;
    id.extractor = None;
    if let Some(ext) = report.source.extension.as_deref() {
        id.extension_matches =
            Some(to.extensions.is_empty() || to.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)));
    }
    // What the container's extractor wrote under its format id now describes the real format.
    if let Some(v) = report.format.remove(from.id) {
        report.format.insert(to.id.to_string(), v);
    }
}

fn decode_blocks(
    engine: &Engine,
    report: &mut Report,
    text: &mut TextStore,
    blocks: &mut VecDeque<PendingBlock>,
    children: &mut Vec<PendingChild>,
    format_id: &str,
    budget: &Budget,
) {
    // Decoders may emit further blocks (e.g. Photoshop IRB → IPTC); cap the chain.
    let mut processed = 0;
    while let Some(block) = blocks.pop_front() {
        processed += 1;
        if processed > 256 {
            report.diagnostics.warnings.push("too many metadata blocks; rest ignored".into());
            break;
        }
        let decoder = engine.registry.block_decoder(block.kind).filter(|d| engine.options.allows(d.id()));
        let Some(decoder) = decoder else {
            let kind = block.kind.to_string();
            if !report.diagnostics.undecoded_blocks.contains(&kind) {
                report.diagnostics.undecoded_blocks.push(kind);
            }
            continue;
        };
        let mut pending = Vec::new();
        let run = run_stage(decoder.id(), decoder.version(), engine.options.limits.extractor_timeout, budget, || {
            let mut cx = Context {
                report: &mut *report,
                text: &mut *text,
                blocks: &mut pending,
                children: &mut *children,
                options: &engine.options,
                budget,
                format_id,
                emitter: decoder.id(),
                redirect: &mut None,
            };
            decoder.decode(&block.data, &mut cx)
        });
        report.diagnostics.extractors.push(run);
        blocks.extend(pending);
    }
}

fn extract_children(engine: &Engine, report: &mut Report, children: Vec<PendingChild>, level: Level, budget: &Budget) {
    for child in children {
        let source = SourceInfo::from_name(None, &child.name);
        let next = if child.inner && level.layers < MAX_LAYERS {
            Level { depth: level.depth, layers: level.layers + 1 }
        } else {
            Level { depth: level.depth + 1, layers: 0 }
        };
        if next.depth > engine.options.limits.max_depth {
            budget.hit("max_depth");
            let mut r = new_report(engine, source);
            r.system.kind = FileKind::Memory;
            r.system.size_bytes = Some(child.data.len() as u64);
            r.diagnostics.warnings.push("not analysed: max_depth reached".into());
            report.embedded.push(r);
            continue;
        }
        let mut r = bytes_report(engine, source, &child.data.into(), next, budget);
        if child.truncated {
            r.diagnostics.truncated = true;
            r.diagnostics.warnings.push("only the start of this content was analysed".into());
        }
        report.embedded.push(r);
    }
}

fn run_analyzers(engine: &Engine, report: &mut Report, text: &TextStore, budget: &Budget) {
    for analyzer in engine.registry.analyzers() {
        // `only` selects extractors; analyzers are skipped only explicitly.
        if engine.options.skip.iter().any(|s| analyzer.id() == s || analyzer.id().starts_with(&format!("{s}."))) {
            continue;
        }
        let run = run_stage(analyzer.id(), analyzer.version(), engine.options.limits.extractor_timeout, budget, || {
            analyzer.run(report, text, &engine.options)
        });
        report.diagnostics.extractors.push(run);
    }
}

/// Run one extractor/decoder/analyzer with its own deadline, containing panics.
fn run_stage(
    id: &str,
    version: u32,
    timeout: Option<std::time::Duration>,
    budget: &Budget,
    f: impl FnOnce() -> Result<(), crate::ExtractError>,
) -> ExtractorRun {
    let clock = Stopwatch::start();
    budget.begin_stage(timeout);
    let result = catch_unwind(AssertUnwindSafe(f));
    budget.end_stage();
    let mut run = ExtractorRun { id: id.to_string(), version, ms: clock.ms(), ..ExtractorRun::default() };
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            run.status =
                if matches!(e, crate::ExtractError::Internal(_)) { RunStatus::Internal } else { RunStatus::Error };
            run.error_kind = Some(e.kind().to_string());
            run.error = Some(e.to_string());
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            run.status = RunStatus::Internal;
            run.error_kind = Some("internal".into());
            run.error = Some(format!("panicked: {msg}"));
        }
    }
    run
}

fn finish(report: &mut Report, budget: &Budget, text: &TextStore, clock: &Stopwatch) {
    for hit in budget.limits_hit() {
        if !report.diagnostics.limits_hit.iter().any(|h| h == hit) {
            report.diagnostics.limits_hit.push(hit.to_string());
        }
    }
    report.diagnostics.truncated |= text.truncated() || !report.diagnostics.limits_hit.is_empty();
    roll_up_risks(report);
    finish_clock(report, clock);
}

/// `risk_level` and `embedded_risks` from the report's own risks and its
/// children's (each child is finished first, so its totals cover its own
/// descendants).
fn roll_up_risks(report: &mut Report) {
    let mut level = report.security.risks.iter().map(|r| r.severity).max();
    let mut nested: BTreeMap<String, u64> = BTreeMap::new();
    for child in &report.embedded {
        let s = &child.security;
        for r in &s.risks {
            *nested.entry(r.kind.clone()).or_default() += 1;
        }
        for (kind, n) in &s.embedded_risks {
            *nested.entry(kind.clone()).or_default() += n;
        }
        level = level.max(s.risk_level);
    }
    report.security.risk_level = level;
    report.security.embedded_risks = nested;
}

fn finish_clock(report: &mut Report, clock: &Stopwatch) {
    report.diagnostics.elapsed_ms = clock.ms();
}
