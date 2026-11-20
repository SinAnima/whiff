//! The extraction engine: stat → detect → extractors → block decoders →
//! children → analyzers → report.

pub(crate) mod analyzers;
mod options;
mod pipeline;
pub(crate) mod universal;
mod xattrs;

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub(crate) use options::SLOW_SNIFF;
pub use options::{Hashes, Limits, Options, Privacy, Profile, Redaction};

use crate::Error;
use crate::plugin::Registry;
use crate::report::{Identification, Report};

/// How the engine identifies the root input.
#[derive(Debug, Clone, Default)]
enum Detect {
    /// Run detection.
    #[default]
    Run,
    /// Run detection and publish the root identification as soon as it is
    /// known (a worker under the watchdog).
    Publish(Arc<OnceLock<Identification>>),
    /// Use this identification: what an abandoned worker had detected.
    Preset(Box<Identification>),
    /// Use only the built-in fallbacks (`empty`, `text`, `binary`): the
    /// abandoned worker was still detecting, so no sniffer runs again.
    BuiltinOnly,
}

/// Runs extractions. Cheap to share across threads (`&Engine` is `Sync`).
#[derive(Debug, Clone)]
pub struct Engine {
    registry: Registry,
    options: Options,
    /// Stop after detection (the report of an abandoned extraction).
    detect_only: bool,
    detect: Detect,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// An engine with every registered extractor and the standard profile.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Configure an engine.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// The registry in use.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The options in use.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Describe the file (or directory, link, device…) at `path`.
    ///
    /// Fails only when `path` cannot be inspected at all; every problem inside
    /// the file is recorded in `diagnostics` instead.
    ///
    /// With a file deadline (`limits.file_timeout`), the work runs on a worker
    /// thread. Deadlines are checked on every read, but a parser that loops
    /// without reading cannot see them; if the worker overruns, the caller
    /// gets a detection-only report with `limits_hit: ["timeout"]` and the
    /// worker is abandoned. That report reuses the worker's detection (or,
    /// when detection itself overran, only the built-in `empty` / `text` /
    /// `binary` fallbacks); no extractor code runs on the caller. While 8
    /// abandoned workers are still running, further files get that report
    /// without a worker.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `path` cannot be inspected (it does not exist, or
    /// its metadata cannot be read). An unreadable or damaged file is still
    /// `Ok`: the problem is in `diagnostics`. An overrun deadline is `Ok` too,
    /// with `"timeout"` in `diagnostics.limits_hit`.
    ///
    /// ```
    /// let engine = whiff::Engine::new();
    ///
    /// let report = engine.extract_path(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
    /// assert_eq!(report.identification.format, "cargo_manifest");
    /// assert!(report.integrity.sha256.is_some());
    ///
    /// let missing = engine.extract_path("no/such/file.txt");
    /// assert!(matches!(missing, Err(whiff::Error::Io { .. })));
    /// # Ok::<(), whiff::Error>(())
    /// ```
    pub fn extract_path(&self, path: impl AsRef<Path>) -> Result<Report, Error> {
        let path = path.as_ref();
        let owned = path.to_path_buf();
        self.guarded(move |e| pipeline::extract_path(e, &owned), |e| pipeline::extract_path(e, path))
    }

    /// Describe in-memory bytes. `name` (a file name, `None` if unknown)
    /// helps detection; `bytes` is anything that becomes an `Arc<[u8]>`
    /// (`Vec<u8>`, `&[u8]`, `Box<[u8]>`). Runs under the same watchdog as
    /// [`extract_path`](Self::extract_path).
    ///
    /// Never fails and never panics on bad input: problems are recorded in
    /// `diagnostics`. The `system` section is empty (there is no file).
    ///
    /// ```
    /// let engine = whiff::Engine::new();
    ///
    /// let csv: &[u8] = b"berth,vessel\n1,Grey Tern\n2,Kittiwake\n";
    /// let report = engine.extract_bytes(Some("berths.csv"), csv);
    /// assert_eq!(report.identification.format, "csv");
    ///
    /// // Unrecognised bytes with no name: identified as binary, no panic.
    /// let noise = [0x00, 0x9c, 0x7f, 0x01].repeat(64);
    /// let report = engine.extract_bytes(None, noise);
    /// assert_eq!(report.identification.format, "binary");
    /// ```
    pub fn extract_bytes(&self, name: Option<&str>, bytes: impl Into<Arc<[u8]>>) -> Report {
        let data: Arc<[u8]> = bytes.into();
        let (owned_name, owned_data) = (name.map(str::to_string), Arc::clone(&data));
        let report = self.guarded(
            move |e| Ok(pipeline::extract_bytes(e, owned_name.as_deref(), &owned_data)),
            |e| Ok(pipeline::extract_bytes(e, name, &data)),
        );
        report.unwrap_or_else(|_: Error| unreachable!("in-memory extraction cannot fail"))
    }

    /// Run `work` on a worker thread with a hard deadline; on overrun, run
    /// `fallback` here without extraction. Without threads (WASM) or
    /// without a file deadline, `work` runs here.
    ///
    /// The fallback never re-runs detection: it reuses what the worker had
    /// detected, or only the built-in `empty` / `text` / `binary` fallbacks
    /// when the worker was still detecting.
    fn guarded(
        &self,
        work: impl FnOnce(&Engine) -> Result<Report, Error> + Send + 'static,
        fallback: impl FnOnce(&Engine) -> Result<Report, Error>,
    ) -> Result<Report, Error> {
        let threads = !cfg!(all(target_arch = "wasm32", target_os = "unknown"));
        let Some(timeout) = self.options.limits.file_timeout.filter(|_| threads && !self.detect_only) else {
            return work(self);
        };
        // Reads, inflating and hashing check the deadline themselves; the
        // grace period only lets a cooperative stop finish.
        let deadline = timeout + (timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(2));
        let detected = Arc::new(OnceLock::new());
        let mut engine = self.clone();
        engine.detect = Detect::Publish(Arc::clone(&detected));
        let failure = match worker::run(Box::new(move || work(&engine)), deadline) {
            Ok(Ok(result)) => return result,
            // No thread available: detection and extraction run here, cooperatively bounded.
            Err(worker::NoWorker::SpawnFailed) => return fallback(self),
            Err(worker::NoWorker::TooManyAbandoned) => format!(
                "extraction skipped: {} earlier extractions are still running past their deadline",
                worker::ABANDONED_CAP
            ),
            Ok(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => format!(
                "extraction abandoned after {:.1} s: an extractor did not stop at the deadline",
                deadline.as_secs_f64()
            ),
            // Stages contain their own panics; this is a bug in the engine.
            Ok(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) => {
                "extraction failed: the worker thread panicked".into()
            }
        };
        let mut quick = self.clone();
        quick.detect_only = true;
        quick.options.limits.file_timeout = None;
        quick.detect = detected.get().map_or(Detect::BuiltinOnly, |id| Detect::Preset(Box::new(id.clone())));
        let mut report = fallback(&quick)?;
        if !failure.contains("panicked") {
            report.diagnostics.limits_hit.push("timeout".into());
        }
        report.diagnostics.truncated = true;
        report.diagnostics.warnings.push(failure);
        Ok(report)
    }

    /// Read `reader` into memory (up to `limits.max_read_bytes`) and describe
    /// it, as [`extract_bytes`](Self::extract_bytes) does. Longer input is cut
    /// at the limit: the report has `diagnostics.truncated` and `"read_bytes"`
    /// in `diagnostics.limits_hit`.
    ///
    /// # Errors
    ///
    /// The reader's own error, when a read fails. A reader that ends early
    /// is not an error: whatever it gave is described.
    ///
    /// ```
    /// use std::io::{Cursor, Error, Read};
    ///
    /// let engine = whiff::Engine::new();
    /// let report = engine.extract_reader(Some("notes.md"), Cursor::new("# Tides\n\nHigh water at 06:12.\n"))?;
    /// assert_eq!(report.identification.format, "markdown");
    ///
    /// // Past the read limit: described up to it, and marked.
    /// let small = whiff::Engine::builder().limits(whiff::Limits::default().max_read_bytes(8)).build();
    /// let report = small.extract_reader(None, Cursor::new(vec![b'a'; 100]))?;
    /// assert!(report.diagnostics.truncated);
    /// assert!(report.diagnostics.limits_hit.contains(&"read_bytes".to_string()));
    ///
    /// // A failing reader is an error.
    /// struct Broken;
    /// impl Read for Broken {
    ///     fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
    ///         Err(Error::other("disk went away"))
    ///     }
    /// }
    /// assert!(engine.extract_reader(None, Broken).is_err());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn extract_reader(&self, name: Option<&str>, reader: impl Read) -> std::io::Result<Report> {
        let mut buf = Vec::new();
        let limit = self.options.limits.max_read_bytes;
        reader.take(limit.saturating_add(1)).read_to_end(&mut buf)?;
        let truncated = buf.len() as u64 > limit;
        if truncated {
            buf.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        let mut report = self.extract_bytes(name, buf);
        if truncated {
            report.diagnostics.truncated = true;
            report.diagnostics.limits_hit.push("read_bytes".into());
        }
        Ok(report)
    }
}

/// The text of a caught panic (`"panic"` when it carries none).
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".to_string())
}

/// The extraction worker: one per calling thread, reused from file to file
/// (spawning a thread per file cost about 3% of the time on small files).
mod worker {
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
    use std::time::Duration;

    use crate::Error;
    use crate::report::Report;

    /// Stack of the extraction worker thread.
    const STACK: usize = 16 * 1024 * 1024;

    /// Abandoned workers still running, process-wide. Past the cap no new
    /// worker is started, so a stream of hostile files cannot pile up threads.
    pub(super) const ABANDONED_CAP: usize = 8;
    static ABANDONED: AtomicUsize = AtomicUsize::new(0);

    pub(super) type Job = Box<dyn FnOnce() -> Result<Report, Error> + Send>;

    /// Why `run` did not run the job.
    pub(super) enum NoWorker {
        /// The OS refused a thread.
        SpawnFailed,
        /// [`ABANDONED_CAP`] abandoned workers are still running.
        TooManyAbandoned,
    }

    struct Worker {
        jobs: Sender<Job>,
        results: Receiver<Result<Report, Error>>,
        /// Set when the caller gives up on this worker.
        abandoned: Arc<AtomicBool>,
    }

    thread_local! {
        static WORKER: RefCell<Option<Worker>> = const { RefCell::new(None) };
    }

    /// Run `job` on this thread's worker and wait up to `deadline`. A worker
    /// that overran or panicked is dropped (it ends once its job does), and
    /// the next call starts another.
    pub(super) fn run(
        job: Job,
        deadline: Duration,
    ) -> Result<Result<Result<Report, Error>, RecvTimeoutError>, NoWorker> {
        WORKER.with(|cell| {
            let mut slot = cell.borrow_mut();
            let mut job = Some(job);
            // A worker whose thread has ended returns the job: start another.
            for _ in 0..2 {
                if slot.is_none() {
                    if ABANDONED.load(Ordering::Relaxed) >= ABANDONED_CAP {
                        return Err(NoWorker::TooManyAbandoned);
                    }
                    *slot = Some(spawn().ok_or(NoWorker::SpawnFailed)?);
                }
                let Some(worker) = slot.as_ref() else { break };
                let Some(next) = job.take() else { break };
                match worker.jobs.send(next) {
                    Ok(()) => {
                        let outcome = worker.results.recv_timeout(deadline);
                        if outcome.is_err() {
                            if matches!(outcome, Err(RecvTimeoutError::Timeout)) {
                                // Counted before the flag is set, so the worker's
                                // decrement can never come first.
                                ABANDONED.fetch_add(1, Ordering::Relaxed);
                                if worker.abandoned.swap(true, Ordering::AcqRel) {
                                    ABANDONED.fetch_sub(1, Ordering::Relaxed);
                                }
                            }
                            *slot = None;
                        }
                        return Ok(outcome);
                    }
                    Err(returned) => {
                        job = Some(returned.0);
                        *slot = None;
                    }
                }
            }
            Err(NoWorker::SpawnFailed)
        })
    }

    fn spawn() -> Option<Worker> {
        let (jobs, inbox) = channel::<Job>();
        let (outbox, results): (SyncSender<_>, _) = sync_channel(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&abandoned);
        std::thread::Builder::new()
            .name("whiff-extract".into())
            .stack_size(STACK)
            .spawn(move || {
                // Ends when the caller drops the worker (its thread ended, or
                // it gave up on this one after a deadline).
                while let Ok(job) = inbox.recv() {
                    if outbox.send(job()).is_err() {
                        break;
                    }
                }
                // The caller marked this worker abandoned: it no longer counts.
                // When the flag is not set yet, setting it tells a caller that
                // is about to count it that the worker has already ended.
                if flag.swap(true, Ordering::AcqRel) {
                    ABANDONED.fetch_sub(1, Ordering::Relaxed);
                }
            })
            .ok()?;
        Some(Worker { jobs, results, abandoned })
    }
}

/// Builder for [`Engine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    registry: Option<Registry>,
    options: Options,
    limits_set: bool,
}

impl EngineBuilder {
    /// Profile. [`build`](Self::build) then uses the profile's
    /// [limits](Profile::limits), unless [`limits`](Self::limits) or
    /// [`options`](Self::options) set them.
    #[must_use]
    pub fn profile(mut self, profile: Profile) -> Self {
        self.options.profile = profile;
        self
    }

    /// Limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.options.limits = limits;
        self.limits_set = true;
        self
    }

    /// Hashes to compute.
    #[must_use]
    pub fn hashes(mut self, hashes: Hashes) -> Self {
        self.options.hashes = hashes;
        self
    }

    /// Run only these extractors / groups.
    #[must_use]
    pub fn only(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.only = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Never run these extractors / groups.
    #[must_use]
    pub fn skip(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.skip = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Force a format id instead of detecting.
    #[must_use]
    pub fn format(mut self, id: impl Into<String>) -> Self {
        self.options.format = Some(id.into());
        self
    }

    /// Record which source set each normalised field.
    #[must_use]
    pub fn provenance(mut self, on: bool) -> Self {
        self.options.provenance = on;
        self
    }

    /// How personal data is reported (default [`Privacy::Strict`]).
    #[must_use]
    pub fn privacy(mut self, privacy: Privacy) -> Self {
        self.options.privacy = privacy;
        self
    }

    /// Whether secrets are redacted (default [`Redaction::On`]).
    #[must_use]
    pub fn redaction(mut self, redaction: Redaction) -> Self {
        self.options.redaction = redaction;
        self
    }

    /// Use exactly this registry instead of [`Registry::builtin`].
    #[must_use]
    pub fn registry(mut self, registry: Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Replace all options at once, limits included: an `Options` changed
    /// only in its `profile` keeps the `standard` limits, so set
    /// `limits: profile.limits()` too.
    #[must_use]
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self.limits_set = true;
        self
    }

    /// Build the engine.
    pub fn build(mut self) -> Engine {
        if !self.limits_set {
            self.options.limits = self.options.profile.limits();
        }
        Engine {
            registry: self.registry.unwrap_or_else(Registry::builtin),
            options: self.options,
            detect_only: false,
            detect: Detect::Run,
        }
    }
}
