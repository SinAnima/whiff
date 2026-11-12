//! The extraction engine: stat → detect → extractors → block decoders →
//! children → analyzers → report.

pub(crate) mod analyzers;
mod options;
mod pipeline;
pub(crate) mod universal;
mod xattrs;

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub use options::{Hashes, Limits, Options, Privacy, Profile};

use crate::Error;
use crate::plugin::Registry;
use crate::report::Report;

/// Runs extractions. Cheap to share across threads (`&Engine` is `Sync`).
#[derive(Debug, Clone)]
pub struct Engine {
    registry: Registry,
    options: Options,
    /// Stop after detection (the report of an abandoned extraction).
    detect_only: bool,
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
    /// worker is abandoned.
    pub fn extract_path(&self, path: impl AsRef<Path>) -> Result<Report, Error> {
        let path = path.as_ref();
        let size = std::fs::metadata(path).map_or(0, |m| m.len());
        let owned = path.to_path_buf();
        self.guarded(size, move |e| pipeline::extract_path(e, &owned), |e| pipeline::extract_path(e, path))
    }

    /// Describe in-memory bytes. `name` (a file name) helps detection. Runs
    /// under the same watchdog as [`extract_path`](Self::extract_path).
    pub fn extract_bytes(&self, name: Option<&str>, bytes: impl Into<Arc<[u8]>>) -> Report {
        let data: Arc<[u8]> = bytes.into();
        let (owned_name, owned_data) = (name.map(str::to_string), Arc::clone(&data));
        let report = self.guarded(
            data.len() as u64,
            move |e| Ok(pipeline::extract_bytes(e, owned_name.as_deref(), &owned_data)),
            |e| Ok(pipeline::extract_bytes(e, name, &data)),
        );
        report.unwrap_or_else(|_: Error| unreachable!("in-memory extraction cannot fail"))
    }

    /// Run `work` on a worker thread with a hard deadline; on overrun, run
    /// `fallback` with detection only. Without threads (WASM) or without a
    /// file deadline, `work` runs here.
    fn guarded(
        &self,
        size: u64,
        work: impl FnOnce(&Engine) -> Result<Report, Error> + Send + 'static,
        fallback: impl FnOnce(&Engine) -> Result<Report, Error>,
    ) -> Result<Report, Error> {
        let threads = !cfg!(all(target_arch = "wasm32", target_os = "unknown"));
        let Some(timeout) = self.options.limits.file_timeout.filter(|_| threads && !self.detect_only) else {
            return work(self);
        };
        // Cooperative deadlines stop extractors; hashing a large file is not
        // bounded by them, so allow for it at ~100 MiB/s.
        let deadline = timeout + Duration::from_secs(2) + Duration::from_secs(size / (100 << 20));
        let engine = self.clone();
        let Some(outcome) = worker::run(Box::new(move || work(&engine)), deadline) else {
            // No thread available: detection and extraction run here, cooperatively bounded.
            return fallback(self);
        };
        let failure = match outcome {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => format!(
                "extraction abandoned after {:.1} s: an extractor did not stop at the deadline",
                deadline.as_secs_f64()
            ),
            // Stages contain their own panics; this is a bug in the engine.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                "extraction failed: the worker thread panicked".into()
            }
        };
        let mut quick = self.clone();
        quick.detect_only = true;
        quick.options.limits.file_timeout = None;
        let mut report = fallback(&quick)?;
        if failure.contains("abandoned") {
            report.diagnostics.limits_hit.push("timeout".into());
        }
        report.diagnostics.truncated = true;
        report.diagnostics.warnings.push(failure);
        Ok(report)
    }

    /// Read `reader` into memory (up to `max_read_bytes`) and describe it.
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

/// The extraction worker: one per calling thread, reused from file to file
/// (spawning a thread per file cost about 3% of the time on small files).
mod worker {
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
    use std::time::Duration;

    use crate::Error;
    use crate::report::Report;

    /// Stack of the extraction worker thread.
    const STACK: usize = 16 * 1024 * 1024;

    pub(super) type Job = Box<dyn FnOnce() -> Result<Report, Error> + Send>;

    struct Worker {
        jobs: Sender<Job>,
        results: Receiver<Result<Report, Error>>,
    }

    thread_local! {
        static WORKER: RefCell<Option<Worker>> = const { RefCell::new(None) };
    }

    /// Run `job` on this thread's worker and wait up to `deadline`. `None`
    /// when no thread could be started. A worker that overran or panicked is
    /// dropped (it ends once its job does), and the next call starts another.
    pub(super) fn run(job: Job, deadline: Duration) -> Option<Result<Result<Report, Error>, RecvTimeoutError>> {
        WORKER.with(|cell| {
            let mut slot = cell.borrow_mut();
            let mut job = Some(job);
            // A worker whose thread has ended returns the job: start another.
            for _ in 0..2 {
                if slot.is_none() {
                    *slot = Some(spawn()?);
                }
                let worker = slot.as_ref()?;
                match worker.jobs.send(job.take()?) {
                    Ok(()) => {
                        let outcome = worker.results.recv_timeout(deadline);
                        if outcome.is_err() {
                            *slot = None;
                        }
                        return Some(outcome);
                    }
                    Err(returned) => {
                        job = Some(returned.0);
                        *slot = None;
                    }
                }
            }
            None
        })
    }

    fn spawn() -> Option<Worker> {
        let (jobs, inbox) = channel::<Job>();
        let (outbox, results): (SyncSender<_>, _) = sync_channel(1);
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
            })
            .ok()?;
        Some(Worker { jobs, results })
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
    /// Profile (also resets limits to the profile's defaults unless set explicitly).
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

    /// Use exactly this registry instead of [`Registry::builtin`].
    #[must_use]
    pub fn registry(mut self, registry: Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Replace all options at once.
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
        Engine { registry: self.registry.unwrap_or_else(Registry::builtin), options: self.options, detect_only: false }
    }
}
