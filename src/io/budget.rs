use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::SourceError;

/// Monotonic clock. `std::time::Instant` panics on `wasm32-unknown-unknown`,
/// so there the clock is absent and deadlines are not enforced.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
type Instant = std::time::Instant;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[allow(clippy::unnecessary_wraps)] // `None` on wasm32-unknown-unknown
fn now() -> Option<Instant> {
    Some(Instant::now())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
struct Instant;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl std::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, _: Duration) -> Instant {
        Instant
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl Instant {
    fn duration_since(self, _: Instant) -> Duration {
        Duration::ZERO
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now() -> Option<Instant> {
    None
}

/// Resource limits shared by everything that reads one root input and its
/// embedded children. Cheap to clone (an `Arc`).
#[derive(Clone, Debug)]
pub struct Budget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    read_limit: u64,
    read: AtomicU64,
    decompressed_limit: u64,
    decompressed: AtomicU64,
    file_deadline: Option<Instant>,
    /// The tighter of the file deadline and the current extractor's deadline.
    current_deadline: Mutex<Option<Instant>>,
    limits_hit: Mutex<Vec<&'static str>>,
    /// A sniffer slower than this is skipped (`None` = never).
    slow_sniff: Option<Duration>,
    /// Extractors whose sniffer was too slow: skipped for the rest of this
    /// input and its embedded files.
    slow_sniffers: Mutex<Vec<&'static str>>,
}

/// Add `n` to `counter` only when the total stays within `limit`, so a
/// rejected charge leaves the counter unchanged (no overflow, no drift).
fn commit(counter: &AtomicU64, limit: u64, n: u64) -> bool {
    let mut before = counter.load(Ordering::Relaxed);
    loop {
        let Some(total) = before.checked_add(n).filter(|&t| t <= limit) else { return false };
        match counter.compare_exchange_weak(before, total, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => before = now,
        }
    }
}

impl Budget {
    /// A budget allowing `read_limit` bytes read, `decompressed_limit` bytes
    /// inflated, and finishing within `timeout`.
    pub fn new(read_limit: u64, decompressed_limit: u64, timeout: Option<Duration>) -> Self {
        let file_deadline = timeout.and_then(|t| now().map(|n| n + t));
        Self {
            inner: Arc::new(Inner {
                read_limit,
                read: AtomicU64::new(0),
                decompressed_limit,
                decompressed: AtomicU64::new(0),
                file_deadline,
                current_deadline: Mutex::new(file_deadline),
                limits_hit: Mutex::new(Vec::new()),
                slow_sniff: Some(crate::engine::SLOW_SNIFF),
                slow_sniffers: Mutex::new(Vec::new()),
            }),
        }
    }

    /// The same budget with sniffers slower than `t` skipped (`None` = never).
    /// Call before the budget is shared.
    #[must_use]
    pub(crate) fn slow_sniff(mut self, t: Option<Duration>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.slow_sniff = t;
        }
        self
    }

    /// The slow-sniffer threshold.
    pub(crate) fn slow_sniff_threshold(&self) -> Option<Duration> {
        self.inner.slow_sniff
    }

    /// No limits at all (tests, trusted callers).
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, None)
    }

    /// Charge `n` bytes read.
    pub fn charge_read(&self, n: u64) -> Result<(), SourceError> {
        self.check_deadline()?;
        if !commit(&self.inner.read, self.inner.read_limit, n) {
            self.hit("read_bytes");
            return Err(SourceError::LimitExceeded("read_bytes"));
        }
        Ok(())
    }

    /// Charge `n` bytes produced by decompression (zip-bomb guard).
    pub fn charge_decompressed(&self, n: u64) -> Result<(), SourceError> {
        self.check_deadline()?;
        if !commit(&self.inner.decompressed, self.inner.decompressed_limit, n) {
            self.hit("decompressed_bytes");
            return Err(SourceError::LimitExceeded("decompressed_bytes"));
        }
        Ok(())
    }

    /// Bytes decompression may still produce.
    pub fn remaining_decompressed(&self) -> u64 {
        self.inner.decompressed_limit.saturating_sub(self.inner.decompressed.load(Ordering::Relaxed))
    }

    /// Fail with [`SourceError::Timeout`] once the deadline has passed.
    pub fn check_deadline(&self) -> Result<(), SourceError> {
        let deadline = *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner);
        if let (Some(d), Some(n)) = (deadline, now())
            && n >= d
        {
            self.hit("timeout");
            return Err(SourceError::Timeout);
        }
        Ok(())
    }

    /// Bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.inner.read.load(Ordering::Relaxed)
    }

    /// Record that a limit stopped work (shown in `diagnostics.limits_hit`).
    pub fn hit(&self, what: &'static str) {
        let mut hits = self.inner.limits_hit.lock().unwrap_or_else(PoisonError::into_inner);
        if !hits.contains(&what) {
            hits.push(what);
        }
    }

    /// Limits hit so far, in first-hit order.
    pub fn limits_hit(&self) -> Vec<&'static str> {
        self.inner.limits_hit.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Start an extractor: its deadline is `timeout` from now, capped by the file deadline.
    pub(crate) fn begin_stage(&self, timeout: Option<Duration>) {
        let stage = timeout.and_then(|t| now().map(|n| n + t));
        let deadline = match (self.inner.file_deadline, stage) {
            (Some(f), Some(s)) => Some(if s < f { s } else { f }),
            (f, s) => f.or(s),
        };
        *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
    }

    /// Run `f` and say how long it took (`None` where there is no clock).
    pub(crate) fn timed<T>(f: impl FnOnce() -> T) -> (T, Option<Duration>) {
        let start = now();
        let out = f();
        (out, start.and_then(|s| now().map(|n| n.duration_since(s))))
    }

    /// Whether the sniffer of extractor `id` was marked slow.
    pub(crate) fn sniffer_is_slow(&self, id: &str) -> bool {
        self.inner.slow_sniffers.lock().unwrap_or_else(PoisonError::into_inner).contains(&id)
    }

    /// Skip the sniffer of extractor `id` from now on.
    pub(crate) fn mark_sniffer_slow(&self, id: &'static str) {
        let mut slow = self.inner.slow_sniffers.lock().unwrap_or_else(PoisonError::into_inner);
        if !slow.contains(&id) {
            slow.push(id);
        }
    }

    /// Back to the file deadline only.
    pub(crate) fn end_stage(&self) {
        *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner) = self.inner.file_deadline;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_charges_leave_the_counter_alone() {
        let b = Budget::new(100, 100, None);
        assert!(b.charge_read(u64::MAX - 50).is_err());
        assert!(b.charge_read(50).is_ok(), "the refused charge was not committed");
        assert!(b.charge_read(51).is_err());
        assert!(b.charge_read(50).is_ok());
        assert_eq!(b.bytes_read(), 100);
        assert!(b.charge_read(1).is_err());
        assert_eq!(b.limits_hit(), ["read_bytes"]);

        assert!(b.charge_decompressed(u64::MAX).is_err());
        assert!(b.charge_decompressed(100).is_ok());
        assert_eq!(b.remaining_decompressed(), 0);
    }

    #[test]
    fn concurrent_charges_never_pass_the_limit() {
        let b = Budget::new(1000, u64::MAX, None);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..500 {
                        let _ = b.charge_read(3);
                    }
                });
            }
        });
        assert!(b.bytes_read() <= 1000);
        assert!(b.bytes_read() >= 997);
    }
}
