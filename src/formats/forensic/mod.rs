//! `forensic` extractors (feature `forensics`): the artefacts incident
//! responders triage. Each gives counts, time ranges and the facts that
//! identify the source (link type, channel, hive, target, crashing module),
//! not the content: packets, event data, registry values and file names
//! are summarised, never dumped. Paths under a user's profile have the
//! user name hidden when privacy is strict.

#![allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, as in the specifications

pub(crate) mod capture;
pub(crate) mod dump;
pub(crate) mod ese;
pub(crate) mod evtx;
pub(crate) mod logs;
pub(crate) mod longtail;
pub(crate) mod mft;
pub(crate) mod registry;
pub(crate) mod shell;
pub(crate) mod xpress;

// Helpers shared with the archive and executable extractors.
pub(crate) use super::archive::unix_time;
pub(crate) use super::exec::hex;
use crate::plugin::Source;
pub(crate) use crate::plugin::user_path;

/// Windows FILETIME (100 ns since 1601) as RFC 3339 UTC; `None` for zero
/// and implausible values.
pub(crate) fn filetime(ticks: u64) -> Option<String> {
    crate::plugin::filetime(ticks)
}

/// A FILETIME read little-endian at `at`.
pub(crate) fn filetime_at(b: &[u8], at: usize) -> Option<String> {
    filetime(le(b.get(at..at + 8)?))
}

pub(crate) fn le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

/// A little-endian field (at most 4 bytes) as an offset or count.
pub(crate) fn le_usize(b: &[u8]) -> usize {
    b.iter().rev().fold(0usize, |a, &x| a << 8 | usize::from(x))
}

/// A little-endian field of at most 4 bytes.
pub(crate) fn le_u32(b: &[u8]) -> u32 {
    b.iter().take(4).rev().fold(0u32, |a, &x| a << 8 | u32::from(x))
}

pub(crate) fn be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

/// UTF-16LE text up to the first NUL.
pub(crate) fn utf16z(b: &[u8]) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Latin-1 / ASCII text up to the first NUL.
pub(crate) fn asciiz(b: &[u8]) -> String {
    b.iter().take_while(|&&c| c != 0).map(|&c| char::from(c)).collect()
}

/// Sequential reads through a window, for walking record headers over a
/// large file without a read per record.
pub(crate) struct Window<'s> {
    src: &'s mut dyn Source,
    start: u64,
    buf: Vec<u8>,
}

/// Bytes read per window refill.
const WINDOW: usize = 1 << 20;

impl<'s> Window<'s> {
    pub fn new(src: &'s mut dyn Source) -> Self {
        Self { src, start: 0, buf: Vec::new() }
    }

    pub fn len(&self) -> u64 {
        self.src.len()
    }

    /// `n` bytes at `off` (up to the end of the file).
    pub fn get(&mut self, off: u64, n: usize) -> Option<&[u8]> {
        let end = off.checked_add(n as u64)?;
        if end > self.src.len() {
            return None;
        }
        if off < self.start || end > self.start + self.buf.len() as u64 {
            let want = usize::try_from((self.src.len() - off).min(WINDOW.max(n) as u64)).ok()?;
            self.buf.resize(want, 0);
            self.src.read_exact_at(off, &mut self.buf).ok()?;
            self.start = off;
        }
        let at = usize::try_from(off - self.start).ok()?;
        self.buf.get(at..at + n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_and_ascii_strings() {
        assert_eq!(utf16z(&[b'h', 0, b'i', 0, 0, 0, b'x', 0]), "hi");
        assert_eq!(asciiz(b"tide\0x"), "tide");
    }
}
