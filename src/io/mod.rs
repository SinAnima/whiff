//! Bounded, random-access input.
//!
//! Every read goes through a [`Source`], which charges the bytes against a
//! shared [`Budget`] and checks the deadline. A runaway parser therefore stops
//! by itself with [`SourceError::LimitExceeded`] or [`SourceError::Timeout`].

mod budget;
mod bytes;
mod source;

pub use budget::Budget;
pub use bytes::ByteReader;
pub use source::{BoundedReader, BytesSource, FileSource, Source, SubSource};

/// Size of the pre-read head and tail windows.
pub const WINDOW: usize = 64 * 1024;

/// Why a read failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// A budget was exhausted (`read_bytes`, `decompressed_bytes`).
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// The deadline passed.
    #[error("timeout")]
    Timeout,
    /// The requested range lies (partly) beyond the end of the input.
    #[error("out of bounds: needed {needed} bytes at offset {offset}")]
    OutOfBounds {
        /// Requested offset.
        offset: u64,
        /// Requested length.
        needed: u64,
    },
    /// The underlying reader failed.
    #[error("i/o: {0}")]
    Io(String),
}
