use std::path::PathBuf;

use crate::io::SourceError;

/// Failure of a whole `extract_*` call. Problems *inside* a file never produce
/// this; they are recorded in the report's `diagnostics` instead.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The path could not be inspected at all (missing, permission denied on stat, …).
    #[error("{path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Why an extractor, block decoder or analyzer stopped. Recorded in
/// `diagnostics.extractors[].status`; never fatal for the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExtractError {
    /// The input is not (or no longer) the format this extractor handles.
    #[error("not a {0} file")]
    Unsupported(String),
    /// The input violates the format's structure.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The input ended before a structure was complete.
    #[error("truncated: needed {needed} bytes at offset {offset}")]
    Truncated {
        /// Offset at which more data was needed.
        offset: u64,
        /// Number of bytes that were needed.
        needed: u64,
    },
    /// The content is encrypted and cannot be inspected further.
    #[error("encrypted")]
    Encrypted,
    /// A byte, decompression, child or depth budget was exhausted.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    /// The deadline passed.
    #[error("timeout")]
    Timeout,
    /// An I/O error while reading the input.
    #[error("i/o: {0}")]
    Io(String),
    /// A bug: the extractor panicked or broke an invariant.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ExtractError {
    /// Shorthand for [`ExtractError::Malformed`].
    pub fn malformed(msg: impl Into<String>) -> Self {
        Self::Malformed(msg.into())
    }

    /// Stable `snake_case` name of the variant, used in reports.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "unsupported",
            Self::Malformed(_) => "malformed",
            Self::Truncated { .. } => "truncated",
            Self::Encrypted => "encrypted",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Timeout => "timeout",
            Self::Io(_) => "io",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<SourceError> for ExtractError {
    fn from(e: SourceError) -> Self {
        match e {
            SourceError::LimitExceeded(what) => Self::LimitExceeded(what.to_string()),
            SourceError::Timeout => Self::Timeout,
            SourceError::OutOfBounds { offset, needed } => Self::Truncated { offset, needed },
            SourceError::Io(msg) => Self::Io(msg),
        }
    }
}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        // Errors produced by `BoundedReader` wrap a `SourceError`; recover it so
        // budget and timeout failures keep their meaning through `std::io` APIs.
        if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<SourceError>()) {
            return inner.clone().into();
        }
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Self::Truncated { offset: 0, needed: 0 };
        }
        Self::Io(e.to_string())
    }
}
