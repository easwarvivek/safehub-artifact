//! Storage errors.

use safehub_types::HeadHash;
use thiserror::Error;

/// Persistence / CAS failures.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Blob missing.
    #[error("blob not found: {0}")]
    NotFound(String),
    /// Compare-and-swap lost the race.
    #[error("cas conflict: expected prev {expected:?}")]
    CasConflict {
        /// Hash the client must build on.
        expected: HeadHash,
    },
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization failure.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Other.
    #[error("{0}")]
    Other(String),
}
