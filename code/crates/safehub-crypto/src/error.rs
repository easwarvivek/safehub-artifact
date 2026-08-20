//! Crypto-layer errors.

use thiserror::Error;

/// Errors raised by ACGKA / DKR / AEAD adapters.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Operation requires admin privileges.
    #[error("not an admin")]
    NotAdmin,
    /// Member not present in roster.
    #[error("unknown member")]
    UnknownMember,
    /// Epoch outside granted history window.
    #[error("epoch {epoch} outside window [{from}, {to}]")]
    EpochOutOfWindow {
        /// Requested epoch.
        epoch: u64,
        /// First epoch in the granted interval.
        from: u64,
        /// Last epoch in the granted interval.
        to: u64,
    },
    /// KDF failure.
    #[error("kdf failed")]
    Kdf,
    /// AEAD failure.
    #[error(transparent)]
    Aead(#[from] crate::aead::AeadError),
    /// OpenMLS / adapter-specific failure.
    #[error("mls adapter: {0}")]
    Mls(String),
    /// Stub limitation: real crypto not wired yet.
    #[error("stub crypto: {0}")]
    Stub(&'static str),
}
