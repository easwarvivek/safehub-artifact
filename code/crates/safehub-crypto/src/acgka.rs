//! Administrated CGKA surface matching hybrid functionality F_acgka.
//!
//! Operations mirror the paper: Create, Add, Remove, Update, Rotate, Export.

use crate::error::CryptoError;
use crate::params::{AEAD_KEY_LEN, SEC_PARAM_LEN};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque group identifier (typically derived from RepoId).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub Vec<u8>);

/// Member leaf identity inside the group.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub String);

/// Secrets exported from an MLS epoch (zeroized on drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    /// `Export("safehub-v1:transport")` → ss_e / DKR seed (λ = 384 bits).
    pub transport: [u8; SEC_PARAM_LEN],
    /// `Export("safehub-v1:refs")` → mk_e (AES-256 / HMAC key material).
    pub refs_mac: [u8; AEAD_KEY_LEN],
    /// Epoch number.
    pub epoch: u64,
}

/// Confidential welcome payload for a joiner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WelcomePayload {
    /// Opaque MLS Welcome ciphertext.
    pub welcome: Vec<u8>,
    /// Interval grant embedded for DKR window `[h, ·]`.
    pub history_from_epoch: u64,
}

/// Admin-gated continuous group key agreement.
#[async_trait]
pub trait AcgkaGroup: Send + Sync {
    /// Create a new group with the caller as sole admin member.
    async fn create(&mut self, group_id: GroupId, admin: MemberId) -> Result<u64, CryptoError>;

    /// Admin adds a member; returns welcome for the joiner.
    async fn add(
        &mut self,
        member: MemberId,
        key_package: &[u8],
        history_from_epoch: u64,
    ) -> Result<(WelcomePayload, Vec<u8>), CryptoError>;

    /// Admin removes a member (all devices).
    async fn remove(&mut self, member: &MemberId) -> Result<Vec<u8>, CryptoError>;

    /// Member self-update (PCS heal contribution).
    async fn update(&mut self) -> Result<Vec<u8>, CryptoError>;

    /// Admin rotate without membership change.
    async fn rotate(&mut self) -> Result<Vec<u8>, CryptoError>;

    /// Merge an incoming MLS commit / proposal ciphertext.
    async fn merge(&mut self, commit: &[u8]) -> Result<u64, CryptoError>;

    /// Export epoch secrets; caller must zeroize after use.
    async fn export(&self, label_transport: &str, label_refs: &str) -> Result<EpochSecrets, CryptoError>;

    /// Current epoch number.
    fn epoch(&self) -> u64;

    /// Whether `member` is currently in the roster.
    fn contains(&self, member: &MemberId) -> bool;
}
