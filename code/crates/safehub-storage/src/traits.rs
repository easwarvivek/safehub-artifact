//! Abstract storage interfaces (blob / head log / MLS delivery / directory).

use crate::error::StorageError;
use async_trait::async_trait;
use bytes::Bytes;
use safehub_types::{
    BlobId, BlobMeta, HeadHash, KeyLogEntry, MlsDeliveryEnvelope, RefHead, RepoId, RepoRecord,
    UserId,
};

/// Content-addressed ciphertext blob store.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Idempotent put; returns the content id.
    async fn put(&self, meta: BlobMeta, ciphertext: Bytes) -> Result<BlobId, StorageError>;

    /// Fetch ciphertext by id.
    async fn get(&self, id: &BlobId) -> Result<Bytes, StorageError>;

    /// Optional metadata lookup.
    async fn meta(&self, id: &BlobId) -> Result<BlobMeta, StorageError>;

    /// True if blob exists.
    async fn exists(&self, id: &BlobId) -> Result<bool, StorageError>;
}

/// Ordered, CAS-protected encrypted ref-head log per repository.
#[async_trait]
pub trait HeadLog: Send + Sync {
    /// Current tip, if any.
    async fn tip(&self, repo: &RepoId) -> Result<Option<RefHead>, StorageError>;

    /// Append `head` iff `head.prev_head_hash` matches the current tip hash
    /// (or zero for genesis).
    async fn cas_append(&self, head: RefHead) -> Result<HeadHash, StorageError>;

    /// Fetch heads with `seq` in `(after_seq, tip]` (exclusive lower bound).
    async fn since(&self, repo: &RepoId, after_seq: u64) -> Result<Vec<RefHead>, StorageError>;

    /// Append a key-log entry (admin-signed DKR update).
    async fn append_key_log(&self, repo: &RepoId, entry: KeyLogEntry) -> Result<(), StorageError>;

    /// Key-log entries since epoch.
    async fn key_log_since(
        &self,
        repo: &RepoId,
        after_epoch: u64,
    ) -> Result<Vec<KeyLogEntry>, StorageError>;
}

/// MLS ciphertext delivery (Welcome / Commit / application messages).
#[async_trait]
pub trait MlsDeliveryQueue: Send + Sync {
    /// Enqueue opaque MLS framing; returns assigned sequence.
    async fn enqueue(&self, env: MlsDeliveryEnvelope) -> Result<u64, StorageError>;

    /// Fetch messages with seq > `after`.
    async fn fetch(
        &self,
        repo: &RepoId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MlsDeliveryEnvelope>, StorageError>;
}

/// Soft directory of repository names (non-cryptographic metadata).
#[async_trait]
pub trait RepoDirectory: Send + Sync {
    /// Register a new repository name → id mapping.
    async fn create(&self, record: RepoRecord) -> Result<(), StorageError>;
    /// Look up by `owner/name`.
    async fn get_by_name(&self, owner: &str, name: &str) -> Result<Option<RepoRecord>, StorageError>;
    /// Look up by cryptographic id.
    async fn get_by_id(&self, id: &RepoId) -> Result<Option<RepoRecord>, StorageError>;
    /// List repos owned by `user` (directory view).
    async fn list_for_user(&self, user: &UserId) -> Result<Vec<RepoRecord>, StorageError>;
    /// Persist an updated directory record (archive / tombstone / description).
    async fn update(&self, record: RepoRecord) -> Result<(), StorageError>;
}
