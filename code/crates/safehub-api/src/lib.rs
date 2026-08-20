//! Shared HTTP API surface for SafeHub server and clients.

#![deny(missing_docs)]

use safehub_types::{BlobId, BlobMeta, HeadHash, KeyLogEntry, MlsDeliveryEnvelope, RefHead, RepoId};
use serde::{Deserialize, Serialize};

/// API version prefix.
pub const API_PREFIX: &str = "/v1";

/// Route paths (relative to [`API_PREFIX`]).
pub mod routes {
    /// `POST /auth/register`
    pub const REGISTER: &str = "/auth/register";
    /// `POST /auth/login`
    pub const LOGIN: &str = "/auth/login";
    /// `GET /auth/whoami`
    pub const WHOAMI: &str = "/auth/whoami";
    /// `GET|POST /user/tokens`
    pub const USER_TOKENS: &str = "/user/tokens";
    /// `DELETE /user/tokens/:token`
    pub const USER_TOKEN: &str = "/user/tokens/:token";
    /// `POST /repos`
    pub const REPOS: &str = "/repos";
    /// `GET|PATCH|DELETE /repos/:owner/:name`
    pub const REPO: &str = "/repos/:owner/:name";
    /// `GET|POST /repos/:owner/:name/hooks` — always 501 on untrusted host
    pub const REPO_HOOKS: &str = "/repos/:owner/:name/hooks";
    /// `PUT /repos/:repo_id/blobs`
    pub const BLOBS: &str = "/repos/:repo_id/blobs";
    /// `GET /repos/:repo_id/blobs/:blob_id`
    pub const BLOB: &str = "/repos/:repo_id/blobs/:blob_id";
    /// `GET /repos/:repo_id/heads/tip`
    pub const HEAD_TIP: &str = "/repos/:repo_id/heads/tip";
    /// `POST /repos/:repo_id/heads` (CAS append)
    pub const HEADS: &str = "/repos/:repo_id/heads";
    /// `GET /repos/:repo_id/heads?after=N`
    pub const HEADS_SINCE: &str = "/repos/:repo_id/heads";
    /// `POST /repos/:repo_id/mls`
    pub const MLS_ENQUEUE: &str = "/repos/:repo_id/mls";
    /// `GET /repos/:repo_id/mls?after=N`
    pub const MLS_FETCH: &str = "/repos/:repo_id/mls";
    /// `PUT /users/:user/key_packages`
    pub const KEY_PACKAGES: &str = "/users/:user/key_packages";
    /// `GET /users/:user/key_packages`
    pub const KEY_PACKAGES_GET: &str = "/users/:user/key_packages";
    /// `POST /repos/:repo_id/keylog`
    pub const KEYLOG: &str = "/repos/:repo_id/keylog";
}

/// Blob upload: JSON metadata + base64 ciphertext (legacy).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobPutRequest {
    /// Chunk metadata.
    pub meta: BlobMeta,
    /// Base64 ciphertext (legacy JSON path; prefer raw octet-stream PUT).
    pub ciphertext_b64: String,
}

/// HTTP header carrying JSON [`BlobMeta`] for binary blob PUTs.
pub const BLOB_META_HEADER: &str = "x-safehub-blob-meta";

/// Blob upload response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobPutResponse {
    /// Content id of stored ciphertext.
    pub id: BlobId,
}

/// CAS append request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeadAppendRequest {
    /// New head to append.
    pub head: RefHead,
}

/// CAS append response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeadAppendResponse {
    /// Hash of the accepted head.
    pub hash: HeadHash,
}

/// Heads-since query response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeadsSinceResponse {
    /// Heads with seq greater than the query cursor.
    pub heads: Vec<RefHead>,
}

/// MLS enqueue request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsEnqueueRequest {
    /// Opaque MLS framing bytes.
    pub payload: Vec<u8>,
    /// Optional debug hint.
    pub sender_hint: Option<String>,
}

/// MLS enqueue response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsEnqueueResponse {
    /// Assigned delivery sequence.
    pub seq: u64,
}

/// MLS fetch response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsFetchResponse {
    /// Delivered envelopes.
    pub messages: Vec<MlsDeliveryEnvelope>,
}

/// Key-log append.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyLogAppendRequest {
    /// Entry to append.
    pub entry: KeyLogEntry,
}

pub use safehub_types::{
    AuthToken, CreateRepoRequest, KeyPackageRecord, LoginRequest, RegisterRequest, RepoRecord,
    UserId,
};

/// Create personal access token request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreatePatRequest {
    /// Human-readable note.
    pub note: String,
    /// Scopes (`repo`, `read:user`). Empty → both.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Whoami response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhoAmIResponse {
    /// Authenticated user.
    pub user: UserId,
}

/// Create-repo response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateRepoResponse {
    /// Created repository record.
    pub repo: RepoRecord,
}

/// Helper to build a full path.
pub fn path(route: &str) -> String {
    format!("{API_PREFIX}{route}")
}

/// Substitute `:repo_id` in a route template.
pub fn with_repo(route: &str, repo: &RepoId) -> String {
    route.replace(":repo_id", &repo.to_hex())
}
