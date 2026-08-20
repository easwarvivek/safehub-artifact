//! Collaboration / MLS application-message schemas and API envelopes.

use crate::ids::{RepoId, RepoName, UserId};
use serde::{Deserialize, Serialize};

/// Structured collaboration messages carried as MLS application payloads.
///
/// The server stores ciphertext only; these enums describe the plaintext
/// shapes clients encrypt inside the group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CollabMessage {
    /// Open or update a pull request.
    PullRequest {
        /// Stable PR id within the repo.
        id: String,
        /// Source ref (encrypted tip name / oid).
        head_ref: String,
        /// Target ref.
        base_ref: String,
        /// Title.
        title: String,
        /// Body markdown.
        body: String,
        /// `open` | `closed` | `merged` (latest message wins when folding the inbox).
        #[serde(default = "default_open")]
        state: String,
    },
    /// Issue tracker item.
    Issue {
        /// Stable issue id.
        id: String,
        /// Title.
        title: String,
        /// Body markdown.
        body: String,
        /// `open` | `closed` (latest message wins when folding the inbox).
        #[serde(default = "default_open")]
        state: String,
    },
    /// Code review comment / verdict.
    Review {
        /// Target pull request id.
        pr_id: String,
        /// `approve` | `request_changes` | `comment`
        verdict: String,
        /// Review body.
        body: String,
    },
    /// CI runner result.
    CiVerdict {
        /// Commit oid (plaintext hash; integrity from git DAG).
        commit: String,
        /// `success` | `failure` | `neutral`
        status: String,
        /// Human-readable summary.
        summary: String,
        /// Optional workflow / run correlation id.
        #[serde(default)]
        run_id: Option<String>,
    },
    /// Release announcement (notes encrypted; assets referenced by CAS blob ids).
    Release {
        /// Tag name (also a git ref tip when pushed).
        tag: String,
        /// Release title.
        title: String,
        /// Release notes (markdown).
        notes: String,
        /// Encrypted asset blob ids (hex SHA-512 of ciphertext).
        #[serde(default)]
        asset_blob_ids: Vec<String>,
        /// Asset filenames aligned with `asset_blob_ids`.
        #[serde(default)]
        asset_names: Vec<String>,
    },
    /// Issue / PR label definition.
    Label {
        /// Label name.
        name: String,
        /// Optional color hint (client-only display).
        #[serde(default)]
        color: Option<String>,
        /// Optional description.
        #[serde(default)]
        description: Option<String>,
        /// `create` | `delete`.
        #[serde(default = "default_create")]
        action: String,
    },
    /// Milestone metadata.
    Milestone {
        /// Milestone title.
        title: String,
        /// Optional due date (ISO-8601 string).
        #[serde(default)]
        due: Option<String>,
        /// `open` | `closed`.
        #[serde(default = "default_open")]
        state: String,
    },
    /// Runner secret sealed to a runner KeyPackage (never plaintext on server).
    Secret {
        /// Secret name.
        name: String,
        /// Opaque ciphertext sealed to runner KeyPackage (or group AEAD).
        sealed_value: Vec<u8>,
        /// Target runner / device hint.
        #[serde(default)]
        runner_hint: Option<String>,
        /// `set` | `delete`.
        #[serde(default = "default_set")]
        action: String,
    },
    /// Actions-style variable sealed under group AEAD (never plaintext on host).
    Variable {
        /// Variable name.
        name: String,
        /// Opaque ciphertext (group AEAD).
        sealed_value: Vec<u8>,
        /// `set` | `delete`.
        #[serde(default = "default_set")]
        action: String,
    },
    /// Encrypted gist blob (single-file or multi-file JSON).
    Gist {
        /// Gist id.
        id: String,
        /// Optional description.
        #[serde(default)]
        description: Option<String>,
        /// Filename → contents map.
        files: std::collections::BTreeMap<String, String>,
        /// `create` | `edit` | `delete`.
        #[serde(default = "default_create")]
        action: String,
    },
    /// Encrypted project board.
    Project {
        /// Project number / id.
        id: String,
        /// Title.
        title: String,
        /// Column name → card titles.
        #[serde(default)]
        columns: std::collections::BTreeMap<String, Vec<String>>,
        /// `create` | `update` | `delete`.
        #[serde(default = "default_create")]
        action: String,
    },
    /// Draft codespace / remote-dev config (not a hosted VM).
    CodespaceConfig {
        /// Config name.
        name: String,
        /// JSON/YAML-ish config body (encrypted).
        config: String,
        /// `create` | `delete`.
        #[serde(default = "default_create")]
        action: String,
    },
    /// Workflow run request / metadata (YAML itself lives in encrypted git).
    WorkflowRun {
        /// Run id.
        id: String,
        /// Workflow file / name.
        workflow: String,
        /// `queued` | `in_progress` | `completed` | `cancelled`.
        status: String,
        /// Optional commit oid.
        #[serde(default)]
        commit: Option<String>,
    },
    /// Org / team membership list (encrypted directory payload).
    OrgDirectory {
        /// Organization name.
        org: String,
        /// Member usernames.
        members: Vec<String>,
        /// Optional team name → members.
        #[serde(default)]
        teams: std::collections::BTreeMap<String, Vec<String>>,
    },
    /// PR / issue comment body (when dual-writing encrypted inbox).
    Comment {
        /// Target kind: `issue` | `pr`.
        target_kind: String,
        /// Target id.
        target_id: String,
        /// Comment body.
        body: String,
    },
}

fn default_create() -> String {
    "create".into()
}

fn default_open() -> String {
    "open".into()
}

fn default_set() -> String {
    "set".into()
}

/// Public repository directory record (names only; no ciphertext).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoRecord {
    /// Cryptographic repo id.
    pub id: RepoId,
    /// Human `owner/name`.
    pub name: RepoName,
    /// Creating user.
    pub created_by: UserId,
    /// Whether the directory listing is visible to authenticated users.
    pub private: bool,
    /// Soft-archive flag (control-plane metadata only; ciphertext retained).
    #[serde(default)]
    pub archived: bool,
    /// Soft-delete / tombstone (control-plane; GC of CAS is operator policy).
    #[serde(default)]
    pub deleted: bool,
    /// Optional server-visible description (names/metadata leakage; prefer MLS edit).
    #[serde(default)]
    pub description: Option<String>,
}

/// Auth token issued by the server (scaffold: bearer string).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    /// Opaque bearer credential.
    pub token: String,
    /// Subject user.
    pub user: UserId,
}

/// Registration request body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Username / login.
    pub user: String,
    /// Password (hashed server-side with argon2id).
    pub password: String,
}

/// Login request body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username / login.
    pub user: String,
    /// Password.
    pub secret: String,
}

/// Create-repository request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateRepoRequest {
    /// Repository name (under the authenticated owner).
    pub name: String,
    /// Private by default.
    #[serde(default = "default_true")]
    pub private: bool,
    /// Optional description (server-visible metadata).
    pub description: Option<String>,
}

fn default_true() -> bool {
    true
}

/// MLS delivery envelope: opaque framing the server fans out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsDeliveryEnvelope {
    /// Repository group this message belongs to.
    pub repo_id: RepoId,
    /// Monotonic delivery sequence for this repo's MLS channel.
    pub seq: u64,
    /// Opaque MLS ciphertext / welcome / commit bytes.
    pub payload: Vec<u8>,
    /// Optional sender hint for debugging (not authenticated).
    pub sender_hint: Option<String>,
}

/// KeyPackage upload for invites (opaque to server).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackageRecord {
    /// Owning user.
    pub user: UserId,
    /// Device label within the user.
    pub device: String,
    /// Opaque OpenMLS KeyPackage bytes.
    pub key_package: Vec<u8>,
}
