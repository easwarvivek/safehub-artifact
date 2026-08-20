//! Filesystem-backed store for local development and tests.

use crate::error::StorageError;
use crate::traits::{BlobStore, HeadLog, MlsDeliveryQueue, RepoDirectory};
use async_trait::async_trait;
use bytes::Bytes;
use safehub_types::{
    BlobId, BlobMeta, HeadHash, KeyLogEntry, MlsDeliveryEnvelope, RefHead, RepoId, RepoRecord,
    UserId,
};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::Mutex;

/// Root layout:
/// ```text
/// root/
///   blobs/{hex}
///   blobmeta/{hex}.json
///   heads/{repo}/tip.bin          # canonical TLS-presentation RefHead
///   heads/{repo}/log/{seq}.bin
///   keylog/{repo}/{epoch}.json
///   mls/{repo}/{seq}.json
///   repos/{owner}/{name}.json
///   repos_by_id/{repo}.json
/// ```
pub struct LocalStore {
    root: PathBuf,
    /// Serialize CAS on heads.
    head_lock: Mutex<()>,
}

impl LocalStore {
    /// Open or create a store at `root`.
    pub async fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        for sub in [
            "blobs",
            "blobmeta",
            "heads",
            "keylog",
            "mls",
            "repos",
            "repos_by_id",
            "key_packages",
        ] {
            fs::create_dir_all(root.join(sub)).await?;
        }
        Ok(Self {
            root,
            head_lock: Mutex::new(()),
        })
    }

    fn blob_path(&self, id: &BlobId) -> PathBuf {
        self.root.join("blobs").join(id.to_hex())
    }

    fn blobmeta_path(&self, id: &BlobId) -> PathBuf {
        self.root
            .join("blobmeta")
            .join(format!("{}.json", id.to_hex()))
    }

    fn heads_dir(&self, repo: &RepoId) -> PathBuf {
        self.root.join("heads").join(repo.to_hex())
    }
}

/// Write `bytes` via temp file → fsync → rename → fsync parent (best-effort).
async fn atomic_write_sync(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("bin")
    ));
    {
        use tokio::io::AsyncWriteExt;
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
    }
    fs::rename(&tmp, path).await?;
    // Best-effort directory fsync for durability of the rename.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn decode_head_bytes(bytes: &[u8]) -> Result<RefHead, StorageError> {
    // Prefer canonical TLS encoding; fall back to legacy pretty JSON tips.
    match safehub_types::decode_ref_head(bytes) {
        Ok(h) => Ok(h),
        Err(_) => serde_json::from_slice(bytes)
            .map_err(|e| StorageError::Other(format!("decode RefHead: {e}"))),
    }
}

#[async_trait]
impl BlobStore for LocalStore {
    async fn put(&self, meta: BlobMeta, ciphertext: Bytes) -> Result<BlobId, StorageError> {
        let id = BlobId::of_ciphertext(&ciphertext);
        if id != meta.id && meta.id.0 != [0u8; 64] {
            // Allow caller to leave id zero; we overwrite with computed.
        }
        let mut meta = meta;
        meta.id = id;
        meta.size = ciphertext.len() as u64;

        let path = self.blob_path(&id);
        if !path.exists() {
            fs::write(&path, &ciphertext).await?;
        }
        fs::write(self.blobmeta_path(&id), serde_json::to_vec_pretty(&meta)?).await?;
        Ok(id)
    }

    async fn get(&self, id: &BlobId) -> Result<Bytes, StorageError> {
        let path = self.blob_path(id);
        if !path.exists() {
            return Err(StorageError::NotFound(id.to_hex()));
        }
        Ok(Bytes::from(fs::read(path).await?))
    }

    async fn meta(&self, id: &BlobId) -> Result<BlobMeta, StorageError> {
        let path = self.blobmeta_path(id);
        if !path.exists() {
            return Err(StorageError::NotFound(id.to_hex()));
        }
        let bytes = fs::read(path).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn exists(&self, id: &BlobId) -> Result<bool, StorageError> {
        Ok(self.blob_path(id).exists())
    }
}

#[async_trait]
impl HeadLog for LocalStore {
    async fn tip(&self, repo: &RepoId) -> Result<Option<RefHead>, StorageError> {
        let dir = self.heads_dir(repo);
        let bin = dir.join("tip.bin");
        let json = dir.join("tip.json");
        let path = if bin.exists() {
            bin
        } else if json.exists() {
            json
        } else {
            return Ok(None);
        };
        let bytes = fs::read(path).await?;
        Ok(Some(decode_head_bytes(&bytes)?))
    }

    async fn cas_append(&self, head: RefHead) -> Result<HeadHash, StorageError> {
        let _guard = self.head_lock.lock().await;
        let dir = self.heads_dir(&head.repo_id);
        fs::create_dir_all(dir.join("log")).await?;

        let current = self.tip(&head.repo_id).await?;
        let expected_prev = match &current {
            Some(h) => h.hash(),
            None => HeadHash::zero(),
        };
        if head.prev_head_hash != expected_prev {
            return Err(StorageError::CasConflict {
                expected: expected_prev,
            });
        }
        if let Some(cur) = &current {
            if head.seq != cur.seq + 1 {
                return Err(StorageError::Other(format!(
                    "seq must be {}, got {}",
                    cur.seq + 1,
                    head.seq
                )));
            }
        } else if head.seq != 1 {
            return Err(StorageError::Other("genesis seq must be 1".into()));
        }

        let hash = head.hash();
        // Persist canonical TLS-presentation bytes (same bytes that are hashed).
        let body = head.canonical_bytes();
        let log_path = dir.join("log").join(format!("{}.bin", head.seq));
        let tip_path = dir.join("tip.bin");
        // Atomic durable append: write log entry, fsync, then tip via temp+rename+fsync.
        atomic_write_sync(&log_path, &body).await?;
        atomic_write_sync(&tip_path, &body).await?;
        // Legacy JSON tip cleanup (migration): ignore errors.
        let _ = fs::remove_file(dir.join("tip.json")).await;
        Ok(hash)
    }

    async fn since(&self, repo: &RepoId, after_seq: u64) -> Result<Vec<RefHead>, StorageError> {
        let log_dir = self.heads_dir(repo).join("log");
        if !log_dir.exists() {
            return Ok(vec![]);
        }
        let mut out: Vec<RefHead> = Vec::new();
        let mut rd = fs::read_dir(log_dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let seq_str = name
                .strip_suffix(".bin")
                .or_else(|| name.strip_suffix(".json"));
            if let Some(seq_str) = seq_str {
                if let Ok(seq) = seq_str.parse::<u64>() {
                    if seq > after_seq {
                        let bytes = fs::read(ent.path()).await?;
                        out.push(decode_head_bytes(&bytes)?);
                    }
                }
            }
        }
        out.sort_by_key(|h| h.seq);
        Ok(out)
    }

    async fn append_key_log(&self, repo: &RepoId, entry: KeyLogEntry) -> Result<(), StorageError> {
        let dir = self.root.join("keylog").join(repo.to_hex());
        fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{}.json", entry.drive_epoch));
        fs::write(path, serde_json::to_vec_pretty(&entry)?).await?;
        Ok(())
    }

    async fn key_log_since(
        &self,
        repo: &RepoId,
        after_epoch: u64,
    ) -> Result<Vec<KeyLogEntry>, StorageError> {
        let dir = self.root.join("keylog").join(repo.to_hex());
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out: Vec<KeyLogEntry> = Vec::new();
        let mut rd = fs::read_dir(dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(ep) = name.strip_suffix(".json") {
                if let Ok(epoch) = ep.parse::<u64>() {
                    if epoch > after_epoch {
                        let bytes = fs::read(ent.path()).await?;
                        out.push(serde_json::from_slice(&bytes)?);
                    }
                }
            }
        }
        out.sort_by_key(|e| e.drive_epoch);
        Ok(out)
    }
}

#[async_trait]
impl MlsDeliveryQueue for LocalStore {
    async fn enqueue(&self, mut env: MlsDeliveryEnvelope) -> Result<u64, StorageError> {
        let dir = self.root.join("mls").join(env.repo_id.to_hex());
        fs::create_dir_all(&dir).await?;
        // Assign next seq.
        let mut max = 0u64;
        let mut rd = fs::read_dir(&dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(s) = name.strip_suffix(".json") {
                if let Ok(n) = s.parse::<u64>() {
                    max = max.max(n);
                }
            }
        }
        env.seq = max + 1;
        let seq = env.seq;
        fs::write(dir.join(format!("{seq}.json")), serde_json::to_vec_pretty(&env)?).await?;
        Ok(seq)
    }

    async fn fetch(
        &self,
        repo: &RepoId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MlsDeliveryEnvelope>, StorageError> {
        let dir = self.root.join("mls").join(repo.to_hex());
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out: Vec<MlsDeliveryEnvelope> = Vec::new();
        let mut rd = fs::read_dir(&dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(s) = name.strip_suffix(".json") {
                if let Ok(n) = s.parse::<u64>() {
                    if n > after {
                        let bytes = fs::read(ent.path()).await?;
                        out.push(serde_json::from_slice(&bytes)?);
                    }
                }
            }
        }
        out.sort_by_key(|e| e.seq);
        out.truncate(limit);
        Ok(out)
    }
}

#[async_trait]
impl RepoDirectory for LocalStore {
    async fn create(&self, record: RepoRecord) -> Result<(), StorageError> {
        let owner_dir = self.root.join("repos").join(&record.name.owner);
        fs::create_dir_all(&owner_dir).await?;
        let path = owner_dir.join(format!("{}.json", record.name.name));
        if path.exists() {
            return Err(StorageError::Other(format!(
                "repo {} already exists",
                record.name
            )));
        }
        let body = serde_json::to_vec_pretty(&record)?;
        fs::write(path, &body).await?;
        fs::write(
            self.root
                .join("repos_by_id")
                .join(format!("{}.json", record.id.to_hex())),
            &body,
        )
        .await?;
        Ok(())
    }

    async fn get_by_name(&self, owner: &str, name: &str) -> Result<Option<RepoRecord>, StorageError> {
        let path = self.root.join("repos").join(owner).join(format!("{name}.json"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path).await?)?))
    }

    async fn get_by_id(&self, id: &RepoId) -> Result<Option<RepoRecord>, StorageError> {
        let path = self
            .root
            .join("repos_by_id")
            .join(format!("{}.json", id.to_hex()));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path).await?)?))
    }

    async fn list_for_user(&self, user: &UserId) -> Result<Vec<RepoRecord>, StorageError> {
        let dir = self.root.join("repos").join(&user.0);
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut rd = fs::read_dir(dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            if ent.file_name().to_string_lossy().ends_with(".json") {
                let rec: RepoRecord = serde_json::from_slice(&fs::read(ent.path()).await?)?;
                if !rec.deleted {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    async fn update(&self, record: RepoRecord) -> Result<(), StorageError> {
        let owner_dir = self.root.join("repos").join(&record.name.owner);
        fs::create_dir_all(&owner_dir).await?;
        let path = owner_dir.join(format!("{}.json", record.name.name));
        if !path.exists() {
            return Err(StorageError::Other(format!(
                "repo {} not found",
                record.name
            )));
        }
        let body = serde_json::to_vec_pretty(&record)?;
        fs::write(path, &body).await?;
        fs::write(
            self.root
                .join("repos_by_id")
                .join(format!("{}.json", record.id.to_hex())),
            &body,
        )
        .await?;
        Ok(())
    }
}

impl LocalStore {
    /// List every non-deleted directory record (for membership-scoped listing).
    pub async fn list_all_repos(&self) -> Result<Vec<RepoRecord>, StorageError> {
        let root = self.root.join("repos");
        if !root.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut owners = fs::read_dir(&root).await?;
        while let Some(owner_ent) = owners.next_entry().await? {
            if !owner_ent.file_type().await?.is_dir() {
                continue;
            }
            let mut repos = fs::read_dir(owner_ent.path()).await?;
            while let Some(ent) = repos.next_entry().await? {
                if !ent.file_name().to_string_lossy().ends_with(".json") {
                    continue;
                }
                let rec: RepoRecord = serde_json::from_slice(&fs::read(ent.path()).await?)?;
                if !rec.deleted {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }
}

impl LocalStore {
    /// Store an opaque KeyPackage for a user/device.
    pub async fn put_key_package(
        &self,
        record: &safehub_types::KeyPackageRecord,
    ) -> Result<(), StorageError> {
        let dir = self.root.join("key_packages").join(&record.user.0);
        fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{}.bin", record.device));
        fs::write(path, &record.key_package).await?;
        let meta = dir.join(format!("{}.json", record.device));
        fs::write(
            meta,
            serde_json::to_vec_pretty(&serde_json::json!({
                "user": record.user.0,
                "device": record.device,
                "size": record.key_package.len(),
            }))?,
        )
        .await?;
        Ok(())
    }

    /// List KeyPackages for a user (opaque bytes).
    pub async fn list_key_packages(
        &self,
        user: &UserId,
    ) -> Result<Vec<safehub_types::KeyPackageRecord>, StorageError> {
        let dir = self.root.join("key_packages").join(&user.0);
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut rd = fs::read_dir(dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(device) = name.strip_suffix(".bin") {
                let bytes = fs::read(ent.path()).await?;
                out.push(safehub_types::KeyPackageRecord {
                    user: user.clone(),
                    device: device.to_string(),
                    key_package: bytes,
                });
            }
        }
        Ok(out)
    }
}
