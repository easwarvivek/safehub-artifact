//! Push / fetch planning: chunk, encrypt, wrap DEK, build RefHead.
//!
//! Epoch keys come from OpenMLS exporters composed with DKR (see `mls_local`).
//! Push framing (`push_id` + chunk ids) is sealed inside `enc_refs` so any
//! device with epoch material can fetch without local side-channel files.
//! Leaf and (when non-FF) admin signatures are real ML-DSA-87.

use crate::error::ClientError;
use crate::http::HttpClient;
use crate::mls_local::{load_admin_keypair, load_persisted_group, EpochMaterial};
use crate::policy::{admin_cosig_sign, leaf_sign_message, refs_digest};
use rand::RngCore;
use safehub_crypto::aead::{
    derive_cas_seal_key, derive_head_seal_key, CommittingAead,
};
use safehub_types::domain_label;
use safehub_types::{BlobId, BlobMeta, HeadHash, RefHead, RepoId, BUNDLE_CHUNK_SIZE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// One encrypted chunk ready for upload.
#[derive(Clone, Debug)]
pub struct EncryptedChunk {
    /// Server-visible chunk metadata.
    pub meta: BlobMeta,
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

/// Plan produced before contacting the server.
#[derive(Clone, Debug)]
pub struct PushPlan {
    /// Client push correlation id.
    pub push_id: String,
    /// Encrypted chunks to upload.
    pub chunks: Vec<EncryptedChunk>,
    /// SHA-512 Merkle tip over chunk content-ids.
    pub bundle_root: BlobId,
    /// Wrapped DEK.
    pub dek_wrap: Vec<u8>,
    /// Encrypted refs map.
    pub enc_refs: Vec<u8>,
    /// MLS epoch.
    pub epoch: u64,
    /// HMAC-SHA-512-256(mk_e, ·) epoch authenticator (32 bytes).
    pub epoch_tag: Vec<u8>,
}

/// Result after successful CAS.
#[derive(Clone, Debug)]
pub struct PushResult {
    /// Accepted head.
    pub head: RefHead,
    /// Head hash.
    pub head_hash: HeadHash,
    /// Plaintext refs map that was sealed (includes framing).
    pub refs: EncryptedRefsMap,
}

/// Result of a fetch decryption.
#[derive(Clone, Debug)]
pub struct FetchResult {
    /// Tip head that was decrypted.
    pub head: RefHead,
    /// Decrypted git refs + push framing.
    pub refs: EncryptedRefsMap,
    /// Decrypted git-bundle bytes.
    pub bundle: Vec<u8>,
}

/// Payload sealed in `RefHead.enc_refs` (git tips + fetch framing).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRefsMap {
    /// Git ref name → object id (hex).
    #[serde(default)]
    pub refs: BTreeMap<String, String>,
    /// Symbolic HEAD, e.g. `ref: refs/heads/main`.
    #[serde(default)]
    pub head: Option<String>,
    /// Client push correlation id (needed to rebuild chunk AAD).
    #[serde(default)]
    pub push_id: String,
    /// Content-ids of uploaded ciphertext chunks, in order.
    #[serde(default)]
    pub chunk_ids: Vec<String>,
}

/// Payload used for a head that updates refs without adding objects.
///
/// A ref deletion changes the ref map but introduces no commits, so there is no
/// git bundle to build. The head still has to exist — the ref set is part of the
/// authenticated chain — so it carries this sentinel instead. Readers replaying
/// the chain must recognise it and apply the refs without attempting an import:
/// handing these bytes to `git fetch` fails with "couldn't find remote ref
/// HEAD", which would make every clone after a deletion fail permanently.
pub const REF_ONLY_BUNDLE: &[u8] = b"safehub-ref-delete";

/// True when a fetched payload carries refs only and must not be imported.
pub fn is_ref_only_bundle(bundle: &[u8]) -> bool {
    bundle == REF_ONLY_BUNDLE
}

/// Default parallel chunk-upload window (WAN round-trip amortization).
pub const DEFAULT_UPLOAD_WINDOW: usize = 8;

/// Protocol round trips for a push with `n` chunks and upload window `P`
/// (tip GET + ⌈n/P⌉ parallel PUT waves + head POST). Does not count CAS retries.
pub fn push_round_trips(chunk_count: usize, upload_window: usize) -> u64 {
    let p = upload_window.max(1);
    let waves = chunk_count.div_ceil(p) as u64;
    1 + waves + 1
}

/// Split plaintext into 4 MiB chunks and encrypt under a fresh DEK.
///
/// Chunk AAD binds `(repo, push_id, i, n)`, so truncation and reordering are
/// rejected on open. Prefer [`bundle_chunks_seek`] for large file-backed bundles.
pub fn bundle_chunks(
    repo: &RepoId,
    push_id: &str,
    plaintext: &[u8],
    dek: &[u8; 32],
) -> Result<Vec<EncryptedChunk>, ClientError> {
    use std::io::Cursor;
    bundle_chunks_seek(repo, push_id, &mut Cursor::new(plaintext), dek)
}

/// Stream-seal a seekable plaintext source in `BUNDLE_CHUNK_SIZE` blocks.
///
/// Computes `n` from length via seek, then encrypts one chunk at a time so
/// peak plaintext residency is one chunk (plus the sealed ciphertext list).
pub fn bundle_chunks_seek<R: std::io::Read + std::io::Seek>(
    repo: &RepoId,
    push_id: &str,
    reader: &mut R,
    dek: &[u8; 32],
) -> Result<Vec<EncryptedChunk>, ClientError> {
    use std::io::SeekFrom;
    let len = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| ClientError::Other(format!("bundle seek: {e}")))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| ClientError::Other(format!("bundle rewind: {e}")))?;
    let n = if len == 0 {
        1u32
    } else {
        ((len as usize).div_ceil(BUNDLE_CHUNK_SIZE)) as u32
    };
    let mut out = Vec::with_capacity(n as usize);
    let mut buf = vec![0u8; BUNDLE_CHUNK_SIZE];
    for i in 0..n {
        let mut filled = 0usize;
        while filled < BUNDLE_CHUNK_SIZE {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(nread) => filled += nread,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ClientError::Other(format!("bundle read: {e}"))),
            }
        }
        let aad = format!("{}:{}:{}:{}", repo.to_hex(), push_id, i, n);
        let mut aad_bytes = domain_label("bundle-chunk").into_bytes();
        aad_bytes.push(b'|');
        aad_bytes.extend_from_slice(aad.as_bytes());
        let ct = CommittingAead::seal(dek, &aad_bytes, &buf[..filled])?;
        buf[..filled].fill(0);
        let id = BlobId::of_ciphertext(&ct);
        out.push(EncryptedChunk {
            meta: BlobMeta {
                id,
                size: ct.len() as u64,
                chunk_index: i,
                chunk_count: n,
                push_id: push_id.into(),
            },
            ciphertext: ct,
        });
    }
    Ok(out)
}

/// Alias of [`bundle_chunks_seek`].
#[inline]
pub fn bundle_chunks_reader<R: std::io::Read + std::io::Seek>(
    repo: &RepoId,
    push_id: &str,
    reader: &mut R,
    dek: &[u8; 32],
) -> Result<Vec<EncryptedChunk>, ClientError> {
    bundle_chunks_seek(repo, push_id, reader, dek)
}

/// Attach leaf ML-DSA-87 (and admin co-sig when non-FF) to a planned head.
pub fn sign_ref_head(
    head: &mut RefHead,
    refs: &EncryptedRefsMap,
    repo: &RepoId,
) -> Result<(), ClientError> {
    let group = load_persisted_group(repo)?;
    let msg = leaf_sign_message(head);
    head.pusher_sig = group
        .sign_detached(&msg)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    if head.non_ff {
        let admin = load_admin_keypair(repo)?;
        let dig = refs_digest(refs);
        let roster = group.member_signature_keys();
        head.admin_cosig = Some(admin_cosig_sign(
            &admin,
            repo,
            head.mls_epoch,
            "push",
            head.seq,
            &head.prev_head_hash,
            &dig,
            &crate::policy::roster_digest(&roster),
        )?);
    } else {
        head.admin_cosig = None;
    }
    Ok(())
}

fn build_push_plan<R: std::io::Read + std::io::Seek>(
    repo: &RepoId,
    plaintext_bundle: &mut R,
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    prev_head_hash: HeadHash,
    next_seq: u64,
    non_ff: bool,
    sign: bool,
) -> Result<(PushPlan, RefHead, EncryptedRefsMap), ClientError> {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);

    let push_id = hex::encode({
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        b
    });

    let epoch = material.epoch;
    let mut ke = material.epoch_key()?;
    // Per-head seal subkey: counters are local to this seq under K_e^{seq}.
    let mut seal_key = derive_head_seal_key(&ke, next_seq)?;
    ke.zeroize();
    let mut seal_counter = 0u64;

    let chunks = bundle_chunks_seek(repo, &push_id, plaintext_bundle, &dek)?;
    let mut root_hasher = Sha512::new();
    for c in &chunks {
        root_hasher.update(&c.meta.id.0);
    }
    let digest = root_hasher.finalize();
    let mut root = [0u8; 64];
    root.copy_from_slice(&digest);
    let bundle_root = BlobId(root);

    let refs_map = EncryptedRefsMap {
        refs: git_refs,
        head: head_symref,
        push_id: push_id.clone(),
        chunk_ids: chunks.iter().map(|c| c.meta.id.to_hex()).collect(),
    };
    let refs_json = serde_json::to_vec(&refs_map)?;

    let dek_wrap = CommittingAead::seal_deterministic(
        &seal_key,
        domain_label("dek-wrap").as_bytes(),
        &dek,
        seal_counter,
    )?;
    seal_counter += 1;
    let enc_refs = CommittingAead::seal_deterministic(
        &seal_key,
        domain_label("refs").as_bytes(),
        &refs_json,
        seal_counter,
    )?;
    seal_key.zeroize();

    // Same function the read path verifies with, so the two cannot drift.
    let epoch_tag =
        crate::policy::epoch_tag_bytes(&material.refs_mac, epoch, &bundle_root, next_seq);

    dek.zeroize();

    let mut head = RefHead {
        repo_id: *repo,
        seq: next_seq,
        enc_refs: enc_refs.clone(),
        bundle_root,
        dek_wrap: dek_wrap.clone(),
        prev_head_hash,
        mls_epoch: epoch,
        epoch_tag: epoch_tag.clone(),
        non_ff,
        pusher_sig: vec![],
        admin_cosig: None,
    };
    if sign {
        sign_ref_head(&mut head, &refs_map, repo)?;
    }

    Ok((
        PushPlan {
            push_id,
            chunks,
            bundle_root,
            dek_wrap,
            enc_refs,
            epoch,
            epoch_tag,
        },
        head,
        refs_map,
    ))
}

/// Build a push plan using MLS-exported epoch material.
///
/// Signs the RefHead with durable leaf ML-DSA-87 when a group keystore exists.
pub fn plan_push(
    repo: &RepoId,
    plaintext_bundle: &[u8],
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    prev_head_hash: HeadHash,
    next_seq: u64,
    non_ff: bool,
) -> Result<(PushPlan, RefHead, EncryptedRefsMap), ClientError> {
    use std::io::Cursor;
    plan_push_reader(
        repo,
        &mut Cursor::new(plaintext_bundle),
        git_refs,
        head_symref,
        material,
        prev_head_hash,
        next_seq,
        non_ff,
    )
}

/// Plan a push from a seekable plaintext source (file-backed bundles).
pub fn plan_push_reader<R: std::io::Read + std::io::Seek>(
    repo: &RepoId,
    plaintext_bundle: &mut R,
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    prev_head_hash: HeadHash,
    next_seq: u64,
    non_ff: bool,
) -> Result<(PushPlan, RefHead, EncryptedRefsMap), ClientError> {
    let sign = EpochMaterial::has_durable_group(repo);
    build_push_plan(
        repo,
        plaintext_bundle,
        git_refs,
        head_symref,
        material,
        prev_head_hash,
        next_seq,
        non_ff,
        sign,
    )
}

/// Like [`plan_push`] but never attempts leaf/admin signing (crypto unit tests).
pub fn plan_push_unsigned(
    repo: &RepoId,
    plaintext_bundle: &[u8],
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    prev_head_hash: HeadHash,
    next_seq: u64,
    non_ff: bool,
) -> Result<(PushPlan, RefHead, EncryptedRefsMap), ClientError> {
    use std::io::Cursor;
    build_push_plan(
        repo,
        &mut Cursor::new(plaintext_bundle),
        git_refs,
        head_symref,
        material,
        prev_head_hash,
        next_seq,
        non_ff,
        false,
    )
}

/// Default CAS retries on concurrent tip races (git-style optimistic concurrency).
pub const DEFAULT_CAS_RETRIES: u32 = 16;

/// First backoff step after a lost compare-and-swap.
const CAS_BACKOFF_BASE_MS: u64 = 20;

/// Ceiling for the exponential backoff, so a heavily contended push still
/// makes progress instead of sleeping unboundedly.
const CAS_BACKOFF_MAX_MS: u64 = 750;

/// Randomised exponential backoff for CAS retry `attempt` (1-based).
///
/// Without jitter every contending client wakes at the same instant, re-reads
/// the same tip, and collides again; that thundering herd is what starves
/// writers under multi-device contention.
fn cas_backoff(attempt: u32) -> std::time::Duration {
    use rand::Rng;
    let exp = CAS_BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(6));
    let capped = exp.min(CAS_BACKOFF_MAX_MS);
    // Full jitter over [capped/2, capped].
    let half = capped / 2;
    let jittered = half + rand::thread_rng().gen_range(0..=half.max(1));
    std::time::Duration::from_millis(jittered)
}

/// Reconcile a caller's planned refs with the tip observed on a CAS attempt.
///
/// `baseline` is the tip refs when the push was planned. `caller` is the full
/// map the caller wants to publish (typically baseline ∪ intentional updates).
/// `remote` is the tip refs at the current attempt (may have advanced).
///
/// Sibling refs landed by concurrent pushes are preserved. Updates the caller
/// actually intended are overlaid. If the remote moved a ref the caller is also
/// updating to a different oid, returns an error unless `allow_non_ff` (force /
/// admin path). This closes the race where attempt 0 could overwrite a divergent
/// tip that landed between the CLI fast-forward check and head append.
pub fn reconcile_refs_for_cas(
    baseline: &BTreeMap<String, String>,
    caller: &BTreeMap<String, String>,
    remote: &BTreeMap<String, String>,
    allow_non_ff: bool,
) -> Result<BTreeMap<String, String>, ClientError> {
    let mut intended: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in caller {
        if baseline.get(k) != Some(v) {
            intended.insert(k.clone(), v.clone());
        }
    }
    // Intentional deletes: present at plan time, absent from the caller's map.
    let mut deleted: Vec<String> = Vec::new();
    for k in baseline.keys() {
        if !caller.contains_key(k) {
            deleted.push(k.clone());
        }
    }

    if !allow_non_ff {
        for (k, new_oid) in &intended {
            if let Some(remote_oid) = remote.get(k) {
                let base_oid = baseline.get(k);
                let remote_moved = base_oid.map(|b| b != remote_oid).unwrap_or(true);
                if remote_moved && remote_oid != new_oid {
                    return Err(ClientError::Other(
                        "the remote advanced while this push was in flight; \
                         run `sit pull` to merge, then push again"
                            .into(),
                    ));
                }
            }
        }
        // Do not treat "keys present on a fresher tip but absent from the
        // caller's planned map" as deletions — that is the concurrent
        // sibling-branch case. Only the force/non-ff path may drop refs.
    }

    let mut merged = remote.clone();
    for (k, v) in &intended {
        merged.insert(k.clone(), v.clone());
    }
    if allow_non_ff {
        for k in &deleted {
            merged.remove(k);
        }
    }
    Ok(merged)
}

/// Plan + upload a git bundle as the next RefHead tip.
pub async fn push_bundle(
    client: &HttpClient,
    repo: &RepoId,
    plaintext_bundle: &[u8],
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    non_ff: bool,
) -> Result<PushResult, ClientError> {
    push_bundle_with_retries(
        client,
        repo,
        plaintext_bundle,
        git_refs,
        head_symref,
        material,
        non_ff,
        DEFAULT_CAS_RETRIES,
    )
    .await
}

/// Like [`push_bundle`], with an explicit CAS retry budget.
pub async fn push_bundle_with_retries(
    client: &HttpClient,
    repo: &RepoId,
    plaintext_bundle: &[u8],
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    non_ff: bool,
    max_retries: u32,
) -> Result<PushResult, ClientError> {
    push_bundle_with_retries_window(
        client,
        repo,
        plaintext_bundle,
        git_refs,
        head_symref,
        material,
        non_ff,
        max_retries,
        DEFAULT_UPLOAD_WINDOW,
    )
    .await
}

/// Like [`push_bundle_with_retries`] with a tunable parallel upload window.
pub async fn push_bundle_with_retries_window(
    client: &HttpClient,
    repo: &RepoId,
    plaintext_bundle: &[u8],
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    non_ff: bool,
    max_retries: u32,
    upload_window: usize,
) -> Result<PushResult, ClientError> {
    use std::io::Cursor;
    push_bundle_reader_with_retries_window(
        client,
        repo,
        &mut Cursor::new(plaintext_bundle),
        git_refs,
        head_symref,
        material,
        non_ff,
        max_retries,
        upload_window,
    )
    .await
}

/// Push from a seekable plaintext source without loading the full bundle into RAM.
pub async fn push_bundle_reader<R: std::io::Read + std::io::Seek>(
    client: &HttpClient,
    repo: &RepoId,
    plaintext_bundle: &mut R,
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    non_ff: bool,
) -> Result<PushResult, ClientError> {
    push_bundle_reader_with_retries_window(
        client,
        repo,
        plaintext_bundle,
        git_refs,
        head_symref,
        material,
        non_ff,
        DEFAULT_CAS_RETRIES,
        DEFAULT_UPLOAD_WINDOW,
    )
    .await
}

/// Reader-backed push with CAS retries and parallel upload window.
pub async fn push_bundle_reader_with_retries_window<R: std::io::Read + std::io::Seek>(
    client: &HttpClient,
    repo: &RepoId,
    plaintext_bundle: &mut R,
    git_refs: BTreeMap<String, String>,
    head_symref: Option<String>,
    material: &EpochMaterial,
    non_ff: bool,
    max_retries: u32,
    upload_window: usize,
) -> Result<PushResult, ClientError> {
    // Capture the tip we planned against so CAS retries can distinguish our
    // intentional updates from sibling refs landed by concurrent pushers.
    let tip0 = client.head_tip(repo).await?;
    let baseline: BTreeMap<String, String> = match &tip0 {
        Some(h) => open_refs_map(h, material)?.refs,
        None => BTreeMap::new(),
    };
    let caller_refs = git_refs;

    let mut attempt = 0u32;
    loop {
        plaintext_bundle
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|e| ClientError::Other(format!("bundle rewind: {e}")))?;
        let tip = client.head_tip(repo).await?;
        let (prev, next_seq) = match &tip {
            Some(h) => (h.hash(), h.seq + 1),
            None => (HeadHash::zero(), 1),
        };
        let remote_refs: BTreeMap<String, String> = match &tip {
            Some(h) => open_refs_map(h, material)?.refs,
            None => BTreeMap::new(),
        };
        let merged_refs =
            reconcile_refs_for_cas(&baseline, &caller_refs, &remote_refs, non_ff)?;
        let (plan, head, refs_map) = plan_push_reader(
            repo,
            plaintext_bundle,
            merged_refs,
            head_symref.clone(),
            material,
            prev,
            next_seq,
            non_ff,
        )?;
        // Pipelined/parallel chunk upload in waves of `upload_window`.
        // Chunks are content-addressed and idempotent → natural resume.
        let window = upload_window.max(1);
        for wave in plan.chunks.chunks(window) {
            let futs: Vec<_> = wave
                .iter()
                .map(|chunk| {
                    let meta = chunk.meta.clone();
                    let ct = chunk.ciphertext.clone();
                    async move { client.put_blob(repo, meta, &ct).await }
                })
                .collect();
            let results = futures::future::join_all(futs).await;
            for r in results {
                r?;
            }
        }
        match client.append_head(head.clone()).await {
            Ok(resp) => {
                tracing::debug!(
                    chunks = plan.chunks.len(),
                    rts = push_round_trips(plan.chunks.len(), window),
                    "push accepted"
                );
                return Ok(PushResult {
                    head,
                    head_hash: resp.hash,
                    refs: refs_map,
                });
            }
            Err(e) if e.is_cas_conflict() && attempt < max_retries => {
                attempt += 1;
                let wait = cas_backoff(attempt);
                tracing::warn!(
                    attempt,
                    max_retries,
                    backoff_ms = wait.as_millis() as u64,
                    "CAS conflict on head append; backing off before retrying with fresh tip"
                );
                tokio::time::sleep(wait).await;
                continue;
            }
            Err(e) if e.is_cas_conflict() => {
                return Err(ClientError::Other(format!(
                    "push lost the compare-and-swap race {max_retries} times: another \
                     device is pushing concurrently. Your commits are safe locally; \
                     run `sit pull` and push again."
                )))
            }
            Err(e) => return Err(e),
        }
    }
}

/// Encrypt arbitrary bytes under the refs exporter and upload as a single CAS blob.
///
/// Server sees only ciphertext + size (honest size leakage). Used for release
/// assets, LFS objects, and gist payloads.
pub async fn put_sealed_object(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    plaintext: &[u8],
    push_id: &str,
) -> Result<BlobId, ClientError> {
    let key = derive_cas_seal_key(&material.transport)?;
    let ct = CommittingAead::seal(&key, domain_label("cas-obj").as_bytes(), plaintext)?;
    let id = BlobId::of_ciphertext(&ct);
    let meta = BlobMeta {
        id: id.clone(),
        size: ct.len() as u64,
        chunk_index: 0,
        chunk_count: 1,
        push_id: push_id.into(),
    };
    client.put_blob(repo, meta, &ct).await?;
    Ok(id)
}

/// Download and decrypt a sealed CAS object produced by [`put_sealed_object`].
pub async fn get_sealed_object(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    id: &BlobId,
) -> Result<Vec<u8>, ClientError> {
    let ct = client.get_blob(repo, id).await?;
    let key = derive_cas_seal_key(&material.transport)?;
    Ok(CommittingAead::open(
        &key,
        domain_label("cas-obj").as_bytes(),
        &ct,
    )?)
}

/// Decrypt one chunk with known push framing.
pub fn open_chunk(
    repo: &RepoId,
    push_id: &str,
    index: u32,
    count: u32,
    dek: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let aad = format!("{}:{}:{}:{}", repo.to_hex(), push_id, index, count);
    let mut aad_bytes = domain_label("bundle-chunk").into_bytes();
    aad_bytes.push(b'|');
    aad_bytes.extend_from_slice(aad.as_bytes());
    Ok(CommittingAead::open(dek, &aad_bytes, ciphertext)?)
}

/// Unwrap DEK from a head using persisted MLS/DKR material.
pub fn unwrap_dek(head: &RefHead, material: &EpochMaterial) -> Result<[u8; 32], ClientError> {
    // A head is sealed under the epoch that produced it.
    let mut ke = material.epoch_key_at(head.mls_epoch)?;
    let mut seal_key = derive_head_seal_key(&ke, head.seq)?;
    ke.zeroize();
    let bytes = CommittingAead::open(
        &seal_key,
        domain_label("dek-wrap").as_bytes(),
        &head.dek_wrap,
    );
    seal_key.zeroize();
    let bytes = bytes?;
    let mut dek = [0u8; 32];
    if bytes.len() != 32 {
        return Err(ClientError::Other("invalid dek length".into()));
    }
    dek.copy_from_slice(&bytes);
    Ok(dek)
}

/// Open encrypted refs map from a head (raw JSON bytes).
pub fn open_refs(head: &RefHead, material: &EpochMaterial) -> Result<Vec<u8>, ClientError> {
    let mut ke = material.epoch_key_at(head.mls_epoch)?;
    let mut seal_key = derive_head_seal_key(&ke, head.seq)?;
    ke.zeroize();
    let out = CommittingAead::open(
        &seal_key,
        domain_label("refs").as_bytes(),
        &head.enc_refs,
    );
    seal_key.zeroize();
    Ok(out?)
}

/// Open and parse [`EncryptedRefsMap`] from a head.
pub fn open_refs_map(
    head: &RefHead,
    material: &EpochMaterial,
) -> Result<EncryptedRefsMap, ClientError> {
    let raw = open_refs(head, material)?;
    Ok(serde_json::from_slice(&raw)?)
}

/// Fetch tip head, decrypt refs + bundle chunks.
pub async fn fetch_tip(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
) -> Result<Option<FetchResult>, ClientError> {
    let Some(head) = client.head_tip(repo).await? else {
        return Ok(None);
    };
    fetch_head_bundle(client, repo, material, head).await.map(Some)
}

/// Download and decrypt every bundle in `(after_seq, tip]`, oldest first.
///
/// Pushes carry only the delta since the previous head, so a reader must
/// replay the chain in order: a single bundle is not self-contained. Clone
/// passes `after_seq = 0`; fetch passes the last sequence it already holds.
pub async fn fetch_bundles_since(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    after_seq: u64,
    anchor: Option<HeadHash>,
) -> Result<Vec<FetchResult>, ClientError> {
    let mut heads = client.heads_since(repo, after_seq).await?;
    heads.sort_by_key(|h| h.seq);

    // A grafted (forward-only) member holds no key material for epochs below
    // its grant: that history is represented by the graft snapshot imported at
    // join, not by these heads. Replaying them is not merely wasteful, it is
    // impossible -- epoch_key_at refuses below the grant -- and because the
    // loop below is fail-fast, a single pre-grant head aborts the entire fetch.
    // Without this filter a forward-only member can never clone at all.
    let mut anchor = anchor;
    if material.history_from > 0 {
        let before = heads.len();
        heads.retain(|h| h.mls_epoch >= material.history_from);
        if heads.len() != before {
            // The retained run no longer descends from the caller's anchor:
            // its first head's predecessor sits below the graft and is not
            // readable here, so continuity is checked within the window only.
            anchor = None;
        }
    }

    let leaf_vks = load_persisted_group(repo)
        .map(|g| g.member_signature_keys())
        .unwrap_or_default();
    verify_fetched_heads(&heads, material, anchor, &leaf_vks)?;

    // The chain check proves the run is internally consistent, not that it is
    // *complete*: a prefix of an honest chain is itself a valid chain, so a host
    // can truncate the log and a first-time cloner — which holds no prior
    // anchor — would accept the short history as the whole repository. Compare
    // against the tip the host itself advertises: to hide a truncation it must
    // now also lie on the tip endpoint, and that lie is visible to anyone who
    // has ever seen a later head.
    if let Some(tip) = client.head_tip(repo).await? {
        match heads.last() {
            Some(last) if last.seq < tip.seq => {
                return Err(ClientError::Other(format!(
                    "host served heads up to seq {} but advertises tip seq {}: \
                     the head log is truncated or withheld",
                    last.seq, tip.seq
                )));
            }
            None if tip.seq > after_seq => {
                return Err(ClientError::Other(format!(
                    "host served no heads after seq {after_seq} but advertises tip seq {}",
                    tip.seq
                )));
            }
            _ => {}
        }
    }
    let mut out = Vec::with_capacity(heads.len());
    for head in heads {
        out.push(fetch_head_bundle(client, repo, material, head).await?);
    }
    Ok(out)
}

/// Check the host's sequencing before trusting any of the bundles it served.
///
/// AEAD tells a reader that each head decrypts under an epoch key, which is a
/// statement about individual heads and says nothing about the *sequence*. A
/// malicious host can still roll a reader back to an earlier tip, drop heads
/// from the middle, replay a head into another epoch, or serve a fork — all
/// with heads that decrypt perfectly. The chain hash, the epoch MAC, and the
/// leaf ML-DSA signature are what make those detectable, so they run before
/// the bundles are replayed rather than after.
/// `anchor` is the hash of the last head the caller already trusts. `None`
/// means the caller holds no trusted predecessor, so only internal continuity
/// of the returned run is checked — it cannot detect a rollback relative to
/// state the caller did not keep.
/// `leaf_vks` are MLS roster signature keys; when non-empty, every head must
/// carry a leaf signature that verifies under at least one key.
pub fn verify_fetched_heads(
    heads: &[RefHead],
    material: &EpochMaterial,
    anchor: Option<HeadHash>,
    leaf_vks: &[Vec<u8>],
) -> Result<(), ClientError> {
    if let Some(a) = anchor {
        crate::policy::verify_head_chain(heads, a)?;
    } else if let Some(rest) = heads.split_first().map(|(_, r)| r) {
        // Skip descent for the first head; still require the rest to link.
        if let Some(first) = heads.first() {
            crate::policy::verify_head_chain(rest, first.hash())?;
        }
    }
    for head in heads {
        match material.refs_mac_at(head.mls_epoch) {
            Some(mk) => {
                if !crate::policy::verify_epoch_tag(head, &mk) {
                    return Err(ClientError::Other(format!(
                        "epoch tag mismatch at seq {} (epoch {}): head not authenticated by this group",
                        head.seq, head.mls_epoch
                    )));
                }
            }
            // No retained key: the tag cannot be *checked*, which is not the
            // same as checking it and finding it invalid.
            //
            // mk_e is an MLS exporter output for a specific epoch, so unlike
            // K_e it is not recoverable by DKR — a member holds it only for
            // epochs it witnessed or retained across a rotation. Refusing every
            // unverifiable tag would break members granted history that predates
            // their join, who legitimately cannot have those keys.
            //
            // An epoch *newer* than our own is a different matter: no honest
            // head can be sealed under an epoch this member has not reached, so
            // that is refused. For older unretained epochs the head is accepted
            // on the strength of the AEAD alone — its refs still have to open
            // under that epoch's K_e — with the epoch binding unchecked. That
            // residual gap is why `history_from` members get weaker sequencing
            // guarantees than members present since genesis.
            None => {
                if head.mls_epoch > material.epoch {
                    return Err(ClientError::Other(format!(
                        "head at seq {} claims epoch {}, beyond this member's current epoch {}",
                        head.seq, head.mls_epoch, material.epoch
                    )));
                }
            }
        }
        if !leaf_vks.is_empty() {
            let mut ok = false;
            let mut last_err = None;
            for vk in leaf_vks {
                match crate::policy::verify_pusher_sig(head, vk) {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            if !ok {
                return Err(last_err.unwrap_or_else(|| {
                    ClientError::Other(format!(
                        "leaf ML-DSA signature rejected at seq {}",
                        head.seq
                    ))
                }));
            }
        }
    }
    Ok(())
}

/// Decrypt one head's bundle payload.
pub async fn fetch_head_bundle(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    head: RefHead,
) -> Result<FetchResult, ClientError> {
    let refs = open_refs_map(&head, material)?;
    if refs.push_id.is_empty() || refs.chunk_ids.is_empty() {
        return Err(ClientError::Other(
            "tip enc_refs missing push framing; re-push with a current client".into(),
        ));
    }
    let dek = unwrap_dek(&head, material)?;
    let count = refs.chunk_ids.len() as u32;
    let mut plain = Vec::new();
    for (i, id_hex) in refs.chunk_ids.iter().enumerate() {
        let id = BlobId::from_hex(id_hex).map_err(|e| ClientError::Other(e.to_string()))?;
        let ct = client.get_blob(repo, &id).await?;
        let chunk = open_chunk(repo, &refs.push_id, i as u32, count, &dek, &ct)?;
        plain.extend_from_slice(&chunk);
    }
    Ok(FetchResult {
        head,
        refs,
        bundle: plain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_local::EpochMaterial;

    #[test]
    fn sealed_cas_obj_roundtrip_aead() {
        let material = EpochMaterial {
            epoch: 1,
            transport: [7u8; 48],
            refs_mac: [11u8; 32],
            history_from: 0,
            dkr_token: vec![],
            prior_transport: Default::default(),
            prior_refs_mac: Default::default(),
        };
        let pt = b"release-asset-bytes";
        let key = derive_cas_seal_key(&material.transport).unwrap();
        let ct = CommittingAead::seal(&key, domain_label("cas-obj").as_bytes(), pt).unwrap();
        let id = BlobId::of_ciphertext(&ct);
        assert_eq!(id.to_hex().len(), 128);
        let opened =
            CommittingAead::open(&key, domain_label("cas-obj").as_bytes(), &ct).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn encrypt_roundtrip_chunk() {
        let repo = RepoId::random();
        let mut dek = [9u8; 32];
        let chunks = bundle_chunks(&repo, "push1", b"hello world", &dek).unwrap();
        assert_eq!(chunks.len(), 1);
        let pt = open_chunk(&repo, "push1", 0, 1, &dek, &chunks[0].ciphertext).unwrap();
        assert_eq!(pt, b"hello world");
        dek.zeroize();
    }

    #[test]
    fn plan_push_embeds_framing_in_refs() {
        let repo = RepoId::random();
        let material = EpochMaterial {
            epoch: 0,
            transport: [3u8; 48],
            refs_mac: [5u8; 32],
            history_from: 0,
            dkr_token: vec![],
            prior_transport: Default::default(),
            prior_refs_mac: Default::default(),
        };
        let mut git_refs = BTreeMap::new();
        git_refs.insert("refs/heads/main".into(), "abc".into());
        let (plan, head, refs_map) = plan_push_unsigned(
            &repo,
            b"bundle-bytes",
            git_refs,
            Some("ref: refs/heads/main".into()),
            &material,
            HeadHash::zero(),
            1,
            false,
        )
        .unwrap();
        assert_eq!(head.seq, 1);
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(refs_map.chunk_ids.len(), 1);
        assert_eq!(refs_map.push_id, plan.push_id);
        let dek = unwrap_dek(&head, &material).unwrap();
        let pt = open_chunk(
            &repo,
            &plan.push_id,
            0,
            1,
            &dek,
            &plan.chunks[0].ciphertext,
        )
        .unwrap();
        assert_eq!(pt, b"bundle-bytes");
        let opened = open_refs_map(&head, &material).unwrap();
        assert_eq!(
            opened.refs.get("refs/heads/main").map(String::as_str),
            Some("abc")
        );
        assert_eq!(opened.chunk_ids, refs_map.chunk_ids);
        assert_eq!(opened.head.as_deref(), Some("ref: refs/heads/main"));
    }

    #[test]
    fn plan_push_empty_bundle_still_one_chunk() {
        let repo = RepoId::random();
        let material = EpochMaterial {
            epoch: 0,
            transport: [7u8; 48],
            refs_mac: [9u8; 32],
            history_from: 0,
            dkr_token: vec![],
            prior_transport: Default::default(),
            prior_refs_mac: Default::default(),
        };
        let (plan, _head, refs) = plan_push_unsigned(
            &repo,
            b"",
            BTreeMap::new(),
            None,
            &material,
            HeadHash::zero(),
            1,
            false,
        )
        .unwrap();
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(refs.chunk_ids.len(), 1);
    }

    /// Synthetic seekable source of `len` zero bytes without allocating the body.
    struct HugeZeros {
        len: u64,
        pos: u64,
    }

    impl std::io::Read for HugeZeros {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.len {
                return Ok(0);
            }
            let n = ((self.len - self.pos) as usize).min(buf.len());
            buf[..n].fill(0);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl std::io::Seek for HugeZeros {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            let next = match pos {
                std::io::SeekFrom::Start(p) => p as i128,
                std::io::SeekFrom::End(p) => self.len as i128 + p as i128,
                std::io::SeekFrom::Current(p) => self.pos as i128 + p as i128,
            };
            if next < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "seek before start",
                ));
            }
            self.pos = next as u64;
            Ok(self.pos)
        }
    }

    #[test]
    fn streaming_chunker_bounds_plaintext_to_one_chunk() {
        let repo = RepoId::random();
        let mut dek = [9u8; 32];
        // 3 full chunks + 1 partial without allocating a contiguous plaintext.
        let len = (BUNDLE_CHUNK_SIZE as u64) * 3 + 123;
        let mut src = HugeZeros { len, pos: 0 };
        let chunks = bundle_chunks_seek(&repo, "push-stream", &mut src, &dek).unwrap();
        assert_eq!(chunks.len(), 4);
        assert!(chunks.iter().all(|c| c.ciphertext.len() > 12));
        dek.zeroize();
    }

    /// Optional stress: 1 GiB synthetic bundle; peak RSS must stay well below 1 GiB
    /// of *plaintext* (ciphertext list still ~O(size)). Enable with
    /// `SAFEHUB_RSS_1GIB=1`.
    #[test]
    fn streaming_1gib_rss_bounded() {
        if std::env::var("SAFEHUB_RSS_1GIB").ok().as_deref() != Some("1") {
            return;
        }
        let repo = RepoId::random();
        let mut dek = [3u8; 32];
        let gib = 1u64 << 30;
        let mut src = HugeZeros { len: gib, pos: 0 };
        let before = peak_rss_bytes();
        let chunks = bundle_chunks_seek(&repo, "push-1gib", &mut src, &dek).unwrap();
        let after = peak_rss_bytes();
        assert_eq!(chunks.len(), (gib as usize).div_ceil(BUNDLE_CHUNK_SIZE) as usize);
        // Allow ciphertext retention + allocator slack; must not look like a
        // full extra plaintext copy of the GiB beside the sealed list.
        let delta = after.saturating_sub(before);
        assert!(
            delta < gib + (512 << 20),
            "RSS grew by {delta} bytes (before={before}, after={after}); expected < 1.5 GiB"
        );
        dek.zeroize();
    }

    #[cfg(unix)]
    fn peak_rss_bytes() -> u64 {
        // ru_maxrss is kilobytes on Linux and bytes on macOS.
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc != 0 {
            return 0;
        }
        let usage = unsafe { usage.assume_init() };
        let rss = usage.ru_maxrss as u64;
        if cfg!(target_os = "macos") {
            rss
        } else {
            rss.saturating_mul(1024)
        }
    }

    #[cfg(not(unix))]
    fn peak_rss_bytes() -> u64 {
        0
    }

    #[test]
    fn reconcile_preserves_sibling_refs_on_cas_retry() {
        let mut baseline = BTreeMap::new();
        baseline.insert("refs/heads/main".into(), "X".into());
        let mut caller = baseline.clone();
        caller.insert("refs/heads/branch-2".into(), "B".into());
        let mut remote = baseline.clone();
        remote.insert("refs/heads/branch-1".into(), "A".into());
        let merged = reconcile_refs_for_cas(&baseline, &caller, &remote, false).unwrap();
        assert_eq!(merged.get("refs/heads/main").map(String::as_str), Some("X"));
        assert_eq!(merged.get("refs/heads/branch-1").map(String::as_str), Some("A"));
        assert_eq!(merged.get("refs/heads/branch-2").map(String::as_str), Some("B"));
    }

    #[test]
    fn reconcile_rejects_same_branch_race_even_on_first_attempt() {
        let mut baseline = BTreeMap::new();
        baseline.insert("refs/heads/main".into(), "X".into());
        let mut caller = BTreeMap::new();
        caller.insert("refs/heads/main".into(), "B".into());
        let mut remote = BTreeMap::new();
        remote.insert("refs/heads/main".into(), "A".into());
        let err = reconcile_refs_for_cas(&baseline, &caller, &remote, false).unwrap_err();
        assert!(
            err.to_string().contains("remote advanced"),
            "expected remote-advanced error, got {err}"
        );
    }

    #[test]
    fn reconcile_allows_planned_ff_when_tip_unchanged() {
        let mut baseline = BTreeMap::new();
        baseline.insert("refs/heads/main".into(), "X".into());
        let mut caller = BTreeMap::new();
        caller.insert("refs/heads/main".into(), "Y".into());
        let remote = baseline.clone();
        let merged = reconcile_refs_for_cas(&baseline, &caller, &remote, false).unwrap();
        assert_eq!(merged.get("refs/heads/main").map(String::as_str), Some("Y"));
    }

    #[test]
    fn reconcile_ignores_spurious_sibling_deletes_without_force() {
        // Tip advanced with branch-1 between plan and push_bundle entry, so
        // baseline contains a sibling the caller's map never named.
        let mut baseline = BTreeMap::new();
        baseline.insert("refs/heads/main".into(), "X".into());
        baseline.insert("refs/heads/branch-1".into(), "A".into());
        let mut caller = BTreeMap::new();
        caller.insert("refs/heads/main".into(), "X".into());
        caller.insert("refs/heads/branch-2".into(), "B".into());
        let remote = baseline.clone();
        let merged = reconcile_refs_for_cas(&baseline, &caller, &remote, false).unwrap();
        assert_eq!(merged.get("refs/heads/branch-1").map(String::as_str), Some("A"));
        assert_eq!(merged.get("refs/heads/branch-2").map(String::as_str), Some("B"));
    }

    #[test]
    fn reconcile_force_applies_intentional_deletes() {
        let mut baseline = BTreeMap::new();
        baseline.insert("refs/heads/main".into(), "X".into());
        baseline.insert("refs/heads/doomed".into(), "D".into());
        let mut caller = BTreeMap::new();
        caller.insert("refs/heads/main".into(), "X".into());
        let remote = baseline.clone();
        let merged = reconcile_refs_for_cas(&baseline, &caller, &remote, true).unwrap();
        assert!(!merged.contains_key("refs/heads/doomed"));
    }
}
