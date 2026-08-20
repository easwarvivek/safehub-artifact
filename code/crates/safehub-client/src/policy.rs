//! Fast-forward classification and force-push authorization checks.
//!
//! Verifiers recompute the FF/non-FF relation from decrypted refs and the
//! local Git object DAG. The sender-declared `non_ff` bit is advisory only;
//! a lie (`non_ff=0` on a non-fast-forward update) is rejected.
//!
//! Leaf and admin co-signatures are ML-DSA-87 (FIPS 204), matching the paper.

use crate::error::ClientError;
use crate::pushfetch::EncryptedRefsMap;
use safehub_crypto::mldsa::{
    admin_cosig_message, refhead_leaf_message, verify as mldsa_verify, MlDsa87KeyPair,
    ADMIN_COSIG_POLICY_VERSION,
};
use safehub_types::{HeadHash, RefHead, RepoId};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use safehub_types::domain_label;

/// Whether updating `old_oid` → `new_oid` is a fast-forward in `repo_dir`.
///
/// Returns `true` if `old` is an ancestor of `new` (or `old` is absent/zero).
pub fn is_fast_forward(repo_dir: &Path, old_oid: &str, new_oid: &str) -> Result<bool, ClientError> {
    if old_oid.is_empty() || old_oid.chars().all(|c| c == '0') {
        return Ok(true);
    }
    if old_oid == new_oid {
        return Ok(true);
    }
    // A remote oid the local DAG has never seen is not an ancestor of ours;
    // git reports that on stderr, which is expected here and must not surface
    // as a spurious error line to the user.
    let out = Command::new("git")
        .args(["-C"])
        .arg(repo_dir)
        .args(["merge-base", "--is-ancestor", old_oid, new_oid])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| ClientError::Other(format!("git merge-base: {e}")))?;
    Ok(out.success())
}

/// Whether `oid` names an object the local DAG actually holds.
///
/// A grafted member's history stops at the graft boundary, so an `old_oid`
/// below it is absent rather than merely unreachable — `merge-base
/// --is-ancestor` then exits non-zero for a *missing* object, which is not the
/// same answer as "not an ancestor".
fn has_object(repo_dir: &Path, oid: &str) -> bool {
    if oid.is_empty() || oid.chars().all(|c| c == '0') {
        return true;
    }
    Command::new("git")
        .args(["-C"])
        .arg(repo_dir)
        .args(["cat-file", "-e", &format!("{oid}^{{object}}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The ancestry verdict a verifier can actually justify from its local DAG.
///
/// `Unverifiable`: a forward-only member whose DAG starts at a graft cannot
/// recompute the merge-base when it lies below the graft, so it can neither
/// confirm nor refute the pusher's `non_ff` bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfStatus {
    /// Every changed ref advances along the local DAG.
    FastForward,
    /// At least one changed (or deleted) ref is provably not a fast-forward.
    NonFastForward,
    /// Ancestry is undecidable here: the merge-base is below the graft.
    Unverifiable,
}

impl FfStatus {
    /// Whether a verifier must treat this as a non-fast-forward policy event.
    ///
    /// `Unverifiable` counts: accepting it would be a silent accept of an
    /// unproven fast-forward, which is exactly what must not happen.
    pub fn is_non_ff(self) -> bool {
        !matches!(self, FfStatus::FastForward)
    }
}

/// What a verifier knows about the completeness of its own object DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AncestryScope {
    /// Inclusive epoch from which history was granted (0 = full history).
    pub history_from: u64,
    /// True when the local DAG was seeded from a grafted snapshot.
    pub grafted: bool,
}

impl AncestryScope {
    /// A member present since genesis: ancestry is complete.
    pub fn full() -> Self {
        Self {
            history_from: 0,
            grafted: false,
        }
    }

    /// A forward-only member grafted at `history_from`.
    pub fn grafted_from(history_from: u64) -> Self {
        Self {
            history_from,
            grafted: true,
        }
    }

    /// Whether this verifier can recompute ancestry back to the repository root.
    pub fn is_complete(self) -> bool {
        !self.grafted && self.history_from == 0
    }
}

/// Classify a tip update against the local DAG, distinguishing "not a
/// fast-forward" from "cannot tell".
///
/// If `repo_dir` is `None` there is no DAG at all, so nothing is decidable.
pub fn classify_ff(
    repo_dir: Option<&Path>,
    old_refs: &BTreeMap<String, String>,
    new_refs: &BTreeMap<String, String>,
) -> Result<FfStatus, ClientError> {
    // Deletions (present in old, absent in new) are non-FF policy events and
    // need no ancestry to establish.
    for name in old_refs.keys() {
        if !new_refs.contains_key(name) {
            return Ok(FfStatus::NonFastForward);
        }
    }
    let mut unverifiable = false;
    for (name, new_oid) in new_refs {
        let Some(old_oid) = old_refs.get(name) else {
            continue;
        };
        if old_oid == new_oid {
            continue;
        }
        // A tag that moves is a policy event whatever the ancestry says. Git
        // refuses to update one without --force precisely because a consumer
        // who resolved it once expects it to stay put; treating a descendant
        // retarget as fast-forward would let a tag be repointed silently.
        if name.starts_with("refs/tags/") {
            return Ok(FfStatus::NonFastForward);
        }
        let Some(dir) = repo_dir else {
            unverifiable = true;
            continue;
        };
        if !has_object(dir, old_oid) || !has_object(dir, new_oid) {
            unverifiable = true;
            continue;
        }
        if !is_fast_forward(dir, old_oid, new_oid)? {
            return Ok(FfStatus::NonFastForward);
        }
    }
    if unverifiable {
        return Ok(FfStatus::Unverifiable);
    }
    Ok(FfStatus::FastForward)
}

/// Classify whether the tip update is non-fast-forward given old/new ref maps.
///
/// Undecidable ancestry counts as non-fast-forward, so a `non_ff=0` claim a
/// grafted verifier cannot check never passes as a fast-forward.
pub fn classify_non_ff(
    repo_dir: Option<&Path>,
    old_refs: &BTreeMap<String, String>,
    new_refs: &BTreeMap<String, String>,
) -> Result<bool, ClientError> {
    Ok(classify_ff(repo_dir, old_refs, new_refs)?.is_non_ff())
}

/// Domain-separated admin co-signature over a non-FF update (ML-DSA-87).
#[allow(clippy::too_many_arguments)]
pub fn admin_cosig_sign(
    admin: &MlDsa87KeyPair,
    repo: &RepoId,
    epoch: u64,
    op: &str,
    seq: u64,
    prev_head: &HeadHash,
    new_refs_digest: &[u8; 64],
    roster_digest: &[u8; 64],
) -> Result<Vec<u8>, ClientError> {
    let msg = admin_cosig_message(
        &repo.0, epoch, op, seq, &prev_head.0, new_refs_digest, roster_digest,
        ADMIN_COSIG_POLICY_VERSION,
    );
    admin
        .sign(&msg)
        .map_err(|e| ClientError::Other(e.to_string()))
}

/// Verify admin co-signature (ML-DSA-87).
#[allow(clippy::too_many_arguments)]
pub fn admin_cosig_verify(
    admin_vk: &[u8],
    repo: &RepoId,
    epoch: u64,
    op: &str,
    seq: u64,
    prev_head: &HeadHash,
    new_refs_digest: &[u8; 64],
    roster_digest: &[u8; 64],
    cosig: &[u8],
) -> Result<(), ClientError> {
    let msg = admin_cosig_message(
        &repo.0, epoch, op, seq, &prev_head.0, new_refs_digest, roster_digest,
        ADMIN_COSIG_POLICY_VERSION,
    );
    mldsa_verify(admin_vk, &msg, cosig).map_err(|e| ClientError::Other(e.to_string()))
}

/// Digest of the MLS group-context roster at the authorizing epoch.
///
/// Verifiers already resolve leaf keys from this roster, so binding its digest
/// costs nothing they do not already hold.
pub fn roster_digest(leaf_vks: &[Vec<u8>]) -> [u8; 64] {
    let mut sorted: Vec<&Vec<u8>> = leaf_vks.iter().collect();
    sorted.sort();
    let mut h = Sha512::new();
    h.update(domain_label("roster-digest").as_bytes());
    h.update((sorted.len() as u32).to_le_bytes());
    for vk in sorted {
        h.update((vk.len() as u32).to_le_bytes());
        h.update(vk);
    }
    let out = h.finalize();
    let mut a = [0u8; 64];
    a.copy_from_slice(&out);
    a
}

/// Digest of canonical refs JSON for cosig binding.
pub fn refs_digest(refs: &EncryptedRefsMap) -> [u8; 64] {
    let bytes = serde_json::to_vec(refs).unwrap_or_default();
    let mut h = Sha512::new();
    h.update(domain_label("refs-digest").as_bytes());
    h.update(&bytes);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Leaf ML-DSA-87 transcript for a RefHead (signatures excluded from the message).
pub fn leaf_sign_message(head: &RefHead) -> Vec<u8> {
    refhead_leaf_message(
        &head.repo_id.0,
        head.seq,
        &head.enc_refs,
        &head.bundle_root.0,
        &head.dek_wrap,
        &head.prev_head_hash.0,
        head.mls_epoch,
        &head.epoch_tag,
        head.non_ff,
    )
}

/// Epoch authenticator: `MAC(mk_e, "epoch-tag" ‖ epoch ‖ bundle_root ‖ seq)`.
///
/// Binds a head to the epoch that produced it, so a head cannot be replayed
/// into a different epoch or re-sequenced within one.
pub fn epoch_tag_bytes(refs_mac: &[u8], epoch: u64, root: &safehub_types::BlobId, seq: u64) -> Vec<u8> {
    type HmacSha512 = hmac::Hmac<sha2::Sha512>;
    use hmac::Mac;
    let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(refs_mac)
        .expect("hmac accepts any key length");
    mac.update(domain_label("epoch-tag").as_bytes());
    mac.update(&epoch.to_le_bytes());
    mac.update(&root.0);
    mac.update(&seq.to_le_bytes());
    mac.finalize().into_bytes()[..32].to_vec()
}

/// Epoch witness: `MAC(mk_e, "epoch-witness" ‖ repo ‖ epoch)`.
///
/// A malicious MLS delivery service can partition Commits so two subgroups sit
/// at the same `epoch` number with different ratchet-tree transcripts. MLS
/// exporter outputs depend on the confirmed transcript, so `mk_e` differs
/// between the subgroups even though the epoch *number* agrees. Publishing this
/// value in a checkpoint turns that otherwise-silent divergence into a Compare
/// failure: the head chains can look identical and the witnesses still differ.
pub fn epoch_witness_bytes(refs_mac: &[u8], repo: &RepoId, epoch: u64) -> Vec<u8> {
    type HmacSha512 = hmac::Hmac<sha2::Sha512>;
    use hmac::Mac;
    let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(refs_mac)
        .expect("hmac accepts any key length");
    mac.update(domain_label("epoch-witness").as_bytes());
    mac.update(&repo.0);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes()[..32].to_vec()
}

/// Recompute a head's epoch tag and compare in constant time.
pub fn verify_epoch_tag(head: &RefHead, refs_mac: &[u8]) -> bool {
    let want = epoch_tag_bytes(refs_mac, head.mls_epoch, &head.bundle_root, head.seq);
    if want.len() != head.epoch_tag.len() {
        return false;
    }
    want.iter()
        .zip(head.epoch_tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Verify that `heads` (ascending by seq) forms an unbroken hash chain rooted
/// at `anchor`.
///
/// This is what makes the host's sequencing checkable. Without it a malicious
/// or buggy host can roll a reader back to an earlier tip, drop heads from the
/// middle, or serve a forked branch, and the reader cannot tell: AEAD only says
/// each head decrypts, not that the sequence is the one the writers produced.
///
/// `anchor` is the hash of the last head the reader already trusts, or
/// `HeadHash::zero()` when starting from genesis.
pub fn verify_head_chain(heads: &[RefHead], anchor: HeadHash) -> Result<(), ClientError> {
    let mut expect_prev = anchor;
    let mut expect_seq: Option<u64> = None;
    for head in heads {
        if head.prev_head_hash != expect_prev {
            return Err(ClientError::Other(format!(
                "head chain broken at seq {}: prev_head_hash does not descend from the previous head",
                head.seq
            )));
        }
        if let Some(prev_seq) = expect_seq {
            if head.seq != prev_seq + 1 {
                return Err(ClientError::Other(format!(
                    "head chain gap: seq {} follows seq {prev_seq}",
                    head.seq
                )));
            }
        }
        expect_seq = Some(head.seq);
        expect_prev = head.hash();
    }
    Ok(())
}

/// Verify the pusher's leaf ML-DSA-87 signature on a RefHead.
pub fn verify_pusher_sig(head: &RefHead, leaf_vk: &[u8]) -> Result<(), ClientError> {
    if head.pusher_sig.is_empty() {
        return Err(ClientError::Other(
            "RefHead missing leaf ML-DSA signature".into(),
        ));
    }
    let msg = leaf_sign_message(head);
    mldsa_verify(leaf_vk, &msg, &head.pusher_sig)
        .map_err(|e| ClientError::Other(format!("leaf ML-DSA verify: {e}")))
}

/// Verify that a head's force-push policy matches recomputed FF status.
pub fn verify_force_push_policy(
    head: &RefHead,
    claimed_non_ff: bool,
    recomputed_non_ff: bool,
    admin_vk: Option<&[u8]>,
    new_refs: &EncryptedRefsMap,
    roster: &[Vec<u8>],
) -> Result<(), ClientError> {
    let status = if recomputed_non_ff {
        FfStatus::NonFastForward
    } else {
        FfStatus::FastForward
    };
    verify_force_push_policy_scoped(
        head,
        claimed_non_ff,
        status,
        AncestryScope::full(),
        admin_vk,
        new_refs,
        roster,
    )
}

/// Force-push policy for a verifier whose ancestry may be incomplete.
///
/// A grafted, forward-only member cannot recompute the merge-base when it lies
/// below its graft. That view must not be weaker than a full-history one, so an
/// update it cannot check is **must-reject** unless the update carries an admin
/// co-signature: the admin attestation is the graft-aware fast-forward oracle,
/// and it is checkable from any window because it binds
/// `(repo, epoch, op, seq, prev_head, refs_digest, roster_digest, policy)` —
/// values a verifier of any window already holds.
pub fn verify_force_push_policy_scoped(
    head: &RefHead,
    claimed_non_ff: bool,
    status: FfStatus,
    scope: AncestryScope,
    admin_vk: Option<&[u8]>,
    new_refs: &EncryptedRefsMap,
    roster: &[Vec<u8>],
) -> Result<(), ClientError> {
    match status {
        FfStatus::FastForward => return Ok(()),
        FfStatus::NonFastForward if !claimed_non_ff => {
            return Err(ClientError::Other(
                "non-fast-forward update falsely labeled as fast-forward".into(),
            ));
        }
        FfStatus::NonFastForward => {}
        FfStatus::Unverifiable => {}
    }
    let Some(cosig) = head.admin_cosig.as_ref() else {
        return Err(ClientError::Other(match status {
            FfStatus::Unverifiable if scope.grafted => format!(
                "fast-forward at seq {} is unverifiable from a grafted view \
                 (history granted from epoch {}): the merge-base is below the graft, \
                 so this update must-reject without an admin co-signature",
                head.seq, scope.history_from
            ),
            FfStatus::Unverifiable => format!(
                "fast-forward at seq {} is unverifiable without a local object DAG: \
                 must-reject without an admin co-signature",
                head.seq
            ),
            _ => "non-fast-forward head missing admin co-signature".into(),
        }));
    };
    let Some(vk) = admin_vk else {
        return Err(ClientError::Other(
            "admin verifying key required to verify non-FF co-signature".into(),
        ));
    };
    admin_cosig_verify(
        vk,
        &head.repo_id,
        head.mls_epoch,
        "push",
        head.seq,
        &head.prev_head_hash,
        &refs_digest(new_refs),
        &roster_digest(roster),
        cosig,
    )
}

/// Magic prefix for m-of-n admin co-signature bundles (`SHQ1`).
pub const ADMIN_QUORUM_MAGIC: &[u8; 4] = b"SHQ1";

/// Encode an m-of-n admin co-signature bundle into `RefHead.admin_cosig` bytes.
pub fn encode_admin_quorum(m: u8, sigs: &[Vec<u8>]) -> Result<Vec<u8>, ClientError> {
    if m == 0 || sigs.is_empty() || (m as usize) > sigs.len() || sigs.len() > 255 {
        return Err(ClientError::Other("invalid admin quorum".into()));
    }
    let mut out = Vec::with_capacity(8 + sigs.iter().map(|s| s.len() + 4).sum::<usize>());
    out.extend_from_slice(ADMIN_QUORUM_MAGIC);
    out.push(m);
    out.push(sigs.len() as u8);
    for s in sigs {
        let len = u32::try_from(s.len()).map_err(|_| ClientError::Other("sig too long".into()))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Decode a quorum bundle; `None` means legacy single-signature bytes.
pub fn decode_admin_quorum(bytes: &[u8]) -> Option<(u8, Vec<Vec<u8>>)> {
    if bytes.len() < 6 || &bytes[..4] != ADMIN_QUORUM_MAGIC {
        return None;
    }
    let m = bytes[4];
    let n = bytes[5] as usize;
    let mut rest = &bytes[6..];
    let mut sigs = Vec::with_capacity(n);
    for _ in 0..n {
        if rest.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes(rest[..4].try_into().ok()?) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return None;
        }
        sigs.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some((m, sigs))
}

/// Verify m-of-n admin co-signatures (or a legacy single cosig against `vks[0]`).
pub fn admin_quorum_verify(
    vks: &[&[u8]],
    repo: &RepoId,
    epoch: u64,
    op: &str,
    seq: u64,
    prev_head: &HeadHash,
    new_refs_digest: &[u8; 64],
    roster_digest_v: &[u8; 64],
    cosig_bytes: &[u8],
) -> Result<(), ClientError> {
    let msg = admin_cosig_message(
        &repo.0, epoch, op, seq, &prev_head.0, new_refs_digest, roster_digest_v,
        ADMIN_COSIG_POLICY_VERSION,
    );
    if let Some((m, sigs)) = decode_admin_quorum(cosig_bytes) {
        if vks.len() < sigs.len() {
            return Err(ClientError::Other(
                "fewer admin verifying keys than quorum signatures".into(),
            ));
        }
        let mut ok = 0u8;
        for (i, sig) in sigs.iter().enumerate() {
            if mldsa_verify(vks[i], &msg, sig).is_ok() {
                ok = ok.saturating_add(1);
            }
        }
        if ok < m {
            return Err(ClientError::Other(format!(
                "admin quorum failed: {ok}/{m} valid"
            )));
        }
        return Ok(());
    }
    // Legacy single signature: verify under the first VK.
    let vk = vks
        .first()
        .copied()
        .ok_or_else(|| ClientError::Other("admin verifying key required".into()))?;
    mldsa_verify(vk, &msg, cosig_bytes).map_err(|e| ClientError::Other(e.to_string()))
}

/// Sign with multiple admin keys and pack an m-of-n quorum cosig.
pub fn admin_quorum_sign(
    admins: &[&MlDsa87KeyPair],
    m: u8,
    repo: &RepoId,
    epoch: u64,
    op: &str,
    seq: u64,
    prev_head: &HeadHash,
    new_refs_digest: &[u8; 64],
    roster_digest_v: &[u8; 64],
) -> Result<Vec<u8>, ClientError> {
    let mut sigs = Vec::with_capacity(admins.len());
    for a in admins {
        sigs.push(admin_cosig_sign(
            a, repo, epoch, op, seq, prev_head, new_refs_digest, roster_digest_v,
        )?);
    }
    encode_admin_quorum(m, &sigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safehub_types::{BlobId, HeadHash, RefHead, RepoId};

    /// A fixed roster for cases that are not about roster binding. Cases that
    /// *are* about it build a second, different roster and check the
    /// co-signature does not carry across.
    fn test_roster() -> Vec<Vec<u8>> {
        vec![vec![1u8; 32], vec![2u8; 32]]
    }

    #[test]
    fn false_ff_label_rejected() {
        let roster = test_roster();
        let head = RefHead {
            repo_id: RepoId([1u8; 32]),
            seq: 2,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: HeadHash::zero(),
            mls_epoch: 1,
            epoch_tag: vec![0; 32],
            non_ff: false,
            pusher_sig: vec![],
            admin_cosig: None,
        };
        let refs = EncryptedRefsMap::default();
        let err = verify_force_push_policy(&head, false, true, None, &refs, &roster).unwrap_err();
        assert!(err.to_string().contains("falsely labeled"));
    }

    #[test]
    fn valid_mldsa_cosig_accepted() {
        let roster = test_roster();
        let repo = RepoId([2u8; 32]);
        let prev = HeadHash::zero();
        let refs = EncryptedRefsMap::default();
        let dig = refs_digest(&refs);
        let admin = MlDsa87KeyPair::generate().unwrap();
        let cosig =
            admin_cosig_sign(&admin, &repo, 3, "push", 2, &prev, &dig, &roster_digest(&roster))
                .unwrap();
        let head = RefHead {
            repo_id: repo,
            seq: 2,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: prev,
            mls_epoch: 3,
            epoch_tag: vec![0; 32],
            non_ff: true,
            pusher_sig: vec![],
            admin_cosig: Some(cosig),
        };
        verify_force_push_policy(&head, true, true, Some(admin.public_key()), &refs, &roster).unwrap();
    }

    /// C3.2 — a co-signature must not carry across a roster change.
    ///
    /// Same epoch, same predecessor, same refs: only the membership differs.
    /// Before the roster digest was bound, this replay verified.
    #[test]
    fn cosig_does_not_carry_across_a_roster_change() {
        let repo = RepoId([2u8; 32]);
        let prev = HeadHash::zero();
        let refs = EncryptedRefsMap::default();
        let dig = refs_digest(&refs);
        let admin = MlDsa87KeyPair::generate().unwrap();
        let roster_a = test_roster();
        let roster_b = vec![vec![1u8; 32], vec![9u8; 32]];
        assert_ne!(roster_digest(&roster_a), roster_digest(&roster_b));
        let cosig =
            admin_cosig_sign(&admin, &repo, 3, "push", 2, &prev, &dig, &roster_digest(&roster_a))
                .unwrap();
        let head = RefHead {
            repo_id: repo,
            seq: 2,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: prev,
            mls_epoch: 3,
            epoch_tag: vec![0; 32],
            non_ff: true,
            pusher_sig: vec![],
            admin_cosig: Some(cosig),
        };
        verify_force_push_policy(&head, true, true, Some(admin.public_key()), &refs, &roster_a)
            .expect("verifies under the roster it was issued for");
        verify_force_push_policy(&head, true, true, Some(admin.public_key()), &refs, &roster_b)
            .expect_err("must not verify under a different roster");
    }

    /// C3.3 — a co-signature must not carry to a different sequence.
    #[test]
    fn cosig_does_not_carry_to_another_sequence() {
        let repo = RepoId([2u8; 32]);
        let prev = HeadHash::zero();
        let refs = EncryptedRefsMap::default();
        let dig = refs_digest(&refs);
        let admin = MlDsa87KeyPair::generate().unwrap();
        let roster = test_roster();
        // Authorized for seq 2, presented on a head at seq 3.
        let cosig =
            admin_cosig_sign(&admin, &repo, 3, "push", 2, &prev, &dig, &roster_digest(&roster))
                .unwrap();
        let head = RefHead {
            repo_id: repo,
            seq: 3,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: prev,
            mls_epoch: 3,
            epoch_tag: vec![0; 32],
            non_ff: true,
            pusher_sig: vec![],
            admin_cosig: Some(cosig),
        };
        verify_force_push_policy(&head, true, true, Some(admin.public_key()), &refs, &roster)
            .expect_err("a co-signature for seq 2 must not authorize seq 3");
    }

    /// The roster digest must not depend on the order keys are listed in.
    #[test]
    fn roster_digest_is_order_independent() {
        let a = vec![vec![1u8; 32], vec![2u8; 32]];
        let b = vec![vec![2u8; 32], vec![1u8; 32]];
        assert_eq!(roster_digest(&a), roster_digest(&b));
        let c = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        assert_ne!(roster_digest(&a), roster_digest(&c));
    }

    // ---- C5: the ref-transition table -------------------------------------
    //
    // classify_ff must be total over transitions. Each row states a transition
    // and the verdict a verifier must reach without consulting anyone.

    fn refs(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn ref_transition_table_without_a_dag() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        // create: absent -> present is a fast-forward
        assert_eq!(
            classify_ff(None, &refs(&[]), &refs(&[("refs/heads/main", a)])).unwrap(),
            FfStatus::FastForward
        );
        // unchanged
        assert_eq!(
            classify_ff(
                None,
                &refs(&[("refs/heads/main", a)]),
                &refs(&[("refs/heads/main", a)])
            )
            .unwrap(),
            FfStatus::FastForward
        );
        // delete: present -> absent is never a fast-forward, and needs no DAG
        assert_eq!(
            classify_ff(None, &refs(&[("refs/heads/main", a)]), &refs(&[])).unwrap(),
            FfStatus::NonFastForward
        );
        // a tag that moves is a policy event regardless of ancestry
        assert_eq!(
            classify_ff(
                None,
                &refs(&[("refs/tags/v1", a)]),
                &refs(&[("refs/tags/v1", b)])
            )
            .unwrap(),
            FfStatus::NonFastForward
        );
        // branch change with no DAG to decide it
        assert_eq!(
            classify_ff(
                None,
                &refs(&[("refs/heads/main", a)]),
                &refs(&[("refs/heads/main", b)])
            )
            .unwrap(),
            FfStatus::Unverifiable
        );
        // replacing a branch with a tag of the same short name is a delete plus
        // a create, so the delete decides it
        assert_eq!(
            classify_ff(
                None,
                &refs(&[("refs/heads/v1", a)]),
                &refs(&[("refs/tags/v1", a)])
            )
            .unwrap(),
            FfStatus::NonFastForward
        );
    }

    /// C5.9 — a deletion declared as fast-forward must be refused.
    #[test]
    fn deletion_declared_as_fast_forward_is_rejected() {
        let roster = test_roster();
        let refs_map = EncryptedRefsMap::default();
        let head = RefHead {
            repo_id: RepoId([4u8; 32]),
            seq: 2,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: HeadHash::zero(),
            mls_epoch: 1,
            epoch_tag: vec![0; 32],
            non_ff: false,
            pusher_sig: vec![],
            admin_cosig: None,
        };
        let status = classify_ff(
            None,
            &refs(&[("refs/heads/main", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]),
            &refs(&[]),
        )
        .unwrap();
        assert_eq!(status, FfStatus::NonFastForward);
        verify_force_push_policy_scoped(
            &head,
            false,
            status,
            AncestryScope::full(),
            None,
            &refs_map,
            &roster,
        )
        .expect_err("a deletion labelled fast-forward must be refused");
    }

    #[test]
    fn missing_cosig_rejected() {
        let roster = test_roster();
        let head = RefHead {
            repo_id: RepoId([3u8; 32]),
            seq: 2,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: HeadHash::zero(),
            mls_epoch: 1,
            epoch_tag: vec![0; 32],
            non_ff: true,
            pusher_sig: vec![],
            admin_cosig: None,
        };
        let refs = EncryptedRefsMap::default();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let err =
            verify_force_push_policy(&head, true, true, Some(admin.public_key()), &refs, &roster).unwrap_err();
        assert!(err.to_string().contains("missing admin"));
    }

    fn head_with(non_ff: bool, cosig: Option<Vec<u8>>) -> RefHead {
        RefHead {
            repo_id: RepoId([5u8; 32]),
            seq: 9,
            enc_refs: vec![],
            bundle_root: BlobId([0u8; 64]),
            dek_wrap: vec![],
            prev_head_hash: HeadHash::zero(),
            mls_epoch: 4,
            epoch_tag: vec![0; 32],
            non_ff,
            pusher_sig: vec![],
            admin_cosig: cosig,
        }
    }

    /// A forward-only member whose merge-base is below the graft cannot decide
    /// ancestry, and must not accept the pusher's word for it.
    #[test]
    fn grafted_member_must_reject_unverifiable_fast_forward() {
        let roster = test_roster();
        let head = head_with(false, None);
        let refs = EncryptedRefsMap::default();
        let err = verify_force_push_policy_scoped(
            &head,
            false,
            FfStatus::Unverifiable,
            AncestryScope::grafted_from(6),
            None,
            &refs,
            &roster,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("must-reject"),
            "grafted view silently accepted an unverifiable fast-forward: {err}"
        );
    }

    /// The admin co-signature is the graft-aware FF oracle: it is checkable from
    /// any window, so it is the one way an unverifiable update may be accepted.
    #[test]
    fn admin_cosig_rescues_unverifiable_fast_forward_under_graft() {
        let roster = test_roster();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let refs = EncryptedRefsMap::default();
        let mut head = head_with(false, None);
        head.admin_cosig = Some(
            admin_cosig_sign(
                &admin,
                &head.repo_id,
                head.mls_epoch,
                "push",
                head.seq,
                &head.prev_head_hash,
                &refs_digest(&refs),
                &roster_digest(&roster),
            )
            .unwrap(),
        );
        verify_force_push_policy_scoped(
            &head,
            false,
            FfStatus::Unverifiable,
            AncestryScope::grafted_from(6),
            Some(admin.public_key()),
            &refs,
            &roster,
        )
        .expect("an admin-cosigned update must be acceptable from a grafted view");

        // A co-signature from a non-admin key must not rescue it.
        let impostor = MlDsa87KeyPair::generate().unwrap();
        assert!(verify_force_push_policy_scoped(
            &head,
            false,
            FfStatus::Unverifiable,
            AncestryScope::grafted_from(6),
            Some(impostor.public_key()),
            &refs,
            &roster,
        )
        .is_err());
    }

    /// Without a checkout there is no DAG, so nothing is decidable — and that
    /// must not be reported as a clean fast-forward.
    #[test]
    fn missing_dag_is_unverifiable_not_fast_forward() {
        let mut old = BTreeMap::new();
        old.insert("refs/heads/main".to_string(), "a".repeat(40));
        let mut new = BTreeMap::new();
        new.insert("refs/heads/main".to_string(), "b".repeat(40));
        assert_eq!(
            classify_ff(None, &old, &new).unwrap(),
            FfStatus::Unverifiable
        );
        assert!(classify_non_ff(None, &old, &new).unwrap());
    }

    #[test]
    fn deletion_is_definitively_non_fast_forward() {
        let mut old = BTreeMap::new();
        old.insert("refs/heads/doomed".to_string(), "c".repeat(40));
        assert_eq!(
            classify_ff(None, &old, &BTreeMap::new()).unwrap(),
            FfStatus::NonFastForward
        );
    }

    #[test]
    fn quorum_2_of_3_accepts() {
        let repo = RepoId([9u8; 32]);
        let prev = HeadHash::zero();
        let dig = [7u8; 64];
        let a1 = MlDsa87KeyPair::generate().unwrap();
        let a2 = MlDsa87KeyPair::generate().unwrap();
        let a3 = MlDsa87KeyPair::generate().unwrap();
        let rd = roster_digest(&test_roster());
        let bundle =
            admin_quorum_sign(&[&a1, &a2, &a3], 2, &repo, 1, "push", 4, &prev, &dig, &rd).unwrap();
        let (m, sigs) = decode_admin_quorum(&bundle).unwrap();
        assert_eq!(m, 2);
        assert_eq!(sigs.len(), 3);
        admin_quorum_verify(
            &[a1.public_key(), a2.public_key(), a3.public_key()],
            &repo,
            1,
            "push",
            4,
            &prev,
            &dig,
            &rd,
            &bundle,
        )
        .unwrap();
    }
}
