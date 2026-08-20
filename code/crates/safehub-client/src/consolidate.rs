//! Consolidation bindings a window-limited verifier can actually check.
//!
//! Consolidation rewrites physical storage while the logical log — `L`, the
//! per-head logical roots, and every member's `win(u)` — must stay unchanged.
//! A verifier that holds only its own window cannot replay the whole log, so
//! without a binding it has to trust whoever ran the consolidation. A corrupt
//! full-history member (or a CI job) could then drop or rewrite heads outside
//! every honest verifier's window and go unnoticed.
//!
//! The receipt closes that: consolidation is authorized by the admin
//! credential (single key or an m-of-n quorum), and it commits to
//!
//!   * a Merkle root over the per-head logical leaves of the whole span, and
//!   * a per-epoch commitment for every epoch in the span.
//!
//! A member holding any sub-window can then verify, from its own heads alone:
//! the admin authorization, a Merkle inclusion proof for each head it holds,
//! and the commitment of each epoch it holds completely. Anything the
//! consolidator changed inside that window fails; anything it changed outside
//! is still bound to the same root, so a second verifier with a different
//! window catches it.

use crate::error::ClientError;
use safehub_crypto::mldsa::MlDsa87KeyPair;
use safehub_types::{domain_label, BlobId, HeadHash, RefHead, RepoId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// Per-head logical leaf: sequence, head identity, and payload root.
///
/// The bundle root is included so a consolidator cannot re-point a head at
/// different ciphertext while keeping its hash chain intact.
pub fn logical_leaf(head: &RefHead) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain_label("consol-leaf").as_bytes());
    h.update(head.seq.to_le_bytes());
    h.update(head.hash().0);
    h.update(head.bundle_root.0);
    h.update(head.mls_epoch.to_le_bytes());
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

fn node(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain_label("consol-node").as_bytes());
    h.update(left);
    h.update(right);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

/// One step of a Merkle inclusion path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleStep {
    /// Sibling digest at this level.
    #[serde(with = "digest64")]
    pub sibling: [u8; 64],
    /// Whether the sibling sits on the right of the running hash.
    pub sibling_right: bool,
}

/// Inclusion proof for one logical leaf.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePath {
    /// Leaf index within the consolidated span.
    pub index: usize,
    /// Path from leaf to root.
    pub steps: Vec<MerkleStep>,
}

mod digest64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte digest"))
    }
}

/// Merkle root over `leaves`; an odd level duplicates its last node.
pub fn merkle_root(leaves: &[[u8; 64]]) -> [u8; 64] {
    if leaves.is_empty() {
        let mut h = Sha512::new();
        h.update(domain_label("consol-empty").as_bytes());
        let mut out = [0u8; 64];
        out.copy_from_slice(&h.finalize());
        return out;
    }
    let mut level: Vec<[u8; 64]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(node(&pair[0], right));
        }
        level = next;
    }
    level[0]
}

/// Inclusion path for `index` in the tree built from `leaves`.
pub fn merkle_path(leaves: &[[u8; 64]], index: usize) -> Option<MerklePath> {
    if index >= leaves.len() {
        return None;
    }
    let mut steps = Vec::new();
    let mut level: Vec<[u8; 64]> = leaves.to_vec();
    let mut i = index;
    while level.len() > 1 {
        let sibling_right = i % 2 == 0;
        let sibling_idx = if sibling_right { i + 1 } else { i - 1 };
        let sibling = *level.get(sibling_idx).unwrap_or(&level[i]);
        steps.push(MerkleStep {
            sibling,
            sibling_right,
        });
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(node(&pair[0], right));
        }
        level = next;
        i /= 2;
    }
    Some(MerklePath { index, steps })
}

/// Recompute the root implied by `leaf` and `path`.
pub fn merkle_root_from_path(leaf: &[u8; 64], path: &MerklePath) -> [u8; 64] {
    let mut running = *leaf;
    for step in &path.steps {
        running = if step.sibling_right {
            node(&running, &step.sibling)
        } else {
            node(&step.sibling, &running)
        };
    }
    running
}

/// What a compaction replaces the replayed prefix with.
///
/// Compaction is the step that bounds replay: instead of every reader
/// replaying heads `1..=at_seq`, the consolidator publishes one self-contained
/// checkpoint of the tree as of `at_seq`, and readers replay only the tail
/// after it. That is only safe if a reader can tell a real checkpoint from a
/// fabricated one *without* doing the replay it is trying to avoid, so the
/// binding names the state it claims to be:
///
///   * `anchor_head` — the hash of the head at `at_seq`. That head is signed by
///     its pusher and MACed under its epoch, so the adversary cannot move it.
///   * `refs_digest` — over the ref map sealed inside that head's `enc_refs`.
///     A reader opens the anchor head itself and recomputes this, which is O(1)
///     in depth. A checkpoint claiming different tips fails here.
///   * `bundle_root` — CAS root of the sealed checkpoint chunks.
///
/// The objects themselves need no separate commitment: the ref map names git
/// object ids, and git objects are content-addressed, so a substituted object
/// fails its own id and an omitted one breaks DAG resolution. The checkpoint
/// therefore inherits exactly the object-hash assumption the rest of the
/// system already makes, and nothing weaker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointBinding {
    /// Sequence the checkpoint materializes.
    pub at_seq: u64,
    /// Hash of the head at `at_seq`.
    pub anchor_head: HeadHash,
    /// Digest over the canonical ref map sealed in that head.
    pub refs_digest: HeadHash,
    /// CAS root of the sealed checkpoint bundle.
    pub bundle_root: BlobId,
}

/// Digest a reader recomputes from the anchor head's own decrypted ref bytes.
pub fn refs_digest(repo: &RepoId, at_seq: u64, refs_plaintext: &[u8]) -> HeadHash {
    let mut h = Sha512::new();
    h.update(domain_label("consol-refs").as_bytes());
    h.update(repo.0);
    h.update(at_seq.to_le_bytes());
    h.update((refs_plaintext.len() as u64).to_le_bytes());
    h.update(refs_plaintext);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    HeadHash(out)
}

/// Admin-authorized commitment to a consolidated span of the log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsolidationReceipt {
    /// Repository the consolidation belongs to.
    pub repo_id: RepoId,
    /// Epoch in which the consolidation was performed.
    pub epoch: u64,
    /// First sequence in the consolidated span.
    pub from_seq: u64,
    /// Last sequence in the consolidated span.
    pub to_seq: u64,
    /// Merkle root over the per-head logical leaves of the span.
    pub logical_root: BlobId,
    /// Per-epoch commitment: epoch → (first seq, last seq, digest).
    pub epoch_commitments: BTreeMap<u64, (u64, u64, HeadHash)>,
    /// Checkpoint this consolidation compacted the prefix into, when it
    /// compacted rather than only attested.
    #[serde(default)]
    pub checkpoint: Option<CheckpointBinding>,
    /// Admin ML-DSA-87 signature (or m-of-n quorum bundle) over the receipt.
    #[serde(default)]
    pub admin_sig: Vec<u8>,
}

/// A receipt plus the leaves needed to answer inclusion queries.
pub struct ConsolidationPlan {
    /// Receipt to publish (signed by [`sign_consolidation`]).
    pub receipt: ConsolidationReceipt,
    /// Logical leaves in sequence order.
    pub leaves: Vec<[u8; 64]>,
}

impl ConsolidationPlan {
    /// Inclusion proof for the head at `seq`, if it is inside the span.
    pub fn proof_for(&self, seq: u64) -> Option<MerklePath> {
        if seq < self.receipt.from_seq || seq > self.receipt.to_seq {
            return None;
        }
        let index = (seq - self.receipt.from_seq) as usize;
        merkle_path(&self.leaves, index)
    }
}

/// Per-epoch commitment over `heads`, matching what a verifier recomputes.
fn epoch_commitments(heads: &[RefHead]) -> BTreeMap<u64, (u64, u64, HeadHash)> {
    let mut per_epoch: BTreeMap<u64, Vec<&RefHead>> = BTreeMap::new();
    for h in heads {
        per_epoch.entry(h.mls_epoch).or_default().push(h);
    }
    per_epoch
        .into_iter()
        .map(|(epoch, group)| {
            let lo = group.first().map(|h| h.seq).unwrap_or_default();
            let hi = group.last().map(|h| h.seq).unwrap_or_default();
            let mut h = Sha512::new();
            h.update(domain_label("consol-epoch").as_bytes());
            h.update(epoch.to_le_bytes());
            for head in group {
                h.update(head.seq.to_le_bytes());
                h.update(head.hash().0);
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&h.finalize());
            (epoch, (lo, hi, HeadHash(arr)))
        })
        .collect()
}

/// Domain-separated transcript signed by the admin (signature excluded).
pub fn consolidation_message(receipt: &ConsolidationReceipt) -> Vec<u8> {
    let mut msg = domain_label("consolidation").into_bytes();
    msg.extend_from_slice(&receipt.repo_id.0);
    msg.extend_from_slice(&receipt.epoch.to_le_bytes());
    msg.extend_from_slice(&receipt.from_seq.to_le_bytes());
    msg.extend_from_slice(&receipt.to_seq.to_le_bytes());
    msg.extend_from_slice(&receipt.logical_root.0);
    for (epoch, (lo, hi, dig)) in &receipt.epoch_commitments {
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&lo.to_le_bytes());
        msg.extend_from_slice(&hi.to_le_bytes());
        msg.extend_from_slice(&dig.0);
    }
    // The checkpoint must sit inside the signed transcript, not beside it:
    // otherwise an admin could authorize an honest span and then re-point the
    // checkpoint it compacts to, which is the one object readers accept
    // without replaying anything.
    match &receipt.checkpoint {
        None => msg.push(0),
        Some(c) => {
            msg.push(1);
            msg.extend_from_slice(&c.at_seq.to_le_bytes());
            msg.extend_from_slice(&c.anchor_head.0);
            msg.extend_from_slice(&c.refs_digest.0);
            msg.extend_from_slice(&c.bundle_root.0);
        }
    }
    msg
}

/// Build the binding for consolidating `heads` (ascending, contiguous).
pub fn plan_consolidation(
    repo: &RepoId,
    epoch: u64,
    heads: &[RefHead],
) -> Result<ConsolidationPlan, ClientError> {
    if heads.is_empty() {
        return Err(ClientError::Other(
            "consolidation needs at least one head".into(),
        ));
    }
    for w in heads.windows(2) {
        if w[1].seq != w[0].seq + 1 {
            return Err(ClientError::Other(format!(
                "consolidation span is not contiguous at seq {}",
                w[1].seq
            )));
        }
    }
    let leaves: Vec<[u8; 64]> = heads.iter().map(logical_leaf).collect();
    let root = merkle_root(&leaves);
    Ok(ConsolidationPlan {
        receipt: ConsolidationReceipt {
            repo_id: *repo,
            epoch,
            from_seq: heads[0].seq,
            to_seq: heads[heads.len() - 1].seq,
            logical_root: BlobId(root),
            epoch_commitments: epoch_commitments(heads),
            checkpoint: None,
            admin_sig: Vec::new(),
        },
        leaves,
    })
}

/// Plan a compaction: the attestation of [`plan_consolidation`] plus the
/// checkpoint that lets readers stop replaying the span.
///
/// `checkpoint_refs` is the decrypted ref-map plaintext of the last head in
/// `heads` — the same bytes [`crate::pushfetch::open_refs`] returns — and
/// `bundle_root` is the CAS root of the sealed checkpoint bundle. Both are
/// bound into the signed transcript by [`sign_consolidation`].
pub fn plan_compaction(
    repo: &RepoId,
    epoch: u64,
    heads: &[RefHead],
    checkpoint_refs: &[u8],
    bundle_root: BlobId,
) -> Result<ConsolidationPlan, ClientError> {
    let mut plan = plan_consolidation(repo, epoch, heads)?;
    let anchor = heads.last().expect("plan_consolidation rejects empty spans");
    plan.receipt.checkpoint = Some(CheckpointBinding {
        at_seq: anchor.seq,
        anchor_head: anchor.hash(),
        refs_digest: refs_digest(repo, anchor.seq, checkpoint_refs),
        bundle_root,
    });
    Ok(plan)
}

/// Authorize a receipt with the repository admin credential.
pub fn sign_consolidation(
    receipt: &mut ConsolidationReceipt,
    admin: &MlDsa87KeyPair,
) -> Result<(), ClientError> {
    receipt.admin_sig = admin
        .sign(&consolidation_message(receipt))
        .map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(())
}

/// Authorize a receipt with an m-of-n admin quorum.
pub fn sign_consolidation_quorum(
    receipt: &mut ConsolidationReceipt,
    admins: &[&MlDsa87KeyPair],
    m: u8,
) -> Result<(), ClientError> {
    let msg = consolidation_message(receipt);
    let mut sigs = Vec::with_capacity(admins.len());
    for a in admins {
        sigs.push(a.sign(&msg).map_err(|e| ClientError::Other(e.to_string()))?);
    }
    receipt.admin_sig = crate::policy::encode_admin_quorum(m, &sigs)?;
    Ok(())
}

/// Verify a checkpoint against its anchor head alone, in O(1) of depth.
///
/// This is what a reader that holds *no* history runs: it is the whole point of
/// compaction that such a reader exists, and it is why this cannot be folded
/// into [`verify_consolidation_window`], which requires the caller to hold
/// heads inside the span and rejects a caller that holds none.
///
/// `anchor` is the head at the checkpoint sequence, fetched and already checked
/// for signature and epoch tag by the normal head path; `refs_plaintext` is that
/// head's own decrypted ref map. Passing a head the caller has not
/// authenticated proves nothing — the binding is only as good as the anchor.
pub fn verify_checkpoint_anchor(
    receipt: &ConsolidationReceipt,
    admin_vks: &[&[u8]],
    anchor: &RefHead,
    refs_plaintext: &[u8],
) -> Result<(), ClientError> {
    if admin_vks.is_empty() {
        return Err(ClientError::Other(
            "checkpoint verification requires at least one admin verifying key".into(),
        ));
    }
    if receipt.admin_sig.is_empty() {
        return Err(ClientError::Other(
            "consolidation receipt carries no admin authorization".into(),
        ));
    }
    let Some(cp) = &receipt.checkpoint else {
        return Err(ClientError::Other(
            "receipt attests a span but publishes no checkpoint: \
             readers cannot skip the replay it covers"
                .into(),
        ));
    };
    verify_admin_authorization(&consolidation_message(receipt), admin_vks, &receipt.admin_sig)?;

    if anchor.repo_id != receipt.repo_id {
        return Err(ClientError::Other(
            "checkpoint anchor belongs to a different repository".into(),
        ));
    }
    if anchor.seq != cp.at_seq {
        return Err(ClientError::Other(format!(
            "checkpoint claims seq {} but the anchor head is seq {}",
            cp.at_seq, anchor.seq
        )));
    }
    // Pins the exact chain, so a receipt from a fork carrying the same sequence
    // numbers does not transfer.
    if anchor.hash() != cp.anchor_head {
        return Err(ClientError::Other(format!(
            "checkpoint at seq {} is bound to a different head than the one served",
            cp.at_seq
        )));
    }
    if refs_digest(&receipt.repo_id, cp.at_seq, refs_plaintext) != cp.refs_digest {
        return Err(ClientError::Other(format!(
            "checkpoint tips disagree with the ref map sealed in head {}",
            cp.at_seq
        )));
    }
    if cp.at_seq < receipt.from_seq || cp.at_seq > receipt.to_seq {
        return Err(ClientError::Other(format!(
            "checkpoint at seq {} lies outside the consolidated span [{},{}]",
            cp.at_seq, receipt.from_seq, receipt.to_seq
        )));
    }
    Ok(())
}

/// Verify a consolidation receipt from a window-limited view.
///
/// `window_heads` are the heads this verifier holds, ascending. Only the ones
/// inside the receipt's span are checked; a verifier is never asked for heads
/// outside its own `win(u)`.
pub fn verify_consolidation_window(
    receipt: &ConsolidationReceipt,
    admin_vks: &[&[u8]],
    window_heads: &[RefHead],
    proofs: &BTreeMap<u64, MerklePath>,
) -> Result<(), ClientError> {
    if admin_vks.is_empty() {
        return Err(ClientError::Other(
            "consolidation verification requires at least one admin verifying key".into(),
        ));
    }
    if receipt.admin_sig.is_empty() {
        return Err(ClientError::Other(
            "consolidation receipt carries no admin authorization".into(),
        ));
    }
    // Only the admin credential (or a quorum of them) may consolidate: a
    // corrupt ordinary member holds no key that satisfies this.
    let msg = consolidation_message(receipt);
    verify_admin_authorization(&msg, admin_vks, &receipt.admin_sig)?;

    let in_span: Vec<&RefHead> = window_heads
        .iter()
        .filter(|h| h.seq >= receipt.from_seq && h.seq <= receipt.to_seq)
        .collect();
    if in_span.is_empty() {
        return Err(ClientError::Other(
            "verifier window does not intersect the consolidated span".into(),
        ));
    }
    for head in &in_span {
        let Some(path) = proofs.get(&head.seq) else {
            return Err(ClientError::Other(format!(
                "consolidation receipt has no inclusion proof for seq {} (inside this window)",
                head.seq
            )));
        };
        let expect_index = (head.seq - receipt.from_seq) as usize;
        if path.index != expect_index {
            return Err(ClientError::Other(format!(
                "inclusion proof for seq {} claims leaf index {} (expected {expect_index})",
                head.seq, path.index
            )));
        }
        let leaf = logical_leaf(head);
        if merkle_root_from_path(&leaf, path) != receipt.logical_root.0 {
            return Err(ClientError::Other(format!(
                "consolidation dropped or rewrote the head at seq {}: \
                 it does not hash into the committed logical root",
                head.seq
            )));
        }
    }

    // Per-epoch commitments catch removals: an inclusion proof only speaks for
    // heads the verifier still holds, so a consolidator that deletes one from
    // an epoch this verifier holds completely is caught here.
    let local = epoch_commitments(
        &in_span
            .iter()
            .map(|h| (*h).clone())
            .collect::<Vec<RefHead>>(),
    );
    for (epoch, (lo, hi, dig)) in &local {
        let Some((r_lo, r_hi, r_dig)) = receipt.epoch_commitments.get(epoch) else {
            return Err(ClientError::Other(format!(
                "consolidation receipt omits epoch {epoch}, which this window holds"
            )));
        };
        // Compare only where the spans coincide: a window that holds part of an
        // epoch has no opinion about the rest of it.
        if (lo, hi) == (r_lo, r_hi) && dig != r_dig {
            return Err(ClientError::Other(format!(
                "consolidation changed the head set of epoch {epoch} inside this window"
            )));
        }
        if lo < r_lo || hi > r_hi {
            return Err(ClientError::Other(format!(
                "consolidation receipt covers epoch {epoch} only over [{r_lo},{r_hi}] \
                 but this window holds [{lo},{hi}]"
            )));
        }
    }

    // A window member that happens to hold the anchor head checks the
    // checkpoint too, so a fabricated one is caught by ordinary members and not
    // only by readers that rely on it.
    if let Some(cp) = &receipt.checkpoint {
        if let Some(anchor) = in_span.iter().find(|h| h.seq == cp.at_seq) {
            if anchor.hash() != cp.anchor_head {
                return Err(ClientError::Other(format!(
                    "checkpoint at seq {} is bound to a head this window does not have",
                    cp.at_seq
                )));
            }
        }
        if cp.at_seq < receipt.from_seq || cp.at_seq > receipt.to_seq {
            return Err(ClientError::Other(format!(
                "checkpoint at seq {} lies outside the consolidated span [{},{}]",
                cp.at_seq, receipt.from_seq, receipt.to_seq
            )));
        }
    }
    Ok(())
}

fn verify_admin_authorization(
    msg: &[u8],
    admin_vks: &[&[u8]],
    sig: &[u8],
) -> Result<(), ClientError> {
    if crate::policy::decode_admin_quorum(sig).is_some() {
        // Reuse the quorum encoding, but over the consolidation transcript.
        return verify_quorum_over(msg, admin_vks, sig);
    }
    for vk in admin_vks {
        if safehub_crypto::mldsa::verify(vk, msg, sig).is_ok() {
            return Ok(());
        }
    }
    Err(ClientError::Other(
        "consolidation was not authorized by an admin credential".into(),
    ))
}

fn verify_quorum_over(msg: &[u8], admin_vks: &[&[u8]], sig: &[u8]) -> Result<(), ClientError> {
    let Some((m, sigs)) = crate::policy::decode_admin_quorum(sig) else {
        return Err(ClientError::Other("malformed admin quorum".into()));
    };
    let mut ok = 0u8;
    for s in &sigs {
        if admin_vks
            .iter()
            .any(|vk| safehub_crypto::mldsa::verify(vk, msg, s).is_ok())
        {
            ok = ok.saturating_add(1);
        }
    }
    if ok < m {
        return Err(ClientError::Other(format!(
            "consolidation admin quorum failed: {ok}/{m} valid"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use safehub_types::HeadHash;

    fn head(seq: u64, prev: HeadHash, epoch: u64, salt: u8) -> RefHead {
        RefHead {
            repo_id: RepoId([2u8; 32]),
            seq,
            enc_refs: vec![salt; 4],
            bundle_root: BlobId([salt; 64]),
            dek_wrap: vec![salt],
            prev_head_hash: prev,
            mls_epoch: epoch,
            epoch_tag: vec![0; 32],
            non_ff: false,
            pusher_sig: vec![],
            admin_cosig: None,
        }
    }

    /// 12 heads over 4 epochs of 3.
    fn log() -> Vec<RefHead> {
        let mut out = Vec::new();
        let mut prev = HeadHash::zero();
        for seq in 1..=12u64 {
            let h = head(seq, prev, (seq - 1) / 3, seq as u8);
            prev = h.hash();
            out.push(h);
        }
        out
    }

    fn proofs_for(plan: &ConsolidationPlan, heads: &[RefHead]) -> BTreeMap<u64, MerklePath> {
        heads
            .iter()
            .filter_map(|h| plan.proof_for(h.seq).map(|p| (h.seq, p)))
            .collect()
    }

    #[test]
    fn merkle_paths_verify_for_every_leaf() {
        let heads = log();
        let leaves: Vec<[u8; 64]> = heads.iter().map(logical_leaf).collect();
        let root = merkle_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let path = merkle_path(&leaves, i).unwrap();
            assert_eq!(merkle_root_from_path(leaf, &path), root, "leaf {i}");
        }
    }

    #[test]
    fn an_admin_consolidation_verifies_from_a_narrow_window() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let mut plan = plan_consolidation(&repo, 3, &heads).unwrap();
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        // A forward-only member holding only epochs 2–3 (seqs 7..=12).
        let window: Vec<RefHead> = heads.iter().filter(|h| h.mls_epoch >= 2).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
            .expect("an honest admin consolidation must verify from a narrow window");
    }

    /// A non-admin member must not be able to authorize consolidation.
    #[test]
    fn a_malicious_member_consolidation_is_rejected_by_a_window_limited_verifier() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let member = MlDsa87KeyPair::generate().unwrap();

        let mut plan = plan_consolidation(&repo, 3, &heads).unwrap();
        sign_consolidation(&mut plan.receipt, &member).unwrap();

        let window: Vec<RefHead> = heads.iter().filter(|h| h.mls_epoch >= 2).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        let err =
            verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
                .unwrap_err();
        assert!(
            err.to_string().contains("not authorized by an admin"),
            "a non-admin consolidation was accepted: {err}"
        );
    }

    /// A consolidator that rewrites a head inside the verifier's window fails
    /// inclusion, even though it signed the receipt with the real admin key.
    #[test]
    fn rewriting_a_head_inside_the_window_breaks_inclusion() {
        let repo = RepoId([2u8; 32]);
        let honest = log();
        let admin = MlDsa87KeyPair::generate().unwrap();

        let mut tampered = honest.clone();
        tampered[9].bundle_root = BlobId([0xEE; 64]); // seq 10, epoch 3
        let mut plan = plan_consolidation(&repo, 3, &tampered).unwrap();
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        // The verifier holds the honest heads, so the receipt does not match.
        let window: Vec<RefHead> = honest.iter().filter(|h| h.mls_epoch >= 3).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        let err =
            verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
                .unwrap_err();
        assert!(
            err.to_string().contains("seq 10"),
            "expected the rewritten head to be named, got: {err}"
        );
    }

    /// A consolidator holding the admin key (compromised admin, or a CI job)
    /// that under-reports an epoch's head set is caught by the per-epoch
    /// commitment rather than by inclusion: the Merkle root still contains the
    /// head, but the epoch it belongs to no longer accounts for it.
    #[test]
    fn under_reporting_an_epoch_breaks_the_epoch_commitment() {
        let repo = RepoId([2u8; 32]);
        let honest = log();
        let admin = MlDsa87KeyPair::generate().unwrap();

        let mut plan = plan_consolidation(&repo, 3, &honest).unwrap();
        let shrunk: Vec<RefHead> = honest
            .iter()
            .filter(|h| h.mls_epoch == 3 && h.seq < 12)
            .cloned()
            .collect();
        let (lo, hi, dig) = epoch_commitments(&shrunk)[&3];
        plan.receipt.epoch_commitments.insert(3, (lo, hi, dig));
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        let window: Vec<RefHead> = honest.iter().filter(|h| h.mls_epoch >= 3).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        let err =
            verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
                .unwrap_err();
        assert!(
            err.to_string().contains("epoch 3"),
            "expected an epoch-3 commitment failure, got: {err}"
        );
    }

    #[test]
    fn an_unsigned_receipt_is_rejected() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = plan_consolidation(&repo, 1, &heads).unwrap();
        let proofs = proofs_for(&plan, &heads);
        let err = verify_consolidation_window(&plan.receipt, &[admin.public_key()], &heads, &proofs)
            .unwrap_err();
        assert!(err.to_string().contains("no admin authorization"));
    }

    #[test]
    fn a_quorum_authorized_consolidation_verifies() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let a1 = MlDsa87KeyPair::generate().unwrap();
        let a2 = MlDsa87KeyPair::generate().unwrap();
        let a3 = MlDsa87KeyPair::generate().unwrap();
        let mut plan = plan_consolidation(&repo, 2, &heads).unwrap();
        sign_consolidation_quorum(&mut plan.receipt, &[&a1, &a2, &a3], 2).unwrap();
        let proofs = proofs_for(&plan, &heads);
        verify_consolidation_window(
            &plan.receipt,
            &[a1.public_key(), a2.public_key(), a3.public_key()],
            &heads,
            &proofs,
        )
        .expect("a 2-of-3 admin quorum must authorize consolidation");

        // A 2-of-2 bundle verified against a key set that only recognizes one
        // of the two signers cannot reach the threshold.
        let mut solo = plan_consolidation(&repo, 2, &heads).unwrap();
        sign_consolidation_quorum(&mut solo.receipt, &[&a1, &a2], 2).unwrap();
        assert!(verify_consolidation_window(
            &solo.receipt,
            &[a1.public_key(), a3.public_key()],
            &heads,
            &proofs_for(&solo, &heads),
        )
        .is_err());
    }

    #[test]
    fn a_receipt_signature_does_not_survive_root_substitution() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let mut plan = plan_consolidation(&repo, 1, &heads).unwrap();
        sign_consolidation(&mut plan.receipt, &admin).unwrap();
        plan.receipt.logical_root = BlobId([0x01; 64]);
        let proofs = proofs_for(&plan, &heads);
        assert!(
            verify_consolidation_window(&plan.receipt, &[admin.public_key()], &heads, &proofs)
                .is_err()
        );
    }
    // ---- compaction: the step that bounds replay -------------------------
    //
    // One test per attack the design was checked against before it was built.
    // The property under test throughout is that a reader holding *no* history
    // can accept a checkpoint, and that everything which could make that
    // unsafe is caught.

    /// Plaintext ref map the anchor head would seal.
    fn refs_bytes(tip: &str) -> Vec<u8> {
        format!(r#"{{"refs":{{"refs/heads/main":"{tip}"}}}}"#).into_bytes()
    }

    fn compaction(
        repo: &RepoId,
        heads: &[RefHead],
        refs: &[u8],
        admin: &MlDsa87KeyPair,
    ) -> ConsolidationPlan {
        let mut plan = plan_compaction(repo, 3, heads, refs, BlobId([9u8; 64])).unwrap();
        sign_consolidation(&mut plan.receipt, admin).unwrap();
        plan
    }

    /// The point of the step: a reader with no history at all accepts it.
    #[test]
    fn a_reader_holding_no_history_can_verify_a_checkpoint() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs, &admin);
        let anchor = heads.last().unwrap();

        verify_checkpoint_anchor(&plan.receipt, &[admin.public_key()], anchor, &refs)
            .expect("a fresh reader must be able to accept an honest checkpoint");
    }

    /// A4: the window verifier cannot serve that reader — it needs held heads.
    /// This is why the anchor path exists as a separate entry point.
    #[test]
    fn the_window_verifier_cannot_serve_a_reader_with_no_history() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs, &admin);

        let err = verify_consolidation_window(
            &plan.receipt,
            &[admin.public_key()],
            &[],
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not intersect"),
            "expected the window verifier to refuse an empty window: {err}"
        );
    }

    /// A1: a checkpoint whose tips differ from the ref map sealed in the
    /// anchor head is rejected, which is what stops a malicious admin from
    /// handing fresh readers a tree nobody ever pushed.
    #[test]
    fn a_checkpoint_that_restates_the_tips_is_rejected() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs_bytes("aa00"), &admin);
        let anchor = heads.last().unwrap();

        // Reader opens the anchor head and gets the real tips, not the ones
        // the consolidator committed to.
        let err = verify_checkpoint_anchor(
            &plan.receipt,
            &[admin.public_key()],
            anchor,
            &refs_bytes("bb11"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tips disagree"),
            "a checkpoint contradicting its anchor head was accepted: {err}"
        );
    }

    /// A3: the checkpoint is inside the signed transcript, so re-pointing it
    /// after authorization invalidates the signature.
    #[test]
    fn re_pointing_a_checkpoint_after_signing_breaks_the_signature() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        let mut plan = compaction(&repo, &heads, &refs, &admin);
        let anchor = heads.last().unwrap();

        plan.receipt.checkpoint.as_mut().unwrap().bundle_root = BlobId([0xEE; 64]);
        let err = verify_checkpoint_anchor(&plan.receipt, &[admin.public_key()], anchor, &refs)
            .unwrap_err();
        assert!(
            err.to_string().contains("not authorized by an admin"),
            "a re-pointed checkpoint kept its authorization: {err}"
        );
    }

    /// A5: sequence numbers repeat across forks, so the binding names the head
    /// hash. A receipt from one chain must not transfer to another.
    #[test]
    fn a_checkpoint_does_not_transfer_to_a_fork_with_the_same_sequence() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs, &admin);

        // Same seq, same epoch, different chain.
        let mut fork = heads.clone();
        let last = fork.len() - 1;
        fork[last].bundle_root = BlobId([0x77; 64]);

        let err =
            verify_checkpoint_anchor(&plan.receipt, &[admin.public_key()], &fork[last], &refs)
                .unwrap_err();
        assert!(
            err.to_string().contains("bound to a different head"),
            "a checkpoint transferred to a fork: {err}"
        );
    }

    /// A7: compaction is admin-gated exactly as attestation is.
    #[test]
    fn a_member_cannot_publish_a_checkpoint() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        let member = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs, &member);

        let err = verify_checkpoint_anchor(
            &plan.receipt,
            &[admin.public_key()],
            heads.last().unwrap(),
            &refs,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not authorized by an admin"),
            "a member published an accepted checkpoint: {err}"
        );
    }

    /// An attest-only receipt must not be usable to skip replay: it commits to
    /// no checkpoint, so there is nothing for a fresh reader to accept.
    #[test]
    fn an_attestation_without_a_checkpoint_cannot_shorten_replay() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let mut plan = plan_consolidation(&repo, 3, &heads).unwrap();
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        let err = verify_checkpoint_anchor(
            &plan.receipt,
            &[admin.public_key()],
            heads.last().unwrap(),
            &refs_bytes("aa00"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("publishes no checkpoint"),
            "an attest-only receipt was used to skip replay: {err}"
        );
    }

    /// Compaction keeps the attestation: an ordinary window member still
    /// verifies inclusion, so the step adds a reader path without weakening
    /// the one that already existed.
    #[test]
    fn compaction_still_verifies_from_a_narrow_window() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        let plan = compaction(&repo, &heads, &refs_bytes("aa00"), &admin);

        let window: Vec<RefHead> = heads.iter().filter(|h| h.mls_epoch >= 2).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
            .expect("compaction must not break window-limited attestation");
    }

    /// A window member holding the anchor checks the checkpoint too, so a
    /// fabricated one is caught by ordinary members, not only by the readers
    /// that depend on it.
    #[test]
    fn a_window_member_holding_the_anchor_catches_a_swapped_checkpoint() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let admin = MlDsa87KeyPair::generate().unwrap();
        // Swap the anchor *before* signing, so the receipt carries a valid
        // admin signature: otherwise this would only re-test the signature
        // check and say nothing about the window path.
        let mut plan =
            plan_compaction(&repo, 3, &heads, &refs_bytes("aa00"), BlobId([9u8; 64])).unwrap();
        plan.receipt.checkpoint.as_mut().unwrap().anchor_head = HeadHash([0x5A; 64]);
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        let window: Vec<RefHead> = heads.iter().filter(|h| h.mls_epoch >= 2).cloned().collect();
        let proofs = proofs_for(&plan, &window);
        let err =
            verify_consolidation_window(&plan.receipt, &[admin.public_key()], &window, &proofs)
                .unwrap_err();
        assert!(
            err.to_string().contains("head this window does not have"),
            "a window member missed a swapped checkpoint: {err}"
        );
    }

    /// The checkpoint has to sit inside the span it compacts, or it commits to
    /// state the receipt never attested.
    #[test]
    fn a_checkpoint_outside_the_span_is_rejected() {
        let repo = RepoId([2u8; 32]);
        let heads = log();
        let refs = refs_bytes("aa00");
        let admin = MlDsa87KeyPair::generate().unwrap();
        // Attest only seqs 1..=6 but checkpoint the tree as of seq 12.
        let mut plan = plan_compaction(&repo, 3, &heads[..6], &refs, BlobId([9u8; 64])).unwrap();
        let anchor = heads.last().unwrap();
        plan.receipt.checkpoint = Some(CheckpointBinding {
            at_seq: anchor.seq,
            anchor_head: anchor.hash(),
            refs_digest: refs_digest(&repo, anchor.seq, &refs),
            bundle_root: BlobId([9u8; 64]),
        });
        sign_consolidation(&mut plan.receipt, &admin).unwrap();

        let err = verify_checkpoint_anchor(&plan.receipt, &[admin.public_key()], anchor, &refs)
            .unwrap_err();
        assert!(
            err.to_string().contains("outside the consolidated span"),
            "a checkpoint outside its own span was accepted: {err}"
        );
    }
}
