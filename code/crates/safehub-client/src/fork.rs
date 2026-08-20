//! Authenticated RefHead checkpoint exchange (gossip Compare).
//!
//! Local hash-chain anchors detect rollback on a single client view.
//! Cross-party equivocation (split views) is detected when two honest
//! clients exchange checkpoints and find non-prefix-comparable chains,
//! realizing the ideal `Forked(sid,P,Q)` event.
//!
//! Fetch yields a *filtered* subsequence of the log: a member granted history
//! from epoch `w` holds only the heads at epochs `≥ w`. Comparing two such
//! views positionally would report a fork whenever the windows differ, so
//! Compare runs over the **authorized projection** — the sequence range both
//! sides are entitled to hold — and aligns entries by `seq`, never by index.
//! Each entry carries its epoch, and each epoch carries a commitment plus an
//! optional MLS epoch witness, so the predicate is embeddable in every window.

use crate::policy::epoch_witness_bytes;
use safehub_types::{HeadHash, RefHead, RepoId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// One accepted head in a client's observed chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainEntry {
    /// Sequence number.
    pub seq: u64,
    /// SHA-512 digest of the RefHead record.
    pub hash: HeadHash,
    /// Predecessor hash (zero for genesis).
    pub prev: HeadHash,
    /// MLS epoch that sealed the head, so windows can be intersected.
    #[serde(default)]
    pub epoch: u64,
}

/// Exportable checkpoint for Compare / gossip.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefCheckpoint {
    /// Repository id.
    pub repo_id: RepoId,
    /// Ordered chain entries (increasing seq) inside this view's window.
    pub chain: Vec<ChainEntry>,
    /// Inclusive epoch from which this view is authorized to hold heads.
    ///
    /// `0` is a full-history member. A grafted, forward-only member exports its
    /// join epoch, which is what makes mixed-window Compare well defined.
    #[serde(default)]
    pub window_from: u64,
    /// `MAC(mk_e, epoch)` per epoch, when the exporter holds `mk_e`.
    ///
    /// Detects an MLS delivery-service partition: two subgroups at the same
    /// epoch number derive different exporters, so these values disagree even
    /// when both head chains look internally perfect.
    #[serde(default)]
    pub epoch_witnesses: BTreeMap<u64, Vec<u8>>,
    /// Domain-separated authenticator over the chain tip.
    ///
    /// Prototype: HMAC-SHA-512-256 under the exporter `refs` key is applied
    /// by callers; this field holds the raw tip digest binding.
    pub tip_binding: HeadHash,
}

impl RefCheckpoint {
    /// Build a full-history checkpoint from an ordered head list.
    pub fn from_heads(repo_id: RepoId, heads: &[RefHead]) -> Self {
        Self::from_heads_windowed(repo_id, heads, 0)
    }

    /// Build a checkpoint restricted to the window `[window_from, ∞)`.
    ///
    /// Heads sealed under earlier epochs are dropped: a grafted member has no
    /// authority over them and must not be asked to commit to them.
    pub fn from_heads_windowed(repo_id: RepoId, heads: &[RefHead], window_from: u64) -> Self {
        let chain: Vec<ChainEntry> = heads
            .iter()
            .filter(|h| h.mls_epoch >= window_from)
            .map(|h| ChainEntry {
                seq: h.seq,
                hash: h.hash(),
                prev: h.prev_head_hash,
                epoch: h.mls_epoch,
            })
            .collect();
        let mut cp = Self {
            repo_id,
            chain,
            window_from,
            epoch_witnesses: BTreeMap::new(),
            tip_binding: HeadHash::zero(),
        };
        cp.rebind();
        cp
    }

    /// Attach `MAC(mk_e, epoch)` for an epoch this exporter holds keys for.
    pub fn with_epoch_witness(mut self, epoch: u64, refs_mac: &[u8]) -> Self {
        let witness = epoch_witness_bytes(refs_mac, &self.repo_id, epoch);
        self.epoch_witnesses.insert(epoch, witness);
        self.rebind();
        self
    }

    /// Recompute the tip binding after mutating the checkpoint.
    fn rebind(&mut self) {
        self.tip_binding = bind_checkpoint(self);
    }

    /// Tip sequence, if any.
    pub fn tip_seq(&self) -> Option<u64> {
        self.chain.last().map(|e| e.seq)
    }

    /// Tip hash, if any.
    pub fn tip_hash(&self) -> Option<HeadHash> {
        self.chain.last().map(|e| e.hash)
    }

    /// Per-epoch commitment plus the seq span it covers in this view.
    ///
    /// The span is part of the comparison predicate: two views that hold
    /// different slices of the same epoch have nothing to say to each other
    /// about it, whereas identical spans with different commitments are a fork.
    pub fn epoch_commitments(&self) -> BTreeMap<u64, (u64, u64, HeadHash)> {
        let mut per_epoch: BTreeMap<u64, Vec<&ChainEntry>> = BTreeMap::new();
        for e in &self.chain {
            per_epoch.entry(e.epoch).or_default().push(e);
        }
        per_epoch
            .into_iter()
            .map(|(epoch, entries)| {
                let lo = entries.first().map(|e| e.seq).unwrap_or_default();
                let hi = entries.last().map(|e| e.seq).unwrap_or_default();
                let mut h = Sha512::new();
                h.update(safehub_types::domain_label("epoch-commit").as_bytes());
                h.update(epoch.to_le_bytes());
                for e in entries {
                    h.update(e.seq.to_le_bytes());
                    h.update(e.hash.0);
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&h.finalize());
                (epoch, (lo, hi, HeadHash(arr)))
            })
            .collect()
    }
}

/// Why two views were declared forked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkReason {
    /// Divergent head hashes at a sequence number both views hold.
    DivergentHead,
    /// Same epoch number, different MLS epoch witness (a Commit partition).
    EpochWitness {
        /// Epoch whose witness disagreed.
        epoch: u64,
    },
    /// Identical epoch span, different per-epoch commitment.
    EpochCommitment {
        /// Epoch whose commitment disagreed.
        epoch: u64,
    },
}

/// Outcome of comparing two checkpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareResult {
    /// Identical tips / compatible prefixes.
    Consistent,
    /// One chain is a strict prefix of the other (lagging client).
    PrefixCompatible {
        /// Which side is ahead: `A` or `B`.
        ahead: char,
    },
    /// The two windows share no sequence range, so neither confirms the other.
    ///
    /// Not a fork and not agreement: the views are simply incomparable and the
    /// pair must find a peer whose window bridges them.
    WindowDisjoint,
    /// Non-prefix-comparable views → Forked.
    Forked {
        /// First divergent sequence (if identifiable).
        at_seq: Option<u64>,
        /// Which part of the projection disagreed.
        reason: ForkReason,
    },
}

/// Compare two authenticated checkpoints for the same repository.
///
/// Comparability is defined on the authorized projection: entries at epochs
/// `≥ max(window_from_a, window_from_b)`, intersected on `seq`. Inside that
/// projection the views must agree exactly; outside it neither view is
/// entitled to an opinion.
pub fn compare_checkpoints(a: &RefCheckpoint, b: &RefCheckpoint) -> Result<CompareResult, String> {
    if a.repo_id != b.repo_id {
        return Err("checkpoint repository id mismatch".into());
    }
    if bind_checkpoint(a) != a.tip_binding || bind_checkpoint(b) != b.tip_binding {
        return Err("checkpoint tip binding mismatch (tampered export)".into());
    }
    if !chain_internally_valid(&a.chain) || !chain_internally_valid(&b.chain) {
        return Err("checkpoint chain fails internal prev/seq checks".into());
    }
    if a.chain.iter().any(|e| e.epoch < a.window_from)
        || b.chain.iter().any(|e| e.epoch < b.window_from)
    {
        return Err("checkpoint holds heads outside its declared window".into());
    }

    // A Commit partition is visible before any head is compared: same epoch
    // number, different exporter, therefore different witness.
    for (epoch, wa) in &a.epoch_witnesses {
        if let Some(wb) = b.epoch_witnesses.get(epoch) {
            if wa != wb {
                let at_seq = a
                    .chain
                    .iter()
                    .find(|e| e.epoch == *epoch)
                    .map(|e| e.seq);
                return Ok(CompareResult::Forked {
                    at_seq,
                    reason: ForkReason::EpochWitness { epoch: *epoch },
                });
            }
        }
    }

    let window = a.window_from.max(b.window_from);
    let pa = projection(&a.chain, window);
    let pb = projection(&b.chain, window);

    let (Some(lo_a), Some(hi_a)) = (pa.keys().next(), pa.keys().next_back()) else {
        return Ok(CompareResult::WindowDisjoint);
    };
    let (Some(lo_b), Some(hi_b)) = (pb.keys().next(), pb.keys().next_back()) else {
        return Ok(CompareResult::WindowDisjoint);
    };
    let lo = *lo_a.max(lo_b);
    let hi = *hi_a.min(hi_b);
    if lo > hi {
        return Ok(CompareResult::WindowDisjoint);
    }

    for seq in lo..=hi {
        match (pa.get(&seq), pb.get(&seq)) {
            (Some(ea), Some(eb)) => {
                if ea.hash != eb.hash || ea.epoch != eb.epoch {
                    return Ok(CompareResult::Forked {
                        at_seq: Some(seq),
                        reason: ForkReason::DivergentHead,
                    });
                }
            }
            // A hole inside the shared range: one side is missing a head the
            // other holds at an epoch both are entitled to.
            _ => {
                return Ok(CompareResult::Forked {
                    at_seq: Some(seq),
                    reason: ForkReason::DivergentHead,
                })
            }
        }
    }

    let ca = a.epoch_commitments();
    let cb = b.epoch_commitments();
    for (epoch, (lo_a, hi_a, dig_a)) in &ca {
        if *epoch < window {
            continue;
        }
        if let Some((lo_b, hi_b, dig_b)) = cb.get(epoch) {
            if (lo_a, hi_a) == (lo_b, hi_b) && dig_a != dig_b {
                return Ok(CompareResult::Forked {
                    at_seq: Some(*lo_a),
                    reason: ForkReason::EpochCommitment { epoch: *epoch },
                });
            }
        }
    }

    match hi_a.cmp(hi_b) {
        std::cmp::Ordering::Equal => Ok(CompareResult::Consistent),
        std::cmp::Ordering::Less => Ok(CompareResult::PrefixCompatible { ahead: 'B' }),
        std::cmp::Ordering::Greater => Ok(CompareResult::PrefixCompatible { ahead: 'A' }),
    }
}

/// Entries this view is authorized to commit to under `window`, keyed by seq.
fn projection(chain: &[ChainEntry], window: u64) -> BTreeMap<u64, &ChainEntry> {
    chain
        .iter()
        .filter(|e| e.epoch >= window)
        .map(|e| (e.seq, e))
        .collect()
}

fn chain_internally_valid(chain: &[ChainEntry]) -> bool {
    for i in 1..chain.len() {
        if chain[i].seq != chain[i - 1].seq + 1 {
            return false;
        }
        if chain[i].prev != chain[i - 1].hash {
            return false;
        }
        if chain[i].epoch < chain[i - 1].epoch {
            return false;
        }
    }
    true
}

fn bind_checkpoint(cp: &RefCheckpoint) -> HeadHash {
    let mut h = Sha512::new();
    h.update(b"safehub-v1:checkpoint");
    h.update(cp.window_from.to_le_bytes());
    for e in &cp.chain {
        h.update(e.seq.to_le_bytes());
        h.update(e.hash.0);
        h.update(e.prev.0);
        h.update(e.epoch.to_le_bytes());
    }
    for (epoch, w) in &cp.epoch_witnesses {
        h.update(epoch.to_le_bytes());
        h.update(w);
    }
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    HeadHash(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safehub_types::{BlobId, RefHead, RepoId};

    fn dummy_head(seq: u64, prev: HeadHash, salt: u8) -> RefHead {
        head_at_epoch(seq, prev, salt, 0)
    }

    fn head_at_epoch(seq: u64, prev: HeadHash, salt: u8, epoch: u64) -> RefHead {
        RefHead {
            repo_id: RepoId([1u8; 32]),
            seq,
            enc_refs: vec![salt],
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

    /// `n` heads, one epoch bump every `per_epoch` heads.
    fn chain_of(n: u64, per_epoch: u64) -> Vec<RefHead> {
        let mut out = Vec::new();
        let mut prev = HeadHash::zero();
        for seq in 1..=n {
            let h = head_at_epoch(seq, prev, seq as u8, (seq - 1) / per_epoch);
            prev = h.hash();
            out.push(h);
        }
        out
    }

    #[test]
    fn split_view_compare_detects_fork() {
        let repo = RepoId([9u8; 32]);
        let h0 = dummy_head(1, HeadHash::zero(), 1);
        let ha = dummy_head(2, h0.hash(), 2);
        let hb = dummy_head(2, h0.hash(), 3); // divergent at seq=2

        let alice = RefCheckpoint::from_heads(repo, &[h0.clone(), ha]);
        let bob = RefCheckpoint::from_heads(repo, &[h0, hb]);
        match compare_checkpoints(&alice, &bob).unwrap() {
            CompareResult::Forked { at_seq, .. } => assert_eq!(at_seq, Some(2)),
            other => panic!("expected Forked, got {other:?}"),
        }
    }

    #[test]
    fn prefix_compatible_when_lagging() {
        let repo = RepoId([8u8; 32]);
        let h0 = dummy_head(1, HeadHash::zero(), 1);
        let h1 = dummy_head(2, h0.hash(), 2);
        let short = RefCheckpoint::from_heads(repo, &[h0.clone()]);
        let long = RefCheckpoint::from_heads(repo, &[h0, h1]);
        assert_eq!(
            compare_checkpoints(&short, &long).unwrap(),
            CompareResult::PrefixCompatible { ahead: 'B' }
        );
    }

    /// A grafted view holds a filtered subsequence of the full head chain;
    /// that alone must not read as a fork.
    #[test]
    fn full_history_and_grafted_views_agree_on_their_shared_projection() {
        let repo = RepoId([4u8; 32]);
        let heads = chain_of(9, 3); // epochs 0,0,0,1,1,1,2,2,2
        let full = RefCheckpoint::from_heads(repo, &heads);
        let grafted = RefCheckpoint::from_heads_windowed(repo, &heads, 1);
        assert_eq!(grafted.chain.len(), 6);
        assert_eq!(
            compare_checkpoints(&full, &grafted).unwrap(),
            CompareResult::Consistent,
            "a filtered window must not be mistaken for a divergent chain"
        );
    }

    /// Divergence *inside* the shared projection is still a fork, and the
    /// grafted side finds it at the right sequence despite the index offset.
    #[test]
    fn grafted_view_still_detects_divergence_inside_its_window() {
        let repo = RepoId([4u8; 32]);
        let honest = chain_of(9, 3);
        let mut evil = honest.clone();
        evil[7].enc_refs = b"equivocation".to_vec(); // seq 8, epoch 2
        for i in 8..evil.len() {
            evil[i].prev_head_hash = evil[i - 1].hash();
        }
        let full = RefCheckpoint::from_heads(repo, &honest);
        let grafted = RefCheckpoint::from_heads_windowed(repo, &evil, 2);
        match compare_checkpoints(&full, &grafted).unwrap() {
            CompareResult::Forked { at_seq, reason } => {
                assert_eq!(at_seq, Some(8));
                assert_eq!(reason, ForkReason::DivergentHead);
            }
            other => panic!("expected Forked inside the shared window, got {other:?}"),
        }
    }

    /// Two grafted views agree only about their shared window; heads below it
    /// are outside the authorized projection and are not asserted either way.
    #[test]
    fn grafted_pair_commits_only_to_its_shared_window() {
        let repo = RepoId([4u8; 32]);
        let honest = chain_of(9, 3);
        let a = RefCheckpoint::from_heads_windowed(repo, &honest, 2);
        let b = RefCheckpoint::from_heads_windowed(repo, &honest, 2);
        assert_eq!(
            compare_checkpoints(&a, &b).unwrap(),
            CompareResult::Consistent
        );
        // Neither view carries the pre-window heads at all, so nothing about
        // epochs 0–1 is being asserted.
        assert!(a.chain.iter().all(|e| e.epoch >= 2));
    }

    #[test]
    fn non_overlapping_windows_are_incomparable_not_consistent() {
        let repo = RepoId([4u8; 32]);
        let heads = chain_of(6, 3); // epochs 0,0,0,1,1,1
        let early = RefCheckpoint::from_heads_windowed(repo, &heads[..3], 0);
        let late = RefCheckpoint::from_heads_windowed(repo, &heads[3..], 1);
        assert_eq!(
            compare_checkpoints(&early, &late).unwrap(),
            CompareResult::WindowDisjoint
        );
    }

    #[test]
    fn a_hole_in_an_export_fails_the_internal_chain_check() {
        let repo = RepoId([4u8; 32]);
        let heads = chain_of(6, 6);
        let full = RefCheckpoint::from_heads(repo, &heads);
        let mut holed = full.clone();
        holed.chain.remove(3);
        // Re-bind so this is a well-formed export, not a detectable tamper.
        holed.tip_binding = bind_checkpoint(&holed);
        assert!(
            compare_checkpoints(&full, &holed).is_err(),
            "a gap must fail the internal chain check"
        );
    }

    #[test]
    fn a_tampered_export_is_rejected() {
        let repo = RepoId([4u8; 32]);
        let heads = chain_of(3, 3);
        let mut cp = RefCheckpoint::from_heads(repo, &heads);
        cp.chain[1].hash = HeadHash([0x55; 64]);
        assert!(compare_checkpoints(&cp, &cp).is_err());
    }

    /// A delivery-service Commit partition: identical head chains, different
    /// exporters at the same epoch number.
    #[test]
    fn epoch_witness_mismatch_is_forked() {
        let repo = RepoId([7u8; 32]);
        let heads = chain_of(3, 3);
        let a = RefCheckpoint::from_heads(repo, &heads).with_epoch_witness(0, &[0xAA; 32]);
        let b = RefCheckpoint::from_heads(repo, &heads).with_epoch_witness(0, &[0xBB; 32]);
        match compare_checkpoints(&a, &b).unwrap() {
            CompareResult::Forked { reason, .. } => {
                assert_eq!(reason, ForkReason::EpochWitness { epoch: 0 })
            }
            other => panic!("expected a Forked epoch witness, got {other:?}"),
        }
        // The same witness on both sides stays consistent.
        let c = RefCheckpoint::from_heads(repo, &heads).with_epoch_witness(0, &[0xAA; 32]);
        assert_eq!(
            compare_checkpoints(&a, &c).unwrap(),
            CompareResult::Consistent
        );
    }
}
