//! The read path must reject a malicious host's sequencing, not just decrypt it.
//!
//! AEAD says each head decrypts under an epoch key. It says nothing about the
//! *sequence*, so a host can still roll a reader back, drop heads from the
//! middle, or replay a head into another epoch, using heads that decrypt
//! perfectly. `verify_fetched_heads` is what makes those detectable, and these
//! tests pin it: an honest run is accepted, and every tampered run is refused.
//!
//! Completeness (a truncated-but-valid prefix) cannot be caught here — a prefix
//! of an honest chain *is* an honest chain. That is caught in
//! `fetch_bundles_since` by cross-checking the host's advertised tip, which
//! needs a live server and is covered by the end-to-end harness.

use safehub_client::mls_local::EpochMaterial;
use safehub_client::policy::epoch_tag_bytes;
use safehub_client::verify_fetched_heads;
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};

const EPOCH: u64 = 7;

fn material() -> EpochMaterial {
    EpochMaterial {
        epoch: EPOCH,
        transport: [3u8; 48],
        refs_mac: [5u8; 32],
        history_from: 0,
        dkr_token: vec![],
        prior_transport: Default::default(),
        prior_refs_mac: Default::default(),
    }
}

/// A head with a correct epoch tag, chained onto `prev`.
fn head(seq: u64, prev: HeadHash, mat: &EpochMaterial) -> RefHead {
    let root = BlobId([seq as u8; 64]);
    RefHead {
        repo_id: RepoId([1u8; 32]),
        seq,
        enc_refs: vec![seq as u8; 16],
        bundle_root: root,
        dek_wrap: vec![2u8; 16],
        prev_head_hash: prev,
        mls_epoch: mat.epoch,
        epoch_tag: epoch_tag_bytes(&mat.refs_mac, mat.epoch, &root, seq),
        non_ff: false,
        pusher_sig: vec![9u8; 8],
        admin_cosig: None,
    }
}

/// `n` correctly chained heads from genesis.
fn honest_chain(n: u64, mat: &EpochMaterial) -> Vec<RefHead> {
    let mut out = Vec::new();
    let mut prev = HeadHash::zero();
    for seq in 1..=n {
        let h = head(seq, prev, mat);
        prev = h.hash();
        out.push(h);
    }
    out
}

#[test]
fn an_honest_chain_is_accepted() {
    let mat = material();
    let heads = honest_chain(6, &mat);
    verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &[])
        .expect("an honest chain from genesis must be accepted");
}

#[test]
fn a_head_dropped_from_the_middle_is_rejected() {
    let mat = material();
    let mut heads = honest_chain(6, &mat);
    heads.remove(3); // drop seq 4
    let err = verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &[])
        .expect_err("a gap in the chain must be rejected");
    assert!(
        err.to_string().contains("chain"),
        "expected a chain error, got: {err}"
    );
}

#[test]
fn a_reordered_chain_is_rejected() {
    let mat = material();
    let mut heads = honest_chain(6, &mat);
    heads.swap(2, 3);
    assert!(
        verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &[]).is_err(),
        "reordered heads must be rejected"
    );
}

#[test]
fn a_tampered_epoch_tag_is_rejected() {
    let mat = material();
    let mut heads = honest_chain(3, &mat);
    heads[1].epoch_tag[0] ^= 0xff;
    assert!(
        verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &[]).is_err(),
        "a head whose epoch MAC does not verify must be rejected"
    );
}

/// A head sealed under one epoch must not be accepted as belonging to another.
///
/// Two distinct cases. Relabelling to an epoch whose key we hold breaks the
/// tag. Relabelling to an epoch beyond our own is refused outright: no honest
/// head can be sealed under an epoch this member has not reached.
#[test]
fn a_head_replayed_into_another_epoch_is_rejected() {
    let mut mat = material();
    mat.prior_refs_mac.insert(EPOCH - 1, vec![6u8; 32]);

    let mut relabelled_to_known = honest_chain(2, &mat);
    relabelled_to_known[1].mls_epoch = EPOCH - 1;
    assert!(
        verify_fetched_heads(&relabelled_to_known, &mat, Some(HeadHash::zero()), &[]).is_err(),
        "relabelling into an epoch we can check must fail the tag"
    );

    let mut relabelled_to_future = honest_chain(2, &mat);
    relabelled_to_future[1].mls_epoch = EPOCH + 1;
    let err = verify_fetched_heads(&relabelled_to_future, &mat, Some(HeadHash::zero()), &[])
        .expect_err("a head claiming an epoch beyond our own must be rejected");
    assert!(
        err.to_string().contains("beyond this member's current epoch"),
        "expected a future-epoch rejection, got: {err}"
    );
}

/// An older epoch whose MAC key was never retained cannot be checked, and is
/// accepted on the AEAD alone. This documents a real limit rather than a bug:
/// mk_e is not DKR-recoverable, so members granted history predating their join
/// hold no key for it, and refusing would lock them out of their own history.
#[test]
fn an_unretained_older_epoch_is_accepted_with_the_tag_unchecked() {
    let mat = material();
    let mut heads = honest_chain(2, &mat);
    heads[1].mls_epoch = EPOCH - 3; // older, no retained mk_e
    verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &[])
        .expect("an unverifiable older epoch must not lock the member out");
}

/// A chain that is internally valid but does not descend from what the reader
/// already holds is a fork, and must not be silently applied over it.
#[test]
fn a_chain_that_does_not_descend_from_the_anchor_is_rejected() {
    let mat = material();
    let heads = honest_chain(3, &mat);
    let foreign_anchor = HeadHash::of(b"some other head this reader never saw");
    let err = verify_fetched_heads(&heads, &mat, Some(foreign_anchor), &[])
        .expect_err("a run that does not descend from the reader's anchor must be rejected");
    assert!(
        err.to_string().contains("chain"),
        "expected a chain error, got: {err}"
    );
}

/// Without an anchor the first head's ancestry cannot be checked, but the rest
/// of the run must still link — a reader with no history is not a reason to
/// accept an arbitrary sequence.
#[test]
fn without_an_anchor_internal_continuity_is_still_enforced() {
    let mat = material();
    let heads = honest_chain(5, &mat);
    verify_fetched_heads(&heads, &mat, None, &[]).expect("an honest run must pass without an anchor");

    let mut broken = honest_chain(5, &mat);
    broken.remove(2);
    assert!(
        verify_fetched_heads(&broken, &mat, None, &[]).is_err(),
        "a gap must be rejected even when the reader holds no anchor"
    );
}

#[test]
fn leaf_signature_is_required_when_roster_keys_are_supplied() {
    use safehub_client::policy::leaf_sign_message;
    use safehub_crypto::mldsa::MlDsa87KeyPair;

    let mat = material();
    let kp = MlDsa87KeyPair::generate().unwrap();
    // Chain hashes include signatures, so sign each head before linking the next.
    let mut heads = Vec::new();
    let mut prev = HeadHash::zero();
    for seq in 1..=2u64 {
        let mut h = head(seq, prev, &mat);
        h.pusher_sig = kp.sign(&leaf_sign_message(&h)).unwrap();
        prev = h.hash();
        heads.push(h);
    }
    let vks = vec![kp.public_key().to_vec()];
    verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &vks)
        .expect("honest leaf signatures must verify under the roster key");

    heads[1].pusher_sig[0] ^= 0xff;
    assert!(
        verify_fetched_heads(&heads, &mat, Some(HeadHash::zero()), &vks).is_err(),
        "tampered leaf signature must be rejected when roster keys are supplied"
    );
}

#[test]
fn an_empty_run_is_not_an_error() {
    let mat = material();
    verify_fetched_heads(&[], &mat, Some(HeadHash::zero()), &[])
        .expect("no new heads is a normal up-to-date fetch, not a failure");
}
