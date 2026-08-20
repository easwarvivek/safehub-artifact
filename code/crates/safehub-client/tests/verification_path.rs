//! The complete client-side acceptance path for a `RefHead`.
//!
//! A client accepts a head only after every one of these checks passes:
//!   1. leaf ML-DSA-87 signature over the canonical head fields,
//!   2. epoch MAC under the exporter `refs` key,
//!   3. hash-chain descent from the client's last-seen anchor,
//!   4. recomputed fast-forward status matching the sender-declared bit,
//!   5. admin co-signature when the update is non-fast-forward,
//!   6. Compare against a peer checkpoint (fork/equivocation detection).
//!
//! Each check is asserted to accept an honest head and to reject every
//! tampering that check is responsible for. Keys come from a real OpenMLS
//! group, so this exercises the production exporter path rather than stubs.

use hmac::{Hmac, Mac};
use safehub_client::{
    admin_cosig_sign, admin_cosig_verify, compare_checkpoints, refs_digest,
    roster_digest,
    verify_force_push_policy, verify_pusher_sig, CompareResult, EncryptedRefsMap, RefCheckpoint,
};
use safehub_crypto::mldsa::MlDsa87KeyPair;
use safehub_crypto::mls::{MlsIdentity, OpenMlsGroup};
use safehub_types::{domain_label, BlobId, HeadHash, RefHead, RepoId};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const REPO_BYTES: [u8; 32] = [0x3C; 32];

fn group() -> OpenMlsGroup {
    MlsIdentity::generate(b"alice")
        .unwrap()
        .create_group(REPO_BYTES)
        .unwrap()
}

/// Epoch MAC exactly as `build_push_plan` computes it.
fn epoch_tag(refs_mac: &[u8], epoch: u64, root: &BlobId, seq: u64) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(refs_mac).unwrap();
    mac.update(domain_label("epoch-tag").as_bytes());
    mac.update(&epoch.to_le_bytes());
    mac.update(&root.0);
    mac.update(&seq.to_le_bytes());
    mac.finalize().into_bytes()[..32].to_vec()
}

fn verify_epoch_tag(head: &RefHead, refs_mac: &[u8]) -> bool {
    epoch_tag(refs_mac, head.mls_epoch, &head.bundle_root, head.seq) == head.epoch_tag
}

/// Build a fully authenticated head: real epoch MAC + real leaf signature.
fn signed_head(g: &OpenMlsGroup, refs_mac: &[u8], seq: u64, prev: HeadHash, non_ff: bool) -> RefHead {
    let root = BlobId([0x11; 64]);
    let epoch = g.epoch();
    let mut head = RefHead {
        repo_id: RepoId(REPO_BYTES),
        seq,
        enc_refs: format!("enc-refs-{seq}").into_bytes(),
        bundle_root: root,
        dek_wrap: b"wrapped-dek".to_vec(),
        prev_head_hash: prev,
        mls_epoch: epoch,
        epoch_tag: epoch_tag(refs_mac, epoch, &root, seq),
        non_ff,
        pusher_sig: vec![],
        admin_cosig: None,
    };
    head.pusher_sig = g
        .sign_detached(&safehub_client::leaf_sign_message(&head))
        .unwrap();
    head
}

/// The whole acceptance path, in the order a client runs it.
fn accept(
    head: &RefHead,
    leaf_vk: &[u8],
    refs_mac: &[u8],
    anchor: HeadHash,
    recomputed_non_ff: bool,
    admin_vk: Option<&[u8]>,
    roster: &[Vec<u8>],
) -> Result<(), String> {
    verify_pusher_sig(head, leaf_vk).map_err(|e| format!("leaf sig: {e}"))?;
    if !verify_epoch_tag(head, refs_mac) {
        return Err("epoch MAC mismatch".into());
    }
    if head.prev_head_hash != anchor {
        return Err("chain descent: prev does not match anchor".into());
    }
    let refs = EncryptedRefsMap::default();
    verify_force_push_policy(head, head.non_ff, recomputed_non_ff, admin_vk, &refs, roster)
        .map_err(|e| format!("force-push policy: {e}"))?;
    Ok(())
}

// ------------------------------------------------------- the happy path ----

#[test]
fn an_honest_head_passes_every_check() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let head = signed_head(&g, keys.refs(), 1, HeadHash::zero(), false);
    accept(
        &head,
        &g.leaf_verifying_key(),
        keys.refs(),
        HeadHash::zero(),
        false,
        None,
        &g.member_signature_keys(),
    )
    .expect("honest head must be accepted");
}

// ------------------------------------------------- 1. leaf signature ------

#[test]
fn leaf_signature_check_rejects_every_field_mutation() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let base = signed_head(&g, keys.refs(), 1, HeadHash::zero(), false);
    assert!(verify_pusher_sig(&base, &vk).is_ok());

    let mutate: Vec<(&str, Box<dyn Fn(&mut RefHead)>)> = vec![
        ("seq", Box::new(|h: &mut RefHead| h.seq += 1)),
        ("enc_refs", Box::new(|h: &mut RefHead| h.enc_refs.push(0xAA))),
        ("bundle_root", Box::new(|h: &mut RefHead| h.bundle_root = BlobId([0x22; 64]))),
        ("dek_wrap", Box::new(|h: &mut RefHead| h.dek_wrap.push(0xBB))),
        ("prev", Box::new(|h: &mut RefHead| h.prev_head_hash = HeadHash([0x33; 64]))),
        ("mls_epoch", Box::new(|h: &mut RefHead| h.mls_epoch += 1)),
        ("epoch_tag", Box::new(|h: &mut RefHead| h.epoch_tag[0] ^= 0x01)),
        ("non_ff", Box::new(|h: &mut RefHead| h.non_ff = !h.non_ff)),
        ("repo_id", Box::new(|h: &mut RefHead| h.repo_id = RepoId([0x44; 32]))),
    ];
    for (field, f) in mutate {
        let mut h = base.clone();
        f(&mut h);
        assert!(
            verify_pusher_sig(&h, &vk).is_err(),
            "leaf signature survived mutation of {field}"
        );
    }
}

#[test]
fn leaf_signature_check_rejects_missing_and_foreign_signatures() {
    let g = group();
    let other = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();

    let mut unsigned = signed_head(&g, keys.refs(), 1, HeadHash::zero(), false);
    unsigned.pusher_sig.clear();
    assert!(verify_pusher_sig(&unsigned, &vk).is_err(), "unsigned head accepted");

    // A head signed by a different device must not verify under this leaf key.
    let foreign = signed_head(&other, keys.refs(), 1, HeadHash::zero(), false);
    assert!(
        verify_pusher_sig(&foreign, &vk).is_err(),
        "another device's leaf signature verified"
    );
}

// ----------------------------------------------------- 2. epoch MAC ------

#[test]
fn epoch_mac_binds_epoch_root_and_seq() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let head = signed_head(&g, keys.refs(), 4, HeadHash::zero(), false);
    assert!(verify_epoch_tag(&head, keys.refs()));

    // Wrong key (e.g. another epoch's exporter).
    assert!(!verify_epoch_tag(&head, &[0u8; 32]));

    for (field, mutated) in [
        ("epoch", RefHead { mls_epoch: head.mls_epoch + 1, ..head.clone() }),
        ("seq", RefHead { seq: head.seq + 1, ..head.clone() }),
        ("bundle_root", RefHead { bundle_root: BlobId([0x99; 64]), ..head.clone() }),
    ] {
        assert!(
            !verify_epoch_tag(&mutated, keys.refs()),
            "epoch MAC survived mutation of {field}"
        );
    }
}

#[test]
fn epoch_mac_from_a_different_epoch_is_rejected() {
    let mut alice = group();
    let mut bob = {
        let joiner = MlsIdentity::generate(b"bob").unwrap();
        let inv = alice.add_member(&joiner.key_package().unwrap()).unwrap();
        joiner.join(&inv).unwrap()
    };
    let e1 = alice.export_epoch_keys(&REPO_BYTES).unwrap();
    let head = signed_head(&alice, e1.refs(), 1, HeadHash::zero(), false);

    // Rotate: the refs exporter changes, so the old tag must no longer verify.
    let change = alice.rotate().unwrap();
    bob.apply_commit(&change.commit).unwrap();
    let e2 = alice.export_epoch_keys(&REPO_BYTES).unwrap();
    assert_ne!(e1.refs(), e2.refs());
    assert!(
        !verify_epoch_tag(&head, e2.refs()),
        "stale epoch tag verified under the rotated exporter"
    );
}

// -------------------------------------------------- 3. chain descent ------

#[test]
fn chain_descent_rejects_rollback_and_forks() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();

    let h1 = signed_head(&g, keys.refs(), 1, HeadHash::zero(), false);
    let anchor = h1.hash();
    let h2 = signed_head(&g, keys.refs(), 2, anchor, false);
    assert!(accept(&h2, &vk, keys.refs(), anchor, false, None, &g.member_signature_keys()).is_ok());

    // Rollback: a head that builds on genesis when the anchor has advanced.
    let stale = signed_head(&g, keys.refs(), 2, HeadHash::zero(), false);
    let err = accept(&stale, &vk, keys.refs(), anchor, false, None, &g.member_signature_keys()).unwrap_err();
    assert!(err.contains("chain descent"), "unexpected error: {err}");

    // Fork: a head anchored on an unrelated predecessor.
    let forked = signed_head(&g, keys.refs(), 2, HeadHash([0x77; 64]), false);
    assert!(accept(&forked, &vk, keys.refs(), anchor, false, None, &g.member_signature_keys()).is_err());
}

// ------------------------------------------- 4./5. force-push policy ------

#[test]
fn a_non_ff_head_without_an_admin_cosignature_is_rejected() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let admin = MlDsa87KeyPair::generate().unwrap();

    let head = signed_head(&g, keys.refs(), 2, HeadHash::zero(), true);
    // recomputed_non_ff = true, but no co-signature attached.
    let err = accept(&head, &vk, keys.refs(), HeadHash::zero(), true, Some(admin.public_key()), &g.member_signature_keys())
        .unwrap_err();
    assert!(err.contains("missing admin co-signature"), "got: {err}");
}

#[test]
fn a_head_that_lies_about_being_fast_forward_is_rejected() {
    // Sender declares non_ff = false while the verifier recomputes non-FF.
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let head = signed_head(&g, keys.refs(), 2, HeadHash::zero(), false);
    let err = accept(&head, &vk, keys.refs(), HeadHash::zero(), true, None, &g.member_signature_keys()).unwrap_err();
    assert!(err.contains("falsely labeled"), "got: {err}");
}

#[test]
fn a_non_ff_head_is_rejected_when_no_admin_key_is_known() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let admin = MlDsa87KeyPair::generate().unwrap();
    let mut head = signed_head(&g, keys.refs(), 2, HeadHash::zero(), true);
    let refs = EncryptedRefsMap::default();
    head.admin_cosig = Some(
        admin_cosig_sign(
            &admin,
            &head.repo_id,
            head.mls_epoch,
            "push",
            head.seq,
            &head.prev_head_hash,
            &refs_digest(&refs),
            &roster_digest(&g.member_signature_keys()),
        )
        .unwrap(),
    );
    let err = accept(&head, &vk, keys.refs(), HeadHash::zero(), true, None, &g.member_signature_keys()).unwrap_err();
    assert!(err.contains("admin verifying key required"), "got: {err}");
}

#[test]
fn a_non_ff_head_cosigned_by_the_wrong_admin_is_rejected() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let real_admin = MlDsa87KeyPair::generate().unwrap();
    let impostor = MlDsa87KeyPair::generate().unwrap();

    let mut head = signed_head(&g, keys.refs(), 2, HeadHash::zero(), true);
    let refs = EncryptedRefsMap::default();
    head.admin_cosig = Some(
        admin_cosig_sign(
            &impostor,
            &head.repo_id,
            head.mls_epoch,
            "push",
            head.seq,
            &head.prev_head_hash,
            &refs_digest(&refs),
            &roster_digest(&g.member_signature_keys()),
        )
        .unwrap(),
    );
    assert!(
        accept(&head, &vk, keys.refs(), HeadHash::zero(), true, Some(real_admin.public_key()), &g.member_signature_keys())
            .is_err(),
        "co-signature from a non-admin key was accepted"
    );
}

#[test]
fn a_properly_cosigned_non_ff_head_is_accepted() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let vk = g.leaf_verifying_key();
    let admin = MlDsa87KeyPair::generate().unwrap();

    let mut head = signed_head(&g, keys.refs(), 2, HeadHash::zero(), true);
    let refs = EncryptedRefsMap::default();
    head.admin_cosig = Some(
        admin_cosig_sign(
            &admin,
            &head.repo_id,
            head.mls_epoch,
            "push",
            head.seq,
            &head.prev_head_hash,
            &refs_digest(&refs),
            &roster_digest(&g.member_signature_keys()),
        )
        .unwrap(),
    );
    // Re-sign: attaching the co-signature does not change the leaf message,
    // but the head must still verify end to end.
    accept(&head, &vk, keys.refs(), HeadHash::zero(), true, Some(admin.public_key()), &g.member_signature_keys())
        .expect("correctly co-signed non-FF head must be accepted");
}

#[test]
fn an_admin_cosignature_cannot_be_replayed_onto_another_head() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let admin = MlDsa87KeyPair::generate().unwrap();
    let refs = EncryptedRefsMap::default();
    let h1 = signed_head(&g, keys.refs(), 2, HeadHash::zero(), true);
    let cosig =
        admin_cosig_sign(
            &admin,
            &h1.repo_id,
            h1.mls_epoch,
            "push",
            h1.seq,
            &h1.prev_head_hash,
            &refs_digest(&refs),
            &roster_digest(&g.member_signature_keys()),
        )
        .unwrap();
    assert!(admin_cosig_verify(
        admin.public_key(),
        &h1.repo_id,
        h1.mls_epoch,
        "push",
        h1.seq,
        &h1.prev_head_hash,
        &refs_digest(&refs),
        &roster_digest(&g.member_signature_keys()),
        &cosig
    )
    .is_ok());
    // Same co-signature, different predecessor: must not verify.
    assert!(admin_cosig_verify(
        admin.public_key(),
        &h1.repo_id,
        h1.mls_epoch,
        "push",
        h1.seq,
        &HeadHash([0x66; 64]),
        &refs_digest(&refs),
        &roster_digest(&g.member_signature_keys()),
        &cosig
    )
    .is_err());
}

// ------------------------------------------- 6. Compare / fork detection ---

#[test]
fn compare_flags_equivocating_views_and_accepts_prefixes() {
    let g = group();
    let keys = g.export_epoch_keys(&REPO_BYTES).unwrap();
    let repo = RepoId(REPO_BYTES);

    let h1 = signed_head(&g, keys.refs(), 1, HeadHash::zero(), false);
    let h2 = signed_head(&g, keys.refs(), 2, h1.hash(), false);
    // A divergent h2' at the same seq: the malicious-host split view.
    let mut h2b = signed_head(&g, keys.refs(), 2, h1.hash(), false);
    h2b.enc_refs = b"divergent-view".to_vec();
    assert_ne!(h2.hash(), h2b.hash());

    let alice_view = RefCheckpoint::from_heads(repo, &[h1.clone(), h2.clone()]);
    let bob_view = RefCheckpoint::from_heads(repo, &[h1.clone(), h2b]);
    assert!(
        matches!(
            compare_checkpoints(&alice_view, &bob_view),
            Ok(CompareResult::Forked { .. })
        ),
        "equivocating views were not reported as Forked"
    );

    // A strict prefix (a lagging but honest client) must not be a fork.
    let lagging = RefCheckpoint::from_heads(repo, &[h1]);
    assert!(
        !matches!(
            compare_checkpoints(&alice_view, &lagging),
            Ok(CompareResult::Forked { .. })
        ),
        "an honest lagging prefix was misreported as a fork"
    );
    // Identical views agree.
    assert!(!matches!(
        compare_checkpoints(&alice_view, &alice_view),
        Ok(CompareResult::Forked { .. })
    ));
}
