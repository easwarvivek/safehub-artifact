//! Negative tests for the crypto layer.
//!
//! Every test here asserts that an operation *fails* under adversarial or
//! malformed input. Positive-path coverage lives in `vectors.rs` and
//! `openmls_flow.rs`; scenario coverage in `adversarial_scenarios.rs`.

use safehub_crypto::aead::{
    derive_cas_seal_key, derive_head_seal_key, derive_secret_seal_key, AeadError, MAX_SEALS_PER_KEY,
};
use safehub_crypto::dkr::{
    cap_interval, DkrInterval, DualKeyRegression, IntervalDkr,
};
use safehub_crypto::error::CryptoError;
use safehub_crypto::mldsa::{admin_cosig_message, refhead_leaf_message, verify, MlDsa87KeyPair};
use safehub_crypto::params::SEC_PARAM_LEN;
use safehub_crypto::CommittingAead;

const AAD: &[u8] = b"safehub-v1:bundle-chunk|neg";

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn sealed(k: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    CommittingAead::seal(k, AAD, pt).unwrap()
}

// ---------------------------------------------------------------- AEAD ----

#[test]
fn aead_open_rejects_wrong_key() {
    let ct = sealed(&key(1), b"plaintext");
    assert!(matches!(
        CommittingAead::open(&key(2), AAD, &ct),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn aead_open_rejects_wrong_aad() {
    let ct = sealed(&key(1), b"plaintext");
    assert!(matches!(
        CommittingAead::open(&key(1), b"safehub-v1:bundle-chunk|other", &ct),
        Err(AeadError::Decrypt)
    ));
}

#[test]
fn aead_open_rejects_bitflip_in_every_region() {
    let pt = b"a plaintext long enough to span regions";
    let base = sealed(&key(7), pt);
    // nonce (0..12), gcm body+tag (12..len-32), outer hmac tag (len-32..).
    let probes = [0usize, 6, 11, 12, base.len() / 2, base.len() - 33, base.len() - 1];
    for &i in &probes {
        let mut ct = base.clone();
        ct[i] ^= 0x01;
        assert!(
            CommittingAead::open(&key(7), AAD, &ct).is_err(),
            "bitflip at byte {i} was accepted"
        );
    }
    // Unmodified still opens, so the probes above are meaningful.
    assert_eq!(CommittingAead::open(&key(7), AAD, &base).unwrap(), pt);
}

#[test]
fn aead_open_rejects_truncation_and_extension() {
    let base = sealed(&key(3), b"payload");
    for cut in [0usize, 1, 12, base.len() / 2, base.len() - 1] {
        assert!(
            CommittingAead::open(&key(3), AAD, &base[..cut]).is_err(),
            "truncation to {cut} bytes was accepted"
        );
    }
    let mut extended = base.clone();
    extended.push(0x00);
    assert!(CommittingAead::open(&key(3), AAD, &extended).is_err());
}

#[test]
fn aead_open_rejects_reordered_chunks() {
    // AAD binds (repo, push_id, i, n); swapping chunk indices must not verify.
    let k = key(9);
    let aad0 = b"safehub-v1:bundle-chunk|repo|push|0|2";
    let aad1 = b"safehub-v1:bundle-chunk|repo|push|1|2";
    let c0 = CommittingAead::seal(&k, aad0, b"first").unwrap();
    assert!(CommittingAead::open(&k, aad1, &c0).is_err());
}

#[test]
fn aead_key_commitment_binds_ciphertext_to_one_key() {
    // Key commitment: no second key may open a ciphertext sealed under another.
    let ct = sealed(&key(1), b"committed");
    for b in 0u8..64 {
        if b == 1 {
            continue;
        }
        assert!(CommittingAead::open(&key(b), AAD, &ct).is_err());
    }
}

#[test]
fn aead_deterministic_seal_refuses_counter_past_cap() {
    let k = key(5);
    assert!(matches!(
        CommittingAead::seal_deterministic(&k, AAD, b"x", MAX_SEALS_PER_KEY),
        Err(AeadError::CounterExhausted)
    ));
    assert!(matches!(
        CommittingAead::seal_deterministic(&k, AAD, b"x", MAX_SEALS_PER_KEY + 1),
        Err(AeadError::CounterExhausted)
    ));
    // One below the cap is still allowed.
    assert!(CommittingAead::seal_deterministic(&k, AAD, b"x", MAX_SEALS_PER_KEY - 1).is_ok());
}

#[test]
fn head_seal_subkeys_are_distinct_per_seq() {
    // K_e is never an AEAD key directly; each head derives its own subkey, and
    // a subkey for seq must not open a head sealed at another seq.
    let epoch_key = key(21);
    let k10 = derive_head_seal_key(&epoch_key, 10).unwrap();
    let k11 = derive_head_seal_key(&epoch_key, 11).unwrap();
    assert_ne!(k10, k11);
    assert_ne!(k10, epoch_key, "seal subkey must differ from the epoch key");
    let ct = CommittingAead::seal(&k10, AAD, b"head at seq 10").unwrap();
    assert!(CommittingAead::open(&k11, AAD, &ct).is_err());
}

#[test]
fn seal_key_domains_are_separated() {
    // cas-obj, head-seal, and secret-seal keys must not collide.
    let secret = [42u8; 32];
    let cas = derive_cas_seal_key(&secret).unwrap();
    let sec = derive_secret_seal_key(&secret).unwrap();
    let head = derive_head_seal_key(&secret, 0).unwrap();
    assert_ne!(cas, sec);
    assert_ne!(cas, head);
    assert_ne!(sec, head);
    let ct = CommittingAead::seal(&cas, AAD, b"cas object").unwrap();
    assert!(CommittingAead::open(&sec, AAD, &ct).is_err());
    assert!(CommittingAead::open(&head, AAD, &ct).is_err());
}

// ----------------------------------------------------------------- DKR ----

#[test]
fn dkr_rejects_epoch_below_interval() {
    let mut dkr = IntervalDkr::with_seed([1u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    let iv = dkr.advance(5).unwrap();
    let joined = dkr.backward_block(8).unwrap();
    assert!(matches!(
        dkr.derive_epoch_key(&joined, 7),
        Err(CryptoError::EpochOutOfWindow { epoch: 7, .. })
    ));
    // The pre-block interval also cannot reach past its own end.
    assert!(matches!(
        dkr.derive_epoch_key(&iv, 6),
        Err(CryptoError::EpochOutOfWindow { epoch: 6, .. })
    ));
}

#[test]
fn dkr_rejects_epoch_above_interval() {
    let mut dkr = IntervalDkr::with_seed([2u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    let iv = dkr.advance(4).unwrap();
    for e in [5u64, 6, 100, u64::MAX] {
        assert!(
            dkr.derive_epoch_key(&iv, e).is_err(),
            "epoch {e} accepted outside interval"
        );
    }
}

#[test]
fn dkr_rejects_advance_to_past_epoch() {
    let mut dkr = IntervalDkr::with_seed([3u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    dkr.advance(10).unwrap();
    assert!(matches!(
        dkr.advance(9),
        Err(CryptoError::EpochOutOfWindow { epoch: 9, .. })
    ));
}

#[test]
fn dkr_capped_interval_cannot_reach_past_removal() {
    let mut dkr = IntervalDkr::with_seed([4u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    let full = dkr.advance(9).unwrap();
    let capped = cap_interval(&full, 4);
    assert_eq!(capped.to, 4);
    for e in 5..=9u64 {
        assert!(
            dkr.derive_epoch_key(&capped, e).is_err(),
            "capped interval derived epoch {e}"
        );
    }
    assert!(dkr.derive_epoch_key(&capped, 4).is_ok());
}

#[test]
fn dkr_forward_block_denies_all_post_removal_epochs() {
    let mut dkr = IntervalDkr::with_seed([5u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    let pre = cap_interval(&dkr.advance(3).unwrap(), 3);
    dkr.forward_block(4).unwrap();
    let post = dkr.advance(9).unwrap();
    for e in 4..=9u64 {
        assert!(
            dkr.derive_epoch_key(&pre, e).is_err(),
            "removed member derived post-removal epoch {e}"
        );
    }
    // A forged interval that merely widens `to` must not unlock the new segment.
    let forged = DkrInterval {
        from: pre.from,
        to: 9,
        token: pre.token,
    };
    for e in 4..=9u64 {
        let leaked = dkr.derive_epoch_key(&forged, e).unwrap();
        let real = dkr.derive_epoch_key(&post, e).unwrap();
        assert_ne!(
            leaked, real,
            "widening `to` on a stale token recovered epoch {e}"
        );
    }
}

#[test]
fn dkr_backward_block_denies_pre_join_epochs_via_window_check() {
    // The bounds check inside derive_epoch_key does reject pre-join epochs
    // for an honestly-constructed forward-only interval.
    let mut dkr = IntervalDkr::with_seed([6u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    dkr.advance(6).unwrap();
    let joined = dkr.backward_block(7).unwrap();
    assert_eq!(joined.from, 7);
    for e in 0..=6u64 {
        assert!(
            dkr.derive_epoch_key(&joined, e).is_err(),
            "forward-only member derived pre-join epoch {e}"
        );
    }
}

/// Forward-only join issues a distinct segment token: widening `from` cannot
/// recover pre-join epoch keys (cryptographic backward block, not advisory).
#[test]
fn dkr_backward_block_should_be_cryptographic_not_advisory() {
    let mut dkr = IntervalDkr::with_seed([6u8; SEC_PARAM_LEN]);
    dkr.init().unwrap();
    let full = dkr.advance(6).unwrap();
    let joined = dkr.backward_block(7).unwrap();
    assert_ne!(
        joined.token, full.token,
        "forward-only join must issue a distinct segment token"
    );
    for e in 0..=6u64 {
        let forged = DkrInterval {
            from: 0,
            to: joined.to,
            token: joined.token,
        };
        let leaked = dkr.derive_epoch_key(&forged, e).unwrap();
        let real = dkr.derive_epoch_key(&full, e).unwrap();
        assert_ne!(
            leaked, real,
            "widening `from` on the joiner token recovered pre-join epoch {e}"
        );
    }
}

// --------------------------------------------------------------- ML-DSA ----

#[test]
fn mldsa_verify_rejects_tampered_signature() {
    let kp = MlDsa87KeyPair::generate().unwrap();
    let msg = b"safehub-v1:refhead|canonical";
    let mut sig = kp.sign(msg).unwrap();
    assert!(verify(kp.public_key(), msg, &sig).is_ok());
    for i in [0usize, sig.len() / 2, sig.len() - 1] {
        let mut bad = sig.clone();
        bad[i] ^= 0x01;
        assert!(
            verify(kp.public_key(), msg, &bad).is_err(),
            "tampered signature byte {i} verified"
        );
    }
    sig.truncate(sig.len() - 1);
    assert!(verify(kp.public_key(), msg, &sig).is_err());
    assert!(verify(kp.public_key(), msg, &[]).is_err());
}

#[test]
fn mldsa_verify_rejects_wrong_message_and_wrong_key() {
    let kp = MlDsa87KeyPair::generate().unwrap();
    let other = MlDsa87KeyPair::generate().unwrap();
    let sig = kp.sign(b"message one").unwrap();
    assert!(verify(kp.public_key(), b"message two", &sig).is_err());
    assert!(verify(other.public_key(), b"message one", &sig).is_err());
}

#[test]
fn refhead_signature_does_not_transfer_across_fields() {
    // A leaf signature is bound to every field of the head it authorizes;
    // changing any one of them must invalidate it.
    let kp = MlDsa87KeyPair::generate().unwrap();
    let repo = [1u8; 32];
    let root = [2u8; 64];
    let prev = [3u8; 64];
    let base = refhead_leaf_message(&repo, 5, b"refs", &root, b"dek", &prev, 2, b"tag", false);
    let sig = kp.sign(&base).unwrap();
    assert!(verify(kp.public_key(), &base, &sig).is_ok());

    let mutations = vec![
        ("repo", refhead_leaf_message(&[9u8; 32], 5, b"refs", &root, b"dek", &prev, 2, b"tag", false)),
        ("seq", refhead_leaf_message(&repo, 6, b"refs", &root, b"dek", &prev, 2, b"tag", false)),
        ("refs", refhead_leaf_message(&repo, 5, b"REFS", &root, b"dek", &prev, 2, b"tag", false)),
        ("root", refhead_leaf_message(&repo, 5, b"refs", &[9u8; 64], b"dek", &prev, 2, b"tag", false)),
        ("dek", refhead_leaf_message(&repo, 5, b"refs", &root, b"DEK", &prev, 2, b"tag", false)),
        ("prev", refhead_leaf_message(&repo, 5, b"refs", &root, b"dek", &[9u8; 64], 2, b"tag", false)),
        ("epoch", refhead_leaf_message(&repo, 5, b"refs", &root, b"dek", &prev, 3, b"tag", false)),
        ("tag", refhead_leaf_message(&repo, 5, b"refs", &root, b"dek", &prev, 2, b"TAG", false)),
        ("non_ff", refhead_leaf_message(&repo, 5, b"refs", &root, b"dek", &prev, 2, b"tag", true)),
    ];
    for (field, msg) in mutations {
        assert_ne!(msg, base, "mutation of {field} did not change the message");
        assert!(
            verify(kp.public_key(), &msg, &sig).is_err(),
            "signature survived mutation of {field}"
        );
    }
}

#[test]
fn admin_cosig_is_not_reusable_across_heads_or_epochs() {
    let admin = MlDsa87KeyPair::generate().unwrap();
    let repo = [4u8; 32];
    let prev = [5u8; 64];
    let digest = [6u8; 64];
    let msg = admin_cosig_message(&repo, 7, "push", 1, &prev, &digest, &[3u8; 64], 1);
    let sig = admin.sign(&msg).unwrap();
    assert!(verify(admin.public_key(), &msg, &sig).is_ok());

    for (label, other) in [
        ("epoch", admin_cosig_message(&repo, 8, "push", 1, &prev, &digest, &[3u8; 64], 1)),
        ("prev head", admin_cosig_message(&repo, 7, "push", 1, &[9u8; 64], &digest, &[3u8; 64], 1)),
        ("refs digest", admin_cosig_message(&repo, 7, "push", 1, &prev, &[9u8; 64], &[3u8; 64], 1)),
        ("repo", admin_cosig_message(&[9u8; 32], 7, "push", 1, &prev, &digest, &[3u8; 64], 1)),
    ] {
        assert!(
            verify(admin.public_key(), &other, &sig).is_err(),
            "admin co-signature replayed across {label}"
        );
    }
}

#[test]
fn leaf_signature_is_not_a_valid_admin_cosig() {
    // Domain separation: a leaf signature must not satisfy an admin co-sig check
    // even when produced by the same key over the same head fields.
    let kp = MlDsa87KeyPair::generate().unwrap();
    let repo = [1u8; 32];
    let prev = [3u8; 64];
    let digest = [7u8; 64];
    let leaf = refhead_leaf_message(&repo, 5, b"refs", &digest, b"dek", &prev, 2, b"tag", true);
    let leaf_sig = kp.sign(&leaf).unwrap();
    let cosig_msg = admin_cosig_message(&repo, 2, "push", 1, &prev, &digest, &[3u8; 64], 1);
    assert!(verify(kp.public_key(), &cosig_msg, &leaf_sig).is_err());
}
