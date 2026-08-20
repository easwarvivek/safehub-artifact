//! Adversarial crypto scenarios (post-removal future secrecy, forward-only).

use safehub_crypto::dkr::{cap_interval, DualKeyRegression, IntervalDkr};
use safehub_crypto::params::SEC_PARAM_LEN;
use safehub_crypto::CommittingAead;

#[test]
fn s2_removed_member_cannot_decrypt_future_ciphertext() {
    // Pre-removal: member holds interval covering epochs 0..=5.
    let mut dkr = IntervalDkr::with_seed([11u8; SEC_PARAM_LEN]);
    let _ = dkr.init().unwrap();
    let pre = dkr.advance(5).unwrap();
    let retained = cap_interval(&pre, 5);
    let k_old = dkr.derive_epoch_key(&retained, 5).unwrap();

    // Post-removal: forward block + new epoch ciphertext under fresh seed.
    dkr.forward_block(6).unwrap();
    let post = dkr.advance(7).unwrap();
    let k_new = dkr.derive_epoch_key(&post, 7).unwrap();
    assert_ne!(k_old, k_new);

    let aad = b"safehub-v1:bundle-chunk|test";
    let ct = CommittingAead::seal(&k_new, aad, b"post-removal secret").unwrap();

    // Malicious server hands ct to removed member with retained keys → fail.
    assert!(CommittingAead::open(&k_old, aad, &ct).is_err());
    assert!(dkr.derive_epoch_key(&retained, 7).is_err());
    // Authorized post-removal member succeeds.
    assert_eq!(
        CommittingAead::open(&k_new, aad, &ct).unwrap(),
        b"post-removal secret"
    );
}

#[test]
fn s3_forward_only_cannot_open_prejoin_epochs() {
    let mut dkr = IntervalDkr::with_seed([13u8; SEC_PARAM_LEN]);
    let _ = dkr.init().unwrap();
    let full = dkr.advance(4).unwrap();
    let k_pre = dkr.derive_epoch_key(&full, 3).unwrap();
    let aad = b"safehub-v1:bundle-chunk|hist";
    let old_ct = CommittingAead::seal(&k_pre, aad, b"pre-join history").unwrap();

    let join = dkr.backward_block(5).unwrap();
    assert_ne!(join.token, full.token);
    assert!(dkr.derive_epoch_key(&join, 3).is_err());
    let k_join = dkr.derive_epoch_key(&join, 5).unwrap();
    assert!(CommittingAead::open(&k_join, aad, &old_ct).is_err());
    // Even a corrupted joiner who widens `from` cannot open pre-join ciphertext.
    let forged = safehub_crypto::dkr::DkrInterval {
        from: 0,
        to: join.to,
        token: join.token,
    };
    let leaked = dkr.derive_epoch_key(&forged, 3).unwrap();
    assert!(CommittingAead::open(&leaked, aad, &old_ct).is_err());
}
