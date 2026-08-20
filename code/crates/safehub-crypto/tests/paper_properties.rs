//! Executable restatement of the crypto-layer claims of the paper.
//!
//! Each test names the claim it defends, so a functionality change that breaks
//! a property the UC proof relies on fails here rather than in review. This
//! file is the crypto half; the ref-manifest and fork half lives in
//! `safehub-client/tests/paper_properties_refhead.rs`.
//!
//! Claim map (paper -> test):
//!   Def. 4 / Table IX  parameters          -> params_match_published_claim
//!   Thm. 7             DKR correctness     -> dkr_interval_derives_exactly_its_epochs
//!   Thm. 8 / Lem. 4    window soundness    -> forward_block_*, backward_block_*
//!   Thm. 8             independence        -> blocks_sample_independent_roots
//!   Lem. 4             completeness        -> capped_interval_keeps_authorized_epochs
//!   Thm. 6(i)          INT-CTXT            -> tampered_ciphertext_is_rejected
//!   Thm. 6(ii)         key commitment      -> second_key_cannot_open_ciphertext
//!   Thm. 6(iii)        equivocability      -> body_is_pad_xor_committed_plaintext
//!   §D                 seal cap 2^32       -> seal_cap_is_two_to_the_32
//!   §D                 domain separation   -> domain_labels_are_prefixed_and_distinct
//!   §VI-A              provenance          -> build_reports_category5_suite

use safehub_crypto::{
    aead_backend_name, cap_interval, domain_label, derive_head_seal_key, CommittingAead,
    DkrInterval, DualKeyRegression, IntervalDkr, AEAD_KEY_LEN, DKR_SEGMENT_CAPACITY,
    MAX_SEALS_PER_KEY, MLS_CIPHERSUITE_NAME, OPENMLS_LINKED, SEC_PARAM_BITS, SEC_PARAM_LEN,
    TAG_LEN,
};

const COMMIT_BLOCK_LEN: usize = 48;

fn key_of(byte: u8) -> [u8; AEAD_KEY_LEN] {
    [byte; AEAD_KEY_LEN]
}

// ---------------------------------------------------------------- parameters

/// Definition 4 and Table IX: lambda = 384 for DKR/RO nodes, 256-bit tags,
/// 2^20 DKR segment capacity. The margins table is only meaningful if the code
/// agrees with it.
#[test]
fn params_match_published_claim() {
    assert_eq!(SEC_PARAM_BITS, 384, "lambda must be 384 (Def. 4)");
    assert_eq!(SEC_PARAM_LEN, 48, "lambda in bytes");
    assert_eq!(TAG_LEN, 32, "256-bit tags (Table IX row 'Tag / MAC forgery')");
    assert_eq!(
        DKR_SEGMENT_CAPACITY,
        1 << 20,
        "N = 2^20 (Table XI); Prop. 1's q_seg budget is stated against this"
    );
}

/// Section VI-A: a build that claims the Category-5 path must name the paper's
/// suite. Gated on the feature, because `cargo test -p safehub-crypto` with
/// default features deliberately exercises the stub; the shipped binaries and
/// the eval harness link `openmls`, and `scripts/run_property_suite.sh` runs
/// this file both ways.
#[cfg(feature = "openmls")]
#[test]
fn build_reports_category5_suite() {
    assert!(OPENMLS_LINKED, "feature on but linkage flag says otherwise");
    assert_eq!(
        MLS_CIPHERSUITE_NAME,
        "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87"
    );
}

/// The reported ciphersuite name must never disagree with what is linked. This
/// is the check that keeps `shub crypto report` -- and therefore the provenance
/// block in every published JSON -- honest in either build configuration.
#[test]
fn ciphersuite_name_matches_linkage() {
    if OPENMLS_LINKED {
        assert_eq!(
            MLS_CIPHERSUITE_NAME,
            "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87",
            "a Category-5 build must name the Category-5 suite"
        );
    } else {
        assert!(
            MLS_CIPHERSUITE_NAME.starts_with("none"),
            "a build without OpenMLS must not name a ciphersuite it cannot run, \
             got {MLS_CIPHERSUITE_NAME}"
        );
    }
}

/// Section D: the transport is the RO-pad construction, because Lemma 1 case
/// (a) needs to reopen a published ciphertext. If this ever reads as AES-GCM
/// the equivocation hop H3->H4 no longer goes through and the appendix claim
/// about the standard backend has become the deployed claim.
#[test]
fn deployed_transport_is_the_equivocable_backend() {
    let backend = aead_backend_name();
    assert!(
        backend.contains("hkdf"),
        "deployed transport must be the RO-pad construction, got {backend}"
    );
    assert!(
        !backend.to_ascii_lowercase().contains("gcm"),
        "AES-GCM is committing on the message; it cannot serve Lemma 1(a)"
    );
}

// ------------------------------------------------------------------- DKR/GKP

/// Theorem 7: an honest token for [from, to] derives exactly the epoch keys in
/// that closed interval and rejects everything outside it.
#[test]
fn dkr_interval_derives_exactly_its_epochs() {
    let mut dkr = IntervalDkr::default();
    dkr.init().expect("init");
    let interval = dkr.advance(10).expect("advance");

    for e in interval.from..=interval.to {
        assert!(
            dkr.derive_epoch_key(&interval, e).is_ok(),
            "epoch {e} inside [{}, {}] must derive",
            interval.from,
            interval.to
        );
    }
    assert!(
        dkr.derive_epoch_key(&interval, interval.to + 1).is_err(),
        "epoch above the interval must not derive (Thm. 7 soundness)"
    );

    // Derivation is a deterministic function of (token, epoch).
    let a = dkr.derive_epoch_key(&interval, 5).unwrap();
    let b = dkr.derive_epoch_key(&interval, 5).unwrap();
    assert_eq!(a, b, "derivation must be deterministic");
    let c = dkr.derive_epoch_key(&interval, 6).unwrap();
    assert_ne!(a, c, "distinct epochs must give distinct keys");
}

/// Theorem 8 / Lemma 4 (soundness, forward direction): after a Remove inserts
/// a forward block at epoch e, a token issued before the block derives no key
/// at or beyond e. This is what makes "removed users receive no post-removal
/// interval" true rather than a policy statement.
/// C6 — which segment owns the epoch at which the removal commits.
///
/// Rule: the removal commits at `e0` and the new segment begins at `e1 = e0+1`,
/// so `e0` is the removed member's last decryptable epoch and `e1` its first
/// forbidden one. Both sides are asserted, because a rule that only forbids
/// "after removal" leaves the boundary epoch undefined and a reader cannot tell
/// which side of the cut a payload sealed during the commit falls on.
#[test]
fn removal_epoch_boundary_is_e0_decryptable_e1_forbidden() {
    let mut dkr = IntervalDkr::with_seed([21u8; SEC_PARAM_LEN]);
    dkr.init().expect("init");
    let e0 = 5u64;
    let retained = dkr.advance(e0).expect("advance to e0");
    let capped = cap_interval(&retained, e0);

    // e0 is inside the removed member's window and stays openable: removal is
    // not retroactive.
    let at_e0 = dkr
        .derive_epoch_key(&capped, e0)
        .expect("e0 must remain decryptable for the removed member");
    let reference_e0 = dkr.derive_epoch_key(&retained, e0).expect("reference e0");
    assert_eq!(at_e0, reference_e0, "e0 is the last decryptable epoch");

    // The commit advances to e1 and re-roots the segment.
    dkr.forward_block(e0 + 1).expect("rekey at e1");
    let post = dkr.advance(e0 + 1).expect("advance to e1");

    // e1 is forbidden by the window check, and forging a wider window does not
    // help because the root changed.
    assert!(
        dkr.derive_epoch_key(&capped, e0 + 1).is_err(),
        "e1 must be outside the capped window"
    );
    let forged = DkrInterval { from: capped.from, to: e0 + 1, token: capped.token };
    assert_ne!(
        dkr.derive_epoch_key(&forged, e0 + 1).expect("forged derive"),
        dkr.derive_epoch_key(&post, e0 + 1).expect("real derive"),
        "widening the window must not recover the post-removal key"
    );
}

#[test]
fn forward_block_denies_post_removal_epochs() {
    let mut dkr = IntervalDkr::default();
    dkr.init().expect("init");
    let pre = dkr.advance(5).expect("advance");
    let pre_key_at_3 = dkr.derive_epoch_key(&pre, 3).expect("in-window");

    dkr.forward_block(6).expect("forward block");
    let post = dkr.advance(9).expect("advance past block");

    // The removed member's retained token cannot reach the new segment.
    let capped = cap_interval(&pre, 5);
    assert!(
        dkr.derive_epoch_key(&capped, 7).is_err(),
        "pre-block token must not derive a post-block epoch (Thm. 8)"
    );

    // And the new segment is not the old one continued.
    let post_key_at_7 = dkr.derive_epoch_key(&post, 7).expect("new segment");
    assert_ne!(
        pre_key_at_3, post_key_at_7,
        "forward block must sample a fresh independent root"
    );
}

/// Theorem 8 / Lemma 4 (soundness, backward direction): a forward-only join at
/// epoch h gets a backward block, so it holds no key material below h --
/// including when the joiner rewrites `from` on its own token, which is the
/// attack the "widening" clause of section C-E calls out.
#[test]
fn backward_block_denies_pre_join_epochs_even_when_widened() {
    let mut dkr = IntervalDkr::default();
    dkr.init().expect("init");
    let pre = dkr.advance(20).expect("advance");

    // The real pre-join keys, taken from the same chain the joiner is grafted
    // onto. Comparing against a freshly seeded instance instead would make this
    // test pass for the trivial reason that two random seeds differ.
    let real_at_10 = dkr.derive_epoch_key(&pre, 10).expect("pre-join key exists");

    let joiner = dkr.backward_block(21).expect("backward block");
    assert_eq!(joiner.from, 21, "joiner window starts at the join epoch");

    assert!(
        dkr.derive_epoch_key(&joiner, 20).is_err(),
        "pre-join epoch must not derive from a forward-only token"
    );

    // Widening `from` on the joiner's own token may satisfy the range check,
    // but the root is independent, so whatever it derives must not be the key
    // that actually sealed epoch 10.
    let widened = DkrInterval {
        from: 1,
        to: joiner.to,
        token: joiner.token,
    };
    if let Ok(forged_at_10) = dkr.derive_epoch_key(&widened, 10) {
        assert_ne!(
            real_at_10, forged_at_10,
            "a widened forward-only token must not reproduce pre-join keys \
             (section C-E widening clause; Thm. 8)"
        );
    }
}

/// Theorem 8: forward and backward blocks each sample a fresh independent
/// root, so knowledge of one segment's tokens is useless for another. Two
/// blocks in a row must not collide.
#[test]
fn blocks_sample_independent_roots() {
    let mut dkr = IntervalDkr::default();
    dkr.init().expect("init");
    dkr.advance(4).expect("advance");
    let gen0 = dkr.segment_generation();

    dkr.forward_block(5).expect("fwd");
    let seg_a = dkr.advance(6).expect("advance");
    let gen1 = dkr.segment_generation();

    dkr.forward_block(7).expect("fwd again");
    let seg_b = dkr.advance(8).expect("advance");
    let gen2 = dkr.segment_generation();

    assert!(gen0 < gen1 && gen1 < gen2, "each block opens a new segment");

    let ka = dkr.derive_epoch_key(&seg_a, 6);
    let kb = dkr.derive_epoch_key(&seg_b, 8).expect("current segment");
    if let Ok(ka) = ka {
        assert_ne!(ka, kb, "independent segments must not share keys");
    }
}

/// Lemma 4 (completeness): capping an interval at the Remove epoch preserves
/// exactly the epochs the member was already authorized to read. Removal must
/// not retroactively revoke authorized history -- Fsafehub's Remove handler
/// caps open intervals, it does not delete them.
#[test]
fn capped_interval_keeps_authorized_epochs() {
    let mut dkr = IntervalDkr::default();
    dkr.init().expect("init");
    let full = dkr.advance(10).expect("advance");
    let capped = cap_interval(&full, 7);

    assert_eq!(capped.to, 7, "cap lands on the Remove epoch");
    assert_eq!(capped.from, full.from, "cap must not move the lower bound");
    for e in capped.from..=capped.to {
        assert!(
            dkr.derive_epoch_key(&capped, e).is_ok(),
            "authorized epoch {e} must remain derivable after capping"
        );
    }
    assert!(
        dkr.derive_epoch_key(&capped, 8).is_err(),
        "capped interval must not derive beyond the cap"
    );
}

// ------------------------------------------------------------ transport AEAD

/// Theorem 6(i) INT-CTXT: a modified ciphertext must not open. Checks every
/// region of the wire format, since a tag that only covers part of the body is
/// the classic way this fails.
#[test]
fn tampered_ciphertext_is_rejected() {
    let key = key_of(0x11);
    let aad = b"safehub-v1:refhead";
    let pt = b"ref map: refs/heads/main -> deadbeef".to_vec();
    let ct = CommittingAead::seal(&key, aad, &pt).expect("seal");
    assert_eq!(CommittingAead::open(&key, aad, &ct).unwrap(), pt);

    for idx in [0usize, 6, 12, ct.len() / 2, ct.len() - 1] {
        let mut bad = ct.clone();
        bad[idx] ^= 0x01;
        assert!(
            CommittingAead::open(&key, aad, &bad).is_err(),
            "flipping byte {idx} must fail authentication"
        );
    }

    // Associated data is bound: chunk splicing across pushes must not verify.
    assert!(
        CommittingAead::open(&key, b"safehub-v1:other", &ct).is_err(),
        "AD mismatch must fail (chunk AD binds repo/push_id/i/n)"
    );

    // Truncation must not verify.
    assert!(
        CommittingAead::open(&key, aad, &ct[..ct.len() - 1]).is_err(),
        "truncated ciphertext must fail"
    );
}

/// Theorem 6(ii) key commitment: one ciphertext must not open under a second
/// key. Without this, hybrid H4->H5 loses the key-commitment component of
/// eps_ae and a malicious inviter could show two members different plaintexts.
#[test]
fn second_key_cannot_open_ciphertext() {
    let aad = b"safehub-v1:bundle-chunk";
    let pt = b"objects".to_vec();
    let ct = CommittingAead::seal(&key_of(0x22), aad, &pt).expect("seal");
    for other in [0x00u8, 0x21, 0x23, 0xff] {
        assert!(
            CommittingAead::open(&key_of(other), aad, &ct).is_err(),
            "ciphertext must be committing on the key"
        );
    }
}

/// Theorem 6(iii): the body is `pad XOR (commit_block || plaintext)`, which is
/// exactly the structure the simulator programs to reopen a published
/// ciphertext. The observable consequence is a fixed 48-byte commitment block
/// plus a 12-byte nonce and a 32-byte tag of expansion, and a body that is
/// length-preserving in the plaintext.
#[test]
fn body_is_pad_xor_committed_plaintext() {
    let key = key_of(0x33);
    let aad = b"safehub-v1:collab";
    for len in [0usize, 1, 64, 4096] {
        let pt = vec![0x5Au8; len];
        let ct = CommittingAead::seal(&key, aad, &pt).expect("seal");
        assert_eq!(
            ct.len(),
            12 + COMMIT_BLOCK_LEN + len + TAG_LEN,
            "expansion must be nonce + 48-byte commit block + tag"
        );
        assert_eq!(CommittingAead::open(&key, aad, &ct).unwrap(), pt);
    }

    // Equal-length plaintexts give equal-length ciphertexts: the simulator
    // emits equal-length zero-encryptions from leakage alone (H3->H4).
    let a = CommittingAead::seal(&key, aad, &vec![0u8; 1000]).unwrap();
    let b = CommittingAead::seal(&key, aad, &vec![7u8; 1000]).unwrap();
    assert_eq!(a.len(), b.len(), "leakage must be length-only");
    assert_ne!(a, b, "distinct plaintexts must not give identical ciphertext");
}

/// Section D: the per-head seal subkey cap is 2^32, the bound under which the
/// IND-CPA step assumes non-repeating deterministic nonces.
#[test]
fn seal_cap_is_two_to_the_32() {
    assert_eq!(MAX_SEALS_PER_KEY, 1u64 << 32);
}

/// Section D: every domain-separation label is prefixed `safehub-v1:` and the
/// labels are pairwise distinct, so no two contexts can be made to hash or
/// sign the same byte string.
#[test]
fn domain_labels_are_prefixed_and_distinct() {
    let labels = [
        "refhead",
        "epoch-tag",
        "dek-wrap",
        "refs-digest",
        "bundle-chunk",
        "consol",
        "collab",
        "admin-cosig",
        "aead-keys",
        "aead-pad",
        "head-seal",
        "cas-obj-key",
        "cas-obj",
        "keylog",
        "device-anchor",
        "keypackage-pin",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for l in labels {
        let full = domain_label(l);
        assert!(
            full.starts_with("safehub-v1:"),
            "label {l} must carry the version prefix, got {full}"
        );
        assert!(seen.insert(full.clone()), "duplicate domain label: {full}");
    }
}

/// Section D / Figure 7: `K_e` is never an AEAD key itself; each head derives
/// its own subkey, and distinct seq values must give distinct subkeys.
#[test]
fn head_seal_subkeys_are_per_sequence() {
    let epoch_key = key_of(0x44);
    let k0 = derive_head_seal_key(&epoch_key, 0).expect("seq 0 subkey");
    let k1 = derive_head_seal_key(&epoch_key, 1).expect("seq 1 subkey");
    let k1_again = derive_head_seal_key(&epoch_key, 1).expect("seq 1 again");
    assert_ne!(k0, k1, "per-seq subkeys must differ");
    assert_eq!(k1, k1_again, "subkey derivation must be deterministic");
    assert_ne!(
        k0, epoch_key,
        "the epoch key must not be used as a seal key directly"
    );

    // A ciphertext sealed under seq 0 must not open under seq 1.
    let aad = b"safehub-v1:refs-digest";
    let ct = CommittingAead::seal(&k0, aad, b"refs").expect("seal");
    assert!(
        CommittingAead::open(&k1, aad, &ct).is_err(),
        "seal subkeys must be independent across heads"
    );
}
