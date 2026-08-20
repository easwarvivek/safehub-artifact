//! End-to-end tests for the SGitChar/SGitLine reimplementation.
//!
//! Positive cases check that the protocol does what Figure 6 says. Negative
//! cases check that it refuses what its security argument claims it refuses --
//! a reimplementation that only round-trips is not evidence of the construction.

use sgit_rs::{diff, init, pull, share, update, Member, Variant};
use std::collections::BTreeMap;

fn tree(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn src_file(n: usize, marker: &str) -> String {
    (0..n)
        .map(|i| format!("pub fn unit_{i}(x: &u64) -> u64 {{ let mut o = 0u64; o += 1; {marker} o }}\n"))
        .collect()
}

// ---------------------------------------------------------------- positive ---

#[test]
fn char_variant_round_trips_through_many_updates() {
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let mut plain = tree(&[("a.rs", &src_file(20, "//x")), ("b.rs", "static: unchanged\n")]);
    let mut repo = init(&alice, "rid1", &plain, Variant::Char).unwrap();
    assert_eq!(pull(&alice, &repo, &vk, Variant::Char).unwrap(), plain);

    // Ten successive edits, as their evaluation methodology uses.
    for i in 0..10 {
        let next = tree(&[
            ("a.rs", &src_file(20, &format!("//edit{i}"))),
            ("b.rs", "static: unchanged\n"),
        ]);
        update(&alice, &mut repo, &plain, &next, Variant::Char).unwrap();
        plain = next;
        assert_eq!(
            pull(&alice, &repo, &vk, Variant::Char).unwrap(),
            plain,
            "append-and-replay must reconstruct exactly at update {i}"
        );
    }
    assert_eq!(repo.files["a.rs"].deltas.len(), 10, "each update appends one block");
}

#[test]
fn line_variant_round_trips_and_keeps_versions_self_contained() {
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let plain = tree(&[("a.rs", &src_file(30, "//x"))]);
    let mut repo = init(&alice, "rid2", &plain, Variant::Line).unwrap();
    let next = tree(&[("a.rs", &src_file(30, "//y"))]);
    update(&alice, &mut repo, &plain, &next, Variant::Line).unwrap();
    assert_eq!(pull(&alice, &repo, &vk, Variant::Line).unwrap(), next);
    // SGitLine replaces ciphertext in place, so it accumulates no delta blocks.
    assert!(repo.files["a.rs"].deltas.is_empty(),
            "line variant must not append history-dependent blocks");
    assert!(!repo.files["a.rs"].lines.is_empty());
}

#[test]
fn char_transmits_less_than_line_for_the_same_edit() {
    // The paper's central efficiency claim: l2 <= l1.
    let alice = Member::new("alice");
    let plain = tree(&[("a.rs", &src_file(200, "//x"))]);
    let next = tree(&[("a.rs", &src_file(200, "//x").replacen("o += 1;", "o += 2;", 1))]);

    let mut rc = init(&alice, "r", &plain, Variant::Char).unwrap();
    let cc = update(&alice, &mut rc, &plain, &next, Variant::Char).unwrap();
    let mut rl = init(&alice, "r", &plain, Variant::Line).unwrap();
    let cl = update(&alice, &mut rl, &plain, &next, Variant::Line).unwrap();

    assert!(
        cc.delta_ciphertext_bytes <= cl.delta_ciphertext_bytes,
        "char delta {} should not exceed line delta {}",
        cc.delta_ciphertext_bytes, cl.delta_ciphertext_bytes
    );
}

#[test]
fn update_cost_tracks_the_edit_not_the_file() {
    // This is what separates SGitChar from git-crypt's n_f*L: a one-line change
    // in a large file must not transmit the file.
    let alice = Member::new("alice");
    let big = src_file(4000, "//x");
    let plain = tree(&[("a.rs", &big)]);
    let next = tree(&[("a.rs", &big.replacen("unit_2000", "unit_2000_CHANGED", 1))]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let cost = update(&alice, &mut repo, &plain, &next, Variant::Char).unwrap();
    assert!(
        cost.delta_ciphertext_bytes < big.len() / 20,
        "a one-token edit in a {}-byte file transmitted {} bytes",
        big.len(), cost.delta_ciphertext_bytes
    );
}

#[test]
fn base64_expansion_is_present_and_roughly_a_third() {
    // The paper records Base64 as a ~30% expansion needed to survive a host's
    // format checks. Omitting it would understate every storage number, so its
    // presence is asserted rather than assumed.
    let alice = Member::new("alice");
    let body = src_file(100, "//x");
    let plain = tree(&[("a.rs", &body)]);
    let repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let stored = repo.files["a.rs"].stored_bytes();
    let ratio = stored as f64 / body.len() as f64;
    assert!(ratio > 1.25 && ratio < 1.45, "expansion {ratio:.3} outside the expected ~4/3");
}

#[test]
fn sharing_grants_read_and_write_and_is_signed() {
    let alice = Member::new("alice");
    let plain = tree(&[("a.rs", "x\n")]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let before = repo.tag.sig.clone();
    share(&alice, &mut repo, "bob", true).unwrap();
    assert!(repo.acs.read.contains_key("bob"), "read grant recorded");
    assert!(repo.acs.write.iter().any(|u| u == "bob"), "write grant recorded");
    assert_ne!(repo.tag.sig, before, "the version must be re-signed after sharing");
}

// ---------------------------------------------------------------- negative ---

#[test]
fn a_tampered_ciphertext_fails_verification() {
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let plain = tree(&[("a.rs", &src_file(10, "//x"))]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();

    // A malicious host rewrites stored ciphertext without the signing key.
    let f = repo.files.get_mut("a.rs").unwrap();
    let mut b = f.base.clone().into_bytes();
    let i = b.len() / 2;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    f.base = String::from_utf8(b).unwrap();

    assert!(
        pull(&alice, &repo, &vk, Variant::Char).is_err(),
        "tampered ciphertext must not verify: this is repository integrity"
    );
}

#[test]
fn a_forged_version_from_an_unauthorized_key_is_refused() {
    let alice = Member::new("alice");
    let eve = Member::new("eve");
    let plain = tree(&[("a.rs", "x\n")]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();

    // Eve re-signs the version as herself. She has write access to nothing.
    let next = tree(&[("a.rs", "eve was here\n")]);
    update(&eve, &mut repo, &plain, &next, Variant::Char).unwrap();
    assert_eq!(repo.tag.uid, "eve");
    assert!(
        pull(&alice, &repo, &alice.signer.verifying_key_bytes(), Variant::Char).is_err(),
        "a version authored by someone with no write access must be refused"
    );
}

#[test]
fn a_version_signed_by_the_wrong_key_is_refused() {
    let alice = Member::new("alice");
    let eve = Member::new("eve");
    let plain = tree(&[("a.rs", "x\n")]);
    let repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    assert!(
        pull(&alice, &repo, &eve.signer.verifying_key_bytes(), Variant::Char).is_err(),
        "verification against the wrong verifying key must fail"
    );
}

#[test]
fn a_dropped_delta_block_is_detected() {
    // A host that silently discards an appended block to save storage must not
    // go unnoticed: the Merkle root covers every block.
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let plain = tree(&[("a.rs", &src_file(10, "//x"))]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let next = tree(&[("a.rs", &src_file(10, "//y"))]);
    update(&alice, &mut repo, &plain, &next, Variant::Char).unwrap();
    assert_eq!(repo.files["a.rs"].deltas.len(), 1);

    repo.files.get_mut("a.rs").unwrap().deltas.clear();
    assert!(
        pull(&alice, &repo, &vk, Variant::Char).is_err(),
        "dropping an appended delta must break the signed root"
    );
}

#[test]
fn a_file_deleted_by_the_host_is_detected() {
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let plain = tree(&[("a.rs", "one\n"), ("b.rs", "two\n")]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    repo.files.remove("b.rs");
    assert!(
        pull(&alice, &repo, &vk, Variant::Char).is_err(),
        "repository integrity must cover file deletion, not just file contents"
    );
}

#[test]
fn a_reordered_repository_is_detected() {
    // The signed root covers layout, so renaming a file to swap positions must
    // not verify even though the ciphertext bytes are unchanged.
    let alice = Member::new("alice");
    let vk = alice.signer.verifying_key_bytes();
    let plain = tree(&[("a.rs", "aaa\n"), ("b.rs", "bbb\n")]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let a = repo.files["a.rs"].clone();
    let b = repo.files["b.rs"].clone();
    repo.files.insert("a.rs".into(), b);
    repo.files.insert("b.rs".into(), a);
    assert!(
        pull(&alice, &repo, &vk, Variant::Char).is_err(),
        "layout is part of what is signed"
    );
}

#[test]
fn a_non_member_cannot_read_content() {
    // Confidentiality: without the master key the repository key cannot be
    // derived, so decryption yields something other than the plaintext.
    let alice = Member::new("alice");
    let outsider = Member::new("mallory");
    let body = "SECRET_CANARY_VALUE\n";
    let plain = tree(&[("a.rs", body)]);
    let repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    let got = pull(&outsider, &repo, &alice.signer.verifying_key_bytes(), Variant::Char);
    match got {
        Err(_) => {}
        Ok(t) => assert_ne!(
            t.get("a.rs").map(String::as_str), Some(body),
            "an outsider recovered the plaintext"
        ),
    }
}

#[test]
fn diff_ops_are_the_only_thing_encrypted_in_a_delta_block() {
    // If a delta block were the whole file, the construction would collapse to
    // trivial-enc-sign. Guard against that regressing silently.
    let alice = Member::new("alice");
    let big = src_file(2000, "//x");
    let plain = tree(&[("a.rs", &big)]);
    let next = tree(&[("a.rs", &big.replacen("unit_1000", "unit_1000_X", 1))]);
    let mut repo = init(&alice, "r", &plain, Variant::Char).unwrap();
    update(&alice, &mut repo, &plain, &next, Variant::Char).unwrap();
    let block = &repo.files["a.rs"].deltas[0];
    assert!(
        block.len() < repo.files["a.rs"].base.len() / 10,
        "delta block {} is not small relative to the base {}",
        block.len(), repo.files["a.rs"].base.len()
    );
}

#[test]
fn ops_round_trip_is_required_for_correctness() {
    // ComDiff's stated correctness condition, checked directly on random-ish
    // localized edits rather than only through the protocol.
    let base = src_file(300, "//x");
    for k in [1usize, 7, 99, 250] {
        let edited = base.replacen(&format!("unit_{k}("), &format!("unit_{k}_MOD("), 1);
        let ops = diff::com_diff_char(&base, &edited);
        assert_eq!(diff::apply_chars(&base, &ops), edited, "char ops must reconstruct");
        let lops = diff::com_diff_line(&base, &edited);
        assert_eq!(diff::apply_lines(&base, &lops), edited, "line ops must reconstruct");
    }
}
