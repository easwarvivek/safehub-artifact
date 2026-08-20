//! Full MLS group semantics against the real vendored OpenMLS stack.
//!
//! Exercises the lifecycle SafeHub actually depends on — create, KeyPackage,
//! Add, Welcome/join, Commit application, epoch advance, exporter agreement,
//! application messages, and Rotate/PCS — plus the negative cases for each.
//!
//! Requires the `openmls` feature (enabled by default for product builds).
#![cfg(feature = "openmls")]

use safehub_crypto::mls::{MlsIdentity, OpenMlsGroup};

const REPO: [u8; 32] = [0xA7; 32];

fn founder(repo: [u8; 32]) -> OpenMlsGroup {
    MlsIdentity::generate(b"alice")
        .expect("identity")
        .create_group(repo)
        .expect("create group")
}

/// Add `name` to `group`, returning the joined group. Mirrors the real invite
/// path: KeyPackage -> Add -> Welcome -> join. Note that `add_member` merges
/// the committer's own pending commit, so the adder must NOT `apply_commit`;
/// only other existing members do.
fn add_and_join(group: &mut OpenMlsGroup, name: &[u8]) -> OpenMlsGroup {
    let joiner = MlsIdentity::generate(name).expect("identity");
    let kp = joiner.key_package().expect("key package");
    let invitation = group.add_member(&kp).expect("add member");
    joiner.join(&invitation).expect("join")
}

// ------------------------------------------------------------ lifecycle ----

#[test]
fn new_group_starts_at_epoch_zero_with_one_member() {
    let g = founder(REPO);
    assert_eq!(g.epoch(), 0);
    assert_eq!(g.member_count(), 1);
    assert_eq!(g.group_id_bytes().unwrap(), REPO, "group id binds the repo");
}

#[test]
fn add_advances_epoch_and_membership_on_both_sides() {
    let mut alice = founder(REPO);
    let bob = add_and_join(&mut alice, b"bob");

    assert_eq!(alice.epoch(), 1, "adder must advance on Commit");
    assert_eq!(bob.epoch(), 1, "joiner must land in the same epoch");
    assert_eq!(alice.member_count(), 2);
    assert_eq!(bob.member_count(), 2);
    assert_eq!(bob.group_id_bytes().unwrap(), REPO);
}

#[test]
fn members_in_the_same_epoch_export_identical_keys() {
    let mut alice = founder(REPO);
    let bob = add_and_join(&mut alice, b"bob");

    let ka = alice.export_epoch_keys(&REPO).unwrap();
    let kb = bob.export_epoch_keys(&REPO).unwrap();
    assert_eq!(ka.transport(), kb.transport(), "transport exporter diverged");
    assert_eq!(ka.refs(), kb.refs(), "refs exporter diverged");
    // The two labels must not collide.
    assert_ne!(&ka.transport()[..32], &ka.refs()[..]);
}

#[test]
fn exports_are_bound_to_the_repo_id() {
    let alice = founder(REPO);
    let mine = alice.export_epoch_keys(&REPO).unwrap();
    let other = alice.export_epoch_keys(&[0x5B; 32]).unwrap();
    assert_ne!(
        mine.transport(),
        other.transport(),
        "exporter must be bound to the repository id"
    );
    assert_ne!(mine.refs(), other.refs());
}

#[test]
fn three_member_group_stays_in_lockstep() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");

    // Alice adds Carol; Bob must apply the same Commit to keep up.
    let carol_id = MlsIdentity::generate(b"carol").unwrap();
    let kp = carol_id.key_package().unwrap();
    let inv = alice.add_member(&kp).unwrap(); // alice merges her own commit
    let carol = carol_id.join(&inv).unwrap();
    bob.apply_commit(&inv.commit).unwrap();

    for (who, g) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        assert_eq!(g.epoch(), 2, "{who} epoch");
        assert_eq!(g.member_count(), 3, "{who} member count");
    }
    let ka = alice.export_epoch_keys(&REPO).unwrap();
    for (who, g) in [("bob", &bob), ("carol", &carol)] {
        let k = g.export_epoch_keys(&REPO).unwrap();
        assert_eq!(ka.transport(), k.transport(), "{who} transport");
        assert_eq!(ka.refs(), k.refs(), "{who} refs");
    }
}

// ------------------------------------------------- application messages ----

#[test]
fn application_messages_round_trip_between_members() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");

    let msg = alice.protect_application(b"pull request #1 body").unwrap();
    let got = bob.unprotect_application(&msg).unwrap();
    assert_eq!(got, b"pull request #1 body");
}

#[test]
fn a_non_member_cannot_unprotect_application_traffic() {
    let mut alice = founder(REPO);
    let mut outsider = founder(REPO); // same repo id, different group instance
    let msg = alice.protect_application(b"members only").unwrap();
    assert!(
        outsider.unprotect_application(&msg).is_err(),
        "outsider decrypted group application traffic"
    );
}

#[test]
fn application_message_replay_is_rejected() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");
    let msg = alice.protect_application(b"once").unwrap();
    assert_eq!(bob.unprotect_application(&msg).unwrap(), b"once");
    assert!(
        bob.unprotect_application(&msg).is_err(),
        "replayed application message was accepted twice"
    );
}

#[test]
fn tampered_application_ciphertext_is_rejected() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");
    let msg = alice.protect_application(b"authentic body").unwrap();
    let mut bad = msg.clone();
    let n = bad.0.len();
    bad.0[n / 2] ^= 0x01;
    assert!(bob.unprotect_application(&bad).is_err());
}

// ------------------------------------------------------ rotate / PCS -------

#[test]
fn rotate_advances_the_epoch_and_replaces_exporters() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");

    let before = alice.export_epoch_keys(&REPO).unwrap();
    let epoch_before = alice.epoch();

    let change = alice.rotate().unwrap(); // alice merges her own self-update
    bob.apply_commit(&change.commit).unwrap();

    assert_eq!(alice.epoch(), epoch_before + 1, "rotate must advance epoch");
    assert_eq!(bob.epoch(), alice.epoch(), "peer must follow the rotation");

    let after = alice.export_epoch_keys(&REPO).unwrap();
    assert_ne!(
        before.transport(),
        after.transport(),
        "PCS heal must replace the transport exporter"
    );
    assert_ne!(before.refs(), after.refs());
    assert_eq!(
        after.transport(),
        bob.export_epoch_keys(&REPO).unwrap().transport(),
        "post-rotation exporters must agree"
    );
}

#[test]
fn every_epoch_yields_a_distinct_exporter() {
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");
    let mut seen = vec![*alice.export_epoch_keys(&REPO).unwrap().transport()];
    for _ in 0..3 {
        let change = alice.rotate().unwrap();
        bob.apply_commit(&change.commit).unwrap();
        let k = *alice.export_epoch_keys(&REPO).unwrap().transport();
        assert!(!seen.contains(&k), "exporter repeated across epochs");
        seen.push(k);
    }
}

#[test]
fn a_stale_member_cannot_read_traffic_from_an_epoch_it_never_applied() {
    // Bob misses the rotation Commit; his group state stays behind and he must
    // not silently decrypt post-rotation traffic.
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");
    let change = alice.rotate().unwrap();
    let _ = change; // deliberately NOT applied by bob

    let msg = alice.protect_application(b"post-rotation").unwrap();
    assert!(
        bob.unprotect_application(&msg).is_err(),
        "stale member decrypted traffic from an unapplied epoch"
    );
    assert_ne!(
        alice.export_epoch_keys(&REPO).unwrap().transport(),
        bob.export_epoch_keys(&REPO).unwrap().transport(),
        "stale member must not share the new epoch exporter"
    );
}

// -------------------------------------------------------- commit hygiene ---

#[test]
fn applying_the_same_commit_twice_is_rejected() {
    // A receiving member applies once; the replay must be refused.
    let mut alice = founder(REPO);
    let mut bob = add_and_join(&mut alice, b"bob");
    let carol_id = MlsIdentity::generate(b"carol").unwrap();
    let inv = alice.add_member(&carol_id.key_package().unwrap()).unwrap();
    bob.apply_commit(&inv.commit).unwrap();
    assert!(
        bob.apply_commit(&inv.commit).is_err(),
        "replayed Commit advanced the group a second time"
    );
}

#[test]
fn garbage_commit_and_key_package_bytes_are_rejected() {
    let mut alice = founder(REPO);
    assert!(alice.apply_commit(b"").is_err());
    assert!(alice.apply_commit(b"not an mls message").is_err());
    assert!(alice.add_member(b"").is_err());
    assert!(alice.add_member(b"not a key package").is_err());
}

#[test]
fn truncated_commit_bytes_are_rejected() {
    let mut alice = founder(REPO);
    let joiner = MlsIdentity::generate(b"bob").unwrap();
    let inv = alice.add_member(&joiner.key_package().unwrap()).unwrap();
    let cut = inv.commit.len() / 2;
    assert!(alice.apply_commit(&inv.commit[..cut]).is_err());
}

#[test]
fn joining_with_a_tampered_welcome_fails() {
    let mut alice = founder(REPO);
    let joiner = MlsIdentity::generate(b"bob").unwrap();
    let mut inv = alice.add_member(&joiner.key_package().unwrap()).unwrap();
    let n = inv.welcome.len();
    inv.welcome[n / 2] ^= 0x01;
    assert!(joiner.join(&inv).is_err(), "tampered Welcome was accepted");
}

// ------------------------------------------------------- leaf signatures ---

#[test]
fn each_member_has_a_distinct_leaf_key_that_signs_verifiably() {
    use safehub_crypto::mldsa::verify;
    let mut alice = founder(REPO);
    let bob = add_and_join(&mut alice, b"bob");

    let vk_a = alice.leaf_verifying_key();
    let vk_b = bob.leaf_verifying_key();
    assert_ne!(vk_a, vk_b, "leaf keys must be per-device");

    let msg = b"safehub-v1:refhead|test";
    let sig_a = alice.sign_detached(msg).unwrap();
    assert!(verify(&vk_a, msg, &sig_a).is_ok());
    // Attribution: Bob's leaf key must not validate Alice's signature.
    assert!(
        verify(&vk_b, msg, &sig_a).is_err(),
        "leaf signature verified under another member's key"
    );
}

// --------------------------------------------------------------- gaps ------

/// KNOWN GAP: the MLS wrapper exposes no member removal.
///
/// `OpenMlsGroup` offers `add_member`, `rotate`, and `apply_commit`, but no
/// `remove_member`, even though the vendored OpenMLS provides
/// `MlsGroup::remove_members`. Consequently `sh repo remove-member` performs a
/// server-side ACL deletion only (`client.remove_collaborator`) and merely
/// prints a recommendation to run `sh repo rotate` afterwards.
///
/// Un-ignore once the wrapper exposes removal and the CLI issues a real
/// admin-signed Remove commit.
#[test]
#[ignore = "KNOWN GAP: no MLS remove_member; removal is a server ACL call plus a manual rotate"]
fn removing_a_member_should_evict_their_leaf_from_the_group() {
    let mut alice = founder(REPO);
    let bob = add_and_join(&mut alice, b"bob");
    assert_eq!(alice.member_count(), 2);
    let _ = bob;

    // Intended once removal exists:
    //   let change = alice.remove_member(&bob_leaf).unwrap();
    //   assert_eq!(alice.member_count(), 1);
    //   assert!(bob.unprotect_application(&alice.protect_application(b"x")?).is_err());
    panic!("OpenMlsGroup exposes no remove_member; cryptographic eviction is unimplemented");
}
