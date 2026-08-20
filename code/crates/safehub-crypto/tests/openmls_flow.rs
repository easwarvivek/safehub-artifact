#![cfg(feature = "openmls")]

use safehub_crypto::MlsIdentity;

#[test]
fn category_five_group_join_message_and_rotation() {
    let repo_id = [0x42; 32];
    let alice = MlsIdentity::generate("alice-device").unwrap();
    let bob = MlsIdentity::generate("bob-device").unwrap();
    let bob_key_package = bob.key_package().unwrap();

    let mut alice_group = alice.create_group(repo_id).unwrap();
    let invitation = alice_group.add_member(&bob_key_package).unwrap();
    let mut bob_group = bob.join(&invitation).unwrap();

    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(bob_group.member_count(), 2);
    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(
        alice_group.export_epoch_keys(&repo_id).unwrap().transport(),
        bob_group.export_epoch_keys(&repo_id).unwrap().transport()
    );

    let encrypted = alice_group
        .protect_application(b"encrypted pull-request metadata")
        .unwrap();
    assert_eq!(
        bob_group.unprotect_application(&encrypted).unwrap(),
        b"encrypted pull-request metadata"
    );

    let before = *alice_group.export_epoch_keys(&repo_id).unwrap().transport();
    let rotation = alice_group.rotate().unwrap();
    bob_group.apply_commit(&rotation.commit).unwrap();
    let alice_after = alice_group.export_epoch_keys(&repo_id).unwrap();
    let bob_after = bob_group.export_epoch_keys(&repo_id).unwrap();

    assert_ne!(&before, alice_after.transport());
    assert_eq!(alice_after.transport(), bob_after.transport());
    assert_eq!(alice_after.refs(), bob_after.refs());
}
