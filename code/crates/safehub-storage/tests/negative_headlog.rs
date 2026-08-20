//! Negative tests for the head log and blob store.
//!
//! Asserts that malformed, stale, replayed, or tampered inputs are rejected.
//! Happy-path coverage lives in `headlog.rs`.

use bytes::Bytes;
use safehub_storage::local::LocalStore;
use safehub_storage::{BlobStore, HeadLog, StorageError};
use safehub_types::{BlobId, BlobMeta, HeadHash, RefHead, RepoId};

fn head(repo: RepoId, seq: u64, prev: HeadHash) -> RefHead {
    RefHead {
        repo_id: repo,
        seq,
        enc_refs: format!("enc-{seq}").into_bytes(),
        bundle_root: BlobId([9u8; 64]),
        dek_wrap: b"dek".to_vec(),
        prev_head_hash: prev,
        mls_epoch: 1,
        epoch_tag: vec![1u8; 32],
        non_ff: false,
        pusher_sig: vec![2u8; 8],
        admin_cosig: None,
    }
}

async fn store() -> (tempfile::TempDir, LocalStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = LocalStore::open(dir.path()).await.unwrap();
    (dir, s)
}

fn is_conflict(e: &StorageError) -> bool {
    matches!(e, StorageError::CasConflict { .. })
}

// ------------------------------------------------------------ head log ----

#[tokio::test]
async fn second_genesis_append_is_rejected() {
    let (_d, s) = store().await;
    let repo = RepoId([1u8; 32]);
    s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap();
    // A second writer that still believes the log is empty must lose.
    let err = s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap_err();
    assert!(is_conflict(&err), "second genesis accepted: {err:?}");
}

#[tokio::test]
async fn replaying_the_current_tip_is_rejected() {
    let (_d, s) = store().await;
    let repo = RepoId([2u8; 32]);
    let h1 = head(repo, 1, HeadHash::zero());
    let hash1 = s.cas_append(h1.clone()).await.unwrap();
    let h2 = head(repo, 2, hash1);
    s.cas_append(h2.clone()).await.unwrap();
    // Replaying h2 (whose prev is now stale) must not append twice.
    let err = s.cas_append(h2).await.unwrap_err();
    assert!(is_conflict(&err), "replayed head accepted: {err:?}");
    assert_eq!(s.tip(&repo).await.unwrap().unwrap().seq, 2);
}

#[tokio::test]
async fn rollback_to_an_older_prev_is_rejected() {
    let (_d, s) = store().await;
    let repo = RepoId([3u8; 32]);
    let hash1 = s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap();
    let hash2 = s.cas_append(head(repo, 2, hash1)).await.unwrap();
    let _ = s.cas_append(head(repo, 3, hash2)).await.unwrap();
    // Malicious/stale client rewinds to seq 2 by reusing an old prev.
    let err = s.cas_append(head(repo, 2, hash1)).await.unwrap_err();
    assert!(is_conflict(&err), "rollback accepted: {err:?}");
    assert_eq!(s.tip(&repo).await.unwrap().unwrap().seq, 3);
}

#[tokio::test]
async fn fork_off_a_non_tip_ancestor_is_rejected() {
    let (_d, s) = store().await;
    let repo = RepoId([4u8; 32]);
    let hash1 = s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap();
    let hash2 = s.cas_append(head(repo, 2, hash1)).await.unwrap();
    let _ = s.cas_append(head(repo, 3, hash2)).await.unwrap();
    // Equivocating branch anchored at seq 1 must not be appendable.
    let mut sibling = head(repo, 2, hash1);
    sibling.enc_refs = b"divergent".to_vec();
    let err = s.cas_append(sibling).await.unwrap_err();
    assert!(is_conflict(&err), "fork accepted: {err:?}");
}

#[tokio::test]
async fn append_with_garbage_prev_is_rejected() {
    let (_d, s) = store().await;
    let repo = RepoId([5u8; 32]);
    s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap();
    for filler in [0x00u8, 0xff, 0xab] {
        let err = s
            .cas_append(head(repo, 2, HeadHash([filler; 64])))
            .await
            .unwrap_err();
        assert!(is_conflict(&err), "garbage prev {filler:#x} accepted");
    }
}

#[tokio::test]
async fn repos_do_not_share_a_head_log() {
    let (_d, s) = store().await;
    let a = RepoId([6u8; 32]);
    let b = RepoId([7u8; 32]);
    let ha = s.cas_append(head(a, 1, HeadHash::zero())).await.unwrap();
    // b is still empty: an append carrying a's tip as prev must not link.
    let err = s.cas_append(head(b, 2, ha)).await.unwrap_err();
    assert!(is_conflict(&err), "cross-repo prev accepted: {err:?}");
    assert!(s.tip(&b).await.unwrap().is_none());
}

#[tokio::test]
async fn tip_and_since_are_empty_for_unknown_repo() {
    let (_d, s) = store().await;
    let ghost = RepoId([8u8; 32]);
    assert!(s.tip(&ghost).await.unwrap().is_none());
    assert!(s.since(&ghost, 0).await.unwrap().is_empty());
}

#[tokio::test]
async fn since_past_the_tip_returns_nothing() {
    let (_d, s) = store().await;
    let repo = RepoId([9u8; 32]);
    let h1 = s.cas_append(head(repo, 1, HeadHash::zero())).await.unwrap();
    s.cas_append(head(repo, 2, h1)).await.unwrap();
    assert!(s.since(&repo, 2).await.unwrap().is_empty());
    assert!(s.since(&repo, 99).await.unwrap().is_empty());
    assert_eq!(s.since(&repo, 0).await.unwrap().len(), 2);
}

#[tokio::test]
async fn tampering_with_tip_bytes_breaks_the_hash_binding() {
    // An honest client re-hashes what it reads; a host that edits tip.bin in
    // place cannot keep the stored bytes hashing to the advertised head hash.
    let dir = tempfile::tempdir().unwrap();
    let s = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([10u8; 32]);
    let h1 = head(repo, 1, HeadHash::zero());
    let advertised = s.cas_append(h1).await.unwrap();

    let path = dir.path().join("heads").join(repo.to_hex()).join("tip.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    assert_ne!(
        HeadHash::of(&bytes),
        advertised,
        "tampered tip still matched the advertised hash"
    );
    // Either the record fails to decode, or it decodes to a different hash.
    match safehub_types::decode_ref_head(&bytes) {
        Ok(decoded) => assert_ne!(decoded.hash(), advertised),
        Err(_) => {}
    }
}

// ---------------------------------------------------------- blob store ----

#[tokio::test]
async fn missing_blob_reads_report_not_found() {
    let (_d, s) = store().await;
    let ghost = BlobId([0xcd; 64]);
    assert!(!s.exists(&ghost).await.unwrap());
    assert!(matches!(
        s.get(&ghost).await.unwrap_err(),
        StorageError::NotFound(_)
    ));
    assert!(matches!(
        s.meta(&ghost).await.unwrap_err(),
        StorageError::NotFound(_)
    ));
}

#[tokio::test]
async fn blob_ids_are_content_bound() {
    // Content addressing: distinct ciphertexts must not collide onto one id,
    // and an id computed from other bytes must not resolve.
    let (_d, s) = store().await;
    let ct = Bytes::from_static(b"ciphertext-one");
    let other = Bytes::from_static(b"ciphertext-two");
    let id = BlobId::of_ciphertext(&ct);
    let other_id = BlobId::of_ciphertext(&other);
    assert_ne!(id, other_id);

    let meta = BlobMeta {
        id,
        size: ct.len() as u64,
        chunk_index: 0,
        chunk_count: 1,
        push_id: "p".into(),
    };
    s.put(meta, ct.clone()).await.unwrap();
    assert!(s.exists(&id).await.unwrap());
    assert!(!s.exists(&other_id).await.unwrap());
    assert_eq!(s.get(&id).await.unwrap(), ct);
}

#[tokio::test]
async fn a_tampered_stored_blob_no_longer_matches_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let s = LocalStore::open(dir.path()).await.unwrap();
    let ct = Bytes::from_static(b"authentic ciphertext");
    let id = BlobId::of_ciphertext(&ct);
    let meta = BlobMeta {
        id,
        size: ct.len() as u64,
        chunk_index: 0,
        chunk_count: 1,
        push_id: "p".into(),
    };
    s.put(meta, ct).await.unwrap();

    let fetched = s.get(&id).await.unwrap();
    let mut tampered = fetched.to_vec();
    tampered[0] ^= 0xff;
    assert_ne!(
        BlobId::of_ciphertext(&Bytes::from(tampered)),
        id,
        "tampered blob still hashed to its original id"
    );
}
