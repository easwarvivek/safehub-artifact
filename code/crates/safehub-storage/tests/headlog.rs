//! Unit tests for durable head-log CAS.

use bytes::Bytes;
use safehub_storage::local::LocalStore;
use safehub_storage::{BlobStore, HeadLog};
use safehub_types::{BlobId, BlobMeta, HeadHash, RefHead, RepoId};

fn sample_head(repo: RepoId, seq: u64, prev: HeadHash) -> RefHead {
    RefHead {
        repo_id: repo,
        seq,
        enc_refs: b"enc".to_vec(),
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

#[tokio::test]
async fn cas_append_persists_canonical_tip() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([7u8; 32]);
    let h1 = sample_head(repo, 1, HeadHash::zero());
    let hash = store.cas_append(h1.clone()).await.unwrap();
    assert_eq!(hash, h1.hash());
    let tip = store.tip(&repo).await.unwrap().unwrap();
    assert_eq!(tip.hash(), h1.hash());
    // Stored tip.bin bytes hash to the same value.
    let tip_path = dir.path().join("heads").join(repo.to_hex()).join("tip.bin");
    let bytes = std::fs::read(&tip_path).unwrap();
    assert_eq!(HeadHash::of(&bytes), h1.hash());
    assert_eq!(safehub_types::decode_ref_head(&bytes).unwrap().hash(), h1.hash());
}

#[tokio::test]
async fn cas_conflict_on_stale_prev() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([3u8; 32]);
    let h1 = sample_head(repo, 1, HeadHash::zero());
    store.cas_append(h1.clone()).await.unwrap();
    let bad = sample_head(repo, 2, HeadHash::zero());
    let err = store.cas_append(bad).await.unwrap_err();
    assert!(matches!(err, safehub_storage::StorageError::CasConflict { .. }));
}

#[tokio::test]
async fn blob_put_if_absent_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let ct = Bytes::from(vec![1u8, 2, 3, 4]);
    let id = BlobId::of_ciphertext(&ct);
    let meta = BlobMeta {
        id,
        size: 4,
        chunk_index: 0,
        chunk_count: 1,
        push_id: "p".into(),
    };
    let a = store.put(meta.clone(), ct.clone()).await.unwrap();
    let b = store.put(meta, ct).await.unwrap();
    assert_eq!(a, b);
    assert!(store.exists(&a).await.unwrap());
}
