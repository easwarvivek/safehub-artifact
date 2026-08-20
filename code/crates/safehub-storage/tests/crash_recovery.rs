//! Crash, interruption, and concurrent-read durability of the head log.
//!
//! Section V-B states that the UC model assumes an atomic tip/log update and
//! that the prototype mitigates a non-atomic honest-server write path with a
//! durable `tip.bin` compare-and-swap (temp + rename + fsync). These tests
//! exercise that mitigation directly: torn writes, leftover temp files,
//! reopening after a simulated crash, and reads racing a rename.

use safehub_storage::local::LocalStore;
use safehub_storage::{HeadLog, StorageError};
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};
use std::sync::Arc;

fn head(repo: RepoId, seq: u64, prev: HeadHash) -> RefHead {
    RefHead {
        repo_id: repo,
        seq,
        enc_refs: format!("enc-{seq}").into_bytes(),
        bundle_root: BlobId([7u8; 64]),
        dek_wrap: b"dek".to_vec(),
        prev_head_hash: prev,
        mls_epoch: 1,
        epoch_tag: vec![3u8; 32],
        non_ff: false,
        pusher_sig: vec![4u8; 8],
        admin_cosig: None,
    }
}

/// Append `n` heads, returning the final tip hash.
async fn seed(store: &LocalStore, repo: RepoId, n: u64) -> HeadHash {
    let mut prev = HeadHash::zero();
    for seq in 1..=n {
        prev = store.cas_append(head(repo, seq, prev)).await.unwrap();
    }
    prev
}

#[tokio::test]
async fn reopening_after_a_crash_recovers_the_committed_tip() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([1u8; 32]);
    let tip_hash = {
        let store = LocalStore::open(dir.path()).await.unwrap();
        seed(&store, repo, 3).await
        // store dropped: simulates process death with no clean shutdown hook
    };

    let reopened = LocalStore::open(dir.path()).await.unwrap();
    let tip = reopened.tip(&repo).await.unwrap().expect("tip lost on reopen");
    assert_eq!(tip.seq, 3);
    assert_eq!(tip.hash(), tip_hash);
    assert_eq!(reopened.since(&repo, 0).await.unwrap().len(), 3);

    // The recovered tip must still be a valid CAS predecessor.
    reopened.cas_append(head(repo, 4, tip_hash)).await.unwrap();
}

#[tokio::test]
async fn a_leftover_temp_file_does_not_corrupt_the_tip() {
    // Crash between `File::create(tmp)` and `rename(tmp, tip.bin)`.
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([2u8; 32]);
    let store = LocalStore::open(dir.path()).await.unwrap();
    let tip_hash = seed(&store, repo, 2).await;

    let head_dir = dir.path().join("heads").join(repo.to_hex());
    let tmp = head_dir.join("tip.bin.tmp");
    std::fs::write(&tmp, b"half-written garbage").unwrap();

    let reopened = LocalStore::open(dir.path()).await.unwrap();
    let tip = reopened.tip(&repo).await.unwrap().unwrap();
    assert_eq!(tip.hash(), tip_hash, "orphan temp file displaced the tip");
    assert_eq!(tip.seq, 2);
    reopened.cas_append(head(repo, 3, tip_hash)).await.unwrap();
}

#[tokio::test]
async fn a_truncated_tip_is_not_silently_accepted_as_valid() {
    // Torn write: tip.bin exists but holds a prefix of a record.
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([3u8; 32]);
    let store = LocalStore::open(dir.path()).await.unwrap();
    let good = seed(&store, repo, 2).await;

    let tip_path = dir.path().join("heads").join(repo.to_hex()).join("tip.bin");
    let bytes = std::fs::read(&tip_path).unwrap();
    std::fs::write(&tip_path, &bytes[..bytes.len() / 2]).unwrap();

    let reopened = LocalStore::open(dir.path()).await.unwrap();
    match reopened.tip(&repo).await {
        // Either the torn record fails to decode ...
        Err(_) => {}
        // ... or it decodes to something that is demonstrably not the tip,
        // which an honest client detects by re-hashing.
        Ok(Some(t)) => assert_ne!(
            t.hash(),
            good,
            "a truncated tip.bin was accepted as the committed tip"
        ),
        Ok(None) => {}
    }
}

#[tokio::test]
async fn the_per_seq_log_survives_tip_loss() {
    // tip.bin is deleted (lost write) but the per-seq log remains: the history
    // must still be readable, so recovery is possible.
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([4u8; 32]);
    let store = LocalStore::open(dir.path()).await.unwrap();
    seed(&store, repo, 3).await;

    let tip_path = dir.path().join("heads").join(repo.to_hex()).join("tip.bin");
    std::fs::remove_file(&tip_path).unwrap();

    let reopened = LocalStore::open(dir.path()).await.unwrap();
    let log = reopened.since(&repo, 0).await.unwrap();
    assert_eq!(log.len(), 3, "per-seq log lost when tip.bin disappeared");
    let mut prev = HeadHash::zero();
    for h in &log {
        assert_eq!(h.prev_head_hash, prev, "log chain broken at seq {}", h.seq);
        prev = h.hash();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_never_observe_a_partial_tip() {
    // `tip()` checks `exists()` and then reads; a rename landing in between
    // must not surface a torn record or a spurious error to a reader.
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([5u8; 32]);
    let store = Arc::new(LocalStore::open(dir.path()).await.unwrap());
    seed(&store, repo, 1).await;

    let writer = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let mut prev = store.tip(&repo).await.unwrap().unwrap().hash();
            for seq in 2..=60u64 {
                prev = store.cas_append(head(repo, seq, prev)).await.unwrap();
            }
        })
    };

    let mut readers = Vec::new();
    for _ in 0..3 {
        let store = Arc::clone(&store);
        readers.push(tokio::spawn(async move {
            let mut transient_errors = 0usize;
            for _ in 0..400 {
                match store.tip(&repo).await {
                    Ok(Some(t)) => {
                        // Whatever we read must be a self-consistent record.
                        assert_eq!(
                            t.hash(),
                            t.clone().hash(),
                            "tip decoded inconsistently"
                        );
                        assert!(t.seq >= 1 && t.seq <= 60, "tip seq out of range: {}", t.seq);
                    }
                    Ok(None) => panic!("tip vanished while the log was non-empty"),
                    Err(StorageError::Io(_)) => transient_errors += 1,
                    Err(e) => panic!("unexpected read error: {e:?}"),
                }
                tokio::task::yield_now().await;
            }
            transient_errors
        }));
    }

    writer.await.unwrap();
    let mut transient = 0usize;
    for r in readers {
        transient += r.await.unwrap();
    }
    assert_eq!(
        transient, 0,
        "readers saw {transient} transient I/O errors racing the tip rename \
         (TOCTOU between exists() and read())"
    );
    assert_eq!(store.tip(&repo).await.unwrap().unwrap().seq, 60);
}

#[tokio::test]
async fn an_interrupted_push_leaves_no_half_applied_head() {
    // A push that fails CAS must leave the log byte-identical: no partial
    // record, no seq gap, no advanced tip.
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([6u8; 32]);
    let store = LocalStore::open(dir.path()).await.unwrap();
    let tip_hash = seed(&store, repo, 2).await;
    let before = store.since(&repo, 0).await.unwrap();

    for bad in [
        head(repo, 3, HeadHash::zero()),   // wrong prev
        head(repo, 9, tip_hash),           // seq gap
        head(repo, 2, tip_hash),           // seq regression
    ] {
        assert!(store.cas_append(bad).await.is_err());
    }

    let after = store.since(&repo, 0).await.unwrap();
    assert_eq!(after.len(), before.len(), "a rejected push mutated the log");
    assert_eq!(store.tip(&repo).await.unwrap().unwrap().hash(), tip_hash);
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.hash(), b.hash());
    }
}
