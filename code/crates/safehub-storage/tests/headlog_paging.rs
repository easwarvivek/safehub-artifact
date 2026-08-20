//! Head-log paging contract.
//!
//! `heads_since` is served in bounded pages. A client that reads only the first
//! page silently truncates history: a clone of a repository with more heads
//! than the page size checks out an old tip and reports success, which is
//! indistinguishable from a correct clone. These tests pin the contract the
//! client's paging loop depends on — ascending order, strict `after`
//! exclusivity, and no gaps or repeats when walking page by page.

use safehub_storage::local::LocalStore;
use safehub_storage::HeadLog;
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};

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

/// Append `n` chained heads and return the store.
async fn store_with_heads(dir: &std::path::Path, repo: RepoId, n: u64) -> LocalStore {
    let store = LocalStore::open(dir).await.unwrap();
    let mut prev = HeadHash::zero();
    for seq in 1..=n {
        let h = sample_head(repo, seq, prev);
        prev = store.cas_append(h).await.unwrap();
    }
    store
}

#[tokio::test]
async fn since_returns_every_head_in_ascending_order() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([11u8; 32]);
    let store = store_with_heads(dir.path(), repo, 250).await;

    let heads = store.since(&repo, 0).await.unwrap();
    assert_eq!(heads.len(), 250, "since(0) must not truncate at the store");
    let seqs: Vec<u64> = heads.iter().map(|h| h.seq).collect();
    assert_eq!(seqs, (1..=250).collect::<Vec<_>>(), "ascending, no gaps");
}

#[tokio::test]
async fn since_is_exclusive_on_after() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([12u8; 32]);
    let store = store_with_heads(dir.path(), repo, 120).await;

    let heads = store.since(&repo, 100).await.unwrap();
    assert_eq!(heads.first().map(|h| h.seq), Some(101), "after is exclusive");
    assert_eq!(heads.len(), 20);
}

/// The client walks pages by advancing `after` to the last seq it saw. If that
/// walk ever repeated or skipped a head, a clone would replay a broken bundle
/// chain or miss commits outright.
#[tokio::test]
async fn paged_walk_covers_the_log_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([13u8; 32]);
    let total = 512u64;
    let store = store_with_heads(dir.path(), repo, total).await;

    for page in [1usize, 7, 100, 500] {
        let mut seen: Vec<u64> = Vec::new();
        let mut cursor = 0u64;
        loop {
            let mut batch = store.since(&repo, cursor).await.unwrap();
            batch.truncate(page); // what the route does
            if batch.is_empty() {
                break;
            }
            cursor = batch.last().unwrap().seq;
            seen.extend(batch.iter().map(|h| h.seq));
        }
        assert_eq!(
            seen,
            (1..=total).collect::<Vec<_>>(),
            "page size {page}: walk must cover every seq exactly once"
        );
    }
}

#[tokio::test]
async fn since_past_the_tip_is_empty_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RepoId([14u8; 32]);
    let store = store_with_heads(dir.path(), repo, 10).await;

    assert!(store.since(&repo, 10).await.unwrap().is_empty());
    assert!(store.since(&repo, 9999).await.unwrap().is_empty());
}
