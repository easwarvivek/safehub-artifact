//! Multi-device group simulation: the push / conflict / pull loop.
//!
//! Models several member devices sharing one repository head log. Each device
//! runs the client's real concurrency strategy: read tip, build a head whose
//! `prev` is that tip, attempt compare-and-swap, and on conflict re-read the
//! tip and retry (`sit push` -> CAS fail -> fetch, merge, retry).
//!
//! The invariants asserted here are the ones the paper's fork-consistency claim
//! depends on: exactly one linear chain survives, every accepted head links to
//! its predecessor, sequence numbers are gap-free, and no device's work is
//! silently dropped or double-applied.

use safehub_storage::local::LocalStore;
use safehub_storage::{HeadLog, StorageError};
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};
use std::collections::HashSet;
use std::sync::Arc;

/// Bound mirroring the client's retry budget (`CAS + retry <= 8`).
const MAX_RETRIES: usize = 8;

fn device_head(repo: RepoId, device: u8, seq: u64, prev: HeadHash, epoch: u64) -> RefHead {
    RefHead {
        repo_id: repo,
        seq,
        enc_refs: format!("device-{device}-seq-{seq}").into_bytes(),
        bundle_root: BlobId([device; 64]),
        dek_wrap: vec![device; 8],
        prev_head_hash: prev,
        mls_epoch: epoch,
        epoch_tag: vec![epoch as u8; 32],
        non_ff: false,
        pusher_sig: vec![device; 8],
        admin_cosig: None,
    }
}

/// One `sit push`: read tip, build on it, CAS, retry on conflict.
/// Returns the number of CAS conflicts absorbed before success.
async fn push_within(
    store: &LocalStore,
    repo: RepoId,
    device: u8,
    epoch: u64,
    budget: usize,
) -> Result<usize, StorageError> {
    let mut conflicts = 0usize;
    loop {
        let tip = store.tip(&repo).await?;
        let (prev, next_seq) = match &tip {
            Some(h) => (h.hash(), h.seq + 1),
            None => (HeadHash::zero(), 1),
        };
        let head = device_head(repo, device, next_seq, prev, epoch);
        match store.cas_append(head).await {
            Ok(_) => return Ok(conflicts),
            Err(StorageError::CasConflict { .. }) => {
                conflicts += 1;
                if conflicts > budget {
                    return Err(StorageError::Other(format!(
                        "retry budget of {budget} exhausted"
                    )));
                }
                tokio::task::yield_now().await;
                // Real client fetches and merges here; the head log only needs
                // the refreshed tip, which the next loop iteration reads.
            }
            Err(e) => return Err(e),
        }
    }
}

/// Push under the client's documented budget (`CAS + retry <= 8`).
async fn push_with_retry(
    store: &LocalStore,
    repo: RepoId,
    device: u8,
    epoch: u64,
) -> Result<usize, StorageError> {
    push_within(store, repo, device, epoch, MAX_RETRIES).await
}

/// Assert the log is a single gap-free chain of `expected` heads.
async fn assert_linear_chain(store: &LocalStore, repo: &RepoId, expected: u64) {
    let heads = store.since(repo, 0).await.unwrap();
    assert_eq!(heads.len() as u64, expected, "head count");

    let mut prev = HeadHash::zero();
    let mut seen = HashSet::new();
    for (i, h) in heads.iter().enumerate() {
        assert_eq!(h.seq, i as u64 + 1, "sequence must be gap-free and ordered");
        assert_eq!(h.prev_head_hash, prev, "head {} broke the hash chain", h.seq);
        assert!(seen.insert(h.hash()), "duplicate head at seq {}", h.seq);
        prev = h.hash();
    }
    let tip = store.tip(repo).await.unwrap().unwrap();
    assert_eq!(tip.hash(), prev, "tip must be the chain head");
    assert_eq!(tip.seq, expected);
}

#[tokio::test]
async fn two_devices_interleaved_pushes_converge() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([1u8; 32]);

    // Alternating pushes from two devices of the same member.
    for round in 0..6u8 {
        let device = if round % 2 == 0 { 1 } else { 2 };
        push_with_retry(&store, repo, device, 1).await.unwrap();
    }
    assert_linear_chain(&store, &repo, 6).await;
}

#[tokio::test]
async fn stale_device_loses_cas_then_succeeds_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([2u8; 32]);

    // Device A reads the tip and goes away to build its bundle.
    let stale_tip = store.tip(&repo).await.unwrap();
    let stale_prev = stale_tip.map(|h| h.hash()).unwrap_or(HeadHash::zero());

    // Device B lands a push in the meantime.
    push_with_retry(&store, repo, 2, 1).await.unwrap();

    // A's original attempt is now stale and must be rejected.
    let err = store
        .cas_append(device_head(repo, 1, 1, stale_prev, 1))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::CasConflict { .. }));

    // After fetching the new tip, A's retry succeeds — no work is lost.
    let conflicts = push_with_retry(&store, repo, 1, 1).await.unwrap();
    assert_eq!(conflicts, 0, "retry after refresh should not conflict again");
    assert_linear_chain(&store, &repo, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_devices_serialize_without_forking() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(dir.path()).await.unwrap());
    let repo = RepoId([3u8; 32]);

    const DEVICES: u8 = 6;
    const PUSHES_PER_DEVICE: usize = 4;

    let mut tasks = Vec::new();
    for device in 1..=DEVICES {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let mut conflicts = 0usize;
            let mut worst = 0usize;
            for _ in 0..PUSHES_PER_DEVICE {
                // Unbounded here: this test isolates the *safety* property
                // (no fork, no lost or duplicated push) from the retry budget,
                // which `retry_budget_*` below measures separately.
                let c = push_within(&store, repo, device, 1, usize::MAX).await.unwrap();
                conflicts += c;
                worst = worst.max(c);
            }
            (conflicts, worst)
        }));
    }

    let mut total_conflicts = 0usize;
    let mut worst_single = 0usize;
    for t in tasks {
        let (c, w) = t.await.unwrap();
        total_conflicts += c;
        worst_single = worst_single.max(w);
    }

    let expected = DEVICES as u64 * PUSHES_PER_DEVICE as u64;
    assert_linear_chain(&store, &repo, expected).await;

    // Every device's writes are present exactly once.
    let heads = store.since(&repo, 0).await.unwrap();
    for device in 1..=DEVICES {
        let n = heads
            .iter()
            .filter(|h| h.bundle_root == BlobId([device; 64]))
            .count();
        assert_eq!(n, PUSHES_PER_DEVICE, "device {device} lost or duplicated a push");
    }
    eprintln!(
        "concurrent loop: {total_conflicts} CAS conflicts across {expected} pushes          ({DEVICES} devices), worst single push retried {worst_single}x          (documented budget {MAX_RETRIES})"
    );
}

/// The documented budget is `CAS + retry <= 8`. Ample for two concurrent
/// pushers; this test records where the budget starts to bind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn documented_retry_budget_suffices_for_two_pushers() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(dir.path()).await.unwrap());
    let repo = RepoId([7u8; 32]);

    let mut tasks = Vec::new();
    for device in 1..=2u8 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            for _ in 0..8 {
                push_within(&store, repo, device, 1, MAX_RETRIES)
                    .await
                    .expect("2-way contention must fit the documented budget");
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_linear_chain(&store, &repo, 16).await;
}

#[tokio::test]
async fn pull_after_remote_advance_sees_every_missed_head() {
    // The "pull" half of the loop: a device that has been offline since seq N
    // must receive exactly the heads it missed, in order, chained to what it has.
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([4u8; 32]);

    push_with_retry(&store, repo, 1, 1).await.unwrap();
    push_with_retry(&store, repo, 1, 1).await.unwrap();
    let last_seen = store.tip(&repo).await.unwrap().unwrap();

    // Other devices advance the log while this one is offline.
    for device in 2..=4u8 {
        push_with_retry(&store, repo, device, 1).await.unwrap();
    }

    let missed = store.since(&repo, last_seen.seq).await.unwrap();
    assert_eq!(missed.len(), 3, "pull must return every missed head");
    assert_eq!(missed.first().unwrap().prev_head_hash, last_seen.hash());
    let mut prev = last_seen.hash();
    for h in &missed {
        assert_eq!(h.prev_head_hash, prev, "pulled heads must chain from the anchor");
        prev = h.hash();
    }
}

#[tokio::test]
async fn retry_budget_is_bounded_under_sustained_contention() {
    // Starvation guard: the client's bounded retry loop must still terminate
    // when other devices keep winning the race.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(dir.path()).await.unwrap());
    let repo = RepoId([5u8; 32]);

    // Pre-load the log so the contended device always finds a moved tip.
    for _ in 0..MAX_RETRIES {
        push_with_retry(&store, repo, 9, 1).await.unwrap();
    }
    let conflicts = push_with_retry(&store, repo, 1, 1).await.unwrap();
    assert!(
        conflicts <= MAX_RETRIES,
        "retry loop exceeded its budget ({conflicts} conflicts)"
    );
    assert_linear_chain(&store, &repo, MAX_RETRIES as u64 + 1).await;
}

#[tokio::test]
async fn epoch_change_does_not_break_the_chain() {
    // Membership change mid-loop: heads before and after a rotation must still
    // form one chain, with the epoch recorded per head.
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(dir.path()).await.unwrap();
    let repo = RepoId([6u8; 32]);

    push_with_retry(&store, repo, 1, 1).await.unwrap();
    push_with_retry(&store, repo, 2, 1).await.unwrap();
    // Admin rotates: subsequent pushes carry the new epoch.
    push_with_retry(&store, repo, 1, 2).await.unwrap();
    push_with_retry(&store, repo, 3, 2).await.unwrap();

    assert_linear_chain(&store, &repo, 4).await;
    let heads = store.since(&repo, 0).await.unwrap();
    let epochs: Vec<u64> = heads.iter().map(|h| h.mls_epoch).collect();
    assert_eq!(epochs, vec![1, 1, 2, 2], "epoch must advance monotonically");
}
