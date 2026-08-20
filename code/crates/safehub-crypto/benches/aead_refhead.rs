//! Criterion microbenchmarks: CommittingAead + RefHead hash (head-verify proxy).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use safehub_crypto::aead::CommittingAead;
use safehub_crypto::params::AEAD_KEY_LEN;
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};

fn sample_head() -> RefHead {
    RefHead {
        repo_id: RepoId([3u8; 32]),
        seq: 42,
        enc_refs: vec![1u8; 128],
        bundle_root: BlobId([4u8; 64]),
        dek_wrap: vec![2u8; 64],
        prev_head_hash: HeadHash([0u8; 64]),
        mls_epoch: 7,
        epoch_tag: vec![3u8; 32],
        non_ff: false,
        pusher_sig: vec![4u8; 64],
        admin_cosig: None,
    }
}

fn bench_aead(c: &mut Criterion) {
    let key = [11u8; AEAD_KEY_LEN];
    let aad = b"bench-aad";
    let mut group = c.benchmark_group("committing_aead");
    for &size in &[1024usize, 64 * 1024, 1024 * 1024] {
        let pt = vec![0x55u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("seal_{size}"), |b| {
            b.iter(|| CommittingAead::seal(black_box(&key), aad, black_box(&pt)).unwrap())
        });
        let sealed = CommittingAead::seal(&key, aad, &pt).unwrap();
        group.bench_function(format!("open_{size}"), |b| {
            b.iter(|| CommittingAead::open(black_box(&key), aad, black_box(&sealed)).unwrap())
        });
    }
    group.finish();
}

fn bench_refhead_hash(c: &mut Criterion) {
    let head = sample_head();
    c.bench_function("refhead_hash", |b| {
        b.iter(|| black_box(head.hash()))
    });
}

criterion_group!(benches, bench_aead, bench_refhead_hash);
criterion_main!(benches);
