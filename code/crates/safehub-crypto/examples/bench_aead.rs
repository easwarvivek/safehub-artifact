//! Ad-hoc transport-AEAD latency probe (median of N reps). Not a published artifact.
use safehub_crypto::aead::{aead_backend_name, CommittingAead};
use safehub_crypto::params::AEAD_KEY_LEN;
use std::time::Instant;

fn med(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn bench(n: usize, reps: usize) -> (u128, u128) {
    let key = [7u8; AEAD_KEY_LEN];
    let aad = b"repo|push|0|1";
    let pt = vec![0xABu8; n];
    for _ in 0..3 {
        let c = CommittingAead::seal(&key, aad, &pt).unwrap();
        let _ = CommittingAead::open(&key, aad, &c).unwrap();
    }
    let mut se = Vec::new();
    let mut op = Vec::new();
    for _ in 0..reps {
        let t = Instant::now();
        let c = CommittingAead::seal(&key, aad, &pt).unwrap();
        se.push(t.elapsed().as_nanos());
        let t = Instant::now();
        let _ = CommittingAead::open(&key, aad, &c).unwrap();
        op.push(t.elapsed().as_nanos());
    }
    (med(se), med(op))
}

fn main() {
    let (s1, o1) = bench(1024, 25);
    let (s2, o2) = bench(1024 * 1024, 25);
    println!("backend={}", aead_backend_name());
    println!("seal 1KiB={:.2}us open 1KiB={:.2}us", s1 as f64 / 1e3, o1 as f64 / 1e3);
    println!("seal 1MiB={:.3}ms open 1MiB={:.3}ms", s2 as f64 / 1e6, o2 as f64 / 1e6);
}
