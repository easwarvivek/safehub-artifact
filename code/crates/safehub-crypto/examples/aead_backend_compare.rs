//! Transport-AEAD backend comparison: RO-pad (deployed) vs AES-256-GCM.
//!
//! The deployed transport is the key-committing, message-equivocable
//! HKDF-SHA-512 RO-pad + HMAC-SHA-512-256 construction, because the UC
//! simulator has to reopen an already-published ciphertext to the plaintext
//! `F_safehub` discloses on adaptive `Corrupt` (Lemma 1 case (a)), and
//! AES-256-GCM is committing on the message and cannot do that.
//!
//! That choice costs bulk throughput, so this example measures both backends
//! under one methodology on one machine and emits JSON. The paper reports the
//! standard AES-256-GCM figures alongside the deployed ones rather than only
//! asserting that the difference is small.
//!
//! Run: `cargo run -p safehub-crypto --release --example aead_backend_compare`

use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use safehub_crypto::{aead_backend_name, CommittingAead, AEAD_KEY_LEN};

const WARMUPS: usize = 3;
const RUNS: usize = 25;

fn median_ns(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    let n = samples.len();
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2
    }
}

fn stats(samples: Vec<u128>) -> (u128, u128, u128) {
    let mut s = samples.clone();
    s.sort_unstable();
    (median_ns(samples), s[0], s[s.len() - 1])
}

/// Times `op` with the shared warmup/median-of-runs discipline.
fn time_op(mut op: impl FnMut()) -> (u128, u128, u128) {
    for _ in 0..WARMUPS {
        op();
    }
    let mut samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t0 = Instant::now();
        op();
        samples.push(t0.elapsed().as_nanos());
    }
    stats(samples)
}

fn main() {
    let key = [0x42u8; AEAD_KEY_LEN];
    let aad = b"safehub-v1:bench-aad";
    let gcm_key: &Key<Aes256Gcm> = (&key).into();
    let gcm = Aes256Gcm::new(gcm_key);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let mut cells = Vec::new();
    for (label, len) in [("1KiB", 1024usize), ("1MiB", 1024 * 1024)] {
        let pt = vec![0xABu8; len];

        // Deployed: RO-pad Encrypt-then-MAC.
        let (ro_seal, ro_seal_min, ro_seal_max) =
            time_op(|| {
                let _ = CommittingAead::seal(&key, aad, &pt).expect("ro-pad seal");
            });
        let ro_ct = CommittingAead::seal(&key, aad, &pt).expect("ro-pad seal");
        let (ro_open, ro_open_min, ro_open_max) = time_op(|| {
            let _ = CommittingAead::open(&key, aad, &ro_ct).expect("ro-pad open");
        });

        // Reference: standard AES-256-GCM.
        let (gcm_seal, gcm_seal_min, gcm_seal_max) = time_op(|| {
            let _ = gcm
                .encrypt(nonce, Payload { msg: &pt, aad })
                .expect("gcm seal");
        });
        let gcm_ct = gcm
            .encrypt(nonce, Payload { msg: &pt, aad })
            .expect("gcm seal");
        let (gcm_open, gcm_open_min, gcm_open_max) = time_op(|| {
            let _ = gcm
                .decrypt(
                    nonce,
                    Payload {
                        msg: &gcm_ct,
                        aad,
                    },
                )
                .expect("gcm open");
        });

        let mib = len as f64 / (1024.0 * 1024.0);
        let rate = |ns: u128| {
            if mib > 0.0 {
                (ns as f64 / 1e6) / mib
            } else {
                0.0
            }
        };

        cells.push(format!(
            r#"    {{
      "payload": "{label}",
      "payload_bytes": {len},
      "ro_pad_seal_ns": {ro_seal}, "ro_pad_seal_min_ns": {ro_seal_min}, "ro_pad_seal_max_ns": {ro_seal_max},
      "ro_pad_open_ns": {ro_open}, "ro_pad_open_min_ns": {ro_open_min}, "ro_pad_open_max_ns": {ro_open_max},
      "aes256gcm_seal_ns": {gcm_seal}, "aes256gcm_seal_min_ns": {gcm_seal_min}, "aes256gcm_seal_max_ns": {gcm_seal_max},
      "aes256gcm_open_ns": {gcm_open}, "aes256gcm_open_min_ns": {gcm_open_min}, "aes256gcm_open_max_ns": {gcm_open_max},
      "ro_pad_seal_ms_per_mib": {ro_seal_rate:.4},
      "aes256gcm_seal_ms_per_mib": {gcm_seal_rate:.4},
      "seal_slowdown_ro_over_aes": {seal_ratio:.3},
      "open_slowdown_ro_over_aes": {open_ratio:.3},
      "ciphertext_expansion_ro_pad_bytes": {ro_exp},
      "ciphertext_expansion_aes256gcm_bytes": {gcm_exp},
      "measured": true
    }}"#,
            ro_seal_rate = rate(ro_seal),
            gcm_seal_rate = rate(gcm_seal),
            seal_ratio = ro_seal as f64 / gcm_seal as f64,
            open_ratio = ro_open as f64 / gcm_open as f64,
            ro_exp = ro_ct.len() - len,
            gcm_exp = gcm_ct.len() - len,
        ));
    }

    println!(
        r#"{{
  "id": "E16",
  "title": "Transport AEAD backend comparison: deployed RO-pad vs standard AES-256-GCM",
  "method": "{WARMUPS} warmups, median of {RUNS} runs, same process, same machine, identical payloads",
  "deployed_backend": "{deployed}",
  "reference_backend": "AES-256-GCM (aes-gcm crate, software AES on this build)",
  "why_not_aes": "AES-256-GCM is committing on the message, so the UC simulator cannot reopen a published ciphertext to the plaintext F_safehub discloses on adaptive Corrupt (Lemma 1 case (a)). The RO-pad transport is deployed to make that hop go through; these AES figures are reported as the standard-primitive reference point.",
  "cells": [
{cells}
  ]
}}"#,
        deployed = aead_backend_name(),
        cells = cells.join(",\n")
    );
}
