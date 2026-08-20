//! Emit / check known-answer vectors for AEAD, DKR, epoch tags, RefHead canon.

use safehub_crypto::aead::CommittingAead;
use safehub_crypto::dkr::{DualKeyRegression, IntervalDkr};
use safehub_crypto::params::{domain_label, SEC_PARAM_LEN};
use safehub_types::{encode_ref_head, BlobId, HeadHash, RefHead, RepoId};
use serde_json::json;
use std::path::PathBuf;

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vectors"));
    std::fs::create_dir_all(&out).expect("mkdir vectors");

    // AEAD deterministic seal
    let key = [0x11u8; 32];
    let ct = CommittingAead::seal_deterministic(&key, b"aad", b"pt", 0).unwrap();
    let aead = json!({
        "key_hex": hex::encode(key),
        "aad": "aad",
        "plaintext": "pt",
        "counter": 0,
        "ciphertext_hex": hex::encode(&ct),
        "note": "deterministic nonce under explicit seal key; use derive_head_seal_key(K_e, seq) on the wire",
    });
    std::fs::write(out.join("aead_det.json"), serde_json::to_vec_pretty(&aead).unwrap()).unwrap();

    // DKR epoch key
    let mut dkr = IntervalDkr::with_seed([0x22u8; SEC_PARAM_LEN]);
    let iv = dkr.init().unwrap();
    let ke = dkr.derive_epoch_key(&iv, 0).unwrap();
    let dkr_v = json!({
        "seed_hex": hex::encode([0x22u8; SEC_PARAM_LEN]),
        "epoch": 0,
        "ke_hex": hex::encode(ke),
        "label": domain_label("dkr-epoch:0"),
    });
    std::fs::write(out.join("dkr_epoch0.json"), serde_json::to_vec_pretty(&dkr_v).unwrap()).unwrap();

    // Canonical RefHead
    let head = RefHead {
        repo_id: RepoId([0x33u8; 32]),
        seq: 1,
        enc_refs: b"enc".to_vec(),
        bundle_root: BlobId([0x44u8; 64]),
        dek_wrap: b"dek".to_vec(),
        prev_head_hash: HeadHash::zero(),
        mls_epoch: 0,
        epoch_tag: vec![0x55; 32],
        non_ff: false,
        pusher_sig: vec![0x66; 16],
        admin_cosig: None,
    };
    let bytes = encode_ref_head(&head);
    let rh = json!({
        "canonical_hex": hex::encode(&bytes),
        "hash_hex": head.hash().to_hex(),
    });
    std::fs::write(out.join("refhead_canon.json"), serde_json::to_vec_pretty(&rh).unwrap()).unwrap();
    std::fs::write(out.join("refhead_canon.bin"), &bytes).unwrap();

    eprintln!("wrote KATs under {}", out.display());
}
