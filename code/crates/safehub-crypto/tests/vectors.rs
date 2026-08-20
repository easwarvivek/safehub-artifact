//! Known-answer vector checks for AEAD / DKR / RefHead canon.

use safehub_crypto::aead::CommittingAead;
use safehub_crypto::dkr::{DualKeyRegression, IntervalDkr};
use safehub_crypto::params::{domain_label, SEC_PARAM_LEN};
use safehub_types::{encode_ref_head, BlobId, HeadHash, RefHead, RepoId};
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    // Prefer CARGO_MANIFEST_DIR/../../vectors (crate → code/).
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors");
    if p.join("aead_det.json").exists() {
        return p;
    }
    PathBuf::from("vectors")
}

#[test]
fn aead_deterministic_kat() {
    let path = vectors_dir().join("aead_det.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let key_hex = v["key_hex"].as_str().unwrap();
    let key: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
    let aad = v["aad"].as_str().unwrap().as_bytes();
    let pt = v["plaintext"].as_str().unwrap().as_bytes();
    let counter = v["counter"].as_u64().unwrap();
    let expected = hex::decode(v["ciphertext_hex"].as_str().unwrap()).unwrap();
    let ct = CommittingAead::seal_deterministic(&key, aad, pt, counter).unwrap();
    assert_eq!(ct, expected, "AEAD KAT drift");
    assert_eq!(CommittingAead::open(&key, aad, &ct).unwrap(), pt);
}

#[test]
fn dkr_epoch0_kat() {
    let path = vectors_dir().join("dkr_epoch0.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let seed: [u8; SEC_PARAM_LEN] = hex::decode(v["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut dkr = IntervalDkr::with_seed(seed);
    let iv = dkr.init().unwrap();
    let ke = dkr.derive_epoch_key(&iv, 0).unwrap();
    assert_eq!(hex::encode(ke), v["ke_hex"].as_str().unwrap());
    assert_eq!(v["label"].as_str().unwrap(), domain_label("dkr-epoch:0"));
}

#[test]
fn refhead_canon_kat() {
    let path = vectors_dir().join("refhead_canon.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
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
    assert_eq!(hex::encode(&bytes), v["canonical_hex"].as_str().unwrap());
    assert_eq!(head.hash().to_hex(), v["hash_hex"].as_str().unwrap());
    let bin = std::fs::read(vectors_dir().join("refhead_canon.bin")).unwrap();
    assert_eq!(bytes, bin);
}
