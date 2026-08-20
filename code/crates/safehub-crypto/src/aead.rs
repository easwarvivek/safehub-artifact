//! Key-committing, message-equivocable transport AEAD (QROM).
//!
//! Construction (paper formats / Theorem 1 hybrids H3–H5):
//! - Expand `K → (K_enc, K_mac)` via HKDF-SHA-512 (`safehub-v1:aead-keys`).
//! - Pad `P = MGF(K_enc, nonce‖aad‖len)`: one keyed HMAC-SHA-512 binds the
//!   inputs to a secret `pad_key`, then `P_i = SHA-512(pad_key‖i)`. Modeled as
//!   a programmable RO; runs one compression per 64-byte block (linear, no
//!   255-block HKDF cap).
//! - Body = `P ⊕ (COMMIT_BLOCK ‖ plaintext)` (key commitment + OTP).
//! - Outer HMAC-SHA-512-256 over `(aad ‖ body)` (Encrypt-then-MAC).
//!
//! Under a fixed RO, decryption is unique (honest INT-CTXT). The UC simulator
//! equivocates by programming the pad RO on adaptive Corrupt after H3→H4
//! zero-payload substitution — AES-256-GCM cannot; this primitive can.
//!
//! Backend note: pad expansion is SHA-512/HKDF (not AES-GCM). Hardware AES is
//! unused for application transport; MLS still uses its own suite AEAD.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::params::{domain_label, AEAD_KEY_LEN, TAG_LEN};

type HmacSha512 = Hmac<Sha512>;

/// AEAD failures.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Encryption failed.
    #[error("aead encrypt failed")]
    Encrypt,
    /// Decryption / key-commitment / outer-tag check failed.
    #[error("aead decrypt failed")]
    Decrypt,
    /// Deterministic nonce counter exhausted; rotate epoch / rekey.
    #[error("aead seal counter exhausted; rotate epoch")]
    CounterExhausted,
}

/// Fixed 48-byte (λ=384) commitment block prepended to plaintext.
///
/// ASCII `safehub-v1:kcommit-block`, zero-padded, version byte `0x03`
/// (v3 = RO-pad transport; message-equivocable under programmable pad RO).
const COMMIT_BLOCK: [u8; 48] = [
    0x73, 0x61, 0x66, 0x65, 0x68, 0x75, 0x62, 0x2d, // "safehub-"
    0x76, 0x31, 0x3a, 0x6b, 0x63, 0x6f, 0x6d, 0x6d, // "v1:kcomm"
    0x69, 0x74, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, // "it-block"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // ver=3
];

/// Hard cap on seals under a single derived seal key with deterministic nonces.
pub const MAX_SEALS_PER_KEY: u64 = 1 << 32;

/// Human-readable AEAD backend actually linked into this build.
pub const AEAD_BACKEND: &str = "hkdf-sha512-pad+HMAC-SHA-512-256";

/// Key-committing transport AEAD with RO-pad message equivocability.
///
/// Wire format: `nonce (12) || body || hmac_tag (32)` where
/// `body = pad ⊕ (COMMIT_BLOCK ‖ plaintext)`.
pub struct CommittingAead;

/// Expanded AEAD subkeys (zeroized on drop).
struct ExpandedKeys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl CommittingAead {
    /// Encrypt `plaintext` under `key` with associated data `aad` (random nonce).
    ///
    /// Prefer [`seal_deterministic`] under a per-head seal subkey of long-lived
    /// epoch keys `K_e` (see [`derive_head_seal_key`]).
    pub fn seal(key: &[u8; AEAD_KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        Self::seal_with_nonce(key, aad, plaintext, &nonce_bytes)
    }

    /// Deterministic nonce from a per-key seal `counter`.
    ///
    /// Callers must supply a **unique seal key** per logical unit (typically
    /// [`derive_head_seal_key`]) so uniqueness does not rest on a short hash of
    /// a random push id. Exhaustion returns [`AeadError::CounterExhausted`].
    pub fn seal_deterministic(
        key: &[u8; AEAD_KEY_LEN],
        aad: &[u8],
        plaintext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, AeadError> {
        if counter >= MAX_SEALS_PER_KEY {
            return Err(AeadError::CounterExhausted);
        }
        let nonce_bytes = deterministic_nonce(counter);
        Self::seal_with_nonce(key, aad, plaintext, &nonce_bytes)
    }

    fn seal_with_nonce(
        key: &[u8; AEAD_KEY_LEN],
        aad: &[u8],
        plaintext: &[u8],
        nonce_bytes: &[u8; 12],
    ) -> Result<Vec<u8>, AeadError> {
        let keys = expand_aead_keys(key)?;
        let body_len = COMMIT_BLOCK.len() + plaintext.len();
        let pad = expand_pad(&keys.enc, nonce_bytes, aad, body_len)?;

        let mut padded = Vec::with_capacity(body_len);
        padded.extend_from_slice(&COMMIT_BLOCK);
        padded.extend_from_slice(plaintext);
        for (b, p) in padded.iter_mut().zip(pad.iter()) {
            *b ^= *p;
        }

        let tag = outer_hmac(&*keys.mac, aad, &padded)?;

        let mut out = Vec::with_capacity(12 + padded.len() + TAG_LEN);
        out.extend_from_slice(nonce_bytes);
        out.extend_from_slice(&padded);
        out.extend_from_slice(&tag);
        padded.zeroize();
        Ok(out)
    }

    /// Verify the outer tag, unmask the pad, and check the key-commitment block.
    pub fn open(key: &[u8; AEAD_KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, AeadError> {
        if sealed.len() < 12 + COMMIT_BLOCK.len() + TAG_LEN {
            return Err(AeadError::Decrypt);
        }
        let (body, tag) = sealed.split_at(sealed.len() - TAG_LEN);
        let (nonce_bytes, ct_body) = body.split_at(12);

        let keys = expand_aead_keys(key)?;
        let expected = outer_hmac(&*keys.mac, aad, ct_body)?;
        if !ct_eq(tag, &expected) {
            return Err(AeadError::Decrypt);
        }

        let pad = expand_pad(&keys.enc, nonce_bytes, aad, ct_body.len())?;
        let mut buf = ct_body.to_vec();
        for (b, p) in buf.iter_mut().zip(pad.iter()) {
            *b ^= *p;
        }

        if buf.len() < COMMIT_BLOCK.len() || buf[..COMMIT_BLOCK.len()] != COMMIT_BLOCK {
            buf.zeroize();
            return Err(AeadError::Decrypt);
        }
        let pt = buf[COMMIT_BLOCK.len()..].to_vec();
        buf.zeroize();
        Ok(pt)
    }
}

/// Derive per-head seal key `K_e^{seq} ← HKDF(K_e, "head-seal" ‖ seq)`.
///
/// Each CAS `seq` gets an independent seal key so push-local counters (0,1,…)
/// are unique under that key; the `2^{32}` seal cap is then meaningful.
pub fn derive_head_seal_key(epoch_key: &[u8; AEAD_KEY_LEN], seq: u64) -> Result<[u8; AEAD_KEY_LEN], AeadError> {
    let hk = Hkdf::<Sha512>::new(None, epoch_key);
    let mut okm = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    let mut info = domain_label("head-seal").into_bytes();
    info.extend_from_slice(&seq.to_be_bytes());
    hk.expand(&info, okm.as_mut())
        .map_err(|_| AeadError::Encrypt)?;
    Ok(*okm)
}

/// Derive CAS / object-seal key `K_e^{cas} ← HKDF(ss, "cas-obj-key")`.
///
/// Uses the transport exporter (or any 32+ byte secret material) so `mk_e`
/// (`refs_mac`) is never reused as an AEAD encryption key.
pub fn derive_cas_seal_key(secret: &[u8]) -> Result<[u8; AEAD_KEY_LEN], AeadError> {
    let hk = Hkdf::<Sha512>::new(None, secret);
    let mut okm = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(domain_label("cas-obj-key").as_bytes(), okm.as_mut())
        .map_err(|_| AeadError::Encrypt)?;
    Ok(*okm)
}

/// Derive KeyPackage-bound secret seal key from epoch transport material.
pub fn derive_secret_seal_key(secret: &[u8]) -> Result<[u8; AEAD_KEY_LEN], AeadError> {
    let hk = Hkdf::<Sha512>::new(None, secret);
    let mut okm = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(domain_label("secret-seal-key").as_bytes(), okm.as_mut())
        .map_err(|_| AeadError::Encrypt)?;
    Ok(*okm)
}

/// 96-bit deterministic nonce: 4 zero bytes ‖ 64-bit big-endian counter.
///
/// Uniqueness under a fixed key is exactly the uniqueness of `counter`
/// (capped at [`MAX_SEALS_PER_KEY`]).
pub fn deterministic_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn expand_aead_keys(key: &[u8; AEAD_KEY_LEN]) -> Result<ExpandedKeys, AeadError> {
    let hk = Hkdf::<Sha512>::new(None, key);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(domain_label("aead-keys").as_bytes(), okm.as_mut())
        .map_err(|_| AeadError::Encrypt)?;
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    Ok(ExpandedKeys { enc, mac })
}

/// Pad oracle (MGF1-style over SHA-512). A single HMAC-SHA-512 keyed by
/// `K_enc` binds the pad to `"aead-pad" ‖ nonce ‖ aad ‖ len_be`, yielding a
/// 64-byte secret `pad_key`; the keystream is then
/// `pad_block_i = SHA-512(pad_key ‖ block_ctr)`. Both steps are modeled as a
/// programmable random oracle in the UC hybrids, so the simulator can open a
/// published body to any equal-length plaintext (Theorem 1, H3→H4).
///
/// This is behaviourally an MGF and runs one SHA-512 compression per 64-byte
/// block (the prefix/AD are hashed once, not per block), so it is not capped
/// at 255 blocks and multi-MiB chunks stay linear.
fn expand_pad(
    enc_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let mut binder = <HmacSha512 as Mac>::new_from_slice(enc_key).map_err(|_| AeadError::Encrypt)?;
    binder.update(domain_label("aead-pad").as_bytes());
    binder.update(nonce);
    binder.update(aad);
    binder.update(&(len as u64).to_be_bytes());
    let mut pad_key = Zeroizing::new([0u8; 64]);
    pad_key.copy_from_slice(&binder.finalize().into_bytes());

    let mut pad = Zeroizing::new(vec![0u8; len]);
    let mut ctr: u64 = 0;
    let mut off = 0usize;
    while off < len {
        use sha2::Digest as _;
        let mut h = Sha512::new();
        sha2::Digest::update(&mut h, pad_key.as_slice());
        sha2::Digest::update(&mut h, ctr.to_be_bytes());
        let block = h.finalize();
        let take = core::cmp::min(block.len(), len - off);
        pad[off..off + take].copy_from_slice(&block[..take]);
        off += take;
        ctr += 1;
    }
    Ok(pad)
}

fn outer_hmac(mac_key: &[u8; 32], aad: &[u8], body: &[u8]) -> Result<[u8; TAG_LEN], AeadError> {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(mac_key).map_err(|_| AeadError::Encrypt)?;
    mac.update(aad);
    mac.update(body);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    Ok(tag)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Linked AEAD backend string (not a CPU capability probe).
pub fn aead_backend_name() -> &'static str {
    AEAD_BACKEND
}

/// Whether bulk transport uses hardware AES.
///
/// Always `false` for the RO-pad construction (SHA-512/HKDF pad). Kept so
/// eval/logging call sites stay honest after the AES-GCM → pad migration.
pub fn hardware_aes_likely() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let aad = b"safehub-v1:test";
        let pt = b"hello bundle";
        let ct = CommittingAead::seal(&key, aad, pt).unwrap();
        assert!(ct.len() >= 12 + TAG_LEN);
        let out = CommittingAead::open(&key, aad, &ct).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn deterministic_roundtrip() {
        let key = [9u8; 32];
        let ct = CommittingAead::seal_deterministic(&key, b"aad", b"pt", 0).unwrap();
        let ct2 = CommittingAead::seal_deterministic(&key, b"aad", b"pt", 0).unwrap();
        assert_eq!(ct, ct2);
        assert_eq!(CommittingAead::open(&key, b"aad", &ct).unwrap(), b"pt");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = CommittingAead::seal(&[1u8; 32], b"aad", b"pt").unwrap();
        assert!(CommittingAead::open(&[2u8; 32], b"aad", &ct).is_err());
    }

    #[test]
    fn tampered_outer_tag_fails() {
        let key = [3u8; 32];
        let mut ct = CommittingAead::seal(&key, b"aad", b"pt").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(CommittingAead::open(&key, b"aad", &ct).is_err());
    }

    #[test]
    fn commit_block_is_lambda_bits() {
        assert_eq!(COMMIT_BLOCK.len(), 48);
        assert_eq!(&COMMIT_BLOCK[..11], b"safehub-v1:");
        assert_eq!(COMMIT_BLOCK[47], 0x03);
    }

    #[test]
    fn expanded_keys_zeroized_type() {
        let _ = expand_aead_keys(&[0u8; 32]).unwrap();
    }

    #[test]
    fn head_seal_keys_differ_by_seq() {
        let ke = [42u8; 32];
        let k0 = derive_head_seal_key(&ke, 0).unwrap();
        let k1 = derive_head_seal_key(&ke, 1).unwrap();
        assert_ne!(k0, k1);
        assert_ne!(k0, ke);
    }

    #[test]
    fn no_key_nonce_repeat_across_million_heads() {
        let ke = [0x11u8; 32];
        let mut seen = HashSet::with_capacity(2_000_000);
        for seq in 0u64..1_000_000 {
            let k = derive_head_seal_key(&ke, seq).unwrap();
            for counter in 0u64..2 {
                let nonce = deterministic_nonce(counter);
                let mut pair = [0u8; 44];
                pair[..32].copy_from_slice(&k);
                pair[32..].copy_from_slice(&nonce);
                assert!(seen.insert(pair), "duplicate at seq={seq} counter={counter}");
            }
        }
    }

    #[test]
    fn backend_name_is_ro_pad() {
        assert!(aead_backend_name().contains("hkdf"));
        assert!(!hardware_aes_likely());
    }

    #[test]
    fn cas_and_secret_keys_differ_from_input() {
        let secret = [9u8; 48];
        let cas = derive_cas_seal_key(&secret).unwrap();
        let sec = derive_secret_seal_key(&secret).unwrap();
        assert_ne!(cas, sec);
        assert_ne!(&cas[..], &secret[..32]);
    }

    /// Concrete stand-in for adaptive Corrupt after H3→H4: retained DKR-derived
    /// `K_e` must open a published ciphertext to the sealed plaintext (honest
    /// path). Simulator equivocation is the RO-programming argument in the
    /// proof; this test locks the unique-open under fixed keys.
    #[test]
    fn adaptive_open_under_retained_epoch_key() {
        let ke = [0xABu8; 32];
        let seq = 7u64;
        let seal_key = derive_head_seal_key(&ke, seq).unwrap();
        let aad = b"safehub-v1:bundle-chunk|adaptive-open";
        let real_pt = b"real git bundle bytes after corrupt";
        let ct = CommittingAead::seal_deterministic(&seal_key, aad, real_pt, 0).unwrap();
        // Adversary recomputes K_e^{seq} from retained DKR token material.
        let recomputed = derive_head_seal_key(&ke, seq).unwrap();
        assert_eq!(seal_key, recomputed);
        let opened = CommittingAead::open(&recomputed, aad, &ct).unwrap();
        assert_eq!(opened, real_pt);
    }
}
