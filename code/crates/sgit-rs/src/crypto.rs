//! Primitives named in SGit's section 5: AES-CTR, ECDSA, SHA-256, HKDF-SHA-256.
//!
//! The originals use Python and pycryptodome. These are the Rust equivalents of
//! the same algorithms, so ciphertext lengths and the number of primitive
//! invocations match; only constant factors differ, which is why the arm is
//! read on bytes and scaling rather than wall-clock (see the design doc).

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// AES-CTR is length-preserving, which is what makes SGitChar's appended delta
/// exactly as large as the delta itself. A 16-byte random nonce is prepended so
/// each encryption is independent; that 16 bytes is the only expansion before
/// Base64.
pub const NONCE_LEN: usize = 16;

pub fn kdf(mk: &[u8], rid: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut out = [0u8; 32];
    hk.expand(rid.as_bytes(), &mut out).expect("32 is a valid length");
    out
}

pub fn enc(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom_bytes(&mut nonce);
    let mut buf = pt.to_vec();
    let mut c = Aes256Ctr::new(key.into(), &nonce.into());
    c.apply_keystream(&mut buf);
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out
}

pub fn dec(key: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>> {
    if ct.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext shorter than its nonce"));
    }
    let (nonce, body) = ct.split_at(NONCE_LEN);
    let mut buf = body.to_vec();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    let mut c = Aes256Ctr::new(key.into(), &n.into());
    c.apply_keystream(&mut buf);
    Ok(buf)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub struct Signer256 {
    sk: SigningKey,
}

impl Signer256 {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom_bytes(&mut seed);
        // from_slice rejects an out-of-range scalar; retry is cheap and the
        // probability of hitting one is ~2^-32.
        let sk = loop {
            match SigningKey::from_slice(&seed) {
                Ok(k) => break k,
                Err(_) => getrandom_bytes(&mut seed),
            }
        };
        Self { sk }
    }
    /// Persist and restore the signing key: the client keeps it across
    /// invocations, since each `sgit push` is a separate process.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(Self { sk: SigningKey::from_slice(b).map_err(|e| anyhow!("bad signing key: {e}"))? })
    }
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.sk.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }
}

pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(vk) else { return false };
    let Ok(sig) = Signature::from_der(sig) else { return false };
    vk.verify(msg, &sig).is_ok()
}

fn getrandom_bytes(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_is_length_preserving_up_to_the_nonce() {
        let k = kdf(b"master", "repo1");
        for n in [0usize, 1, 17, 4096] {
            let pt = vec![7u8; n];
            let ct = enc(&k, &pt);
            assert_eq!(ct.len(), n + NONCE_LEN, "AES-CTR must not pad");
            assert_eq!(dec(&k, &ct).unwrap(), pt);
        }
    }

    #[test]
    fn a_different_repository_id_yields_a_different_key() {
        assert_ne!(kdf(b"master", "a"), kdf(b"master", "b"));
    }

    #[test]
    fn decryption_under_the_wrong_key_does_not_return_the_plaintext() {
        let good = kdf(b"m", "r");
        let bad = kdf(b"m", "other");
        let ct = enc(&good, b"CANARY");
        // CTR has no integrity, so this does not error -- it returns garbage.
        // That is a property of their construction, not of this port: SGit
        // relies on the signature over the Merkle root for integrity.
        assert_ne!(dec(&bad, &ct).unwrap(), b"CANARY".to_vec());
    }

    #[test]
    fn signing_is_deterministic() {
        // p256 signs with RFC6979 nonces. The wrapper depends on this: an
        // unchanged repository must re-sign to the identical tag, so that a
        // push with nothing to say has nothing to send. A randomized nonce
        // would make every no-op push carry a new blob.
        let s = Signer256::generate();
        assert_eq!(s.sign(b"same message"), s.sign(b"same message"));
        assert_ne!(s.sign(b"a"), s.sign(b"b"));
    }

    #[test]
    fn signatures_verify_and_reject() {
        let s = Signer256::generate();
        let vk = s.verifying_key_bytes();
        let sig = s.sign(b"msg");
        assert!(verify(&vk, b"msg", &sig));
        assert!(!verify(&vk, b"other", &sig), "must reject a different message");
        let other = Signer256::generate();
        assert!(!verify(&other.verifying_key_bytes(), b"msg", &sig),
                "must reject a different key");
    }
}
