//! ML-DSA-87 (FIPS 204) detached signatures for RefHead leaf and admin co-sigs.
//!
//! Wire sizes match the paper appendix: verifying key 2 592 B, signature 4 627 B.

use crate::params::domain_label;
use crate::CryptoError;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa87, Seed, Signature,
    Signer as MlSigner, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Result<T> = std::result::Result<T, CryptoError>;

/// Expected ML-DSA-87 verifying-key length (bytes).
pub const MLDSA87_VK_LEN: usize = 2592;
/// Expected ML-DSA-87 signature length (bytes).
pub const MLDSA87_SIG_LEN: usize = 4627;

/// ML-DSA-87 key pair (32-byte seed + encoded verifying key).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87KeyPair {
    /// 32-byte seed (`SigningKey::to_seed`).
    seed: Vec<u8>,
    /// Encoded verifying key (2 592 bytes).
    #[zeroize(skip)]
    public: Vec<u8>,
}

impl MlDsa87KeyPair {
    /// Fresh Category-5 signature key.
    pub fn generate() -> Result<Self> {
        let sk = SigningKey::<MlDsa87>::generate();
        let public = sk.verifying_key().encode().to_vec();
        let seed = sk.to_seed().as_slice().to_vec();
        Ok(Self { seed, public })
    }

    /// Reconstruct from a 32-byte seed (OpenMLS leaf private encoding).
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed_arr: &Seed = seed
            .try_into()
            .map_err(|_| CryptoError::Mls("ML-DSA-87 seed must be 32 bytes".into()))?;
        let sk = SigningKey::<MlDsa87>::from_seed(seed_arr);
        let public = sk.verifying_key().encode().to_vec();
        Ok(Self {
            seed: seed.to_vec(),
            public,
        })
    }

    /// Encoded verifying key.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Detached ML-DSA-87 signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        sign_with_seed(&self.seed, message)
    }
}

/// Sign with a raw 32-byte ML-DSA-87 seed (OpenMLS leaf private key encoding).
pub fn sign_with_seed(seed: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let seed_arr: &Seed = seed
        .try_into()
        .map_err(|_| CryptoError::Mls("ML-DSA-87 seed must be 32 bytes".into()))?;
    let sk = SigningKey::<MlDsa87>::from_seed(seed_arr);
    let sig = MlSigner::sign(&sk, message);
    Ok(sig.encode().to_vec())
}

/// Verify an ML-DSA-87 detached signature.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let encoded_key: &EncodedVerifyingKey<MlDsa87> = public_key
        .try_into()
        .map_err(|_| CryptoError::Mls("invalid ML-DSA-87 verifying key length".into()))?;
    let encoded_sig: &EncodedSignature<MlDsa87> = signature
        .try_into()
        .map_err(|_| CryptoError::Mls("invalid ML-DSA-87 signature length".into()))?;
    let vk = VerifyingKey::<MlDsa87>::decode(encoded_key);
    let sig = Signature::<MlDsa87>::decode(encoded_sig)
        .ok_or_else(|| CryptoError::Mls("ML-DSA-87 signature decode failed".into()))?;
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::Mls("ML-DSA-87 signature verification failed".into()))
}

/// Domain-separated RefHead leaf-signature transcript (excludes signature fields).
pub fn refhead_leaf_message(
    repo_id: &[u8; 32],
    seq: u64,
    enc_refs: &[u8],
    bundle_root: &[u8; 64],
    dek_wrap: &[u8],
    prev_head_hash: &[u8; 64],
    mls_epoch: u64,
    epoch_tag: &[u8],
    non_ff: bool,
) -> Vec<u8> {
    let mut msg = domain_label("refhead").into_bytes();
    msg.extend_from_slice(repo_id);
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(enc_refs);
    msg.extend_from_slice(bundle_root);
    msg.extend_from_slice(dek_wrap);
    msg.extend_from_slice(prev_head_hash);
    msg.extend_from_slice(&mls_epoch.to_le_bytes());
    msg.extend_from_slice(epoch_tag);
    msg.push(u8::from(non_ff));
    msg
}

/// Domain-separated admin co-signature message for non-FF updates.
/// Canonical admin co-signature message.
///
/// The roster digest and sequence are part of the statement, not context. Without
/// the roster a co-signature issued under one membership authorizes the same refs
/// under another at the same `(epoch, prev_head)`; without the sequence it
/// authorizes a different position in the log. Neither is recoverable from the
/// other fields, so both are bound here.
#[allow(clippy::too_many_arguments)]
pub fn admin_cosig_message(
    repo_id: &[u8; 32],
    epoch: u64,
    op: &str,
    seq: u64,
    prev_head: &[u8; 64],
    new_refs_digest: &[u8; 64],
    roster_digest: &[u8; 64],
    policy_version: u32,
) -> Vec<u8> {
    let mut msg = domain_label("admin-cosig").into_bytes();
    msg.extend_from_slice(repo_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    // Length-prefixed so a differently split (op, seq) pair cannot collide with
    // this encoding.
    msg.extend_from_slice(&(op.len() as u32).to_le_bytes());
    msg.extend_from_slice(op.as_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(prev_head);
    msg.extend_from_slice(new_refs_digest);
    msg.extend_from_slice(roster_digest);
    msg.extend_from_slice(&policy_version.to_le_bytes());
    msg
}

/// Policy version bound into every admin authorization.
pub const ADMIN_COSIG_POLICY_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa87_sign_verify_roundtrip() {
        let kp = MlDsa87KeyPair::generate().unwrap();
        let msg = b"safehub-v1:refhead-test";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), MLDSA87_SIG_LEN);
        assert_eq!(kp.public_key().len(), MLDSA87_VK_LEN);
        verify(kp.public_key(), msg, &sig).unwrap();
        assert!(verify(kp.public_key(), b"tampered", &sig).is_err());
    }
}
