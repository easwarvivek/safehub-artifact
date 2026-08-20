//! Encrypted ref-head and key-log records (paper appendix formats).

use crate::ids::{BlobId, HeadHash, RepoId};
use serde::{Deserialize, Serialize};

/// Encrypted, leaf-signed, hash-chained, epoch-bound ref manifest tip.
///
/// Corresponds to `RefHead` in the paper. Ciphertext fields are opaque to the
/// server; only sizes and the CAS compare-and-swap key leak.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefHead {
    /// Repository this head belongs to.
    pub repo_id: RepoId,
    /// Monotonic sequence number.
    pub seq: u64,
    /// AEAD(K_e, refs map) — branch/tag tips encrypted.
    pub enc_refs: Vec<u8>,
    /// SHA-512 Merkle tip / CAS root over encrypted bundle chunk content-ids.
    pub bundle_root: BlobId,
    /// AEAD(K_e, DEK) wrapping the bundle data-encryption key.
    pub dek_wrap: Vec<u8>,
    /// SHA-512 of the previous head (genesis = zeros).
    pub prev_head_hash: HeadHash,
    /// MLS epoch that produced K_e / mk_e.
    pub mls_epoch: u64,
    /// MAC(mk_e, transcript) epoch authenticator.
    pub epoch_tag: Vec<u8>,
    /// When true, an admin co-signature is required (force-push policy).
    pub non_ff: bool,
    /// Pusher ML-DSA-87 leaf signature (FIPS 204; domain `safehub-v1:refhead`).
    pub pusher_sig: Vec<u8>,
    /// Admin ML-DSA-87 co-signature when `non_ff` is set.
    pub admin_cosig: Option<Vec<u8>>,
}

impl RefHead {
    /// Canonical hash used for chain linking and CAS.
    ///
    /// Hashes TLS-presentation bytes ([`crate::encode_ref_head`]), not JSON, so
    /// independent verifiers hashing stored tip bytes agree bit-for-bit.
    pub fn hash(&self) -> HeadHash {
        HeadHash::of(&crate::encode_ref_head(self))
    }

    /// Canonical on-disk / verifier bytes (TLS presentation).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::encode_ref_head(self)
    }
}

/// Key-log entry carrying dual-key-regression token updates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyLogEntry {
    /// Drive / MLS epoch this entry advances.
    pub drive_epoch: u64,
    /// AEAD(ss_e, tokens/blocks) — opaque to the server.
    pub wrapped_dkr: Vec<u8>,
    /// Hash chain link.
    pub prev_hash: HeadHash,
    /// Admin signature over the entry.
    pub admin_sig: Vec<u8>,
}

/// Metadata the server is allowed to see about an uploaded blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMeta {
    /// Content address of ciphertext.
    pub id: BlobId,
    /// Ciphertext byte length (leakage).
    pub size: u64,
    /// Chunk index within a push (0-based).
    pub chunk_index: u32,
    /// Total chunks in the push.
    pub chunk_count: u32,
    /// Client-chosen push correlation id (opaque string).
    pub push_id: String,
}

/// Default encrypted-bundle chunk size (4 MiB) from the parameter appendix.
pub const BUNDLE_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Magic prefix for grafted forward-only snapshots (8-byte wire field).
pub const GRAFT_MAGIC: &[u8; 8] = b"SAFEHUBG";

/// Grafted shallow snapshot for a forward-only invite (paper Appendix C).
///
/// Carries a git bundle of the *current* repository state whose parents below
/// `history_left` are treated as a shallow boundary. Encrypted under the
/// joiner's window before upload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraftedSnapshot {
    /// Inclusive history window start epoch `h` (forward-only grant).
    pub history_left: u64,
    /// Plain git bundle bytes (shallow / tip snapshot).
    pub snapshot_bundle: Vec<u8>,
}

impl GraftedSnapshot {
    /// Encode as `SAFEHUBG ‖ history_left_le64 ‖ bundle`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 + self.snapshot_bundle.len());
        out.extend_from_slice(GRAFT_MAGIC);
        out.extend_from_slice(&self.history_left.to_le_bytes());
        out.extend_from_slice(&self.snapshot_bundle);
        out
    }

    /// Decode a grafted snapshot wire blob.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 || &bytes[..8] != GRAFT_MAGIC {
            return None;
        }
        let mut h = [0u8; 8];
        h.copy_from_slice(&bytes[8..16]);
        Some(Self {
            history_left: u64::from_le_bytes(h),
            snapshot_bundle: bytes[16..].to_vec(),
        })
    }
}

#[cfg(test)]
mod graft_tests {
    use super::*;

    #[test]
    fn grafted_snapshot_roundtrip() {
        let g = GraftedSnapshot {
            history_left: 7,
            snapshot_bundle: b"git-bundle-bytes".to_vec(),
        };
        let wire = g.encode();
        assert_eq!(&wire[..8], GRAFT_MAGIC);
        let back = GraftedSnapshot::decode(&wire).expect("decode");
        assert_eq!(back.history_left, 7);
        assert_eq!(back.snapshot_bundle, b"git-bundle-bytes");
    }
}
