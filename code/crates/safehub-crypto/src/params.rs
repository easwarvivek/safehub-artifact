//! Concrete security parameters from the SafeHub paper (appendix D / §6).
//!
//! Integrity-critical digests and tags target >128-bit quantum attack cost
//! (BHT/QRACM/CNS). AES-256 confidentiality remains the Category-5 Grover
//! floor of 128 bits.

/// Domain-separation prefix for all protocol labels (`safehub-v1:`).
pub const DOMAIN_PREFIX: &str = "safehub-v1:";

/// Security parameter λ in bits (DKR node / RO output length).
pub const SEC_PARAM_BITS: usize = 384;

/// Security parameter λ in bytes (`SEC_PARAM_BITS / 8`).
pub const SEC_PARAM_LEN: usize = SEC_PARAM_BITS / 8;

/// Collision-resistant digest length in bytes (SHA-512).
pub const DIGEST_LEN: usize = 64;

/// Outer AEAD / epoch MAC tag length in bytes (HMAC-SHA-512-256).
pub const TAG_LEN: usize = 32;

/// AES-256 / DEK key length in bytes.
pub const AEAD_KEY_LEN: usize = 32;

/// Build `safehub-v1:{suffix}`.
pub fn domain_label(suffix: &str) -> String {
    format!("{DOMAIN_PREFIX}{suffix}")
}

/// SHA-512 digest (collision-critical CAS / head roots).
pub fn sha512_digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; DIGEST_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// BLAKE3-512 XOF (non-collision-critical local indexing only; not used for
/// claimed BHT/CNS margins).
pub fn blake3_512(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    blake3::Hasher::new()
        .update(data)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// Serde helpers for `[u8; SEC_PARAM_LEN]` (serde only derives arrays up to 32).
pub mod sec_param_serde {
    use super::SEC_PARAM_LEN;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize as a byte array / JSON array of numbers.
    pub fn serialize<S>(value: &[u8; SEC_PARAM_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_slice().serialize(serializer)
    }

    /// Deserialize from a byte sequence of length [`SEC_PARAM_LEN`].
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SEC_PARAM_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        v.try_into()
            .map_err(|v: Vec<u8>| D::Error::custom(format!("expected {SEC_PARAM_LEN} bytes, got {}", v.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_prefix_matches_paper() {
        assert_eq!(DOMAIN_PREFIX, "safehub-v1:");
        assert_eq!(domain_label("transport"), "safehub-v1:transport");
        assert_eq!(SEC_PARAM_LEN, 48);
        assert_eq!(DIGEST_LEN, 64);
        assert_eq!(TAG_LEN, 32);
    }

    #[test]
    fn sha512_digest_length() {
        assert_eq!(sha512_digest(b"cas").len(), 64);
        assert_ne!(sha512_digest(b"a"), sha512_digest(b"b"));
    }

    #[test]
    fn blake3_512_length() {
        assert_eq!(blake3_512(b"cas").len(), 64);
        assert_ne!(blake3_512(b"a"), blake3_512(b"b"));
    }

    #[test]
    fn domain_labels_unique_and_prefixed() {
        let labels = [
            "transport",
            "refs",
            "refhead",
            "epoch-tag",
            "dek-wrap",
            "refs-digest",
            "bundle-chunk",
            "consol",
            "collab",
            "admin-cosig",
            "aead-keys",
            "aead-pad",
            "head-seal",
            "cas-obj-key",
            "secret-seal-key",
            "keylog",
            "cas-obj",
            "consol-leaf",
            "consol-node",
            "consol-epoch",
            "consol-empty",
            "consolidation",
            "epoch-commit",
            "epoch-witness",
            "device-anchor",
            "keypackage-pin",
            "dkr-epoch:0",
        ];
        let mut set = std::collections::BTreeSet::new();
        for s in labels {
            let full = domain_label(s);
            assert!(full.starts_with(DOMAIN_PREFIX));
            assert!(set.insert(full), "duplicate label {s}");
        }
    }
}
