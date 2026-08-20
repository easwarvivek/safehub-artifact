//! Stable identifiers used across the wire and on disk.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// 32-byte repository identifier (opaque to the server).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepoId(pub [u8; 32]);

impl RepoId {
    /// Generate a fresh random repository id.
    pub fn random() -> Self {
        let u = Uuid::new_v4();
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(u.as_bytes());
        let u2 = Uuid::new_v4();
        bytes[16..].copy_from_slice(u2.as_bytes());
        Self(bytes)
    }

    /// Hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let v = hex::decode(s)?;
        let mut arr = [0u8; 32];
        if v.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        arr.copy_from_slice(&v);
        Ok(Self(arr))
    }
}

impl fmt::Debug for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoId({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Content-address of an encrypted blob (SHA-512 of ciphertext).
///
/// Collision-critical CAS roots use SHA-512 (not BLAKE3 XOF) so claimed
/// BHT/CNS margins match a 512-bit collision-resistant digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobId(pub [u8; 64]);

impl BlobId {
    /// Hash ciphertext bytes with SHA-512.
    pub fn of_ciphertext(ct: &[u8]) -> Self {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(ct);
        let out = hasher.finalize();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&out);
        Self(arr)
    }

    /// Hex encoding (128 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex (128 chars).
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let v = hex::decode(s)?;
        let mut arr = [0u8; 64];
        if v.len() != 64 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        arr.copy_from_slice(&v);
        Ok(Self(arr))
    }
}

impl Serialize for BlobId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// SHA-512 digest of a ref-head record (anti-rollback / fork check).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeadHash(pub [u8; 64]);

impl HeadHash {
    /// Hash arbitrary bytes with SHA-512.
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&out);
        Self(arr)
    }

    /// Hex encoding.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex (128 chars).
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let v = hex::decode(s)?;
        let mut arr = [0u8; 64];
        if v.len() != 64 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        arr.copy_from_slice(&v);
        Ok(Self(arr))
    }

    /// Zero / genesis previous-head sentinel.
    pub fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl Serialize for HeadHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for HeadHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for HeadHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeadHash({})", &self.to_hex()[..16])
    }
}

/// Human-facing owner/name pair (server metadata only; not cryptographic).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepoName {
    /// Owner login (e.g. `alice`).
    pub owner: String,
    /// Repository name (e.g. `widgets`).
    pub name: String,
}

impl RepoName {
    /// Construct `owner/name`.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            name: name.into(),
        }
    }

    /// Parse `owner/name`.
    pub fn parse(s: &str) -> Option<Self> {
        let (owner, name) = s.split_once('/')?;
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return None;
        }
        Some(Self::new(owner, name))
    }
}

impl fmt::Display for RepoName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// User identity handle (authenticated via credentials / CA later).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque device identifier within a user.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub String);
