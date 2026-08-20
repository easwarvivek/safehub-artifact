//! Identity hardening: KeyPackage pinning / key-transparency witnessing,
//! new-device anchoring, and the periodic-Compare cadence.
//!
//! The host mediates KeyPackage fetch, so a host that is also the identity
//! provider could substitute a KeyPackage it controls and read plaintext. The
//! UC theorem idealizes this away inside `F_ca`; in a real deployment it is the
//! most likely point of compromise. This module gives the client three checks
//! that do not depend on trusting the host:
//!
//!   * a pinned KeyPackage digest ("safety number") that a substituted package
//!     fails, optionally witnessed against a key-transparency log root;
//!   * a rule that a freshly provisioned device may not accept a server-
//!     presented tip on trust-on-first-use, but only against a signed anchor
//!     from an existing device (or one carried in the Welcome); and
//!   * a periodic-Compare policy so cross-party equivocation is bounded in time
//!     rather than only caught when a user happens to run Compare.
//!
//! Deployments must use an external IdP, a key-transparency log, or manual
//! safety-number pins (see also the limitations section of the paper).

use crate::error::ClientError;
use crate::fork::RefCheckpoint;
use safehub_crypto::mldsa::{self, MlDsa87KeyPair};
use safehub_types::{domain_label, HeadHash, RepoId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// A pinned KeyPackage identity: the digest a device is expected to present.
///
/// Recorded out-of-band (safety-number verification) or from a key-transparency
/// log; any later KeyPackage the host serves for this user/device must hash to
/// the same value or it is a substitution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackagePin {
    /// User the KeyPackage belongs to.
    pub user: String,
    /// Device label within that user.
    pub device: String,
    /// SHA-512 digest of the canonical KeyPackage bytes.
    pub digest: HeadHash,
    /// Optional key-transparency log root this pin was witnessed under.
    #[serde(default)]
    pub kt_root: Option<HeadHash>,
}

/// Digest of KeyPackage bytes under a domain-separated hash.
pub fn keypackage_digest(kp_bytes: &[u8]) -> HeadHash {
    let mut h = Sha512::new();
    h.update(domain_label("keypackage-pin").as_bytes());
    h.update(kp_bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    HeadHash(out)
}

/// Human-comparable safety number (first bytes of the digest, grouped).
pub fn safety_number(pin: &KeyPackagePin) -> String {
    pin.digest.0[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

impl KeyPackagePin {
    /// Pin a KeyPackage seen out-of-band.
    pub fn new(user: &str, device: &str, kp_bytes: &[u8]) -> Self {
        Self {
            user: user.to_string(),
            device: device.to_string(),
            digest: keypackage_digest(kp_bytes),
            kt_root: None,
        }
    }

    /// Verify that a server-supplied KeyPackage matches this pin.
    ///
    /// This is the check that defeats host KeyPackage substitution: the host can
    /// hand out any bytes it likes, but only the pinned ones verify.
    pub fn verify(&self, kp_bytes: &[u8]) -> Result<(), ClientError> {
        if keypackage_digest(kp_bytes) == self.digest {
            Ok(())
        } else {
            Err(ClientError::Other(format!(
                "KeyPackage for {}/{} does not match the pinned safety number \
                 (possible host substitution)",
                self.user, self.device
            )))
        }
    }
}

/// A signed statement, from an existing device, of the tip a new device should
/// anchor to. Prevents trust-on-first-use onto a server-forked chain (W03).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAnchor {
    /// Repository this anchor is for.
    pub repo_id: RepoId,
    /// Checkpoint tip binding the existing device attests to.
    pub tip_binding: HeadHash,
    /// Tip sequence, for a human-readable sanity check.
    pub tip_seq: u64,
    /// ML-DSA-87 signature by an existing (already-trusted) device.
    pub sig: Vec<u8>,
}

fn anchor_message(repo: &RepoId, tip_binding: &HeadHash, tip_seq: u64) -> Vec<u8> {
    let mut m = domain_label("device-anchor").into_bytes();
    m.extend_from_slice(&repo.0);
    m.extend_from_slice(&tip_binding.0);
    m.extend_from_slice(&tip_seq.to_le_bytes());
    m
}

/// Sign a device anchor with an existing device's key (over a checkpoint tip).
pub fn sign_device_anchor(
    repo: &RepoId,
    checkpoint: &RefCheckpoint,
    existing_device: &MlDsa87KeyPair,
) -> Result<DeviceAnchor, ClientError> {
    let tip_seq = checkpoint.tip_seq().unwrap_or(0);
    let msg = anchor_message(repo, &checkpoint.tip_binding, tip_seq);
    let sig = existing_device
        .sign(&msg)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(DeviceAnchor {
        repo_id: *repo,
        tip_binding: checkpoint.tip_binding,
        tip_seq,
        sig,
    })
}

/// A new device's decision when the server presents `checkpoint` for first use.
///
/// Returns `Ok` only when an anchor signed by a known existing-device key
/// attests to exactly this tip. Absent an anchor the presented tip is refused:
/// a new device has no local history to detect a server fork on its own.
pub fn accept_first_tip(
    repo: &RepoId,
    checkpoint: &RefCheckpoint,
    anchor: Option<&DeviceAnchor>,
    existing_device_vks: &[&[u8]],
) -> Result<(), ClientError> {
    let Some(anchor) = anchor else {
        return Err(ClientError::Other(
            "new device refused to accept a server-presented tip without an \
             existing-device anchor (trust-on-first-use is disabled)"
                .into(),
        ));
    };
    if anchor.repo_id != *repo || anchor.tip_binding != checkpoint.tip_binding {
        return Err(ClientError::Other(
            "device anchor does not bind the presented checkpoint tip".into(),
        ));
    }
    let msg = anchor_message(repo, &anchor.tip_binding, anchor.tip_seq);
    if existing_device_vks
        .iter()
        .any(|vk| mldsa::verify(vk, &msg, &anchor.sig).is_ok())
    {
        Ok(())
    } else {
        Err(ClientError::Other(
            "device anchor is not signed by any known existing-device key".into(),
        ))
    }
}

/// Whether a periodic Compare is due (W02).
///
/// Fork detection is only guaranteed under a liveness assumption: the checkpoint
/// travels as an MLS application message over the (malicious) server, which can
/// delay but not forge it, so `Forked` surfaces once any honest checkpoint is
/// delivered. Running Compare on a cadence bounds how long a partition can stay
/// silent to roughly `cadence` rather than "until a user thinks to check".
pub fn periodic_compare_due(last_compare_secs: u64, now_secs: u64, cadence_secs: u64) -> bool {
    cadence_secs > 0 && now_secs.saturating_sub(last_compare_secs) >= cadence_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::RefCheckpoint;
    use safehub_types::{BlobId, HeadHash, RefHead, RepoId};

    fn head(seq: u64, prev: HeadHash) -> RefHead {
        RefHead {
            repo_id: RepoId([5u8; 32]),
            seq,
            enc_refs: vec![seq as u8],
            bundle_root: BlobId([seq as u8; 64]),
            dek_wrap: vec![seq as u8],
            prev_head_hash: prev,
            mls_epoch: 0,
            epoch_tag: vec![0; 32],
            non_ff: false,
            pusher_sig: vec![],
            admin_cosig: None,
        }
    }

    #[test]
    fn a_substituted_keypackage_fails_the_pin() {
        let pin = KeyPackagePin::new("alice", "laptop", b"real-keypackage-bytes");
        assert!(pin.verify(b"real-keypackage-bytes").is_ok());
        let err = pin.verify(b"host-substituted-keypackage").unwrap_err();
        assert!(err.to_string().contains("substitution"));
        assert!(!safety_number(&pin).is_empty());
    }

    #[test]
    fn a_new_device_refuses_an_unwitnessed_tip() {
        let repo = RepoId([5u8; 32]);
        let h0 = head(1, HeadHash::zero());
        let cp = RefCheckpoint::from_heads(repo, &[h0]);
        // No anchor: trust-on-first-use is refused outright.
        assert!(accept_first_tip(&repo, &cp, None, &[]).is_err());
    }

    #[test]
    fn a_new_device_accepts_a_tip_anchored_by_an_existing_device() {
        let repo = RepoId([5u8; 32]);
        let h0 = head(1, HeadHash::zero());
        let h1 = head(2, h0.hash());
        let cp = RefCheckpoint::from_heads(repo, &[h0, h1]);
        let existing = MlDsa87KeyPair::generate().unwrap();
        let anchor = sign_device_anchor(&repo, &cp, &existing).unwrap();
        accept_first_tip(&repo, &cp, Some(&anchor), &[existing.public_key()])
            .expect("a correctly anchored tip must be accepted");
    }

    #[test]
    fn an_anchor_for_a_different_tip_is_rejected() {
        let repo = RepoId([5u8; 32]);
        let h0 = head(1, HeadHash::zero());
        let real = RefCheckpoint::from_heads(repo, &[h0.clone()]);
        let forked = RefCheckpoint::from_heads(repo, &[head(1, HeadHash([9u8; 64]))]);
        let existing = MlDsa87KeyPair::generate().unwrap();
        let anchor = sign_device_anchor(&repo, &real, &existing).unwrap();
        // Server presents a forked tip but replays the honest-tip anchor.
        assert!(accept_first_tip(&repo, &forked, Some(&anchor), &[existing.public_key()]).is_err());
    }

    #[test]
    fn an_anchor_from_an_unknown_device_is_rejected() {
        let repo = RepoId([5u8; 32]);
        let cp = RefCheckpoint::from_heads(repo, &[head(1, HeadHash::zero())]);
        let existing = MlDsa87KeyPair::generate().unwrap();
        let stranger = MlDsa87KeyPair::generate().unwrap();
        let anchor = sign_device_anchor(&repo, &cp, &existing).unwrap();
        assert!(accept_first_tip(&repo, &cp, Some(&anchor), &[stranger.public_key()]).is_err());
    }

    #[test]
    fn periodic_compare_fires_after_the_cadence() {
        assert!(!periodic_compare_due(100, 150, 60));
        assert!(periodic_compare_due(100, 161, 60));
        assert!(!periodic_compare_due(100, 200, 0)); // disabled
    }
}
