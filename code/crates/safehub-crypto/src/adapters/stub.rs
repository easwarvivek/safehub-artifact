//! In-memory ACGKA stub for local development.
//!
//! Named so the OpenMLS adapter can replace it without touching call sites:
//! construct via `Box<dyn AcgkaGroup>`.

use crate::acgka::{AcgkaGroup, EpochSecrets, GroupId, MemberId, WelcomePayload};
use crate::error::CryptoError;
use crate::params::{AEAD_KEY_LEN, SEC_PARAM_LEN};
use async_trait::async_trait;
use sha2::{Digest, Sha512};
use std::collections::HashSet;

/// Development-only group state (no real MLS transcripts).
pub struct StubAcgka {
    group_id: Option<GroupId>,
    admin: Option<MemberId>,
    members: HashSet<MemberId>,
    epoch: u64,
    /// Seed for deterministic Export in tests.
    export_seed: [u8; 32],
}

impl Default for StubAcgka {
    fn default() -> Self {
        Self::new()
    }
}

impl StubAcgka {
    /// Empty stub group.
    pub fn new() -> Self {
        let mut export_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut export_seed);
        Self {
            group_id: None,
            admin: None,
            members: HashSet::new(),
            epoch: 0,
            export_seed,
        }
    }

    fn bump(&mut self) -> u64 {
        self.epoch = self.epoch.saturating_add(1);
        self.epoch
    }

    fn fake_commit(tag: &str, epoch: u64) -> Vec<u8> {
        format!("stub-commit:{tag}:{epoch}").into_bytes()
    }
}

#[async_trait]
impl AcgkaGroup for StubAcgka {
    async fn create(&mut self, group_id: GroupId, admin: MemberId) -> Result<u64, CryptoError> {
        self.group_id = Some(group_id);
        self.admin = Some(admin.clone());
        self.members.clear();
        self.members.insert(admin);
        self.epoch = 0;
        Ok(0)
    }

    async fn add(
        &mut self,
        member: MemberId,
        key_package: &[u8],
        history_from_epoch: u64,
    ) -> Result<(WelcomePayload, Vec<u8>), CryptoError> {
        if key_package.is_empty() {
            return Err(CryptoError::Stub("empty key package"));
        }
        self.members.insert(member.clone());
        let epoch = self.bump();
        let welcome = WelcomePayload {
            welcome: format!("stub-welcome:{}:{history_from_epoch}", member.0).into_bytes(),
            history_from_epoch,
        };
        Ok((welcome, Self::fake_commit("add", epoch)))
    }

    async fn remove(&mut self, member: &MemberId) -> Result<Vec<u8>, CryptoError> {
        if !self.members.remove(member) {
            return Err(CryptoError::UnknownMember);
        }
        let epoch = self.bump();
        Ok(Self::fake_commit("remove", epoch))
    }

    async fn update(&mut self) -> Result<Vec<u8>, CryptoError> {
        let epoch = self.bump();
        Ok(Self::fake_commit("update", epoch))
    }

    async fn rotate(&mut self) -> Result<Vec<u8>, CryptoError> {
        let epoch = self.bump();
        Ok(Self::fake_commit("rotate", epoch))
    }

    async fn merge(&mut self, commit: &[u8]) -> Result<u64, CryptoError> {
        if commit.is_empty() {
            return Err(CryptoError::Stub("empty commit"));
        }
        Ok(self.bump())
    }

    async fn export(
        &self,
        label_transport: &str,
        label_refs: &str,
    ) -> Result<EpochSecrets, CryptoError> {
        let mut transport = [0u8; SEC_PARAM_LEN];
        let mut refs_mac = [0u8; AEAD_KEY_LEN];
        let mut h = Sha512::new();
        h.update(self.export_seed);
        h.update(label_transport.as_bytes());
        h.update(self.epoch.to_le_bytes());
        let t = h.finalize_reset();
        transport.copy_from_slice(&t[..SEC_PARAM_LEN]);
        h.update(self.export_seed);
        h.update(label_refs.as_bytes());
        h.update(self.epoch.to_le_bytes());
        refs_mac.copy_from_slice(&h.finalize()[..AEAD_KEY_LEN]);
        Ok(EpochSecrets {
            transport,
            refs_mac,
            epoch: self.epoch,
        })
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn contains(&self, member: &MemberId) -> bool {
        self.members.contains(member)
    }
}
