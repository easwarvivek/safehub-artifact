//! [`AcgkaGroup`] bridge to the vendored OpenMLS implementation.

use std::collections::HashSet;

use crate::{
    acgka::{AcgkaGroup, EpochSecrets, GroupId, MemberId, WelcomePayload},
    error::CryptoError,
    mls::{MlsIdentity, OpenMlsGroup},
};
use async_trait::async_trait;

/// OpenMLS-backed ACGKA adapter.
pub struct OpenMlsAcgka {
    group: Option<OpenMlsGroup>,
    repo_id: Option<[u8; 32]>,
    roster: HashSet<MemberId>,
}

impl OpenMlsAcgka {
    /// Constructs an uninitialized adapter; call [`AcgkaGroup::create`].
    pub fn new() -> Self {
        Self {
            group: None,
            repo_id: None,
            roster: HashSet::new(),
        }
    }

    fn group(&self) -> Result<&OpenMlsGroup, CryptoError> {
        self.group
            .as_ref()
            .ok_or_else(|| CryptoError::Mls("group has not been created".into()))
    }

    fn group_mut(&mut self) -> Result<&mut OpenMlsGroup, CryptoError> {
        self.group
            .as_mut()
            .ok_or_else(|| CryptoError::Mls("group has not been created".into()))
    }
}

impl Default for OpenMlsAcgka {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AcgkaGroup for OpenMlsAcgka {
    async fn create(&mut self, group_id: GroupId, admin: MemberId) -> Result<u64, CryptoError> {
        let repo_id: [u8; 32] = group_id
            .0
            .try_into()
            .map_err(|_| CryptoError::Mls("repository group ID must be 32 bytes".into()))?;
        let identity = MlsIdentity::generate(admin.0.as_bytes())?;
        let group = identity.create_group(repo_id)?;
        let epoch = group.epoch();
        self.group = Some(group);
        self.repo_id = Some(repo_id);
        self.roster.clear();
        self.roster.insert(admin);
        Ok(epoch)
    }

    async fn add(
        &mut self,
        member: MemberId,
        key_package: &[u8],
        history_from_epoch: u64,
    ) -> Result<(WelcomePayload, Vec<u8>), CryptoError> {
        let invitation = self.group_mut()?.add_member(key_package)?;
        self.roster.insert(member);
        Ok((
            WelcomePayload {
                welcome: invitation.welcome,
                history_from_epoch,
            },
            invitation.commit,
        ))
    }

    async fn remove(&mut self, _member: &MemberId) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Mls(
            "removal awaits durable credential-to-leaf indexing".into(),
        ))
    }

    async fn update(&mut self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.group_mut()?.rotate()?.commit)
    }

    async fn rotate(&mut self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.group_mut()?.rotate()?.commit)
    }

    async fn merge(&mut self, commit: &[u8]) -> Result<u64, CryptoError> {
        self.group_mut()?.apply_commit(commit)?;
        Ok(self.group()?.epoch())
    }

    async fn export(
        &self,
        label_transport: &str,
        label_refs: &str,
    ) -> Result<EpochSecrets, CryptoError> {
        if label_transport != "transport" || label_refs != "refs" {
            return Err(CryptoError::Mls(
                "adapter only permits the protocol exporter labels".into(),
            ));
        }
        let repo_id = self
            .repo_id
            .as_ref()
            .ok_or_else(|| CryptoError::Mls("group has not been created".into()))?;
        let keys = self.group()?.export_epoch_keys(repo_id)?;
        Ok(EpochSecrets {
            transport: *keys.transport(),
            refs_mac: *keys.refs(),
            epoch: self.group()?.epoch(),
        })
    }

    fn epoch(&self) -> u64 {
        self.group.as_ref().map_or(0, OpenMlsGroup::epoch)
    }

    fn contains(&self, member: &MemberId) -> bool {
        self.roster.contains(member)
    }
}
