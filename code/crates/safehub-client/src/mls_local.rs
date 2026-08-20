//! Local MLS epoch material, durable group persistence, and Welcome import.
//!
//! OpenMLS group state is persisted under the client config directory so
//! invite/rotate survive process boundaries. Welcome bytes are delivered via
//! the server MLS queue; joiners import them and persist exporters + DKR
//! interval grants.

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::http::HttpClient;
use safehub_crypto::dkr::{DualKeyRegression, IntervalDkr};
use safehub_crypto::{MlsIdentity, MlDsa87KeyPair, OpenMlsGroup, AEAD_KEY_LEN, SEC_PARAM_LEN};
use safehub_types::{RepoId, UserId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Persisted MLS exporter material for one repository.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EpochMaterial {
    /// MLS epoch at export time.
    pub epoch: u64,
    /// `Export("safehub-v1:transport")` → seeds DKR / ss_e (λ = 384 bits).
    #[serde(with = "safehub_crypto::params::sec_param_serde")]
    pub transport: [u8; SEC_PARAM_LEN],
    /// `Export("safehub-v1:refs")` → mk_e for epoch tags / collab AEAD.
    pub refs_mac: [u8; AEAD_KEY_LEN],
    /// Inclusive history window start (0 = full; join epoch for forward-only).
    #[serde(default = "default_history_from")]
    pub history_from: u64,
    /// Cryptographic DKR interval token for this member's window (λ bytes).
    ///
    /// Empty in legacy epoch.json files → fall back to `transport`. For
    /// forward-only joiners this is the **reseeded** backward-block token,
    /// independent of every prior segment seed.
    #[serde(default)]
    pub dkr_token: Vec<u8>,
    /// Transport seeds for epochs already superseded by a Commit/Rotate.
    ///
    /// A `RefHead` is sealed under the epoch that produced it, so rotating
    /// must not orphan earlier heads: without this, `sit fetch` after
    /// `sh repo rotate` fails with `aead decrypt failed`.
    #[serde(default)]
    #[zeroize(skip)]
    pub prior_transport: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Epoch MAC keys for epochs already superseded by a Commit/Rotate.
    ///
    /// Mirrors `prior_transport`. A head's epoch tag is computed under the
    /// `mk_e` of the epoch that produced it, so verifying an older head's tag
    /// after a rotation needs that epoch's key retained here.
    #[serde(default)]
    #[zeroize(skip)]
    pub prior_refs_mac: std::collections::BTreeMap<u64, Vec<u8>>,
}

fn default_history_from() -> u64 {
    0
}

impl EpochMaterial {
    /// Carry `previous`'s seeds forward so its epoch stays decryptable.
    pub fn inherit(mut self, previous: Option<&EpochMaterial>) -> Self {
        if let Some(prev) = previous {
            self.prior_transport = prev.prior_transport.clone();
            self.prior_refs_mac = prev.prior_refs_mac.clone();
            if prev.epoch != self.epoch {
                self.prior_transport
                    .insert(prev.epoch, prev.transport.to_vec());
                self.prior_refs_mac
                    .insert(prev.epoch, prev.refs_mac.to_vec());
            }
        }
        self
    }

    /// Directory for a repo's local crypto state.
    pub fn dir(repo: &RepoId) -> Result<PathBuf, ClientError> {
        Ok(ClientConfig::config_dir()?
            .join("repos")
            .join(repo.to_hex()))
    }

    fn path(repo: &RepoId) -> Result<PathBuf, ClientError> {
        Ok(Self::dir(repo)?.join("epoch.json"))
    }

    fn keystore_path(repo: &RepoId) -> Result<PathBuf, ClientError> {
        Ok(Self::dir(repo)?.join("mls_keystore.json"))
    }

    fn signer_path(repo: &RepoId) -> Result<PathBuf, ClientError> {
        Ok(Self::dir(repo)?.join("mls_signer.json"))
    }

    fn admin_path(repo: &RepoId) -> Result<PathBuf, ClientError> {
        Ok(Self::dir(repo)?.join("admin_mldsa.json"))
    }

    /// Whether a durable OpenMLS group keystore exists for `repo`.
    pub fn has_durable_group(repo: &RepoId) -> bool {
        Self::keystore_path(repo)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Persist exporter material (mode 0600 best-effort).
    pub fn save(&self, repo: &RepoId) -> Result<(), ClientError> {
        let dir = Self::dir(repo)?;
        std::fs::create_dir_all(&dir)?;
        let path = Self::path(repo)?;
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Epoch MAC key mk_e for `epoch`, falling back to retained prior keys.
    ///
    /// Returns `None` when the epoch predates what this member retains, in
    /// which case the head's epoch tag cannot be checked (as opposed to
    /// checked and found invalid) — callers must distinguish the two.
    pub fn refs_mac_at(&self, epoch: u64) -> Option<Vec<u8>> {
        if epoch == self.epoch {
            return Some(self.refs_mac.to_vec());
        }
        self.prior_refs_mac.get(&epoch).cloned()
    }

    /// Derive epoch key K_e via DKR for an epoch inside the granted window.
    pub fn epoch_key_at(&self, epoch: u64) -> Result<[u8; AEAD_KEY_LEN], ClientError> {
        if epoch < self.history_from {
            return Err(ClientError::Other(format!(
                "epoch {epoch} before history grant {}",
                self.history_from
            )));
        }
        // Prefer the cryptographic DKR token (forward-only backward-block
        // reseed). Fall back to transport for full-history / legacy files.
        //
        // The fallback used to be unconditional for any epoch other than the
        // current one, which discarded the token and demanded a per-epoch
        // transport seed. A joiner's material is created with prior_transport
        // empty, so every invited member -- full-history included -- failed to
        // read anything pushed before it joined. Key regression exists exactly
        // to derive those earlier keys from the current token, and the window
        // stays enforced: derive_epoch_key rejects anything outside
        // [interval.from, interval.to], and `capped` below pins `from` to the
        // grant, so a forward-only member still cannot reach below its join.
        let mut seed = self.interval_seed();
        if epoch != self.epoch {
            let Some(prior) = self.prior_transport.get(&epoch) else {
                return Err(ClientError::Other(format!(
                    "no retained transport seed for epoch {epoch} (window starts at {})",
                    self.history_from
                )));
            };
            if prior.len() != SEC_PARAM_LEN {
                return Err(ClientError::Other(format!(
                    "corrupt prior transport seed for epoch {epoch}"
                )));
            }
            seed.copy_from_slice(prior);
        }
        let mut dkr = IntervalDkr::with_seed(seed);
        let interval = dkr.advance(self.epoch.max(epoch))?;
        let capped = if self.history_from > 0 {
            safehub_crypto::dkr::DkrInterval {
                from: self.history_from,
                to: interval.to,
                token: interval.token,
            }
        } else {
            interval
        };
        Ok(dkr.derive_epoch_key(&capped, epoch)?)
    }

    /// λ-bit seed used for the current window's DKR derivation.
    fn interval_seed(&self) -> [u8; SEC_PARAM_LEN] {
        let mut seed = [0u8; SEC_PARAM_LEN];
        if self.dkr_token.len() == SEC_PARAM_LEN {
            seed.copy_from_slice(&self.dkr_token);
        } else {
            seed = self.transport;
        }
        seed
    }

    /// Derive epoch key for the material's current epoch.
    pub fn epoch_key(&self) -> Result<[u8; AEAD_KEY_LEN], ClientError> {
        self.epoch_key_at(self.epoch)
    }
}

/// Load persisted epoch material.
pub fn load_epoch_material(repo: &RepoId) -> Result<EpochMaterial, ClientError> {
    let path = EpochMaterial::path(repo)?;
    if !path.exists() {
        return Err(ClientError::Config(format!(
            "missing MLS epoch material at {}; run `sh repo create` or accept a Welcome",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Result of bootstrapping a new repository MLS group.
pub struct BootstrappedGroup {
    /// Live group (persisted to disk before return).
    pub group: OpenMlsGroup,
    /// Exporter material (also persisted).
    pub material: EpochMaterial,
    /// Serialized KeyPackage for invites.
    pub key_package: Vec<u8>,
}

fn persist_group(repo: &RepoId, group: &OpenMlsGroup) -> Result<(), ClientError> {
    let dir = EpochMaterial::dir(repo)?;
    std::fs::create_dir_all(&dir)?;
    group
        .save_keystore(&EpochMaterial::keystore_path(repo)?)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let signer = group
        .signer_bytes()
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let sp = EpochMaterial::signer_path(repo)?;
    std::fs::write(&sp, signer)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sp, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn persist_admin_keypair(repo: &RepoId, admin: &MlDsa87KeyPair) -> Result<(), ClientError> {
    let path = EpochMaterial::admin_path(repo)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(admin)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    // Also publish verifying key for peer verify.
    let vk_path = EpochMaterial::dir(repo)?.join("admin_vk.bin");
    std::fs::write(vk_path, admin.public_key())?;
    Ok(())
}

/// Load the repository admin ML-DSA-87 keypair (creator credential).
pub fn load_admin_keypair(repo: &RepoId) -> Result<MlDsa87KeyPair, ClientError> {
    let path = EpochMaterial::admin_path(repo)?;
    if !path.exists() {
        return Err(ClientError::Config(format!(
            "missing admin ML-DSA key at {}",
            path.display()
        )));
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Load the admin verifying key (for non-FF co-sig checks).
pub fn load_admin_vk(repo: &RepoId) -> Result<Vec<u8>, ClientError> {
    let path = EpochMaterial::dir(repo)?.join("admin_vk.bin");
    if path.exists() {
        return Ok(std::fs::read(path)?);
    }
    Ok(load_admin_keypair(repo)?.public_key().to_vec())
}

/// Leaf verifying key from the durable group signer.
pub fn load_leaf_vk(repo: &RepoId) -> Result<Vec<u8>, ClientError> {
    Ok(load_persisted_group(repo)?.leaf_verifying_key())
}

/// Load a previously persisted OpenMLS group for `repo`.
pub fn load_persisted_group(repo: &RepoId) -> Result<OpenMlsGroup, ClientError> {
    let ks = EpochMaterial::keystore_path(repo)?;
    let sp = EpochMaterial::signer_path(repo)?;
    if !ks.exists() || !sp.exists() {
        return Err(ClientError::Config(format!(
            "missing durable MLS group under {}",
            EpochMaterial::dir(repo)?.display()
        )));
    }
    let signer = std::fs::read(sp)?;
    OpenMlsGroup::load_persisted(&ks, &signer, repo.0)
        .map_err(|e| ClientError::Other(e.to_string()))
}

/// Create a Category-5 MLS group for `repo` owned by `device_name`.
pub fn bootstrap_repo_group(repo: &RepoId, device_name: &str) -> Result<BootstrappedGroup, ClientError> {
    let identity = MlsIdentity::generate(device_name.as_bytes())?;
    let key_package = identity.key_package()?;
    let group = identity.create_group(repo.0)?;
    let keys = group.export_epoch_keys(&repo.0)?;
    let material = EpochMaterial {
        epoch: group.epoch(),
        transport: *keys.transport(),
        refs_mac: *keys.refs(),
        history_from: 0,
        dkr_token: keys.transport().to_vec(),
        prior_transport: Default::default(),
        prior_refs_mac: Default::default(),
    };
    let material = material.inherit(load_epoch_material(repo).ok().as_ref());
    material.save(repo)?;
    persist_group(repo, &group)?;
    // Admin ML-DSA-87 credential for non-FF co-signatures (distinct from leaf).
    let admin = MlDsa87KeyPair::generate().map_err(|e| ClientError::Other(e.to_string()))?;
    persist_admin_keypair(repo, &admin)?;
    // Cache leaf verifying key for tip verify.
    let leaf_vk_path = EpochMaterial::dir(repo)?.join("leaf_vk.bin");
    std::fs::write(leaf_vk_path, group.leaf_verifying_key())?;
    Ok(BootstrappedGroup {
        group,
        material,
        key_package,
    })
}

/// History grant encoded alongside Welcome delivery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WelcomeGrant {
    /// `full` or `forward_only`.
    pub history: String,
    /// Inclusive start epoch for DKR window.
    pub history_from: u64,
    /// Cryptographic DKR interval token (λ bytes) for the joiner's window.
    #[serde(default)]
    pub dkr_token: Vec<u8>,
    /// Optional CAS blob id (hex) of an encrypted grafted snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graft_blob_id: Option<String>,
    /// Opaque MLS Welcome bytes.
    pub welcome: Vec<u8>,
    /// Commit for existing members.
    pub commit: Vec<u8>,
    /// Admin ML-DSA-87 verifying key (for non-FF co-sig checks on the joiner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_vk: Option<Vec<u8>>,
    /// Retained transport seeds for epochs inside a full-history grant.
    ///
    /// A DKR interval token is a segment seed, and `forward_block` (rotate,
    /// removal) starts a new segment under a fresh random seed, so no single
    /// token spans a rotation. A joiner therefore cannot derive keys for epochs
    /// sealed before it joined unless those epochs' seeds travel with the
    /// grant. Empty for forward-only grants, which must not reach below their
    /// join epoch.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub prior_transport: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Epoch MAC keys mirroring `prior_transport`; a head's epoch tag is
    /// verified under the `mk_e` of the epoch that produced it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub prior_refs_mac: std::collections::BTreeMap<u64, Vec<u8>>,
}

/// Invite `user` into `repo` with a durable MLS Welcome on the delivery queue.
///
/// When `forward_only` is set, issues a cryptographic backward DKR block and
/// optionally uploads a grafted tip snapshot (`graft_plaintext`).
pub async fn invite_member_mls(
    client: &HttpClient,
    repo: &RepoId,
    user: &UserId,
    forward_only: bool,
) -> Result<WelcomeGrant, ClientError> {
    invite_member_mls_with_graft(client, repo, user, forward_only, None).await
}

/// Invite with an optional grafted git-bundle plaintext for forward-only joins.
pub async fn invite_member_mls_with_graft(
    client: &HttpClient,
    repo: &RepoId,
    user: &UserId,
    forward_only: bool,
    graft_plaintext: Option<&[u8]>,
) -> Result<WelcomeGrant, ClientError> {
    // Only the repository admin (creator credential) may Add. Joiners receive
    // `admin_vk.bin` but not `admin_mldsa.json`, so this fails closed for them.
    let _admin = load_admin_keypair(repo)?;
    let mut group = load_persisted_group(repo)?;
    let packages = client.list_key_packages(user).await?;
    let kp = packages
        .into_iter()
        .find(|p| p.device == "default")
        .ok_or_else(|| ClientError::Other(format!("no KeyPackage for {}", user.0)))?;
    let invitation = group
        .add_member(&kp.key_package)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let keys = group
        .export_epoch_keys(&repo.0)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let history_from = if forward_only { group.epoch() } else { 0 };

    // DKR window token: forward-only gets a reseeded backward-block token that
    // cannot derive pre-join keys; full-history keeps the MLS transport seed.
    let mut dkr = IntervalDkr::with_seed(*keys.transport());
    let _ = dkr.init().map_err(|e| ClientError::Other(e.to_string()))?;
    let join_interval = if forward_only {
        dkr.backward_block(group.epoch())
            .map_err(|e| ClientError::Other(e.to_string()))?
    } else {
        dkr.advance(group.epoch())
            .map_err(|e| ClientError::Other(e.to_string()))?
    };
    let dkr_token = join_interval.token.to_vec();

    let material = EpochMaterial {
        epoch: group.epoch(),
        transport: *keys.transport(),
        refs_mac: *keys.refs(),
        history_from: 0, // admin retains full history
        dkr_token: dkr_token.clone(), // current epoch seals use the shared segment token
        prior_transport: Default::default(),
        prior_refs_mac: Default::default(),
    };
    let material = material.inherit(load_epoch_material(repo).ok().as_ref());
    material.save(repo)?;
    persist_group(repo, &group)?;

    let mut graft_blob_id = None;
    if forward_only {
        if let Some(bundle) = graft_plaintext {
            let graft = safehub_types::GraftedSnapshot {
                history_left: history_from,
                snapshot_bundle: bundle.to_vec(),
            };
            let wire = graft.encode();
            let push_id = format!("graft-{}", history_from);
            let id = crate::pushfetch::put_sealed_object(
                client, repo, &material, &wire, &push_id,
            )
            .await?;
            graft_blob_id = Some(id.to_hex());
        }
    }

    let grant = WelcomeGrant {
        history: if forward_only {
            "forward_only".into()
        } else {
            "full".into()
        },
        history_from,
        dkr_token,
        graft_blob_id,
        welcome: invitation.welcome.clone(),
        commit: invitation.commit.clone(),
        admin_vk: load_admin_vk(repo).ok(),
        // A full grant carries the retained window so the joiner can read the
        // history it was granted. Forward-only carries nothing: its
        // backward_block token is independent of every prior segment, and
        // shipping these maps would silently undo that.
        prior_transport: if forward_only {
            Default::default()
        } else {
            material.prior_transport.clone()
        },
        prior_refs_mac: if forward_only {
            Default::default()
        } else {
            material.prior_refs_mac.clone()
        },
    };
    let payload = serde_json::to_vec(&grant)?;
    client
        .mls_enqueue(repo, payload, Some(format!("invite:{}", user.0)))
        .await?;
    Ok(grant)
}

/// Publish a device KeyPackage and persist the identity for Welcome import.
pub async fn publish_device_key_package(
    client: &HttpClient,
    device_label: &str,
) -> Result<(), ClientError> {
    let user = client.whoami().await?;
    let device_name = format!("{}-{device_label}", user.0);
    let identity = MlsIdentity::generate(device_name.as_bytes())?;
    let key_package = identity.key_package()?;
    let dir = ClientConfig::config_dir()?.join("device_mls").join(device_label);
    std::fs::create_dir_all(&dir)?;
    identity
        .save_durable(&dir.join("keystore.json"), &dir.join("signer.json"))
        .map_err(|e| ClientError::Other(e.to_string()))?;
    std::fs::write(dir.join("name.txt"), device_name.as_bytes())?;
    client
        .put_key_package(&user, device_label, key_package)
        .await?;
    Ok(())
}

/// Accept the latest Welcome for `repo` (joiner device).
pub async fn accept_welcome_mls(
    client: &HttpClient,
    repo: &RepoId,
    device_label: &str,
) -> Result<EpochMaterial, ClientError> {
    let messages = client.mls_fetch(repo, 0).await?;
    let mut last_grant: Option<WelcomeGrant> = None;
    for env in &messages {
        if let Ok(g) = serde_json::from_slice::<WelcomeGrant>(&env.payload) {
            last_grant = Some(g);
        }
    }
    let grant = last_grant.ok_or_else(|| {
        ClientError::Other("no Welcome grant on MLS delivery queue".into())
    })?;
    let dir = ClientConfig::config_dir()?.join("device_mls").join(device_label);
    let name = std::fs::read_to_string(dir.join("name.txt")).map_err(|_| {
        ClientError::Config(format!(
            "missing device MLS identity at {}; run device key-package publish first",
            dir.display()
        ))
    })?;
    let identity = MlsIdentity::load_durable(
        &dir.join("keystore.json"),
        &dir.join("signer.json"),
        name.trim().as_bytes(),
    )
    .map_err(|e| ClientError::Other(e.to_string()))?;
    let invitation = safehub_crypto::MlsInvitation {
        welcome: grant.welcome,
        commit: grant.commit,
    };
    let group = identity
        .join(&invitation)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let keys = group
        .export_epoch_keys(&repo.0)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let material = EpochMaterial {
        epoch: group.epoch(),
        transport: *keys.transport(),
        refs_mac: *keys.refs(),
        history_from: grant.history_from,
        dkr_token: if grant.dkr_token.len() == SEC_PARAM_LEN {
            grant.dkr_token.clone()
        } else {
            keys.transport().to_vec()
        },
        // Retained window from a full grant; empty for forward-only, which
        // must not be able to reach below its join epoch.
        prior_transport: grant.prior_transport.clone(),
        prior_refs_mac: grant.prior_refs_mac.clone(),
    };
    material.save(repo)?;
    persist_group(repo, &group)?;
    let leaf_vk_path = EpochMaterial::dir(repo)?.join("leaf_vk.bin");
    std::fs::write(leaf_vk_path, group.leaf_verifying_key())?;
    // Persist admin VK from grant when provided (for verifying non-FF cosigs).
    if let Some(vk) = grant.admin_vk {
        let vk_path = EpochMaterial::dir(repo)?.join("admin_vk.bin");
        std::fs::write(vk_path, vk)?;
    }
    // Import grafted snapshot when the invite carried one.
    if let Some(blob_hex) = grant.graft_blob_id.as_ref() {
        let id = safehub_types::BlobId::from_hex(blob_hex)
            .map_err(|e| ClientError::Other(e.to_string()))?;
        let wire = crate::pushfetch::get_sealed_object(client, repo, &material, &id).await?;
        if let Some(graft) = safehub_types::GraftedSnapshot::decode(&wire) {
            let graft_path = EpochMaterial::dir(repo)?.join("graft.bundle");
            std::fs::write(&graft_path, &graft.snapshot_bundle)?;
            let meta_path = EpochMaterial::dir(repo)?.join("graft.json");
            let meta = serde_json::json!({
                "history_left": graft.history_left,
                "bundle_path": graft_path,
                "bytes": graft.snapshot_bundle.len(),
            });
            std::fs::write(meta_path, serde_json::to_vec_pretty(&meta)?)?;
        }
    }
    Ok(material)
}

/// Rotate: PCS heal via MLS self-update + forward DKR block.
///
/// Restricted to the admin credential holder. Ordinary members must not be able
/// to advance the group epoch unilaterally after a removal they did not author.
pub fn rotate_repo_group(repo: &RepoId) -> Result<EpochMaterial, ClientError> {
    let _admin = load_admin_keypair(repo)?;
    let mut group = load_persisted_group(repo)?;
    group
        .rotate()
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let keys = group
        .export_epoch_keys(&repo.0)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    // The rekey is the MLS epoch export itself: `dkr_token` below is
    // `keys.transport()`, which this Commit produced and which is not derivable
    // from any earlier export. A DKR forward block here would resample a local
    // seed that never reaches a member, so it is not the mechanism and is not
    // performed (see app:dkr-sem).
    let material = EpochMaterial {
        epoch: group.epoch(),
        transport: *keys.transport(),
        refs_mac: *keys.refs(),
        history_from: 0,
        dkr_token: keys.transport().to_vec(),
        prior_transport: Default::default(),
        prior_refs_mac: Default::default(),
    };
    let material = material.inherit(load_epoch_material(repo).ok().as_ref());
    material.save(repo)?;
    persist_group(repo, &group)?;
    let leaf_vk_path = EpochMaterial::dir(repo)?.join("leaf_vk.bin");
    std::fs::write(leaf_vk_path, group.leaf_verifying_key())?;
    Ok(material)
}

/// Transport AEAD throughput at a given size. **Not** the consolidation path.
///
/// Re-sealing a span under the current epoch key would let any holder of that
/// key read history predating their grant, which is the composition
/// `app:counterexample` forbids, so the CLI consolidates through
/// `plan_compaction` instead and every component keeps the epoch that sealed
/// it. This function is retained only as a throughput probe; a caller that uses
/// it to consolidate widens windows.
pub fn consolidate_tip_rewrite(
    tip_plaintext: &[u8],
    material: &EpochMaterial,
) -> Result<(Vec<u8>, u64), ClientError> {
    use safehub_crypto::CommittingAead;
    use safehub_types::domain_label;
    let ke = material.epoch_key()?;
    let sealed = CommittingAead::seal(&ke, domain_label("consol").as_bytes(), tip_plaintext)?;
    let opened = CommittingAead::open(&ke, domain_label("consol").as_bytes(), &sealed)?;
    if opened.as_slice() != tip_plaintext {
        return Err(ClientError::Other(
            "consolidation rewrite integrity check failed".into(),
        ));
    }
    let len = sealed.len() as u64;
    Ok((sealed, len))
}

/// Encrypt a collaboration JSON blob under mk_e (refs exporter).
pub fn seal_collab(material: &EpochMaterial, plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
    use safehub_crypto::CommittingAead;
    use safehub_types::domain_label;
    Ok(CommittingAead::seal(
        &material.refs_mac,
        domain_label("collab").as_bytes(),
        plaintext,
    )?)
}

/// Decrypt a collaboration blob under mk_e.
pub fn open_collab(material: &EpochMaterial, sealed: &[u8]) -> Result<Vec<u8>, ClientError> {
    use safehub_crypto::CommittingAead;
    use safehub_types::domain_label;
    Ok(CommittingAead::open(
        &material.refs_mac,
        domain_label("collab").as_bytes(),
        sealed,
    )?)
}
