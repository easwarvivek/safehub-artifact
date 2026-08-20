//! Real OpenMLS repository-group integration.
//!
//! This adapter deliberately exposes serialized MLS messages at its boundary:
//! a delivery service can persist and relay them without learning group state.

use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent},
    group::{
        GroupId as OpenMlsGroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        StagedWelcome, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{KeyPackage, KeyPackageIn, ProtocolVersion},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    signatures::Signer,
    types::Ciphersuite,
    OpenMlsProvider,
};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::{domain_label, AEAD_KEY_LEN, SEC_PARAM_LEN};
use crate::CryptoError;

type Result<T> = std::result::Result<T, CryptoError>;

/// The Category-5 ciphersuite specified by the SafeHub paper.
pub const SAFEHUB_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;

/// A device identity and its local OpenMLS key storage.
pub struct MlsIdentity {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl MlsIdentity {
    /// Generates a fresh ML-DSA-87 device credential.
    pub fn generate(name: impl AsRef<[u8]>) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(SAFEHUB_CIPHERSUITE.signature_algorithm()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_ref().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
        })
    }

    /// Persist identity key store + signer JSON for later Welcome import.
    pub fn save_durable(&self, keystore_path: &std::path::Path, signer_path: &std::path::Path) -> Result<()> {
        let file = std::fs::File::create(keystore_path).map_err(|e| CryptoError::Mls(e.to_string()))?;
        self.provider
            .key_store()
            .save_to_file(&file)
            .map_err(CryptoError::Mls)?;
        let signer = serde_json::to_vec(&self.signer).map_err(|e| CryptoError::Mls(e.to_string()))?;
        std::fs::write(signer_path, signer).map_err(|e| CryptoError::Mls(e.to_string()))?;
        Ok(())
    }

    /// Reload an identity that previously published a KeyPackage.
    pub fn load_durable(
        keystore_path: &std::path::Path,
        signer_path: &std::path::Path,
        name: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let mut provider = OpenMlsRustCrypto::default();
        let file =
            std::fs::File::open(keystore_path).map_err(|e| CryptoError::Mls(e.to_string()))?;
        provider
            .key_store_mut()
            .load_from_file(&file)
            .map_err(CryptoError::Mls)?;
        let signer_json =
            std::fs::read(signer_path).map_err(|e| CryptoError::Mls(e.to_string()))?;
        let signer: SignatureKeyPair =
            serde_json::from_slice(&signer_json).map_err(|e| CryptoError::Mls(e.to_string()))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_ref().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
        })
    }

    /// Builds a single-use KeyPackage while retaining its private init key.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        KeyPackage::builder()
            .build(
                SAFEHUB_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls_error)?
            .key_package()
            .tls_serialize_detached()
            .map_err(wire_error)
    }

    /// Creates an MLS group whose group ID is the 32-byte repository ID.
    pub fn create_group(self, repo_id: [u8; 32]) -> Result<OpenMlsGroup> {
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(),
            OpenMlsGroupId::from_slice(&repo_id),
            self.credential,
        )
        .map_err(mls_error)?;
        Ok(OpenMlsGroup {
            provider: self.provider,
            signer: self.signer,
            group,
        })
    }

    /// Consumes this identity and joins from an MLS Welcome.
    pub fn join(self, invitation: &MlsInvitation) -> Result<OpenMlsGroup> {
        let message =
            MlsMessageIn::tls_deserialize_exact(&invitation.welcome).map_err(wire_error)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(unavailable("expected MLS Welcome"));
        };
        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(mls_error)?
            .into_group(&self.provider)
            .map_err(mls_error)?;
        Ok(OpenMlsGroup {
            provider: self.provider,
            signer: self.signer,
            group,
        })
    }
}

/// Serialized add-member output suitable for an untrusted delivery service.
#[derive(Clone, Debug)]
pub struct MlsInvitation {
    /// Welcome sent only to the joining member.
    pub welcome: Vec<u8>,
    /// Commit relayed to all existing members.
    pub commit: Vec<u8>,
}

/// A serialized MLS epoch-changing commit.
#[derive(Clone, Debug)]
pub struct MlsMemberChange {
    /// TLS-encoded MLS commit.
    pub commit: Vec<u8>,
}

/// A TLS-encoded, MLS-protected application message.
#[derive(Clone, Debug)]
pub struct MlsApplicationMessage(pub Vec<u8>);

/// Independent MLS exporter outputs for one repository epoch.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlsEpochKeys {
    transport: [u8; SEC_PARAM_LEN],
    refs: [u8; AEAD_KEY_LEN],
}

impl MlsEpochKeys {
    /// Key material used by the bundle-key progression layer (λ = 384 bits).
    pub fn transport(&self) -> &[u8; SEC_PARAM_LEN] {
        &self.transport
    }

    /// Key material used to authenticate and encrypt ref manifests.
    pub fn refs(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.refs
    }
}

/// A repository MLS group bound to one local device.
pub struct OpenMlsGroup {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl OpenMlsGroup {
    /// Current MLS epoch.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Number of active device leaves.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Repository group id bytes (32).
    pub fn group_id_bytes(&self) -> Result<[u8; 32]> {
        let raw = self.group.group_id().as_slice();
        raw.try_into()
            .map_err(|_| unavailable("group id must be 32 bytes"))
    }

    /// Persist OpenMLS key store to `path` (JSON via memory_storage persistence).
    pub fn save_keystore(&self, path: &std::path::Path) -> Result<()> {
        let file = std::fs::File::create(path).map_err(|e| CryptoError::Mls(e.to_string()))?;
        self.provider
            .key_store()
            .save_to_file(&file)
            .map_err(CryptoError::Mls)
    }

    /// Serialize the leaf signature key pair (durable identity).
    pub fn signer_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.signer).map_err(|e| CryptoError::Mls(e.to_string()))
    }

    /// Leaf ML-DSA-87 verifying key (encoded).
    pub fn leaf_verifying_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Signature verifying keys of every current group member (roster).
    ///
    /// Used by fetch to check RefHead leaf signatures against the MLS tree
    /// rather than only the local device key.
    pub fn member_signature_keys(&self) -> Vec<Vec<u8>> {
        self.group
            .members()
            .map(|m| m.signature_key)
            .collect()
    }

    /// Detached ML-DSA-87 signature with the group's leaf credential.
    pub fn sign_detached(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer
            .sign(message)
            .map_err(|e| CryptoError::Mls(format!("leaf ML-DSA sign: {e:?}")))
    }

    /// Reload a group from a persisted key store + signer.
    pub fn load_persisted(
        keystore_path: &std::path::Path,
        signer_json: &[u8],
        repo_id: [u8; 32],
    ) -> Result<Self> {
        let mut provider = OpenMlsRustCrypto::default();
        let file =
            std::fs::File::open(keystore_path).map_err(|e| CryptoError::Mls(e.to_string()))?;
        provider
            .key_store_mut()
            .load_from_file(&file)
            .map_err(CryptoError::Mls)?;
        let signer: SignatureKeyPair =
            serde_json::from_slice(signer_json).map_err(|e| CryptoError::Mls(e.to_string()))?;
        let group_id = OpenMlsGroupId::from_slice(&repo_id);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(mls_error)?
            .ok_or_else(|| unavailable("no MlsGroup in persisted storage"))?;
        Ok(Self {
            provider,
            signer,
            group,
        })
    }

    /// Adds a member and locally merges the generated commit.
    pub fn add_member(&mut self, key_package_wire: &[u8]) -> Result<MlsInvitation> {
        let key_package = KeyPackageIn::tls_deserialize_exact(key_package_wire)
            .map_err(wire_error)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_error)?;
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(mls_error)?;
        let commit = serialize_message(&commit)?;
        let welcome = serialize_message(&welcome)?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        Ok(MlsInvitation { welcome, commit })
    }

    /// Performs a self-update for post-compromise healing.
    pub fn rotate(&mut self) -> Result<MlsMemberChange> {
        let commit = self
            .group
            .self_update(
                &self.provider,
                &self.signer,
                openmls::treesync::LeafNodeParameters::default(),
            )
            .map_err(mls_error)?
            .into_commit();
        let commit = serialize_message(&commit)?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        Ok(MlsMemberChange { commit })
    }

    /// Processes and merges a commit received from another member.
    pub fn apply_commit(&mut self, wire: &[u8]) -> Result<()> {
        let message = decode_protocol_message(wire)?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(mls_error)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => self
                .group
                .merge_staged_commit(&self.provider, *staged)
                .map_err(mls_error),
            _ => Err(unavailable("expected MLS commit")),
        }
    }

    /// Encrypts and authenticates a small collaboration/control message.
    pub fn protect_application(&mut self, plaintext: &[u8]) -> Result<MlsApplicationMessage> {
        let message = self
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls_error)?;
        Ok(MlsApplicationMessage(serialize_message(&message)?))
    }

    /// Verifies and decrypts a collaboration/control message.
    pub fn unprotect_application(&mut self, message: &MlsApplicationMessage) -> Result<Vec<u8>> {
        let protocol = decode_protocol_message(&message.0)?;
        let processed = self
            .group
            .process_message(&self.provider, protocol)
            .map_err(mls_error)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(application.into_bytes())
            }
            _ => Err(unavailable("expected MLS application message")),
        }
    }

    /// Exports separately labeled, repository-bound epoch secrets.
    pub fn export_epoch_keys(&self, repo_id: &[u8; 32]) -> Result<MlsEpochKeys> {
        let transport = self
            .group
            .export_secret(
                self.provider.crypto(),
                &domain_label("transport"),
                repo_id,
                SEC_PARAM_LEN,
            )
            .map_err(mls_error)?;
        let refs = self
            .group
            .export_secret(
                self.provider.crypto(),
                &domain_label("refs"),
                repo_id,
                AEAD_KEY_LEN,
            )
            .map_err(mls_error)?;
        Ok(MlsEpochKeys {
            transport: transport
                .try_into()
                .map_err(|_| unavailable("invalid transport exporter length"))?,
            refs: refs
                .try_into()
                .map_err(|_| unavailable("invalid refs exporter length"))?,
        })
    }
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SAFEHUB_CIPHERSUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn decode_protocol_message(wire: &[u8]) -> Result<openmls::framing::ProtocolMessage> {
    MlsMessageIn::tls_deserialize_exact(wire)
        .map_err(wire_error)?
        .try_into_protocol_message()
        .map_err(wire_error)
}

fn serialize_message(message: &openmls::framing::MlsMessageOut) -> Result<Vec<u8>> {
    message.tls_serialize_detached().map_err(wire_error)
}

fn mls_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::Mls(error.to_string())
}

fn wire_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::Mls(format!("invalid MLS wire message: {error}"))
}

fn unavailable(message: impl Into<String>) -> CryptoError {
    CryptoError::Mls(message.into())
}
