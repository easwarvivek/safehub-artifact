//! Cryptographic interfaces for SafeHub.
//!
//! # OpenMLS integration
//!
//! The product surface depends only on the traits in [`acgka`], [`aead`], and
//! [`dkr`]. The sibling OpenMLS fork under `code/vendor/openmls` plugs in via
//! [`adapters::openmls_adapter`] (feature `openmls`). Until that adapter is
//! fully wired to the Category-5 ciphersuite, use [`adapters::stub`].

#![deny(missing_docs)]

/// True when the vendored OpenMLS Category-5 adapter is compiled into this build.
pub const OPENMLS_LINKED: bool = cfg!(feature = "openmls");

/// True when the development stub adapter is compiled into this build.
///
/// The stub is the bare-crate default feature and does not provide real MLS
/// security. Its presence in the build graph does not put it on the runtime
/// membership path: `safehub-client` calls [`OpenMlsGroup`] directly.
pub const STUB_LINKED: bool = cfg!(feature = "stub");

/// Name of the MLS ciphersuite this build would create groups with.
pub const MLS_CIPHERSUITE_NAME: &str = if cfg!(feature = "openmls") {
    "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87"
} else {
    "none (openmls feature not linked)"
};

pub mod acgka;
pub mod adapters;
pub mod aead;
pub mod dkr;
pub mod error;
pub mod mldsa;
pub mod params;
#[cfg(feature = "openmls")]
pub mod mls;

pub use acgka::{AcgkaGroup, EpochSecrets, GroupId, MemberId, WelcomePayload};
pub use aead::{
    aead_backend_name, derive_cas_seal_key, derive_head_seal_key, derive_secret_seal_key,
    hardware_aes_likely, AeadError, CommittingAead, AEAD_BACKEND, MAX_SEALS_PER_KEY,
};
pub use dkr::{
    cap_interval, DkrInterval, DualKeyRegression, IntervalDkr, StubDkr, DKR_SEGMENT_CAPACITY,
};
pub use error::CryptoError;
pub use mldsa::{
    admin_cosig_message, refhead_leaf_message, sign_with_seed, verify as mldsa_verify,
    MlDsa87KeyPair, MLDSA87_SIG_LEN, MLDSA87_VK_LEN,
};
pub use params::{
    blake3_512, domain_label, sha512_digest, AEAD_KEY_LEN, DIGEST_LEN, DOMAIN_PREFIX,
    SEC_PARAM_BITS, SEC_PARAM_LEN, TAG_LEN,
};
#[cfg(feature = "openmls")]
pub use mls::{
    MlsApplicationMessage, MlsEpochKeys, MlsIdentity, MlsInvitation, MlsMemberChange,
    OpenMlsGroup, SAFEHUB_CIPHERSUITE,
};
