//! SafeHub client: HTTP API + local push/fetch orchestration.

#![deny(missing_docs)]

mod config;
/// Window-verifiable consolidation bindings (admin-authorized, Merkle-bound).
pub mod consolidate;
mod error;
/// Cross-client RefHead checkpoint Compare (fork detection).
pub mod fork;
mod http;
/// KeyPackage pinning / KT witnessing, new-device anchoring, periodic Compare.
pub mod identity;
/// Local MLS epoch material and collab sealing helpers.
pub mod mls_local;
/// Fast-forward classification and force-push co-signature checks.
pub mod policy;
mod pushfetch;

pub use config::{ClientConfig, Credentials};
pub use consolidate::{
    plan_compaction, plan_consolidation, sign_consolidation, sign_consolidation_quorum,
    verify_consolidation_window, ConsolidationPlan, ConsolidationReceipt, MerklePath,
};
pub use error::ClientError;
pub use fork::{compare_checkpoints, ChainEntry, CompareResult, RefCheckpoint};
pub use http::HttpClient;
pub use identity::{
    accept_first_tip, keypackage_digest, periodic_compare_due, safety_number, sign_device_anchor,
    DeviceAnchor, KeyPackagePin,
};
pub use mls_local::{
    accept_welcome_mls, bootstrap_repo_group, consolidate_tip_rewrite, invite_member_mls,
    invite_member_mls_with_graft, load_admin_keypair, load_admin_vk, load_epoch_material,
    load_leaf_vk, load_persisted_group, open_collab, publish_device_key_package, rotate_repo_group,
    seal_collab, EpochMaterial, WelcomeGrant,
};
pub use policy::{
    admin_cosig_sign, admin_cosig_verify, admin_quorum_sign, admin_quorum_verify, classify_non_ff,
    decode_admin_quorum, encode_admin_quorum, is_fast_forward, leaf_sign_message, refs_digest,
    roster_digest, verify_force_push_policy, verify_pusher_sig, ADMIN_QUORUM_MAGIC,
};
pub use pushfetch::{
    bundle_chunks, bundle_chunks_reader, bundle_chunks_seek, fetch_bundles_since, fetch_head_bundle,
    fetch_tip, get_sealed_object, is_ref_only_bundle, open_chunk, open_refs, open_refs_map,
    plan_push, plan_push_reader, plan_push_unsigned, put_sealed_object, push_bundle,
    push_bundle_reader, push_bundle_with_retries, push_round_trips, reconcile_refs_for_cas,
    sign_ref_head, unwrap_dek, verify_fetched_heads, EncryptedRefsMap, FetchResult, PushPlan,
    PushResult, DEFAULT_CAS_RETRIES, DEFAULT_UPLOAD_WINDOW, REF_ONLY_BUNDLE,
};
