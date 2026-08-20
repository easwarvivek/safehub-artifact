//! Shared protocol types for SafeHub.
//!
//! Domain-separated labels use the prefix `safehub-v1:` as specified in the
//! paper appendix (message formats). Logical fields are JSON/HTTP-friendly for
//! control-plane APIs; hash-chained and signed structures use TLS-presentation
//! canonical bytes via [`canon`].

#![deny(missing_docs)]

mod canon;
mod ids;
mod messages;
mod refs;

pub use canon::{decode_ref_head, encode_key_log_entry, encode_ref_head};
pub use ids::*;
pub use messages::*;
pub use refs::*;

/// Domain-separation prefix for all SafeHub protocol labels.
pub const DOMAIN_PREFIX: &str = "safehub-v1:";

/// Label helper: `safehub-v1:{suffix}`.
pub fn domain_label(suffix: &str) -> String {
    format!("{DOMAIN_PREFIX}{suffix}")
}
