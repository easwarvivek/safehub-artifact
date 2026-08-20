//! JSON result schema documentation (also mirrored in README).

/// Schema version for eval result documents.
#[allow(dead_code)]
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Documented fields for `EvalReport` JSON — see `../schema.json`.
///
/// `status` values: `measured` | `measured-proxy` | `proxy` | `smoke` | `estimated` | `skipped`.
#[allow(dead_code)]
pub fn schema_doc() -> &'static str {
    include_str!("../schema.json")
}
