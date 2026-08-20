//! `shub crypto report` — what this binary actually linked.
//!
//! Provenance for published measurements. `safehub-crypto` still carries a
//! development `stub` feature as its bare-crate default, so a reader of an
//! eval JSON cannot otherwise tell whether a cell was produced by the real
//! Category-5 OpenMLS path or by the stub. The manifest asserting
//! `features = ["openmls"]` is a claim about the build graph; this command is a
//! claim about the binary that ran.

use clap::Subcommand;

/// Crypto provenance commands.
#[derive(Debug, Subcommand)]
pub enum CryptoCmd {
    /// Report the linked MLS ciphersuite, AEAD backend, and features.
    Report {
        /// Emit machine-readable JSON (used by the eval harness).
        #[arg(long)]
        json: bool,
    },
}

// Read the linkage from the crypto crate itself: these are features of
// `safehub-crypto`, not of this CLI, so asking `cfg!` here would always answer
// false and quietly report the wrong thing.
const STUB_LINKED: bool = safehub_crypto::STUB_LINKED;
const OPENMLS_LINKED: bool = safehub_crypto::OPENMLS_LINKED;

fn ciphersuite_name() -> &'static str {
    safehub_crypto::MLS_CIPHERSUITE_NAME
}

/// Runs `shub crypto <cmd>`.
pub async fn run(cmd: CryptoCmd) -> anyhow::Result<()> {
    match cmd {
        CryptoCmd::Report { json } => {
            let suite = ciphersuite_name();
            let aead = safehub_crypto::aead_backend_name();
            let mls_backend = if OPENMLS_LINKED {
                "vendored OpenMLS (draft-ietf-mls-pq-ciphersuites)"
            } else {
                "none"
            };
            let mut features: Vec<&str> = Vec::new();
            if OPENMLS_LINKED {
                features.push("openmls");
            }
            if STUB_LINKED {
                features.push("stub");
            }
            let effective = if OPENMLS_LINKED {
                "openmls"
            } else if STUB_LINKED {
                "stub (NOT SECURE — development only)"
            } else {
                "none"
            };

            if json {
                let doc = serde_json::json!({
                    "mls_ciphersuite": suite,
                    "mls_backend": mls_backend,
                    "aead_backend": aead,
                    "features": features,
                    "effective_acgka_path": effective,
                    "stub_linked": STUB_LINKED,
                    "openmls_linked": OPENMLS_LINKED,
                    "dkr_segment_capacity": safehub_crypto::DKR_SEGMENT_CAPACITY,
                    "sec_param_bits": safehub_crypto::SEC_PARAM_BITS,
                    "max_seals_per_key": safehub_crypto::MAX_SEALS_PER_KEY,
                    "mldsa87_sig_len": safehub_crypto::MLDSA87_SIG_LEN,
                    "binary": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION"),
                });
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                println!("MLS ciphersuite   {suite}");
                println!("MLS backend       {mls_backend}");
                println!("transport AEAD    {aead}");
                println!("features linked   {}", features.join(", "));
                println!("effective A-CGKA  {effective}");
                println!("DKR capacity      2^{}",
                    (safehub_crypto::DKR_SEGMENT_CAPACITY as f64).log2().round() as u32);
                println!("lambda (bits)     {}", safehub_crypto::SEC_PARAM_BITS);
                if STUB_LINKED && !OPENMLS_LINKED {
                    println!();
                    println!("WARNING: stub A-CGKA only. Measurements from this");
                    println!("binary must not be published as Category-5 results.");
                }
            }
            Ok(())
        }
    }
}
