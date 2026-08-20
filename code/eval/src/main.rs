//! SafeHub evaluation harness: fixtures, smoke, size/join sweeps, full-stack E2E.

mod fixture;
mod results;
mod schema;

use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Repository size sweep (MiB): 5, 10, 50, 100, 200, 250, 300.
///
/// Single axis — the former locked 8/10/12 MiB sweep and the separate additive
/// 100/200 MiB harness are folded into this one range.
pub const SIZE_SWEEP_MIB: &[u64] = &[5, 10, 50, 100, 200, 250, 300];

/// Deprecated alias kept for callers that referenced the additive-only range.
pub const LARGE_SIZE_SWEEP_MIB: &[u64] = SIZE_SWEEP_MIB;

/// Locked join/collaborator sweep: 10..100 step 10.
pub const JOIN_SWEEP: &[u32] = &[10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

/// Narrative small-team collaborator count (optional figure only).
pub const NARRATIVE_COLLABORATORS: u32 = 3;

/// Target working-tree file count at each swept size.
pub const TARGET_FILES: u32 = 200;

/// Target working-tree files for additive 100/200 MiB multi-push runs.
/// Paper/JSON may say "objects"; the harness maps that to tracked files
/// (each becomes ≥1 git blob after commit).
pub const LARGE_TARGET_FILES: u32 = 1000;

/// Sequential pushes used to grow each large fixture (not a single monolith).
pub const LARGE_PUSH_COUNT: u32 = 8;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    /// CI-friendly tiny run (reduced fixture + micro timings).
    Smoke,
    /// Generate fixtures across the size sweep (no full E2E timings).
    Fixtures,
    /// Full paper sweeps (size AEAD proxy + join); may be expensive.
    Full,
    /// Full-stack E2E: delegates to `scripts/e2e_eval.sh` (server + sit://).
    FullStack,
}

#[derive(Debug, Parser)]
#[command(
    name = "safehub-eval",
    about = "SafeHub evaluation harness (fixtures, smoke, size/join sweeps, full-stack E2E)"
)]
struct Args {
    /// Run mode.
    #[arg(long, value_enum, default_value_t = Mode::Smoke)]
    mode: Mode,

    /// Shorthand for `--mode smoke`.
    #[arg(long, conflicts_with = "mode")]
    smoke: bool,

    /// Cache / output directory for fixtures and results.
    #[arg(long, default_value = "eval/results")]
    out: PathBuf,

    /// Override size MiB for a single fixture (smoke ignores).
    #[arg(long)]
    size_mib: Option<u64>,

    /// Override target working-tree file / object count for fixture generation.
    /// Default: 200 (locked sweep). Use 1000 for additive 100/200 MiB runs.
    #[arg(long)]
    target_files: Option<u32>,

    /// Override join count for a single join timing cell.
    #[arg(long)]
    joins: Option<u32>,

    /// Working-tree shape for generated fixtures:
    /// `balanced` (default), `many-tiny`, `few-huge`, `pathological-paths`.
    #[arg(long, default_value = "balanced")]
    profile: String,
}

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();
    if args.smoke {
        args.mode = Mode::Smoke;
    }

    std::fs::create_dir_all(&args.out)?;
    let published = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("published");
    std::fs::create_dir_all(&published)?;

    match args.mode {
        Mode::Smoke => run_smoke(&args.out, &published)?,
        Mode::Fixtures => {
            let profile = fixture::FixtureProfile::parse(&args.profile).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown --profile {:?} (balanced|many-tiny|few-huge|pathological-paths)",
                    args.profile
                )
            })?;
            run_fixtures(&args.out, args.size_mib, args.target_files, profile)?
        }
        Mode::Full => run_full(&args.out, &published, args.size_mib, args.joins)?,
        Mode::FullStack => run_full_stack()?,
    }
    Ok(())
}

fn run_smoke(out: &PathBuf, published: &PathBuf) -> anyhow::Result<()> {
    eprintln!("safehub-eval: smoke mode");
    let t0 = Instant::now();

    // Tiny fixture: ~1 MiB, 20 files — CI-friendly.
    let smoke_dir = out.join("fixture-smoke");
    let meta = fixture::generate(
        &smoke_dir,
        fixture::FixtureSpec {
            target_files: 20,
            target_bytes: 1024 * 1024,
            commit_depth: 5,
            seed: 0x5AFE_F00D,
            profile: fixture::FixtureProfile::Balanced,
        },
    )?;

    // Micro timings: AEAD + RefHead hash (no full MLS join in smoke).
    let micro = results::run_micro_timings()?;

    let report = results::EvalReport {
        mode: "smoke".into(),
        machine: results::machine_info(),
        experimental: results::ExperimentalMeta {
            narrative_collaborators: NARRATIVE_COLLABORATORS,
            target_files: TARGET_FILES,
            size_sweep_mib: SIZE_SWEEP_MIB.to_vec(),
            join_sweep: JOIN_SWEEP.to_vec(),
        },
        fixtures: vec![meta],
        micro,
        size_ops: vec![],
        join_ops: vec![],
        security: None,
        invite_path: None,
        notes: vec![
            "Smoke uses reduced fixture (20 files / 1 MiB).".into(),
            "Full size sweep: 5/10/50/100/200/250/300 MiB (E2E via --mode full-stack).".into(),
            "Join sweep: n=10..100 step 10 via OpenMLS Category-5.".into(),
        ],
        elapsed_ms: t0.elapsed().as_millis() as u64,
    };

    let path = out.join("smoke.json");
    results::write_json(&path, &report)?;
    results::write_json(&published.join("smoke-latest.json"), &report)?;
    eprintln!("wrote {}", path.display());
    eprintln!("safehub-eval: smoke OK ({} ms)", report.elapsed_ms);
    Ok(())
}

fn run_fixtures(
    out: &PathBuf,
    only: Option<u64>,
    target_files: Option<u32>,
    profile: fixture::FixtureProfile,
) -> anyhow::Result<()> {
    let sizes: Vec<u64> = only
        .map(|s| vec![s])
        .unwrap_or_else(|| SIZE_SWEEP_MIB.to_vec());
    let files = target_files.unwrap_or(TARGET_FILES);
    // Deeper history for locked small sweeps; large multi-push uses push_count commits.
    let commit_depth = if files >= LARGE_TARGET_FILES {
        LARGE_PUSH_COUNT
    } else {
        50
    };
    for mib in sizes {
        let dir = if profile == fixture::FixtureProfile::Balanced {
            out.join(format!("fixture-{mib}mib"))
        } else {
            out.join(format!("fixture-{mib}mib-{}", profile.slug()))
        };
        eprintln!(
            "generating {mib} MiB fixture (target_files={files}, profile={}) → {}",
            profile.slug(),
            dir.display()
        );
        let meta = fixture::generate(
            &dir,
            fixture::FixtureSpec {
                target_files: files,
                target_bytes: mib * 1024 * 1024,
                commit_depth,
                seed: 0x5AFE_F00D ^ mib ^ (files as u64),
                profile,
            },
        )?;
        results::write_json(&dir.join("meta.json"), &meta)?;
        eprintln!(
            "  files={} bytes={} (±tol checked in tests)",
            meta.file_count, meta.total_bytes
        );
    }
    Ok(())
}

fn run_full(
    out: &PathBuf,
    published: &PathBuf,
    only_size: Option<u64>,
    only_joins: Option<u32>,
) -> anyhow::Result<()> {
    eprintln!("safehub-eval: full mode (may be expensive for n→100)");
    let t0 = Instant::now();
    run_fixtures(out, only_size, None, fixture::FixtureProfile::Balanced)?;

    let sizes: Vec<u64> = only_size
        .map(|s| vec![s])
        .unwrap_or_else(|| SIZE_SWEEP_MIB.to_vec());
    let joins: Vec<u32> = only_joins
        .map(|n| vec![n])
        .unwrap_or_else(|| JOIN_SWEEP.to_vec());

    let micro = results::run_micro_timings()?;
    let mut size_ops = Vec::new();
    for mib in &sizes {
        let dir = out.join(format!("fixture-{mib}mib"));
        size_ops.push(results::time_size_ops(&dir, *mib)?);
    }

    let mut join_ops = Vec::new();
    for n in &joins {
        // Prefer 12 MiB when present; fall back to smallest available.
        let base = out.join("fixture-12mib");
        let dir = if base.exists() {
            base
        } else {
            out.join(format!("fixture-{}mib", sizes[0]))
        };
        join_ops.push(results::time_join_ops(&dir, *n)?);
    }

    let fixtures: Vec<_> = sizes
        .iter()
        .filter_map(|mib| {
            let p = out.join(format!("fixture-{mib}mib/meta.json"));
            std::fs::read_to_string(p)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
        })
        .collect();

    let report = results::EvalReport {
        mode: "full".into(),
        machine: results::machine_info(),
        experimental: results::ExperimentalMeta {
            narrative_collaborators: NARRATIVE_COLLABORATORS,
            target_files: TARGET_FILES,
            size_sweep_mib: SIZE_SWEEP_MIB.to_vec(),
            join_sweep: JOIN_SWEEP.to_vec(),
        },
        fixtures,
        micro,
        size_ops,
        join_ops,
        security: None,
        invite_path: None,
        notes: vec![
            "Size sweep (this mode): AEAD crypto-path + plain-git; prefer --mode full-stack for sit:// E2E.".into(),
            "Join sweep: n=10..100 step 10 — real OpenMLS Category-5 grow; full adds AEAD history-open proxy.".into(),
            "Residual: durable multi-device Welcome delivery not timed here; history decrypt is AEAD proxy.".into(),
        ],
        elapsed_ms: t0.elapsed().as_millis() as u64,
    };

    let path = out.join("full.json");
    results::write_json(&path, &report)?;
    results::write_json(&published.join("full-latest.json"), &report)?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

/// Delegate to `scripts/e2e_eval.sh` for server + sit:// measurements.
fn run_full_stack() -> anyhow::Result<()> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // code/eval → repo root is ../..
    let repo_root = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let script = repo_root.join("scripts/e2e_eval.sh");
    anyhow::ensure!(
        script.exists(),
        "missing {}; run from SafeHub checkout",
        script.display()
    );
    eprintln!(
        "safehub-eval: full-stack → {} (release profile recommended)",
        script.display()
    );
    let status = Command::new("bash").arg(&script).status()?;
    if !status.success() {
        anyhow::bail!("e2e_eval.sh failed with {status}");
    }
    Ok(())
}
