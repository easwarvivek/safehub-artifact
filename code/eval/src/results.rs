//! Result JSON types and timing helpers.

use crate::fixture::FixtureMeta;
use safehub_crypto::aead::CommittingAead;
use safehub_crypto::params::AEAD_KEY_LEN;
use safehub_crypto::{MlsIdentity, OpenMlsGroup};
use safehub_types::{BlobId, HeadHash, RefHead, RepoId};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExperimentalMeta {
    pub narrative_collaborators: u32,
    pub target_files: u32,
    pub size_sweep_mib: Vec<u64>,
    pub join_sweep: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineInfo {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub cpu_hint: String,
    /// release | debug when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<String>,
    /// Linked AEAD backend (e.g. hkdf-sha512-pad+HMAC-SHA-512-256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_backend: Option<String>,
    /// Whether hardware AES is likely for the linked backend on this CPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_aes_likely: Option<bool>,
    /// `rustc -vV` release line when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustc_release: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MicroTimings {
    pub aead_seal_1kib_ns: u64,
    pub aead_open_1kib_ns: u64,
    pub aead_seal_1mib_ns: u64,
    pub aead_open_1mib_ns: u64,
    pub refhead_hash_ns: u64,
    /// Synthetic RefHead chain verify (hash + prev link check) over N heads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_verify_100_ns: Option<u64>,
    pub runs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warmups: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_of: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_profile: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SizeOpTimings {
    pub size_mib: u64,
    pub plain_git_clone_ms: Option<u64>,
    /// Local bare-repo `git push` wall time when git is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_git_push_ms: Option<u64>,
    /// Local `git fetch` wall time when git is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_git_fetch_ms: Option<u64>,
    pub safehub_push_ms: Option<u64>,
    pub safehub_fetch_ms: Option<u64>,
    pub safehub_clone_ms: Option<u64>,
    /// Crypto-path AEAD-only lower bound retained when E2E columns are primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_proxy_push_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_proxy_fetch_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_proxy_clone_ms: Option<u64>,
    pub overhead_ratio_clone: Option<f64>,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_store_bytes_approx: Option<u64>,
    pub status: String,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinOpTimings {
    pub n: u32,
    pub invite_join_full_ms: Option<u64>,
    pub invite_join_forward_only_ms: Option<u64>,
    /// Pure OpenMLS grow 1→n (admin create + n−1 invite/join).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_grow_ms: Option<u64>,
    /// Residual AEAD history open proxy added only to full-join cells.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_proxy_ms: Option<u64>,
    pub status: String,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalReport {
    pub mode: String,
    pub machine: MachineInfo,
    pub experimental: ExperimentalMeta,
    pub fixtures: Vec<FixtureMeta>,
    pub micro: MicroTimings,
    pub size_ops: Vec<SizeOpTimings>,
    pub join_ops: Vec<JoinOpTimings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_path: Option<serde_json::Value>,
    pub notes: Vec<String>,
    pub elapsed_ms: u64,
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(value)?;
    std::fs::write(path, s)?;
    Ok(())
}

pub fn machine_info() -> MachineInfo {
    MachineInfo {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hostname: hostname(),
        cpu_hint: std::env::var("SAFEHUB_EVAL_CPU").unwrap_or_else(|_| "unspecified".into()),
        build_profile: std::env::var("SAFEHUB_EVAL_PROFILE").ok(),
        listen: None,
        measured_at: Some(chrono_now()),
        aead_backend: Some(safehub_crypto::aead_backend_name().into()),
        hardware_aes_likely: Some(safehub_crypto::hardware_aes_likely()),
        rustc_release: rustc_release(),
    }
}

fn chrono_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn rustc_release() -> Option<String> {
    let out = std::process::Command::new("rustc").arg("-vV").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with("release:"))
        .map(|l| l.trim().to_string())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".into())
}

pub fn run_micro_timings() -> anyhow::Result<MicroTimings> {
    let key = [7u8; AEAD_KEY_LEN];
    let aad = b"safehub-eval";
    let runs = 25u32;

    let pt_1k = vec![0xABu8; 1024];
    let sealed_1k = CommittingAead::seal(&key, aad, &pt_1k)?;
    let seal_1k = median_ns(runs, || {
        let _ = CommittingAead::seal(&key, aad, &pt_1k).unwrap();
    });
    let open_1k = median_ns(runs, || {
        let _ = CommittingAead::open(&key, aad, &sealed_1k).unwrap();
    });

    let pt_1m = vec![0xCDu8; 1024 * 1024];
    let sealed_1m = CommittingAead::seal(&key, aad, &pt_1m)?;
    let seal_1m = median_ns(runs, || {
        let _ = CommittingAead::seal(&key, aad, &pt_1m).unwrap();
    });
    let open_1m = median_ns(runs, || {
        let _ = CommittingAead::open(&key, aad, &sealed_1m).unwrap();
    });

    let head = sample_ref_head();
    let hash_ns = median_ns(runs, || {
        let _ = head.hash();
    });

    // Synthetic chain of 100 heads: hash each + check prev link (head-verify microbench).
    let chain: Vec<RefHead> = (0..100)
        .map(|i| {
            let mut h = sample_ref_head();
            h.seq = i + 1;
            h.enc_refs = vec![i as u8; 64];
            h
        })
        .collect();
    let verify_ns = median_ns(runs, || {
        let mut prev = HeadHash([0u8; 64]);
        for (i, h) in chain.iter().enumerate() {
            let _ = h.hash();
            if i > 0 && h.prev_head_hash != prev {
                // expected mismatch on synthetic chain; still exercises compare path
            }
            prev = h.hash();
        }
    });

    Ok(MicroTimings {
        aead_seal_1kib_ns: seal_1k,
        aead_open_1kib_ns: open_1k,
        aead_seal_1mib_ns: seal_1m,
        aead_open_1mib_ns: open_1m,
        refhead_hash_ns: hash_ns,
        head_verify_100_ns: Some(verify_ns),
        runs,
        warmups: Some(3),
        median_of: Some(runs),
        build_profile: std::env::var("SAFEHUB_EVAL_PROFILE").ok(),
        status: "measured".into(),
    })
}

fn sample_ref_head() -> RefHead {
    RefHead {
        repo_id: RepoId([1u8; 32]),
        seq: 1,
        enc_refs: vec![0u8; 64],
        bundle_root: BlobId([2u8; 64]),
        dek_wrap: vec![0u8; 48],
        prev_head_hash: HeadHash([0u8; 64]),
        mls_epoch: 1,
        epoch_tag: vec![0u8; 32],
        non_ff: false,
        pusher_sig: vec![0u8; 64],
        admin_cosig: None,
    }
}

fn median_ns(runs: u32, mut f: impl FnMut()) -> u64 {
    let mut samples = Vec::with_capacity(runs as usize);
    for _ in 0..3 {
        f();
    }
    for _ in 0..runs {
        let t0 = Instant::now();
        f();
        samples.push(t0.elapsed());
    }
    samples.sort();
    samples[samples.len() / 2].as_nanos() as u64
}

/// Chunk size for size-sweep AEAD (matches typical bundle chunking).
const AEAD_CHUNK: usize = 1024 * 1024;

/// Time size-related ops for one fixture.
///
/// SafeHub columns seal/open the **full fixture byte budget** in 1 MiB AEAD
/// chunks (crypto-path proxy until the HTTP remote helper is timed end-to-end).
/// Plain-git push/fetch/clone are local file:// baselines when `git` exists.
pub fn time_size_ops(fixture_dir: &Path, size_mib: u64) -> anyhow::Result<SizeOpTimings> {
    let bytes = dir_size(fixture_dir).unwrap_or(size_mib * 1024 * 1024);
    eprintln!(
        "  size {size_mib} MiB: timing AEAD ({bytes} bytes) + plain git…"
    );

    let plain = time_plain_git_ops(fixture_dir);
    let (push_ms, fetch_ms) = time_aead_fixture(bytes)?;

    let (plain_push, plain_fetch, plain_clone, status, note) = match plain {
        Some(p) => (
            Some(p.push_ms),
            Some(p.fetch_ms),
            Some(p.clone_ms),
            "measured-proxy".into(),
            "safehub_* = CommittingAead over full fixture bytes in 1MiB chunks (crypto path; HTTP remote helper not included). plain_git_* = local bare push/fetch/clone.".into(),
        ),
        None => (
            None,
            None,
            None,
            "measured-proxy".into(),
            "git unavailable; SafeHub AEAD full-fixture chunk timings only.".into(),
        ),
    };

    let ratio = plain_clone.map(|c| {
        if c == 0 {
            0.0
        } else {
            (push_ms + fetch_ms) as f64 / c as f64
        }
    });

    Ok(SizeOpTimings {
        size_mib,
        plain_git_clone_ms: plain_clone,
        plain_git_push_ms: plain_push,
        plain_git_fetch_ms: plain_fetch,
        safehub_push_ms: Some(push_ms),
        safehub_fetch_ms: Some(fetch_ms),
        safehub_clone_ms: Some(push_ms + fetch_ms),
        aead_proxy_push_ms: None,
        aead_proxy_fetch_ms: None,
        aead_proxy_clone_ms: None,
        overhead_ratio_clone: ratio,
        bytes,
        ciphertext_store_bytes_approx: None,
        status,
        note,
    })
}

fn time_aead_fixture(total_bytes: u64) -> anyhow::Result<(u64, u64)> {
    let key = [9u8; AEAD_KEY_LEN];
    let aad = b"eval-push";
    let total = total_bytes.max(1) as usize;
    let mut sealed_chunks: Vec<Vec<u8>> = Vec::new();

    let t0 = Instant::now();
    let mut offset = 0usize;
    while offset < total {
        let len = (total - offset).min(AEAD_CHUNK);
        // Deterministic pseudo-content (avoid reading whole tree into RAM twice).
        let mut buf = vec![0u8; len];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((offset + i) as u8).wrapping_add(0x5A);
        }
        sealed_chunks.push(CommittingAead::seal(&key, aad, &buf)?);
        offset += len;
    }
    let push_ms = t0.elapsed().as_millis() as u64;

    let t1 = Instant::now();
    for chunk in &sealed_chunks {
        let _ = CommittingAead::open(&key, aad, chunk)?;
    }
    let fetch_ms = t1.elapsed().as_millis() as u64;
    Ok((push_ms, fetch_ms))
}

struct PlainGitTimings {
    push_ms: u64,
    fetch_ms: u64,
    clone_ms: u64,
}

fn time_plain_git_ops(fixture_dir: &Path) -> Option<PlainGitTimings> {
    let git = which_git()?;
    let tmp = tempfile::tempdir().ok()?;
    let repo = tmp.path().join("repo");
    let bare = tmp.path().join("repo.git");
    let clone = tmp.path().join("clone");
    let fetch_wt = tmp.path().join("fetch-wt");

    std::fs::create_dir_all(&repo).ok()?;
    copy_dir(fixture_dir, &repo).ok()?;
    // Empty template avoids writing hook samples (sandbox-hostile).
    run_cmd(
        &git,
        &["-C", repo.to_str()?, "init", "-q", "--template="],
    )
    .ok()?;
    run_cmd(
        &git,
        &["-C", repo.to_str()?, "config", "user.email", "eval@safehub"],
    )
    .ok()?;
    run_cmd(&git, &["-C", repo.to_str()?, "config", "user.name", "eval"]).ok()?;
    run_cmd(&git, &["-C", repo.to_str()?, "add", "."]).ok()?;
    run_cmd(&git, &["-C", repo.to_str()?, "commit", "-qm", "fixture"]).ok()?;

    run_cmd(
        &git,
        &["init", "--bare", "-q", "--template=", bare.to_str()?],
    )
    .ok()?;
    run_cmd(
        &git,
        &["-C", repo.to_str()?, "remote", "add", "origin", bare.to_str()?],
    )
    .ok()?;

    let t_push = Instant::now();
    run_cmd(
        &git,
        &["-C", repo.to_str()?, "push", "-q", "origin", "HEAD"],
    )
    .ok()?;
    let push_ms = t_push.elapsed().as_millis() as u64;

    let t_clone = Instant::now();
    run_cmd(
        &git,
        &["clone", "-q", bare.to_str()?, clone.to_str()?],
    )
    .ok()?;
    let clone_ms = t_clone.elapsed().as_millis() as u64;

    // Second working tree + fetch of an empty update still exercises fetch plumbing;
    // force a no-op fetch against the bare remote after an initial clone.
    run_cmd(
        &git,
        &["clone", "-q", bare.to_str()?, fetch_wt.to_str()?],
    )
    .ok()?;
    let t_fetch = Instant::now();
    run_cmd(
        &git,
        &["-C", fetch_wt.to_str()?, "fetch", "-q", "origin"],
    )
    .ok()?;
    let fetch_ms = t_fetch.elapsed().as_millis() as u64;

    Some(PlainGitTimings {
        push_ms,
        fetch_ms,
        clone_ms,
    })
}

fn which_git() -> Option<String> {
    let out = std::process::Command::new("which")
        .arg("git")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn run_cmd(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let st = std::process::Command::new(bin).args(args).status()?;
    if !st.success() {
        anyhow::bail!("command failed: {bin} {args:?}");
    }
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
    for entry in walkdir(src)? {
        let rel = entry.strip_prefix(src)?;
        let target = dst.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(p) = target.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::copy(&entry, &target)?;
        }
    }
    Ok(())
}

fn walkdir(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            out.push(p.clone());
            if p.is_dir() {
                rec(&p, out)?;
            }
        }
        Ok(())
    }
    rec(root, &mut out)?;
    Ok(out)
}

fn dir_size(root: &Path) -> anyhow::Result<u64> {
    let mut n = 0u64;
    for p in walkdir(root)? {
        if p.is_file() {
            n += std::fs::metadata(p)?.len();
        }
    }
    Ok(n)
}

/// History AEAD proxy budget: one full fixture open (full-history join residual).
fn history_proxy_bytes(fixture_dir: &Path) -> u64 {
    dir_size(fixture_dir).unwrap_or(12 * 1024 * 1024)
}

/// Grow an OpenMLS Category-5 group from 1 → `n` members.
///
/// Returns wall time for admin create + (n−1) × (KeyPackage + add_member + join).
fn time_mls_grow(n: u32) -> anyhow::Result<(u64, OpenMlsGroup)> {
    anyhow::ensure!(n >= 1, "n must be ≥ 1");
    let repo_id = [0x5Au8; 32];
    let t0 = Instant::now();
    let admin = MlsIdentity::generate(b"eval-admin")?;
    let mut group = admin.create_group(repo_id)?;
    for i in 1..n {
        let member = MlsIdentity::generate(format!("eval-member-{i}"))?;
        let kp = member.key_package()?;
        let invitation = group.add_member(&kp)?;
        // Joiner accepts Welcome (invite+join path).
        let _joined = member.join(&invitation)?;
    }
    let ms = t0.elapsed().as_millis() as u64;
    Ok((ms, group))
}

fn time_history_aead_proxy(bytes: u64) -> anyhow::Result<u64> {
    let key = [3u8; AEAD_KEY_LEN];
    let aad = b"eval-history";
    let total = bytes.max(1) as usize;
    let mut sealed = Vec::new();
    let mut offset = 0usize;
    while offset < total {
        let len = (total - offset).min(AEAD_CHUNK);
        let buf = vec![0x11u8; len];
        sealed.push(CommittingAead::seal(&key, aad, &buf)?);
        offset += len;
    }
    let t0 = Instant::now();
    for chunk in &sealed {
        let _ = CommittingAead::open(&key, aad, chunk)?;
    }
    Ok(t0.elapsed().as_millis() as u64)
}

/// Join timings via real OpenMLS Category-5 invite+join (safehub-crypto).
///
/// * `invite_join_forward_only_ms` — measured MLS grow 1→n (no history).
/// * `invite_join_full_ms` — MLS grow + residual AEAD history-open proxy
///   (honest stand-in for decrypting prior ciphertext until durable history
///   replay is timed end-to-end).
pub fn time_join_ops(fixture_dir: &Path, n: u32) -> anyhow::Result<JoinOpTimings> {
    eprintln!("  join n={n}: OpenMLS Category-5 grow 1→{n}…");
    let (mls_ms, group) = time_mls_grow(n)?;
    // Keep group alive briefly so member_count is checked (sanity).
    let members = group.member_count();
    anyhow::ensure!(
        members == n as usize,
        "expected {n} members, got {members}"
    );

    let hist_bytes = history_proxy_bytes(fixture_dir);
    let hist_ms = time_history_aead_proxy(hist_bytes)?;
    let full_ms = mls_ms.saturating_add(hist_ms);

    Ok(JoinOpTimings {
        n,
        invite_join_full_ms: Some(full_ms),
        invite_join_forward_only_ms: Some(mls_ms),
        mls_grow_ms: Some(mls_ms),
        history_proxy_ms: Some(hist_ms),
        status: "measured".into(),
        note: format!(
            "OpenMLS Category-5 (ML-KEM-1024 / ML-DSA-87) grow 1→{n}: \
             identity+KeyPackage+add_member+Welcome join per member. \
             forward-only = MLS only; full = MLS + AEAD open of {hist_bytes} fixture bytes \
             as residual history-decrypt approximation (not durable epoch replay)."
        ),
    })
}

#[allow(dead_code)]
fn dur_ms(d: Duration) -> u64 {
    d.as_millis() as u64
}
