//! Synthetic git-like working-tree fixtures for evaluation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Working-tree shape. Real repositories are not uniform, and ciphertext
/// overhead / bundle behaviour is shape-dependent, so the harness can emit
/// several profiles at the same byte target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureProfile {
    /// Default mix: ~30% small text files, ~70% large blobs.
    Balanced,
    /// Source-tree shape: many small files, no large blobs.
    ManyTiny,
    /// Asset-repo shape: a handful of very large blobs.
    FewHuge,
    /// Adversarial paths: unicode, spaces, deep nesting, long names.
    PathologicalPaths,
}

impl Default for FixtureProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

impl FixtureProfile {
    /// Parse from a CLI string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "balanced" => Some(Self::Balanced),
            "many-tiny" => Some(Self::ManyTiny),
            "few-huge" => Some(Self::FewHuge),
            "pathological-paths" => Some(Self::PathologicalPaths),
            _ => None,
        }
    }

    /// Stable slug for filenames and JSON.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::ManyTiny => "many-tiny",
            Self::FewHuge => "few-huge",
            Self::PathologicalPaths => "pathological-paths",
        }
    }

    /// Fraction of the byte budget reserved for large blobs.
    fn large_fraction(&self) -> f64 {
        match self {
            Self::Balanced => 0.70,
            Self::ManyTiny => 0.0,
            Self::FewHuge => 0.98,
            Self::PathologicalPaths => 0.50,
        }
    }
}

/// Fixture generation parameters.
#[derive(Clone, Debug)]
pub struct FixtureSpec {
    pub target_files: u32,
    pub target_bytes: u64,
    pub commit_depth: u32,
    pub seed: u64,
    /// Working-tree shape (see [`FixtureProfile`]).
    pub profile: FixtureProfile,
}

/// Metadata written beside a generated fixture.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixtureMeta {
    pub path: String,
    pub file_count: u32,
    pub total_bytes: u64,
    pub commit_depth: u32,
    pub seed: u64,
    pub content_hash: String,
    pub target_files: u32,
    pub target_bytes: u64,
}

/// Path for small file `i` under the given profile.
///
/// `PathologicalPaths` deliberately exercises unicode, spaces, dots, deep
/// nesting, and near-limit component lengths — cases that break naive path
/// handling in bundle creation, manifests, and browse UIs.
fn small_file_path(profile: FixtureProfile, i: u32) -> String {
    match profile {
        FixtureProfile::PathologicalPaths => match i % 6 {
            0 => format!("src/δοκιμή/файл-{i:04}.txt"),
            1 => format!("src/with spaces/name {i:04}.txt"),
            2 => format!("src/a/b/c/d/e/f/g/h/deep-{i:04}.txt"),
            3 => format!("src/dot.dir/.hidden-{i:04}"),
            4 => format!("src/{}-{i:04}.txt", "long".repeat(40)),
            _ => format!("src/emoji-🔐-{i:04}.txt"),
        },
        _ => format!("src/f{i:04}.txt"),
    }
}

/// Generate a deterministic synthetic working tree (not a real git repo required for smoke).
///
/// Layout:
/// ```text
/// <dir>/
///   README.md
///   src/fNNNN.txt          # many small files
///   blobs/large-K.bin      # few larger blobs to hit size target
///   MANIFEST.json          # path → size list
///   commits.txt            # fake history lines for depth
/// ```
pub fn generate(dir: &Path, spec: FixtureSpec) -> anyhow::Result<FixtureMeta> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir.join("src"))?;
    fs::create_dir_all(dir.join("blobs"))?;

    let mut rng = XorShift64::new(spec.seed);
    let mut total: u64 = 0;
    let mut files: Vec<(String, u64)> = Vec::new();

    // README
    let readme = format!(
        "# SafeHub eval fixture\n\nseed={:#x} target_files={} target_bytes={}\n",
        spec.seed, spec.target_files, spec.target_bytes
    );
    write_file(dir, "README.md", readme.as_bytes())?;
    total += readme.len() as u64;
    files.push(("README.md".into(), readme.len() as u64));

    // Reserve ~70% of budget for large blobs, rest for small text files.
    // For large additive fixtures, leave enough blob slots so the byte target
    // is reachable under the per-file 4 MiB cap and the object-count cap.
    let large_budget = (spec.target_bytes as f64 * spec.profile.large_fraction()) as u64;
    let max_chunk = 4 * 1024 * 1024u64;
    let min_blob_slots = ((large_budget + max_chunk - 1) / max_chunk).max(1) as u32;
    let n_small = if spec.target_bytes > 16 * 1024 * 1024 {
        spec.target_files
            .saturating_sub(min_blob_slots.saturating_add(2))
            .max(1)
    } else {
        spec.target_files.saturating_sub(1).max(1)
    };
    let small_budget = spec.target_bytes.saturating_sub(large_budget).max(n_small as u64);

    let avg_small = (small_budget / n_small as u64).max(64);
    for i in 0..n_small {
        let path = small_file_path(spec.profile, i);
        // Vary size ±50% around avg.
        let jitter = (rng.next() % 100) as u64;
        let sz = ((avg_small as f64) * (0.5 + (jitter as f64) / 100.0)) as u64;
        let sz = sz.max(32);
        let mut buf = vec![0u8; sz as usize];
        for chunk in buf.chunks_mut(8) {
            let v = rng.next().to_le_bytes();
            for (b, vb) in chunk.iter_mut().zip(v.iter()) {
                *b = *vb;
            }
        }
        // Make mostly printable-ish for "text" files.
        for b in &mut buf {
            *b = b'a' + (*b % 26);
        }
        write_file(dir, &path, &buf)?;
        total += sz;
        files.push((path, sz));
    }

    // Large blobs to approach target_bytes. Cap near target_files so large
    // additive fixtures (100/200 MiB, ~1000 files) stay object-count honest;
    // locked ≤16 MiB sweeps keep the historical ±5% file-count band.
    let max_files = if spec.target_bytes > 16 * 1024 * 1024 {
        // Allow a small overshoot for README/manifest/commits bookkeeping.
        spec.target_files.saturating_add(spec.target_files / 50).max(spec.target_files)
    } else {
        spec.target_files + spec.target_files / 20
    };
    let mut blob_idx = 0u32;
    while total + 1024 < spec.target_bytes {
        if (files.len() as u32) >= max_files {
            break;
        }
        let remaining = spec.target_bytes - total;
        let slots_left = (max_files - files.len() as u32).max(1);
        // Spread remaining budget across leftover slots (cap 4 MiB/chunk).
        let chunk = (remaining / slots_left as u64)
            .min(max_chunk)
            .max(1024);
        let path = format!("blobs/large-{blob_idx}.bin");
        let mut buf = vec![0u8; chunk as usize];
        for chunk_b in buf.chunks_mut(8) {
            let v = rng.next().to_le_bytes();
            for (b, vb) in chunk_b.iter_mut().zip(v.iter()) {
                *b = *vb;
            }
        }
        write_file(dir, &path, &buf)?;
        total += chunk;
        files.push((path, chunk));
        blob_idx += 1;
    }

    // Pad with empty-ish tiny files if under file count.
    while (files.len() as u32) < spec.target_files {
        let i = files.len();
        let path = format!("src/pad{i:04}.txt");
        let content = format!("pad-{i}\n");
        write_file(dir, &path, content.as_bytes())?;
        total += content.len() as u64;
        files.push((path, content.len() as u64));
    }

    // Fake commit history lines.
    let mut commits = String::new();
    for c in 0..spec.commit_depth {
        commits.push_str(&format!(
            "commit {c:04} seed={:#x} files={}\n",
            spec.seed ^ c as u64,
            files.len()
        ));
    }
    write_file(dir, "commits.txt", commits.as_bytes())?;
    total += commits.len() as u64;
    files.push(("commits.txt".into(), commits.len() as u64));

    let manifest = serde_json::json!({
        "files": files.iter().map(|(p, s)| serde_json::json!({"path": p, "size": s})).collect::<Vec<_>>(),
        "file_count": files.len(),
        "total_bytes": total,
        "profile": spec.profile.slug(),
    });
    let man_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_file(dir, "MANIFEST.json", &man_bytes)?;
    total += man_bytes.len() as u64;

    let content_hash = hash_tree(dir)?;

    Ok(FixtureMeta {
        path: dir.display().to_string(),
        file_count: files.len() as u32,
        total_bytes: total,
        commit_depth: spec.commit_depth,
        seed: spec.seed,
        content_hash,
        target_files: spec.target_files,
        target_bytes: spec.target_bytes,
    })
}

fn write_file(root: &Path, rel: &str, data: &[u8]) -> anyhow::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    Ok(())
}

fn hash_tree(root: &Path) -> anyhow::Result<String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    collect_files(root, &mut paths)?;
    paths.sort();
    let mut hasher = Sha256::new();
    for p in paths {
        let rel = p.strip_prefix(root).unwrap_or(&p);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(&fs::read(&p)?);
        hasher.update(b"\0");
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Tiny deterministic PRNG (no external dep for fixtures).
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn smoke_fixture_generates() {
        let dir = tempdir().unwrap();
        let meta = generate(
            &dir.path().join("f"),
            FixtureSpec {
                target_files: 20,
                target_bytes: 1024 * 1024,
                commit_depth: 3,
                seed: 42,
                profile: FixtureProfile::default(),
            },
        )
        .unwrap();
        assert!(meta.file_count >= 18 && meta.file_count <= 25);
        let lo = (1024 * 1024) as f64 * 0.85;
        let hi = (1024 * 1024) as f64 * 1.20;
        assert!(
            (meta.total_bytes as f64) >= lo && (meta.total_bytes as f64) <= hi,
            "bytes={} not in [{lo},{hi}]",
            meta.total_bytes
        );
    }

    #[test]
    fn size_targets_within_tolerance() {
        let dir = tempdir().unwrap();
        for mib in [8u64, 10, 12] {
            let meta = generate(
                &dir.path().join(format!("{mib}")),
                FixtureSpec {
                    target_files: 200,
                    target_bytes: mib * 1024 * 1024,
                    commit_depth: 10,
                    seed: 0x5AFE_0000 ^ mib,
                    profile: FixtureProfile::default(),
                },
            )
            .unwrap();
            // ±5% files, ±10% size (plan exit criteria).
            let file_lo = (200.0 * 0.95) as u32;
            let file_hi = (200.0 * 1.05) as u32 + 5; // commits/manifest may add a few
            assert!(
                meta.file_count >= file_lo && meta.file_count <= file_hi + 20,
                "{mib} MiB file_count={}",
                meta.file_count
            );
            let target = (mib * 1024 * 1024) as f64;
            let ratio = meta.total_bytes as f64 / target;
            assert!(
                ratio >= 0.90 && ratio <= 1.15,
                "{mib} MiB size ratio={ratio} bytes={}",
                meta.total_bytes
            );
        }
    }

    #[test]
    fn large_fixture_honors_object_count() {
        let dir = tempdir().unwrap();
        for mib in [100u64, 200] {
            let meta = generate(
                &dir.path().join(format!("{mib}")),
                FixtureSpec {
                    target_files: 1000,
                    target_bytes: mib * 1024 * 1024,
                    commit_depth: 8,
                    seed: 0x5AFE_1000 ^ mib,
                    profile: FixtureProfile::default(),
                },
            )
            .unwrap();
            // Harness "objects" ≈ working-tree files (± bookkeeping).
            assert!(
                meta.file_count >= 950 && meta.file_count <= 1100,
                "{mib} MiB file_count={} (want ~1000)",
                meta.file_count
            );
            let target = (mib * 1024 * 1024) as f64;
            let ratio = meta.total_bytes as f64 / target;
            assert!(
                ratio >= 0.85 && ratio <= 1.20,
                "{mib} MiB size ratio={ratio} bytes={}",
                meta.total_bytes
            );
        }
    }
}
