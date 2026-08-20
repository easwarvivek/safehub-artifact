//! Encrypted LFS-style large objects via sealed CAS streams.

use clap::Subcommand;
use safehub_client::{get_sealed_object, put_sealed_object, HttpClient};
use safehub_types::BlobId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::common::{load_local_repo, material_for, short_id};

#[derive(Debug, Subcommand)]
pub enum LfsCmd {
    /// Track a glob in `.safehub-lfs.json` (pointer files in git).
    Track {
        pattern: String,
    },
    /// Push tracked large files as sealed CAS blobs; write pointer stubs.
    Push {
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
    /// Fetch sealed LFS objects referenced by pointer files.
    Fetch {
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LfsConfig {
    patterns: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LfsPointer {
    version: String,
    oid: String,
    size: u64,
}

fn config_path() -> PathBuf {
    PathBuf::from(".safehub-lfs.json")
}

fn load_config() -> LfsConfig {
    let p = config_path();
    if !p.exists() {
        return LfsConfig::default();
    }
    serde_json::from_slice(&std::fs::read(p).unwrap_or_default()).unwrap_or_default()
}

fn save_config(cfg: &LfsConfig) -> anyhow::Result<()> {
    std::fs::write(config_path(), serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}

fn matches_pattern(path: &Path, pattern: &str) -> bool {
    let name = path.to_string_lossy();
    if let Some(ext) = pattern.strip_prefix("*.") {
        return path.extension().and_then(|e| e.to_str()) == Some(ext);
    }
    name.contains(pattern)
}

pub async fn run(cmd: LfsCmd) -> anyhow::Result<()> {
    match cmd {
        LfsCmd::Track { pattern } => {
            let mut cfg = load_config();
            if !cfg.patterns.contains(&pattern) {
                cfg.patterns.push(pattern.clone());
            }
            save_config(&cfg)?;
            println!("tracking {pattern} (encrypted LFS via sealed CAS)");
        }
        LfsCmd::Push { path } => {
            let client = HttpClient::from_disk()?;
            let repo = load_local_repo()?;
            let material = material_for(&repo.id)?;
            let cfg = load_config();
            if cfg.patterns.is_empty() {
                anyhow::bail!("no patterns; run `sh lfs track '*.bin'` first");
            }
            let mut pointers: BTreeMap<String, LfsPointer> = BTreeMap::new();
            let walker = walkdir_lite(&path)?;
            for file in walker {
                if !cfg.patterns.iter().any(|p| matches_pattern(&file, p)) {
                    continue;
                }
                if file.extension().and_then(|e| e.to_str()) == Some("safehub-lfs") {
                    continue;
                }
                let bytes = std::fs::read(&file)?;
                let push_id = format!("lfs-{}", short_id());
                let id = put_sealed_object(&client, &repo.id, &material, &bytes, &push_id).await?;
                let ptr = LfsPointer {
                    version: "safehub-lfs-v1".into(),
                    oid: id.to_hex(),
                    size: bytes.len() as u64,
                };
                let ptr_path = PathBuf::from(format!("{}.safehub-lfs", file.display()));
                std::fs::write(&ptr_path, serde_json::to_vec_pretty(&ptr)?)?;
                // Replace working file with tiny pointer for git (optional).
                std::fs::write(
                    &file,
                    format!(
                        "version {}\noid sha512:{}\nsize {}\n",
                        ptr.version, ptr.oid, ptr.size
                    ),
                )?;
                pointers.insert(file.display().to_string(), ptr);
                println!(
                    "uploaded {} ({} plaintext bytes → sealed CAS; size leaks)",
                    file.display(),
                    bytes.len()
                );
            }
            let _ = Command::new("git").args(["add", "-A"]).status();
            println!("pushed {} LFS object(s); commit + `sit push` to publish pointers", pointers.len());
        }
        LfsCmd::Fetch { path } => {
            let client = HttpClient::from_disk()?;
            let repo = load_local_repo()?;
            let material = material_for(&repo.id)?;
            let walker = walkdir_lite(&path)?;
            for file in walker {
                let text = match std::fs::read_to_string(&file) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let oid_hex = if let Some(line) = text.lines().find(|l| l.starts_with("oid sha512:"))
                {
                    line.trim_start_matches("oid sha512:").to_string()
                } else if let Ok(p) = serde_json::from_str::<LfsPointer>(&text) {
                    p.oid
                } else {
                    continue;
                };
                let id = BlobId::from_hex(oid_hex.trim())
                    .map_err(|e| anyhow::anyhow!("bad oid: {e}"))?;
                let pt = get_sealed_object(&client, &repo.id, &material, &id).await?;
                let out = if file.extension().and_then(|e| e.to_str()) == Some("safehub-lfs") {
                    file.with_extension("")
                } else {
                    file.clone()
                };
                std::fs::write(&out, &pt)?;
                println!("fetched {} ({} bytes)", out.display(), pt.len());
            }
        }
    }
    Ok(())
}

fn walkdir_lite(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if dir.is_file() {
            out.push(dir.to_path_buf());
            return Ok(());
        }
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            let p = ent.path();
            if p.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            if p.is_dir() {
                rec(&p, out)?;
            } else {
                out.push(p);
            }
        }
        Ok(())
    }
    rec(root, &mut out)?;
    Ok(out)
}
