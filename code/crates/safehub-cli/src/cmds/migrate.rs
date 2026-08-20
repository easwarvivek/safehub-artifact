//! Migrate plain git history into encrypted SafeHub bundles.

use clap::Subcommand;
use safehub_client::{load_epoch_material, push_bundle, HttpClient};
use safehub_types::RepoName;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Subcommand)]
pub enum MigrateCmd {
    /// Import a git URL / local path into an existing SafeHub repo as encrypted bundles.
    Import {
        /// Source git URL or path.
        source: String,
        /// Destination `owner/name` SafeHub repo (must exist + local MLS material).
        #[arg(long)]
        repo: String,
        /// Working directory for temporary clone.
        #[arg(long)]
        workdir: Option<PathBuf>,
    },
}

pub async fn run(cmd: MigrateCmd) -> anyhow::Result<()> {
    match cmd {
        MigrateCmd::Import {
            source,
            repo,
            workdir,
        } => {
            let client = HttpClient::from_disk()?;
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = load_epoch_material(&record.id)?;

            let tmp = workdir.unwrap_or_else(|| {
                std::env::temp_dir().join(format!("safehub-migrate-{}", std::process::id()))
            });
            if tmp.exists() {
                let _ = std::fs::remove_dir_all(&tmp);
            }
            let status = Command::new("git")
                .args(["clone", "--mirror", &source])
                .arg(&tmp)
                .status()?;
            if !status.success() {
                anyhow::bail!("git clone --mirror failed for {source}");
            }

            // Collect refs from mirror.
            let out = Command::new("git")
                .args(["--git-dir"])
                .arg(&tmp)
                .args(["for-each-ref", "--format=%(refname) %(objectname)"])
                .output()?;
            if !out.status.success() {
                anyhow::bail!("for-each-ref failed");
            }
            let mut git_refs = BTreeMap::new();
            let mut main_oid = None;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.split_whitespace();
                let Some(r) = parts.next() else { continue };
                let Some(oid) = parts.next() else { continue };
                if r.starts_with("refs/heads/") || r.starts_with("refs/tags/") {
                    git_refs.insert(r.to_string(), oid.to_string());
                    if r == "refs/heads/main" || r == "refs/heads/master" {
                        main_oid = Some(oid.to_string());
                    }
                }
            }
            if git_refs.is_empty() {
                anyhow::bail!("no refs found in source");
            }

            let bundle_path = tmp.join("all.bundle");
            let status = Command::new("git")
                .args(["--git-dir"])
                .arg(&tmp)
                .args(["bundle", "create"])
                .arg(&bundle_path)
                .arg("--all")
                .status()?;
            let plaintext = if status.success() {
                std::fs::read(&bundle_path)?
            } else {
                anyhow::bail!("git bundle create --all failed");
            };

            let head_symref = main_oid
                .as_ref()
                .map(|_| "ref: refs/heads/main".to_string())
                .or_else(|| {
                    git_refs
                        .keys()
                        .next()
                        .map(|r| format!("ref: {r}"))
                });

            let result = push_bundle(
                &client,
                &record.id,
                &plaintext,
                git_refs.clone(),
                head_symref,
                &material,
                false,
            )
            .await?;

            println!(
                "imported {} into {} as encrypted bundle (seq={} refs={})",
                source,
                repo,
                result.head.seq,
                git_refs.len()
            );
            println!("leakage: ciphertext size and ref count visible to server; history plaintext is not");
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }
    Ok(())
}
