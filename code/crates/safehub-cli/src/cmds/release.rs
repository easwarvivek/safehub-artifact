//! Encrypted releases: notes as MLS app messages; assets as sealed CAS blobs.

use clap::Subcommand;
use safehub_client::{get_sealed_object, put_sealed_object, HttpClient};
use safehub_types::{BlobId, CollabMessage};
use std::path::PathBuf;

use super::common::{enqueue_collab, material_for, resolve_repo, short_id, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum ReleaseCmd {
    /// Create a release (notes encrypted; optional assets → sealed CAS).
    Create {
        #[arg(long)]
        tag: String,
        #[arg(long, default_value = "")]
        title: String,
        #[arg(long, default_value = "")]
        notes: String,
        /// Path to an asset file to upload encrypted (repeatable).
        #[arg(long = "asset")]
        assets: Vec<PathBuf>,
        #[arg(long)]
        repo: Option<String>,
    },
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    View {
        tag: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Download {
        tag: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    Delete {
        tag: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: ReleaseCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        ReleaseCmd::Create {
            tag,
            title,
            notes,
            assets,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let mut asset_blob_ids = Vec::new();
            let mut asset_names = Vec::new();
            for path in &assets {
                let bytes = std::fs::read(path)?;
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "asset".into());
                let push_id = format!("release-{}-{}", tag, short_id());
                let id = put_sealed_object(&client, &record.id, &material, &bytes, &push_id).await?;
                asset_blob_ids.push(id.to_hex());
                asset_names.push(name);
                println!(
                    "uploaded sealed asset {} ({} ciphertext bytes; size leaks)",
                    asset_names.last().unwrap(),
                    bytes.len()
                );
            }
            let title = if title.is_empty() {
                tag.clone()
            } else {
                title
            };
            let msg = CollabMessage::Release {
                tag: tag.clone(),
                title,
                notes,
                asset_blob_ids,
                asset_names,
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "release").await?;
            println!("Created encrypted release {tag} (MLS seq {seq})");
            println!("note: server stores opaque ciphertext only; notes never plaintext on host");
        }
        ReleaseCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let inbox = super::common::read_inbox_cache(&record.id)?;
            for (_, msg) in inbox {
                if let CollabMessage::Release { tag, title, .. } = msg {
                    println!("{tag}\t{title}");
                }
            }
        }
        ReleaseCmd::View { tag, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let tag = tag.ok_or_else(|| anyhow::anyhow!("tag required"))?;
            let inbox = super::common::read_inbox_cache(&record.id)?;
            for (_, msg) in inbox {
                if let CollabMessage::Release {
                    tag: t,
                    title,
                    notes,
                    asset_names,
                    asset_blob_ids,
                } = msg
                {
                    if t == tag {
                        println!("tag: {t}");
                        println!("title: {title}");
                        println!("notes:\n{notes}");
                        for (n, id) in asset_names.iter().zip(asset_blob_ids.iter()) {
                            println!("asset: {n} blob={id}");
                        }
                        return Ok(());
                    }
                }
            }
            anyhow::bail!("release {tag} not found in decrypted inbox");
        }
        ReleaseCmd::Download { tag, repo, dir } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let tag = tag.ok_or_else(|| anyhow::anyhow!("tag required"))?;
            let inbox = super::common::read_inbox_cache(&record.id)?;
            for (_, msg) in inbox {
                if let CollabMessage::Release {
                    tag: t,
                    asset_names,
                    asset_blob_ids,
                    ..
                } = msg
                {
                    if t != tag {
                        continue;
                    }
                    std::fs::create_dir_all(&dir)?;
                    for (name, id_hex) in asset_names.iter().zip(asset_blob_ids.iter()) {
                        let id = BlobId::from_hex(id_hex)
                            .map_err(|e| anyhow::anyhow!("bad blob id: {e}"))?;
                        let pt = get_sealed_object(&client, &record.id, &material, &id).await?;
                        let out = dir.join(name);
                        std::fs::write(&out, &pt)?;
                        println!("wrote {} ({} bytes)", out.display(), pt.len());
                    }
                    return Ok(());
                }
            }
            anyhow::bail!("release {tag} not found");
        }
        ReleaseCmd::Delete { tag, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let tag = tag.ok_or_else(|| anyhow::anyhow!("tag required"))?;
            let msg = CollabMessage::Release {
                tag: tag.clone(),
                title: String::new(),
                notes: "__deleted__".into(),
                asset_blob_ids: vec![],
                asset_names: vec![],
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "release-delete").await?;
            println!("Tombstoned release {tag} (MLS seq {seq})");
        }
    }
    Ok(())
}
