//! Encrypted gists (single-blob / multi-file JSON sealed as MLS + optional CAS).

use clap::Subcommand;
use safehub_client::{put_sealed_object, HttpClient};
use safehub_types::CollabMessage;
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::common::{enqueue_collab, material_for, resolve_repo, short_id, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum GistCmd {
    Create {
        /// File paths to include (filename → contents).
        files: Vec<PathBuf>,
        #[arg(long)]
        description: Option<String>,
        /// Host gist under this repo's MLS group (required for E2EE delivery).
        #[arg(long)]
        repo: Option<String>,
    },
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    View {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Edit {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        files: Vec<PathBuf>,
    },
    Delete {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: GistCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        GistCmd::Create {
            files,
            description,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let mut map = BTreeMap::new();
            for path in &files {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                map.insert(name, std::fs::read_to_string(path)?);
            }
            if map.is_empty() {
                anyhow::bail!("provide at least one file");
            }
            let id = format!("gist-{}", short_id());
            // Also store a sealed CAS snapshot for large gists.
            let snapshot = serde_json::to_vec(&map)?;
            let blob = put_sealed_object(
                &client,
                &record.id,
                &material,
                &snapshot,
                &format!("gist-{id}"),
            )
            .await?;
            let msg = CollabMessage::Gist {
                id: id.clone(),
                description,
                files: map,
                action: "create".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "gist").await?;
            println!("Created encrypted gist {id} (MLS seq {seq}, CAS {})", blob.to_hex());
        }
        GistCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let mut live = BTreeMap::new();
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Gist { id, description, action, .. } = msg {
                    if action == "delete" {
                        live.remove(&id);
                    } else {
                        live.insert(id, description.unwrap_or_default());
                    }
                }
            }
            for (id, desc) in live {
                println!("{id}\t{desc}");
            }
        }
        GistCmd::View { id, repo } => {
            let id = id.ok_or_else(|| anyhow::anyhow!("gist id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Gist {
                    id: gid,
                    description,
                    files,
                    action,
                } = msg
                {
                    if gid == id && action != "delete" {
                        println!("id: {gid}");
                        if let Some(d) = description {
                            println!("description: {d}");
                        }
                        for (name, body) in files {
                            println!("--- {name} ---\n{body}");
                        }
                        return Ok(());
                    }
                }
            }
            anyhow::bail!("gist {id} not found");
        }
        GistCmd::Edit { id, repo, files } => {
            let id = id.ok_or_else(|| anyhow::anyhow!("gist id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let mut map = BTreeMap::new();
            for path in &files {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                map.insert(name, std::fs::read_to_string(path)?);
            }
            let msg = CollabMessage::Gist {
                id: id.clone(),
                description: None,
                files: map,
                action: "edit".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "gist-edit").await?;
            println!("Updated encrypted gist {id} (MLS seq {seq})");
        }
        GistCmd::Delete { id, repo } => {
            let id = id.ok_or_else(|| anyhow::anyhow!("gist id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Gist {
                id: id.clone(),
                description: None,
                files: BTreeMap::new(),
                action: "delete".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "gist-delete").await?;
            println!("Deleted encrypted gist {id} (MLS seq {seq})");
        }
    }
    Ok(())
}
