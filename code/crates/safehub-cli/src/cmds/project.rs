//! Encrypted project boards + draft codespace configs (app messages; no hosted VMs).

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;
use std::collections::BTreeMap;

use super::common::{enqueue_collab, material_for, resolve_repo, short_id, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum ProjectCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    View {
        number: Option<u32>,
        #[arg(long)]
        repo: Option<String>,
    },
    Create {
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run_project(cmd: ProjectCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        ProjectCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Project {
                    id, title, action, ..
                } = msg
                {
                    if action != "delete" {
                        println!("{id}\t{title}");
                    }
                }
            }
        }
        ProjectCmd::View { number, repo } => {
            let want = number
                .map(|n| n.to_string())
                .ok_or_else(|| anyhow::anyhow!("project number/id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Project {
                    id,
                    title,
                    columns,
                    action,
                } = msg
                {
                    if (id == want || title == want) && action != "delete" {
                        println!("id: {id}");
                        println!("title: {title}");
                        for (col, cards) in columns {
                            println!("[{col}]");
                            for c in cards {
                                println!("  - {c}");
                            }
                        }
                        return Ok(());
                    }
                }
            }
            anyhow::bail!("project not found");
        }
        ProjectCmd::Create { title, repo } => {
            let title = title.unwrap_or_else(|| "Project".into());
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let id = format!("{}", short_id().chars().take(6).collect::<String>());
            let mut columns = BTreeMap::new();
            columns.insert("Todo".into(), vec![]);
            columns.insert("In Progress".into(), vec![]);
            columns.insert("Done".into(), vec![]);
            let msg = CollabMessage::Project {
                id: id.clone(),
                title: title.clone(),
                columns,
                action: "create".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "project").await?;
            println!("Created encrypted project board {id} ({title}) MLS seq {seq}");
        }
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
pub enum CodespaceCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Create a draft encrypted codespace config (not a hosted VM).
    Create {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "")]
        config: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Delete {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run_codespace(cmd: CodespaceCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        CodespaceCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::CodespaceConfig { name, action, .. } = msg {
                    if action != "delete" {
                        println!("{name}");
                    }
                }
            }
            println!("note: SafeHub stores draft configs only — no GitHub Codespaces VMs");
        }
        CodespaceCmd::Create { name, config, repo } => {
            let name = name.unwrap_or_else(|| format!("cs-{}", short_id()));
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let config = if config.is_empty() {
                serde_json::json!({
                    "image": "devcontainer",
                    "machine": "local-draft",
                    "note": "encrypted draft; not a hosted VM"
                })
                .to_string()
            } else {
                config
            };
            let msg = CollabMessage::CodespaceConfig {
                name: name.clone(),
                config,
                action: "create".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "codespace").await?;
            println!("Stored encrypted codespace draft {name} (MLS seq {seq})");
        }
        CodespaceCmd::Delete { name, repo } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::CodespaceConfig {
                name: name.clone(),
                config: String::new(),
                action: "delete".into(),
            };
            let seq =
                enqueue_collab(&client, &record.id, &material, &msg, "codespace-delete").await?;
            println!("Deleted codespace draft {name} (MLS seq {seq})");
        }
    }
    Ok(())
}
