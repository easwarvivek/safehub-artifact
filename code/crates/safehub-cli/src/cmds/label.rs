//! Encrypted labels (MLS app messages).

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;

use super::common::{enqueue_collab, material_for, resolve_repo, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum LabelCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    Create {
        name: Option<String>,
        #[arg(long)]
        color: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Delete {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: LabelCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        LabelCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let mut seen = std::collections::BTreeMap::new();
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Label {
                    name, action, color, description, ..
                } = msg
                {
                    if action == "delete" {
                        seen.remove(&name);
                    } else {
                        seen.insert(name, (color, description));
                    }
                }
            }
            for (name, (color, desc)) in seen {
                println!(
                    "{name}\t{}\t{}",
                    color.unwrap_or_default(),
                    desc.unwrap_or_default()
                );
            }
        }
        LabelCmd::Create {
            name,
            color,
            description,
            repo,
        } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("label name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Label {
                name: name.clone(),
                color,
                description,
                action: "create".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "label").await?;
            println!("Created encrypted label {name} (MLS seq {seq})");
        }
        LabelCmd::Delete { name, repo } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("label name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Label {
                name: name.clone(),
                color: None,
                description: None,
                action: "delete".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "label-delete").await?;
            println!("Deleted encrypted label {name} (MLS seq {seq})");
        }
    }
    Ok(())
}
