//! Encrypted Actions-style variables (group AEAD; never host plaintext).

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;

use super::common::{
    enqueue_collab, material_for, read_inbox_cache, resolve_repo, seal_secret_for_runner, sync_inbox,
};

#[derive(Debug, Subcommand)]
pub enum VariableCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    Get {
        name: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Set {
        name: Option<String>,
        /// Variable value (prefer env SAFEHUB_VARIABLE_VALUE to avoid argv leak).
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Delete {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: VariableCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        VariableCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let mut names = std::collections::BTreeSet::new();
            for (_, msg) in read_inbox_cache(&record.id)? {
                if let CollabMessage::Variable { name, action, .. } = msg {
                    if action == "delete" {
                        names.remove(&name);
                    } else {
                        names.insert(name);
                    }
                }
            }
            for n in names {
                println!("{n}");
            }
            println!("note: names from decrypted MLS inbox; values sealed (use `sh variable get`)");
        }
        VariableCmd::Get { name, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let mut sealed: Option<Vec<u8>> = None;
            for (_, msg) in read_inbox_cache(&record.id)? {
                if let CollabMessage::Variable {
                    name: n,
                    sealed_value,
                    action,
                } = msg
                {
                    if n != name {
                        continue;
                    }
                    if action == "delete" {
                        sealed = None;
                    } else {
                        sealed = Some(sealed_value);
                    }
                }
            }
            let sealed = sealed.ok_or_else(|| anyhow::anyhow!("variable {name} not found"))?;
            let pt = safehub_client::open_collab(&material, &sealed)?;
            println!("{}", String::from_utf8_lossy(&pt));
        }
        VariableCmd::Set { name, body, repo } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("variable name required"))?;
            let value = body
                .or_else(|| std::env::var("SAFEHUB_VARIABLE_VALUE").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("provide --body or SAFEHUB_VARIABLE_VALUE env")
                })?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let sealed = seal_secret_for_runner(&material, value.as_bytes(), None)?;
            drop(value);
            let msg = CollabMessage::Variable {
                name: name.clone(),
                sealed_value: sealed,
                action: "set".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "variable").await?;
            println!("Stored sealed variable {name} (MLS seq {seq}; host sees ciphertext only)");
        }
        VariableCmd::Delete { name, repo } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("variable name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Variable {
                name: name.clone(),
                sealed_value: vec![],
                action: "delete".into(),
            };
            let seq =
                enqueue_collab(&client, &record.id, &material, &msg, "variable-delete").await?;
            println!("Deleted variable {name} (MLS seq {seq})");
        }
    }
    Ok(())
}
