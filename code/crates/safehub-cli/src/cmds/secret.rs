//! Runner secrets: client-side sealed to runner KeyPackage / group AEAD.

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::{CollabMessage, UserId};

use super::common::{
    enqueue_collab, material_for, resolve_repo, seal_secret_for_runner, sync_inbox,
};

#[derive(Debug, Subcommand)]
pub enum SecretCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    Set {
        name: Option<String>,
        /// Secret value (prefer env SAFEHUB_SECRET_VALUE to avoid argv leak).
        #[arg(long)]
        body: Option<String>,
        /// Runner username whose KeyPackage seals the secret.
        #[arg(long)]
        runner: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Delete {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: SecretCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        SecretCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let mut names = std::collections::BTreeSet::new();
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::Secret { name, action, .. } = msg {
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
            println!("note: values never listed; only names from decrypted inbox metadata");
        }
        SecretCmd::Set {
            name,
            body,
            runner,
            repo,
        } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("secret name required"))?;
            let value = body
                .or_else(|| std::env::var("SAFEHUB_SECRET_VALUE").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("provide --body or SAFEHUB_SECRET_VALUE env")
                })?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let kp = if let Some(user) = &runner {
                let pkgs = client.list_key_packages(&UserId(user.clone())).await?;
                pkgs.into_iter().next().map(|p| p.key_package)
            } else {
                None
            };
            let sealed = seal_secret_for_runner(
                &material,
                value.as_bytes(),
                kp.as_deref(),
            )?;
            // Zeroize best-effort: drop value
            drop(value);
            let msg = CollabMessage::Secret {
                name: name.clone(),
                sealed_value: sealed,
                runner_hint: runner,
                action: "set".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "secret").await?;
            println!("Stored sealed secret {name} (MLS seq {seq}; server sees ciphertext only)");
        }
        SecretCmd::Delete { name, repo } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("secret name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Secret {
                name: name.clone(),
                sealed_value: vec![],
                runner_hint: None,
                action: "delete".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "secret-delete").await?;
            println!("Deleted secret {name} (MLS seq {seq})");
        }
    }
    Ok(())
}
