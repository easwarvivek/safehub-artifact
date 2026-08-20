//! Encrypted milestones via MLS application messages.

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;

use super::common::{
    enqueue_collab, material_for, read_inbox_cache, resolve_repo, sync_inbox,
};

#[derive(Debug, Subcommand)]
pub enum MilestoneCmd {
    Create {
        #[arg(long)]
        title: String,
        #[arg(long)]
        due: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    List {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        state: Option<String>,
    },
    Close {
        title: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Reopen {
        title: String,
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct FoldedMilestone {
    title: String,
    due: Option<String>,
    state: String,
}

fn fold_milestones(messages: &[(u64, CollabMessage)]) -> Vec<FoldedMilestone> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, FoldedMilestone> = BTreeMap::new();
    for (_, msg) in messages {
        if let CollabMessage::Milestone { title, due, state } = msg {
            let e = map.entry(title.clone()).or_insert_with(|| FoldedMilestone {
                title: title.clone(),
                due: due.clone(),
                state: state.clone(),
            });
            if due.is_some() {
                e.due = due.clone();
            }
            if !state.is_empty() {
                e.state = state.clone();
            }
        }
    }
    map.into_values().collect()
}

pub async fn run(cmd: MilestoneCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        MilestoneCmd::Create { title, due, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Milestone {
                title: title.clone(),
                due,
                state: "open".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "milestone").await?;
            println!("Created encrypted milestone {title:?} (MLS seq {seq})");
        }
        MilestoneCmd::List { repo, state } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let filter = state.as_deref().unwrap_or("open");
            for m in fold_milestones(&read_inbox_cache(&record.id)?) {
                if filter != "all" && m.state != filter {
                    continue;
                }
                let due = m.due.as_deref().unwrap_or("-");
                println!("{}\t{}\t{}", m.state, m.title, due);
            }
            println!("note: listed from decrypted MLS inbox (not host plaintext)");
        }
        MilestoneCmd::Close { title, repo } => {
            set_state(&client, repo.as_deref(), &title, "closed").await?;
            println!("Closed encrypted milestone {title:?}");
        }
        MilestoneCmd::Reopen { title, repo } => {
            set_state(&client, repo.as_deref(), &title, "open").await?;
            println!("Reopened encrypted milestone {title:?}");
        }
    }
    Ok(())
}

async fn set_state(
    client: &HttpClient,
    repo: Option<&str>,
    title: &str,
    state: &str,
) -> anyhow::Result<()> {
    let record = resolve_repo(client, repo).await?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(client, &record.id, &material).await?;
    let due = fold_milestones(&read_inbox_cache(&record.id)?)
        .into_iter()
        .find(|m| m.title == title)
        .and_then(|m| m.due);
    let msg = CollabMessage::Milestone {
        title: title.into(),
        due,
        state: state.into(),
    };
    let _ = enqueue_collab(client, &record.id, &material, &msg, "milestone-state").await?;
    Ok(())
}
