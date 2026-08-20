//! `sh inbox` — opaque MLS wake + local decrypt of collab messages.

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;

use super::common::{material_for, resolve_repo, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum InboxCmd {
    /// Sync and list decrypted collaboration messages.
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Sync only (update local decrypt cache).
    Sync {
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: InboxCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        InboxCmd::Sync { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let new = sync_inbox(&client, &record.id, &material).await?;
            println!("synced {} new decryptable collab message(s)", new.len());
        }
        InboxCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (seq, msg) in super::common::read_inbox_cache(&record.id)? {
                let kind = match &msg {
                    CollabMessage::PullRequest { .. } => "pr",
                    CollabMessage::Issue { .. } => "issue",
                    CollabMessage::Review { .. } => "review",
                    CollabMessage::CiVerdict { .. } => "ci",
                    CollabMessage::Release { .. } => "release",
                    CollabMessage::Label { .. } => "label",
                    CollabMessage::Milestone { .. } => "milestone",
                    CollabMessage::Secret { .. } => "secret",
                    CollabMessage::Variable { .. } => "variable",
                    CollabMessage::Gist { .. } => "gist",
                    CollabMessage::Project { .. } => "project",
                    CollabMessage::CodespaceConfig { .. } => "codespace",
                    CollabMessage::WorkflowRun { .. } => "workflow_run",
                    CollabMessage::OrgDirectory { .. } => "org",
                    CollabMessage::Comment { .. } => "comment",
                };
                println!("{seq}\t{kind}\t{}", summary(&msg));
            }
            println!("note: server delivers opaque MLS frames; bodies decrypt locally only");
        }
    }
    Ok(())
}

fn summary(msg: &CollabMessage) -> String {
    match msg {
        CollabMessage::PullRequest { id, title, .. } => format!("{id} {title}"),
        CollabMessage::Issue { id, title, .. } => format!("{id} {title}"),
        CollabMessage::Review { pr_id, verdict, .. } => format!("{pr_id} {verdict}"),
        CollabMessage::CiVerdict {
            commit, status, ..
        } => format!("{status} {commit}"),
        CollabMessage::Release { tag, title, .. } => format!("{tag} {title}"),
        CollabMessage::Label { name, action, .. } => format!("{action} {name}"),
        CollabMessage::Milestone { title, state, .. } => format!("{state} {title}"),
        CollabMessage::Secret { name, action, .. } => format!("{action} {name}"),
        CollabMessage::Variable { name, action, .. } => format!("{action} {name}"),
        CollabMessage::Gist { id, action, .. } => format!("{action} {id}"),
        CollabMessage::Project { id, title, .. } => format!("{id} {title}"),
        CollabMessage::CodespaceConfig { name, action, .. } => format!("{action} {name}"),
        CollabMessage::WorkflowRun {
            id, workflow, status, ..
        } => format!("{id} {workflow} {status}"),
        CollabMessage::OrgDirectory { org, members, .. } => {
            format!("{org} members={}", members.len())
        }
        CollabMessage::Comment {
            target_kind,
            target_id,
            ..
        } => format!("{target_kind} {target_id}"),
    }
}
