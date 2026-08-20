//! Encrypted issues via MLS application messages (host never sees bodies).

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;

use super::common::{
    enqueue_collab, fold_collab_inbox, material_for, next_collab_number, read_inbox_cache,
    resolve_repo, sync_inbox, FoldedIssue,
};

#[derive(Debug, Subcommand)]
pub enum IssueCmd {
    Create {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
        /// Attach encrypted labels (names must exist via `sh label create`).
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    List {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        state: Option<String>,
    },
    View {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Close {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Reopen {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Add an encrypted comment (MLS app message; host never sees the text).
    Comment {
        id: String,
        #[arg(long)]
        body: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Show open/closed counts (`gh issue status`).
    Status {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Edit title/body (re-emits encrypted Issue message).
    Edit {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Delete is a soft close + tombstone comment (no host wipe of ciphertext).
    Delete {
        id: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

pub async fn run(cmd: IssueCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        IssueCmd::Create {
            title,
            body,
            labels,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let (issues, _) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
            let id = next_collab_number(issues.iter().map(|i| i.id.clone())).to_string();
            let msg = CollabMessage::Issue {
                id: id.clone(),
                title: title.clone(),
                body: body.clone(),
                state: "open".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "issue").await?;
            for label in &labels {
                let lmsg = CollabMessage::Label {
                    name: label.clone(),
                    color: None,
                    description: Some(format!("attached to issue {id}")),
                    action: "create".into(),
                };
                let _ = enqueue_collab(&client, &record.id, &material, &lmsg, "issue-label").await?;
            }
            println!("Created encrypted issue #{id} (MLS seq {seq})");
            println!("note: body sealed under group keys; untrusted host stores opaque frames only");
            if !labels.is_empty() {
                println!("attached encrypted labels: {}", labels.join(", "));
            }
        }
        IssueCmd::List { repo, state } => {
            let issues = load_issues(&client, repo.as_deref()).await?;
            let filter = state.as_deref().unwrap_or("open");
            for i in issues {
                if filter != "all" && i.state != filter {
                    continue;
                }
                println!("#{}\t{}\t{}", i.id, i.state, i.title);
            }
            println!("note: listed from local decrypt of MLS inbox (not host plaintext index)");
        }
        IssueCmd::View { id, repo } => {
            let issue = find_issue(&client, repo.as_deref(), &id).await?;
            println!("#{} [{}] {}", issue.id, issue.state, issue.title);
            println!("{}", issue.body);
            for c in &issue.comments {
                println!("--- encrypted comment\n{c}");
            }
        }
        IssueCmd::Close { id, repo } => {
            set_issue_state(&client, repo.as_deref(), &id, "closed").await?;
            println!("Closed encrypted issue #{id}");
        }
        IssueCmd::Reopen { id, repo } => {
            set_issue_state(&client, repo.as_deref(), &id, "open").await?;
            println!("Reopened encrypted issue #{id}");
        }
        IssueCmd::Comment { id, body, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Comment {
                target_kind: "issue".into(),
                target_id: id.clone(),
                body: body.clone(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "issue-comment").await?;
            println!("Added encrypted comment on issue #{id} (MLS seq {seq})");
        }
        IssueCmd::Status { repo } => {
            let issues = load_issues(&client, repo.as_deref()).await?;
            let open = issues.iter().filter(|i| i.state == "open").count();
            let closed = issues.iter().filter(|i| i.state == "closed").count();
            println!("Open issues: {open}");
            for i in issues.iter().filter(|i| i.state == "open") {
                println!("  #{}\t{}", i.id, i.title);
            }
            println!("Closed issues: {closed}");
            println!("note: counted from decrypted MLS inbox");
        }
        IssueCmd::Edit {
            id,
            title,
            body,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let issue = find_issue(&client, Some(&format!("{}", record.name)), &id).await?;
            let msg = CollabMessage::Issue {
                id: issue.id.clone(),
                title: title.unwrap_or(issue.title),
                body: body.unwrap_or(issue.body),
                state: issue.state,
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "issue-edit").await?;
            println!("Updated encrypted issue #{id} (MLS seq {seq})");
        }
        IssueCmd::Delete { id, repo, yes } => {
            if !yes {
                anyhow::bail!("refusing to delete without --yes (soft-close + tombstone only)");
            }
            set_issue_state(&client, repo.as_deref(), &id, "closed").await?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Comment {
                target_kind: "issue".into(),
                target_id: id.clone(),
                body: "[deleted]".into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "issue-delete").await?;
            println!("Soft-deleted encrypted issue #{id} (closed + tombstone comment)");
        }
    }
    Ok(())
}

async fn load_issues(client: &HttpClient, repo: Option<&str>) -> anyhow::Result<Vec<FoldedIssue>> {
    let record = resolve_repo(client, repo).await?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(client, &record.id, &material).await?;
    let (issues, _) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    Ok(issues)
}

async fn find_issue(
    client: &HttpClient,
    repo: Option<&str>,
    id: &str,
) -> anyhow::Result<FoldedIssue> {
    let issues = load_issues(client, repo).await?;
    issues
        .into_iter()
        .find(|i| i.id == id || format!("#{}", i.id) == id)
        .ok_or_else(|| anyhow::anyhow!("issue #{id} not found in decrypted inbox; run `sh inbox sync`"))
}

async fn set_issue_state(
    client: &HttpClient,
    repo: Option<&str>,
    id: &str,
    state: &str,
) -> anyhow::Result<()> {
    let record = resolve_repo(client, repo).await?;
    let material = material_for(&record.id)?;
    let issue = find_issue(client, Some(&format!("{}", record.name)), id).await?;
    let msg = CollabMessage::Issue {
        id: issue.id.clone(),
        title: issue.title,
        body: String::new(),
        state: state.into(),
    };
    let _ = enqueue_collab(client, &record.id, &material, &msg, "issue-state").await?;
    Ok(())
}
