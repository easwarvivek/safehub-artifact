//! Encrypted pull requests via MLS application messages (host never sees bodies).

use clap::Subcommand;
use safehub_client::{fetch_tip, HttpClient};
use safehub_types::CollabMessage;
use std::process::Command;

use super::common::{
    enqueue_collab, fold_collab_inbox, material_for, next_collab_number, read_inbox_cache,
    resolve_repo, sync_inbox, FoldedPr,
};
// CollabMessage used throughout; CiVerdict matched in Checks.

#[derive(Debug, Subcommand)]
pub enum PrCmd {
    Create {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
        #[arg(long, default_value = "main")]
        base: String,
        #[arg(long)]
        head: String,
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
    /// Fetch encrypted tip and checkout PR head branch.
    Checkout {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Diff PR head against base (local objects after fetch).
    Diff {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Submit an encrypted review verdict.
    Review {
        id: String,
        #[arg(long, default_value = "comment")]
        verdict: String,
        #[arg(long, default_value = "")]
        body: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Merge PR: mark merged, git merge head, sit push when possible.
    Merge {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Close PR.
    Close {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Reopen a closed PR.
    Reopen {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Add an encrypted comment to a PR (MLS only; host never sees the text).
    Comment {
        id: String,
        #[arg(long)]
        body: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Show open/closed/merged counts (`gh pr status`).
    Status {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Show CI verdicts from decrypted inbox (`gh pr checks`).
    Checks {
        id: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Edit title/body (re-emits encrypted PullRequest message).
    Edit {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        head: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: PrCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        PrCmd::Create {
            title,
            body,
            base,
            head,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let (_, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
            let id = next_collab_number(prs.iter().map(|p| p.id.clone())).to_string();
            let msg = CollabMessage::PullRequest {
                id: id.clone(),
                head_ref: head.clone(),
                base_ref: base.clone(),
                title: title.clone(),
                body: body.clone(),
                state: "open".into(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "pr-create").await?;
            println!("Created encrypted PR #{id} (MLS seq {seq})");
            println!("{head} → {base}");
            println!("note: title/body sealed; untrusted host stores opaque frames only");
        }
        PrCmd::List { repo, state } => {
            let prs = load_prs(&client, repo.as_deref()).await?;
            let filter = state.as_deref().unwrap_or("open");
            for p in prs {
                if filter != "all" && p.state != filter {
                    continue;
                }
                println!(
                    "#{}\t{}\t{}\t{} → {}",
                    p.id, p.state, p.title, p.head_ref, p.base_ref
                );
            }
            println!("note: listed from local decrypt of MLS inbox (not host plaintext index)");
        }
        PrCmd::View { id, repo } => {
            let pr = find_pr(&client, repo.as_deref(), &id).await?;
            println!(
                "#{} [{}] {} ({} → {})",
                pr.id, pr.state, pr.title, pr.head_ref, pr.base_ref
            );
            println!("{}", pr.body);
            for (v, b) in &pr.reviews {
                println!("--- encrypted review [{v}]\n{b}");
            }
            for c in &pr.comments {
                println!("--- encrypted comment\n{c}");
            }
        }
        PrCmd::Checkout { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            let head = pr.head_ref.as_str();
            if let Ok(material) = material_for(&record.id) {
                if let Ok(Some(fetched)) = fetch_tip(&client, &record.id, &material).await {
                    let bundle_path = std::env::temp_dir().join(format!(
                        "safehub-pr-{}.bundle",
                        fetched.head.seq
                    ));
                    std::fs::write(&bundle_path, &fetched.bundle)?;
                    let _ = Command::new("git")
                        .args(["fetch", bundle_path.to_str().unwrap()])
                        .status();
                    let _ = std::fs::remove_file(&bundle_path);
                    if let Some(oid) = fetched
                        .refs
                        .refs
                        .get(&format!("refs/heads/{head}"))
                        .or_else(|| fetched.refs.refs.get(head))
                    {
                        let branch = format!("pr-{id}");
                        let _ = Command::new("git")
                            .args(["checkout", "-B", &branch, oid])
                            .status()?;
                        println!("checked out {branch} at {oid} (from encrypted tip)");
                        return Ok(());
                    }
                }
            }
            let branch = format!("pr-{id}");
            let status = Command::new("git")
                .args(["checkout", "-B", &branch, head])
                .status()?;
            if status.success() {
                println!("checked out {branch} from local ref {head}");
            } else {
                println!("Checkout PR {id} — fetch tip then:");
                println!("  sit fetch && sit checkout -b pr-{id} {head}");
            }
        }
        PrCmd::Diff { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            let base = pr.base_ref.as_str();
            let head = pr.head_ref.as_str();
            if let Ok(material) = material_for(&record.id) {
                let _ = fetch_tip(&client, &record.id, &material).await;
            }
            let status = Command::new("git")
                .args(["diff", &format!("{base}...{head}")])
                .status()?;
            if !status.success() {
                anyhow::bail!("git diff failed; ensure tip fetched (`sit fetch`)");
            }
        }
        PrCmd::Review {
            id,
            verdict,
            body,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Review {
                pr_id: id.clone(),
                verdict: verdict.clone(),
                body: body.clone(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "pr-review").await?;
            println!("Encrypted review on PR #{id} ({verdict}) MLS seq {seq}");
        }
        PrCmd::Merge { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            let head = pr.head_ref.as_str();
            let base = pr.base_ref.as_str();
            set_pr_state(&client, &record, &pr, "merged").await?;
            let _ = Command::new("git").args(["checkout", base]).status();
            let merge = Command::new("git")
                .args(["merge", "--no-ff", head, "-m", &format!("Merge PR #{id}")])
                .status()?;
            if merge.success() {
                println!("Merged {head} into {base} locally");
                match crate::cmds::push::run("sit", "HEAD").await {
                    Ok(()) => println!("sit push completed after merge"),
                    Err(e) => println!("sit push deferred: {e:#} (run `sit push` when ready)"),
                }
            } else {
                println!("Marked PR {id} merged. Complete with local merge + `sit push`.");
            }
        }
        PrCmd::Close { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            set_pr_state(&client, &record, &pr, "closed").await?;
            println!("Closed encrypted PR #{id}");
        }
        PrCmd::Reopen { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            set_pr_state(&client, &record, &pr, "open").await?;
            println!("Reopened encrypted PR #{id}");
        }
        PrCmd::Comment { id, body, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::Comment {
                target_kind: "pr".into(),
                target_id: id.clone(),
                body: body.clone(),
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "pr-comment").await?;
            println!("Added encrypted comment on PR #{id} (MLS seq {seq})");
        }
        PrCmd::Status { repo } => {
            let prs = load_prs(&client, repo.as_deref()).await?;
            let open = prs.iter().filter(|p| p.state == "open").count();
            let closed = prs.iter().filter(|p| p.state == "closed").count();
            let merged = prs.iter().filter(|p| p.state == "merged").count();
            println!("Open pull requests: {open}");
            for p in prs.iter().filter(|p| p.state == "open") {
                println!(
                    "  #{}\t{}\t{} → {}",
                    p.id, p.title, p.head_ref, p.base_ref
                );
            }
            println!("Closed: {closed} · Merged: {merged}");
            println!("note: counted from decrypted MLS inbox");
        }
        PrCmd::Checks { id, repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            let mut found = false;
            for (_, msg) in read_inbox_cache(&record.id)? {
                if let CollabMessage::CiVerdict {
                    commit,
                    status,
                    summary,
                    run_id,
                } = msg
                {
                    // Best-effort: show all verdicts; correlate by run_id containing PR id when present.
                    let related = run_id
                        .as_deref()
                        .map(|r| r.contains(&id) || r.contains(&pr.id))
                        .unwrap_or(true);
                    if !related {
                        continue;
                    }
                    found = true;
                    let rid = run_id.as_deref().unwrap_or("-");
                    println!("{status}\t{commit}\trun={rid}\t{summary}");
                }
            }
            if !found {
                println!("no CI verdicts in decrypted inbox for PR #{id}");
                println!("note: runners post `CiVerdict` MLS messages; no hosted Actions on SafeHub");
            }
        }
        PrCmd::Edit {
            id,
            title,
            body,
            base,
            head,
            repo,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let pr = find_pr(&client, Some(&format!("{}", record.name)), &id).await?;
            let msg = CollabMessage::PullRequest {
                id: pr.id.clone(),
                head_ref: head.unwrap_or(pr.head_ref),
                base_ref: base.unwrap_or(pr.base_ref),
                title: title.unwrap_or(pr.title),
                body: body.unwrap_or(pr.body),
                state: pr.state,
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "pr-edit").await?;
            println!("Updated encrypted PR #{id} (MLS seq {seq})");
        }
    }
    Ok(())
}

async fn load_prs(client: &HttpClient, repo: Option<&str>) -> anyhow::Result<Vec<FoldedPr>> {
    let record = resolve_repo(client, repo).await?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(client, &record.id, &material).await?;
    let (_, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    Ok(prs)
}

async fn find_pr(client: &HttpClient, repo: Option<&str>, id: &str) -> anyhow::Result<FoldedPr> {
    let prs = load_prs(client, repo).await?;
    prs.into_iter()
        .find(|p| p.id == id || format!("#{}", p.id) == id)
        .ok_or_else(|| anyhow::anyhow!("PR #{id} not found in decrypted inbox; run `sh inbox sync`"))
}

async fn set_pr_state(
    client: &HttpClient,
    record: &safehub_types::RepoRecord,
    pr: &FoldedPr,
    state: &str,
) -> anyhow::Result<()> {
    let material = material_for(&record.id)?;
    let msg = CollabMessage::PullRequest {
        id: pr.id.clone(),
        head_ref: pr.head_ref.clone(),
        base_ref: pr.base_ref.clone(),
        title: pr.title.clone(),
        body: String::new(),
        state: state.into(),
    };
    let _ = enqueue_collab(client, &record.id, &material, &msg, "pr-state").await?;
    Ok(())
}
