//! Collaboration and repository search (member-local only — no plaintext host search).

use clap::Subcommand;
use safehub_client::{fetch_tip, HttpClient};
use std::path::Path;
use std::process::Command;

use super::common::{fold_collab_inbox, material_for, read_inbox_cache, resolve_repo, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum SearchCmd {
    /// Search repository names (membership-scoped listing).
    Repos { query: Option<String> },
    /// Search issues in the decrypted MLS inbox (not on the host).
    Issues {
        query: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Search pull requests in the decrypted MLS inbox (not on the host).
    Prs {
        query: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Member-local code search over decrypted working tree / tip (no plaintext server search).
    Code {
        query: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run_search(cmd: SearchCmd) -> anyhow::Result<()> {
    match cmd {
        SearchCmd::Code { query, repo } => {
            let q = query.ok_or_else(|| anyhow::anyhow!("search query required"))?;
            let client = HttpClient::from_disk()?;
            // Prefer local working tree (already decrypted by member).
            if Path::new(".git").exists() {
                let out = Command::new("git")
                    .args(["grep", "-n", "-I", &q])
                    .output()?;
                if out.status.success() || !out.stdout.is_empty() {
                    print!("{}", String::from_utf8_lossy(&out.stdout));
                    println!(
                        "note: member-local decrypt search; host never sees plaintext query/index"
                    );
                    return Ok(());
                }
            }
            // Fallback: fetch tip bundle and grep extracted text if keyed.
            if let Ok(record) = resolve_repo(&client, repo.as_deref()).await {
                if let Ok(material) = material_for(&record.id) {
                    if let Ok(Some(fetched)) = fetch_tip(&client, &record.id, &material).await {
                        let text = String::from_utf8_lossy(&fetched.bundle);
                        for (i, line) in text.lines().enumerate() {
                            if line.contains(&q) {
                                println!("bundle:{}:{line}", i + 1);
                            }
                        }
                        println!(
                            "note: searched decrypted tip bundle locally (forward-only members limited by history window)"
                        );
                        return Ok(());
                    }
                }
            }
            println!("[]");
            println!("no local decrypt index; clone + sit pull, then retry `sh search code`");
            Ok(())
        }
        SearchCmd::Repos { query } => {
            let client = HttpClient::from_disk()?;
            let repos = client.list_repos().await?;
            let q = query.unwrap_or_default().to_lowercase();
            let mut n = 0usize;
            for r in repos {
                let name = format!("{}/{}", r.name.owner, r.name.name);
                if q.is_empty() || name.to_lowercase().contains(&q) {
                    let flags = match (r.archived, r.private) {
                        (true, _) => "archived",
                        (false, true) => "private",
                        (false, false) => "public",
                    };
                    println!("{name}\t{flags}");
                    n += 1;
                }
            }
            if n == 0 {
                println!("[]");
            }
            println!(
                "note: membership-scoped name listing only; host has no plaintext code/index search"
            );
            Ok(())
        }
        SearchCmd::Issues { query, repo } => {
            let q = query.ok_or_else(|| anyhow::anyhow!("search query required"))?;
            let client = HttpClient::from_disk()?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let (issues, _) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
            let ql = q.to_lowercase();
            let mut n = 0usize;
            for i in issues {
                let hay = format!("{} {} {}", i.id, i.title, i.body).to_lowercase();
                if hay.contains(&ql) {
                    println!("#{}\t{}\t{}", i.id, i.state, i.title);
                    n += 1;
                }
            }
            if n == 0 {
                println!("[]");
            }
            println!("note: member-local decrypt search over MLS inbox; host never indexes issue bodies");
            Ok(())
        }
        SearchCmd::Prs { query, repo } => {
            let q = query.ok_or_else(|| anyhow::anyhow!("search query required"))?;
            let client = HttpClient::from_disk()?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            let (_, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
            let ql = q.to_lowercase();
            let mut n = 0usize;
            for p in prs {
                let hay = format!("{} {} {}", p.id, p.title, p.body).to_lowercase();
                if hay.contains(&ql) {
                    println!("#{}\t{}\t{}", p.id, p.state, p.title);
                    n += 1;
                }
            }
            if n == 0 {
                println!("[]");
            }
            println!("note: member-local decrypt search over MLS inbox; host never indexes PR bodies");
            Ok(())
        }
    }
}
