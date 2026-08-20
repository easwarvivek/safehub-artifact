//! Aggregate status across decrypted MLS inboxes (`gh status` analogue).

use clap::Args;
use safehub_client::HttpClient;

use super::common::{fold_collab_inbox, material_for, read_inbox_cache, resolve_repo, sync_inbox};

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Limit to one repository (`owner/name`). Default: current checkout.
    #[arg(long)]
    repo: Option<String>,
    /// Comma-separated owner/name repos to exclude.
    #[arg(long)]
    exclude: Option<String>,
}

pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    let exclude: Vec<String> = args
        .exclude
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let repos = if let Some(r) = &args.repo {
        vec![client
            .get_repo(&safehub_types::RepoName::parse(r).ok_or_else(|| {
                anyhow::anyhow!("expected owner/name")
            })?)
            .await?]
    } else if let Ok(local) = resolve_repo(&client, None).await {
        vec![local]
    } else {
        client
            .list_repos()
            .await?
            .into_iter()
            .filter(|r| !r.deleted && !r.archived)
            .collect()
    };

    let mut issue_lines = Vec::new();
    let mut pr_lines = Vec::new();
    let mut review_lines = Vec::new();

    for record in repos {
        let name = format!("{}", record.name);
        if exclude.iter().any(|e| e == &name) {
            continue;
        }
        let Ok(material) = material_for(&record.id) else {
            continue;
        };
        let _ = sync_inbox(&client, &record.id, &material).await;
        let Ok(cache) = read_inbox_cache(&record.id) else {
            continue;
        };
        let (issues, prs) = fold_collab_inbox(&cache);
        for i in issues {
            if i.state == "open" {
                issue_lines.push(format!("  {name}#{}\t{}", i.id, i.title));
            }
        }
        for p in prs {
            if p.state == "open" {
                pr_lines.push(format!(
                    "  {name}#{}\t{}\t{} → {}",
                    p.id, p.title, p.head_ref, p.base_ref
                ));
                if p.reviews.is_empty() {
                    review_lines.push(format!("  {name}#{}\t(no reviews yet) {}", p.id, p.title));
                }
            }
        }
    }

    println!("Assigned Issues");
    if issue_lines.is_empty() {
        println!("  (none open in decrypted inbox)");
    } else {
        for line in &issue_lines {
            println!("{line}");
        }
    }
    println!();
    println!("Assigned Pull Requests");
    if pr_lines.is_empty() {
        println!("  (none open in decrypted inbox)");
    } else {
        for line in &pr_lines {
            println!("{line}");
        }
    }
    println!();
    println!("Review Requests");
    if review_lines.is_empty() {
        println!("  (none — reviews are MLS messages; no host assignment index)");
    } else {
        for line in &review_lines {
            println!("{line}");
        }
    }
    println!();
    println!(
        "note: status is member-local decrypt of MLS inboxes; host cannot assign or search plaintext"
    );
    Ok(())
}
