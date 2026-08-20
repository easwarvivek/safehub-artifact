//! Plaintext collab index for the local web gateway (issues / PRs).
//! MLS ciphertext remains on the delivery queue; this index powers the HTML UI.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueRecord {
    pub id: u64,
    pub title: String,
    pub body: String,
    pub state: String, // open | closed
    pub author: String,
    pub created_at: String,
    pub comments: Vec<CommentRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommentRecord {
    pub id: String,
    pub author: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullRequestRecord {
    pub id: u64,
    pub title: String,
    pub body: String,
    pub state: String, // open | closed | merged
    pub author: String,
    pub base: String,
    pub head: String,
    pub created_at: String,
    pub comments: Vec<CommentRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollabIndex {
    pub issues: Vec<IssueRecord>,
    pub pulls: Vec<PullRequestRecord>,
    next_issue: u64,
    next_pr: u64,
}

fn path(data: &Path, owner: &str, name: &str) -> PathBuf {
    data.join("collab").join(owner).join(format!("{name}.json"))
}

pub async fn load(data: &Path, owner: &str, name: &str) -> anyhow::Result<CollabIndex> {
    let p = path(data, owner, name);
    if !p.exists() {
        return Ok(CollabIndex {
            next_issue: 1,
            next_pr: 1,
            ..Default::default()
        });
    }
    Ok(serde_json::from_slice(&tokio::fs::read(p).await?)?)
}

async fn save(data: &Path, owner: &str, name: &str, idx: &CollabIndex) -> anyhow::Result<()> {
    let p = path(data, owner, name);
    if let Some(parent) = p.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(p, serde_json::to_vec_pretty(idx)?).await?;
    Ok(())
}

pub async fn create_issue(
    data: &Path,
    owner: &str,
    name: &str,
    author: &str,
    title: &str,
    body: &str,
) -> anyhow::Result<IssueRecord> {
    let mut idx = load(data, owner, name).await?;
    let rec = IssueRecord {
        id: idx.next_issue,
        title: title.into(),
        body: body.into(),
        state: "open".into(),
        author: author.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        comments: vec![],
    };
    idx.next_issue += 1;
    idx.issues.push(rec.clone());
    save(data, owner, name, &idx).await?;
    Ok(rec)
}

pub async fn create_pr(
    data: &Path,
    owner: &str,
    name: &str,
    author: &str,
    title: &str,
    body: &str,
    base: &str,
    head: &str,
) -> anyhow::Result<PullRequestRecord> {
    let mut idx = load(data, owner, name).await?;
    let rec = PullRequestRecord {
        id: idx.next_pr,
        title: title.into(),
        body: body.into(),
        state: "open".into(),
        author: author.into(),
        base: base.into(),
        head: head.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        comments: vec![],
    };
    idx.next_pr += 1;
    idx.pulls.push(rec.clone());
    save(data, owner, name, &idx).await?;
    Ok(rec)
}

pub async fn set_issue_state(
    data: &Path,
    owner: &str,
    name: &str,
    id: u64,
    state: &str,
) -> anyhow::Result<IssueRecord> {
    let mut idx = load(data, owner, name).await?;
    let issue = idx
        .issues
        .iter_mut()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow::anyhow!("issue not found"))?;
    issue.state = state.into();
    let out = issue.clone();
    save(data, owner, name, &idx).await?;
    Ok(out)
}

pub async fn set_pr_state(
    data: &Path,
    owner: &str,
    name: &str,
    id: u64,
    state: &str,
) -> anyhow::Result<PullRequestRecord> {
    let mut idx = load(data, owner, name).await?;
    let pr = idx
        .pulls
        .iter_mut()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow::anyhow!("pr not found"))?;
    pr.state = state.into();
    let out = pr.clone();
    save(data, owner, name, &idx).await?;
    Ok(out)
}

pub async fn comment_issue(
    data: &Path,
    owner: &str,
    name: &str,
    id: u64,
    author: &str,
    body: &str,
) -> anyhow::Result<IssueRecord> {
    let mut idx = load(data, owner, name).await?;
    let issue = idx
        .issues
        .iter_mut()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow::anyhow!("issue not found"))?;
    issue.comments.push(CommentRecord {
        id: Uuid::new_v4().to_string(),
        author: author.into(),
        body: body.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    let out = issue.clone();
    save(data, owner, name, &idx).await?;
    Ok(out)
}

pub async fn comment_pr(
    data: &Path,
    owner: &str,
    name: &str,
    id: u64,
    author: &str,
    body: &str,
) -> anyhow::Result<PullRequestRecord> {
    let mut idx = load(data, owner, name).await?;
    let pr = idx
        .pulls
        .iter_mut()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow::anyhow!("pr not found"))?;
    pr.comments.push(CommentRecord {
        id: Uuid::new_v4().to_string(),
        author: author.into(),
        body: body.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    let out = pr.clone();
    save(data, owner, name, &idx).await?;
    Ok(out)
}

/// Case-insensitive substring search over issue/PR titles and bodies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchHit {
    pub kind: String,
    pub owner: String,
    pub repo: String,
    pub id: u64,
    pub title: String,
    pub state: String,
    pub author: String,
}

/// Walk the collab index tree and return matching issues/PRs.
pub async fn search(
    data: &Path,
    query: &str,
    kind: Option<&str>,
) -> anyhow::Result<Vec<SearchHit>> {
    let q = query.to_lowercase();
    let mut hits = Vec::new();
    let root = data.join("collab");
    if !root.exists() {
        return Ok(hits);
    }
    let mut owners = tokio::fs::read_dir(&root).await?;
    while let Some(owner_ent) = owners.next_entry().await? {
        if !owner_ent.file_type().await?.is_dir() {
            continue;
        }
        let owner = owner_ent.file_name().to_string_lossy().into_owned();
        let mut repos = tokio::fs::read_dir(owner_ent.path()).await?;
        while let Some(repo_ent) = repos.next_entry().await? {
            let fname = repo_ent.file_name().to_string_lossy().into_owned();
            if !fname.ends_with(".json") {
                continue;
            }
            let repo = fname.trim_end_matches(".json").to_string();
            let idx = load(data, &owner, &repo).await?;
            let want_issues = kind.is_none() || kind == Some("issues");
            let want_prs = kind.is_none() || kind == Some("prs");
            if want_issues {
                for issue in &idx.issues {
                    let hay = format!("{} {}", issue.title, issue.body).to_lowercase();
                    if hay.contains(&q) {
                        hits.push(SearchHit {
                            kind: "issue".into(),
                            owner: owner.clone(),
                            repo: repo.clone(),
                            id: issue.id,
                            title: issue.title.clone(),
                            state: issue.state.clone(),
                            author: issue.author.clone(),
                        });
                    }
                }
            }
            if want_prs {
                for pr in &idx.pulls {
                    let hay = format!("{} {}", pr.title, pr.body).to_lowercase();
                    if hay.contains(&q) {
                        hits.push(SearchHit {
                            kind: "pr".into(),
                            owner: owner.clone(),
                            repo: repo.clone(),
                            id: pr.id,
                            title: pr.title.clone(),
                            state: pr.state.clone(),
                            author: pr.author.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(hits)
}
