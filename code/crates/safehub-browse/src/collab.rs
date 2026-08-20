//! Member-local MLS inbox helpers for browse UI (same fold model as `sh issue` / `sh pr`).

use anyhow::{Context, Result};
use safehub_client::{
    load_epoch_material, open_collab, seal_collab, Credentials, EpochMaterial, HttpClient,
};
use safehub_types::{CollabMessage, RepoId, RepoRecord};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct FoldedIssue {
    pub id: String,
    pub title: String,
    pub body: String,
    pub state: String,
    pub comments: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct FoldedPr {
    pub id: String,
    pub title: String,
    pub body: String,
    pub state: String,
    pub head_ref: String,
    pub base_ref: String,
    pub comments: Vec<String>,
    pub reviews: Vec<(String, String)>,
}

/// Load `.git/safehub/repo.json` from a checkout root.
pub fn load_repo_record(repo_root: &Path) -> Result<RepoRecord> {
    let path = repo_root.join(".git").join("safehub").join("repo.json");
    if !path.exists() {
        anyhow::bail!("no SafeHub binding (.git/safehub/repo.json); clone or create with `sh`/`sit`");
    }
    Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
}

pub fn material_for(repo: &RepoId) -> Result<EpochMaterial> {
    Ok(load_epoch_material(repo)?)
}

fn inbox_dir(repo: &RepoId) -> Result<PathBuf> {
    let dir = EpochMaterial::dir(repo)?.join("inbox");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn mls_cursor_path(repo: &RepoId) -> Result<PathBuf> {
    Ok(EpochMaterial::dir(repo)?.join("mls_cursor.json"))
}

fn load_mls_cursor(repo: &RepoId) -> u64 {
    let Ok(path) = mls_cursor_path(repo) else {
        return 0;
    };
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("after").and_then(|x| x.as_u64()))
        .unwrap_or(0)
}

fn save_mls_cursor(repo: &RepoId, after: u64) -> Result<()> {
    let path = mls_cursor_path(repo)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({ "after": after }))?,
    )?;
    Ok(())
}

pub async fn sync_inbox(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
) -> Result<Vec<(u64, CollabMessage)>> {
    let after = load_mls_cursor(repo);
    let envs = client.mls_fetch(repo, after).await?;
    let mut out = Vec::new();
    let mut max_seq = after;
    let dir = inbox_dir(repo)?;
    for env in envs {
        max_seq = max_seq.max(env.seq);
        match open_collab(material, &env.payload) {
            Ok(pt) => {
                if let Ok(msg) = serde_json::from_slice::<CollabMessage>(&pt) {
                    let path = dir.join(format!("{:016}.json", env.seq));
                    std::fs::write(&path, serde_json::to_vec_pretty(&msg)?)?;
                    out.push((env.seq, msg));
                }
            }
            Err(_) => {}
        }
    }
    if max_seq > after {
        save_mls_cursor(repo, max_seq)?;
    }
    Ok(out)
}

pub fn read_inbox_cache(repo: &RepoId) -> Result<Vec<(u64, CollabMessage)>> {
    let dir = inbox_dir(repo)?;
    let mut entries = Vec::new();
    if !dir.exists() {
        return Ok(entries);
    }
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let seq: u64 = name.trim_end_matches(".json").parse().unwrap_or(0);
        let msg: CollabMessage = serde_json::from_slice(&std::fs::read(ent.path())?)?;
        entries.push((seq, msg));
    }
    entries.sort_by_key(|(s, _)| *s);
    Ok(entries)
}

pub fn fold_collab_inbox(messages: &[(u64, CollabMessage)]) -> (Vec<FoldedIssue>, Vec<FoldedPr>) {
    let mut issues: BTreeMap<String, FoldedIssue> = BTreeMap::new();
    let mut prs: BTreeMap<String, FoldedPr> = BTreeMap::new();
    for (_seq, msg) in messages {
        match msg {
            CollabMessage::Issue {
                id,
                title,
                body,
                state,
            } => {
                let e = issues.entry(id.clone()).or_insert_with(|| FoldedIssue {
                    id: id.clone(),
                    title: title.clone(),
                    body: body.clone(),
                    state: state.clone(),
                    comments: vec![],
                });
                if !title.is_empty() {
                    e.title = title.clone();
                }
                if !body.is_empty() {
                    e.body = body.clone();
                }
                if !state.is_empty() {
                    e.state = state.clone();
                }
            }
            CollabMessage::PullRequest {
                id,
                head_ref,
                base_ref,
                title,
                body,
                state,
            } => {
                let e = prs.entry(id.clone()).or_insert_with(|| FoldedPr {
                    id: id.clone(),
                    title: title.clone(),
                    body: body.clone(),
                    state: state.clone(),
                    head_ref: head_ref.clone(),
                    base_ref: base_ref.clone(),
                    comments: vec![],
                    reviews: vec![],
                });
                if !title.is_empty() {
                    e.title = title.clone();
                }
                if !body.is_empty() {
                    e.body = body.clone();
                }
                if !state.is_empty() {
                    e.state = state.clone();
                }
                if !head_ref.is_empty() {
                    e.head_ref = head_ref.clone();
                }
                if !base_ref.is_empty() {
                    e.base_ref = base_ref.clone();
                }
            }
            CollabMessage::Comment {
                target_kind,
                target_id,
                body,
            } => {
                if target_kind == "issue" {
                    if let Some(i) = issues.get_mut(target_id) {
                        i.comments.push(body.clone());
                    }
                } else if target_kind == "pr" {
                    if let Some(p) = prs.get_mut(target_id) {
                        p.comments.push(body.clone());
                    }
                }
            }
            CollabMessage::Review {
                pr_id,
                verdict,
                body,
            } => {
                if let Some(p) = prs.get_mut(pr_id) {
                    p.reviews.push((verdict.clone(), body.clone()));
                }
            }
            _ => {}
        }
    }
    (issues.into_values().collect(), prs.into_values().collect())
}

pub fn next_collab_number(ids: impl Iterator<Item = String>) -> u64 {
    let mut max = 0u64;
    for id in ids {
        let n = id
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .parse::<u64>()
            .or_else(|_| id.parse::<u64>())
            .unwrap_or(0);
        max = max.max(n);
    }
    max + 1
}

pub async fn enqueue_collab(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    msg: &CollabMessage,
    hint: &str,
) -> Result<u64> {
    let sealed = seal_collab(material, &serde_json::to_vec(msg)?)?;
    Ok(client.mls_enqueue(repo, sealed, Some(hint.into())).await?)
}

pub async fn load_folded(repo_root: &Path) -> Result<(RepoRecord, Vec<FoldedIssue>, Vec<FoldedPr>)> {
    let record = load_repo_record(repo_root)?;
    let client = HttpClient::from_disk().context("SafeHub client (run `sh auth login`)")?;
    let material = material_for(&record.id).context("MLS epoch material")?;
    let _ = sync_inbox(&client, &record.id, &material).await;
    let (issues, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    Ok((record, issues, prs))
}

pub fn auth_user() -> Option<String> {
    Credentials::load()
        .ok()
        .flatten()
        .map(|c| c.token.user.0)
}
