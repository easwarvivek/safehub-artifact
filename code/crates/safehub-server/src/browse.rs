//! Local member browse helpers: plaintext tree/blob/commits from a mirror
//! under `{data}/mirrors/{owner}/{name}/`.
//!
//! Used by `safehub-local-ui` / `safehub-browse` on the member machine.
//! The untrusted `safehub-server` host must not mount these handlers.
//! The CAS store remains ciphertext-only; the mirror is populated on the
//! member machine (same trust domain as CLI keys).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    pub entry_type: String, // "file" | "dir"
    pub size: Option<u64>,
    pub sha: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobView {
    pub path: String,
    pub sha: String,
    pub size: u64,
    pub encoding: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitInfo {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub date: String,
    pub parents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RepoMembers {
    pub owner: String,
    pub members: Vec<MemberEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberEntry {
    pub user: String,
    /// `full` | `forward_only`
    pub history: String,
    pub invited_at: String,
}

pub fn mirror_root(data: &Path, owner: &str, name: &str) -> PathBuf {
    data.join("mirrors").join(owner).join(name)
}

pub fn members_path(data: &Path, owner: &str, name: &str) -> PathBuf {
    data.join("membership").join(owner).join(format!("{name}.json"))
}

pub async fn load_members(data: &Path, owner: &str, name: &str) -> anyhow::Result<RepoMembers> {
    let path = members_path(data, owner, name);
    if !path.exists() {
        return Ok(RepoMembers {
            owner: owner.into(),
            members: vec![MemberEntry {
                user: owner.into(),
                history: "full".into(),
                invited_at: chrono::Utc::now().to_rfc3339(),
            }],
        });
    }
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn save_members(data: &Path, owner: &str, name: &str, m: &RepoMembers) -> anyhow::Result<()> {
    let path = members_path(data, owner, name);
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?;
    }
    let bytes = serde_json::to_vec_pretty(m)?;
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

pub fn is_member(m: &RepoMembers, user: &str) -> bool {
    m.owner == user || m.members.iter().any(|e| e.user == user)
}

/// Ensure mirror exists; seed with README if empty.
pub async fn ensure_mirror(data: &Path, owner: &str, name: &str) -> anyhow::Result<PathBuf> {
    let root = mirror_root(data, owner, name);
    tokio::fs::create_dir_all(&root).await?;
    let readme = root.join("README.md");
    if !readme.exists() {
        let body = format!(
            "# {owner}/{name}\n\nSafeHub encrypted repository (local browse mirror).\n"
        );
        tokio::fs::write(&readme, body).await?;
        // Init git for commit history if git is available.
        let _ = init_git_mirror(&root, owner);
    }
    Ok(root)
}

fn init_git_mirror(root: &Path, author: &str) -> anyhow::Result<()> {
    if root.join(".git").exists() {
        return Ok(());
    }
    let git = "git";
    run(git, &["-C", root.to_str().unwrap(), "init", "-q", "--template="])?;
    run(
        git,
        &[
            "-C",
            root.to_str().unwrap(),
            "config",
            "user.email",
            &format!("{author}@safehub.local"),
        ],
    )?;
    run(
        git,
        &["-C", root.to_str().unwrap(), "config", "user.name", author],
    )?;
    run(git, &["-C", root.to_str().unwrap(), "add", "."])?;
    run(
        git,
        &["-C", root.to_str().unwrap(), "commit", "-qm", "Initial commit"],
    )?;
    Ok(())
}

fn run(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let st = Command::new(bin).args(args).status()?;
    if !st.success() {
        anyhow::bail!("{bin} {:?} failed", args);
    }
    Ok(())
}

pub fn list_tree(root: &Path, rel: &str) -> anyhow::Result<Vec<TreeEntry>> {
    let dir = if rel.is_empty() || rel == "/" {
        root.to_path_buf()
    } else {
        root.join(rel.trim_start_matches('/'))
    };
    if !dir.is_dir() {
        anyhow::bail!("not a directory");
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        let meta = entry.metadata()?;
        let path = if rel.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", rel.trim_end_matches('/'), name)
        };
        if meta.is_dir() {
            out.push(TreeEntry {
                path,
                entry_type: "dir".into(),
                size: None,
                sha: None,
            });
        } else {
            let sha = blake3_hex(&std::fs::read(entry.path())?);
            out.push(TreeEntry {
                path,
                entry_type: "file".into(),
                size: Some(meta.len()),
                sha: Some(sha),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub fn read_blob(root: &Path, rel: &str) -> anyhow::Result<BlobView> {
    let path = root.join(rel.trim_start_matches('/'));
    if !path.is_file() {
        anyhow::bail!("not a file");
    }
    let bytes = std::fs::read(&path)?;
    let sha = blake3_hex(&bytes);
    let (encoding, content) = if looks_text(&bytes) {
        (
            "utf-8".into(),
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    } else {
        ("base64".into(), base64_encode(&bytes))
    };
    Ok(BlobView {
        path: rel.trim_start_matches('/').into(),
        sha,
        size: bytes.len() as u64,
        encoding,
        content,
    })
}

pub fn list_commits(root: &Path, limit: usize) -> anyhow::Result<Vec<CommitInfo>> {
    if !root.join(".git").exists() {
        return Ok(vec![CommitInfo {
            sha: "0".repeat(40),
            message: "No git history in mirror".into(),
            author: "safehub".into(),
            date: chrono::Utc::now().to_rfc3339(),
            parents: vec![],
        }]);
    }
    let out = Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap(),
            "log",
            &format!("-n{limit}"),
            "--pretty=format:%H%x09%an%x09%aI%x09%P%x09%s",
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("git log failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut commits = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 5 {
            continue;
        }
        let parents = if parts[3].is_empty() {
            vec![]
        } else {
            parts[3].split_whitespace().map(|s| s.to_string()).collect()
        };
        commits.push(CommitInfo {
            sha: parts[0].into(),
            author: parts[1].into(),
            date: parts[2].into(),
            parents,
            message: parts[4].into(),
        });
    }
    Ok(commits)
}

pub fn commit_detail(root: &Path, sha: &str) -> anyhow::Result<CommitInfo> {
    let commits = list_commits(root, 200)?;
    commits
        .into_iter()
        .find(|c| c.sha.starts_with(sha) || c.sha == sha)
        .ok_or_else(|| anyhow::anyhow!("commit not found"))
}

fn blake3_hex(data: &[u8]) -> String {
    let mut out = [0u8; 32];
    blake3::Hasher::new()
        .update(data)
        .finalize_xof()
        .fill(&mut out);
    hex::encode(out)
}

fn looks_text(bytes: &[u8]) -> bool {
    !bytes.iter().take(512).any(|&b| b == 0)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

/// Seed mirror from an external directory (eval fixture / demo).
pub async fn import_tree(data: &Path, owner: &str, name: &str, src: &Path) -> anyhow::Result<usize> {
    let dest = ensure_mirror(data, owner, name).await?;
    copy_tree(src, &dest)?;
    let _ = Command::new("git")
        .args(["-C", dest.to_str().unwrap(), "add", "-A"])
        .status();
    let _ = Command::new("git")
        .args([
            "-C",
            dest.to_str().unwrap(),
            "commit",
            "-qm",
            "Import browse mirror",
        ])
        .status();
    Ok(count_files(&dest)?)
}

fn copy_tree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    for entry in walk(src)? {
        let rel = entry.strip_prefix(src)?;
        let target = dst.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.is_file() {
            if let Some(p) = target.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::copy(&entry, &target)?;
        }
    }
    Ok(())
}

fn walk(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            let name = e.file_name();
            if name == ".git" {
                continue;
            }
            out.push(p.clone());
            if p.is_dir() {
                rec(&p, out)?;
            }
        }
        Ok(())
    }
    rec(root, &mut out)?;
    Ok(out)
}

fn count_files(root: &Path) -> anyhow::Result<usize> {
    Ok(walk(root)?.into_iter().filter(|p| p.is_file()).count())
}
