//! Local git helpers via `git -C <repo> …`.
//!
//! All tree/blob content is read from git objects (not the working tree), so
//! browsing a ref is independent of checkout dirty state. Path arguments are
//! validated to reject `..` and absolute escapes.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct Repo {
    root: PathBuf,
    git_dir: PathBuf,
    name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    pub path: String,
    pub entry_type: String, // "tree" | "blob"
    pub mode: String,
    pub sha: String,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobView {
    pub path: String,
    pub sha: String,
    pub size: u64,
    pub binary: bool,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitInfo {
    pub sha: String,
    pub short: String,
    pub message: String,
    pub subject: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub parents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchInfo {
    pub name: String,
    pub current: bool,
    pub remote: bool,
    pub sha: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagInfo {
    pub name: String,
    pub sha: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitDiff {
    pub commit: CommitInfo,
    pub stat: String,
    pub patch: String,
    pub files: Vec<DiffFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffFile {
    pub path: String,
    pub status: String,
}

impl Repo {
    /// Resolve a path to a git work tree (or bare repo) and validate it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let abs = abs
            .canonicalize()
            .with_context(|| format!("cannot resolve repo path {}", abs.display()))?;

        let worktree = git_raw(&abs, &["rev-parse", "--is-inside-work-tree"])
            .map(|out| out.trim() == "true")
            .unwrap_or(false);
        let bare = git_raw(&abs, &["rev-parse", "--is-bare-repository"])
            .map(|out| out.trim() == "true")
            .unwrap_or(false);
        let ok = worktree || bare;
        if !ok {
            bail!("{} is not a git repository", abs.display());
        }

        // Prefer work-tree root when available.
        let root = match git_raw(&abs, &["rev-parse", "--show-toplevel"]) {
            Ok(top) => {
                let t = top.trim();
                if t.is_empty() {
                    abs.clone()
                } else {
                    PathBuf::from(t)
                }
            }
            Err(_) => abs.clone(),
        };
        let root = root.canonicalize().unwrap_or(root);
        let git_dir = git_raw(&abs, &["rev-parse", "--absolute-git-dir"])
            .map(|s| PathBuf::from(s.trim()))
            .unwrap_or_else(|_| root.join(".git"));
        let name = root
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "repository".into());
        Ok(Self {
            root,
            git_dir,
            name,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn default_ref(&self) -> Result<String> {
        if let Ok(s) = git_raw(&self.root, &["symbolic-ref", "--short", "HEAD"]) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
        if let Ok(s) = git_raw(&self.root, &["rev-parse", "--abbrev-ref", "HEAD"]) {
            let s = s.trim().to_string();
            if !s.is_empty() && s != "HEAD" {
                return Ok(s);
            }
        }
        // Detached HEAD — use short SHA.
        let sha = git_raw(&self.root, &["rev-parse", "--short", "HEAD"])?;
        Ok(sha.trim().to_string())
    }

    pub fn resolve_ref(&self, rev: &str) -> Result<String> {
        let rev = rev.trim();
        if rev.is_empty() {
            bail!("empty revision");
        }
        validate_rev(rev)?;
        let out = git_raw(&self.root, &["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
        Ok(out.trim().to_string())
    }

    pub fn list_tree(&self, rev: &str, path: &str) -> Result<Vec<TreeEntry>> {
        validate_rev(rev)?;
        let path = normalize_repo_path(path)?;
        let spec = if path.is_empty() {
            format!("{rev}^{{tree}}")
        } else {
            format!("{rev}:{path}")
        };
        let out = git_raw(
            &self.root,
            &["ls-tree", "-z", "-l", "--full-name", &spec],
        )?;
        let mut entries = Vec::new();
        for rec in out.split('\0') {
            if rec.is_empty() {
                continue;
            }
            // format: <mode> SP <type> SP <object> SP <size> TAB <file>
            let Some((meta, name)) = rec.split_once('\t') else {
                continue;
            };
            let parts: Vec<&str> = meta.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let mode = parts[0].to_string();
            let entry_type = parts[1].to_string();
            let sha = parts[2].to_string();
            let size = if parts[3] == "-" {
                None
            } else {
                parts[3].parse().ok()
            };
            let full_path = if path.is_empty() {
                name.to_string()
            } else {
                format!("{path}/{name}")
            };
            entries.push(TreeEntry {
                name: name.to_string(),
                path: full_path,
                entry_type,
                mode,
                sha,
                size,
            });
        }
        entries.sort_by(|a, b| {
            let ad = a.entry_type == "tree";
            let bd = b.entry_type == "tree";
            match bd.cmp(&ad) {
                std::cmp::Ordering::Equal => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                o => o,
            }
        });
        Ok(entries)
    }

    pub fn read_blob(&self, rev: &str, path: &str) -> Result<BlobView> {
        validate_rev(rev)?;
        let path = normalize_repo_path(path)?;
        if path.is_empty() {
            bail!("empty blob path");
        }
        let spec = format!("{rev}:{path}");
        let meta = git_raw(&self.root, &["cat-file", "-s", &spec])?;
        let size: u64 = meta.trim().parse().unwrap_or(0);
        let bytes = git_bytes(&self.root, &["show", &spec])?;
        let binary = !looks_text(&bytes);
        let content = if binary {
            format!("Binary file ({size} bytes)")
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let sha = git_raw(&self.root, &["rev-parse", &spec])
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        Ok(BlobView {
            path,
            sha,
            size,
            binary,
            content,
        })
    }

    pub fn list_commits(&self, rev: &str, limit: usize) -> Result<Vec<CommitInfo>> {
        validate_rev(rev)?;
        let lim = format!("-n{limit}");
        let out = git_raw(
            &self.root,
            &[
                "log",
                &lim,
                "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%P%x1f%s%x1f%b%x1e",
                rev,
            ],
        )?;
        Ok(parse_commits(&out))
    }

    pub fn commit_detail(&self, sha: &str) -> Result<CommitDiff> {
        validate_rev(sha)?;
        let full = self.resolve_ref(sha)?;
        let list = self.list_commits(&full, 1)?;
        let commit = list
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("commit not found"))?;
        let stat = git_raw(
            &self.root,
            &["show", "--stat", "--format=", "--no-color", &full],
        )
        .unwrap_or_default();
        let patch = git_raw(
            &self.root,
            &[
                "show",
                "--format=",
                "--no-color",
                "--find-renames",
                &full,
            ],
        )
        .unwrap_or_default();
        let name_status = git_raw(
            &self.root,
            &["show", "--name-status", "--format=", "--no-color", &full],
        )
        .unwrap_or_default();
        let mut files = Vec::new();
        for line in name_status.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            let status = parts.next().unwrap_or("M").to_string();
            let path = parts.next().unwrap_or("").to_string();
            if !path.is_empty() {
                files.push(DiffFile { path, status });
            }
        }
        Ok(CommitDiff {
            commit,
            stat: stat.trim().to_string(),
            patch,
            files,
        })
    }

    pub fn list_branches(&self) -> Result<Vec<BranchInfo>> {
        let out = git_raw(
            &self.root,
            &[
                "for-each-ref",
                "--format=%(refname:short)%00%(objectname)%00%(HEAD)%00%(refname)",
                "refs/heads",
                "refs/remotes",
            ],
        )?;
        let mut branches = Vec::new();
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\0').collect();
            if parts.len() < 4 {
                continue;
            }
            let name = parts[0].to_string();
            if name.ends_with("/HEAD") {
                continue;
            }
            let sha = parts[1].to_string();
            let current = parts[2] == "*";
            let remote = parts[3].starts_with("refs/remotes/");
            branches.push(BranchInfo {
                name,
                current,
                remote,
                sha,
            });
        }
        branches.sort_by(|a, b| {
            match (a.remote, b.remote) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            }
        });
        Ok(branches)
    }

    pub fn list_tags(&self) -> Result<Vec<TagInfo>> {
        let out = git_raw(
            &self.root,
            &[
                "for-each-ref",
                "--sort=-creatordate",
                "--format=%(refname:short)%00%(objectname)",
                "refs/tags",
            ],
        )?;
        let mut tags = Vec::new();
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\0').collect();
            if parts.len() < 2 || parts[0].is_empty() {
                continue;
            }
            tags.push(TagInfo {
                name: parts[0].to_string(),
                sha: parts[1].to_string(),
            });
        }
        Ok(tags)
    }

    /// Latest commit touching a path (for tree header), optional.
    pub fn last_commit_for_path(&self, rev: &str, path: &str) -> Result<Option<CommitInfo>> {
        validate_rev(rev)?;
        let path = normalize_repo_path(path)?;
        let mut args = vec![
            "log",
            "-n1",
            "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%P%x1f%s%x1f%b%x1e",
            rev,
        ];
        let owned_path;
        if !path.is_empty() {
            args.push("--");
            owned_path = path;
            args.push(&owned_path);
        }
        let out = git_raw(&self.root, &args)?;
        Ok(parse_commits(&out).into_iter().next())
    }

    pub fn path_is_tree(&self, rev: &str, path: &str) -> Result<bool> {
        validate_rev(rev)?;
        let path = normalize_repo_path(path)?;
        if path.is_empty() {
            return Ok(true);
        }
        let spec = format!("{rev}:{path}");
        let t = git_raw(&self.root, &["cat-file", "-t", &spec])?;
        Ok(t.trim() == "tree")
    }
}

fn parse_commits(out: &str) -> Vec<CommitInfo> {
    let mut commits = Vec::new();
    for rec in out.split('\x1e') {
        let rec = rec.trim_matches('\n').trim_matches('\r');
        if rec.is_empty() {
            continue;
        }
        let parts: Vec<&str> = rec.split('\x1f').collect();
        if parts.len() < 7 {
            continue;
        }
        let parents = if parts[5].is_empty() {
            vec![]
        } else {
            parts[5]
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        let subject = parts[6].to_string();
        let body = parts.get(7).copied().unwrap_or("").trim();
        let message = if body.is_empty() {
            subject.clone()
        } else {
            format!("{subject}\n\n{body}")
        };
        commits.push(CommitInfo {
            sha: parts[0].into(),
            short: parts[1].into(),
            author: parts[2].into(),
            email: parts[3].into(),
            date: parts[4].into(),
            parents,
            subject,
            message,
        });
    }
    commits
}

fn git_raw(root: &Path, args: &[&str]) -> Result<String> {
    let root_s = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-utf8 repo path"))?;
    let out = Command::new("git")
        .arg("-C")
        .arg(root_s)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn git {}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("git {} failed: {}", args.join(" "), err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let root_s = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-utf8 repo path"))?;
    let out = Command::new("git")
        .arg("-C")
        .arg(root_s)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn git {}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("git {} failed: {}", args.join(" "), err.trim());
    }
    Ok(out.stdout)
}

/// Reject path traversal and absolute paths. Returns cleaned relative path
/// without leading `./` or trailing `/`.
pub fn normalize_repo_path(path: &str) -> Result<String> {
    let path = path.trim().trim_start_matches('/');
    if path.is_empty() {
        return Ok(String::new());
    }
    if path.starts_with('/') || Path::new(path).is_absolute() {
        bail!("absolute paths are not allowed");
    }
    let mut out = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            bail!("path escape (..) is not allowed");
        }
        if part.contains('\0') {
            bail!("invalid path component");
        }
        out.push(part);
    }
    Ok(out.join("/"))
}

fn validate_rev(rev: &str) -> Result<()> {
    if rev.is_empty() {
        bail!("empty revision");
    }
    // Disallow shell metacharacters / path tricks in rev arguments.
    if rev.chars().any(|c| {
        matches!(
            c,
            '\0' | '\n' | '\r' | ' ' | '\t' | ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>'
        )
    }) {
        bail!("invalid revision characters");
    }
    if rev.contains("..") && !rev.contains("...") {
        // Allow `A...B` range? We don't use ranges; reject `..` in revs.
        if rev.contains("..") {
            // HEAD~2 style is fine; only block path-like `../`
            if rev.contains('/') && rev.contains("..") {
                bail!("invalid revision");
            }
        }
    }
    Ok(())
}

fn looks_text(bytes: &[u8]) -> bool {
    !bytes.iter().take(8000).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_dotdot() {
        assert!(normalize_repo_path("../etc/passwd").is_err());
        assert!(normalize_repo_path("foo/../../bar").is_err());
        assert_eq!(normalize_repo_path("src/main.rs").unwrap(), "src/main.rs");
        assert_eq!(normalize_repo_path("/a/b").unwrap(), "a/b");
    }
}
