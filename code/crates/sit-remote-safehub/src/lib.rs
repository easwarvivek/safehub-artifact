//! Sit remote helper library for `sit://` (and legacy `safehub://`) URLs.
//!
//! Speaks the git remote-helper line protocol:
//! <https://git-scm.com/docs/gitremote-helpers>

use anyhow::{anyhow, bail, Context, Result};
use safehub_client::{fetch_tip, load_epoch_material, push_bundle, HttpClient};
use safehub_types::{RepoName, RepoRecord};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

/// Parse `sit://owner/name`, `safehub://owner/name`, or `sit::` / `safehub::`
/// forms into `owner/name`.
pub fn parse_url(url: &str) -> Result<String> {
    let u = url
        .strip_prefix("sit://")
        .or_else(|| url.strip_prefix("sit::"))
        .or_else(|| url.strip_prefix("safehub://"))
        .or_else(|| url.strip_prefix("safehub::"))
        .unwrap_or(url);
    // Allow optional host form: sit://host/owner/name → take last two segments.
    let path = if let Some(rest) = u.strip_prefix("http://").or_else(|| u.strip_prefix("https://")) {
        rest
    } else {
        u
    };
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let (owner, name) = match parts.as_slice() {
        [o, n] => (*o, *n),
        [_, o, n] => (*o, *n), // host/owner/name
        _ => bail!("invalid sit url: {url}"),
    };
    let joined = format!("{owner}/{name}");
    if RepoName::parse(&joined).is_none() {
        bail!("invalid sit url: {url}");
    }
    Ok(joined)
}

/// Shared CLI entry for `sit-remote-safehub` and the `git-remote-*` discovery shims.
pub async fn cli_main() -> Result<()> {
    // git / sit invoke: <helper> <remote-name> <url>
    let mut args = std::env::args().skip(1);
    let _remote_name = args.next().unwrap_or_default();
    let url = args.next().unwrap_or_default();
    let repo_path = parse_url(&url)?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_helper(&repo_path, stdin.lock(), stdout.lock()).await
}

/// Resolve local checkout metadata and/or server record.
pub async fn resolve_repo(repo_path: &str) -> Result<RepoRecord> {
    if let Some(record) = load_meta_repo()? {
        return Ok(record);
    }
    let name = RepoName::parse(repo_path).ok_or_else(|| anyhow!("bad repo path"))?;
    let client = HttpClient::from_disk()?;
    let record = client.get_repo(&name).await?;
    // Persist for subsequent helper invocations in this clone.
    if let Ok(dir) = git_dir() {
        let meta = dir.join("safehub");
        std::fs::create_dir_all(&meta)?;
        std::fs::write(meta.join("repo.json"), serde_json::to_vec_pretty(&record)?)?;
    }
    Ok(record)
}

fn load_meta_repo() -> Result<Option<RepoRecord>> {
    let meta = git_dir()?.join("safehub").join("repo.json");
    if !meta.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&std::fs::read(meta)?)?))
}

/// Locate `.git` for the repository git invoked us in.
pub fn git_dir() -> Result<PathBuf> {
    if let Ok(d) = std::env::var("GIT_DIR") {
        return Ok(PathBuf::from(d));
    }
    let out = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Ok(PathBuf::from(p));
        }
    }
    Ok(PathBuf::from(".git"))
}

fn work_tree() -> PathBuf {
    if let Ok(d) = std::env::var("GIT_WORK_TREE") {
        return PathBuf::from(d);
    }
    // Parent of .git when possible.
    git_dir()
        .ok()
        .and_then(|g| g.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Run the git remote-helper line protocol on `stdin`/`stdout`.
pub async fn run_helper(repo_path: &str, stdin: impl BufRead, mut stdout: impl Write) -> Result<()> {
    let mut pending_fetch: Vec<(String, String)> = Vec::new();
    let mut pending_push: Vec<String> = Vec::new();

    for line in stdin.lines() {
        let line = line?;
        if line.is_empty() {
            if !pending_fetch.is_empty() {
                do_fetch(repo_path, &pending_fetch).await?;
                pending_fetch.clear();
                writeln!(stdout)?;
                stdout.flush()?;
            }
            if !pending_push.is_empty() {
                for spec in pending_push.drain(..) {
                    match do_push(repo_path, &spec).await {
                        Ok(dst) => writeln!(stdout, "ok {dst}")?,
                        Err(e) => {
                            let dst = spec.split(':').nth(1).unwrap_or(&spec);
                            writeln!(stdout, "error {dst} {e:#}")?;
                        }
                    }
                }
                writeln!(stdout)?;
                stdout.flush()?;
            }
            continue;
        }

        if line == "capabilities" {
            writeln!(stdout, "fetch")?;
            writeln!(stdout, "push")?;
            writeln!(stdout, "option")?;
            writeln!(stdout)?;
            stdout.flush()?;
        } else if line.starts_with("option ") {
            // Accept progress / verbosity / etc.
            writeln!(stdout, "ok")?;
            stdout.flush()?;
        } else if line == "list" || line == "list for-push" {
            list_refs(repo_path, &mut stdout).await?;
            writeln!(stdout)?;
            stdout.flush()?;
        } else if let Some(rest) = line.strip_prefix("fetch ") {
            // fetch <sha> <name>
            let mut parts = rest.splitn(2, ' ');
            let sha = parts.next().unwrap_or("").to_string();
            let name = parts.next().unwrap_or("").to_string();
            pending_fetch.push((sha, name));
        } else if let Some(rest) = line.strip_prefix("push ") {
            pending_push.push(rest.to_string());
        } else {
            tracing::debug!(%line, "ignored remote-helper command");
        }
    }
    Ok(())
}

async fn list_refs(repo_path: &str, stdout: &mut impl Write) -> Result<()> {
    let record = match resolve_repo(repo_path).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "list: cannot resolve repo; advertising empty");
            return Ok(());
        }
    };
    let client = match HttpClient::from_disk() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "list: not logged in; advertising empty");
            return Ok(());
        }
    };
    let material = match load_epoch_material(&record.id) {
        Ok(m) => m,
        Err(_) => {
            // Without epoch keys we cannot decrypt tips; advertise empty remote
            // so a first push can create genesis.
            return Ok(());
        }
    };
    let fetched = match fetch_tip(&client, &record.id, &material).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "list: fetch_tip failed; advertising empty");
            return Ok(());
        }
    };
    let Some(fetched) = fetched else {
        return Ok(());
    };
    for (name, oid) in fetched.refs.refs.iter() {
        writeln!(stdout, "{oid} {name}")?;
    }
    if let Some(sym) = &fetched.refs.head {
        if let Some(target) = sym.strip_prefix("ref: ") {
            writeln!(stdout, "@{target} HEAD")?;
        }
    } else if let Some((name, _)) = fetched.refs.refs.iter().next() {
        writeln!(stdout, "@{name} HEAD")?;
    }
    Ok(())
}

async fn do_fetch(repo_path: &str, _wanted: &[(String, String)]) -> Result<()> {
    let record = resolve_repo(repo_path).await?;
    let client = HttpClient::from_disk()?;
    let material = load_epoch_material(&record.id)?;
    let Some(fetched) = fetch_tip(&client, &record.id, &material).await? else {
        return Ok(());
    };
    let gd = git_dir()?;
    let bundle_path = std::env::temp_dir().join(format!(
        "safehub-rh-fetch-{}.bundle",
        fetched.head.seq
    ));
    std::fs::write(&bundle_path, &fetched.bundle)?;

    // Import objects into this repository.
    let status = Command::new("git")
        .args([
            "--git-dir",
            gd.to_str().unwrap(),
            "fetch",
            bundle_path.to_str().unwrap(),
        ])
        .status()
        .context("git fetch bundle")?;
    let _ = std::fs::remove_file(&bundle_path);
    if !status.success() {
        // Placeholder / empty-history bundles are non-fatal for listing-only clones.
        tracing::warn!("bundle import failed; objects may be incomplete");
    }
    Ok(())
}

async fn do_push(repo_path: &str, spec: &str) -> Result<String> {
    // Spec forms: src:dst, +src:dst, or :dst (delete).
    let force = spec.starts_with('+');
    let spec = spec.trim_start_matches('+');
    let (src, dst) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("bad push refspec: {spec}"))?;
    let dst = dst.to_string();
    let record = resolve_repo(repo_path).await?;
    let client = HttpClient::from_disk()?;
    let material = load_epoch_material(&record.id)?;

    // Merge with existing remote refs when possible.
    let mut git_refs = BTreeMap::new();
    let mut head_symref = None;
    if let Ok(Some(prev)) = fetch_tip(&client, &record.id, &material).await {
        git_refs = prev.refs.refs;
        head_symref = prev.refs.head;
    }

    let dst_ref = if dst.starts_with("refs/") {
        dst.clone()
    } else {
        format!("refs/heads/{dst}")
    };

    if src.is_empty() {
        // Ref delete: remove from encrypted refs map and push with non_ff.
        if git_refs.remove(&dst_ref).is_none() {
            bail!("remote ref {dst_ref} not present");
        }
        let bundle = b"safehub-ref-delete".to_vec();
        let _result = push_bundle(
            &client,
            &record.id,
            &bundle,
            git_refs,
            head_symref,
            &material,
            true,
        )
        .await?;
        return Ok(dst);
    }

    let oid = rev_parse(src)?;
    let bundle = create_bundle(src)?;
    git_refs.insert(dst_ref.clone(), oid);
    let head_symref = Some(format!("ref: {dst_ref}"));

    let _result = push_bundle(
        &client,
        &record.id,
        &bundle,
        git_refs,
        head_symref,
        &material,
        force,
    )
    .await?;
    Ok(dst)
}

fn rev_parse(rev: &str) -> Result<String> {
    let gd = git_dir()?;
    let out = Command::new("git")
        .args(["--git-dir", gd.to_str().unwrap(), "rev-parse", rev])
        .output()
        .context("git rev-parse")?;
    if !out.status.success() {
        bail!(
            "rev-parse {rev}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn create_bundle(src: &str) -> Result<Vec<u8>> {
    let gd = git_dir()?;
    let wt = work_tree();
    let path = std::env::temp_dir().join(format!(
        "safehub-rh-push-{}.bundle",
        std::process::id()
    ));
    let status = Command::new("git")
        .current_dir(&wt)
        .args(["--git-dir", gd.to_str().unwrap()])
        .args(["bundle", "create"])
        .arg(&path)
        .arg(src)
        .status()
        .context("git bundle create")?;
    if !status.success() {
        bail!("git bundle create failed for {src}");
    }
    let bytes = std::fs::read(&path)?;
    let _ = std::fs::remove_file(&path);
    Ok(bytes)
}

/// Format refs listing lines for tests (no I/O).
pub fn format_list_lines(refs: &BTreeMap<String, String>, head: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    for (name, oid) in refs {
        lines.push(format!("{oid} {name}"));
    }
    if let Some(sym) = head {
        if let Some(target) = sym.strip_prefix("ref: ") {
            lines.push(format!("@{target} HEAD"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_url() {
        assert_eq!(parse_url("sit://alice/widgets").unwrap(), "alice/widgets");
        assert_eq!(parse_url("sit::alice/widgets").unwrap(), "alice/widgets");
        assert_eq!(parse_url("safehub://alice/widgets").unwrap(), "alice/widgets");
        assert_eq!(parse_url("safehub::alice/widgets").unwrap(), "alice/widgets");
    }

    #[test]
    fn parse_host_form() {
        assert_eq!(
            parse_url("sit://127.0.0.1/alice/widgets").unwrap(),
            "alice/widgets"
        );
        assert_eq!(
            parse_url("safehub://127.0.0.1/alice/widgets").unwrap(),
            "alice/widgets"
        );
    }

    #[test]
    fn parse_rejects_bad() {
        assert!(parse_url("sit://nonsuch").is_err());
        assert!(parse_url("safehub://nonsuch").is_err());
    }

    #[test]
    fn list_line_format() {
        let mut refs = BTreeMap::new();
        refs.insert("refs/heads/main".into(), "abc123".into());
        let lines = format_list_lines(&refs, Some("ref: refs/heads/main"));
        assert_eq!(lines[0], "abc123 refs/heads/main");
        assert_eq!(lines[1], "@refs/heads/main HEAD");
    }
}
