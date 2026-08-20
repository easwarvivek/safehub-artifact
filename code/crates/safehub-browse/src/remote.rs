//! Opt-in SafeHub fetch into an isolated bare mirror.
//!
//! The local working tree and its refs are never changed. Decrypted bundle
//! objects and refs live under `.git/safehub/browse-mirror.git`.

use crate::Repo;
use anyhow::{bail, Context, Result};
use safehub_client::{fetch_tip, load_epoch_material, Credentials, HttpClient};
use safehub_types::RepoRecord;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct RemoteMirror {
    inner: Arc<RwLock<RemoteState>>,
}

#[derive(Default)]
struct RemoteState {
    repo: Option<Arc<Repo>>,
    last_error: Option<String>,
    last_summary: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RemoteStatus {
    pub ready: bool,
    pub error: Option<String>,
    pub summary: Option<String>,
}

impl RemoteMirror {
    pub async fn repo(&self) -> Option<Arc<Repo>> {
        self.inner.read().await.repo.clone()
    }

    pub async fn status(&self) -> RemoteStatus {
        let state = self.inner.read().await;
        RemoteStatus {
            ready: state.repo.is_some(),
            error: state.last_error.clone(),
            summary: state.last_summary.clone(),
        }
    }

    /// Fetch and decrypt the SafeHub tip into the isolated bare mirror.
    pub async fn fetch(&self, local: &Repo) -> Result<Arc<Repo>> {
        match fetch_remote(local).await {
            Ok((repo, summary)) => {
                let repo = Arc::new(repo);
                let mut state = self.inner.write().await;
                state.repo = Some(repo.clone());
                state.last_error = None;
                state.last_summary = Some(summary);
                Ok(repo)
            }
            Err(error) => {
                let formal = format!("{error:#}");
                let mut state = self.inner.write().await;
                // Preserve the last successfully fetched mirror, but report the
                // failed refresh explicitly.
                state.last_error = Some(formal.clone());
                bail!(formal)
            }
        }
    }

    /// Load an existing mirror at browser startup without network access.
    pub async fn load_existing(&self, local: &Repo) {
        let path = mirror_path(local);
        if let Ok(repo) = Repo::open(&path) {
            let mut state = self.inner.write().await;
            state.repo = Some(Arc::new(repo));
            state.last_summary = Some("Previously fetched SafeHub mirror".into());
        }
    }
}

async fn fetch_remote(local: &Repo) -> Result<(Repo, String)> {
    let record_path = local.git_dir().join("safehub").join("repo.json");
    if !record_path.is_file() {
        bail!(
            "This is not a SafeHub checkout. Missing {}. Local view remains unchanged.",
            record_path.display()
        );
    }
    let record: RepoRecord = serde_json::from_slice(
        &std::fs::read(&record_path)
            .with_context(|| format!("read {}", record_path.display()))?,
    )
    .context("parse SafeHub repository metadata")?;

    if Credentials::load()?.is_none() {
        bail!("Not logged in. Run `sh auth login`, then fetch again. Local view remains active.");
    }
    let client = HttpClient::from_disk().context("load SafeHub client configuration")?;
    let material = load_epoch_material(&record.id)
        .context("No usable MLS keys for this repository; join or restore the device first")?;
    let fetched = fetch_tip(&client, &record.id, &material)
        .await
        .context("SafeHub fetch/decrypt failed")?
        .ok_or_else(|| anyhow::anyhow!("SafeHub remote has no published tip"))?;

    let mirror = mirror_path(local);
    if !mirror.join("HEAD").exists() {
        if let Some(parent) = mirror.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let output = Command::new("git")
            .args(["init", "--bare", "-q"])
            .arg(&mirror)
            .output()
            .context("spawn git init --bare")?;
        if !output.status.success() {
            bail!(
                "git init --bare failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }

    let bundle = mirror.join(format!("safehub-fetch-{}.bundle", fetched.head.seq));
    std::fs::write(&bundle, &fetched.bundle)
        .with_context(|| format!("write temporary bundle {}", bundle.display()))?;

    let import_result = run_git_at(
        &mirror,
        &["fetch", "--force", bundle.to_string_lossy().as_ref()],
    );
    let _ = std::fs::remove_file(&bundle);
    import_result.context("import decrypted bundle into isolated mirror")?;

    let mut updated = 0usize;
    for (refname, oid) in &fetched.refs.refs {
        if !allowed_ref(refname) {
            continue;
        }
        run_git_at(&mirror, &["update-ref", refname, oid])
            .with_context(|| format!("update mirror ref {refname}"))?;
        updated += 1;
    }
    if let Some(head) = fetched.refs.head.as_deref() {
        if let Some(target) = head.strip_prefix("ref: ") {
            if allowed_ref(target) {
                run_git_at(&mirror, &["symbolic-ref", "HEAD", target])?;
            }
        }
    }

    let repo = Repo::open(&mirror).context("open fetched SafeHub mirror")?;
    Ok((
        repo,
        format!(
            "Fetched SafeHub tip seq {} · epoch {} · {} refs",
            fetched.head.seq, fetched.head.mls_epoch, updated
        ),
    ))
}

fn mirror_path(local: &Repo) -> PathBuf {
    local
        .git_dir()
        .join("safehub")
        .join("browse-mirror.git")
}

fn allowed_ref(name: &str) -> bool {
    (name.starts_with("refs/heads/")
        || name.starts_with("refs/tags/")
        || name.starts_with("refs/remotes/"))
        && !name.contains("..")
        && !name.contains('\\')
        && !name.chars().any(char::is_whitespace)
}

fn run_git_at(repo: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("spawn git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
