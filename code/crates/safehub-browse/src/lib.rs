//! SafeHub local git repository browser.
//!
//! Serves a GitHub-like HTML UI over a local working tree / `.git` directory.
//! Code/commits read via `git -C <repo>`; Issues/PRs fold the member-local MLS inbox.

mod collab;
mod git;
mod html;
mod remote;
mod routes;

pub use git::{normalize_repo_path, Repo};
pub use routes::{router, AppState};

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct BrowseOptions {
    pub repo: PathBuf,
    pub listen: SocketAddr,
}

impl Default for BrowseOptions {
    fn default() -> Self {
        Self {
            repo: PathBuf::from("."),
            listen: "127.0.0.1:8081".parse().expect("valid default addr"),
        }
    }
}

/// Open the repo and serve until the process is interrupted.
pub async fn run(opts: BrowseOptions) -> Result<()> {
    let repo = Repo::open(&opts.repo)
        .with_context(|| format!("open repo at {}", opts.repo.display()))?;
    let name = repo.name().to_string();
    let root = repo.root().display().to_string();
    let state = AppState::new(Arc::new(repo));
    state.remote.load_existing(&state.local).await;
    let app = router(state);

    // Bind localhost by default (opts.listen); refuse wildcard only if user asks.
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("bind {}", opts.listen))?;
    let addr = listener.local_addr().unwrap_or(opts.listen);
    eprintln!("SafeHub local browse");
    eprintln!("  repo   {root} ({name})");
    eprintln!("  listen http://{addr}/");
    eprintln!("  local  /tree /blob /commits /commit /branches /tags");
    eprintln!("  collab /issues /pulls /settings (MLS inbox · member-local)");
    eprintln!("  remote /remote (opt-in SafeHub fetch into isolated mirror)");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("shutting down");
}

/// Parse `listen` like `127.0.0.1:8081` or `:8081` (host defaults to 127.0.0.1).
pub fn parse_listen(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some(port) = s.strip_prefix(':') {
        let port: u16 = port.parse().context("invalid port")?;
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    anyhow::bail!("invalid listen address: {s} (expected host:port)")
}
