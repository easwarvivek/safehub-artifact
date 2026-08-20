//! Sit remote helper binary: `sit-remote-safehub`.
//!
//! Primary branded binary for the encrypted remote helper. Companion
//! `git-remote-sit` / `git-remote-safehub` shims exist only so the underlying
//! git binary can auto-discover helpers for `sit://` / `safehub://` URLs —
//! users should run `sit push` / `sit fetch` / `sit clone`, not invoke git
//! remotes directly. Prefer `sh` for hosting UX (auth, repo, PR, issue).

use std::io;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(io::stderr)
        .init();

    sit_remote_safehub::cli_main().await
}
