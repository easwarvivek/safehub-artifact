//! Compatibility shim: git discovers `git-remote-safehub` for `safehub://` URLs.
//! Same entrypoint as `sit-remote-safehub`.

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
