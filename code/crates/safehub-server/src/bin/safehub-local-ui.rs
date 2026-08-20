//! `safehub-local-ui` — **deprecated** GitHub-clone HTML UI.
//!
//! The member UI is [`safehub-browse`] (default `http://127.0.0.1:8081/`).
//! This binary remains for regression tests behind `--allow-deprecated`.
//!
//! Plaintext issue/PR HTML pages lived here; use `sh issue` / `sh pr` instead.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "safehub-local-ui",
    about = "DEPRECATED: use safehub-browse for the member UI"
)]
struct Args {
    /// Listen address (loopback recommended).
    #[arg(long, default_value = "127.0.0.1:8082", env = "SAFEHUB_LOCAL_UI_LISTEN")]
    listen: SocketAddr,

    /// Data directory (mirrors + collab metadata).
    #[arg(long, default_value = "./data-local", env = "SAFEHUB_LOCAL_UI_DATA")]
    data: PathBuf,

    /// Run the deprecated GitHub-clone UI (for ui_conformance tests only).
    #[arg(long, hide = true)]
    allow_deprecated: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    if !args.allow_deprecated {
        eprintln!(
            "safehub-local-ui is deprecated and no longer the member UI.\n\
             \n\
             Start the SafeHub browse UI instead:\n\
               cargo run -p safehub-browse -- --repo . --listen 127.0.0.1:8081\n\
               sh browse --repo . --listen 127.0.0.1:8081\n\
             \n\
             Open http://127.0.0.1:8081/ (Local | Remote fetch-and-show).\n\
             Issues and pull requests: use `sh issue` / `sh pr` (no HTML surface).\n\
             \n\
             To run this legacy UI for tests: safehub-local-ui --allow-deprecated …"
        );
        std::process::exit(2);
    }

    let state = safehub_server::AppState::open(&args.data).await?;
    let app = safehub_server::router_local_ui(state);

    tracing::warn!(
        %args.listen,
        data = %args.data.display(),
        "safehub-local-ui (DEPRECATED GitHub-clone UI — use safehub-browse on :8081)"
    );
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
