//! `safehub-browse` — local GitHub-like repository browser.

use clap::Parser;
use safehub_browse::{parse_listen, run, BrowseOptions};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "safehub-browse",
    about = "Browse a local git repository in a GitHub-like UI (localhost only by default)"
)]
struct Cli {
    /// Path to a git working tree or repository.
    #[arg(long, short = 'C', default_value = ".")]
    repo: PathBuf,

    /// Listen address (default 127.0.0.1:8081).
    #[arg(long, default_value = "127.0.0.1:8081")]
    listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let opts = BrowseOptions {
        repo: cli.repo,
        listen: parse_listen(&cli.listen)?,
    };
    run(opts).await
}
