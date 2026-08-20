//! `shub` — GitHub-analogue CLI for SafeHub (`gh` feel).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    safehub_cli::cli_main().await
}
