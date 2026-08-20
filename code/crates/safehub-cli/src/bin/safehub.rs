//! `safehub` — identical to `sh` (GitHub-analogue CLI for SafeHub).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    safehub_cli::cli_main().await
}
