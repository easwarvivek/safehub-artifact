//! SafeHub server binary — three logical services over one HTTP front door:
//! content-addressed blobs, CAS head log, MLS delivery (+ soft repo directory).

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "safehub-server", about = "Private encrypted git hosting server")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8080", env = "SAFEHUB_LISTEN")]
    listen: SocketAddr,

    /// Data directory for the local filesystem backend.
    #[arg(long, default_value = "./data", env = "SAFEHUB_DATA")]
    data: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let state = safehub_server::AppState::open(&args.data).await?;
    let app = safehub_server::router(state);

    tracing::info!(%args.listen, data = %args.data.display(), "safehub-server listening (ciphertext host; member UI is safehub-browse on :8081)");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
