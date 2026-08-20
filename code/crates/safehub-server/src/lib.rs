//! SafeHub server library (HTTP API + durable auth).
//!
//! The default [`router`] is the *untrusted host* surface (ciphertext only).
//! Plaintext browse/HTML UI is [`router_local_ui`], shipped as deprecated `safehub-local-ui`.
//! The member UI is `safehub-browse` (default `http://127.0.0.1:8081/`).

pub mod auth;
pub mod browse;
pub mod collab;
pub mod routes;
pub mod state;
pub mod ui;
pub mod users;

pub use routes::{router, router_host, router_local_ui};
pub use state::AppState;

/// Build an untrusted-host router for tests against a temp data directory.
pub async fn test_app(data: impl AsRef<std::path::Path>) -> anyhow::Result<axum::Router> {
    let state = AppState::open(data).await?;
    Ok(router(state))
}

/// Build a local plaintext-UI router (member machine) for browse tests.
pub async fn test_app_local_ui(data: impl AsRef<std::path::Path>) -> anyhow::Result<axum::Router> {
    let state = AppState::open(data).await?;
    Ok(router_local_ui(state))
}
