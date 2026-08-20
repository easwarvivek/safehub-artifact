//! Application state shared across handlers.

use crate::users::AuthStore;
use safehub_storage::LocalStore;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared server state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<LocalStore>,
    pub auth: Arc<RwLock<AuthStore>>,
    /// Root data directory (for browse cache, UI, etc.).
    pub data_root: std::path::PathBuf,
}

impl AppState {
    pub async fn open(data: impl AsRef<Path>) -> anyhow::Result<Self> {
        let data_root = data.as_ref().to_path_buf();
        let store = LocalStore::open(&data_root).await?;
        let auth = AuthStore::open(&data_root).await?;
        Ok(Self {
            store: Arc::new(store),
            auth: Arc::new(RwLock::new(auth)),
            data_root,
        })
    }
}
