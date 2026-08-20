//! Local config / credential store (`~/.config/safehub`).

use crate::error::ClientError;
use directories::ProjectDirs;
use safehub_types::{AuthToken, UserId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Client configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// API base URL, e.g. `http://127.0.0.1:8080`.
    pub server_url: String,
    /// Optional default owner for `owner/name` shorthand.
    pub default_owner: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".into(),
            default_owner: None,
        }
    }
}

/// Saved login credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    /// Bearer token from the control plane.
    pub token: AuthToken,
}

impl ClientConfig {
    /// Config directory (`$XDG_CONFIG_HOME/safehub` or platform equivalent).
    pub fn config_dir() -> Result<PathBuf, ClientError> {
        let dirs = ProjectDirs::from("dev", "safehub", "safehub")
            .ok_or_else(|| ClientError::Config("cannot resolve config dir".into()))?;
        Ok(dirs.config_dir().to_path_buf())
    }

    /// Load config from disk, or defaults.
    pub fn load() -> Result<Self, ClientError> {
        let path = Self::config_dir()?.join("config.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(&path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Persist config.
    pub fn save(&self) -> Result<(), ClientError> {
        let dir = Self::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("config.json");
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

impl Credentials {
    fn path() -> Result<PathBuf, ClientError> {
        Ok(ClientConfig::config_dir()?.join("credentials.json"))
    }

    /// Load credentials if present.
    pub fn load() -> Result<Option<Self>, ClientError> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    /// Persist credentials (mode 0600 best-effort).
    pub fn save(&self) -> Result<(), ClientError> {
        let dir = ClientConfig::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = Self::path()?;
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Current user, if logged in.
    pub fn user(&self) -> &UserId {
        &self.token.user
    }
}
