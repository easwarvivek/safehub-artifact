//! Durable user accounts (argon2id) and personal access tokens.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Scopes supported for PATs (GitHub-like subset).
pub const SCOPE_REPO: &str = "repo";
pub const SCOPE_READ_USER: &str = "read:user";

/// Persisted user record (password never stored in plaintext).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    /// argon2id PHC string.
    pub password_hash: String,
    pub created_at: String,
}

/// Persisted personal access token / session token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    /// Opaque bearer (`ph_…` or `shpat_…`).
    pub token: String,
    pub user: String,
    /// Human note / name.
    pub note: String,
    pub scopes: Vec<String>,
    /// `session` | `pat`
    pub kind: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AuthDb {
    users: HashMap<String, UserRecord>,
    /// token → record
    tokens: HashMap<String, TokenRecord>,
}

/// On-disk auth store under `{data}/auth/auth.json`.
pub struct AuthStore {
    path: PathBuf,
    db: AuthDb,
}

impl AuthStore {
    pub async fn open(data_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = data_root.as_ref().join("auth");
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join("auth.json");
        let db = if path.exists() {
            let bytes = tokio::fs::read(&path).await?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            AuthDb::default()
        };
        Ok(Self { path, db })
    }

    async fn persist(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.db)?;
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn get_user(&self, username: &str) -> Option<&UserRecord> {
        self.db.users.get(username)
    }

    pub async fn register(&mut self, username: &str, password: &str) -> Result<UserRecord, AuthError> {
        if username.is_empty() || password.is_empty() {
            return Err(AuthError::BadRequest("user and password required".into()));
        }
        if self.db.users.contains_key(username) {
            return Err(AuthError::Conflict("user already exists".into()));
        }
        let hash = hash_password(password)?;
        let rec = UserRecord {
            username: username.to_string(),
            password_hash: hash,
            created_at: now_rfc3339(),
        };
        self.db.users.insert(username.to_string(), rec.clone());
        self.persist().await.map_err(|e| AuthError::Io(e.to_string()))?;
        Ok(rec)
    }

    pub fn verify_password(&self, username: &str, password: &str) -> Result<(), AuthError> {
        let Some(user) = self.db.users.get(username) else {
            return Err(AuthError::Unauthorized);
        };
        let parsed = PasswordHash::new(&user.password_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthError::Unauthorized)
    }

    pub async fn issue_session(&mut self, username: &str) -> Result<TokenRecord, AuthError> {
        let token = format!("ph_{}", Uuid::new_v4());
        let rec = TokenRecord {
            token: token.clone(),
            user: username.to_string(),
            note: "session".into(),
            scopes: vec![SCOPE_REPO.into(), SCOPE_READ_USER.into()],
            kind: "session".into(),
            created_at: now_rfc3339(),
        };
        self.db.tokens.insert(token, rec.clone());
        self.persist().await.map_err(|e| AuthError::Io(e.to_string()))?;
        Ok(rec)
    }

    pub async fn create_pat(
        &mut self,
        username: &str,
        note: &str,
        scopes: Vec<String>,
    ) -> Result<TokenRecord, AuthError> {
        for s in &scopes {
            if s != SCOPE_REPO && s != SCOPE_READ_USER {
                return Err(AuthError::BadRequest(format!("unknown scope: {s}")));
            }
        }
        let scopes = if scopes.is_empty() {
            vec![SCOPE_REPO.into(), SCOPE_READ_USER.into()]
        } else {
            scopes
        };
        let token = format!("shpat_{}", Uuid::new_v4());
        let rec = TokenRecord {
            token: token.clone(),
            user: username.to_string(),
            note: note.to_string(),
            scopes,
            kind: "pat".into(),
            created_at: now_rfc3339(),
        };
        self.db.tokens.insert(token, rec.clone());
        self.persist().await.map_err(|e| AuthError::Io(e.to_string()))?;
        Ok(rec)
    }

    pub fn lookup_token(&self, token: &str) -> Option<&TokenRecord> {
        self.db.tokens.get(token)
    }

    pub fn list_pats(&self, username: &str) -> Vec<TokenRecordPublic> {
        self.db
            .tokens
            .values()
            .filter(|t| t.user == username && t.kind == "pat")
            .map(TokenRecordPublic::from_record)
            .collect()
    }

    pub async fn revoke_token(&mut self, username: &str, token: &str) -> Result<(), AuthError> {
        match self.db.tokens.get(token) {
            Some(t) if t.user == username => {
                self.db.tokens.remove(token);
                self.persist().await.map_err(|e| AuthError::Io(e.to_string()))?;
                Ok(())
            }
            Some(_) => Err(AuthError::Unauthorized),
            None => Err(AuthError::NotFound),
        }
    }
}

/// Public PAT view (token redacted except prefix).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecordPublic {
    pub id: String,
    pub note: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    /// Full token only present on create response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl TokenRecordPublic {
    fn from_record(r: &TokenRecord) -> Self {
        let id = if r.token.len() > 12 {
            format!("{}…", &r.token[..12])
        } else {
            r.token.clone()
        };
        Self {
            id,
            note: r.note.clone(),
            scopes: r.scopes.clone(),
            created_at: r.created_at.clone(),
            token: None,
        }
    }

    pub fn from_create(r: &TokenRecord) -> Self {
        Self {
            id: r.token.clone(),
            note: r.note.clone(),
            scopes: r.scopes.clone(),
            created_at: r.created_at.clone(),
            token: Some(r.token.clone()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("io: {0}")]
    Io(String),
    #[error("hash: {0}")]
    Hash(String),
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Hash(e.to_string()))?
        .to_string();
    Ok(hash)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn register_login_persist() {
        let dir = tempdir().unwrap();
        {
            let mut store = AuthStore::open(dir.path()).await.unwrap();
            store.register("alice", "s3cret!").await.unwrap();
            store.verify_password("alice", "s3cret!").unwrap();
            assert!(store.verify_password("alice", "wrong").is_err());
            let tok = store.issue_session("alice").await.unwrap();
            assert!(store.lookup_token(&tok.token).is_some());
        }
        let store = AuthStore::open(dir.path()).await.unwrap();
        assert!(store.get_user("alice").is_some());
        store.verify_password("alice", "s3cret!").unwrap();
    }

    #[tokio::test]
    async fn pat_create_list_revoke() {
        let dir = tempdir().unwrap();
        let mut store = AuthStore::open(dir.path()).await.unwrap();
        store.register("bob", "pw").await.unwrap();
        let pat = store
            .create_pat("bob", "ci", vec![SCOPE_REPO.into()])
            .await
            .unwrap();
        assert_eq!(store.list_pats("bob").len(), 1);
        store.revoke_token("bob", &pat.token).await.unwrap();
        assert!(store.lookup_token(&pat.token).is_none());
    }
}
