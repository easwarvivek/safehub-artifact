//! Thin HTTP client over the SafeHub JSON API.

use crate::config::{ClientConfig, Credentials};
use crate::error::ClientError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use safehub_api::{
    path, routes, with_repo, BlobPutRequest, BlobPutResponse, CreatePatRequest, CreateRepoRequest,
    CreateRepoResponse, HeadAppendRequest, HeadAppendResponse, HeadsSinceResponse,
    KeyLogAppendRequest, LoginRequest, MlsEnqueueRequest, MlsEnqueueResponse, MlsFetchResponse,
    RegisterRequest, WhoAmIResponse, API_PREFIX, BLOB_META_HEADER,
};
use safehub_types::{
    AuthToken, BlobId, BlobMeta, KeyLogEntry, MlsDeliveryEnvelope, RefHead, RepoId, RepoName,
    RepoRecord, UserId,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

/// Public PAT view returned by the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatInfo {
    pub id: String,
    pub note: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    #[serde(default)]
    pub token: Option<String>,
}

/// Authenticated HTTP client.
pub struct HttpClient {
    http: reqwest::Client,
    base: String,
    token: Option<AuthToken>,
}

impl HttpClient {
    /// From config + optional credentials.
    pub fn new(config: &ClientConfig, creds: Option<&Credentials>) -> Result<Self, ClientError> {
        Ok(Self {
            http: reqwest::Client::new(),
            base: config.server_url.trim_end_matches('/').to_string(),
            token: creds.map(|c| c.token.clone()),
        })
    }

    /// Load from disk config/credentials.
    pub fn from_disk() -> Result<Self, ClientError> {
        let config = ClientConfig::load()?;
        let creds = Credentials::load()?;
        Self::new(&config, creds.as_ref())
    }

    fn url(&self, route: &str) -> String {
        format!("{}{API_PREFIX}{route}", self.base)
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, ClientError> {
        match &self.token {
            Some(t) => Ok(req.header(AUTHORIZATION, format!("Bearer {}", t.token))),
            None => Err(ClientError::NotLoggedIn),
        }
    }

    async fn check_json<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, ClientError> {
        let status = resp.status();
        let body = resp.text().await.map_err(|e| ClientError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }

    /// `POST /auth/register` then store credentials.
    pub async fn register(&mut self, user: &str, password: &str) -> Result<AuthToken, ClientError> {
        let resp = self
            .http
            .post(self.url(routes::REGISTER))
            .json(&RegisterRequest {
                user: user.into(),
                password: password.into(),
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let token: AuthToken = Self::check_json(resp).await?;
        self.token = Some(token.clone());
        Credentials {
            token: token.clone(),
        }
        .save()?;
        Ok(token)
    }

    /// `POST /auth/login`
    pub async fn login(&mut self, user: &str, secret: &str) -> Result<AuthToken, ClientError> {
        let resp = self
            .http
            .post(self.url(routes::LOGIN))
            .json(&LoginRequest {
                user: user.into(),
                secret: secret.into(),
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let token: AuthToken = Self::check_json(resp).await?;
        self.token = Some(token.clone());
        Credentials {
            token: token.clone(),
        }
        .save()?;
        Ok(token)
    }

    /// `GET /auth/whoami`
    pub async fn whoami(&self) -> Result<UserId, ClientError> {
        let req = self.auth(self.http.get(self.url(routes::WHOAMI)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let body: WhoAmIResponse = Self::check_json(resp).await?;
        Ok(body.user)
    }

    /// `POST /user/tokens`
    pub async fn create_pat(
        &self,
        note: &str,
        scopes: Vec<String>,
    ) -> Result<PatInfo, ClientError> {
        let req = self.auth(self.http.post(self.url(routes::USER_TOKENS)))?;
        let resp = req
            .json(&CreatePatRequest {
                note: note.into(),
                scopes,
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// `GET /user/tokens`
    pub async fn list_pats(&self) -> Result<Vec<PatInfo>, ClientError> {
        let req = self.auth(self.http.get(self.url(routes::USER_TOKENS)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// `DELETE /user/tokens/:token`
    pub async fn revoke_pat(&self, token: &str) -> Result<(), ClientError> {
        let route = format!("/user/tokens/{token}");
        let req = self.auth(self.http.delete(self.url(&route)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// `POST /repos`
    pub async fn create_repo(
        &self,
        name: &str,
        private: bool,
        description: Option<String>,
    ) -> Result<RepoRecord, ClientError> {
        let req = self.auth(self.http.post(self.url(routes::REPOS)))?;
        let resp = req
            .json(&CreateRepoRequest {
                name: name.into(),
                private,
                description,
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let body: CreateRepoResponse = Self::check_json(resp).await?;
        Ok(body.repo)
    }

    /// `GET /repos` — list repositories visible to the authenticated user.
    pub async fn list_repos(&self) -> Result<Vec<RepoRecord>, ClientError> {
        let req = self.auth(self.http.get(self.url("/repos")))?;
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// `GET /repos/:owner/:name`
    pub async fn get_repo(&self, name: &RepoName) -> Result<RepoRecord, ClientError> {
        let route = format!("/repos/{}/{}", name.owner, name.name);
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Upload an encrypted blob (`application/octet-stream` body + meta header).
    pub async fn put_blob(&self, repo: &RepoId, meta: BlobMeta, ct: &[u8]) -> Result<BlobId, ClientError> {
        let route = with_repo(routes::BLOBS, repo);
        let meta_json = serde_json::to_string(&meta).map_err(|e| ClientError::Other(e.to_string()))?;
        let req = self.auth(self.http.put(self.url(&route)))?;
        let resp = req
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(BLOB_META_HEADER, meta_json)
            .body(ct.to_vec())
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let body: BlobPutResponse = Self::check_json(resp).await?;
        Ok(body.id)
    }

    /// Legacy JSON+base64 blob upload (tests / older clients).
    pub async fn put_blob_json_b64(
        &self,
        repo: &RepoId,
        meta: BlobMeta,
        ct: &[u8],
    ) -> Result<BlobId, ClientError> {
        let route = with_repo(routes::BLOBS, repo);
        let req = self.auth(self.http.put(self.url(&route)))?;
        let resp = req
            .header(CONTENT_TYPE, "application/json")
            .json(&BlobPutRequest {
                meta,
                ciphertext_b64: B64.encode(ct),
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let body: BlobPutResponse = Self::check_json(resp).await?;
        Ok(body.id)
    }

    /// Download blob ciphertext.
    pub async fn get_blob(&self, repo: &RepoId, id: &BlobId) -> Result<Vec<u8>, ClientError> {
        let route = format!("/repos/{}/blobs/{}", repo.to_hex(), id.to_hex());
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| ClientError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(ClientError::Api {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into(),
            });
        }
        Ok(body.to_vec())
    }

    /// Tip head.
    pub async fn head_tip(&self, repo: &RepoId) -> Result<Option<RefHead>, ClientError> {
        let route = with_repo(routes::HEAD_TIP, repo);
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        Ok(Some(Self::check_json(resp).await?))
    }

    /// CAS append head.
    pub async fn append_head(&self, head: RefHead) -> Result<HeadAppendResponse, ClientError> {
        let route = with_repo(routes::HEADS, &head.repo_id);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&HeadAppendRequest { head })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Heads since sequence.
    ///
    /// The server returns a bounded page (it caps `limit` regardless of what we
    /// ask for), so this pages until a short page arrives. Returning only the
    /// first page would silently truncate history: a clone of a repository with
    /// more heads than the page size would check out an old tip and report
    /// success.
    pub async fn heads_since(&self, repo: &RepoId, after: u64) -> Result<Vec<RefHead>, ClientError> {
        const PAGE: usize = 500;
        let mut all: Vec<RefHead> = Vec::new();
        let mut cursor = after;
        loop {
            let route = format!(
                "{}?after={cursor}&limit={PAGE}",
                with_repo(routes::HEADS_SINCE, repo)
            );
            let req = self.auth(self.http.get(self.url(&route)))?;
            let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
            let body: HeadsSinceResponse = Self::check_json(resp).await?;
            let n = body.heads.len();
            // A page that does not advance the cursor would loop forever.
            let last = body.heads.last().map(|h| h.seq);
            all.extend(body.heads);
            match last {
                Some(seq) if seq > cursor => cursor = seq,
                _ => break,
            }
            if n < PAGE {
                break;
            }
        }
        Ok(all)
    }

    /// Enqueue MLS framing.
    pub async fn mls_enqueue(
        &self,
        repo: &RepoId,
        payload: Vec<u8>,
        sender_hint: Option<String>,
    ) -> Result<u64, ClientError> {
        let route = with_repo(routes::MLS_ENQUEUE, repo);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&MlsEnqueueRequest {
                payload,
                sender_hint,
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let body: MlsEnqueueResponse = Self::check_json(resp).await?;
        Ok(body.seq)
    }

    /// Fetch MLS messages.
    pub async fn mls_fetch(
        &self,
        repo: &RepoId,
        after: u64,
    ) -> Result<Vec<MlsDeliveryEnvelope>, ClientError> {
        let route = format!("{}?after={after}&limit=100", with_repo(routes::MLS_FETCH, repo));
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        let body: MlsFetchResponse = Self::check_json(resp).await?;
        Ok(body.messages)
    }

    /// Append key-log entry.
    pub async fn append_key_log(&self, repo: &RepoId, entry: KeyLogEntry) -> Result<(), ClientError> {
        let route = with_repo(routes::KEYLOG, repo);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&KeyLogAppendRequest { entry })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// Publish a KeyPackage for the authenticated user.
    pub async fn put_key_package(
        &self,
        user: &UserId,
        device: &str,
        key_package: Vec<u8>,
    ) -> Result<(), ClientError> {
        let route = format!("/users/{}/key_packages", user.0);
        let req = self.auth(self.http.put(self.url(&route)))?;
        let resp = req
            .json(&safehub_types::KeyPackageRecord {
                user: user.clone(),
                device: device.into(),
                key_package,
            })
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// Fetch KeyPackages for a user.
    pub async fn list_key_packages(
        &self,
        user: &UserId,
    ) -> Result<Vec<safehub_types::KeyPackageRecord>, ClientError> {
        let route = format!("/users/{}/key_packages", user.0);
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Invite a collaborator via control-plane membership API.
    pub async fn invite_collaborator(
        &self,
        repo: &RepoName,
        user: &str,
        history: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let route = format!("/repos/{}/{}/collaborators", repo.owner, repo.name);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&serde_json::json!({ "user": user, "history": history }))
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Remove a collaborator.
    pub async fn remove_collaborator(
        &self,
        repo: &RepoName,
        user: &str,
    ) -> Result<(), ClientError> {
        let route = format!("/repos/{}/{}/collaborators/{user}", repo.owner, repo.name);
        let req = self.auth(self.http.delete(self.url(&route)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// List collaborators (membership metadata only — usernames visible to host).
    pub async fn list_collaborators(
        &self,
        repo: &RepoName,
    ) -> Result<serde_json::Value, ClientError> {
        let route = format!("/repos/{}/{}/collaborators", repo.owner, repo.name);
        let req = self.auth(self.http.get(self.url(&route)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Soft-archive / unarchive via control-plane flag.
    pub async fn patch_repo(
        &self,
        repo: &RepoName,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let route = format!("/repos/{}/{}", repo.owner, repo.name);
        let req = self.auth(self.http.patch(self.url(&route)))?;
        let resp = req
            .json(body)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Tombstone a repository on the control plane.
    pub async fn delete_repo(&self, repo: &RepoName) -> Result<(), ClientError> {
        let route = format!("/repos/{}/{}", repo.owner, repo.name);
        let req = self.auth(self.http.delete(self.url(&route)))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// Create issue via **local-ui** plaintext collab index (not untrusted host).
    /// Prefer `sh issue create` MLS path against `safehub-server`.
    pub async fn create_issue_api(
        &self,
        repo: &RepoName,
        title: &str,
        body: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let route = format!("/repos/{}/{}/issues", repo.owner, repo.name);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&serde_json::json!({ "title": title, "body": body }))
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Create PR via **local-ui** plaintext collab index (not untrusted host).
    /// Prefer `sh pr create` MLS path against `safehub-server`.
    pub async fn create_pull_api(
        &self,
        repo: &RepoName,
        title: &str,
        body: &str,
        base: &str,
        head: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let route = format!("/repos/{}/{}/pulls", repo.owner, repo.name);
        let req = self.auth(self.http.post(self.url(&route)))?;
        let resp = req
            .json(&serde_json::json!({
                "title": title, "body": body, "base": base, "head": head
            }))
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Self::check_json(resp).await
    }

    /// Thin authenticated request against the SafeHub control plane (`/v1/...`).
    ///
    /// `method` is GET/POST/PATCH/PUT/DELETE. `route` is relative to `/v1`
    /// (leading slash optional). Optional JSON body for mutating methods.
    pub async fn api_request(
        &self,
        method: &str,
        route: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, String), ClientError> {
        let route = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{route}")
        };
        let url = self.url(&route);
        let builder = match method.to_uppercase().as_str() {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PATCH" => self.http.patch(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            other => {
                return Err(ClientError::Other(format!("unsupported HTTP method {other}")));
            }
        };
        let req = self.auth(builder)?;
        let resp = if let Some(b) = body {
            req.json(b)
                .send()
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        } else {
            req.send()
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        };
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Ok((status, text))
    }

    /// Suppress unused import warning for `path` helper in docs.
    pub fn api_path(route: &str) -> String {
        path(route)
    }
}
