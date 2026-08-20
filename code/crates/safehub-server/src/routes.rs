//! HTTP routes for blobs, heads, MLS delivery, auth, and repo directory.

use crate::auth::AuthUser;
use crate::state::AppState;
use crate::users::{AuthError, TokenRecordPublic};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use safehub_api::{
    BlobPutRequest, BlobPutResponse, CreatePatRequest, CreateRepoRequest, CreateRepoResponse,
    HeadAppendRequest, HeadAppendResponse, HeadsSinceResponse, KeyLogAppendRequest, LoginRequest,
    MlsEnqueueRequest, MlsEnqueueResponse, MlsFetchResponse, RegisterRequest, WhoAmIResponse,
    API_PREFIX, BLOB_META_HEADER,
};
use safehub_storage::{BlobStore, HeadLog, MlsDeliveryQueue, RepoDirectory};
use safehub_types::{
    AuthToken, KeyPackageRecord, MlsDeliveryEnvelope, RepoId, RepoName, RepoRecord, UserId,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub fn router(state: AppState) -> Router {
    // Untrusted host: ciphertext CAS + membership metadata only.
    // Plaintext browse lives in `safehub-local-ui` / `safehub-browse`.
    router_host(state)
}

fn routes_core() -> Router<AppState> {
    Router::new()
        .route(&format!("{API_PREFIX}/health"), get(health))
        .route(&format!("{API_PREFIX}/auth/register"), post(register))
        .route(&format!("{API_PREFIX}/auth/login"), post(login))
        .route(&format!("{API_PREFIX}/auth/whoami"), get(whoami))
        .route(
            &format!("{API_PREFIX}/user/tokens"),
            get(list_tokens).post(create_token),
        )
        .route(
            &format!("{API_PREFIX}/user/tokens/{{token}}"),
            delete(revoke_token),
        )
        .route(
            &format!("{API_PREFIX}/repos"),
            post(create_repo).get(list_repos),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}"),
            get(get_repo).patch(patch_repo).delete(delete_repo),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/blobs"),
            put(put_blob),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/blobs/{{blob_id}}"),
            get(get_blob),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/heads/tip"),
            get(head_tip),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/heads"),
            post(append_head).get(heads_since),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/mls"),
            post(mls_enqueue).get(mls_fetch),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{repo_id}}/keylog"),
            post(append_keylog),
        )
        .route(
            &format!("{API_PREFIX}/users/{{user}}/key_packages"),
            put(put_key_package).get(list_key_packages),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/collaborators"),
            get(list_collabs).post(invite_collab),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/collaborators/{{user}}"),
            delete(remove_collab),
        )
        // Hosted webhooks would require the untrusted host to observe plaintext
        // event semantics — refuse explicitly rather than store fake hooks.
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/hooks"),
            get(webhooks_refused).post(webhooks_refused),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/hooks/{{id}}"),
            get(webhooks_refused)
                .patch(webhooks_refused)
                .delete(webhooks_refused),
        )
}

/// Plaintext collab index + search: member-machine / local-ui only.
/// Never mount on the untrusted host (`router_host`).
fn routes_plaintext_collab() -> Router<AppState> {
    Router::new()
        .route(&format!("{API_PREFIX}/search"), get(search_collab))
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/issues"),
            get(list_issues).post(create_issue),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/issues/{{id}}"),
            get(get_issue).patch(patch_issue),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/issues/{{id}}/comments"),
            post(comment_issue),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/pulls"),
            get(list_pulls).post(create_pull),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/pulls/{{id}}"),
            get(get_pull).patch(patch_pull),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/pulls/{{id}}/comments"),
            post(comment_pull),
        )
}

/// Untrusted hosting surface (no plaintext tree/blob/commit routes, no HTML UI,
/// no plaintext issue/PR index).
pub fn router_host(state: AppState) -> Router {
    routes_core()
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Member-machine plaintext browse + HTML UI (must not be the untrusted host binary).
pub fn router_local_ui(state: AppState) -> Router {
    routes_core()
        .merge(routes_plaintext_collab())
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/git/tree"),
            get(git_tree),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/contents"),
            get(git_contents),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/commits"),
            get(git_commits),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/commits/{{sha}}"),
            get(git_commit),
        )
        .route(
            &format!("{API_PREFIX}/repos/{{owner}}/{{name}}/mirror/import"),
            post(mirror_import),
        )
        .merge(crate::ui::router())
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

fn auth_status(e: &AuthError) -> StatusCode {
    match e {
        AuthError::BadRequest(_) => StatusCode::BAD_REQUEST,
        AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
        AuthError::Conflict(_) => StatusCode::CONFLICT,
        AuthError::NotFound => StatusCode::NOT_FOUND,
        AuthError::Io(_) | AuthError::Hash(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "service": "safehub-server" }))
}

/// GitHub-style webhooks are incompatible with host-blind E2EE: the host cannot
/// emit meaningful event payloads without reading plaintext. Clients should poll
/// MLS delivery (`GET …/mls`) for opaque wakes.
async fn webhooks_refused() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "webhooks_not_supported",
            "reason": "Untrusted host cannot observe plaintext events under SafeHub E2EE. \
                       Poll MLS delivery / use `sh inbox sync` for opaque wakes; \
                       decrypt collab locally."
        })),
    )
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(default)]
    kind: Option<String>,
}

async fn search_collab(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Vec<crate::collab::SearchHit>>, StatusCode> {
    let _ = user;
    let kind = q.kind.as_deref();
    let hits = crate::collab::search(&state.data_root, &q.q, kind)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(hits))
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<AuthToken>, (StatusCode, String)> {
    let mut auth = state.auth.write().await;
    auth.register(&body.user, &body.password)
        .await
        .map_err(|e| (auth_status(&e), e.to_string()))?;
    let tok = auth
        .issue_session(&body.user)
        .await
        .map_err(|e| (auth_status(&e), e.to_string()))?;
    Ok(Json(AuthToken {
        token: tok.token,
        user: UserId(body.user),
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthToken>, StatusCode> {
    if body.user.is_empty() || body.secret.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut auth = state.auth.write().await;
    auth.verify_password(&body.user, &body.secret)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let tok = auth
        .issue_session(&body.user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AuthToken {
        token: tok.token,
        user: UserId(body.user),
    }))
}

async fn whoami(user: AuthUser) -> Json<WhoAmIResponse> {
    Json(WhoAmIResponse { user: user.user })
}

async fn create_token(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreatePatRequest>,
) -> Result<Json<TokenRecordPublic>, (StatusCode, String)> {
    let mut auth = state.auth.write().await;
    let rec = auth
        .create_pat(&user.user.0, &body.note, body.scopes)
        .await
        .map_err(|e| (auth_status(&e), e.to_string()))?;
    Ok(Json(TokenRecordPublic::from_create(&rec)))
}

async fn list_tokens(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<TokenRecordPublic>>, StatusCode> {
    let auth = state.auth.read().await;
    Ok(Json(auth.list_pats(&user.user.0)))
}

async fn revoke_token(
    State(state): State<AppState>,
    user: AuthUser,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut auth = state.auth.write().await;
    auth.revoke_token(&user.user.0, &token)
        .await
        .map_err(|e| auth_status(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_repos(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<RepoRecord>>, (StatusCode, String)> {
    // Owned repos plus membership-scoped collaborators (ids/names only).
    let mut repos = state
        .store
        .list_for_user(&user.user)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let all = state
        .store
        .list_all_repos()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for r in all {
        if r.name.owner == user.user.0 {
            continue;
        }
        let members = crate::browse::load_members(&state.data_root, &r.name.owner, &r.name.name)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if crate::browse::is_member(&members, &user.user.0)
            && !repos.iter().any(|x| x.id == r.id)
        {
            repos.push(r);
        }
    }
    Ok(Json(repos))
}

async fn create_repo(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateRepoRequest>,
) -> Result<Json<CreateRepoResponse>, (StatusCode, String)> {
    let record = RepoRecord {
        id: RepoId::random(),
        name: RepoName::new(user.user.0.clone(), body.name),
        created_by: user.user,
        private: body.private,
        archived: false,
        deleted: false,
        description: body.description,
    };
    state
        .store
        .create(record.clone())
        .await
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    // Membership metadata only on the untrusted host — no plaintext git mirror.
    let members = crate::browse::RepoMembers {
        owner: record.name.owner.clone(),
        members: vec![crate::browse::MemberEntry {
            user: record.name.owner.clone(),
            history: "full".into(),
            invited_at: chrono::Utc::now().to_rfc3339(),
        }],
    };
    let _ = crate::browse::save_members(
        &state.data_root,
        &record.name.owner,
        &record.name.name,
        &members,
    )
    .await;
    Ok(Json(CreateRepoResponse { repo: record }))
}

async fn get_repo(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<RepoRecord>, StatusCode> {
    match state.store.get_by_name(&owner, &name).await {
        Ok(Some(r)) if !r.deleted => {
            require_member(&state, &user.user.0, &owner, &name).await?;
            Ok(Json(r))
        }
        Ok(Some(_)) | Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct PatchRepoBody {
    #[serde(default)]
    archived: Option<bool>,
    #[serde(default)]
    description: Option<String>,
}

async fn patch_repo(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<PatchRepoBody>,
) -> Result<Json<RepoRecord>, (StatusCode, String)> {
    require_member(&state, &user.user.0, &owner, &name)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    if user.user.0 != owner {
        return Err((StatusCode::FORBIDDEN, "only owner can archive/edit metadata".into()));
    }
    let mut rec = state
        .store
        .get_by_name(&owner, &name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "not found".into()))?;
    if rec.deleted {
        return Err((StatusCode::NOT_FOUND, "not found".into()));
    }
    if let Some(a) = body.archived {
        rec.archived = a;
    }
    if let Some(d) = body.description {
        rec.description = Some(d);
    }
    state
        .store
        .update(rec.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rec))
}

async fn delete_repo(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    if user.user.0 != owner {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut rec = state
        .store
        .get_by_name(&owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    rec.deleted = true;
    rec.archived = true;
    state
        .store
        .update(rec)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_repo_id(s: &str) -> Result<RepoId, StatusCode> {
    RepoId::from_hex(s).map_err(|_| StatusCode::BAD_REQUEST)
}

async fn put_blob(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BlobPutResponse>, (StatusCode, String)> {
    let repo = parse_repo_id(&repo_id).map_err(|s| (s, "bad repo id".into()))?;
    require_repo_id_member(&state, &user, &repo)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (meta, ct) = if content_type.starts_with("application/octet-stream") {
        let meta_hdr = headers
            .get(BLOB_META_HEADER)
            .ok_or((
                StatusCode::BAD_REQUEST,
                format!("missing {BLOB_META_HEADER}"),
            ))?
            .to_str()
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let meta: safehub_types::BlobMeta = serde_json::from_str(meta_hdr)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        (meta, body)
    } else {
        // Legacy JSON + base64 path.
        let req: BlobPutRequest = serde_json::from_slice(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let ct = B64
            .decode(&req.ciphertext_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        (req.meta, Bytes::from(ct))
    };
    let id = state
        .store
        .put(meta, ct)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(BlobPutResponse { id }))
}

async fn get_blob(
    State(state): State<AppState>,
    user: AuthUser,
    Path((repo_id, blob_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let repo = parse_repo_id(&repo_id)?;
    require_repo_id_member(&state, &user, &repo).await?;
    let id = safehub_types::BlobId::from_hex(&blob_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bytes = state.store.get(&id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(bytes)
}

async fn head_tip(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let repo = parse_repo_id(&repo_id)?;
    require_repo_id_member(&state, &user, &repo).await?;
    match state.store.tip(&repo).await {
        Ok(Some(h)) => Ok(Json(h).into_response()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn append_head(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    Json(body): Json<HeadAppendRequest>,
) -> Result<Json<HeadAppendResponse>, (StatusCode, String)> {
    let repo = parse_repo_id(&repo_id).map_err(|s| (s, "bad repo id".into()))?;
    require_repo_id_member(&state, &user, &repo)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    if body.head.repo_id != repo {
        return Err((StatusCode::BAD_REQUEST, "repo_id mismatch".into()));
    }
    match state.store.cas_append(body.head).await {
        Ok(hash) => Ok(Json(HeadAppendResponse { hash })),
        Err(safehub_storage::StorageError::CasConflict { expected }) => Err((
            StatusCode::CONFLICT,
            format!("cas conflict, expected {}", expected.to_hex()),
        )),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

#[derive(Deserialize)]
struct AfterQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Upper bound on a single page, so a client cannot ask the server to decode an
/// unbounded head log in one request. Clients page with `after` to read more.
const MAX_HEADS_PAGE: usize = 1000;

async fn heads_since(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    Query(q): Query<AfterQuery>,
) -> Result<Json<HeadsSinceResponse>, StatusCode> {
    let repo = parse_repo_id(&repo_id)?;
    require_repo_id_member(&state, &user, &repo).await?;
    let mut heads = state
        .store
        .since(&repo, q.after)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    heads.truncate(q.limit.clamp(1, MAX_HEADS_PAGE));
    Ok(Json(HeadsSinceResponse { heads }))
}

async fn mls_enqueue(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    Json(body): Json<MlsEnqueueRequest>,
) -> Result<Json<MlsEnqueueResponse>, (StatusCode, String)> {
    let repo = parse_repo_id(&repo_id).map_err(|s| (s, "bad repo id".into()))?;
    require_repo_id_member(&state, &user, &repo)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    let env = MlsDeliveryEnvelope {
        repo_id: repo,
        seq: 0,
        payload: body.payload,
        sender_hint: body.sender_hint,
    };
    let seq = state
        .store
        .enqueue(env)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(MlsEnqueueResponse { seq }))
}

async fn mls_fetch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    Query(q): Query<AfterQuery>,
) -> Result<Json<MlsFetchResponse>, StatusCode> {
    let repo = parse_repo_id(&repo_id)?;
    require_repo_id_member(&state, &user, &repo).await?;
    let messages = state
        .store
        .fetch(&repo, q.after, q.limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(MlsFetchResponse { messages }))
}

async fn append_keylog(
    State(state): State<AppState>,
    user: AuthUser,
    Path(repo_id): Path<String>,
    Json(body): Json<KeyLogAppendRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let repo = parse_repo_id(&repo_id).map_err(|s| (s, "bad repo id".into()))?;
    require_repo_id_member(&state, &user, &repo)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    state
        .store
        .append_key_log(&repo, body.entry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_key_package(
    State(state): State<AppState>,
    user: AuthUser,
    Path(path_user): Path<String>,
    Json(mut body): Json<KeyPackageRecord>,
) -> Result<StatusCode, (StatusCode, String)> {
    if user.user.0 != path_user {
        return Err((
            StatusCode::FORBIDDEN,
            "can only publish own key packages".into(),
        ));
    }
    body.user = user.user;
    if body.key_package.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty key package".into()));
    }
    state
        .store
        .put_key_package(&body)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_key_packages(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(path_user): Path<String>,
) -> Result<Json<Vec<KeyPackageRecord>>, StatusCode> {
    let list = state
        .store
        .list_key_packages(&UserId(path_user))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(list))
}

async fn require_member(
    state: &AppState,
    user: &str,
    owner: &str,
    name: &str,
) -> Result<(), StatusCode> {
    let members = crate::browse::load_members(&state.data_root, owner, name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if crate::browse::is_member(&members, user) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Membership check for ciphertext routes keyed by opaque [`RepoId`].
///
/// Unknown repos return [`StatusCode::NOT_FOUND`] so existence is not leaked to
/// non-members beyond what a tip GET already revealed for ghosts.
async fn require_repo_id_member(
    state: &AppState,
    user: &AuthUser,
    repo: &RepoId,
) -> Result<(), StatusCode> {
    let rec = state
        .store
        .get_by_id(repo)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(rec) = rec else {
        return Err(StatusCode::NOT_FOUND);
    };
    require_member(state, &user.user.0, &rec.name.owner, &rec.name.name).await
}

#[derive(Deserialize)]
struct PathQuery {
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

async fn git_tree(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
) -> Result<Json<Vec<crate::browse::TreeEntry>>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries = crate::browse::list_tree(&root, &q.path).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(entries))
}

async fn git_contents(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::browse::BlobView>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let blob = crate::browse::read_blob(&root, &q.path).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(blob))
}

async fn git_commits(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Vec<crate::browse::CommitInfo>>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let commits = crate::browse::list_commits(&root, q.limit).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(commits))
}

async fn git_commit(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, sha)): Path<(String, String, String)>,
) -> Result<Json<crate::browse::CommitInfo>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let c = crate::browse::commit_detail(&root, &sha).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(c))
}

async fn list_collabs(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<crate::browse::RepoMembers>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let m = crate::browse::load_members(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(m))
}

#[derive(Deserialize)]
struct InviteBody {
    user: String,
    #[serde(default = "default_full")]
    history: String,
}

fn default_full() -> String {
    "full".into()
}

async fn invite_collab(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<InviteBody>,
) -> Result<Json<crate::browse::RepoMembers>, (StatusCode, String)> {
    require_member(&state, &user.user.0, &owner, &name)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    if user.user.0 != owner {
        return Err((StatusCode::FORBIDDEN, "only owner can invite".into()));
    }
    let history = if body.history == "forward_only" || body.history == "forward-only" {
        "forward_only"
    } else {
        "full"
    };
    let mut m = crate::browse::load_members(&state.data_root, &owner, &name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !m.members.iter().any(|e| e.user == body.user) {
        m.members.push(crate::browse::MemberEntry {
            user: body.user,
            history: history.into(),
            invited_at: chrono::Utc::now().to_rfc3339(),
        });
    }
    crate::browse::save_members(&state.data_root, &owner, &name, &m)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(m))
}

async fn remove_collab(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, target)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    if user.user.0 != owner {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut m = crate::browse::load_members(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    m.members.retain(|e| e.user != target);
    crate::browse::save_members(&state.data_root, &owner, &name, &m)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct IssueCreateBody {
    title: String,
    #[serde(default)]
    body: String,
}

async fn list_issues(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<crate::collab::IssueRecord>>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(idx.issues))
}

async fn create_issue(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<IssueCreateBody>,
) -> Result<Json<crate::collab::IssueRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::create_issue(
        &state.data_root,
        &owner,
        &name,
        &user.user.0,
        &body.title,
        &body.body,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rec))
}

async fn get_issue(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
) -> Result<Json<crate::collab::IssueRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    idx.issues
        .into_iter()
        .find(|i| i.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct StateBody {
    state: String,
}

async fn patch_issue(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
    Json(body): Json<StateBody>,
) -> Result<Json<crate::collab::IssueRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::set_issue_state(&state.data_root, &owner, &name, id, &body.state)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(rec))
}

#[derive(Deserialize)]
struct CommentBody {
    body: String,
}

async fn comment_issue(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
    Json(body): Json<CommentBody>,
) -> Result<Json<crate::collab::IssueRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::comment_issue(
        &state.data_root,
        &owner,
        &name,
        id,
        &user.user.0,
        &body.body,
    )
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(rec))
}

#[derive(Deserialize)]
struct PullCreateBody {
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default = "default_main")]
    base: String,
    #[serde(default = "default_head")]
    head: String,
}

fn default_main() -> String {
    "main".into()
}
fn default_head() -> String {
    "feature".into()
}

async fn list_pulls(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<crate::collab::PullRequestRecord>>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(idx.pulls))
}

async fn create_pull(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<PullCreateBody>,
) -> Result<Json<crate::collab::PullRequestRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::create_pr(
        &state.data_root,
        &owner,
        &name,
        &user.user.0,
        &body.title,
        &body.body,
        &body.base,
        &body.head,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rec))
}

async fn get_pull(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
) -> Result<Json<crate::collab::PullRequestRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    idx.pulls
        .into_iter()
        .find(|i| i.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn patch_pull(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
    Json(body): Json<StateBody>,
) -> Result<Json<crate::collab::PullRequestRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::set_pr_state(&state.data_root, &owner, &name, id, &body.state)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(rec))
}

async fn comment_pull(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name, id)): Path<(String, String, u64)>,
    Json(body): Json<CommentBody>,
) -> Result<Json<crate::collab::PullRequestRecord>, StatusCode> {
    require_member(&state, &user.user.0, &owner, &name).await?;
    let rec = crate::collab::comment_pr(
        &state.data_root,
        &owner,
        &name,
        id,
        &user.user.0,
        &body.body,
    )
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(rec))
}

#[derive(Deserialize)]
struct ImportBody {
    /// Absolute path on the server host to import into the browse mirror.
    source: String,
}

async fn mirror_import(
    State(state): State<AppState>,
    user: AuthUser,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<ImportBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_member(&state, &user.user.0, &owner, &name)
        .await
        .map_err(|s| (s, "forbidden".into()))?;
    let n = crate::browse::import_tree(
        &state.data_root,
        &owner,
        &name,
        std::path::Path::new(&body.source),
    )
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(serde_json::json!({ "imported_files": n })))
}
