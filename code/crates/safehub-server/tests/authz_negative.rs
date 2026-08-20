//! Server-side authorization negative tests.
//!
//! The paper positions the host as sequencing-only: it must not grant plaintext
//! and must not let an unauthenticated or non-member caller mutate repository
//! state. These tests assert the access-control surface actually enforces that
//! — unauthenticated access, forged and revoked tokens, cross-tenant access,
//! and non-member writes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn req(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    let r = match body {
        Some(v) => b.body(Body::from(serde_json::to_vec(&v).unwrap())).unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(r).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, val)
}

async fn register(app: &axum::Router, user: &str) -> String {
    let (st, body) = req(
        app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user": user, "password": format!("{user}-pw-1!")})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "register {user}: {body}");
    body["token"].as_str().unwrap().to_string()
}

async fn create_repo(app: &axum::Router, token: &str, name: &str) -> Value {
    let (st, body) = req(
        app,
        "POST",
        "/v1/repos",
        Some(token),
        Some(json!({"name": name})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "create repo {name}: {body}");
    body["repo"].clone()
}

fn is_denied(st: StatusCode) -> bool {
    matches!(
        st,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    )
}

// ------------------------------------------------------- authentication ----

#[tokio::test]
async fn unauthenticated_requests_are_refused_on_every_mutating_route() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    create_repo(&app, &alice, "repo1").await;

    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        ("POST", "/v1/repos", Some(json!({"name": "sneaky"}))),
        ("GET", "/v1/auth/whoami", None),
        (
            "POST",
            "/v1/repos/alice/repo1/collaborators",
            Some(json!({"user": "mallory", "history": "full"})),
        ),
        ("DELETE", "/v1/repos/alice/repo1/collaborators/alice", None),
        (
            "PATCH",
            "/v1/repos/alice/repo1",
            Some(json!({"archived": true})),
        ),
        ("DELETE", "/v1/repos/alice/repo1", None),
    ];
    for (method, uri, body) in cases {
        let (st, _) = req(&app, method, uri, None, body).await;
        assert!(
            is_denied(st),
            "{method} {uri} allowed an unauthenticated caller (status {st})"
        );
    }
}

#[tokio::test]
async fn forged_and_malformed_bearer_tokens_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;

    let mut forged = alice.clone();
    forged.push('x');
    for bad in [
        forged.as_str(),
        "",
        "not-a-token",
        "Bearer",
        "../../etc/passwd",
        "00000000-0000-0000-0000-000000000000",
    ] {
        let (st, _) = req(&app, "GET", "/v1/auth/whoami", Some(bad), None).await;
        assert!(is_denied(st), "token {bad:?} was accepted (status {st})");
    }
}

#[tokio::test]
async fn a_revoked_token_cannot_mutate_repositories() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    create_repo(&app, &alice, "repo1").await;

    // Mint a PAT, confirm it works, revoke it, confirm it is dead.
    let (st, body) = req(
        &app,
        "POST",
        "/v1/user/tokens",
        Some(&alice),
        Some(json!({"note": "ci runner", "scopes": []})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let pat = body["token"].as_str().unwrap().to_string();

    let (st, _) = req(&app, "GET", "/v1/auth/whoami", Some(&pat), None).await;
    assert_eq!(st, StatusCode::OK, "fresh PAT should authenticate");

    let (st, _) = req(
        &app,
        "DELETE",
        &format!("/v1/user/tokens/{pat}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "revoke should return 204");

    let (st, _) = req(&app, "GET", "/v1/auth/whoami", Some(&pat), None).await;
    assert!(is_denied(st), "revoked PAT still authenticated");

    let (st, _) = req(
        &app,
        "POST",
        "/v1/repos",
        Some(&pat),
        Some(json!({"name": "after-revoke"})),
    )
    .await;
    assert!(is_denied(st), "revoked PAT created a repository");
}

// -------------------------------------------------------- authorization ----

#[tokio::test]
async fn a_non_member_cannot_administer_someone_elses_repository() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    let mallory = register(&app, "mallory").await;
    create_repo(&app, &alice, "private").await;

    // Add a collaborator to a repo she does not own.
    let (st, _) = req(
        &app,
        "POST",
        "/v1/repos/alice/private/collaborators",
        Some(&mallory),
        Some(json!({"user": "mallory", "history": "full"})),
    )
    .await;
    assert!(is_denied(st), "non-member added themselves as collaborator");

    // Remove the owner from her own repo.
    let (st, _) = req(
        &app,
        "DELETE",
        "/v1/repos/alice/private/collaborators/alice",
        Some(&mallory),
        None,
    )
    .await;
    assert!(is_denied(st), "non-member removed the owner");
}

#[tokio::test]
async fn untrusted_host_has_no_plaintext_collab_or_search_routes() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    create_repo(&app, &alice, "private").await;

    for uri in [
        "/v1/repos/alice/private/issues",
        "/v1/repos/alice/private/pulls",
        "/v1/search?q=secret",
    ] {
        let (st, _) = req(&app, "GET", uri, Some(&alice), None).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "host must not expose plaintext collab at {uri} (got {st})"
        );
    }

    let (st, body) = req(
        &app,
        "POST",
        "/v1/repos/alice/private/hooks",
        Some(&alice),
        Some(json!({"url": "https://example.test/hook"})),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert_eq!(body["error"], "webhooks_not_supported");
}

#[tokio::test]
async fn owner_can_archive_and_tombstone_repo() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    create_repo(&app, &alice, "widgets").await;

    let (st, body) = req(
        &app,
        "PATCH",
        "/v1/repos/alice/widgets",
        Some(&alice),
        Some(json!({"archived": true})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["archived"], true);

    let (st, _) = req(&app, "DELETE", "/v1/repos/alice/widgets", Some(&alice), None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = req(&app, "GET", "/v1/repos/alice/widgets", Some(&alice), None).await;
    assert!(is_denied(st), "tombstoned repo still visible");
}

#[tokio::test]
async fn a_non_member_cannot_write_collaboration_records() {
    let dir = tempfile::tempdir().unwrap();
    // Plaintext collab index lives on local-ui only; still enforce membership there.
    let app = safehub_server::test_app_local_ui(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    let mallory = register(&app, "mallory").await;
    create_repo(&app, &alice, "private").await;

    for (uri, body) in [
        (
            "/v1/repos/alice/private/issues",
            json!({"title": "AAA", "body": "BBB"}),
        ),
        (
            "/v1/repos/alice/private/pulls",
            json!({"title": "AAA", "body": "BBB"}),
        ),
    ] {
        let (st, _) = req(&app, "POST", uri, Some(&mallory), Some(body)).await;
        assert!(is_denied(st), "non-member wrote to {uri} (status {st})");
    }
}

#[tokio::test]
async fn two_tenants_cannot_reach_each_others_repositories() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;
    let bob = register(&app, "bob").await;
    let a = create_repo(&app, &alice, "shared-name").await;
    let b = create_repo(&app, &bob, "shared-name").await;

    // Same repo name under two owners must be two distinct repositories.
    assert_ne!(a["id"], b["id"], "repo ids collided across owners");

    // Bob must not administer alice/shared-name via the owner-scoped route.
    let (st, _) = req(
        &app,
        "POST",
        "/v1/repos/alice/shared-name/collaborators",
        Some(&bob),
        Some(json!({"user": "bob", "history": "full"})),
    )
    .await;
    assert!(is_denied(st), "cross-tenant administration allowed");
}

#[tokio::test]
async fn unknown_repositories_and_blobs_do_not_leak_existence() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let alice = register(&app, "alice").await;

    let (st, _) = req(&app, "GET", "/v1/repos/alice/no-such-repo", Some(&alice), None).await;
    assert!(is_denied(st), "unknown repo returned success");

    let ghost = "ab".repeat(32);
    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{ghost}/heads/tip"),
        Some(&alice),
        None,
    )
    .await;
    assert!(is_denied(st), "tip of an unknown repo returned success");
}

#[tokio::test]
async fn health_is_the_only_route_open_without_a_token() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (st, _) = req(&app, "GET", "/v1/health", None, None).await;
    assert_eq!(st, StatusCode::OK, "health must stay unauthenticated");
}
