//! Auth integration tests: register/login/whoami, bad password, PAT revoke, persistence.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn json_req(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = if let Some(b) = body {
        builder
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ))
    };
    (status, val)
}

#[tokio::test]
async fn register_login_whoami() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();

    let (st, body) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"alice","password":"s3cret!"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_string();

    let (st, body) = json_req(&app, "GET", "/v1/auth/whoami", Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["user"], "alice");

    let (st, _) = json_req(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"user":"alice","secret":"s3cret!"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn bad_password_and_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();

    let (st, _) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"bob","password":"pw"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"bob","password":"other"})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    let (st, _) = json_req(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"user":"bob","secret":"wrong"})),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pat_revoke_then_401() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();

    let (st, body) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"carol","password":"pw"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let session = body["token"].as_str().unwrap().to_string();

    let (st, pat) = json_req(
        &app,
        "POST",
        "/v1/user/tokens",
        Some(&session),
        Some(json!({"note":"ci","scopes":["repo"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{pat}");
    let pat_token = pat["token"].as_str().unwrap().to_string();

    let (st, _) = json_req(&app, "GET", "/v1/auth/whoami", Some(&pat_token), None).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = json_req(
        &app,
        "DELETE",
        &format!("/v1/user/tokens/{pat_token}"),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = json_req(&app, "GET", "/v1/auth/whoami", Some(&pat_token), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tokens_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let token;
    {
        let app = safehub_server::test_app(dir.path()).await.unwrap();
        let (st, body) = json_req(
            &app,
            "POST",
            "/v1/auth/register",
            None,
            Some(json!({"user":"dave","password":"pw"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        token = body["token"].as_str().unwrap().to_string();
    }
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (st, body) = json_req(&app, "GET", "/v1/auth/whoami", Some(&token), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["user"], "dave");

    // Password hash file should not contain plaintext password.
    let auth_json = std::fs::read_to_string(dir.path().join("auth/auth.json")).unwrap();
    assert!(!auth_json.contains("\"pw\""));
    assert!(auth_json.contains("argon2"));
}
