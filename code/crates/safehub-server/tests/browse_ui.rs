//! Browse API membership and tree golden tests.

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
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

#[tokio::test]
async fn member_browses_tree_non_member_denied() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app_local_ui(dir.path()).await.unwrap();

    let (_, alice) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"alice","password":"pw"})),
    )
    .await;
    let alice_tok = alice["token"].as_str().unwrap();

    let (_, bob) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"bob","password":"pw"})),
    )
    .await;
    let bob_tok = bob["token"].as_str().unwrap();

    let (st, repo) = json_req(
        &app,
        "POST",
        "/v1/repos",
        Some(alice_tok),
        Some(json!({"name":"demo","private":true})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{repo}");

    let (st, tree) = json_req(
        &app,
        "GET",
        "/v1/repos/alice/demo/git/tree",
        Some(alice_tok),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{tree}");
    let arr = tree.as_array().unwrap();
    assert!(arr.iter().any(|e| e["path"] == "README.md"));

    let (st, blob) = json_req(
        &app,
        "GET",
        "/v1/repos/alice/demo/contents?path=README.md",
        Some(alice_tok),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{blob}");
    assert!(blob["content"].as_str().unwrap().contains("SafeHub"));

    let (st, _) = json_req(
        &app,
        "GET",
        "/v1/repos/alice/demo/git/tree",
        Some(bob_tok),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    let (st, commits) = json_req(
        &app,
        "GET",
        "/v1/repos/alice/demo/commits",
        Some(alice_tok),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{commits}");
    assert!(!commits.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn ui_login_html_smoke() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app_local_ui(dir.path()).await.unwrap();
    let req = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("Sign in to SafeHub"));
    assert!(html.contains("SafeHub"));
}

async fn html_get(app: &axum::Router, uri: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().uri(uri);
    if let Some(c) = cookie {
        builder = builder.header("Cookie", c);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn ui_repo_tabs_and_token_generate() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app_local_ui(dir.path()).await.unwrap();

    let (_, alice) = json_req(
        &app,
        "POST",
        "/v1/auth/register",
        None,
        Some(json!({"user":"alice","password":"pw"})),
    )
    .await;
    let alice_tok = alice["token"].as_str().unwrap();
    let (st, _) = json_req(
        &app,
        "POST",
        "/v1/repos",
        Some(alice_tok),
        Some(json!({"name":"demo","private":true})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let cookie = format!("sh_user=alice; sh_token={alice_tok}");
    let (st, html) = html_get(&app, "/alice/demo", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK, "{html}");
    for tab in [
        "Code",
        "Issues",
        "Pull requests",
        "Commits",
        "Actions",
        "Projects",
        "Wiki",
        "Packages",
        "Settings",
    ] {
        assert!(html.contains(tab), "missing tab {tab}");
    }

    let (st, html) = html_get(&app, "/alice/demo/actions", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(html.contains("Not available in SafeHub"));

    let (st, html) = html_get(&app, "/settings/tokens/new", Some(&cookie)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(html.contains("Generate token"));

    let req = Request::builder()
        .method("POST")
        .uri("/settings/tokens")
        .header("Cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "note=ui-test&scope_repo=on&scope_read_user=on",
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(loc.contains("shpat_") || loc.contains("new="), "{loc}");
}
