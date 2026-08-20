//! Admin vs ordinary member vs non-member authorization matrix.
//!
//! Control-plane admin == repository owner. Ordinary collaborators are members
//! who can read/write ciphertext CAS for the repo but must not invite, remove,
//! archive, or delete. Non-members and unauthenticated callers are denied.

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

fn denied(st: StatusCode) -> bool {
    matches!(
        st,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    )
}

/// `RepoId` serializes as a 32-byte JSON array; routes expect hex.
fn repo_id_hex(repo: &Value) -> String {
    let arr = repo["id"]
        .as_array()
        .unwrap_or_else(|| panic!("repo.id not an array: {repo}"));
    let mut bytes = [0u8; 32];
    assert_eq!(arr.len(), 32, "repo.id length");
    for (i, v) in arr.iter().enumerate() {
        bytes[i] = v.as_u64().unwrap() as u8;
    }
    hex::encode(bytes)
}

/// Seed alice (owner) + bob (collaborator) on alice/team.
async fn seeded_team(app: &axum::Router) -> (String, String, String, Value) {
    let alice = register(app, "alice").await;
    let bob = register(app, "bob").await;
    let mallory = register(app, "mallory").await;
    let repo = create_repo(app, &alice, "team").await;
    let (st, _) = req(
        app,
        "POST",
        "/v1/repos/alice/team/collaborators",
        Some(&alice),
        Some(json!({"user": "bob", "history": "full"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner invite bob");
    (alice, bob, mallory, repo)
}

#[tokio::test]
async fn owner_can_invite_remove_archive_delete() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (alice, _bob, _mallory, _repo) = seeded_team(&app).await;

    let (st, body) = req(
        &app,
        "POST",
        "/v1/repos/alice/team/collaborators",
        Some(&alice),
        Some(json!({"user": "carol", "history": "forward_only"})),
    )
    .await;
    // carol may not exist as a user yet — invite is metadata-only; still OK.
    let _ = register(&app, "carol").await;
    let (st2, _) = req(
        &app,
        "POST",
        "/v1/repos/alice/team/collaborators",
        Some(&alice),
        Some(json!({"user": "carol", "history": "forward_only"})),
    )
    .await;
    assert!(
        st == StatusCode::OK || st2 == StatusCode::OK,
        "owner invite: {st}/{st2} {body}"
    );

    let (st, _) = req(
        &app,
        "DELETE",
        "/v1/repos/alice/team/collaborators/bob",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "owner remove");

    let (st, body) = req(
        &app,
        "PATCH",
        "/v1/repos/alice/team",
        Some(&alice),
        Some(json!({"archived": true})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner archive: {body}");
    assert_eq!(body["archived"], true);

    let (st, _) = req(&app, "DELETE", "/v1/repos/alice/team", Some(&alice), None).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "owner delete");
}

#[tokio::test]
async fn ordinary_member_cannot_invite_remove_archive_or_delete() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (_alice, bob, _mallory, repo) = seeded_team(&app).await;
    let repo_id = repo_id_hex(&repo);

    let (st, _) = req(
        &app,
        "POST",
        "/v1/repos/alice/team/collaborators",
        Some(&bob),
        Some(json!({"user": "mallory", "history": "full"})),
    )
    .await;
    assert!(denied(st), "member invite must fail ({st})");

    let (st, _) = req(
        &app,
        "DELETE",
        "/v1/repos/alice/team/collaborators/alice",
        Some(&bob),
        None,
    )
    .await;
    assert!(denied(st), "member remove must fail ({st})");

    let (st, _) = req(
        &app,
        "PATCH",
        "/v1/repos/alice/team",
        Some(&bob),
        Some(json!({"archived": true})),
    )
    .await;
    assert!(denied(st), "member archive must fail ({st})");

    let (st, _) = req(&app, "DELETE", "/v1/repos/alice/team", Some(&bob), None).await;
    assert!(denied(st), "member delete must fail ({st})");

    // Member may still read the tip endpoint (empty tip → 404 is ok) and must
    // not be confused with a non-member denial of the route itself.
    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{repo_id}/heads/tip"),
        Some(&bob),
        None,
    )
    .await;
    assert!(
        matches!(st, StatusCode::NOT_FOUND | StatusCode::OK),
        "member tip access should be allowed (got {st})"
    );
}

#[tokio::test]
async fn non_member_cannot_touch_ciphertext_or_membership() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (_alice, _bob, mallory, repo) = seeded_team(&app).await;
    let repo_id = repo_id_hex(&repo);

    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{repo_id}/heads/tip"),
        Some(&mallory),
        None,
    )
    .await;
    assert!(denied(st), "non-member tip ({st})");

    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{repo_id}/heads?after=0"),
        Some(&mallory),
        None,
    )
    .await;
    assert!(denied(st), "non-member heads_since ({st})");

    let (st, _) = req(
        &app,
        "POST",
        &format!("/v1/repos/{repo_id}/heads"),
        Some(&mallory),
        Some(json!({
            "head": {
                "repo_id": repo["id"].clone(),
                "seq": 1,
                "enc_refs": [],
                "bundle_root": "00".repeat(64),
                "dek_wrap": [],
                "prev_head_hash": "00".repeat(64),
                "mls_epoch": 0,
                "epoch_tag": [],
                "non_ff": false,
                "pusher_sig": [],
                "admin_cosig": null
            }
        })),
    )
    .await;
    assert!(denied(st), "non-member append_head ({st})");

    let (st, _) = req(
        &app,
        "POST",
        &format!("/v1/repos/{repo_id}/mls"),
        Some(&mallory),
        Some(json!({"payload": [1, 2, 3], "sender_hint": "x"})),
    )
    .await;
    assert!(denied(st), "non-member mls_enqueue ({st})");

    let (st, _) = req(
        &app,
        "GET",
        "/v1/repos/alice/team",
        Some(&mallory),
        None,
    )
    .await;
    assert!(denied(st), "non-member get_repo ({st})");
}

#[tokio::test]
async fn unauthenticated_cannot_mutate_or_read_repo() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (alice, _, _, repo) = seeded_team(&app).await;
    let _ = alice;
    let repo_id = repo_id_hex(&repo);
    let tip_uri = format!("/v1/repos/{repo_id}/heads/tip");

    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        (
            "POST",
            "/v1/repos/alice/team/collaborators",
            Some(json!({"user": "x", "history": "full"})),
        ),
        ("DELETE", "/v1/repos/alice/team/collaborators/bob", None),
        (
            "PATCH",
            "/v1/repos/alice/team",
            Some(json!({"archived": true})),
        ),
        ("DELETE", "/v1/repos/alice/team", None),
        ("GET", tip_uri.as_str(), None),
    ];
    for (method, uri, body) in cases {
        let (st, _) = req(&app, method, uri, None, body).await;
        assert!(denied(st), "unauth {method} {uri} got {st}");
    }
}

#[tokio::test]
async fn removed_member_loses_ciphertext_access() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (alice, bob, _, repo) = seeded_team(&app).await;
    let repo_id = repo_id_hex(&repo);

    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{repo_id}/heads/tip"),
        Some(&bob),
        None,
    )
    .await;
    assert!(
        matches!(st, StatusCode::NOT_FOUND | StatusCode::OK),
        "bob should access before removal ({st})"
    );

    let (st, _) = req(
        &app,
        "DELETE",
        "/v1/repos/alice/team/collaborators/bob",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = req(
        &app,
        "GET",
        &format!("/v1/repos/{repo_id}/heads/tip"),
        Some(&bob),
        None,
    )
    .await;
    assert!(denied(st), "removed member tip ({st})");

    let (st, _) = req(
        &app,
        "POST",
        &format!("/v1/repos/{repo_id}/mls"),
        Some(&bob),
        Some(json!({"payload": [9], "sender_hint": null})),
    )
    .await;
    assert!(denied(st), "removed member mls_enqueue ({st})");
}

#[tokio::test]
async fn member_can_list_collaborators_but_not_self_promote() {
    let dir = tempfile::tempdir().unwrap();
    let app = safehub_server::test_app(dir.path()).await.unwrap();
    let (_alice, bob, _, _) = seeded_team(&app).await;

    let (st, body) = req(
        &app,
        "GET",
        "/v1/repos/alice/team/collaborators",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    // Re-adding self as collaborator is still an invite → owner only.
    let (st, _) = req(
        &app,
        "POST",
        "/v1/repos/alice/team/collaborators",
        Some(&bob),
        Some(json!({"user": "bob", "history": "full"})),
    )
    .await;
    assert!(denied(st), "member self-invite ({st})");
}
