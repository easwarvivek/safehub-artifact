//! SafeHub member-local HTML UI (`safehub-local-ui`).
//!
//! Auth, tokens, plaintext code browse, commits, issues, PRs, collaborators,
//! and settings — all on the member machine, never on the untrusted host.
//! Icons are inline SVG glyphs; styling lives in `ui_static/app.css`.

use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use serde::Deserialize;
use std::path::Path;

pub fn router() -> Router<crate::state::AppState> {
    // Static paths before `/{owner}/{name}` so they never collide.
    Router::new()
        .route("/", get(home))
        .route("/login", get(login_page).post(login_form))
        .route("/register", get(register_page).post(register_form))
        .route("/logout", get(logout))
        .route("/settings/tokens", get(tokens_page).post(tokens_create))
        .route("/settings/tokens/new", get(tokens_new_page))
        .route("/settings/billing", get(stub_billing))
        .route("/codespaces", get(stub_codespaces))
        .route("/assets/app.css", get(css))
        .route("/assets/app.js", get(js))
        .route("/{owner}", get(user_page))
        .route("/{owner}/{name}", get(repo_code))
        .route("/{owner}/{name}/", get(repo_code))
        .route("/{owner}/{name}/blob", get(repo_blob))
        .route("/{owner}/{name}/commits", get(repo_commits))
        .route("/{owner}/{name}/commit/{sha}", get(repo_commit))
        .route("/{owner}/{name}/issues", get(repo_issues))
        .route("/{owner}/{name}/issues/{id}", get(repo_issue))
        .route("/{owner}/{name}/pulls", get(repo_pulls))
        .route("/{owner}/{name}/pulls/{id}", get(repo_pull))
        .route("/{owner}/{name}/settings", get(repo_settings))
        .route("/{owner}/{name}/settings/access", get(repo_access))
        .route("/{owner}/{name}/actions", get(stub_actions))
        .route("/{owner}/{name}/projects", get(stub_projects))
        .route("/{owner}/{name}/wiki", get(stub_wiki))
        .route("/{owner}/{name}/security", get(stub_security))
        .route("/{owner}/{name}/insights", get(stub_insights))
        .route("/{owner}/{name}/packages", get(stub_packages))
}

/// SafeHub brand mark: two commit nodes on a branch line, wearing incognito
/// spectacles. Drawn on the same 16×16 grid as the interface glyphs.
const SAFEHUB_MARK_BODY: &str = r#"<g fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round"><path d="M2.6 6.5h10.8"/><path d="M5.1 6.5v1.05"/><path d="M10.9 6.5v1.05"/><path d="M.9 9.7h2.05"/><path d="M13.05 9.7h2.05"/><path d="M7.25 9.7h1.5"/><circle cx="5.1" cy="9.7" r="2.15"/><circle cx="10.9" cy="9.7" r="2.15"/></g>"#;

/// Brand mark as a standalone data-URI favicon (brand blue, no external file).
fn favicon_data_uri() -> String {
    let svg = format!(
        r#"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>{}</svg>"#,
        SAFEHUB_MARK_BODY
            .replace('"', "'")
            .replace("currentColor", "#0969da")
    );
    format!("data:image/svg+xml,{}", svg.replace('#', "%23"))
}

/// Inline Octicon-style glyph (16×16, `currentColor`) — no external assets.
fn icon(name: &str) -> String {
    icon_sized(name, 16)
}

fn icon_sized(name: &str, px: u32) -> String {
    let body = match name {
        "safehub-mark" => SAFEHUB_MARK_BODY,
        "search" => r#"<path d="M10.68 11.74a6 6 0 0 1-7.922-8.982 6 6 0 0 1 8.982 7.922l3.04 3.04a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215ZM11.5 7a4.499 4.499 0 1 0-8.997 0A4.499 4.499 0 0 0 11.5 7Z"/>"#,
        "code" => r#"<path d="m11.28 3.22 4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734L13.94 8l-3.72-3.72a.749.749 0 0 1 .326-1.275.749.749 0 0 1 .734.215Zm-6.56 0a.751.751 0 0 1 1.042.018.751.751 0 0 1 .018 1.042L2.06 8l3.72 3.72a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L.47 8.53a.75.75 0 0 1 0-1.06Z"/>"#,
        "issue-opened" => r#"<path d="M8 9.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z"/><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Z"/>"#,
        "issue-closed" => r#"<path d="M11.28 6.78a.75.75 0 0 0-1.06-1.06L7.25 8.69 5.78 7.22a.75.75 0 0 0-1.06 1.06l2 2a.75.75 0 0 0 1.06 0Z"/><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0Zm-1.5 0a6.5 6.5 0 1 0-13 0 6.5 6.5 0 0 0 13 0Z"/>"#,
        "git-pull-request" => r#"<path d="M1.5 3.25a2.25 2.25 0 1 1 3 2.122v5.256a2.251 2.251 0 1 1-1.5 0V5.372A2.25 2.25 0 0 1 1.5 3.25Zm5.677-.177L9.573.677A.25.25 0 0 1 10 .854V2.5h1A2.5 2.5 0 0 1 13.5 5v5.628a2.251 2.251 0 1 1-1.5 0V5a1 1 0 0 0-1-1h-1v1.646a.25.25 0 0 1-.427.177L7.177 3.427a.25.25 0 0 1 0-.354ZM3.75 2.5a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Zm0 9.5a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Zm8.25.75a.75.75 0 1 0 1.5 0 .75.75 0 0 0-1.5 0Z"/>"#,
        "git-merge" => r#"<path d="M5.45 5.154A4.25 4.25 0 0 0 9.25 7.5h1.378a2.251 2.251 0 1 1 0 1.5H9.25A5.734 5.734 0 0 1 5 7.123v3.505a2.25 2.25 0 1 1-1.5 0V5.372a2.25 2.25 0 1 1 1.95-.218ZM4.25 13.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm8.5-4.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5ZM5 3.25a.75.75 0 1 0 0 .005V3.25Z"/>"#,
        "git-commit" => r#"<path d="M11.93 8.5a4.002 4.002 0 0 1-7.86 0H.75a.75.75 0 0 1 0-1.5h3.32a4.002 4.002 0 0 1 7.86 0h3.32a.75.75 0 0 1 0 1.5Zm-1.43-.75a2.5 2.5 0 1 0-5 0 2.5 2.5 0 0 0 5 0Z"/>"#,
        "git-branch" => r#"<path d="M9.5 3.25a2.25 2.25 0 1 1 3 2.122V6A2.5 2.5 0 0 1 10 8.5H6a1 1 0 0 0-1 1v1.128a2.251 2.251 0 1 1-1.5 0V5.372a2.25 2.25 0 1 1 1.5 0v1.836A2.493 2.493 0 0 1 6 7h4a1 1 0 0 0 1-1v-.628A2.25 2.25 0 0 1 9.5 3.25Zm-6 0a.75.75 0 1 0 1.5 0 .75.75 0 0 0-1.5 0Zm8.25-.75a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5ZM4.25 12a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Z"/>"#,
        "history" => r#"<path d="m.427 1.927 1.215 1.215a8.002 8.002 0 1 1-1.6 5.685.75.75 0 1 1 1.493-.154 6.5 6.5 0 1 0 1.18-4.458l1.358 1.358A.25.25 0 0 1 3.896 6H.25A.25.25 0 0 1 0 5.75V2.104a.25.25 0 0 1 .427-.177ZM7.75 4a.75.75 0 0 1 .75.75v2.992l2.028.812a.75.75 0 0 1-.557 1.392l-2.5-1A.751.751 0 0 1 7 8.25v-3.5A.75.75 0 0 1 7.75 4Z"/>"#,
        "play" => r#"<path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Zm4.879-2.773 4.264 2.559a.25.25 0 0 1 0 .428l-4.264 2.559A.25.25 0 0 1 6 10.559V5.442a.25.25 0 0 1 .379-.215Z"/>"#,
        "project" => r#"<path d="M1.75 0h12.5C15.216 0 16 .784 16 1.75v12.5A1.75 1.75 0 0 1 14.25 16H1.75A1.75 1.75 0 0 1 0 14.25V1.75C0 .784.784 0 1.75 0ZM1.5 1.75v12.5c0 .138.112.25.25.25h4.75v-13H1.75a.25.25 0 0 0-.25.25Zm6.5 12.75h6.25a.25.25 0 0 0 .25-.25V8H8v6.5ZM8 6.5h6.5V1.75a.25.25 0 0 0-.25-.25H8Z"/>"#,
        "book" => r#"<path d="M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z"/>"#,
        "shield" => r#"<path d="M7.467.133a1.748 1.748 0 0 1 1.066 0l5.25 1.68A1.75 1.75 0 0 1 15 3.48V7c0 1.566-.32 3.182-1.303 4.682-.983 1.498-2.585 2.813-5.032 3.855a1.697 1.697 0 0 1-1.33 0c-2.447-1.042-4.049-2.357-5.032-3.855C1.32 10.182 1 8.566 1 7V3.48a1.75 1.75 0 0 1 1.217-1.667Zm.61 1.429a.25.25 0 0 0-.153 0l-5.25 1.68a.25.25 0 0 0-.174.238V7c0 1.358.275 2.666 1.057 3.86.784 1.194 2.121 2.34 4.366 3.297a.196.196 0 0 0 .154 0c2.245-.956 3.582-2.104 4.366-3.298C13.225 9.666 13.5 8.36 13.5 7V3.48a.251.251 0 0 0-.174-.237l-5.25-1.68ZM8.75 4.75v3a.75.75 0 0 1-1.5 0v-3a.75.75 0 0 1 1.5 0ZM9 10.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z"/>"#,
        "graph" => r#"<path d="M1.5 1.75V13.5h13.75a.75.75 0 0 1 0 1.5H.75a.75.75 0 0 1-.75-.75V1.75a.75.75 0 0 1 1.5 0Zm14.28 2.53-5.25 5.25a.75.75 0 0 1-1.06 0L7 7.06 4.28 9.78a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042l3.25-3.25a.75.75 0 0 1 1.06 0L10 7.94l4.72-4.72a.751.751 0 0 1 1.042.018.751.751 0 0 1 .018 1.042Z"/>"#,
        "package" => r#"<path d="m8.878.392 5.25 3.045c.54.314.872.89.872 1.514v6.098a1.75 1.75 0 0 1-.872 1.514l-5.25 3.045a1.75 1.75 0 0 1-1.756 0l-5.25-3.045A1.75 1.75 0 0 1 1 11.049V4.951c0-.624.332-1.201.872-1.514L7.122.392a1.75 1.75 0 0 1 1.756 0ZM7.875 1.69l-4.63 2.685L8 7.133l4.755-2.758-4.63-2.685a.248.248 0 0 0-.25 0ZM2.5 5.677v5.372c0 .09.047.171.125.216l4.625 2.683V8.432Zm6.25 8.271 4.625-2.683a.25.25 0 0 0 .125-.216V5.677L8.75 8.432Z"/>"#,
        "gear" => r#"<path d="M8 0a8.2 8.2 0 0 1 .701.031C9.444.095 9.99.645 10.16 1.29l.288 1.107c.018.066.079.158.212.224.231.114.454.243.668.386.123.082.233.09.299.071l1.103-.303c.644-.176 1.392.021 1.82.63.27.385.506.792.704 1.218.315.675.111 1.422-.364 1.891l-.814.806c-.049.048-.098.147-.088.294.016.257.016.515 0 .772-.01.147.038.246.088.294l.814.806c.475.469.679 1.216.364 1.891a7.977 7.977 0 0 1-.704 1.217c-.428.61-1.176.807-1.82.63l-1.102-.302c-.067-.019-.177-.011-.3.071a5.909 5.909 0 0 1-.668.386c-.133.066-.194.158-.211.224l-.29 1.106c-.168.646-.715 1.196-1.458 1.26a8.006 8.006 0 0 1-1.402 0c-.743-.064-1.289-.614-1.458-1.26l-.289-1.106c-.018-.066-.079-.158-.212-.224a5.738 5.738 0 0 1-.668-.386c-.123-.082-.233-.09-.299-.071l-1.103.303c-.644.176-1.392-.021-1.82-.63a8.12 8.12 0 0 1-.704-1.218c-.315-.675-.111-1.422.363-1.891l.815-.806c.05-.048.098-.147.088-.294a6.214 6.214 0 0 1 0-.772c.01-.147-.038-.246-.088-.294l-.815-.806C.635 6.045.431 5.298.746 4.623a7.92 7.92 0 0 1 .704-1.217c.428-.61 1.176-.807 1.82-.63l1.102.302c.067.019.177.011.3-.071.214-.143.437-.272.668-.386.133-.066.194-.158.211-.224l.29-1.106C6.009.645 6.556.095 7.299.03 7.53.01 7.764 0 8 0Zm3 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0ZM9.5 8a1.5 1.5 0 1 0-3.001.001A1.5 1.5 0 0 0 9.5 8Z"/>"#,
        "repo" => r#"<path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.495 2.495 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.708A2.486 2.486 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.087a.249.249 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z"/>"#,
        "file" => r#"<path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.062V4.25c0 .138.112.25.25.25h2.688l-.011-.013-2.914-2.914-.013-.011Z"/>"#,
        "file-directory" => r#"<path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25v-8.5A1.75 1.75 0 0 0 14.25 3H7.5a.25.25 0 0 1-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75Z"/>"#,
        "star" => r#"<path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Zm0 2.445L6.615 5.5a.75.75 0 0 1-.564.41l-3.097.45 2.24 2.184a.75.75 0 0 1 .216.664l-.528 3.084 2.769-1.456a.75.75 0 0 1 .698 0l2.77 1.456-.53-3.084a.75.75 0 0 1 .216-.664l2.24-2.183-3.096-.45a.75.75 0 0 1-.564-.41L8 2.694Z"/>"#,
        "repo-forked" => r#"<path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z"/>"#,
        "eye" => r#"<path d="M8 2c1.981 0 3.671.992 4.933 2.078 1.27 1.091 2.187 2.345 2.637 3.023a1.62 1.62 0 0 1 0 1.798c-.45.678-1.367 1.932-2.637 3.023C11.67 13.008 9.981 14 8 14c-1.981 0-3.671-.992-4.933-2.078C1.797 10.83.88 9.576.43 8.898a1.62 1.62 0 0 1 0-1.798c.45-.677 1.367-1.931 2.637-3.022C4.33 2.992 6.019 2 8 2ZM1.679 7.932a.12.12 0 0 0 0 .136c.411.622 1.241 1.75 2.366 2.717C5.176 11.758 6.527 12.5 8 12.5c1.473 0 2.825-.742 3.955-1.715 1.124-.967 1.954-2.096 2.366-2.717a.12.12 0 0 0 0-.136c-.412-.621-1.242-1.75-2.366-2.717C10.824 4.242 9.473 3.5 8 3.5c-1.473 0-2.825.742-3.955 1.715-1.124.967-1.954 2.096-2.366 2.717ZM8 10a2 2 0 1 1-.001-3.999A2 2 0 0 1 8 10Z"/>"#,
        "lock" => r#"<path d="M4 4a4 4 0 0 1 8 0v2h.25c.966 0 1.75.784 1.75 1.75v5.5A1.75 1.75 0 0 1 12.25 15h-8.5A1.75 1.75 0 0 1 2 13.25v-5.5C2 6.784 2.784 6 3.75 6H4Zm8.25 3.5h-8.5a.25.25 0 0 0-.25.25v5.5c0 .138.112.25.25.25h8.5a.25.25 0 0 0 .25-.25v-5.5a.25.25 0 0 0-.25-.25ZM10.5 6V4a2.5 2.5 0 1 0-5 0v2Z"/>"#,
        "people" => r#"<path d="M2 5.5a3.5 3.5 0 1 1 5.898 2.549 5.508 5.508 0 0 1 3.034 4.084.75.75 0 1 1-1.482.235 4 4 0 0 0-7.9 0 .75.75 0 0 1-1.482-.236A5.507 5.507 0 0 1 3.102 8.05 3.493 3.493 0 0 1 2 5.5ZM11 4a.75.75 0 0 1 0-1.5 3.5 3.5 0 0 1 1.98 6.386 5.5 5.5 0 0 1 2.5 3.27.75.75 0 1 1-1.45.375 4 4 0 0 0-2.925-2.777.75.75 0 0 1 .006-1.455A2 2 0 0 0 11 4ZM5.5 3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/>"#,
        "comment" => r#"<path d="M1 2.75C1 1.784 1.784 1 2.75 1h10.5c.966 0 1.75.784 1.75 1.75v7.5A1.75 1.75 0 0 1 13.25 12H9.06l-2.573 2.573A1.458 1.458 0 0 1 4 13.543V12H2.75A1.75 1.75 0 0 1 1 10.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h2a.75.75 0 0 1 .75.75v2.19l2.72-2.72a.749.749 0 0 1 .53-.22h4.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/>"#,
        "plus" => r#"<path d="M7.75 2a.75.75 0 0 1 .75.75V7h4.25a.75.75 0 0 1 0 1.5H8.5v4.25a.75.75 0 0 1-1.5 0V8.5H2.75a.75.75 0 0 1 0-1.5H7V2.75A.75.75 0 0 1 7.75 2Z"/>"#,
        "alert" => r#"<path d="M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0 1 14.082 15H1.918a1.75 1.75 0 0 1-1.543-2.575Zm1.763.707a.25.25 0 0 0-.44 0L1.698 13.132a.25.25 0 0 0 .22.368h12.164a.25.25 0 0 0 .22-.368Zm.53 3.996v2.5a.75.75 0 0 1-1.5 0v-2.5a.75.75 0 0 1 1.5 0ZM9 11a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z"/>"#,
        "inbox" => r#"<path d="M2.8 2.06A1.75 1.75 0 0 1 4.41 1h7.18c.7 0 1.333.417 1.61 1.06l2.74 6.395c.04.093.06.194.06.295v4.5A1.75 1.75 0 0 1 14.25 15H1.75A1.75 1.75 0 0 1 0 13.25v-4.5c0-.101.02-.202.06-.295Zm1.61.44a.25.25 0 0 0-.23.152L1.887 8H4.75a.75.75 0 0 1 .6.3L6.625 10h2.75l1.275-1.7a.75.75 0 0 1 .6-.3h2.863L11.82 2.652a.25.25 0 0 0-.23-.152Zm10.09 7h-2.875l-1.275 1.7a.75.75 0 0 1-.6.3h-3.5a.75.75 0 0 1-.6-.3L4.375 9.5H1.5v3.75c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25Z"/>"#,
        _ => r#"<path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Z"/>"#,
    };
    format!(
        r#"<svg class="sh-icon sh-icon-{name}" viewBox="0 0 16 16" width="{px}" height="{px}" fill="currentColor" aria-hidden="true">{body}</svg>"#
    )
}

fn layout(title: &str, user: Option<&str>, body: &str) -> Html<String> {
    let nav_user = match user {
        Some(u) => {
            let esc = html_escape(u);
            let initial = u
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".into());
            format!(
                r#"<a class="nav-link" href="/settings/tokens">Settings</a>
<a class="nav-link" href="/logout">Sign out</a>
<a class="avatar user" href="/{esc}" title="{esc}">{initial}</a>"#
            )
        }
        None => r#"<a class="nav-link" href="/login">Sign in</a>
<a class="btn btn-sm" href="/register">Sign up</a>"#
            .into(),
    };
    let logo = icon_sized("safehub-mark", 32);
    let magnifier = icon("search");
    let favicon = favicon_data_uri();
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title} · SafeHub</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;650&display=swap" rel="stylesheet"/>
<link rel="icon" href="{favicon}"/>
<link rel="stylesheet" href="/assets/app.css"/>
</head>
<body>
<header class="top">
  <div class="brand">
    <span class="mark" aria-hidden="true">{logo}</span>
    <a href="/">SafeHub</a>
    <span class="sub">member workspace</span>
  </div>
  <form class="search" method="get" action="/" role="search">
    <label class="sr-only" for="q">Search collab index</label>
    {magnifier}
    <input id="q" name="q" type="text" autocomplete="off" placeholder="Search issues and pull requests…"/>
  </form>
  <nav class="top-nav" aria-label="Account">{nav_user}</nav>
</header>
<main class="wrap">{body}</main>
<p class="footer-note">Member-local plaintext UI · decrypts on this machine only</p>
<script src="/assets/app.js"></script>
</body>
</html>"#
    ))
}

/// Repo header band: owner/name, visibility, tabs.
async fn repo_chrome(
    state: &crate::state::AppState,
    owner: &str,
    name: &str,
    active: &str,
) -> String {
    let private = safehub_storage::RepoDirectory::get_by_name(&*state.store, owner, name)
        .await
        .ok()
        .flatten()
        .map(|r| r.private)
        .unwrap_or(true);
    let idx = crate::collab::load(&state.data_root, owner, name)
        .await
        .unwrap_or_default();
    let open_issues = idx.issues.iter().filter(|i| i.state == "open").count();
    let open_pulls = idx.pulls.iter().filter(|p| p.state == "open").count();
    let o = html_escape(owner);
    let n = html_escape(name);
    let visibility = if private { "Private" } else { "Public" };
    format!(
        r#"<div class="repo-band">
<div class="repo-header">
<h1 class="repo-title">{repo_icon}<a href="/{o}">{o}</a><span class="sep">/</span><a class="repo-name" href="/{o}/{n}">{n}</a><span class="pill">{visibility}</span><span class="pill pill-enc">{lock}E2EE</span></h1>
<div class="repo-actions">
<a class="btn btn-sm" href="/{o}/{n}/settings/access">{people}Access</a>
<a class="btn btn-sm" href="/{o}/{n}/settings">{gear}Settings</a>
</div>
</div>
{tabs}
</div>"#,
        repo_icon = icon("repo"),
        lock = icon("lock"),
        people = icon("people"),
        gear = icon("gear"),
        tabs = repo_tabs(&o, &n, active, open_issues, open_pulls),
    )
}

fn repo_tabs(owner: &str, name: &str, active: &str, issues: usize, pulls: usize) -> String {
    let tabs = [
        ("code", "Code", "code", format!("/{owner}/{name}"), None),
        (
            "issues",
            "Issues",
            "issue-opened",
            format!("/{owner}/{name}/issues"),
            Some(issues),
        ),
        (
            "pulls",
            "Pull requests",
            "git-pull-request",
            format!("/{owner}/{name}/pulls"),
            Some(pulls),
        ),
        (
            "commits",
            "Commits",
            "git-commit",
            format!("/{owner}/{name}/commits"),
            None,
        ),
        (
            "actions",
            "Actions",
            "play",
            format!("/{owner}/{name}/actions"),
            None,
        ),
        (
            "projects",
            "Projects",
            "project",
            format!("/{owner}/{name}/projects"),
            None,
        ),
        ("wiki", "Wiki", "book", format!("/{owner}/{name}/wiki"), None),
        (
            "security",
            "Security",
            "shield",
            format!("/{owner}/{name}/security"),
            None,
        ),
        (
            "insights",
            "Insights",
            "graph",
            format!("/{owner}/{name}/insights"),
            None,
        ),
        (
            "packages",
            "Packages",
            "package",
            format!("/{owner}/{name}/packages"),
            None,
        ),
        (
            "settings",
            "Settings",
            "gear",
            format!("/{owner}/{name}/settings"),
            None,
        ),
    ];
    let mut out = String::from(r#"<nav class="repo-tabs" aria-label="Repository"><ul>"#);
    for (id, label, glyph, href, count) in tabs {
        let cls = if id == active { r#" class="active""# } else { "" };
        let badge = match count {
            Some(n) if n > 0 => format!(r#"<span class="counter">{n}</span>"#),
            _ => String::new(),
        };
        out.push_str(&format!(
            r#"<li{cls}><a href="{href}">{}<span>{label}</span>{badge}</a></li>"#,
            icon(glyph)
        ));
    }
    out.push_str("</ul></nav>");
    out
}

/// `1 comment` / `3 comments`.
fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// GitHub-style empty state box.
/// Render a blankslate page with a real 404 status, so a missing resource is
/// not advertised as a successful page.
fn not_found_page(user: Option<&str>, chrome: &str, glyph: &str, heading: &str, detail: &str) -> Response {
    let body = format!("{chrome}{}", blankslate(glyph, heading, detail));
    (
        axum::http::StatusCode::NOT_FOUND,
        layout("Not found", user, &body),
    )
        .into_response()
}

fn blankslate(glyph: &str, heading: &str, detail: &str) -> String {
    format!(
        r#"<div class="blankslate">{}<h3>{heading}</h3><p>{detail}</p></div>"#,
        icon_sized(glyph, 24)
    )
}

fn cookie_user(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("sh_user=") {
            return Some(urlencoding_decode(v));
        }
    }
    None
}

fn set_session(user: &str, token: &str) -> Response {
    let mut res = Redirect::to("/").into_response();
    let headers = res.headers_mut();
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("sh_user={user}; Path=/; HttpOnly; SameSite=Lax")
            .parse()
            .unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("sh_token={token}; Path=/; HttpOnly; SameSite=Lax")
            .parse()
            .unwrap(),
    );
    res
}

fn clear_session() -> Response {
    let mut res = Redirect::to("/login").into_response();
    let headers = res.headers_mut();
    headers.append(
        axum::http::header::SET_COOKIE,
        "sh_user=; Path=/; Max-Age=0".parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        "sh_token=; Path=/; Max-Age=0".parse().unwrap(),
    );
    res
}

fn urlencoding_decode(s: &str) -> String {
    s.replace("%40", "@")
}

/// `3 days ago` style stamp from an RFC 3339 timestamp (falls back to raw).
fn relative_time(ts: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return html_escape(ts);
    };
    let secs = (chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds();
    if secs < 0 {
        return "just now".into();
    }
    let (n, unit) = match secs {
        s if s < 60 => return "just now".into(),
        s if s < 3600 => (s / 60, "minute"),
        s if s < 86_400 => (s / 3600, "hour"),
        s if s < 2_592_000 => (s / 86_400, "day"),
        s if s < 31_536_000 => (s / 2_592_000, "month"),
        s => (s / 31_536_000, "year"),
    };
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{plural} ago")
}

/// Branch shown in the code-tab selector, read from the mirror's `HEAD`.
fn mirror_branch(root: &Path) -> String {
    std::fs::read_to_string(root.join(".git").join("HEAD"))
        .ok()
        .and_then(|s| {
            s.trim()
                .strip_prefix("ref: refs/heads/")
                .map(str::to_string)
        })
        .unwrap_or_else(|| "main".into())
}

async fn user_page(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    axum::extract::Path(owner): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let viewer = cookie_user(&headers);
    let uid = safehub_types::UserId(owner.clone());
    let repos = safehub_storage::RepoDirectory::list_for_user(&*state.store, &uid)
        .await
        .unwrap_or_default();
    let items = if repos.is_empty() {
        blankslate(
            "repo",
            "No repositories",
            "Nothing here is visible to you yet.",
        )
    } else {
        repo_cards(&repos)
    };
    let o = html_escape(&owner);
    let initial = owner
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());
    let body = format!(
        r#"<div class="profile">
<aside class="profile-side">
<div class="avatar avatar-xl">{initial}</div>
<h1 class="profile-name">{o}</h1>
<p class="muted">SafeHub member</p>
</aside>
<section class="profile-main">
<h2 class="section-title">Repositories</h2>
{items}
</section>
</div>"#
    );
    layout(&owner, viewer.as_deref(), &body)
}

fn repo_cards(repos: &[safehub_types::RepoRecord]) -> String {
    let rows: String = repos
        .iter()
        .map(|r| {
            let o = html_escape(&r.name.owner);
            let n = html_escape(&r.name.name);
            let vis = if r.private { "Private" } else { "Public" };
            format!(
                r#"<li><div class="repo-card-title"><a href="/{o}/{n}">{n}</a><span class="pill">{vis}</span></div>
<p class="muted">{o}/{n} · end-to-end encrypted</p></li>"#
            )
        })
        .collect();
    format!(r#"<ul class="dash repos">{rows}</ul>"#)
}

async fn home(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let user = cookie_user(&headers);
    let Some(u) = user.clone() else {
        let body = format!(
            r#"<div class="hero">
{logo}
<h1>Build and ship software on a private, encrypted host</h1>
<p class="hero-sub">SafeHub is a local, GitHub-shaped front end over end-to-end encrypted repositories.</p>
<p class="hero-actions"><a class="btn primary btn-lg" href="/register">Sign up for SafeHub</a>
<a class="btn btn-lg" href="/login">Sign in</a></p>
</div>"#,
            logo = icon_sized("safehub-mark", 48)
        );
        return layout("Home", None, &body);
    };

    let uid = safehub_types::UserId(u.clone());
    let repos = safehub_storage::RepoDirectory::list_for_user(&*state.store, &uid)
        .await
        .unwrap_or_default();
    let repo_panel = if repos.is_empty() {
        blankslate(
            "repo",
            "No repositories yet",
            "Create one with <code>sh repo create myrepo --clone</code>.",
        )
    } else {
        repo_cards(&repos)
    };
    let esc = html_escape(&u);
    let body = format!(
        r#"<div class="dash-grid">
<section class="dash-side">
<h2 class="section-title">Top repositories</h2>
{repo_panel}
<p><a class="btn primary btn-block" href="/settings/tokens/new">{plus}New token</a></p>
</section>
<section class="dash-main">
<h2 class="section-title">Home</h2>
<div class="box">
<div class="box-header">{inbox}<span>Signed in as <strong>{esc}</strong></span></div>
<div class="box-row"><a href="/settings/tokens">Personal access tokens</a></div>
<div class="box-row"><a href="/settings/billing">Billing</a><span class="muted">stub</span></div>
<div class="box-row"><a href="/codespaces">Codespaces</a><span class="muted">stub</span></div>
</div>
<p class="hint">Create repos via CLI: <code>sh repo create myrepo --clone</code></p>
<p class="hint">Data dir: {data}</p>
</section>
</div>"#,
        plus = icon("plus"),
        inbox = icon("inbox"),
        data = html_escape(&state.data_root.display().to_string()),
    );
    layout("Home", Some(&u), &body)
}

/// Centred single-column card used by sign-in / sign-up.
fn auth_card(heading: &str, inner: &str) -> String {
    format!(
        r#"<div class="auth-wrap">{logo}<h1 class="auth-heading">{heading}</h1>
<div class="auth-card">{inner}</div></div>"#,
        logo = icon_sized("safehub-mark", 48)
    )
}

async fn login_page(headers: axum::http::HeaderMap) -> impl IntoResponse {
    if cookie_user(&headers).is_some() {
        return Redirect::to("/").into_response();
    }
    let body = auth_card(
        "Sign in to SafeHub",
        r#"<form method="post" action="/login" class="auth-form">
<label>Username <input name="user" required/></label>
<label>Password <input name="password" type="password" required/></label>
<button class="btn primary btn-block" type="submit">Sign in</button>
</form>
<p class="auth-alt">New to SafeHub? <a href="/register">Create an account</a>.</p>"#,
    );
    layout("Sign in", None, &body).into_response()
}

#[derive(Deserialize)]
struct AuthForm {
    user: String,
    password: String,
}

async fn login_form(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    Form(form): Form<AuthForm>,
) -> Response {
    let mut auth = state.auth.write().await;
    if auth.verify_password(&form.user, &form.password).is_err() {
        let body = auth_card(
            "Sign in to SafeHub",
            r#"<div class="flash error">Incorrect username or password.</div>
<p class="auth-alt"><a href="/login">Try again</a></p>"#,
        );
        return layout("Sign in", None, &body).into_response();
    }
    match auth.issue_session(&form.user).await {
        Ok(tok) => set_session(&form.user, &tok.token),
        Err(_) => layout(
            "Error",
            None,
            &auth_card("Sign in", r#"<div class="flash error">Session error</div>"#),
        )
        .into_response(),
    }
}

async fn register_page() -> impl IntoResponse {
    let body = auth_card(
        "Create your account",
        r#"<form method="post" action="/register" class="auth-form">
<label>Username <input name="user" required/></label>
<label>Password <input name="password" type="password" required/></label>
<button class="btn primary btn-block" type="submit">Create account</button>
</form>
<p class="auth-alt">Already have an account? <a href="/login">Sign in</a>.</p>"#,
    );
    layout("Sign up", None, &body)
}

async fn register_form(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    Form(form): Form<AuthForm>,
) -> Response {
    let mut auth = state.auth.write().await;
    if let Err(e) = auth.register(&form.user, &form.password).await {
        let body = auth_card(
            "Create your account",
            &format!(
                r#"<div class="flash error">{}</div>
<p class="auth-alt"><a href="/register">Back</a></p>"#,
                html_escape(&e.to_string())
            ),
        );
        return layout("Sign up", None, &body).into_response();
    }
    match auth.issue_session(&form.user).await {
        Ok(tok) => set_session(&form.user, &tok.token),
        Err(_) => layout(
            "Error",
            None,
            &auth_card("Sign up", r#"<div class="flash error">Session error</div>"#),
        )
        .into_response(),
    }
}

async fn logout() -> Response {
    clear_session()
}

async fn tokens_page(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let auth = state.auth.read().await;
    let pats = auth.list_pats(&user);
    let mut rows = String::new();
    for p in &pats {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
            html_escape(&p.id),
            html_escape(&p.note),
            html_escape(&p.scopes.join(", ")),
            relative_time(&p.created_at)
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"4\" class=\"muted\">No tokens yet.</td></tr>".into();
    }
    let flash = if let Some(tok) = q.get("new") {
        format!(
            r##"<div class="flash ok" role="status">
<p><strong>Make sure to copy your personal access token now.</strong> You won’t be able to see it again!</p>
<code class="token-once" id="new-token">{}</code>
<button type="button" class="btn" data-copy="#new-token">Copy</button>
</div>"##,
            html_escape(tok)
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<h1 class="page-title">Developer settings</h1>
<nav class="subnav"><a class="active" href="/settings/tokens">Personal access tokens</a></nav>
{flash}
<div class="section-head">
<h2 class="section-title">Personal access tokens</h2>
<a class="btn primary btn-sm" href="/settings/tokens/new">Generate new token</a>
</div>
<p class="muted">Tokens authenticate the API and <code>sh</code> CLI — like GitHub PATs.</p>
<table class="data"><thead><tr><th>Id</th><th>Note</th><th>Scopes</th><th>Created</th></tr></thead>
<tbody>{rows}</tbody></table>
<pre class="hint"># CLI equivalent
sh auth token create --note ci
sh auth token list
sh auth token revoke shpat_…</pre>"#
    );
    layout("Tokens", Some(&user), &body).into_response()
}

async fn tokens_new_page(headers: axum::http::HeaderMap) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let body = r#"<h1 class="page-title">New personal access token</h1>
<p class="muted">GitHub-style token generation for SafeHub API / <code>sh</code>.</p>
<form method="post" action="/settings/tokens" class="auth-form token-form">
<label>Note <input name="note" placeholder="e.g. local demo" required/></label>
<fieldset>
<legend>Scopes</legend>
<label class="check"><input type="checkbox" name="scope_repo" checked/> <code>repo</code> — full repository access</label>
<label class="check"><input type="checkbox" name="scope_read_user" checked/> <code>read:user</code> — read user profile</label>
</fieldset>
<button class="btn primary" type="submit">Generate token</button>
<p class="auth-alt"><a href="/settings/tokens">Cancel</a></p>
</form>"#;
    layout("New token", Some(&user), body).into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    note: String,
    #[serde(default)]
    scope_repo: Option<String>,
    #[serde(default)]
    scope_read_user: Option<String>,
}

async fn tokens_create(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let mut scopes = Vec::new();
    if form.scope_repo.is_some() {
        scopes.push(crate::users::SCOPE_REPO.into());
    }
    if form.scope_read_user.is_some() {
        scopes.push(crate::users::SCOPE_READ_USER.into());
    }
    if scopes.is_empty() {
        return layout(
            "New token",
            Some(&user),
            r#"<h1 class="page-title">New personal access token</h1>
<div class="flash error">Select at least one scope.</div>
<p><a href="/settings/tokens/new">Back</a></p>"#,
        )
        .into_response();
    }
    let mut auth = state.auth.write().await;
    match auth.create_pat(&user, &form.note, scopes).await {
        Ok(rec) => {
            let loc = format!(
                "/settings/tokens?new={}",
                urlencoding_encode_component(&rec.token)
            );
            Redirect::to(&loc).into_response()
        }
        Err(e) => layout(
            "New token",
            Some(&user),
            &format!(
                r#"<h1 class="page-title">New token</h1><div class="flash error">{}</div>"#,
                html_escape(&e.to_string())
            ),
        )
        .into_response(),
    }
}

/// Shared "not a collaborator" page.
fn forbidden(user: &str, detail: &str) -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        layout(
            "Forbidden",
            Some(user),
            &blankslate("lock", "Access denied", detail),
        ),
    )
        .into_response()
}

/// A repository page for a name that does not exist: 404, not 403.
fn repo_not_found(user: &str, owner: &str, name: &str) -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        layout(
            "Not found",
            Some(user),
            &blankslate(
                "repo",
                "Repository not found",
                &format!("{}/{} does not exist.", html_escape(owner), html_escape(name)),
            ),
        ),
    )
        .into_response()
}

/// True when the directory has no record for `owner/name`.
async fn repo_missing(state: &crate::state::AppState, owner: &str, name: &str) -> bool {
    safehub_storage::RepoDirectory::get_by_name(&*state.store, owner, name)
        .await
        .ok()
        .flatten()
        .is_none()
}

async fn repo_code(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(
            &user,
            "You are not a collaborator on this repository — plaintext browse denied.",
        );
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let path = q.get("path").cloned().unwrap_or_default();
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .unwrap();
    let mut entries = crate::browse::list_tree(&root, &path).unwrap_or_default();
    // GitHub lists directories before files.
    entries.sort_by(|a, b| (a.entry_type != "dir").cmp(&(b.entry_type != "dir")));
    let commits = crate::browse::list_commits(&root, 500).unwrap_or_default();
    let branch = html_escape(&mirror_branch(&root));
    let tip = commits.first();
    let tip_when = tip.map(|c| relative_time(&c.date)).unwrap_or_default();
    let tip_msg = tip.map(|c| html_escape(&c.message)).unwrap_or_default();

    // File rows. The mirror does not track per-path history, so every row shows
    // the tip commit — the same column layout GitHub uses.
    let mut rows = String::new();
    if !path.is_empty() {
        let parent = path.rsplit_once('/').map(|(a, _)| a).unwrap_or("");
        rows.push_str(&format!(
            r#"<tr><td class="icon">{}</td><td colspan="3"><a href="/{o}/{n}?path={}">..</a></td></tr>"#,
            icon("file-directory"),
            html_escape(&urlencoding_encode(parent))
        ));
    }
    for e in &entries {
        let leaf = html_escape(e.path.rsplit('/').next().unwrap_or(&e.path));
        let href = html_escape(&urlencoding_encode(&e.path));
        let (glyph, link) = if e.entry_type == "dir" {
            ("file-directory", format!("/{o}/{n}?path={href}"))
        } else {
            ("file", format!("/{o}/{n}/blob?path={href}"))
        };
        rows.push_str(&format!(
            r#"<tr><td class="icon icon-{kind}">{}</td><td class="file-name"><a href="{link}">{leaf}</a></td><td class="file-msg muted">{tip_msg}</td><td class="file-age muted">{tip_when}</td></tr>"#,
            icon(glyph),
            kind = if e.entry_type == "dir" { "dir" } else { "file" },
        ));
    }
    let file_table = if rows.is_empty() {
        blankslate("file", "This directory is empty", "Nothing to show here.")
    } else {
        format!(
            r#"<div class="filebox">
<div class="filebox-head">
<span class="commit-author">{author}</span>
<a class="commit-msg" href="/{o}/{n}/commit/{sha}">{tip_msg}</a>
<span class="filebox-head-right"><a class="mono" href="/{o}/{n}/commit/{sha}">{short}</a><span class="muted">{tip_when}</span></span>
</div>
<div class="table-scroll"><table class="files"><tbody>{rows}</tbody></table></div>
</div>"#,
            author = tip.map(|c| html_escape(&c.author)).unwrap_or_default(),
            sha = tip.map(|c| html_escape(&c.sha)).unwrap_or_default(),
            short = tip
                .map(|c| html_escape(&c.sha[..7.min(c.sha.len())]))
                .unwrap_or_default(),
        )
    };

    // README panel, rendered below the file list like GitHub.
    let readme = entries
        .iter()
        .find(|e| {
            e.entry_type == "file"
                && e.path
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("README.md")
        })
        .and_then(|e| crate::browse::read_blob(&root, &e.path).ok())
        .map(|blob| {
            format!(
                r#"<div class="readme box">
<div class="box-header">{book}<strong>{path}</strong></div>
<div class="markdown">{md}</div>
</div>"#,
                book = icon("book"),
                path = html_escape(&blob.path),
                md = render_markdown(&blob.content)
            )
        })
        .unwrap_or_default();

    let crumbs = breadcrumb(&o, &n, &path);
    let body = format!(
        r#"{chrome}
<div class="file-nav">
<span class="branch-select">{branch_icon}<strong>{branch}</strong></span>
{crumbs}
<a class="file-nav-right" href="/{o}/{n}/commits">{history}<strong>{count}</strong> {word}</a>
</div>
{file_table}
{readme}"#,
        chrome = repo_chrome(&state, &owner, &name, "code").await,
        branch_icon = icon("git-branch"),
        history = icon("history"),
        count = commits.len(),
        word = if commits.len() == 1 { "commit" } else { "commits" },
    );
    layout(&format!("{owner}/{name}"), Some(&user), &body).into_response()
}

/// `name / sub / dir` breadcrumb for the code browser (empty at the root).
fn breadcrumb(owner_esc: &str, name_esc: &str, path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut out = format!(
        r#"<span class="breadcrumb"><a href="/{owner_esc}/{name_esc}">{name_esc}</a>"#
    );
    let mut acc = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        out.push_str(&format!(
            r#" / <a href="/{owner_esc}/{name_esc}?path={}">{}</a>"#,
            html_escape(&urlencoding_encode(&acc)),
            html_escape(seg)
        ));
    }
    out.push_str("</span>");
    out
}

async fn repo_blob(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(&user, "You are not a collaborator on this repository.");
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let path = q.get("path").cloned().unwrap_or_default();
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .unwrap();
    let chrome = repo_chrome(&state, &owner, &name, "code").await;
    let Ok(blob) = crate::browse::read_blob(&root, &path) else {
        return not_found_page(Some(&user), &chrome, "file", "File not found", "This path is not in the mirror.");
    };
    let lines: Vec<&str> = blob.content.lines().collect();
    let numbered: String = lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            format!(
                r#"<tr><td class="blob-num">{}</td><td class="blob-code">{}</td></tr>"#,
                i + 1,
                html_escape(line)
            )
        })
        .collect();
    let body = format!(
        r#"{chrome}
<div class="file-nav">{crumbs}</div>
<div class="filebox">
<div class="filebox-head">
<span>{lines} lines</span><span class="muted">·</span><span>{size} B</span>
<span class="filebox-head-right"><span class="muted mono">{sha}</span></span>
</div>
<div class="table-scroll"><table class="blob"><tbody>{numbered}</tbody></table></div>
</div>"#,
        crumbs = breadcrumb(&o, &n, &blob.path),
        lines = lines.len(),
        size = blob.size,
        sha = html_escape(&blob.sha[..12.min(blob.sha.len())]),
    );
    layout(&blob.path, Some(&user), &body).into_response()
}

async fn repo_commits(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(&user, "You are not a collaborator on this repository.");
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .unwrap();
    let commits = crate::browse::list_commits(&root, 50).unwrap_or_default();
    let list = if commits.is_empty() {
        blankslate("git-commit", "No commits yet", "Push to see history here.")
    } else {
        let items: String = commits
            .iter()
            .map(|c| {
                let sha = html_escape(&c.sha);
                format!(
                    r#"<li><div class="commit-main"><a class="commit-title" href="/{o}/{n}/commit/{sha}">{msg}</a>
<div class="muted commit-sub"><strong>{author}</strong> committed {when}</div></div>
<a class="btn btn-sm mono" href="/{o}/{n}/commit/{sha}">{short}</a></li>"#,
                    msg = html_escape(&c.message),
                    author = html_escape(&c.author),
                    when = relative_time(&c.date),
                    short = html_escape(&c.sha[..7.min(c.sha.len())]),
                )
            })
            .collect();
        format!(r#"<ul class="commits box">{items}</ul>"#)
    };
    let body = format!(
        r#"{chrome}<h2 class="section-title">Commits</h2>{list}"#,
        chrome = repo_chrome(&state, &owner, &name, "commits").await,
    );
    layout("Commits", Some(&user), &body).into_response()
}

async fn repo_commit(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name, sha)): axum::extract::Path<(String, String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(&user, "You are not a collaborator on this repository.");
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let root = crate::browse::ensure_mirror(&state.data_root, &owner, &name)
        .await
        .unwrap();
    let chrome = repo_chrome(&state, &owner, &name, "commits").await;
    let Ok(c) = crate::browse::commit_detail(&root, &sha) else {
        return not_found_page(Some(&user), &chrome, "git-commit", "Commit not found", "Unknown revision.");
    };
    let parents = if c.parents.is_empty() {
        r#"<span class="muted">none (root commit)</span>"#.to_string()
    } else {
        c.parents
            .iter()
            .map(|p| {
                format!(
                    r#"<a class="mono" href="/{o}/{n}/commit/{p}">{}</a> "#,
                    html_escape(&p[..7.min(p.len())]),
                    p = html_escape(p)
                )
            })
            .collect()
    };
    let body = format!(
        r#"{chrome}
<div class="box commit-detail">
<div class="box-header"><strong class="commit-headline">{msg}</strong></div>
<div class="box-row"><span class="avatar avatar-sm">{initial}</span><strong>{author}</strong>
<span class="muted">committed {when}</span>
<span class="box-row-right mono muted">{sha}</span></div>
<div class="box-row"><span class="muted">Parents:</span> {parents}</div>
</div>
<p><a href="/{o}/{n}/commits">← Back to history</a></p>"#,
        msg = html_escape(&c.message),
        author = html_escape(&c.author),
        when = relative_time(&c.date),
        sha = html_escape(&c.sha),
        initial = c
            .author
            .chars()
            .next()
            .map(|ch| ch.to_uppercase().to_string())
            .unwrap_or_else(|| "?".into()),
    );
    layout("Commit", Some(&user), &body).into_response()
}

/// Coloured state glyph + label for issues and PRs.
fn state_icon(kind: &str, state: &str) -> String {
    let (glyph, cls) = match (kind, state) {
        ("pull", "merged") => ("git-merge", "merged"),
        ("pull", "closed") => ("git-pull-request", "closed"),
        ("pull", _) => ("git-pull-request", "open"),
        (_, "closed") => ("issue-closed", "closed"),
        _ => ("issue-opened", "open"),
    };
    format!(
        r#"<span class="state-icon {cls}" title="{}">{}</span>"#,
        html_escape(state),
        icon(glyph)
    )
}

fn state_pill(kind: &str, state: &str) -> String {
    let (glyph, cls, label) = match (kind, state) {
        ("pull", "merged") => ("git-merge", "merged", "Merged"),
        ("pull", "closed") => ("git-pull-request", "closed", "Closed"),
        ("pull", _) => ("git-pull-request", "open", "Open"),
        (_, "closed") => ("issue-closed", "closed", "Closed"),
        _ => ("issue-opened", "open", "Open"),
    };
    format!(
        r#"<span class="state {cls}">{}{label}</span>"#,
        icon(glyph)
    )
}

async fn repo_issues(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(&user, "You are not a collaborator on this repository.");
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .unwrap_or_default();
    let open = idx.issues.iter().filter(|i| i.state == "open").count();
    let closed = idx.issues.len() - open;
    let list = if idx.issues.is_empty() {
        blankslate(
            "issue-opened",
            "Welcome to issues!",
            "Issues are created through the API or the <code>sh</code> CLI.",
        )
    } else {
        let items: String = idx
            .issues
            .iter()
            .map(|i| {
                format!(
                    r#"<li>{state}<div class="issue-main"><a class="issue-title" href="/{o}/{n}/issues/{id}">{title}</a>
<div class="issue-meta muted">#{id} opened {when} by {author}</div></div>
<span class="issue-side muted">{comments}</span></li>"#,
                    state = state_icon("issue", &i.state),
                    id = i.id,
                    title = html_escape(&i.title),
                    when = relative_time(&i.created_at),
                    author = html_escape(&i.author),
                    comments = if i.comments.is_empty() {
                        String::new()
                    } else {
                        format!("{}{}", icon("comment"), i.comments.len())
                    },
                )
            })
            .collect();
        format!(
            r#"<div class="box issue-list">
<div class="box-header"><span class="filter active">{oi}{open} Open</span><span class="filter">{ci}{closed} Closed</span></div>
<ul>{items}</ul>
</div>"#,
            oi = icon("issue-opened"),
            ci = icon("issue-closed"),
        )
    };
    let body = format!(
        r#"{chrome}
{list}
<pre class="hint"># Issues are member-local (MLS inbox), not stored as plaintext on the host.
sh issue create --repo {o}/{n} --title "bug"</pre>"#,
        chrome = repo_chrome(&state, &owner, &name, "issues").await,
    );
    layout("Issues", Some(&user), &body).into_response()
}

async fn repo_issue(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name, id)): axum::extract::Path<(String, String, u64)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .unwrap_or_default();
    let chrome = repo_chrome(&state, &owner, &name, "issues").await;
    let Some(issue) = idx.issues.iter().find(|i| i.id == id) else {
        return not_found_page(Some(&user), &chrome, "issue-opened", "Issue not found", "No such issue id.");
    };
    let mut comments = comment_box(
        &issue.author,
        &issue.created_at,
        &issue.body,
        "opened this issue",
    );
    for c in &issue.comments {
        comments.push_str(&comment_box(&c.author, &c.created_at, &c.body, "commented"));
    }
    let body = format!(
        r#"{chrome}
<div class="issue-head">
<h1 class="issue-headline">{title} <span class="issue-num">#{id}</span></h1>
<p class="issue-subhead">{pill} <span class="muted"><strong>{author}</strong> opened this issue {when} · {ncomments}</span></p>
</div>
{comments}"#,
        title = html_escape(&issue.title),
        pill = state_pill("issue", &issue.state),
        author = html_escape(&issue.author),
        when = relative_time(&issue.created_at),
        ncomments = plural(issue.comments.len(), "comment"),
    );
    layout("Issue", Some(&user), &body).into_response()
}

fn comment_box(author: &str, created_at: &str, body: &str, verb: &str) -> String {
    let initial = author
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());
    format!(
        r#"<div class="comment">
<div class="box-header"><span class="avatar avatar-sm">{initial}</span><strong>{a}</strong> <span class="muted">{verb} {when}</span></div>
<div class="markdown">{md}</div>
</div>"#,
        a = html_escape(author),
        when = relative_time(created_at),
        md = render_markdown(body),
    )
}

async fn repo_pulls(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    if repo_missing(&state, &owner, &name).await {
        return repo_not_found(&user, &owner, &name);
    }
    if deny_non_member(&state, &user, &owner, &name).await {
        return forbidden(&user, "You are not a collaborator on this repository.");
    }
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .unwrap_or_default();
    let open = idx.pulls.iter().filter(|p| p.state == "open").count();
    let closed = idx.pulls.len() - open;
    let list = if idx.pulls.is_empty() {
        blankslate(
            "git-pull-request",
            "Welcome to pull requests!",
            "Pull requests are created through the API or the <code>sh</code> CLI.",
        )
    } else {
        let items: String = idx
            .pulls
            .iter()
            .map(|p| {
                format!(
                    r#"<li>{state}<div class="issue-main"><a class="issue-title" href="/{o}/{n}/pulls/{id}">{title}</a>
<div class="issue-meta muted">#{id} opened {when} by {author} · <code>{base}</code> ← <code>{head}</code></div></div></li>"#,
                    state = state_icon("pull", &p.state),
                    id = p.id,
                    title = html_escape(&p.title),
                    when = relative_time(&p.created_at),
                    author = html_escape(&p.author),
                    base = html_escape(&p.base),
                    head = html_escape(&p.head),
                )
            })
            .collect();
        format!(
            r#"<div class="box issue-list">
<div class="box-header"><span class="filter active">{oi}{open} Open</span><span class="filter">{ci}{closed} Closed</span></div>
<ul>{items}</ul>
</div>"#,
            oi = icon("git-pull-request"),
            ci = icon("git-merge"),
        )
    };
    let body = format!(
        "{chrome}{list}",
        chrome = repo_chrome(&state, &owner, &name, "pulls").await,
    );
    layout("Pull requests", Some(&user), &body).into_response()
}

async fn repo_pull(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name, id)): axum::extract::Path<(String, String, u64)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let idx = crate::collab::load(&state.data_root, &owner, &name)
        .await
        .unwrap_or_default();
    let chrome = repo_chrome(&state, &owner, &name, "pulls").await;
    let Some(pr) = idx.pulls.iter().find(|i| i.id == id) else {
        return not_found_page(Some(&user), &chrome, "git-pull-request", "Pull request not found", "No such id.");
    };
    let mut comments = comment_box(&pr.author, &pr.created_at, &pr.body, "opened this pull request");
    for c in &pr.comments {
        comments.push_str(&comment_box(&c.author, &c.created_at, &c.body, "commented"));
    }
    let body = format!(
        r#"{chrome}
<div class="issue-head">
<h1 class="issue-headline">{title} <span class="issue-num">#{id}</span></h1>
<p class="issue-subhead">{pill} <span class="muted"><strong>{author}</strong> wants to merge <code>{head}</code> into <code>{base}</code></span></p>
</div>
{comments}"#,
        title = html_escape(&pr.title),
        pill = state_pill("pull", &pr.state),
        author = html_escape(&pr.author),
        head = html_escape(&pr.head),
        base = html_escape(&pr.base),
    );
    layout("Pull request", Some(&user), &body).into_response()
}

async fn repo_settings(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let body = format!(
        r#"{chrome}
<h2 class="section-title">Settings</h2>
<div class="box">
<div class="box-row">{people}<a href="/{o}/{n}/settings/access">Collaborators and teams</a></div>
<div class="box-row">{gear}<a href="/settings/tokens">Personal access tokens</a></div>
</div>"#,
        chrome = repo_chrome(&state, &owner, &name, "settings").await,
        people = icon("people"),
        gear = icon("gear"),
    );
    layout("Settings", Some(&user), &body).into_response()
}

async fn repo_access(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let Some(user) = cookie_user(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let o = html_escape(&owner);
    let n = html_escape(&name);
    let m = crate::browse::load_members(&state.data_root, &owner, &name)
        .await
        .unwrap_or_default();
    let mut rows = format!(
        "<tr><td>{}</td><td>owner</td><td>full</td></tr>",
        html_escape(&m.owner)
    );
    for e in &m.members {
        if e.user == m.owner {
            continue;
        }
        rows.push_str(&format!(
            "<tr><td>{}</td><td>collaborator</td><td>{}</td></tr>",
            html_escape(&e.user),
            html_escape(&e.history)
        ));
    }
    let body = format!(
        r#"{chrome}
<nav class="subnav"><a href="/{o}/{n}/settings">General</a><a class="active" href="/{o}/{n}/settings/access">Collaborators</a></nav>
<h2 class="section-title">Manage access</h2>
<table class="data"><thead><tr><th>User</th><th>Role</th><th>History</th></tr></thead>
<tbody>{rows}</tbody></table>
<pre class="hint"># Invite (full history)
curl -X POST -H "Authorization: Bearer $TOKEN" -d '{{"user":"bob","history":"full"}}' \
  /v1/repos/{o}/{n}/collaborators
# Invite forward-only
curl … -d '{{"user":"carol","history":"forward_only"}}' …</pre>"#,
        chrome = repo_chrome(&state, &owner, &name, "settings").await,
    );
    layout("Collaborators", Some(&user), &body).into_response()
}

async fn stub_page(
    state: &crate::state::AppState,
    user: Option<String>,
    owner: &str,
    name: &str,
    tab: &str,
    glyph: &str,
    feature: &str,
) -> Response {
    let Some(user) = user else {
        return Redirect::to("/login").into_response();
    };
    let body = format!(
        "{chrome}{}",
        blankslate(
            glyph,
            feature,
            "<strong>Not available in SafeHub.</strong> This tab mirrors GitHub navigation for \
             familiarity; the backend feature is out of scope for this research prototype.",
        ),
        chrome = repo_chrome(state, owner, name, tab).await,
    );
    layout(feature, Some(&user), &body).into_response()
}

async fn stub_actions(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "actions",
        "play",
        "Actions",
    )
    .await
}
async fn stub_projects(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "projects",
        "project",
        "Projects",
    )
    .await
}
async fn stub_wiki(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "wiki",
        "book",
        "Wiki",
    )
    .await
}
async fn stub_security(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "security",
        "shield",
        "Security",
    )
    .await
}
async fn stub_insights(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "insights",
        "graph",
        "Insights",
    )
    .await
}
async fn stub_packages(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((owner, name)): axum::extract::Path<(String, String)>,
) -> Response {
    stub_page(
        &state,
        cookie_user(&headers),
        &owner,
        &name,
        "packages",
        "package",
        "Packages",
    )
    .await
}

async fn stub_codespaces(headers: axum::http::HeaderMap) -> Response {
    let user = cookie_user(&headers);
    let body = format!(
        r#"<h1 class="page-title">Codespaces</h1>{}"#,
        blankslate(
            "code",
            "Codespaces",
            "<strong>Not available in SafeHub.</strong> Cloud dev environments are out of scope.",
        )
    );
    layout("Codespaces", user.as_deref(), &body).into_response()
}

async fn stub_billing(headers: axum::http::HeaderMap) -> Response {
    let user = cookie_user(&headers);
    let body = format!(
        r#"<h1 class="page-title">Billing and plans</h1>{}"#,
        blankslate(
            "package",
            "Billing",
            "<strong>Not available in SafeHub.</strong> Self-hosted; no billing.",
        )
    );
    layout("Billing", user.as_deref(), &body).into_response()
}

async fn deny_non_member(
    state: &crate::state::AppState,
    user: &str,
    owner: &str,
    name: &str,
) -> bool {
    let m = crate::browse::load_members(&state.data_root, owner, name)
        .await
        .unwrap_or_default();
    !crate::browse::is_member(&m, user)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Minimal CommonMark subset for README / issue bodies: headings, fenced code,
/// bullets, `code`, **bold**. Input is escaped before any markup is emitted.
fn render_markdown(src: &str) -> String {
    let mut out = String::new();
    let mut para: Vec<String> = Vec::new();
    let mut in_code = false;
    let mut in_list = false;

    fn flush_para(out: &mut String, para: &mut Vec<String>) {
        if !para.is_empty() {
            out.push_str(&format!("<p>{}</p>", para.join(" ")));
            para.clear();
        }
    }

    for line in src.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim_start().starts_with("```") {
            flush_para(&mut out, &mut para);
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            out.push_str(if in_code { "</code></pre>" } else { "<pre><code>" });
            in_code = !in_code;
            continue;
        }
        if in_code {
            out.push_str(&html_escape(trimmed));
            out.push('\n');
            continue;
        }
        if trimmed.trim().is_empty() {
            flush_para(&mut out, &mut para);
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            flush_para(&mut out, &mut para);
            if !in_list {
                out.push_str("<ul>");
                in_list = true;
            }
            out.push_str(&format!("<li>{}</li>", inline_markdown(rest)));
            continue;
        }
        if in_list {
            out.push_str("</ul>");
            in_list = false;
        }
        let hashes = trimmed.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
            flush_para(&mut out, &mut para);
            let level = hashes.min(4);
            out.push_str(&format!(
                "<h{level}>{}</h{level}>",
                inline_markdown(trimmed[hashes + 1..].trim())
            ));
            continue;
        }
        para.push(inline_markdown(trimmed));
    }
    flush_para(&mut out, &mut para);
    if in_list {
        out.push_str("</ul>");
    }
    if in_code {
        out.push_str("</code></pre>");
    }
    out
}

/// Escape, then apply `` `code` `` and `**bold**` spans.
fn inline_markdown(s: &str) -> String {
    let escaped = html_escape(s);
    let coded = wrap_alternating(&escaped, "`", "code");
    wrap_alternating(&coded, "**", "strong")
}

fn wrap_alternating(s: &str, delim: &str, tag: &str) -> String {
    let parts: Vec<&str> = s.split(delim).collect();
    if parts.len() < 3 {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for (i, part) in parts.iter().enumerate() {
        // Trailing unmatched delimiter: emit the raw text back.
        if i % 2 == 1 && i == parts.len() - 1 {
            out.push_str(delim);
            out.push_str(part);
        } else if i % 2 == 1 {
            out.push_str(&format!("<{tag}>{part}</{tag}>"));
        } else {
            out.push_str(part);
        }
    }
    out
}

fn urlencoding_encode(s: &str) -> String {
    s.replace(' ', "%20")
}

fn urlencoding_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn css() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        include_str!("ui_static/app.css"),
    )
}

async fn js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("ui_static/app.js"),
    )
}
