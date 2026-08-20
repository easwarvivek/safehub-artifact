//! Axum routes for the local repository browser.

use crate::git::Repo;
use crate::remote::RemoteMirror;
use crate::html::{
    self, breadcrumb, code_with_lines, decode_ref, encode_path_seg_path, encode_ref, escape,
    format_size, layout, render_diff_html, render_markdown, short_date, state_pill, tabs, CSS,
};
use axum::extract::{Form, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewMode {
    Local,
    Remote,
}

#[derive(Clone)]
pub struct AppState {
    pub repo: Arc<Repo>,
    pub local: Arc<Repo>,
    pub remote: RemoteMirror,
    pub mode: ViewMode,
}

impl AppState {
    pub fn new(repo: Arc<Repo>) -> Self {
        Self {
            local: repo.clone(),
            repo,
            remote: RemoteMirror::default(),
            mode: ViewMode::Local,
        }
    }

    fn prefix(&self) -> &'static str {
        if self.mode == ViewMode::Remote {
            "/remote"
        } else {
            ""
        }
    }

    fn with_remote_repo(&self, repo: Arc<Repo>) -> Self {
        Self {
            repo,
            local: self.local.clone(),
            remote: self.remote.clone(),
            mode: ViewMode::Remote,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/assets/browse.css", get(css))
        .route("/login", get(login_page).post(login_form))
        .route("/logout", get(logout))
        .route("/tree/{rev}", get(tree_root))
        .route("/tree/{rev}/{*path}", get(tree_or_blob))
        .route("/blob/{rev}/{*path}", get(blob))
        .route("/commits/{rev}", get(commits))
        .route("/commit/{sha}", get(commit))
        .route("/branches", get(branches))
        .route("/tags", get(tags))
        .route("/issues", get(issues_list).post(issue_create))
        .route("/issues/{id}", get(issue_detail).post(issue_action))
        .route("/pulls", get(pulls_list).post(pr_create))
        .route("/pulls/{id}", get(pull_detail).post(pr_action))
        .route("/settings", get(settings_page))
        .route("/settings/access", get(access_page).post(access_action))
        .route("/remote", get(remote_home))
        .route("/remote/fetch", post(remote_fetch))
        .route("/remote/tree/{rev}", get(remote_tree_root))
        .route("/remote/tree/{rev}/{*path}", get(remote_tree_or_blob))
        .route("/remote/blob/{rev}/{*path}", get(remote_blob))
        .route("/remote/commits/{rev}", get(remote_commits))
        .route("/remote/commit/{sha}", get(remote_commit))
        .route("/remote/branches", get(remote_branches))
        .route("/remote/tags", get(remote_tags))
        .with_state(state)
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        CSS,
    )
}

async fn home(State(st): State<AppState>) -> Response {
    match st.repo.default_ref() {
        Ok(rev) => Redirect::temporary(&format!("{}{}", st.prefix(), format!("/tree/{}", encode_ref(&rev)))).into_response(),
        Err(e) => error_page(&st, StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn tree_root(State(st): State<AppState>, Path(rev): Path<String>) -> Response {
    tree_page(&st, &decode_ref(&rev), "").await
}

async fn tree_or_blob(
    State(st): State<AppState>,
    Path((rev, path)): Path<(String, String)>,
) -> Response {
    let rev = decode_ref(&rev);
    let path = decode_path(&path);
    match st.repo.path_is_tree(&rev, &path) {
        Ok(true) => tree_page(&st, &rev, &path).await,
        Ok(false) => {
            Redirect::temporary(&format!(
                "{}/blob/{}/{}",
                st.prefix(),
                encode_ref(&rev),
                encode_path_seg_path(&path)
            ))
            .into_response()
        }
        Err(e) => error_page(&st, StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn blob(
    State(st): State<AppState>,
    Path((rev, path)): Path<(String, String)>,
) -> Response {
    let rev = decode_ref(&rev);
    let path = decode_path(&path);
    blob_page(&st, &rev, &path)
}

async fn commits(State(st): State<AppState>, Path(rev): Path<String>) -> Response {
    let rev = decode_ref(&rev);
    commits_page(&st, &rev)
}

async fn commit(State(st): State<AppState>, Path(sha): Path<String>) -> Response {
    commit_page(&st, &decode_ref(&sha))
}

async fn branches(State(st): State<AppState>) -> Response {
    branches_page(&st)
}

async fn tags(State(st): State<AppState>) -> Response {
    tags_page(&st)
}

async fn remote_state(st: &AppState) -> Result<AppState, Response> {
    match st.remote.repo().await {
        Some(repo) => Ok(st.with_remote_repo(repo)),
        None => Err(remote_landing(st, None).await),
    }
}

async fn remote_home(State(st): State<AppState>) -> Response {
    if let Some(repo) = st.remote.repo().await {
        let remote = st.with_remote_repo(repo);
        return home(State(remote)).await;
    }
    remote_landing(&st, None).await
}

async fn remote_fetch(State(st): State<AppState>) -> Response {
    match st.remote.fetch(&st.local).await {
        Ok(repo) => {
            let remote = st.with_remote_repo(repo);
            match remote.repo.default_ref() {
                Ok(rev) => Redirect::to(&format!("/remote/tree/{}", encode_ref(&rev))).into_response(),
                Err(e) => remote_landing(&st, Some(e.to_string())).await,
            }
        }
        Err(e) => remote_landing(&st, Some(format!("{e:#}"))).await,
    }
}

async fn remote_tree_root(State(st): State<AppState>, Path(rev): Path<String>) -> Response {
    match remote_state(&st).await {
        Ok(remote) => tree_page(&remote, &decode_ref(&rev), "").await,
        Err(response) => response,
    }
}

async fn remote_tree_or_blob(
    State(st): State<AppState>,
    Path(path): Path<(String, String)>,
) -> Response {
    match remote_state(&st).await {
        Ok(remote) => tree_or_blob(State(remote), Path(path)).await,
        Err(response) => response,
    }
}

async fn remote_blob(
    State(st): State<AppState>,
    Path(path): Path<(String, String)>,
) -> Response {
    match remote_state(&st).await {
        Ok(remote) => blob(State(remote), Path(path)).await,
        Err(response) => response,
    }
}

async fn remote_commits(State(st): State<AppState>, Path(rev): Path<String>) -> Response {
    match remote_state(&st).await {
        Ok(remote) => commits(State(remote), Path(rev)).await,
        Err(response) => response,
    }
}

async fn remote_commit(State(st): State<AppState>, Path(sha): Path<String>) -> Response {
    match remote_state(&st).await {
        Ok(remote) => commit(State(remote), Path(sha)).await,
        Err(response) => response,
    }
}

async fn remote_branches(State(st): State<AppState>) -> Response {
    match remote_state(&st).await {
        Ok(remote) => branches_page(&remote),
        Err(response) => response,
    }
}

async fn remote_tags(State(st): State<AppState>) -> Response {
    match remote_state(&st).await {
        Ok(remote) => tags_page(&remote),
        Err(response) => response,
    }
}

async fn remote_landing(st: &AppState, explicit_error: Option<String>) -> Response {
    let status = st.remote.status().await;
    let error = explicit_error.or(status.error);
    let error_html = error
        .map(|e| format!(r#"<div class="error"><strong>SafeHub fetch unavailable</strong><p>{}</p><p>The local repository was not modified.</p></div>"#, escape(&e)))
        .unwrap_or_default();
    let summary = status
        .summary
        .map(|s| format!(r#"<p class="muted">{}</p>"#, escape(&s)))
        .unwrap_or_default();
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let body = format!(
        r#"{header}{tabs}
{error}
<div class="panel" style="padding:1.25rem">
  <h2>Remote SafeHub view</h2>
  <p>Fetch and decrypt the published SafeHub tip into an isolated bare mirror. Your working tree and local refs are not changed.</p>
  {summary}
  <form method="post" action="/remote/fetch"><button class="btn primary" type="submit">Fetch from SafeHub</button></form>
</div>"#,
        header = repo_header_as(st, &rev, ViewMode::Remote),
        tabs = tabs("code", &rev, ""),
        error = error_html,
        summary = summary
    );
    Html(layout("Remote SafeHub view", st.local.name(), &body)).into_response()
}

fn decode_path(path: &str) -> String {
    path.split('/')
        .map(html::percent_decode)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn repo_header(st: &AppState, rev: &str) -> String {
    repo_header_as(st, rev, st.mode)
}

fn repo_header_as(st: &AppState, rev: &str, view: ViewMode) -> String {
    let name = escape(st.repo.name());
    let (mode, source) = if view == ViewMode::Remote {
        (
            "Remote (SafeHub)",
            "Fetched from the host as ciphertext, decrypted on this device.",
        )
    } else {
        ("Local", "Read from this machine's git objects.")
    };
    format!(
        r#"<div class="repo-header">
  <h1>{name} <span class="slash">·</span> <span class="muted">{mode}</span></h1>
  <div>{switch} <span class="pill">at <code>{rev}</code></span></div>
</div>
<p class="view-note muted">{source}</p>"#,
        name = name,
        rev = escape(rev),
        mode = mode,
        source = source,
        switch = view_switch(view)
    )
}

/// Two-state Local | Remote control. Local is the default view; Remote routes
/// through a fetch that decrypts on this device before anything is rendered.
fn view_switch(mode: ViewMode) -> String {
    let (local, remote) = match mode {
        ViewMode::Local => (" active\" aria-current=\"page", ""),
        ViewMode::Remote => ("", " active\" aria-current=\"page"),
    };
    format!(
        r#"<span class="view-switch" role="group" aria-label="Repository view">
<a class="seg{local}" href="/" title="Local client workspace">Local</a>
<a class="seg{remote}" href="/remote" title="Fetch from SafeHub, decrypt locally, then show">Remote</a>
</span>"#
    )
}

fn branch_switcher(st: &AppState, current: &str) -> String {
    let branches = st.repo.list_branches().unwrap_or_default();
    let mut out = String::from(
        r##"<form class="toolbar" method="get" action="#" onsubmit="return false;">
<label class="muted" for="branch">Branch</label>
<select class="branch-select" id="branch" onchange="if(this.value) location.href=this.value">"##,
    );
    let mut found = false;
    for b in &branches {
        if b.remote {
            continue;
        }
        let selected = if b.name == current {
            found = true;
            " selected"
        } else {
            ""
        };
        out.push_str(&format!(
            r#"<option value="{}/tree/{}"{selected}>{}</option>"#,
            st.prefix(),
            encode_ref(&b.name),
            escape(&b.name),
            selected = selected
        ));
    }
    // Include remotes in a second group.
    let remotes: Vec<_> = branches.iter().filter(|b| b.remote).collect();
    if !remotes.is_empty() {
        out.push_str(r#"<optgroup label="Remote tracking">"#);
        for b in remotes {
            let selected = if b.name == current {
                found = true;
                " selected"
            } else {
                ""
            };
            out.push_str(&format!(
                r#"<option value="{}/tree/{}"{selected}>{}</option>"#,
                st.prefix(),
                encode_ref(&b.name),
                escape(&b.name),
                selected = selected
            ));
        }
        out.push_str("</optgroup>");
    }
    if !found {
        out.push_str(&format!(
            r#"<option value="{}/tree/{}" selected>{}</option>"#,
            st.prefix(),
            encode_ref(current),
            escape(current)
        ));
    }
    out.push_str("</select>");
    out.push_str(&format!(
        r#" <a class="btn" href="{}/commits/{}">History</a></form>"#,
        st.prefix(),
        encode_ref(current)
    ));
    out
}

async fn tree_page(st: &AppState, rev: &str, path: &str) -> Response {
    if let Err(e) = st.repo.resolve_ref(rev) {
        return error_page(st, StatusCode::NOT_FOUND, &e.to_string());
    }
    let entries = match st.repo.list_tree(rev, path) {
        Ok(e) => e,
        Err(e) => return error_page(st, StatusCode::NOT_FOUND, &e.to_string()),
    };

    let last = st
        .repo
        .last_commit_for_path(rev, path)
        .ok()
        .flatten();

    let mut banner = String::new();
    if let Some(c) = &last {
        banner = format!(
            r#"<div class="commit-banner">
  <div><span class="msg">{}</span>
  <div class="meta">{} · {}</div></div>
  <div class="meta"><a href="{}/commit/{}">{}</a></div>
</div>"#,
            escape(&c.subject),
            escape(&c.author),
            escape(&short_date(&c.date)),
            st.prefix(),
            encode_ref(&c.sha),
            escape(&c.short)
        );
    }

    let mut table = String::from(r#"<table class="files"><tbody>"#);
    if !path.is_empty() {
        let parent = path.rsplit_once('/').map(|(a, _)| a).unwrap_or("");
        let href = if parent.is_empty() {
            format!("{}/tree/{}", st.prefix(), encode_ref(rev))
        } else {
            format!(
                "{}/tree/{}/{}",
                st.prefix(),
                encode_ref(rev),
                encode_path_seg_path(parent)
            )
        };
        table.push_str(&format!(
            r#"<tr><td class="icon icon-dir"></td><td class="name"><a href="{href}">..</a></td><td class="meta"></td></tr>"#
        ));
    }

    let mut readme_html = String::new();
    for e in &entries {
        let is_dir = e.entry_type == "tree";
        let icon = if is_dir { "icon-dir" } else { "icon-file" };
        let href = if is_dir {
            format!(
                "{}/tree/{}/{}",
                st.prefix(),
                encode_ref(rev),
                encode_path_seg_path(&e.path)
            )
        } else {
            format!(
                "{}/blob/{}/{}",
                st.prefix(),
                encode_ref(rev),
                encode_path_seg_path(&e.path)
            )
        };
        table.push_str(&format!(
            r#"<tr><td class="icon {icon}"></td><td class="name"><a href="{href}">{name}</a></td><td class="meta">{size}</td></tr>"#,
            icon = icon,
            href = href,
            name = escape(&e.name),
            size = if is_dir {
                String::new()
            } else {
                format_size(e.size)
            }
        ));

        if path.is_empty()
            && !is_dir
            && (e.name.eq_ignore_ascii_case("README.md")
                || e.name.eq_ignore_ascii_case("README"))
            && readme_html.is_empty()
        {
            if let Ok(blob) = st.repo.read_blob(rev, &e.path) {
                if !blob.binary {
                    let body = if e.name.to_ascii_lowercase().ends_with(".md") {
                        render_markdown(&blob.content)
                    } else {
                        format!("<pre>{}</pre>", escape(&blob.content))
                    };
                    readme_html = format!(
                        r#"<section class="readme"><div class="readme-h">{}</div><div class="readme-body">{}</div></section>"#,
                        escape(&e.name),
                        body
                    );
                }
            }
        }
    }
    table.push_str("</tbody></table>");

    let title = if path.is_empty() {
        st.repo.name().to_string()
    } else {
        format!("{} · {}", st.repo.name(), path)
    };
    let body = format!(
        r#"{header}{tabs}
{switcher}
{crumb}
<div class="panel">{banner}{table}</div>
{readme}"#,
        header = repo_header(st, rev),
        tabs = tabs("code", rev, st.prefix()),
        switcher = branch_switcher(st, rev),
        crumb = breadcrumb(rev, path, false, st.prefix()),
        banner = banner,
        table = table,
        readme = readme_html
    );
    Html(layout(&title, st.repo.name(), &body)).into_response()
}

fn blob_page(st: &AppState, rev: &str, path: &str) -> Response {
    let blob = match st.repo.read_blob(rev, path) {
        Ok(b) => b,
        Err(e) => return error_page(st, StatusCode::NOT_FOUND, &e.to_string()),
    };
    let content = if blob.binary {
        format!(
            r#"<pre class="code">{}</pre>"#,
            escape(&blob.content)
        )
    } else if path.to_ascii_lowercase().ends_with(".md") {
        format!(
            r#"<div class="readme-body">{}</div>"#,
            render_markdown(&blob.content)
        )
    } else {
        format!(r#"<div class="code">{}</div>"#, code_with_lines(&blob.content))
    };
    let body = format!(
        r#"{header}{tabs}
{switcher}
{crumb}
<div class="panel blob-wrap">
  <div class="blob-meta"><span>{path}</span><span>{size} · {sha}</span></div>
  {content}
</div>"#,
        header = repo_header(st, rev),
        tabs = tabs("code", rev, st.prefix()),
        switcher = branch_switcher(st, rev),
        crumb = breadcrumb(rev, path, true, st.prefix()),
        path = escape(path),
        size = format_size(Some(blob.size)),
        sha = escape(&blob.sha.chars().take(12).collect::<String>()),
        content = content
    );
    Html(layout(
        &format!("{} · {}", st.repo.name(), path),
        st.repo.name(),
        &body,
    ))
    .into_response()
}

fn commits_page(st: &AppState, rev: &str) -> Response {
    let list = match st.repo.list_commits(rev, 100) {
        Ok(c) => c,
        Err(e) => return error_page(st, StatusCode::NOT_FOUND, &e.to_string()),
    };
    let mut items = String::from(r#"<ul class="commits">"#);
    for c in &list {
        items.push_str(&format!(
            r#"<li>
  <div>
    <div class="subject"><a href="{prefix}/commit/{sha}">{}</a></div>
    <div class="who">{} committed on {}</div>
  </div>
  <div class="sha"><a href="{prefix}/commit/{sha}">{}</a></div>
</li>"#,
            escape(&c.subject),
            escape(&c.author),
            escape(&short_date(&c.date)),
            escape(&c.short),
            prefix = st.prefix(),
            sha = encode_ref(&c.sha)
        ));
    }
    items.push_str("</ul>");
    if list.is_empty() {
        items = r#"<p class="muted" style="padding:1rem">No commits on this ref.</p>"#.into();
    }
    let body = format!(
        r#"{header}{tabs}
{switcher}
<div class="panel">{items}</div>"#,
        header = repo_header(st, rev),
        tabs = tabs("commits", rev, st.prefix()),
        switcher = branch_switcher(st, rev),
        items = items
    );
    Html(layout(
        &format!("Commits · {}", st.repo.name()),
        st.repo.name(),
        &body,
    ))
    .into_response()
}

fn commit_page(st: &AppState, sha: &str) -> Response {
    let detail = match st.repo.commit_detail(sha) {
        Ok(d) => d,
        Err(e) => return error_page(st, StatusCode::NOT_FOUND, &e.to_string()),
    };
    let c = &detail.commit;
    let mut parents = String::from(r#"<div class="parents">Parents: "#);
    if c.parents.is_empty() {
        parents.push_str("<span class=\"muted\">none (root)</span>");
    } else {
        for (i, p) in c.parents.iter().enumerate() {
            if i > 0 {
                parents.push(' ');
            }
            parents.push_str(&format!(
                r#"<a href="{}/commit/{}">{}</a>"#,
                st.prefix(),
                encode_ref(p),
                escape(&p.chars().take(7).collect::<String>())
            ));
        }
    }
    parents.push_str("</div>");

    let mut files = String::from(r#"<ul class="diff-files">"#);
    for f in &detail.files {
        files.push_str(&format!(
            "<li><code>{}</code> {}</li>",
            escape(&f.status),
            escape(&f.path)
        ));
    }
    files.push_str("</ul>");

    let rev = st.repo.default_ref().unwrap_or_else(|_| c.sha.clone());
    let body = format!(
        r#"{header}{tabs}
<article class="commit-detail">
  <h2 class="subject">{}</h2>
  <div class="meta">{} &lt;{}&gt; · {} · <code>{}</code></div>
  {parents}
  <h3>Files</h3>
  {files}
  <h3>Diff</h3>
  {diff}
</article>"#,
        escape(&c.subject),
        escape(&c.author),
        escape(&c.email),
        escape(&short_date(&c.date)),
        escape(&c.sha),
        header = repo_header(st, &rev),
        tabs = tabs("commits", &rev, st.prefix()),
        parents = parents,
        files = files,
        diff = render_diff_html(&detail.patch)
    );
    Html(layout(
        &format!("{} · {}", c.short, st.repo.name()),
        st.repo.name(),
        &body,
    ))
    .into_response()
}

fn branches_page(st: &AppState) -> Response {
    let list = match st.repo.list_branches() {
        Ok(b) => b,
        Err(e) => return error_page(st, StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let rev = st.repo.default_ref().unwrap_or_else(|_| "HEAD".into());
    let mut items = String::from(r#"<ul class="branch-list">"#);
    for b in &list {
        let badge = if b.current {
            r#"<span class="badge current">current</span>"#
        } else if b.remote {
            r#"<span class="badge">remote</span>"#
        } else {
            ""
        };
        items.push_str(&format!(
            r#"<li>
  <div><a href="{prefix}/tree/{}"><strong>{}</strong></a>{badge}</div>
  <div class="muted"><a href="{prefix}/commit/{}">{}</a> · <a href="{prefix}/commits/{}">commits</a></div>
</li>"#,
            encode_ref(&b.name),
            escape(&b.name),
            encode_ref(&b.sha),
            escape(&b.sha.chars().take(7).collect::<String>()),
            encode_ref(&b.name),
            prefix = st.prefix(),
            badge = badge
        ));
    }
    items.push_str("</ul>");
    let body = format!(
        r#"{header}{tabs}
<div class="panel">{items}</div>"#,
        header = repo_header(st, &rev),
        tabs = tabs("branches", &rev, st.prefix()),
        items = items
    );
    Html(layout(
        &format!("Branches · {}", st.repo.name()),
        st.repo.name(),
        &body,
    ))
    .into_response()
}

fn tags_page(st: &AppState) -> Response {
    let list = match st.repo.list_tags() {
        Ok(t) => t,
        Err(e) => return error_page(st, StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let rev = st.repo.default_ref().unwrap_or_else(|_| "HEAD".into());
    let mut items = String::from(r#"<ul class="tag-list">"#);
    if list.is_empty() {
        items.push_str(r#"<li class="muted">No tags in this repository.</li>"#);
    }
    for t in &list {
        items.push_str(&format!(
            r#"<li>
  <div><a href="{prefix}/tree/{}"><strong>{}</strong></a></div>
  <div class="muted"><a href="{prefix}/commit/{}">{}</a></div>
</li>"#,
            encode_ref(&t.name),
            escape(&t.name),
            encode_ref(&t.sha),
            escape(&t.sha.chars().take(7).collect::<String>()),
            prefix = st.prefix()
        ));
    }
    items.push_str("</ul>");
    let body = format!(
        r#"{header}{tabs}
<div class="panel">{items}</div>"#,
        header = repo_header(st, &rev),
        tabs = tabs("tags", &rev, st.prefix()),
        items = items
    );
    Html(layout(
        &format!("Tags · {}", st.repo.name()),
        st.repo.name(),
        &body,
    ))
    .into_response()
}

fn error_page(st: &AppState, status: StatusCode, msg: &str) -> Response {
    let rev = st.repo.default_ref().unwrap_or_else(|_| "HEAD".into());
    let body = format!(
        r#"{header}{tabs}
<div class="error"><strong>Error</strong><p>{}</p><p><a href="{prefix}/">Back to repository</a></p></div>"#,
        escape(msg),
        header = repo_header(st, &rev),
        tabs = tabs("code", &rev, st.prefix()),
        prefix = st.prefix(),
    );
    (
        status,
        Html(layout("Error", st.repo.name(), &body)),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AuthForm {
    user: String,
    secret: String,
}

async fn login_page(State(st): State<AppState>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let body = format!(
        r#"{header}{tabs}
<div class="auth-card">
  <h2>Sign in to SafeHub</h2>
  <p class="muted">Uses the same credentials as <code>sh auth login</code> (stored on this device).</p>
  <form class="form-grid" method="post" action="/login">
    <label for="user">Username</label>
    <input id="user" name="user" required autocomplete="username"/>
    <label for="secret">Password</label>
    <input id="secret" name="secret" type="password" required autocomplete="current-password"/>
    <button class="btn primary" type="submit">Sign in</button>
  </form>
</div>"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("code", &rev, ""),
    );
    Html(layout("Sign in", st.local.name(), &body)).into_response()
}

async fn login_form(State(st): State<AppState>, Form(form): Form<AuthForm>) -> Response {
    let cfg = match safehub_client::ClientConfig::load() {
        Ok(c) => c,
        Err(e) => return error_page(&st, StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut client = match safehub_client::HttpClient::new(&cfg, None) {
        Ok(c) => c,
        Err(e) => return error_page(&st, StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    match client.login(&form.user, &form.secret).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => {
            let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
            let body = format!(
                r#"{header}{tabs}
<div class="error"><strong>Sign in failed</strong><p>{}</p><p><a href="/login">Try again</a></p></div>"#,
                escape(&e.to_string()),
                header = repo_header_as(&st, &rev, ViewMode::Local),
                tabs = tabs("code", &rev, ""),
            );
            (StatusCode::UNAUTHORIZED, Html(layout("Sign in", st.local.name(), &body))).into_response()
        }
    }
}

async fn logout() -> Response {
    let _ = safehub_client::Credentials::load().ok().flatten().map(|_| {
        let path = safehub_client::ClientConfig::config_dir()
            .ok()
            .map(|d| d.join("credentials.json"));
        if let Some(p) = path {
            let _ = std::fs::remove_file(p);
        }
    });
    Redirect::to("/").into_response()
}

async fn issues_list(State(st): State<AppState>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let folded = crate::collab::load_folded(st.local.root()).await;
    let (list_html, note) = match folded {
        Ok((_record, issues, _)) => {
            let open = issues.iter().filter(|i| i.state == "open").count();
            let closed = issues.len() - open;
            if issues.is_empty() {
                (
                    r#"<div class="blankslate"><h3>No issues yet</h3><p>Create one below. Bodies and comments are sealed under MLS — the host never sees plaintext.</p></div>"#.to_string(),
                    String::new(),
                )
            } else {
                let mut items = String::from(r#"<ul class="issue-list">"#);
                for i in &issues {
                    items.push_str(&format!(
                        r#"<li>{pill}<div class="issue-main"><a class="issue-title" href="/issues/{id}">{title}</a>
<div class="issue-meta">#{id} · {state} · {n} encrypted {noun}</div></div></li>"#,
                        pill = state_pill("issue", &i.state),
                        id = escape(&i.id),
                        title = escape(&i.title),
                        state = escape(&i.state),
                        n = i.comments.len(),
                        noun = if i.comments.len() == 1 {
                            "comment"
                        } else {
                            "comments"
                        },
                    ));
                }
                items.push_str("</ul>");
                (
                    format!(
                        r#"<div class="panel"><div class="commit-banner"><span>{open} open · {closed} closed</span><span class="muted">MLS inbox</span></div>{items}</div>"#
                    ),
                    String::new(),
                )
            }
        }
        Err(e) => (
            format!(
                r#"<div class="error"><strong>Issues unavailable</strong><p>{}</p>
<p>Need a SafeHub checkout (<code>.git/safehub/repo.json</code>), login, and MLS epoch keys.</p></div>"#,
                escape(&format!("{e:#}"))
            ),
            String::new(),
        ),
    };
    let form = r#"<div class="panel" style="margin-top:1rem"><form class="form-grid" method="post" action="/issues">
<label for="title">New issue title</label>
<input id="title" name="title" required/>
<label for="body">Body</label>
<textarea id="body" name="body"></textarea>
<button class="btn primary" type="submit">Create encrypted issue</button>
</form></div>"#;
    let body = format!(
        r#"{header}{tabs}
<p class="view-note muted">Issues are folded from this device’s decrypted MLS inbox — not a host plaintext index.</p>
{list}
{form}
{note}"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("issues", &rev, ""),
        list = list_html,
        form = form,
        note = note,
    );
    Html(layout("Issues", st.local.name(), &body)).into_response()
}

#[derive(Deserialize)]
struct IssueCreateForm {
    title: String,
    #[serde(default)]
    body: String,
}

async fn issue_create(State(st): State<AppState>, Form(form): Form<IssueCreateForm>) -> Response {
    match create_issue(st.local.root(), &form.title, &form.body).await {
        Ok(id) => Redirect::to(&format!("/issues/{id}")).into_response(),
        Err(e) => error_page(&st, StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn create_issue(root: &std::path::Path, title: &str, body: &str) -> anyhow::Result<String> {
    use crate::collab::{
        enqueue_collab, fold_collab_inbox, load_repo_record, material_for, next_collab_number,
        read_inbox_cache, sync_inbox,
    };
    use safehub_client::HttpClient;
    use safehub_types::CollabMessage;
    let record = load_repo_record(root)?;
    let client = HttpClient::from_disk()?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(&client, &record.id, &material).await?;
    let (issues, _) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    let id = next_collab_number(issues.iter().map(|i| i.id.clone())).to_string();
    let msg = CollabMessage::Issue {
        id: id.clone(),
        title: title.into(),
        body: body.into(),
        state: "open".into(),
    };
    let _ = enqueue_collab(&client, &record.id, &material, &msg, "issue").await?;
    Ok(id)
}

async fn issue_detail(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let folded = crate::collab::load_folded(st.local.root()).await;
    let Ok((_record, issues, _)) = folded else {
        return error_page(
            &st,
            StatusCode::BAD_REQUEST,
            "cannot load MLS inbox for issues",
        );
    };
    let Some(issue) = issues.into_iter().find(|i| i.id == id) else {
        return error_page(&st, StatusCode::NOT_FOUND, &format!("issue #{id} not found"));
    };
    let mut comments = format!(
        r#"<div class="comment"><div class="box-header"><strong>body</strong></div><div class="markdown">{}</div></div>"#,
        render_markdown(&issue.body)
    );
    for c in &issue.comments {
        comments.push_str(&format!(
            r#"<div class="comment"><div class="box-header"><strong>comment</strong></div><div class="markdown">{}</div></div>"#,
            render_markdown(c)
        ));
    }
    let body = format!(
        r#"{header}{tabs}
<div class="issue-head">
  <h1>{title} <span class="issue-num">#{id}</span></h1>
  <p>{pill} <span class="enc-bar">encrypted — issue</span></p>
</div>
<div class="enc-bar section">encrypted — comment</div>
{comments}
<div class="panel"><form class="form-grid" method="post" action="/issues/{id}">
<label for="body">Comment</label>
<textarea id="body" name="body"></textarea>
<input type="hidden" name="action" value="comment"/>
<button class="btn primary" type="submit">Comment</button>
</form>
<form class="form-grid" method="post" action="/issues/{id}" style="border-top:1px solid var(--border-soft)">
<input type="hidden" name="action" value="{toggle}"/>
<button class="btn" type="submit">{toggle_label}</button>
</form></div>"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("issues", &rev, ""),
        title = escape(&issue.title),
        id = escape(&issue.id),
        pill = state_pill("issue", &issue.state),
        comments = comments,
        toggle = if issue.state == "open" { "close" } else { "reopen" },
        toggle_label = if issue.state == "open" {
            "Close issue"
        } else {
            "Reopen issue"
        },
    );
    Html(layout(
        &format!("#{} · {}", issue.id, st.local.name()),
        st.local.name(),
        &body,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct IssueActionForm {
    action: String,
    #[serde(default)]
    body: String,
}

async fn issue_action(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Form(form): Form<IssueActionForm>,
) -> Response {
    match apply_issue_action(st.local.root(), &id, &form.action, &form.body).await {
        Ok(()) => Redirect::to(&format!("/issues/{id}")).into_response(),
        Err(e) => error_page(&st, StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn apply_issue_action(
    root: &std::path::Path,
    id: &str,
    action: &str,
    body: &str,
) -> anyhow::Result<()> {
    use crate::collab::{
        enqueue_collab, fold_collab_inbox, load_repo_record, material_for, read_inbox_cache,
        sync_inbox,
    };
    use safehub_client::HttpClient;
    use safehub_types::CollabMessage;
    let record = load_repo_record(root)?;
    let client = HttpClient::from_disk()?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(&client, &record.id, &material).await?;
    let (issues, _) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    let issue = issues
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow::anyhow!("issue not found"))?;
    match action {
        "comment" => {
            let msg = CollabMessage::Comment {
                target_kind: "issue".into(),
                target_id: id.into(),
                body: body.into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "issue-comment").await?;
        }
        "close" | "reopen" => {
            let state = if action == "close" { "closed" } else { "open" };
            let msg = CollabMessage::Issue {
                id: issue.id,
                title: issue.title,
                body: String::new(),
                state: state.into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "issue-state").await?;
        }
        other => anyhow::bail!("unknown action {other}"),
    }
    Ok(())
}

async fn pulls_list(State(st): State<AppState>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let folded = crate::collab::load_folded(st.local.root()).await;
    let list_html = match folded {
        Ok((_record, _, prs)) => {
            let open = prs.iter().filter(|p| p.state == "open").count();
            if prs.is_empty() {
                r#"<div class="blankslate"><h3>No pull requests yet</h3><p>Create one below. Metadata, bodies, and comments are MLS-sealed.</p></div>"#.to_string()
            } else {
                let mut items = String::from(r#"<ul class="issue-list">"#);
                for p in &prs {
                    items.push_str(&format!(
                        r#"<li>{pill}<div class="issue-main"><a class="issue-title" href="/pulls/{id}">{title}</a>
<div class="issue-meta">#{id} · <code>{head}</code> → <code>{base}</code></div></div></li>"#,
                        pill = state_pill("pull", &p.state),
                        id = escape(&p.id),
                        title = escape(&p.title),
                        head = escape(&p.head_ref),
                        base = escape(&p.base_ref),
                    ));
                }
                items.push_str("</ul>");
                format!(
                    r#"<div class="panel"><div class="commit-banner"><span>{open} open</span><span class="muted">MLS inbox</span></div>{items}</div>"#
                )
            }
        }
        Err(e) => format!(
            r#"<div class="error"><strong>Pull requests unavailable</strong><p>{}</p></div>"#,
            escape(&format!("{e:#}"))
        ),
    };
    let form = r#"<div class="panel" style="margin-top:1rem"><form class="form-grid" method="post" action="/pulls">
<label for="title">Title</label>
<input id="title" name="title" required/>
<label for="head">Head branch</label>
<input id="head" name="head" required placeholder="feature"/>
<label for="base">Base branch</label>
<input id="base" name="base" value="main"/>
<label for="body">Body</label>
<textarea id="body" name="body"></textarea>
<button class="btn primary" type="submit">Create encrypted PR</button>
</form></div>"#;
    let body = format!(
        r#"{header}{tabs}
<p class="view-note muted">Pull requests are member-local MLS messages — not plaintext host routes.</p>
{list}
{form}"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("pulls", &rev, ""),
        list = list_html,
        form = form,
    );
    Html(layout("Pull requests", st.local.name(), &body)).into_response()
}

#[derive(Deserialize)]
struct PrCreateForm {
    title: String,
    head: String,
    #[serde(default = "default_main")]
    base: String,
    #[serde(default)]
    body: String,
}

fn default_main() -> String {
    "main".into()
}

async fn pr_create(State(st): State<AppState>, Form(form): Form<PrCreateForm>) -> Response {
    match create_pr(
        st.local.root(),
        &form.title,
        &form.body,
        &form.base,
        &form.head,
    )
    .await
    {
        Ok(id) => Redirect::to(&format!("/pulls/{id}")).into_response(),
        Err(e) => error_page(&st, StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn create_pr(
    root: &std::path::Path,
    title: &str,
    body: &str,
    base: &str,
    head: &str,
) -> anyhow::Result<String> {
    use crate::collab::{
        enqueue_collab, fold_collab_inbox, load_repo_record, material_for, next_collab_number,
        read_inbox_cache, sync_inbox,
    };
    use safehub_client::HttpClient;
    use safehub_types::CollabMessage;
    let record = load_repo_record(root)?;
    let client = HttpClient::from_disk()?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(&client, &record.id, &material).await?;
    let (_, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    let id = next_collab_number(prs.iter().map(|p| p.id.clone())).to_string();
    let msg = CollabMessage::PullRequest {
        id: id.clone(),
        head_ref: head.into(),
        base_ref: base.into(),
        title: title.into(),
        body: body.into(),
        state: "open".into(),
    };
    let _ = enqueue_collab(&client, &record.id, &material, &msg, "pr-create").await?;
    Ok(id)
}

async fn pull_detail(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let folded = crate::collab::load_folded(st.local.root()).await;
    let Ok((_record, _, prs)) = folded else {
        return error_page(&st, StatusCode::BAD_REQUEST, "cannot load MLS inbox for PRs");
    };
    let Some(pr) = prs.into_iter().find(|p| p.id == id) else {
        return error_page(&st, StatusCode::NOT_FOUND, &format!("PR #{id} not found"));
    };
    let mut comments = format!(
        r#"<div class="comment"><div class="box-header"><strong>body</strong></div><div class="markdown">{}</div></div>"#,
        render_markdown(&pr.body)
    );
    for (v, b) in &pr.reviews {
        comments.push_str(&format!(
            r#"<div class="comment"><div class="box-header"><strong>review · {}</strong></div><div class="markdown">{}</div></div>"#,
            escape(v),
            render_markdown(b)
        ));
    }
    for c in &pr.comments {
        comments.push_str(&format!(
            r#"<div class="comment"><div class="box-header"><strong>comment</strong></div><div class="markdown">{}</div></div>"#,
            render_markdown(c)
        ));
    }
    let body = format!(
        r#"{header}{tabs}
<div class="issue-head">
  <h1>{title} <span class="issue-num">#{id}</span></h1>
  <p>{pill} <span class="muted"><code>{head}</code> → <code>{base}</code></span> <span class="enc-bar">encrypted — pr</span></p>
</div>
<div class="enc-bar section">encrypted — comment</div>
{comments}
<div class="panel"><form class="form-grid" method="post" action="/pulls/{id}">
<label for="body">Comment</label>
<textarea id="body" name="body"></textarea>
<input type="hidden" name="action" value="comment"/>
<button class="btn primary" type="submit">Comment</button>
</form>
<form class="form-grid" method="post" action="/pulls/{id}">
<label for="verdict">Review</label>
<select id="verdict" name="verdict"><option value="comment">Comment</option><option value="approve">Approve</option><option value="request_changes">Request changes</option></select>
<textarea name="review_body" placeholder="Review notes"></textarea>
<input type="hidden" name="action" value="review"/>
<button class="btn" type="submit">Submit review</button>
</form>
<form class="form-grid" method="post" action="/pulls/{id}">
<input type="hidden" name="action" value="{toggle}"/>
<button class="btn" type="submit">{toggle_label}</button>
</form></div>"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("pulls", &rev, ""),
        title = escape(&pr.title),
        id = escape(&pr.id),
        pill = state_pill("pull", &pr.state),
        head = escape(&pr.head_ref),
        base = escape(&pr.base_ref),
        comments = comments,
        toggle = if pr.state == "open" { "close" } else { "reopen" },
        toggle_label = if pr.state == "open" {
            "Close pull request"
        } else {
            "Reopen pull request"
        },
    );
    Html(layout(
        &format!("PR #{} · {}", pr.id, st.local.name()),
        st.local.name(),
        &body,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct PrActionForm {
    action: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    review_body: String,
}

async fn pr_action(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Form(form): Form<PrActionForm>,
) -> Response {
    match apply_pr_action(
        st.local.root(),
        &id,
        &form.action,
        &form.body,
        &form.verdict,
        &form.review_body,
    )
    .await
    {
        Ok(()) => Redirect::to(&format!("/pulls/{id}")).into_response(),
        Err(e) => error_page(&st, StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn apply_pr_action(
    root: &std::path::Path,
    id: &str,
    action: &str,
    body: &str,
    verdict: &str,
    review_body: &str,
) -> anyhow::Result<()> {
    use crate::collab::{
        enqueue_collab, fold_collab_inbox, load_repo_record, material_for, read_inbox_cache,
        sync_inbox,
    };
    use safehub_client::HttpClient;
    use safehub_types::CollabMessage;
    let record = load_repo_record(root)?;
    let client = HttpClient::from_disk()?;
    let material = material_for(&record.id)?;
    let _ = sync_inbox(&client, &record.id, &material).await?;
    let (_, prs) = fold_collab_inbox(&read_inbox_cache(&record.id)?);
    let pr = prs
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| anyhow::anyhow!("PR not found"))?;
    match action {
        "comment" => {
            let msg = CollabMessage::Comment {
                target_kind: "pr".into(),
                target_id: id.into(),
                body: body.into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "pr-comment").await?;
        }
        "review" => {
            let msg = CollabMessage::Review {
                pr_id: id.into(),
                verdict: if verdict.is_empty() {
                    "comment".into()
                } else {
                    verdict.into()
                },
                body: review_body.into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "pr-review").await?;
        }
        "close" | "reopen" => {
            let state = if action == "close" { "closed" } else { "open" };
            let msg = CollabMessage::PullRequest {
                id: pr.id,
                head_ref: pr.head_ref,
                base_ref: pr.base_ref,
                title: pr.title,
                body: String::new(),
                state: state.into(),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &msg, "pr-state").await?;
        }
        other => anyhow::bail!("unknown action {other}"),
    }
    Ok(())
}

async fn settings_page(State(st): State<AppState>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let binding = crate::collab::load_repo_record(st.local.root());
    let is_admin = match current_user_is_repo_admin(st.local.root()).await {
        Ok(v) => v,
        Err(_) => false,
    };
    let meta = match &binding {
        Ok(r) => format!(
            r#"<p><strong>{}</strong> · id <code>{}</code>{}{}</p>"#,
            escape(&format!("{}", r.name)),
            escape(&r.id.to_hex()),
            if r.archived {
                " · <span class=\"state closed\">archived</span>"
            } else {
                ""
            },
            if r.deleted {
                " · <span class=\"state closed\">deleted</span>"
            } else {
                ""
            },
        ),
        Err(e) => format!(
            r#"<div class="error"><p>{}</p><p>Bind a SafeHub repo with <code>sit clone</code> or <code>sh repo create --clone</code>.</p></div>"#,
            escape(&format!("{e:#}"))
        ),
    };
    let archive_forms = if let (Ok(r), true) = (&binding, is_admin) {
        let name = format!("{}", r.name);
        format!(
            r#"<div class="panel"><form class="form-grid" method="post" action="/settings/access">
<input type="hidden" name="action" value="archive"/>
<input type="hidden" name="repo" value="{}"/>
<button class="btn" type="submit">{}</button>
</form>
<form class="form-grid" method="post" action="/settings/access">
<input type="hidden" name="action" value="delete"/>
<input type="hidden" name="repo" value="{}"/>
<label><input type="checkbox" name="confirm" value="yes"/> Confirm delete (tombstone)</label>
<button class="btn danger" type="submit">Delete repository</button>
</form></div>"#,
            escape(&name),
            if r.archived {
                "Unarchive repository"
            } else {
                "Archive repository"
            },
            escape(&name),
        )
    } else if binding.is_ok() && !is_admin {
        r#"<div class="panel"><p class="muted">Archive and delete are owner/admin only.</p></div>"#
            .to_string()
    } else {
        String::new()
    };
    let body = format!(
        r#"{header}{tabs}
<h2>Settings</h2>
{meta}
<div class="panel" style="padding:1rem">
  <p><a href="/settings/access">Collaborators and invites</a></p>
  <p class="muted">Roles are membership metadata on the host; history windows are cryptographic (full vs forward-only).</p>
</div>
{archive}"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("settings", &rev, ""),
        meta = meta,
        archive = archive_forms,
    );
    Html(layout("Settings", st.local.name(), &body)).into_response()
}

async fn access_page(State(st): State<AppState>) -> Response {
    let rev = st.local.default_ref().unwrap_or_else(|_| "HEAD".into());
    let rows = match list_collabs_html(st.local.root()).await {
        Ok(s) => s,
        Err(e) => format!(
            r#"<div class="error"><p>{}</p></div>"#,
            escape(&format!("{e:#}"))
        ),
    };
    let is_admin = current_user_is_repo_admin(st.local.root())
        .await
        .unwrap_or(false);
    let admin_forms = if is_admin {
        r#"<div class="panel" style="margin-top:1rem"><form class="form-grid" method="post" action="/settings/access">
<input type="hidden" name="action" value="invite"/>
<label for="user">Invite username</label>
<input id="user" name="user" required/>
<label for="history">History window</label>
<select id="history" name="history">
  <option value="full">full</option>
  <option value="forward_only">forward-only</option>
</select>
<button class="btn primary" type="submit">Invite (control-plane + MLS)</button>
</form>
<form class="form-grid" method="post" action="/settings/access">
<input type="hidden" name="action" value="remove"/>
<label for="remove_user">Remove username</label>
<input id="remove_user" name="user" required/>
<button class="btn danger" type="submit">Remove member</button>
</form>
<form class="form-grid" method="post" action="/settings/access">
<input type="hidden" name="action" value="rotate"/>
<button class="btn" type="submit">Rotate MLS epoch</button>
</form></div>"#
            .to_string()
    } else {
        r#"<div class="panel" style="margin-top:1rem"><p class="muted">Invite, remove, and rotate are owner/admin only. Ordinary members can view this roster.</p></div>"#
            .to_string()
    };
    let body = format!(
        r#"{header}{tabs}
<h2>Collaborators</h2>
<p class="view-note muted">Usernames are visible to the untrusted host. Crypto membership uses MLS Welcome + rotate.</p>
<div class="panel"><table class="data"><thead><tr><th>User</th><th>Role / history</th></tr></thead><tbody>{rows}</tbody></table></div>
{admin_forms}
<pre class="hint"># CLI equivalents
sh repo invite USER --repo owner/name
sh repo invite USER --forward-only
sh repo remove-member USER
sh repo rotate
sh repo accept-welcome</pre>"#,
        header = repo_header_as(&st, &rev, ViewMode::Local),
        tabs = tabs("settings", &rev, ""),
        rows = rows,
        admin_forms = admin_forms,
    );
    Html(layout("Collaborators", st.local.name(), &body)).into_response()
}

async fn list_collabs_html(root: &std::path::Path) -> anyhow::Result<String> {
    let record = crate::collab::load_repo_record(root)?;
    let client = safehub_client::HttpClient::from_disk()?;
    let v = client.list_collaborators(&record.name).await?;
    let mut rows = String::new();
    if let Some(owner) = v.get("owner").and_then(|x| x.as_str()) {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>owner</td></tr>",
            escape(owner)
        ));
    }
    if let Some(arr) = v.get("members").and_then(|x| x.as_array()) {
        for m in arr {
            let user = m
                .get("user")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let hist = m
                .get("history")
                .and_then(|x| x.as_str())
                .unwrap_or("member");
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape(user),
                escape(hist)
            ));
        }
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="2" class="muted">No collaborators returned (or not logged in).</td></tr>"#.into();
    }
    Ok(rows)
}

#[derive(Deserialize)]
struct AccessForm {
    action: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    history: String,
    #[serde(default)]
    #[allow(dead_code)]
    repo: String,
    #[serde(default)]
    confirm: String,
}

async fn access_action(State(st): State<AppState>, Form(form): Form<AccessForm>) -> Response {
    match apply_access(st.local.root(), &form).await {
        Ok(redir) => Redirect::to(&redir).into_response(),
        Err(e) => error_page(&st, StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

async fn apply_access(root: &std::path::Path, form: &AccessForm) -> anyhow::Result<String> {
    use safehub_client::{invite_member_mls_with_graft, rotate_repo_group, HttpClient};
    use safehub_types::UserId;
    let record = crate::collab::load_repo_record(root)?;
    let client = HttpClient::from_disk()?;
    let me = client.whoami().await?;
    // Control-plane admin == repository owner. Fail closed before any side effect.
    if me.0 != record.name.owner {
        anyhow::bail!(
            "only the repository owner/admin can invite, remove, rotate, archive, or delete"
        );
    }
    match form.action.as_str() {
        "invite" => {
            let history = if form.history.is_empty() {
                "full"
            } else {
                form.history.as_str()
            };
            let _ = client
                .invite_collaborator(&record.name, &form.user, history)
                .await?;
            let forward_only = history == "forward_only" || history == "forward-only";
            let _ = invite_member_mls_with_graft(
                &client,
                &record.id,
                &UserId(form.user.clone()),
                forward_only,
                None,
            )
            .await;
            Ok("/settings/access".into())
        }
        "remove" => {
            client
                .remove_collaborator(&record.name, &form.user)
                .await?;
            Ok("/settings/access".into())
        }
        "rotate" => {
            let _ = rotate_repo_group(&record.id)?;
            Ok("/settings/access".into())
        }
        "archive" => {
            let archived = !record.archived;
            let _ = client
                .patch_repo(&record.name, &serde_json::json!({ "archived": archived }))
                .await?;
            Ok("/settings".into())
        }
        "delete" => {
            if form.confirm != "yes" {
                anyhow::bail!("confirm delete with the checkbox");
            }
            client.delete_repo(&record.name).await?;
            Ok("/settings".into())
        }
        other => anyhow::bail!("unknown action {other}"),
    }
}

/// True when the logged-in SafeHub user is the repository owner (control-plane admin).
async fn current_user_is_repo_admin(root: &std::path::Path) -> anyhow::Result<bool> {
    let record = crate::collab::load_repo_record(root)?;
    let client = safehub_client::HttpClient::from_disk()?;
    let me = client.whoami().await?;
    Ok(me.0 == record.name.owner)
}


