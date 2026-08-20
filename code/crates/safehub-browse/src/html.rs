//! HTML layout, CSS, and small render helpers for the local browse UI.

use pulldown_cmark::{html, Options, Parser};

pub const CSS: &str = r#"
:root {
  --bg: #f4f5f7;
  --surface: #ffffff;
  --border: #d8dee4;
  --border-soft: #eaeef2;
  --text: #1c2128;
  --muted: #636c76;
  --link: #0969da;
  --header: #1c2128;
  --header-text: #f0f3f6;
  --accent: #0969da;
  --tab: #0969da;
  --diff-add: #dafbe1;
  --diff-del: #ffebe9;
  --row-hover: #f6f8fa;
  --shadow: 0 1px 0 rgba(27, 31, 36, 0.04);
  --radius: 8px;
  --font: "IBM Plex Sans", "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: var(--font);
  background:
    radial-gradient(1200px 400px at 10% -10%, #e8eef5 0%, transparent 55%),
    radial-gradient(900px 320px at 100% 0%, #e6eefb 0%, transparent 50%),
    var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
.top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  background: var(--header);
  color: var(--header-text);
  padding: 0.7rem 1.25rem;
  box-shadow: var(--shadow);
}
.top a { color: var(--header-text); }
.brand {
  display: flex;
  align-items: baseline;
  gap: 0.55rem;
  font-weight: 650;
  letter-spacing: -0.02em;
}
.brand .mark {
  display: inline-flex;
  align-self: center;
  width: 1.4rem;
  height: 1.4rem;
  color: #6cb0f7;
}
.brand .sub { font-weight: 450; color: #afb8c1; font-size: 0.85rem; }
.top-meta { font-size: 0.85rem; color: #afb8c1; font-family: var(--mono); }
.wrap { max-width: 1120px; margin: 1.25rem auto 3rem; padding: 0 1rem; }
.repo-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
  animation: rise 280ms ease-out;
}
.repo-header h1 {
  margin: 0;
  font-size: 1.35rem;
  font-weight: 550;
  letter-spacing: -0.02em;
}
.repo-header h1 .slash { color: var(--muted); font-weight: 400; }
.pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  border: 1px solid var(--border);
  background: var(--surface);
  border-radius: 999px;
  padding: 0.2rem 0.65rem;
  font-size: 0.8rem;
  color: var(--muted);
}
.repo-tabs {
  border-bottom: 1px solid var(--border);
  margin: 0.75rem 0 1rem;
}
.repo-tabs ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 0.15rem;
}
.repo-tabs a {
  display: block;
  padding: 0.65rem 0.9rem;
  color: var(--text);
  border-bottom: 2px solid transparent;
  transition: border-color 160ms ease, color 160ms ease;
}
.repo-tabs li.active a {
  border-bottom-color: var(--tab);
  font-weight: 600;
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 0.75rem;
}
.branch-select, .btn {
  font: inherit;
  font-size: 0.875rem;
  border: 1px solid var(--border);
  background: var(--surface);
  border-radius: 6px;
  padding: 0.35rem 0.65rem;
  color: var(--text);
  cursor: pointer;
}
.branch-select { max-width: 100%; }
.btn:hover { background: var(--row-hover); text-decoration: none; }
.btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
  font-weight: 550;
}
.btn.primary:hover { background: #0b62c4; }
.btn.danger { color: #cf222e; border-color: #ff8182; }
.state {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  border-radius: 999px;
  padding: 0.15rem 0.55rem;
  font-size: 0.75rem;
  font-weight: 600;
  border: 1px solid var(--border);
}
.state.open { color: #1a7f37; background: #dafbe1; border-color: #4ac26b; }
.state.closed { color: #cf222e; background: #ffebe9; border-color: #ff8182; }
.state.merged { color: #8250df; background: #fbefff; border-color: #c297ff; }
.issue-list { list-style: none; margin: 0; padding: 0; }
.issue-list li {
  display: flex;
  gap: 0.75rem;
  padding: 0.85rem 1rem;
  border-bottom: 1px solid var(--border-soft);
}
.issue-list li:last-child { border-bottom: 0; }
.issue-list .issue-title { font-weight: 550; color: var(--text); }
.issue-list .issue-meta { font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }
.issue-head { margin: 0.5rem 0 1rem; }
.issue-head h1 { margin: 0 0 0.35rem; font-size: 1.5rem; font-weight: 550; }
.issue-num { color: var(--muted); font-weight: 400; }
.comment-section {
  margin: 1.25rem 0 0.6rem;
  font-size: 1rem;
  font-weight: 550;
}
.enc-bar {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.22rem 0.6rem;
  border-radius: 999px;
  background: #ddf4ff;
  border: 1px solid #80baf5;
  color: #0a3069;
  font-size: 0.75rem;
  font-weight: 600;
  font-family: var(--mono);
}
.enc-bar.section { margin: 1.25rem 0 0.6rem; }
.comment {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 0.75rem;
  overflow: hidden;
}
.comment .box-header {
  padding: 0.55rem 0.85rem;
  background: #f6f8fa;
  border-bottom: 1px solid var(--border-soft);
  font-size: 0.875rem;
}
.comment .markdown { padding: 0.85rem 1rem; }
.form-grid { display: grid; gap: 0.65rem; padding: 1rem; }
.form-grid label { font-size: 0.85rem; font-weight: 550; }
.form-grid input, .form-grid textarea, .form-grid select {
  font: inherit;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.45rem 0.65rem;
  width: 100%;
}
.form-grid textarea { min-height: 8rem; font-family: var(--mono); font-size: 0.875rem; }
.hint {
  margin: 1rem 0;
  padding: 0.75rem 1rem;
  background: #f6f8fa;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-family: var(--mono);
  font-size: 0.8rem;
  white-space: pre-wrap;
}
.blankslate {
  text-align: center;
  padding: 2.5rem 1.5rem;
  color: var(--muted);
}
.blankslate h3 { color: var(--text); margin: 0 0 0.5rem; }
.data { width: 100%; border-collapse: collapse; }
.data th, .data td {
  text-align: left;
  padding: 0.55rem 0.85rem;
  border-bottom: 1px solid var(--border-soft);
  font-size: 0.875rem;
}
.data th { color: var(--muted); font-weight: 550; }
.auth-card {
  max-width: 28rem;
  margin: 2rem auto;
  padding: 1.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}
.mode-switch { display: flex; align-items: center; gap: 0.5rem; margin: 0.25rem 0 1rem; }
.view-switch {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  background: var(--surface);
  vertical-align: middle;
}
.view-switch .seg {
  padding: 0.35rem 0.8rem;
  font-size: 0.875rem;
  color: var(--text);
  border-right: 1px solid var(--border);
}
.view-switch .seg:last-child { border-right: 0; }
.view-switch .seg:hover { background: var(--row-hover); text-decoration: none; }
.view-switch .seg.active {
  background: var(--accent);
  color: #fff;
  font-weight: 550;
}
.view-note { margin: 0 0 0.75rem; font-size: 0.82rem; }
.breadcrumb {
  font-family: var(--mono);
  font-size: 0.85rem;
  margin: 0.25rem 0 0.85rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.15rem;
  align-items: baseline;
}
.breadcrumb .sep { color: var(--muted); margin: 0 0.1rem; }
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
  animation: rise 320ms ease-out;
}
.files { width: 100%; border-collapse: collapse; }
.files td {
  padding: 0.55rem 0.85rem;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: middle;
}
.files tr:last-child td { border-bottom: 0; }
.files tr:hover td { background: var(--row-hover); }
.files .icon { width: 1.75rem; color: var(--muted); }
.files .name { font-family: var(--mono); font-size: 0.875rem; }
.files .meta { text-align: right; color: var(--muted); font-size: 0.8rem; white-space: nowrap; }
.icon-dir::before { content: "▸"; }
.icon-file::before { content: "·"; }
.commit-banner {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.7rem 0.9rem;
  border-bottom: 1px solid var(--border-soft);
  background: #fafbfc;
  font-size: 0.875rem;
}
.commit-banner .msg { font-weight: 550; }
.commit-banner .meta { color: var(--muted); font-family: var(--mono); font-size: 0.8rem; }
.readme {
  margin-top: 1.25rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  animation: rise 380ms ease-out;
}
.readme-h {
  padding: 0.65rem 1rem;
  border-bottom: 1px solid var(--border-soft);
  font-weight: 600;
  font-size: 0.9rem;
  background: #fafbfc;
}
.readme-body { padding: 1rem 1.25rem; }
.readme-body h1, .readme-body h2, .readme-body h3 { margin-top: 1.1em; }
.readme-body pre, .code {
  background: #f6f8fa;
  border: 1px solid var(--border-soft);
  border-radius: 6px;
  padding: 0.85rem 1rem;
  overflow: auto;
  font-family: var(--mono);
  font-size: 0.82rem;
  line-height: 1.45;
}
.blob-wrap .code { border: 0; border-radius: 0; margin: 0; }
.blob-meta {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.6rem 0.9rem;
  border-bottom: 1px solid var(--border-soft);
  background: #fafbfc;
  font-size: 0.85rem;
  color: var(--muted);
}
.line-table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 0.8rem; }
.line-table td { padding: 0 0.5rem; vertical-align: top; }
.line-table .ln {
  width: 1%;
  text-align: right;
  color: #8c959f;
  user-select: none;
  padding-right: 0.75rem;
  border-right: 1px solid var(--border-soft);
}
.line-table .lc { white-space: pre; padding-left: 0.85rem; }
.commits { list-style: none; margin: 0; padding: 0; }
.commits li {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.35rem 1rem;
  padding: 0.85rem 1rem;
  border-bottom: 1px solid var(--border-soft);
  transition: background 140ms ease;
}
.commits li:last-child { border-bottom: 0; }
.commits li:hover { background: var(--row-hover); }
.commits .subject { font-weight: 550; }
.commits .who { color: var(--muted); font-size: 0.85rem; }
.commits .sha {
  font-family: var(--mono);
  font-size: 0.8rem;
  align-self: center;
}
.branch-list, .tag-list { list-style: none; margin: 0; padding: 0; }
.branch-list li, .tag-list li {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border-soft);
}
.branch-list li:last-child, .tag-list li:last-child { border-bottom: 0; }
.badge {
  font-size: 0.7rem;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.05rem 0.45rem;
  color: var(--muted);
  margin-left: 0.4rem;
}
.badge.current { color: var(--accent); border-color: #80baf5; background: #ddf4ff; }
.commit-detail .subject {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.5rem;
}
.commit-detail .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1rem; }
.commit-detail .parents { font-family: var(--mono); font-size: 0.85rem; margin-bottom: 1rem; }
.diff-files { margin: 0 0 1rem; padding-left: 1.1rem; }
.diff-files li { margin: 0.25rem 0; font-family: var(--mono); font-size: 0.85rem; }
.diff {
  background: #f6f8fa;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: auto;
  font-family: var(--mono);
  font-size: 0.78rem;
  line-height: 1.4;
  padding: 0.75rem;
  white-space: pre;
}
.diff .add { background: var(--diff-add); }
.diff .del { background: var(--diff-del); }
.muted { color: var(--muted); }
.error {
  background: #ffebe9;
  border: 1px solid #ff8182;
  color: #82071e;
  padding: 1rem;
  border-radius: var(--radius);
}
.footer-note {
  margin-top: 2rem;
  color: var(--muted);
  font-size: 0.8rem;
  text-align: center;
}
@keyframes rise {
  from { opacity: 0; transform: translateY(6px); }
  to { opacity: 1; transform: none; }
}
@media (max-width: 640px) {
  .repo-tabs a { padding: 0.5rem 0.6rem; font-size: 0.85rem; }
  .commits li { grid-template-columns: 1fr; }
  .files .meta { display: none; }
}
"#;

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn encode_path_seg(s: &str) -> String {
    let mut out = String::new();
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

/// Encode a git ref for use as a single URL path segment (`/` → `%2F`).
pub fn encode_ref(rev: &str) -> String {
    encode_path_seg(rev)
}

pub fn decode_ref(s: &str) -> String {
    percent_decode(s)
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((a << 4) | b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn render_markdown(md: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(md, opts);
    let mut html_out = String::new();
    html::push_html(&mut html_out, parser);
    html_out
}

/// SafeHub brand mark: two commit nodes on a branch line, wearing incognito
/// spectacles. Inline so the browser needs no asset request.
pub const MARK_SVG: &str = r#"<svg viewBox="0 0 16 16" width="100%" height="100%" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round"><path d="M2.6 6.5h10.8"/><path d="M5.1 6.5v1.05"/><path d="M10.9 6.5v1.05"/><path d="M.9 9.7h2.05"/><path d="M13.05 9.7h2.05"/><path d="M7.25 9.7h1.5"/><circle cx="5.1" cy="9.7" r="2.15"/><circle cx="10.9" cy="9.7" r="2.15"/></g></svg>"#;

/// Brand mark as a data-URI favicon (brand blue, no external file).
fn favicon_data_uri() -> String {
    let svg = MARK_SVG
        .replace('"', "'")
        .replace("currentColor", "#0969da")
        .replace("<svg ", "<svg xmlns='http://www.w3.org/2000/svg' ");
    format!("data:image/svg+xml,{}", svg.replace('#', "%23"))
}

pub fn layout(title: &str, repo_name: &str, body: &str) -> String {
    let user = crate::collab::auth_user();
    let auth_meta = match &user {
        Some(u) => format!(
            r#"<a href="/settings">Settings</a> · <span>{}</span> · <a href="/logout">Sign out</a>"#,
            escape(u)
        ),
        None => r#"<a href="/login">Sign in</a>"#.to_string(),
    };
    format!(
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
<link rel="stylesheet" href="/assets/browse.css"/>
</head>
<body>
<header class="top">
  <div class="brand">
    <span class="mark" aria-hidden="true">{mark}</span>
    <a href="/">SafeHub</a>
    <span class="sub">local browse</span>
  </div>
  <div class="top-meta">{repo} · {auth}</div>
</header>
<main class="wrap">{body}</main>
<p class="footer-note">Member device · Local | Remote code · Issues/PRs from MLS inbox (host never sees bodies)</p>
</body>
</html>"#,
        title = escape(title),
        repo = escape(repo_name),
        body = body,
        mark = MARK_SVG,
        favicon = favicon_data_uri(),
        auth = auth_meta,
    )
}

pub fn tabs(active: &str, rev: &str, prefix: &str) -> String {
    let er = encode_ref(rev);
    // Code/commits/branches/tags follow Local|Remote prefix; collab tabs are always
    // member-local (MLS inbox on this device), so they ignore the remote prefix.
    let items = [
        ("code", "Code", format!("{prefix}/tree/{er}")),
        ("issues", "Issues", "/issues".to_string()),
        ("pulls", "Pull requests", "/pulls".to_string()),
        ("commits", "Commits", format!("{prefix}/commits/{er}")),
        ("branches", "Branches", format!("{prefix}/branches")),
        ("tags", "Tags", format!("{prefix}/tags")),
        ("settings", "Settings", "/settings".to_string()),
    ];
    let mut out = String::from(r#"<nav class="repo-tabs" aria-label="Repository"><ul>"#);
    for (id, label, href) in items {
        let cls = if id == active { r#" class="active""# } else { "" };
        out.push_str(&format!(
            r#"<li{cls}><a href="{href}">{label}</a></li>"#,
            cls = cls,
            href = href,
            label = label
        ));
    }
    out.push_str("</ul></nav>");
    out
}

pub fn state_pill(kind: &str, state: &str) -> String {
    let (cls, label) = match (kind, state) {
        ("pull", "merged") => ("merged", "Merged"),
        ("pull", "closed") => ("closed", "Closed"),
        ("pull", _) => ("open", "Open"),
        (_, "closed") => ("closed", "Closed"),
        _ => ("open", "Open"),
    };
    format!(r#"<span class="state {cls}">{label}</span>"#)
}

pub fn breadcrumb(rev: &str, path: &str, is_blob: bool, prefix: &str) -> String {
    let er = encode_ref(rev);
    let mut out = String::from(r#"<nav class="breadcrumb" aria-label="Breadcrumb">"#);
    out.push_str(&format!(
        r#"<a href="{prefix}/tree/{er}">{name}</a>"#,
        prefix = prefix,
        er = er,
        name = escape(rev)
    ));
    if path.is_empty() {
        out.push_str("</nav>");
        return out;
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let mut acc = String::new();
    for (i, part) in parts.iter().enumerate() {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        out.push_str(r#"<span class="sep">/</span>"#);
        let last = i + 1 == parts.len();
        if last && is_blob {
            out.push_str(&format!("<strong>{}</strong>", escape(part)));
        } else if last && !is_blob {
            out.push_str(&format!("<strong>{}</strong>", escape(part)));
        } else {
            out.push_str(&format!(
                r#"<a href="{prefix}/tree/{er}/{ep}">{name}</a>"#,
                prefix = prefix,
                er = er,
                ep = encode_path_seg_path(&acc),
                name = escape(part)
            ));
        }
    }
    out.push_str("</nav>");
    out
}

/// Encode each path segment, keeping `/` as separators.
pub fn encode_path_seg_path(path: &str) -> String {
    path.split('/')
        .map(encode_path_seg)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn format_size(n: Option<u64>) -> String {
    match n {
        None => String::new(),
        Some(b) if b < 1024 => format!("{b} B"),
        Some(b) if b < 1024 * 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        Some(b) => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

pub fn short_date(iso: &str) -> String {
    // Keep YYYY-MM-DD HH:MM if present.
    if iso.len() >= 16 {
        format!("{} {}", &iso[0..10], &iso[11..16])
    } else {
        iso.to_string()
    }
}

pub fn render_diff_html(patch: &str) -> String {
    let mut out = String::from(r#"<div class="diff">"#);
    for line in patch.lines() {
        let cls = if line.starts_with('+') && !line.starts_with("+++") {
            "add"
        } else if line.starts_with('-') && !line.starts_with("---") {
            "del"
        } else {
            ""
        };
        if cls.is_empty() {
            out.push_str(&escape(line));
        } else {
            out.push_str(&format!(
                r#"<span class="{cls}">{}</span>"#,
                escape(line)
            ));
        }
        out.push('\n');
    }
    out.push_str("</div>");
    out
}

pub fn code_with_lines(content: &str) -> String {
    let mut out = String::from(r#"<table class="line-table" aria-label="File contents"><tbody>"#);
    for (i, line) in content.lines().enumerate() {
        out.push_str(&format!(
            r#"<tr><td class="ln">{n}</td><td class="lc">{c}</td></tr>"#,
            n = i + 1,
            c = escape(line)
        ));
    }
    if content.is_empty() {
        out.push_str(r#"<tr><td class="ln">1</td><td class="lc"></td></tr>"#);
    }
    out.push_str("</tbody></table>");
    out
}
