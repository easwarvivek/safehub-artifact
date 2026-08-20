//! Shared helpers for SafeHub CLI commands (repo resolve, MLS collab, inbox).

use safehub_client::{
    load_epoch_material, mls_local, open_collab, seal_collab, ClientConfig, Credentials, EpochMaterial,
    HttpClient,
};
use safehub_types::{CollabMessage, RepoId, RepoName, RepoRecord};
use std::path::{Path, PathBuf};

pub async fn resolve_repo(client: &HttpClient, explicit: Option<&str>) -> anyhow::Result<RepoRecord> {
    if let Some(s) = explicit {
        let name = RepoName::parse(s).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
        return Ok(client.get_repo(&name).await?);
    }
    let path = Path::new(".git").join("safehub").join("repo.json");
    if path.exists() {
        return Ok(serde_json::from_slice(&std::fs::read(path)?)?);
    }
    anyhow::bail!("not a safehub checkout; pass --repo owner/name")
}

pub fn load_local_repo() -> anyhow::Result<RepoRecord> {
    let path = Path::new(".git").join("safehub").join("repo.json");
    if !path.exists() {
        anyhow::bail!("not a SafeHub checkout; run `sit clone` or `sh repo create --clone`");
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

pub async fn enqueue_collab(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
    msg: &CollabMessage,
    hint: &str,
) -> anyhow::Result<u64> {
    let sealed = seal_collab(material, &serde_json::to_vec(msg)?)?;
    Ok(client.mls_enqueue(repo, sealed, Some(hint.into())).await?)
}

pub fn inbox_dir(repo: &RepoId) -> anyhow::Result<PathBuf> {
    let dir = EpochMaterial::dir(repo)?.join("inbox");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn mls_cursor_path(repo: &RepoId) -> anyhow::Result<PathBuf> {
    Ok(EpochMaterial::dir(repo)?.join("mls_cursor.json"))
}

pub fn load_mls_cursor(repo: &RepoId) -> u64 {
    let Ok(path) = mls_cursor_path(repo) else {
        return 0;
    };
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("after").and_then(|x| x.as_u64()))
        .unwrap_or(0)
}

pub fn save_mls_cursor(repo: &RepoId, after: u64) -> anyhow::Result<()> {
    let path = mls_cursor_path(repo)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(&serde_json::json!({ "after": after }))?)?;
    Ok(())
}

/// Fetch MLS queue, decrypt collab messages, append to local inbox cache.
pub async fn sync_inbox(
    client: &HttpClient,
    repo: &RepoId,
    material: &EpochMaterial,
) -> anyhow::Result<Vec<(u64, CollabMessage)>> {
    let after = load_mls_cursor(repo);
    let envs = client.mls_fetch(repo, after).await?;
    let mut out = Vec::new();
    let mut max_seq = after;
    let dir = inbox_dir(repo)?;
    for env in envs {
        max_seq = max_seq.max(env.seq);
        match open_collab(material, &env.payload) {
            Ok(pt) => {
                if let Ok(msg) = serde_json::from_slice::<CollabMessage>(&pt) {
                    let path = dir.join(format!("{:016}.json", env.seq));
                    std::fs::write(&path, serde_json::to_vec_pretty(&msg)?)?;
                    out.push((env.seq, msg));
                }
            }
            Err(_) => {
                // Welcome / commit frames are not collab AEAD — skip silently.
            }
        }
    }
    if max_seq > after {
        save_mls_cursor(repo, max_seq)?;
    }
    Ok(out)
}

/// Load all cached decrypted inbox messages (best-effort).
pub fn read_inbox_cache(repo: &RepoId) -> anyhow::Result<Vec<(u64, CollabMessage)>> {
    let dir = inbox_dir(repo)?;
    let mut entries = Vec::new();
    if !dir.exists() {
        return Ok(entries);
    }
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let seq: u64 = name.trim_end_matches(".json").parse().unwrap_or(0);
        let msg: CollabMessage = serde_json::from_slice(&std::fs::read(ent.path())?)?;
        entries.push((seq, msg));
    }
    entries.sort_by_key(|(s, _)| *s);
    Ok(entries)
}

pub fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    hex::encode(t.to_le_bytes())
}

#[allow(dead_code)]
pub async fn gateway_json(
    method: &str,
    route: &str,
    body: Option<&serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let client = HttpClient::from_disk()?;
    let (status, text) = client.api_request(method, route, body).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("API {method} {route} failed: {status} {text}");
    }
    if text.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    Ok(serde_json::from_str(&text)?)
}

#[allow(dead_code)]
pub fn require_login() -> anyhow::Result<()> {
    let _ = ClientConfig::load()?;
    Credentials::load()?
        .ok_or_else(|| anyhow::anyhow!("not logged in; run `sh auth login`"))?;
    Ok(())
}

/// Seal a secret value to a runner KeyPackage (opaque bytes) or fall back to group AEAD.
pub fn seal_secret_for_runner(
    material: &EpochMaterial,
    plaintext: &[u8],
    runner_kp: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(kp) = runner_kp {
        // Bind secret to KeyPackage bytes via domain-separated AEAD under a
        // dedicated seal key (not mk_e / refs_mac).
        use safehub_crypto::{derive_secret_seal_key, CommittingAead};
        use safehub_types::domain_label;
        let mut aad = domain_label("secret-kp").into_bytes();
        aad.extend_from_slice(kp);
        let key = derive_secret_seal_key(&material.transport)?;
        Ok(CommittingAead::seal(&key, &aad, plaintext)?)
    } else {
        Ok(mls_local::seal_collab(material, plaintext)?)
    }
}

pub fn material_for(repo: &RepoId) -> anyhow::Result<EpochMaterial> {
    Ok(load_epoch_material(repo)?)
}

/// Folded issue view from the decrypted MLS inbox (host never sees bodies).
#[derive(Clone, Debug)]
pub struct FoldedIssue {
    pub id: String,
    pub title: String,
    pub body: String,
    pub state: String,
    pub comments: Vec<String>,
}

/// Folded PR view from the decrypted MLS inbox.
#[derive(Clone, Debug)]
pub struct FoldedPr {
    pub id: String,
    pub title: String,
    pub body: String,
    pub state: String,
    pub head_ref: String,
    pub base_ref: String,
    pub comments: Vec<String>,
    pub reviews: Vec<(String, String)>,
}

/// Reduce inbox messages into latest issue/PR state (client-side only).
pub fn fold_collab_inbox(
    messages: &[(u64, CollabMessage)],
) -> (Vec<FoldedIssue>, Vec<FoldedPr>) {
    use std::collections::BTreeMap;
    let mut issues: BTreeMap<String, FoldedIssue> = BTreeMap::new();
    let mut prs: BTreeMap<String, FoldedPr> = BTreeMap::new();
    for (_seq, msg) in messages {
        match msg {
            CollabMessage::Issue {
                id,
                title,
                body,
                state,
            } => {
                let e = issues.entry(id.clone()).or_insert_with(|| FoldedIssue {
                    id: id.clone(),
                    title: title.clone(),
                    body: body.clone(),
                    state: state.clone(),
                    comments: vec![],
                });
                if !title.is_empty() {
                    e.title = title.clone();
                }
                if !body.is_empty() {
                    e.body = body.clone();
                }
                if !state.is_empty() {
                    e.state = state.clone();
                }
            }
            CollabMessage::PullRequest {
                id,
                head_ref,
                base_ref,
                title,
                body,
                state,
            } => {
                let e = prs.entry(id.clone()).or_insert_with(|| FoldedPr {
                    id: id.clone(),
                    title: title.clone(),
                    body: body.clone(),
                    state: state.clone(),
                    head_ref: head_ref.clone(),
                    base_ref: base_ref.clone(),
                    comments: vec![],
                    reviews: vec![],
                });
                if !title.is_empty() {
                    e.title = title.clone();
                }
                if !body.is_empty() {
                    e.body = body.clone();
                }
                if !state.is_empty() {
                    e.state = state.clone();
                }
                if !head_ref.is_empty() {
                    e.head_ref = head_ref.clone();
                }
                if !base_ref.is_empty() {
                    e.base_ref = base_ref.clone();
                }
            }
            CollabMessage::Comment {
                target_kind,
                target_id,
                body,
            } => {
                if target_kind == "issue" {
                    if let Some(i) = issues.get_mut(target_id) {
                        i.comments.push(body.clone());
                    }
                } else if target_kind == "pr" {
                    if let Some(p) = prs.get_mut(target_id) {
                        p.comments.push(body.clone());
                    }
                }
            }
            CollabMessage::Review {
                pr_id,
                verdict,
                body,
            } => {
                if let Some(p) = prs.get_mut(pr_id) {
                    p.reviews.push((verdict.clone(), body.clone()));
                }
            }
            _ => {}
        }
    }
    (issues.into_values().collect(), prs.into_values().collect())
}

/// Next numeric issue/PR id from folded inbox state.
pub fn next_collab_number(ids: impl Iterator<Item = String>) -> u64 {
    let mut max = 0u64;
    for id in ids {
        let n = id
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .parse::<u64>()
            .or_else(|_| id.parse::<u64>())
            .unwrap_or(0);
        max = max.max(n);
    }
    max + 1
}

/// Import a decrypted bundle's objects into the repository at `repo_dir`.
///
/// Clone replays one bundle per push, so this runs O(pushes) times and its
/// constant factor is the dominant term in clone cost. Only the *objects* are
/// wanted — refs come from the tip's decrypted ref map — so the fast path skips
/// git's ref machinery entirely: split the bundle's header from its packfile
/// and stream the pack straight into `git index-pack`. That is one process
/// instead of two and drops ref negotiation, ref updates, and FETCH_HEAD
/// bookkeeping that `git fetch` would do and then throw away.
///
/// Bundles are thin (each carries only a delta, with earlier heads as
/// prerequisites), hence `--fix-thin`; replaying in sequence order guarantees
/// the delta bases are already present. If the pack cannot be resolved, the
/// chain is broken and this reports failure rather than leaving a partial
/// object store.
///
/// The slow path remains as a fallback for any bundle whose header this does
/// not parse, so an unfamiliar bundle version degrades in speed rather than
/// breaking.
pub fn import_bundle_objects(repo_dir: Option<&str>, bundle_path: &std::path::Path) -> bool {
    match std::fs::read(bundle_path) {
        Ok(data) => match bundle_pack_offset(&data) {
            Some(off) if data[off..].starts_with(b"PACK") => {
                if index_pack_stdin(repo_dir, &data[off..]) {
                    return true;
                }
                // Fall through: a pack we could not index may still be
                // importable by git's own reader.
                import_bundle_via_fetch(repo_dir, bundle_path)
            }
            _ => import_bundle_via_fetch(repo_dir, bundle_path),
        },
        Err(_) => false,
    }
}

/// Object format declared by a git bundle, if it says.
///
/// A v3 bundle header carries `@object-format=sha256`; a v2 bundle has no such
/// line and is SHA-1. A clone must init with the same format as the writer,
/// because git cannot convert a repository in place -- and SafeHub carries the
/// ids as opaque bytes, so nothing else in the stack needs to know.
pub fn bundle_object_format(data: &[u8]) -> Option<String> {
    let head_len = data.len().min(8192);
    let head = &data[..head_len];
    for line in head.split(|&b| b == b'\n') {
        if line.is_empty() {
            break; // end of header
        }
        if let Some(rest) = line.strip_prefix(b"@object-format=") {
            return String::from_utf8(rest.to_vec()).ok();
        }
    }
    None
}

/// Byte offset of the packfile inside a git bundle.
///
/// A bundle header is newline-terminated ASCII (`# v2 git bundle`, capability
/// lines, ref lines, `-<oid>` prerequisite lines) and is closed by an empty
/// line; the packfile follows immediately. Returns `None` if no empty line is
/// found, which means this is not a bundle we recognise.
fn bundle_pack_offset(data: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < data.len() {
        let nl = data[i..].iter().position(|&b| b == b'\n')? + i;
        if nl == i {
            return Some(i + 1); // empty line terminates the header
        }
        i = nl + 1;
    }
    None
}

/// How many bundle imports to allow between multi-pack-index refreshes.
///
/// Each replayed head leaves its own packfile, so a deep clone accumulates one
/// pack per push. Git resolves an object by consulting pack indexes in turn, so
/// once the count is in the thousands both `--fix-thin` delta resolution and
/// ordinary lookups start scaling with the number of packs, and per-head import
/// cost climbs instead of staying flat. A multi-pack-index gives git a single
/// sorted lookup across every pack, which restores flat per-head cost; writing
/// it every `MIDX_REFRESH_EVERY` imports keeps the write itself amortized.
const MIDX_REFRESH_EVERY: usize = 256;

/// Refresh the multi-pack-index if `imported` has crossed a refresh boundary.
///
/// Called from the clone replay loop. Failure is not fatal: the object store is
/// already correct without a multi-pack-index, and this is purely a lookup
/// accelerator, so a git build without `multi-pack-index` support simply keeps
/// the slower path.
pub fn maybe_refresh_multi_pack_index(repo_dir: Option<&str>, imported: usize) {
    if imported == 0 || imported % MIDX_REFRESH_EVERY != 0 {
        return;
    }
    refresh_multi_pack_index(repo_dir);
}

/// Write (or rewrite) the multi-pack-index over every pack in the store.
pub fn refresh_multi_pack_index(repo_dir: Option<&str>) {
    use std::process::{Command, Stdio};
    let run = |args: &[&str]| {
        let mut cmd = Command::new("git");
        if let Some(d) = repo_dir {
            cmd.args(["-C", d]);
        }
        let _ = cmd
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    // The index is only consulted when the reader is told to; setting it here
    // rather than at init keeps a repository that never deep-clones untouched.
    run(&["config", "core.multiPackIndex", "true"]);
    run(&["multi-pack-index", "write"]);
}

/// Stream a packfile into the object store via `git index-pack --stdin`.
fn index_pack_stdin(repo_dir: Option<&str>, pack: &[u8]) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("git");
    if let Some(d) = repo_dir {
        cmd.args(["-C", d]);
    }
    let mut child = match cmd
        .args(["index-pack", "--stdin", "--fix-thin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    {
        // Dropping stdin closes the pipe, which is what makes index-pack finish.
        let Some(mut si) = child.stdin.take() else {
            return false;
        };
        if si.write_all(pack).is_err() {
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Original path: enumerate the bundle's refs and fetch exactly those.
///
/// A bare `git fetch <bundle>` resolves `HEAD`, which bundles built for a named
/// branch do not carry, and a blanket `+refs/*:` refspec misses `HEAD`-only
/// bundles while still exiting zero. Asking for what the bundle actually lists
/// covers both.
fn import_bundle_via_fetch(repo_dir: Option<&str>, bundle_path: &std::path::Path) -> bool {
    use std::process::Command;

    let mut list = Command::new("git");
    if let Some(d) = repo_dir {
        list.args(["-C", d]);
    }
    let out = match list.arg("bundle").arg("list-heads").arg(bundle_path).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };

    let mut refspecs: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let Some((_, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let dest = name.strip_prefix("refs/").unwrap_or(name);
        refspecs.push(format!("+{name}:refs/safehub/import/{dest}"));
    }
    if refspecs.is_empty() {
        return true;
    }

    let mut fetch = Command::new("git");
    if let Some(d) = repo_dir {
        fetch.args(["-C", d]);
    }
    fetch.arg("fetch").arg(bundle_path).args(&refspecs);
    fetch.status().map(|s| s.success()).unwrap_or(false)
}
