use safehub_client::{fetch_bundles_since, load_epoch_material, HttpClient};
use safehub_types::RepoRecord;
use std::path::Path;
use std::process::Command;

/// Fetch encrypted tip and merge/ff into the current branch (`git pull` semantics).
pub async fn run(remote: &str) -> anyhow::Result<()> {
    run_fetch_merge(remote, true, false).await
}

/// Fetch + rebase onto the remote tip (`git pull --rebase` analogue).
pub async fn run_rebase(remote: &str) -> anyhow::Result<()> {
    run_fetch_merge(remote, true, true).await
}

/// Fetch only (no merge).
#[allow(dead_code)] // used by `sit` binary; `sh` shares this module
pub async fn run_fetch(remote: &str) -> anyhow::Result<()> {
    run_fetch_merge(remote, false, false).await
}

async fn run_fetch_merge(remote: &str, merge: bool, rebase: bool) -> anyhow::Result<()> {
    let _ = remote;
    let repo = load_local_repo()?;
    let client = HttpClient::from_disk()?;
    let material = load_epoch_material(&repo.id)?;

    // Deltas: ask the server for the heads after the last sequence this
    // checkout already applied, then replay their bundles in order. Bundles are
    // not self-contained, so skipping one would leave the object store missing
    // prerequisites.
    let have = local_applied_seq();
    // Anchor the returned run to the head we already trust, so a host that
    // rewinds or forks us relative to what this checkout holds is rejected
    // rather than replayed.
    let anchor = local_applied_head();
    let batch = fetch_bundles_since(&client, &repo.id, &material, have, anchor).await?;
    let Some(tip) = batch.last() else {
        if have > 0 {
            println!("Already up to date (seq={have}).");
        } else {
            println!("Remote has no heads yet.");
        }
        return Ok(());
    };

    println!(
        "tip seq={} epoch={} refs={} ({} bundle{} to apply)",
        tip.head.seq,
        tip.head.mls_epoch,
        tip.refs.refs.len(),
        batch.len(),
        if batch.len() == 1 { "" } else { "s" }
    );
    for (name, oid) in &tip.refs.refs {
        println!("  {name} -> {oid}");
    }

    for fetched in &batch {
        // Ref-only heads (deletions) carry no objects; importing them fails,
        // and bailing here would strand every reader of a repository that ever
        // deleted a ref. The ref set still applies below.
        if safehub_client::is_ref_only_bundle(&fetched.bundle) {
            record_applied_seq(fetched.head.seq, fetched.head.hash());
            continue;
        }
        let bundle_path = std::env::temp_dir().join(format!(
            "safehub-fetch-{}.bundle",
            fetched.head.seq
        ));
        std::fs::write(&bundle_path, &fetched.bundle)?;
        let ok = crate::cmds::common::import_bundle_objects(None, &bundle_path);
        let _ = std::fs::remove_file(&bundle_path);
        if !ok {
            anyhow::bail!(
                "could not import the bundle at seq {} ({} bytes); the delta chain \
                 is incomplete, so the working tree was left untouched",
                fetched.head.seq,
                fetched.bundle.len()
            );
        }
        record_applied_seq(fetched.head.seq, fetched.head.hash());
    }
    println!("imported {} decrypted bundle(s)", batch.len());
    for (refname, oid) in &tip.refs.refs {
        let _ = Command::new("git")
            .args(["update-ref", &format!("refs/safehub/tip/{refname}"), oid])
            .status();
    }
    let fetched = tip;

    if !merge {
        return Ok(());
    }

    // Prefer HEAD-matching remote ref, else main/master, else first ref.
    let head_sym = fetched.refs.head.clone().unwrap_or_default();
    let target_ref = if let Some(r) = head_sym.strip_prefix("ref: ") {
        r.to_string()
    } else if fetched.refs.refs.contains_key("refs/heads/main") {
        "refs/heads/main".into()
    } else if fetched.refs.refs.contains_key("refs/heads/master") {
        "refs/heads/master".into()
    } else {
        fetched
            .refs.refs
            .keys()
            .next()
            .cloned()
            .unwrap_or_default()
    };

    let Some(remote_oid) = fetched.refs.refs.get(&target_ref) else {
        println!("no merge target ref in tip");
        return Ok(());
    };

    if rebase {
        let status = Command::new("git")
            .args(["rebase", remote_oid])
            .status()?;
        if !status.success() {
            anyhow::bail!("rebase failed; resolve conflicts then `git rebase --continue`");
        }
        println!("rebased onto {target_ref} ({remote_oid})");
        return Ok(());
    }

    // Fast-forward if possible, else merge.
    let ff = Command::new("git")
        .args(["merge-base", "--is-ancestor", "HEAD", remote_oid])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ff {
        let status = Command::new("git")
            .args(["merge", "--ff-only", remote_oid])
            .status()?;
        if status.success() {
            println!("fast-forwarded to {target_ref} ({remote_oid})");
        } else {
            // Fallback: reset --hard only if working tree clean? Prefer merge.
            let status = Command::new("git")
                .args(["merge", remote_oid, "-m", "sit pull: merge remote tip"])
                .status()?;
            if !status.success() {
                anyhow::bail!("merge failed; resolve conflicts then continue");
            }
            println!("merged {target_ref} ({remote_oid})");
        }
    } else {
        // Check if we're ahead (already contain remote) — then nothing to do.
        let already = Command::new("git")
            .args(["merge-base", "--is-ancestor", remote_oid, "HEAD"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if already {
            println!("Already up to date.");
            return Ok(());
        }
        let status = Command::new("git")
            .args(["merge", remote_oid, "-m", "sit pull: merge remote tip"])
            .status()?;
        if !status.success() {
            anyhow::bail!("merge failed; resolve conflicts then continue");
        }
        println!("merged {target_ref} ({remote_oid})");
    }
    Ok(())
}

fn load_local_repo() -> anyhow::Result<RepoRecord> {
    let path = Path::new(".git").join("safehub").join("repo.json");
    if !path.exists() {
        anyhow::bail!("not a SafeHub checkout; run `sit clone` or `sh repo create --clone`");
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}


/// Path holding the last head sequence this checkout has applied.
fn applied_seq_path() -> std::path::PathBuf {
    std::path::PathBuf::from(".git/safehub/applied_seq")
}

/// Path holding the hash of the last head this checkout applied.
fn applied_head_path() -> std::path::PathBuf {
    std::path::PathBuf::from(".git/safehub/applied_head")
}

/// Last applied head sequence, or 0 when this checkout has none.
fn local_applied_seq() -> u64 {
    std::fs::read_to_string(applied_seq_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Hash of the last applied head, used as the chain anchor for the next fetch.
///
/// `None` for checkouts written before this was recorded: the fetch then
/// verifies internal continuity only, which is weaker but does not break an
/// existing working copy.
fn local_applied_head() -> Option<safehub_types::HeadHash> {
    let s = std::fs::read_to_string(applied_head_path()).ok()?;
    safehub_types::HeadHash::from_hex(s.trim()).ok()
}

/// Record `seq` and its head hash so the next fetch asks only for what follows
/// and can prove the continuation descends from it.
fn record_applied_seq(seq: u64, head_hash: safehub_types::HeadHash) {
    let p = applied_seq_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, seq.to_string());
    let _ = std::fs::write(applied_head_path(), head_hash.to_hex());
}
