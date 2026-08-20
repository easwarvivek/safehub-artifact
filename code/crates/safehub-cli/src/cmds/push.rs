use safehub_client::{load_epoch_material, push_bundle, push_bundle_reader, HttpClient};
use safehub_types::RepoRecord;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn run(remote: &str, refspec: &str) -> anyhow::Result<()> {
    run_with_force(remote, refspec, false).await
}

pub async fn run_with_force(remote: &str, refspec: &str, force: bool) -> anyhow::Result<()> {
    let _ = remote;
    let (force, refspec) = if let Some(rest) = refspec.strip_prefix('+') {
        (true, rest)
    } else {
        (force, refspec)
    };

    let repo = load_local_repo()?;
    let client = HttpClient::from_disk()?;
    let material = load_epoch_material(&repo.id)?;

    // Ref delete: `:dst` or empty src.
    if let Some((src, dst)) = refspec.split_once(':') {
        if src.is_empty() {
            return delete_remote_ref(&client, &repo, &material, dst).await;
        }
    }

    let (src, dst) = split_refspec(refspec);

    // Read the remote tip first: it supplies both the fast-forward baseline and
    // the exclusion set that turns this push into a delta.
    //
    // Fail closed on an unreadable tip — assuming a fast-forward we cannot prove
    // would silently discard another device's work.
    let tip = match safehub_client::fetch_tip(&client, &repo.id, &material).await {
        Ok(t) => t,
        Err(e) if force => {
            tracing::warn!("could not read remote tip ({e}); proceeding under --force");
            None
        }
        Err(e) => anyhow::bail!(
            "cannot verify the remote tip ({e}); refusing to push because a \
             fast-forward cannot be proven. Retry, or use `sit push --force`."
        ),
    };
    let mut remote_refs: BTreeMap<String, String> = BTreeMap::new();
    if let Some(prev) = &tip {
        remote_refs = prev.refs.refs.clone();
    }

    // Nothing to do when the remote already holds exactly what we would send.
    //
    // Without this, a no-op push is pathological rather than cheap: the only
    // available negative rev is the remote tip, which equals our own HEAD, and
    // build_bundle_and_refs skips a negative equal to the source (git refuses an
    // empty bundle). With no negatives left, `git bundle create` bundles the
    // ENTIRE history, so pushing nothing cost more than pushing megabytes --
    // measured at 673 ms against 123 ms for a real 3 MiB push on a 16 MB
    // repository, and rising with history.
    let dst_ref_probe = if dst.starts_with("refs/") {
        dst.clone()
    } else {
        format!("refs/heads/{dst}")
    };
    if let Ok(local_oid) = git_rev_parse(src) {
        if remote_refs.get(&dst_ref_probe) == Some(&local_oid) {
            println!("Everything up-to-date");
            return Ok(());
        }
    }

    // Bundle only what the remote is missing.
    let exclude: Vec<String> = remote_refs.values().cloned().collect();
    let (bundle_path, mut git_refs, head_symref) = build_bundle_and_refs(src, &dst, &exclude)?;

    // The manifest still names every ref, so the tip describes the whole repo
    // even though the bundle carries only the delta.
    for (k, v) in remote_refs.clone() {
        git_refs.entry(k).or_insert(v);
    }
    let dst_ref = if dst.starts_with("refs/") {
        dst.clone()
    } else {
        format!("refs/heads/{dst}")
    };
    if let Ok(oid) = git_rev_parse(src) {
        git_refs.insert(dst_ref, oid);
    }

    let repo_dir = std::env::current_dir().ok();
    let recomputed_non_ff =
        safehub_client::classify_non_ff(repo_dir.as_deref(), &remote_refs, &git_refs)
            .unwrap_or(true);
    if recomputed_non_ff && !force {
        let _ = std::fs::remove_file(&bundle_path);
        anyhow::bail!(
            "updates were rejected because the remote contains work you do not have \
             locally.\nThis is usually caused by another device pushing to the same \
             branch. Run `sit pull` to merge, then push again, or use `sit push \
             --force` (requires an admin co-signature)."
        );
    }
    let non_ff = recomputed_non_ff || force;

    let result = {
        let mut file = std::fs::File::open(&bundle_path)?;
        push_bundle_reader(
            &client,
            &repo.id,
            &mut file,
            git_refs,
            head_symref,
            &material,
            non_ff,
        )
        .await?
    };
    let _ = std::fs::remove_file(&bundle_path);

    let meta_dir = Path::new(".git").join("safehub");
    std::fs::create_dir_all(&meta_dir)?;
    std::fs::write(
        meta_dir.join(format!("push-{}.json", result.head.seq)),
        serde_json::to_vec_pretty(&serde_json::json!({
            "push_id": result.refs.push_id,
            "chunk_ids": result.refs.chunk_ids,
            "chunk_count": result.refs.chunk_ids.len(),
            "force": force,
        }))?,
    )?;

    // A successful push means this checkout already holds everything through
    // the new head — it authored it. Advancing the applied marker keeps the
    // next fetch asking only for what follows; without it a writer's `sit
    // fetch` re-downloads and re-decrypts its own entire history every time,
    // turning a no-op into O(history) work.
    record_applied_through(result.head.seq, result.head_hash);

    let hash = result.head_hash.to_hex();
    println!(
        "pushed seq={} epoch={} head={} force={force}",
        result.head.seq,
        result.head.mls_epoch,
        &hash[..16.min(hash.len())]
    );
    for (name, oid) in &result.refs.refs {
        println!("  {name} -> {oid}");
    }
    if force {
        println!("note: force push sets non_ff; admin co-sig attached when durable group present");
    }
    Ok(())
}

async fn delete_remote_ref(
    client: &HttpClient,
    repo: &RepoRecord,
    material: &safehub_client::EpochMaterial,
    dst: &str,
) -> anyhow::Result<()> {
    let dst_ref = if dst.starts_with("refs/") {
        dst.to_string()
    } else {
        format!("refs/heads/{dst}")
    };
    let mut git_refs = BTreeMap::new();
    let mut head_symref = None;
    if let Some(prev) = safehub_client::fetch_tip(client, &repo.id, material).await? {
        git_refs = prev.refs.refs;
        head_symref = prev.refs.head;
    }
    if git_refs.remove(&dst_ref).is_none() {
        anyhow::bail!("remote ref {dst_ref} not present");
    }
    // A deletion adds no objects, so there is no bundle to build. The head
    // still records the new ref set; readers detect this payload and apply the
    // refs without importing.
    let bundle = safehub_client::REF_ONLY_BUNDLE.to_vec();
    let result = push_bundle(
        client,
        &repo.id,
        &bundle,
        git_refs,
        head_symref,
        material,
        true, // non-ff / admin path for destructive ref update
    )
    .await?;
    println!(
        "deleted remote ref {dst_ref} (seq={} force/non_ff)",
        result.head.seq
    );
    Ok(())
}

fn split_refspec(refspec: &str) -> (&str, String) {
    if let Some((src, dst)) = refspec.split_once(':') {
        return (src, dst.to_string());
    }
    if refspec == "HEAD" {
        return ("HEAD", "refs/heads/main".into());
    }
    if refspec.starts_with("refs/") {
        return (refspec, refspec.to_string());
    }
    (refspec, format!("refs/heads/{refspec}"))
}

/// Build the push bundle.
///
/// `exclude` holds the ref tips the remote already has. Any of them present in
/// the local object store becomes a negative rev, so the bundle carries only
/// the delta since the previous head rather than the whole history. Readers
/// replay the chain (`fetch_bundles_since`), so a bundle need not stand alone.
fn build_bundle_and_refs(
    src: &str,
    dst: &str,
    exclude: &[String],
) -> anyhow::Result<(PathBuf, BTreeMap<String, String>, Option<String>)> {
    let oid = git_rev_parse(src)?;
    let bundle_path = std::env::temp_dir().join(format!("safehub-push-{oid}.bundle"));
    let mut args: Vec<String> = vec!["bundle".into(), "create".into()];
    args.push(bundle_path.to_string_lossy().into_owned());
    // Only exclude commits this repository actually has; a tip we cannot name
    // would make git reject the rev outright.
    let mut negatives = 0usize;
    for oid_ex in exclude {
        if oid_ex != &oid && git_has_commit(oid_ex) {
            args.push(format!("^{oid_ex}"));
            negatives += 1;
        }
    }
    args.push(src.to_string());
    if negatives > 0 {
        tracing::debug!(negatives, "pushing delta bundle");
    }
    let status = Command::new("git").args(&args).status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&bundle_path);
        anyhow::bail!(
            "git bundle create failed for {src}; refusing to push. Shipping a \
             placeholder payload would record a head that no reader can replay, \
             breaking every later clone and pull of this repository."
        );
    }

    let dst_ref = if dst.starts_with("refs/") {
        dst.to_string()
    } else {
        format!("refs/heads/{dst}")
    };
    let mut refs = BTreeMap::new();
    refs.insert(dst_ref.clone(), oid);
    Ok((bundle_path, refs, Some(format!("ref: {dst_ref}"))))
}

/// True when `oid` names a commit present in the local object store.
fn git_has_commit(oid: &str) -> bool {
    Command::new("git")
        .args(["cat-file", "-e", &format!("{oid}^{{commit}}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn git_rev_parse(rev: &str) -> anyhow::Result<String> {
    let out = Command::new("git").args(["rev-parse", rev]).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "git rev-parse {rev} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn load_local_repo() -> anyhow::Result<RepoRecord> {
    let path = Path::new(".git").join("safehub").join("repo.json");
    if !path.exists() {
        anyhow::bail!(
            "not a SafeHub checkout (missing .git/safehub/repo.json); run `sh repo create --clone` then `sit push`"
        );
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Record that this checkout holds every head through `seq`.
///
/// Mirrors what `pull`/`clone` write, so a writer and a reader converge on the
/// same fetch cursor. Failures are non-fatal: the marker is an optimisation,
/// and a missing one costs a redundant fetch rather than correctness.
fn record_applied_through(seq: u64, head_hash: safehub_types::HeadHash) {
    let dir = Path::new(".git").join("safehub");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join("applied_seq"), seq.to_string());
    let _ = std::fs::write(dir.join("applied_head"), head_hash.to_hex());
}
