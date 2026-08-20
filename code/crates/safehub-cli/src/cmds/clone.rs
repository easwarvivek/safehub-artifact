use safehub_client::{fetch_bundles_since, load_epoch_material, HttpClient};
use safehub_types::RepoName;
use std::path::Path;
use std::process::Command;

pub async fn run(repo: &str, dir: Option<&str>) -> anyhow::Result<()> {
    let repo = repo
        .strip_prefix("sit://")
        .or_else(|| repo.strip_prefix("safehub://"))
        .unwrap_or(repo);
    let name = RepoName::parse(repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
    let dest = dir.unwrap_or(&name.name);

    let client = HttpClient::from_disk()?;
    let record = client.get_repo(&name).await?;

    if Path::new(dest).exists() {
        anyhow::bail!("destination `{dest}` already exists");
    }

    let status = Command::new("git").args(["init", dest]).status()?;
    if !status.success() {
        anyhow::bail!("git init failed");
    }

    let remote = format!("sit://{}/{}", name.owner, name.name);
    let status = Command::new("git")
        .args(["-C", dest, "remote", "add", "sit", &remote])
        .status()?;
    if !status.success() {
        anyhow::bail!("git remote add failed");
    }

    let meta_dir = Path::new(dest).join(".git").join("safehub");
    std::fs::create_dir_all(&meta_dir)?;
    std::fs::write(
        meta_dir.join("repo.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;

    println!("Initialized {dest}");
    println!("Remote: {remote}");
    println!("Repo id: {}", record.id);

    // Best-effort tip fetch when local MLS material exists (creator device).
    match load_epoch_material(&record.id) {
        Ok(material) => match fetch_bundles_since(&client, &record.id, &material, 0, Some(safehub_types::HeadHash::zero())).await {
            Ok(batch) if !batch.is_empty() => {
                // Bundles carry deltas, so a clone replays the whole chain from
                // the first head; applying only the tip would leave the object
                // store missing prerequisites.
                // Match the writer's object format before importing anything.
                // git cannot convert a repository in place, and the format is
                // only discoverable from the bundle header, which arrives after
                // init. Nothing has been imported yet, so re-initializing here
                // is safe; SafeHub itself is agnostic (chain hashes, CAS
                // addresses and bundle roots are SHA-512 either way).
                if let Some(fmt) = batch
                    .iter()
                    .find(|f| !safehub_client::is_ref_only_bundle(&f.bundle))
                    .and_then(|f| crate::cmds::common::bundle_object_format(&f.bundle))
                {
                    let current = Command::new("git")
                        .args(["-C", dest, "rev-parse", "--show-object-format"])
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if current != fmt {
                        println!("Remote uses the {fmt} object format; re-initializing");
                        std::fs::remove_dir_all(Path::new(dest).join(".git"))?;
                        let status = Command::new("git")
                            .args(["init", &format!("--object-format={fmt}"), dest])
                            .status()?;
                        if !status.success() {
                            anyhow::bail!("git init --object-format={fmt} failed");
                        }
                        let status = Command::new("git")
                            .args(["-C", dest, "remote", "add", "sit", &remote])
                            .status()?;
                        if !status.success() {
                            anyhow::bail!("git remote add failed after re-init");
                        }
                        std::fs::create_dir_all(&meta_dir)?;
                        std::fs::write(
                            meta_dir.join("repo.json"),
                            serde_json::to_vec_pretty(&record)?,
                        )?;
                    }
                }

                let mut applied = 0usize;
                let mut failed = None;
                for fetched in &batch {
                    // Ref-only heads (deletions) carry no objects; importing
                    // them is not just unnecessary, it fails and would break
                    // every clone of a repository that ever deleted a ref.
                    if safehub_client::is_ref_only_bundle(&fetched.bundle) {
                        continue;
                    }
                    let bundle_path = std::env::temp_dir().join(format!(
                        "safehub-clone-{}.bundle",
                        fetched.head.seq
                    ));
                    std::fs::write(&bundle_path, &fetched.bundle)?;
                    let ok = crate::cmds::common::import_bundle_objects(
                        Some(dest),
                        &bundle_path,
                    );
                    let _ = std::fs::remove_file(&bundle_path);
                    if ok {
                        applied += 1;
                        // Keep per-head import cost flat as packs accumulate:
                        // one pack lands per replayed head, and git's object
                        // lookup degrades with pack count without this.
                        crate::cmds::common::maybe_refresh_multi_pack_index(
                            Some(dest),
                            applied,
                        );
                    } else {
                        failed = Some(fetched.head.seq);
                        break;
                    }
                }
                if let Some(seq) = failed {
                    anyhow::bail!(
                        "could not import the bundle at seq {seq}; the delta chain \
                         is incomplete and the clone would be missing objects"
                    );
                }
                if applied >= 64 {
                    crate::cmds::common::refresh_multi_pack_index(Some(dest));
                }
                let tip = batch.last().expect("non-empty");
                if let Some((_, oid)) = tip.refs.refs.iter().next() {
                    let ok = Command::new("git")
                        .args(["-C", dest, "checkout", "-B", "main", oid])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if !ok {
                        anyhow::bail!(
                            "bundles replayed but checkout of {oid} failed; the clone \
                             would have an empty working tree"
                        );
                    }
                }
                let seq_path = std::path::Path::new(dest).join(".git/safehub/applied_seq");
                if let Some(d) = seq_path.parent() {
                    let _ = std::fs::create_dir_all(d);
                }
                let _ = std::fs::write(&seq_path, tip.head.seq.to_string());
                let _ = std::fs::write(
                    std::path::Path::new(dest).join(".git/safehub/applied_head"),
                    tip.head.hash().to_hex(),
                );
                println!(
                    "Fetched tip seq={} ({} refs, {} bundle(s) replayed)",
                    tip.head.seq,
                    tip.refs.refs.len(),
                    applied
                );
            }
            Ok(_) => println!("Remote has no heads yet — empty clone."),
            // A failed fetch must fail the clone. Reporting it as a note and
            // returning Ok leaves an empty working tree behind a zero exit
            // status, which is indistinguishable from a correct clone of an
            // empty repository — and if the failure was a chain or epoch-tag
            // rejection, it is exactly the case a user must not miss.
            Err(e) => anyhow::bail!(
                "refusing to complete the clone: {e}\n\
                 The host's head sequence did not verify, so no working tree was written."
            ),
        },
        Err(_) => {
            println!();
            println!(
                "Note: decrypt requires local MLS epoch material for this repo \
                 (from `sh repo create` on this device, or a future Welcome import)."
            );
        }
    }
    Ok(())
}
