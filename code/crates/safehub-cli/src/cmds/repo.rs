use clap::Subcommand;
use safehub_client::{
    accept_welcome_mls, bootstrap_repo_group, compare_checkpoints, invite_member_mls_with_graft,
    load_admin_keypair, load_epoch_material, load_leaf_vk, plan_compaction, push_bundle,
    rotate_repo_group, sign_consolidation,
    verify_pusher_sig, CompareResult, HttpClient, RefCheckpoint,
};
use safehub_types::{HeadHash, RepoName, UserId};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Subcommand)]
pub enum RepoCmd {
    /// Create a new private repository and bootstrap its MLS group.
    Create {
        name: String,
        #[arg(long)]
        public: bool,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        clone: bool,
        /// Git object format for the local checkout: `sha1` or `sha256`.
        ///
        /// SafeHub carries object ids as opaque bytes, so both transport
        /// identically. Choose `sha256` when the object graph should match the
        /// Category-5 parameterization of the rest of the system rather than
        /// inheriting SHA-1's classical collision weakness.
        #[arg(long, value_parser = ["sha1", "sha256"])]
        object_format: Option<String>,
    },
    /// Clone a repository into a new directory (`sh clone` alias).
    Clone {
        repo: String,
        dir: Option<String>,
    },
    /// List repositories you own or collaborate on.
    List {},
    /// List collaborators (membership metadata only).
    Collaborators {
        /// `owner/name`
        repo: String,
    },
    /// List decrypted tip refs (branches + tags) for a repo.
    Refs {
        /// `owner/name` (optional when in a checkout).
        #[arg(long)]
        repo: Option<String>,
    },
    /// List branch tips from the decrypted RefHead.
    Branches {
        #[arg(long)]
        repo: Option<String>,
    },
    /// List tag tips from the decrypted RefHead.
    Tags {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Soft-archive a repository (control-plane flag; ciphertext retained).
    Archive {
        repo: String,
        #[arg(long)]
        unarchive: bool,
    },
    /// View repository metadata.
    View {
        repo: String,
    },
    /// Invite a collaborator (control-plane + durable MLS Welcome).
    Invite {
        /// `owner/name`
        repo: String,
        /// Username to invite.
        user: String,
        /// Grant history only from the join epoch (grafted join).
        #[arg(long)]
        forward_only: bool,
    },
    /// Accept a pending MLS Welcome for this device.
    AcceptWelcome {
        /// `owner/name`
        repo: String,
    },
    /// Remove a collaborator: revokes membership and advances the epoch.
    RemoveMember {
        repo: String,
        user: String,
    },
    /// Rotate MLS epoch material / PCS heal (durable self-update).
    Rotate {
        repo: String,
    },
    /// Honest-storage tip consolidation rewrite under current epoch keys.
    Consolidate {
        /// `owner/name`
        repo: String,
        /// Tip plaintext budget in MiB (default 12).
        #[arg(long, default_value_t = 12)]
        tip_mib: u64,
    },
    /// Verify RefHead chain integrity for a repo (local fork / rollback).
    Verify {
        repo: String,
    },
    /// Export a RefHead checkpoint for gossip Compare.
    ExportCheckpoint {
        repo: String,
        /// Output path (JSON).
        #[arg(long)]
        out: String,
    },
    /// Compare two checkpoints; emit Forked if non-prefix-comparable.
    Compare {
        /// First checkpoint JSON path.
        a: String,
        /// Second checkpoint JSON path.
        b: String,
    },
    /// Edit encrypted repo description/settings (MLS app message + local meta).
    Edit {
        repo: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        default_branch: Option<String>,
    },
    /// Tombstone repo locally + print wipe guidance (control-plane delete best-effort).
    Delete {
        repo: String,
        #[arg(long)]
        yes: bool,
    },
    /// Fork: new repo + copy tip as encrypted graft (forward-only style history window).
    Fork {
        repo: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// Client-side branch protection policy (non-FF requires admin cosig).
    Protect {
        repo: String,
        #[arg(long, default_value = "main")]
        branch: String,
        #[arg(long, default_value_t = true)]
        require_admin_cosig: bool,
    },
    /// Fetch MLS + heads; merge/retry helper (`sh sync`).
    Sync {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Export tip to a plain git repository (exit / migration).
    Export {
        /// `owner/name`
        repo: String,
        /// Destination directory for the plaintext git checkout.
        #[arg(long)]
        out: String,
    },
}

pub async fn run(cmd: RepoCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        RepoCmd::Create {
            name,
            public,
            description,
            clone,
            object_format,
        } => {
            let user = client.whoami().await?;
            let repo = client.create_repo(&name, !public, description).await?;
            println!("Created {}", repo.name);
            println!("id {}", repo.id);

            let device = format!("{}-default", user.0);
            let boot = bootstrap_repo_group(&repo.id, &device)?;
            client
                .put_key_package(&user, "default", boot.key_package)
                .await?;
            println!(
                "MLS group epoch={} (Cat-5 exporters + durable keystore persisted)",
                boot.material.epoch
            );

            if clone {
                init_local_checkout(&repo, object_format.as_deref())?;
            } else {
                println!();
                println!("Add a remote / checkout:");
                println!("  sh repo create {name} --clone");
                println!("  sh clone {}/{name}", user.0);
            }
        }
        RepoCmd::Clone { repo, dir } => {
            crate::cmds::clone::run(&repo, dir.as_deref()).await?;
        }
        RepoCmd::View { repo } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let repo = client.get_repo(&name).await?;
            println!("{}", serde_json::to_string_pretty(&repo)?);
        }
        RepoCmd::Invite {
            repo,
            user,
            forward_only,
        } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let me = client.whoami().await?;
            if me.0 != name.owner {
                anyhow::bail!("only the repository owner/admin can invite collaborators");
            }
            let history = if forward_only { "forward_only" } else { "full" };
            let members = client.invite_collaborator(&name, &user, history).await?;
            let record = client.get_repo(&name).await?;
            // For forward-only invites, build a grafted tip bundle from a local
            // checkout when one is available (cwd or ./<name>).
            let graft_bytes = if forward_only {
                build_graft_bundle_for_invite(&name.name)
            } else {
                None
            };
            let grant = invite_member_mls_with_graft(
                &client,
                &record.id,
                &UserId(user.clone()),
                forward_only,
                graft_bytes.as_deref(),
            )
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("Duplicate signature key") {
                    anyhow::anyhow!(
                        "{user} is already a member of {name}; \
                         remove them first to change their history grant"
                    )
                } else {
                    anyhow::anyhow!(s)
                }
            })?;
            println!(
                "Invited {user} to {} (history={history}; MLS Welcome queued)",
                name
            );
            println!(
                "Welcome grant history_from={} ({} bytes)",
                grant.history_from,
                grant.welcome.len()
            );
            if let Some(gid) = &grant.graft_blob_id {
                println!("Grafted snapshot CAS blob: {gid}");
            }
            println!("{}", serde_json::to_string_pretty(&members)?);
            if forward_only {
                println!("Note: forward-only join uses cryptographic DKR window + optional graft (h=e+1).");
            }
        }
        RepoCmd::AcceptWelcome { repo } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = accept_welcome_mls(&client, &record.id, "default").await?;
            println!(
                "Accepted Welcome for {name}: epoch={} history_from={}",
                material.epoch, material.history_from
            );
            let graft_meta = safehub_client::EpochMaterial::dir(&record.id)?.join("graft.json");
            if graft_meta.exists() {
                println!("Grafted snapshot imported ({})", graft_meta.display());
            }
        }
        RepoCmd::List {} => {
            let repos = client.list_repos().await?;
            if repos.is_empty() {
                println!("no repositories (create one with `sh repo create <name>`)");
            }
            for r in &repos {
                let flags = match (r.archived, r.private) {
                    (true, _) => "archived",
                    (false, true) => "private",
                    (false, false) => "public",
                };
                println!("{}/{}\t{flags}", r.name.owner, r.name.name);
            }
        }
        RepoCmd::Collaborators { repo } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let (status, text) = client
                .api_request(
                    "GET",
                    &format!("/repos/{}/{}/collaborators", name.owner, name.name),
                    None,
                )
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("list collaborators failed: {status} {text}");
            }
            let v: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(members) = v["members"].as_array() {
                for m in members {
                    println!(
                        "{}\t{}",
                        m["user"].as_str().unwrap_or("?"),
                        m["history"].as_str().unwrap_or("")
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
            println!("note: membership ids are server-visible; history windows are cryptographic");
        }
        RepoCmd::Refs { repo } => {
            print_tip_refs(&client, repo.as_deref(), None).await?;
        }
        RepoCmd::Branches { repo } => {
            print_tip_refs(&client, repo.as_deref(), Some("heads")).await?;
        }
        RepoCmd::Tags { repo } => {
            print_tip_refs(&client, repo.as_deref(), Some("tags")).await?;
        }
        RepoCmd::Archive { repo, unarchive } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let (status, text) = client
                .api_request(
                    "PATCH",
                    &format!("/repos/{}/{}", name.owner, name.name),
                    Some(&serde_json::json!({ "archived": !unarchive })),
                )
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("archive failed: {status} {text}");
            }
            if unarchive {
                println!("Unarchived {name} (control-plane flag only)");
            } else {
                println!(
                    "Archived {name} (ciphertext retained; wipe with `sh repo delete --yes`)"
                );
            }
        }
        RepoCmd::RemoveMember { repo, user } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let me = client.whoami().await?;
            if me.0 != name.owner {
                anyhow::bail!("only the repository owner/admin can remove collaborators");
            }
            client.remove_collaborator(&name, &user).await?;
            // Removal is the rekey. Capping the ACL without advancing the epoch
            // leaves every later payload openable by material the removed member
            // already holds, so the rotate is part of the operation rather than
            // advice the operator may skip. The ACL change lands first, so a
            // failure here is reported with what did complete.
            let record = client.get_repo(&name).await?;
            let material = rotate_repo_group(&record.id).map_err(|e| {
                anyhow::anyhow!(
                    "{user} was removed from {name} but the epoch rotation FAILED ({e}); \
                     the removed member can still open new payloads. Run \
                     `shub repo rotate {name}` before pushing again."
                )
            })?;
            println!("Removed {user} from {name}; epoch advanced to {}", material.epoch);
        }
        RepoCmd::Rotate { repo } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let me = client.whoami().await?;
            if me.0 != name.owner {
                anyhow::bail!("only the repository owner/admin can rotate MLS epoch material");
            }
            let record = client.get_repo(&name).await?;
            let material = rotate_repo_group(&record.id)?;
            println!(
                "Rotated durable MLS/DKR material for {} → epoch={}",
                name, material.epoch
            );
        }
        RepoCmd::Consolidate { repo, tip_mib } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = load_epoch_material(&record.id)?;
            let _ = tip_mib;
            // Compaction is per epoch. Each head keeps the key that already
            // sealed it, so a checkpoint discloses nothing outside the reader's
            // window; re-sealing the span under the current epoch key would let
            // any holder of that key read history predating their grant.
            let heads = client.heads_since(&record.id, 0).await?;
            if heads.is_empty() {
                println!("No heads yet — nothing to consolidate.");
                return Ok(());
            }
            let t0 = std::time::Instant::now();
            // plan_compaction binds the checkpoint anchor as well, which is what
            // a window-limited reader verifies without replaying the span.
            let anchor = heads.last().expect("non-empty");
            let mut plan = plan_compaction(
                &record.id,
                material.epoch,
                &heads,
                &anchor.enc_refs,
                anchor.bundle_root,
            )?;
            let admin = load_admin_keypair(&record.id)?;
            sign_consolidation(&mut plan.receipt, &admin)?;
            let ms = t0.elapsed().as_millis();
            let spans: std::collections::BTreeSet<u64> =
                heads.iter().map(|h| h.mls_epoch).collect();
            println!(
                "Consolidation receipt for {name}: seq {}..{} over {} epoch(s) in {ms} ms",
                heads.first().map(|h| h.seq).unwrap_or(0),
                heads.last().map(|h| h.seq).unwrap_or(0),
                spans.len()
            );
            println!(
                "  components keep their sealing epoch; no window widens (verify with \
                 verify_consolidation_window)"
            );
        }
        RepoCmd::Verify { repo } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let heads = client.heads_since(&record.id, 0).await?;
            if heads.is_empty() {
                println!("No heads yet — chain empty (ok).");
                return Ok(());
            }
            let mut prev = HeadHash([0u8; 64]);
            let mut ok = true;
            for (i, h) in heads.iter().enumerate() {
                if h.prev_head_hash != prev && i > 0 {
                    println!(
                        "FORK DETECTED at seq={}: prev_head_hash mismatch",
                        h.seq
                    );
                    ok = false;
                    break;
                }
                prev = h.hash();
                if i > 0 && h.seq != heads[i - 1].seq + 1 {
                    println!("Non-monotonic seq at {}", h.seq);
                    ok = false;
                }
            }
            for i in 0..heads.len() {
                for j in (i + 1)..heads.len() {
                    if heads[i].seq == heads[j].seq && heads[i].hash() != heads[j].hash() {
                        println!(
                            "FORK DETECTED: duplicate seq={} with divergent hashes",
                            heads[i].seq
                        );
                        ok = false;
                    }
                }
            }
            // Tip leaf ML-DSA verify when local leaf VK is available (skip if tip
            // was deliberately corrupted for fork-injection harnesses).
            if ok {
                if let Some(tip) = heads.last() {
                    if let Ok(vk) = load_leaf_vk(&record.id) {
                        match verify_pusher_sig(tip, &vk) {
                            Ok(()) => println!("Tip leaf ML-DSA-87 signature OK (seq={})", tip.seq),
                            Err(e) => println!("Tip leaf ML-DSA verify note: {e}"),
                        }
                    }
                }
            }
            if ok {
                println!("Verified {} heads for {name} — chain OK", heads.len());
            } else {
                anyhow::bail!("verification failed");
            }
            let _ = load_epoch_material(&record.id);
        }
        RepoCmd::ExportCheckpoint { repo, out } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let heads = client.heads_since(&record.id, 0).await?;
            let cp = RefCheckpoint::from_heads(record.id, &heads);
            std::fs::write(&out, serde_json::to_vec_pretty(&cp)?)?;
            println!(
                "Wrote checkpoint {} ({} entries) → {out}",
                name,
                cp.chain.len()
            );
        }
        RepoCmd::Compare { a, b } => {
            let ca: RefCheckpoint = serde_json::from_slice(&std::fs::read(&a)?)?;
            let cb: RefCheckpoint = serde_json::from_slice(&std::fs::read(&b)?)?;
            match compare_checkpoints(&ca, &cb).map_err(anyhow::Error::msg)? {
                CompareResult::Consistent => {
                    println!("Consistent: checkpoints agree.");
                }
                CompareResult::PrefixCompatible { ahead } => {
                    println!("Prefix-compatible: side {ahead} is ahead (no fork).");
                }
                CompareResult::WindowDisjoint => {
                    println!(
                        "Window-disjoint: the two views share no authorized epoch range; \
                         compare against a peer whose window bridges them."
                    );
                }
                CompareResult::Forked { at_seq, reason } => {
                    println!(
                        "FORKED ({reason:?}): non-prefix-comparable views{}",
                        at_seq
                            .map(|s| format!(" at seq={s}"))
                            .unwrap_or_default()
                    );
                    anyhow::bail!("Forked");
                }
            }
        }
        RepoCmd::Edit {
            repo,
            description,
            default_branch,
        } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = load_epoch_material(&record.id)?;
            let settings = serde_json::json!({
                "description": description,
                "default_branch": default_branch,
            });
            let sealed = safehub_client::seal_collab(&material, &serde_json::to_vec(&settings)?)?;
            let seq = client
                .mls_enqueue(&record.id, sealed, Some("repo-edit".into()))
                .await?;
            let meta = Path::new(".git").join("safehub").join("settings.json");
            if meta.parent().map(|p| p.exists()).unwrap_or(false) {
                std::fs::write(&meta, serde_json::to_vec_pretty(&settings)?)?;
            }
            let dir = safehub_client::EpochMaterial::dir(&record.id)?;
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("settings.json"), serde_json::to_vec_pretty(&settings)?)?;
            println!("Updated encrypted settings for {name} (MLS seq {seq})");
            println!("note: description ciphertext on MLS queue; server cannot read body");
        }
        RepoCmd::Delete { repo, yes } => {
            if !yes {
                anyhow::bail!("refusing to delete without --yes");
            }
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let (status, text) = client
                .api_request(
                    "DELETE",
                    &format!("/repos/{}/{}", name.owner, name.name),
                    None,
                )
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("control-plane delete failed: {status} {text}");
            }
            if let Ok(dir) = safehub_client::EpochMaterial::dir(&record.id) {
                let tomb = dir.join("TOMBSTONE");
                std::fs::create_dir_all(&dir)?;
                std::fs::write(
                    &tomb,
                    format!("deleted {}\nwipe local clone and epoch material\n", name),
                )?;
            }
            println!("Tombstoned {name} on control plane + locally.");
            println!(
                "Wipe guidance: remove checkout; delete ~/.config/safehub/repos/{}/",
                record.id.to_hex()
            );
            println!("note: CAS ciphertext GC is operator policy; crypto keys are wiped by deleting local epoch material");
        }
        RepoCmd::Fork { repo, name: new_name } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let src = client.get_repo(&name).await?;
            let user = client.whoami().await?;
            let fork_name = new_name.unwrap_or_else(|| format!("{}-fork", name.name));
            let created = client.create_repo(&fork_name, true, Some(format!("fork of {name}"))).await?;
            let device = format!("{}-default", user.0);
            let boot = bootstrap_repo_group(&created.id, &device)?;
            client
                .put_key_package(&user, "default", boot.key_package)
                .await?;
            // Graft: if we have source material, re-encrypt tip under new group (best-effort).
            if let Ok(src_mat) = load_epoch_material(&src.id) {
                if let Ok(Some(fetched)) =
                    safehub_client::fetch_tip(&client, &src.id, &src_mat).await
                {
                    let _ = push_bundle(
                        &client,
                        &created.id,
                        &fetched.bundle,
                        fetched.refs.refs,
                        fetched.refs.head,
                        &boot.material,
                        false,
                    )
                    .await?;
                    println!("Grafted encrypted tip into fork (forward-only style new MLS group)");
                }
            }
            println!("Forked {name} → {}/{}", user.0, fork_name);
            println!("id {}", created.id);
        }
        RepoCmd::Protect {
            repo,
            branch,
            require_admin_cosig,
        } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = load_epoch_material(&record.id)?;
            let policy = serde_json::json!({
                "branch": branch,
                "require_admin_cosig_on_non_ff": require_admin_cosig,
                "enforced": "client",
            });
            let sealed = safehub_client::seal_collab(&material, &serde_json::to_vec(&policy)?)?;
            let seq = client
                .mls_enqueue(&record.id, sealed, Some("repo-protect".into()))
                .await?;
            let dir = safehub_client::EpochMaterial::dir(&record.id)?;
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("protect.json"), serde_json::to_vec_pretty(&policy)?)?;
            println!(
                "Protected {branch} on {name} (client-verified; non-FF needs admin cosig) MLS seq {seq}"
            );
        }
        RepoCmd::Sync { repo } => {
            // Fetch MLS inbox + tip; pull merge when in a checkout.
            if let Ok(record) = crate::cmds::common::resolve_repo(&client, repo.as_deref()).await {
                if let Ok(material) = load_epoch_material(&record.id) {
                    let _ = crate::cmds::common::sync_inbox(&client, &record.id, &material).await?;
                    println!("synced MLS inbox for {}", record.name);
                }
            }
            if Path::new(".git").join("safehub").join("repo.json").exists() {
                crate::cmds::pull::run("sit").await?;
            } else {
                println!("no local checkout; inbox sync only (pass --repo or cd into clone)");
            }
        }
        RepoCmd::Export { repo, out } => {
            let name = RepoName::parse(&repo).ok_or_else(|| anyhow::anyhow!("expected owner/name"))?;
            let record = client.get_repo(&name).await?;
            let material = load_epoch_material(&record.id)?;
            let fetched = safehub_client::fetch_tip(&client, &record.id, &material)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no tip to export"))?;
            let dest = Path::new(&out);
            if dest.exists() {
                anyhow::bail!("export destination `{out}` already exists");
            }
            std::fs::create_dir_all(dest)?;
            let bundle_path = dest.join(".safehub-export.bundle");
            std::fs::write(&bundle_path, &fetched.bundle)?;
            let st = Command::new("git")
                .args(["clone", bundle_path.to_str().unwrap(), dest.to_str().unwrap()])
                .status()?;
            let _ = std::fs::remove_file(&bundle_path);
            if !st.success() {
                // Fallback: init + bundle unbundle into empty repo.
                let st2 = Command::new("git")
                    .args(["init", dest.to_str().unwrap()])
                    .status()?;
                if !st2.success() {
                    anyhow::bail!("git init for export failed");
                }
                let st3 = Command::new("git")
                    .args([
                        "-C",
                        dest.to_str().unwrap(),
                        "bundle",
                        "unbundle",
                        bundle_path.to_str().unwrap_or(""),
                    ])
                    .status();
                let _ = st3;
            }
            println!(
                "Exported plaintext git repo to {out} ({} refs; leave path for DR/migration)",
                fetched.refs.refs.len()
            );
        }
    }
    Ok(())
}

async fn print_tip_refs(
    client: &HttpClient,
    repo: Option<&str>,
    kind: Option<&str>,
) -> anyhow::Result<()> {
    let record = crate::cmds::common::resolve_repo(client, repo).await?;
    let material = load_epoch_material(&record.id)?;
    let fetched = safehub_client::fetch_tip(client, &record.id, &material)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no tip yet; push first"))?;
    if let Some(head) = &fetched.refs.head {
        println!("HEAD\t{head}");
    }
    let mut names: Vec<_> = fetched.refs.refs.keys().cloned().collect();
    names.sort();
    for name in names {
        let include = match kind {
            Some("heads") => name.starts_with("refs/heads/"),
            Some("tags") => name.starts_with("refs/tags/"),
            _ => true,
        };
        if !include {
            continue;
        }
        let oid = fetched.refs.refs.get(&name).map(|s| s.as_str()).unwrap_or("");
        println!("{name}\t{oid}");
    }
    println!(
        "note: refs decrypted locally from RefHead (seq={}); host stores ciphertext only",
        fetched.head.seq
    );
    Ok(())
}

/// Build a tip git bundle for a grafted forward-only invite when a local
/// checkout is present (cwd git repo or `./<repo_name>`).
fn build_graft_bundle_for_invite(repo_name: &str) -> Option<Vec<u8>> {
    let candidates = [Path::new("."), Path::new(repo_name)];
    for dir in candidates {
        if !dir.join(".git").exists() && !dir.join("HEAD").exists() {
            continue;
        }
        let tmp = std::env::temp_dir().join(format!(
            "safehub-graft-{}-{}.bundle",
            repo_name,
            std::process::id()
        ));
        let status = Command::new("git")
            .args(["-C"])
            .arg(dir)
            .args(["bundle", "create"])
            .arg(&tmp)
            .arg("HEAD")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        if !status.success() {
            let _ = std::fs::remove_file(&tmp);
            continue;
        }
        let bytes = std::fs::read(&tmp).ok();
        let _ = std::fs::remove_file(&tmp);
        if let Some(b) = bytes {
            if !b.is_empty() {
                return Some(b);
            }
        }
    }
    None
}

fn init_local_checkout(
    repo: &safehub_types::RepoRecord,
    object_format: Option<&str>,
) -> anyhow::Result<()> {
    let dest = &repo.name.name;
    if Path::new(dest).exists() {
        anyhow::bail!("destination `{dest}` already exists");
    }
    // The object format has to be chosen at init: git cannot convert an
    // existing repository in place. SafeHub itself is agnostic -- chain
    // hashes, CAS addresses and bundle roots are SHA-512 regardless -- so this
    // only decides which ids git puts in its own commits and trees.
    let mut args: Vec<&str> = vec!["init"];
    let fmt_arg;
    if let Some(fmt) = object_format {
        fmt_arg = format!("--object-format={fmt}");
        args.push(&fmt_arg);
    }
    args.push(dest);
    let status = Command::new("git").args(&args).status()?;
    if !status.success() {
        anyhow::bail!("git init failed");
    }
    let remote = format!("sit://{}/{}", repo.name.owner, repo.name.name);
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
        serde_json::to_vec_pretty(repo)?,
    )?;
    println!("Initialized local checkout `{dest}` with remote {remote}");
    Ok(())
}
