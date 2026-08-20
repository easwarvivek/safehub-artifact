//! `sit` — VCS-facing CLI (git analogue for SafeHub).
//!
//! SafeHub-aware: `sit push` / `sit pull` / `sit fetch` / `sit clone` use
//! encrypted `sit://` (alias `safehub://`) transport.
//! Other verbs forward to the system `git` binary so everyday workflows stay
//! `sit …` without telling users to run `git`.

use std::process::{Command, ExitCode};
use tracing_subscriber::EnvFilter;

use safehub_cli::cmds;

fn print_help() {
    println!(
        "\
sit — SafeHub VCS CLI (git analogue)

Usage:
  sit <command> [args...]

SafeHub-aware (encrypted sit:// remotes):
  sit browse [--repo PATH] [--listen HOST:PORT]  local UI; remote fetch is opt-in
  sit clone <owner/name|sit://...> [dir]
  sit push  [--force|-f] [remote] [refspec]   (default remote: sit, refspec: HEAD)
  sit pull  [--rebase] [remote]    (fetch + merge/ff, or rebase onto remote tip)
  sit fetch [remote]               (fetch only)

Common local commands (forwarded to git):
  sit init | add | commit | status | log | diff | show | blame
  sit branch | checkout | switch | merge | rebase | cherry-pick | revert
  sit stash | tag | remote | reset | restore | clean | mv | rm
  sit rev-parse | cat-file | ls-files | describe | shortlog | …

Any unrecognized subcommand is forwarded: sit <args...> → git <args...>

Pair with `sh` for GitHub-style auth / repo / PR / issue workflows
(e.g. `sh auth login`, `sh repo create --clone`). Prefer `sit://` remotes;
`safehub://` remains a compatibility alias.

Install `sit-remote-safehub` on PATH (and its git-discovery shims) so the
underlying git can resolve sit:// / safehub:// if invoked directly."
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty()
        || matches!(
            args[0].as_str(),
            "-h" | "--help" | "help" | "-help"
        )
    {
        print_help();
        return Ok(());
    }
    if matches!(args[0].as_str(), "-V" | "--version") {
        println!("sit {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    match args[0].as_str() {
        "browse" => {
            let mut repo = std::path::PathBuf::from(".");
            let mut listen = "127.0.0.1:8081".to_string();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-h" | "--help" => {
                        println!(
                            "Usage: sit browse [--repo PATH] [--listen HOST:PORT]\n\n\
                             Browse local git objects in a GitHub-like UI. SafeHub remote fetch is opt-in in the UI."
                        );
                        return Ok(());
                    }
                    "--repo" | "-C" => {
                        i += 1;
                        repo = args
                            .get(i)
                            .map(std::path::PathBuf::from)
                            .ok_or_else(|| anyhow::anyhow!("--repo requires a path"))?;
                    }
                    "--listen" => {
                        i += 1;
                        listen = args
                            .get(i)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("--listen requires HOST:PORT"))?;
                    }
                    other => anyhow::bail!("unknown browse option: {other}"),
                }
                i += 1;
            }
            safehub_browse::run(safehub_browse::BrowseOptions {
                repo,
                listen: safehub_browse::parse_listen(&listen)?,
            })
            .await
        }
        "push" => {
            // Parse git-compatible flags explicitly. Anything unrecognised is an
            // error: silently treating it as a positional argument used to make
            // `--dry-run` perform a real push and `--delete` push instead of
            // deleting.
            let mut force = false;
            let mut dry_run = false;
            let mut delete = false;
            let mut set_upstream = false;
            let mut tags = false;
            let mut rest: Vec<&str> = Vec::new();
            let mut it = args.iter().skip(1).peekable();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--force" | "-f" => force = true,
                    "--dry-run" | "-n" => dry_run = true,
                    "--delete" | "-d" => delete = true,
                    "--set-upstream" | "-u" => set_upstream = true,
                    "--tags" => tags = true,
                    "--" => rest.extend(it.by_ref().map(String::as_str)),
                    other if other.starts_with('-') => {
                        anyhow::bail!(
                            "unknown option {other} for `sit push`\n\
                             supported: --force/-f, --dry-run/-n, --delete/-d, \
                             --set-upstream/-u, --tags\n\
                             other git push options are not supported over sit://"
                        )
                    }
                    other => rest.push(other),
                }
            }
            if tags {
                anyhow::bail!(
                    "`sit push --tags` is not supported: tags travel inside the \
                     encrypted bundle, so push the refs explicitly \
                     (e.g. `sit push sit refs/tags/v1`)"
                );
            }
            let remote = rest.first().copied().unwrap_or("sit");
            let refspec = rest.get(1).copied().unwrap_or("HEAD");
            if delete {
                // git: `push --delete <ref>` == `push <remote> :<ref>`.
                let target = if rest.len() >= 2 { rest[1] } else { rest_first_or_bail(&rest)? };
                let spec = format!(":{target}");
                if dry_run {
                    println!("dry run: would delete remote ref {target} on {remote}");
                    return Ok(());
                }
                return cmds::push::run_with_force(remote, &spec, true).await;
            }
            if dry_run {
                let resolved = std::process::Command::new("git")
                    .args(["rev-parse", "--short", refspec])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| refspec.to_string());
                println!("dry run: would push {refspec} ({resolved}) to {remote}");
                if set_upstream {
                    println!("dry run: would set upstream to {remote}/{refspec}");
                }
                return Ok(());
            }
            let out = cmds::push::run_with_force(remote, refspec, force).await;
            if out.is_ok() && set_upstream {
                let _ = std::process::Command::new("git")
                    .args(["branch", "--set-upstream-to", &format!("{remote}/{refspec}")])
                    .status();
            }
            out
        }
        "pull" => {
            let mut rebase = false;
            let mut remote = "sit";
            for a in args.iter().skip(1) {
                match a.as_str() {
                    "--rebase" => rebase = true,
                    "-h" | "--help" => {
                        println!(
                            "Usage: sit pull [--rebase] [remote]\n\n\
                             Fetch encrypted tip then merge (default) or rebase onto the remote tip."
                        );
                        return Ok(());
                    }
                    other if other.starts_with('-') => {
                        anyhow::bail!(
                            "unknown option {other} for `sit pull`\n\
                             supported: --rebase"
                        )
                    }
                    other => remote = other,
                }
            }
            if rebase {
                cmds::pull::run_rebase(remote).await
            } else {
                cmds::pull::run(remote).await
            }
        }
        "fetch" => {
            let remote = args.get(1).map(String::as_str).unwrap_or("sit");
            cmds::pull::run_fetch(remote).await
        }
        "clone" => {
            let mut rest: Vec<&str> = Vec::new();
            let mut it = args.iter().skip(1).peekable();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--depth" | "--shallow-since" | "--filter" => {
                        let _ = it.next();
                        anyhow::bail!(
                            "`sit clone {a}` is not supported: partial and shallow \
                             clone are out of scope for encrypted bundles \
                             (see the forward-only grant for a grafted history instead)"
                        )
                    }
                    "--branch" | "-b" => {
                        let _ = it.next();
                        anyhow::bail!(
                            "`sit clone --branch` is not supported yet: clone the \
                             repository and then `sit checkout <branch>`"
                        )
                    }
                    "--" => rest.extend(it.by_ref().map(String::as_str)),
                    other if other.starts_with('-') => anyhow::bail!(
                        "unknown option {other} for `sit clone`\n\
                         usage: sit clone <owner/name|sit://...> [dir]"
                    ),
                    other => rest.push(other),
                }
            }
            let repo = rest
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: sit clone <owner/name|sit://...> [dir]"))?;
            cmds::clone::run(repo, rest.get(1).copied()).await
        }
        _ => forward_to_git(&args),
    }
}

fn rest_first_or_bail<'a>(rest: &[&'a str]) -> anyhow::Result<&'a str> {
    rest.first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("`sit push --delete` requires a ref name"))
}

fn forward_to_git(args: &[String]) -> anyhow::Result<()> {
    let status = Command::new("git").args(args).status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
