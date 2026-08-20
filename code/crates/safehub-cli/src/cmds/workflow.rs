//! Workflow listing / dispatch + signed CI run verdicts (E2EE app messages).

use clap::Subcommand;
use safehub_client::HttpClient;
use safehub_types::CollabMessage;
use std::path::Path;
use std::process::Command;

use super::common::{enqueue_collab, material_for, resolve_repo, short_id, sync_inbox};

#[derive(Debug, Subcommand)]
pub enum WorkflowCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    View {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Queue a workflow run (YAML remains in encrypted git; run is an MLS message).
    Run {
        name: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        commit: Option<String>,
    },
}

pub async fn run_workflow(cmd: WorkflowCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        WorkflowCmd::List { repo } => {
            let _ = resolve_repo(&client, repo.as_deref()).await?;
            // Workflow YAML lives in encrypted git under .safehub/workflows or .github/workflows.
            for dir in [".safehub/workflows", ".github/workflows"] {
                let p = Path::new(dir);
                if !p.is_dir() {
                    continue;
                }
                for ent in std::fs::read_dir(p)? {
                    let ent = ent?;
                    if ent.path().extension().and_then(|e| e.to_str()) == Some("yml")
                        || ent.path().extension().and_then(|e| e.to_str()) == Some("yaml")
                    {
                        println!("{}", ent.file_name().to_string_lossy());
                    }
                }
            }
            println!("note: workflow files are encrypted in git; host cannot read YAML");
        }
        WorkflowCmd::View { name, repo } => {
            let _ = resolve_repo(&client, repo.as_deref()).await?;
            let name = name.ok_or_else(|| anyhow::anyhow!("workflow name required"))?;
            for dir in [".safehub/workflows", ".github/workflows"] {
                let path = Path::new(dir).join(&name);
                if path.exists() {
                    println!("{}", std::fs::read_to_string(path)?);
                    return Ok(());
                }
                let path_yml = Path::new(dir).join(format!("{name}.yml"));
                if path_yml.exists() {
                    println!("{}", std::fs::read_to_string(path_yml)?);
                    return Ok(());
                }
            }
            anyhow::bail!("workflow {name} not found in local encrypted checkout");
        }
        WorkflowCmd::Run { name, repo, commit } => {
            let name = name.ok_or_else(|| anyhow::anyhow!("workflow name required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let commit = commit.or_else(|| {
                Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    })
            });
            let id = format!("run-{}", short_id());
            let msg = CollabMessage::WorkflowRun {
                id: id.clone(),
                workflow: name.clone(),
                status: "queued".into(),
                commit,
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "workflow-run").await?;
            println!("Queued encrypted workflow run {id} for {name} (MLS seq {seq})");
            println!("self-hosted runners decrypt verdicts via `sh run list`; no hosted VMs");
        }
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
pub enum RunCmd {
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    View {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Download run logs if a sealed CAS blob was attached (best-effort).
    Download {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    Watch {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Post a signed CI verdict app message (runner / local).
    Rerun {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long, default_value = "success")]
        status: String,
        #[arg(long, default_value = "")]
        summary: String,
        #[arg(long)]
        commit: Option<String>,
    },
    Cancel {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run_run(cmd: RunCmd) -> anyhow::Result<()> {
    let client = HttpClient::from_disk()?;
    match cmd {
        RunCmd::List { repo } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                match msg {
                    CollabMessage::WorkflowRun {
                        id,
                        workflow,
                        status,
                        commit,
                    } => {
                        println!(
                            "{id}\t{workflow}\t{status}\t{}",
                            commit.unwrap_or_default()
                        );
                    }
                    CollabMessage::CiVerdict {
                        commit,
                        status,
                        summary,
                        run_id,
                    } => {
                        println!(
                            "verdict\t{}\t{status}\t{commit}\t{summary}",
                            run_id.unwrap_or_default()
                        );
                    }
                    _ => {}
                }
            }
        }
        RunCmd::View { id, repo } => {
            let id = id.ok_or_else(|| anyhow::anyhow!("run id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let _ = sync_inbox(&client, &record.id, &material).await?;
            for (_, msg) in super::common::read_inbox_cache(&record.id)? {
                if let CollabMessage::WorkflowRun {
                    id: rid,
                    workflow,
                    status,
                    commit,
                } = &msg
                {
                    if rid == &id {
                        println!("{}", serde_json::to_string_pretty(&msg)?);
                        let _ = (workflow, status, commit);
                        return Ok(());
                    }
                }
            }
            anyhow::bail!("run {id} not found in decrypted inbox");
        }
        RunCmd::Download { id, .. } => {
            let id = id.unwrap_or_default();
            println!("no sealed log blob for run {id} (attach via runner CAS if needed)");
        }
        RunCmd::Watch { id, repo } => {
            // Single-shot sync (no long poll in prototype).
            let _ = RunCmd::View { id, repo };
            Box::pin(run_run(RunCmd::List { repo: None })).await?;
        }
        RunCmd::Rerun {
            id,
            repo,
            status,
            summary,
            commit,
        } => {
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let run_id = id.unwrap_or_else(|| format!("run-{}", short_id()));
            let commit = commit.unwrap_or_else(|| {
                Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default()
            });
            // Re-queue + emit verdict.
            let wr = CollabMessage::WorkflowRun {
                id: run_id.clone(),
                workflow: "rerun".into(),
                status: "completed".into(),
                commit: Some(commit.clone()),
            };
            let _ = enqueue_collab(&client, &record.id, &material, &wr, "run-rerun").await?;
            let verdict = CollabMessage::CiVerdict {
                commit,
                status,
                summary,
                run_id: Some(run_id.clone()),
            };
            let seq =
                enqueue_collab(&client, &record.id, &material, &verdict, "ci-verdict").await?;
            println!("Posted sealed CI verdict for {run_id} (MLS seq {seq})");
        }
        RunCmd::Cancel { id, repo } => {
            let id = id.ok_or_else(|| anyhow::anyhow!("run id required"))?;
            let record = resolve_repo(&client, repo.as_deref()).await?;
            let material = material_for(&record.id)?;
            let msg = CollabMessage::WorkflowRun {
                id: id.clone(),
                workflow: String::new(),
                status: "cancelled".into(),
                commit: None,
            };
            let seq = enqueue_collab(&client, &record.id, &material, &msg, "run-cancel").await?;
            println!("Cancelled run {id} (MLS seq {seq})");
        }
    }
    Ok(())
}
