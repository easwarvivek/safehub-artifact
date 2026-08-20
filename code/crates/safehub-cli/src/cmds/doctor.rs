//! `sh doctor` — local keychain / epoch / tip health checks.

use clap::Subcommand;
use safehub_client::{load_epoch_material, ClientConfig, Credentials, EpochMaterial, HttpClient};
use std::path::Path;

use super::common::resolve_repo;

#[derive(Debug, Subcommand)]
pub enum DoctorCmd {
    /// Run diagnostics for the current checkout or `--repo`.
    #[command(name = "")]
    Default {
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(repo: Option<String>) -> anyhow::Result<()> {
    let mut ok = true;
    println!("SafeHub doctor");

    match ClientConfig::load() {
        Ok(cfg) => println!("ok  config server_url={}", cfg.server_url),
        Err(e) => {
            println!("fail config: {e}");
            ok = false;
        }
    }

    match Credentials::load() {
        Ok(Some(c)) => println!("ok  credentials user={}", c.token.user.0),
        Ok(None) => {
            println!("fail not logged in");
            ok = false;
        }
        Err(e) => {
            println!("fail credentials: {e}");
            ok = false;
        }
    }

    if let Ok(client) = HttpClient::from_disk() {
        match client.whoami().await {
            Ok(u) => println!("ok  whoami {}", u.0),
            Err(e) => {
                println!("warn whoami: {e}");
                ok = false;
            }
        }

        match resolve_repo(&client, repo.as_deref()).await {
            Ok(record) => {
                println!("ok  repo {} id={}", record.name, record.id.to_hex());
                match load_epoch_material(&record.id) {
                    Ok(m) => {
                        println!(
                            "ok  epoch material epoch={} history_from={}",
                            m.epoch, m.history_from
                        );
                        println!(
                            "ok  durable_group={}",
                            EpochMaterial::has_durable_group(&record.id)
                        );
                    }
                    Err(e) => {
                        println!("fail epoch material: {e}");
                        ok = false;
                    }
                }
                match client.head_tip(&record.id).await {
                    Ok(Some(h)) => println!("ok  tip seq={} epoch={}", h.seq, h.mls_epoch),
                    Ok(None) => println!("ok  tip empty (no pushes yet)"),
                    Err(e) => {
                        println!("warn tip: {e}");
                        ok = false;
                    }
                }
                match client.mls_fetch(&record.id, 0).await {
                    Ok(msgs) => println!("ok  mls queue reachable ({} msgs from 0)", msgs.len()),
                    Err(e) => {
                        println!("warn mls fetch: {e}");
                        ok = false;
                    }
                }
            }
            Err(e) => {
                if Path::new(".git").join("safehub").join("repo.json").exists() || repo.is_some() {
                    println!("fail resolve repo: {e}");
                    ok = false;
                } else {
                    println!("skip repo checks (no checkout / --repo)");
                }
            }
        }
    }

    if ok {
        println!("doctor: all checks passed");
    } else {
        anyhow::bail!("doctor: one or more checks failed");
    }
    Ok(())
}
