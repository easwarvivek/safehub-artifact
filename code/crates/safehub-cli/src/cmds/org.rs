//! Org registry + encrypted membership list (client-side E2EE directory).

use clap::Subcommand;
use safehub_client::{ClientConfig, Credentials, HttpClient};
use safehub_crypto::CommittingAead;
use safehub_types::domain_label;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum OrgCmd {
    /// Create a local encrypted org directory entry.
    Create {
        org: String,
    },
    List,
    View {
        org: Option<String>,
    },
    MemberList {
        org: Option<String>,
    },
    /// Add a member (updates sealed membership list).
    AddMember {
        org: String,
        user: String,
        #[arg(long)]
        team: Option<String>,
    },
    /// Remove a member from the encrypted org directory.
    RemoveMember {
        org: String,
        user: String,
        #[arg(long)]
        team: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OrgRecord {
    name: String,
    owner: String,
    /// Ciphertext of OrgPlain membership (AEAD under local org key).
    sealed_membership: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct OrgPlain {
    members: Vec<String>,
    teams: BTreeMap<String, Vec<String>>,
}

fn orgs_dir() -> anyhow::Result<PathBuf> {
    let dir = ClientConfig::config_dir()?.join("orgs");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn org_key_path(org: &str) -> anyhow::Result<PathBuf> {
    Ok(orgs_dir()?.join(format!("{org}.key")))
}

fn org_record_path(org: &str) -> anyhow::Result<PathBuf> {
    Ok(orgs_dir()?.join(format!("{org}.json")))
}

fn load_or_create_key(org: &str) -> anyhow::Result<[u8; 32]> {
    let path = org_key_path(org)?;
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        let mut key = [0u8; 32];
        if bytes.len() != 32 {
            anyhow::bail!("corrupt org key");
        }
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    std::fs::write(&path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

fn seal_plain(key: &[u8; 32], plain: &OrgPlain) -> anyhow::Result<Vec<u8>> {
    Ok(CommittingAead::seal(
        key,
        domain_label("org-dir").as_bytes(),
        &serde_json::to_vec(plain)?,
    )?)
}

fn open_plain(key: &[u8; 32], sealed: &[u8]) -> anyhow::Result<OrgPlain> {
    let pt = CommittingAead::open(key, domain_label("org-dir").as_bytes(), sealed)?;
    Ok(serde_json::from_slice(&pt)?)
}

pub async fn run(cmd: OrgCmd) -> anyhow::Result<()> {
    match cmd {
        OrgCmd::Create { org } => {
            let creds = Credentials::load()?
                .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
            let key = load_or_create_key(&org)?;
            let plain = OrgPlain {
                members: vec![creds.token.user.0.clone()],
                teams: BTreeMap::new(),
            };
            let sealed = seal_plain(&key, &plain)?;
            let rec = OrgRecord {
                name: org.clone(),
                owner: creds.token.user.0.clone(),
                sealed_membership: sealed,
            };
            std::fs::write(org_record_path(&org)?, serde_json::to_vec_pretty(&rec)?)?;
            println!("Created encrypted org directory {org}");
            println!("leakage: org name + owner stored locally; membership ciphertext only");
            // Best-effort: also register name on control plane if reachable.
            if let Ok(client) = HttpClient::from_disk() {
                let _ = client
                    .api_request(
                        "POST",
                        "/orgs",
                        Some(&serde_json::json!({
                            "name": org,
                            "owner": creds.token.user.0,
                        })),
                    )
                    .await;
            }
        }
        OrgCmd::List => {
            let dir = orgs_dir()?;
            for ent in std::fs::read_dir(dir)? {
                let ent = ent?;
                let name = ent.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") {
                    println!("{}", name.trim_end_matches(".json"));
                }
            }
        }
        OrgCmd::View { org } => {
            let org = org.ok_or_else(|| anyhow::anyhow!("org name required"))?;
            let bytes = std::fs::read(org_record_path(&org)?)?;
            let rec: OrgRecord = serde_json::from_slice(&bytes)?;
            println!("org: {}", rec.name);
            println!("owner: {}", rec.owner);
            println!(
                "sealed_membership_bytes: {} (ciphertext; not readable by server)",
                rec.sealed_membership.len()
            );
        }
        OrgCmd::MemberList { org } => {
            let org = org.ok_or_else(|| anyhow::anyhow!("org name required"))?;
            let key = load_or_create_key(&org)?;
            let rec: OrgRecord = serde_json::from_slice(&std::fs::read(org_record_path(&org)?)?)?;
            let plain = open_plain(&key, &rec.sealed_membership)?;
            for m in &plain.members {
                println!("{m}");
            }
            for (team, members) in &plain.teams {
                println!("team:{team}");
                for m in members {
                    println!("  {m}");
                }
            }
        }
        OrgCmd::AddMember { org, user, team } => {
            let key = load_or_create_key(&org)?;
            let path = org_record_path(&org)?;
            let mut rec: OrgRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
            let mut plain = open_plain(&key, &rec.sealed_membership)?;
            if !plain.members.contains(&user) {
                plain.members.push(user.clone());
            }
            if let Some(t) = team {
                plain.teams.entry(t).or_default().push(user.clone());
            }
            rec.sealed_membership = seal_plain(&key, &plain)?;
            std::fs::write(path, serde_json::to_vec_pretty(&rec)?)?;
            println!("Added {user} to encrypted org {org}");
        }
        OrgCmd::RemoveMember { org, user, team } => {
            let key = load_or_create_key(&org)?;
            let path = org_record_path(&org)?;
            let mut rec: OrgRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
            let mut plain = open_plain(&key, &rec.sealed_membership)?;
            plain.members.retain(|m| m != &user);
            if let Some(t) = team {
                if let Some(members) = plain.teams.get_mut(&t) {
                    members.retain(|m| m != &user);
                }
            } else {
                for members in plain.teams.values_mut() {
                    members.retain(|m| m != &user);
                }
            }
            rec.sealed_membership = seal_plain(&key, &plain)?;
            std::fs::write(path, serde_json::to_vec_pretty(&rec)?)?;
            println!("Removed {user} from encrypted org {org}");
        }
    }
    Ok(())
}
