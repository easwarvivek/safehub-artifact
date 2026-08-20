use clap::Subcommand;
use safehub_client::{publish_device_key_package, ClientConfig, HttpClient};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum DeviceCmd {
    /// List local devices recorded for this user.
    List,
    /// Register a device label locally (MLS leaf placeholder).
    Add {
        /// Device name/label.
        name: String,
    },
    /// Generate + publish an MLS KeyPackage for a device (required before invite).
    PublishKeyPackage {
        /// Device label (default: `default`).
        #[arg(long, default_value = "default")]
        device: String,
    },
    /// Revoke a local device label.
    Revoke {
        name: String,
    },
}

#[derive(Default, Serialize, Deserialize)]
struct DeviceFile {
    devices: Vec<String>,
}

fn path() -> anyhow::Result<PathBuf> {
    Ok(ClientConfig::config_dir()?.join("devices.json"))
}

fn load() -> anyhow::Result<DeviceFile> {
    let p = path()?;
    if !p.exists() {
        return Ok(DeviceFile {
            devices: vec!["default".into()],
        });
    }
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}

fn save(f: &DeviceFile) -> anyhow::Result<()> {
    let p = path()?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(p, serde_json::to_vec_pretty(f)?)?;
    Ok(())
}

pub async fn run(cmd: DeviceCmd) -> anyhow::Result<()> {
    match cmd {
        DeviceCmd::List => {
            let f = load()?;
            for d in f.devices {
                println!("{d}");
            }
        }
        DeviceCmd::Add { name } => {
            let mut f = load()?;
            if !f.devices.iter().any(|d| d == &name) {
                f.devices.push(name.clone());
                save(&f)?;
            }
            println!("Added device {name}");
        }
        DeviceCmd::PublishKeyPackage { device } => {
            let client = HttpClient::from_disk()?;
            publish_device_key_package(&client, &device).await?;
            let mut f = load()?;
            if !f.devices.iter().any(|d| d == &device) {
                f.devices.push(device.clone());
                save(&f)?;
            }
            println!("Published MLS KeyPackage for device `{device}` (identity persisted).");
        }
        DeviceCmd::Revoke { name } => {
            let mut f = load()?;
            f.devices.retain(|d| d != &name);
            save(&f)?;
            println!("Revoked device {name}");
        }
    }
    Ok(())
}
