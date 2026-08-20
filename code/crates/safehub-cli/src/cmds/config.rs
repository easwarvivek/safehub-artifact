use clap::Subcommand;
use safehub_client::ClientConfig;

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print the effective configuration.
    Get,
    /// Set the default server URL.
    SetHost {
        /// e.g. `http://127.0.0.1:8080`
        url: String,
    },
}

pub fn run(cmd: ConfigCmd) -> anyhow::Result<()> {
    match cmd {
        ConfigCmd::Get => {
            let cfg = ClientConfig::load()?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        ConfigCmd::SetHost { url } => {
            let mut cfg = ClientConfig::load().unwrap_or_default();
            cfg.server_url = url;
            cfg.save()?;
            println!("server_url = {}", cfg.server_url);
        }
    }
    Ok(())
}
