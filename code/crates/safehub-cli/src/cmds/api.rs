//! Thin authenticated API client for the SafeHub control plane (not GitHub).

use clap::Subcommand;
use safehub_client::HttpClient;

#[derive(Debug, Subcommand)]
pub enum ApiCmd {
    /// Pass path + optional method/body to SafeHub `/v1`.
    #[command(external_subcommand)]
    Extra(Vec<String>),
}

pub async fn run(cmd: ApiCmd) -> anyhow::Result<()> {
    let ApiCmd::Extra(args) = cmd;
    if args.is_empty() {
        anyhow::bail!("usage: sh api [--method METHOD] <path> [json-body]");
    }
    let mut method = "GET".to_string();
    let mut rest = args;
    if rest.first().map(|s| s.as_str()) == Some("--method") && rest.len() >= 2 {
        method = rest[1].clone();
        rest.drain(0..2);
    }
    // Also support: sh api GET /repos/...
    if rest.len() >= 2
        && matches!(
            rest[0].to_uppercase().as_str(),
            "GET" | "POST" | "PATCH" | "PUT" | "DELETE"
        )
    {
        method = rest.remove(0);
    }
    let path = rest
        .first()
        .ok_or_else(|| anyhow::anyhow!("API path required"))?
        .clone();
    let body = if rest.len() > 1 {
        Some(serde_json::from_str::<serde_json::Value>(&rest[1])?)
    } else {
        None
    };
    let client = HttpClient::from_disk()?;
    let (status, text) = client
        .api_request(&method, &path, body.as_ref())
        .await?;
    println!("HTTP {status}");
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{text}");
    }
    if !(200..300).contains(&status) {
        anyhow::bail!("request failed with status {status}");
    }
    Ok(())
}
