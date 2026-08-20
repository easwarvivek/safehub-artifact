//! Explicit refusals for GitHub features incompatible with host-blind E2EE.

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum WebhookCmd {
    /// List webhooks (always refused).
    List {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Create a webhook (always refused).
    Create {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    /// Delete a webhook (always refused).
    Delete {
        id: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

pub async fn run(cmd: WebhookCmd) -> anyhow::Result<()> {
    let _ = cmd;
    anyhow::bail!(
        "webhooks are not supported under SafeHub's threat model.\n\
         The untrusted host cannot emit meaningful event payloads without reading plaintext.\n\
         Use `sh inbox sync` / `GET /v1/repos/:id/mls` for opaque MLS wakes, then decrypt locally.\n\
         Server also returns 501 on `/v1/repos/:owner/:name/hooks`."
    )
}
