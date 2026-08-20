use clap::Subcommand;
use safehub_client::HttpClient;

#[derive(Debug, Subcommand)]
pub enum AuthCmd {
    /// Register a new account (password hashed server-side).
    Register {
        #[arg(long, short)]
        user: String,
        #[arg(long, short)]
        password: String,
        #[arg(long, env = "SAFEHUB_HOST")]
        hostname: Option<String>,
    },
    /// Log in and store a bearer token under the config directory.
    Login {
        #[arg(long, short)]
        user: String,
        #[arg(long, short)]
        secret: String,
        #[arg(long, env = "SAFEHUB_HOST")]
        hostname: Option<String>,
    },
    /// Show the current authenticated user.
    Status,
    /// Remove stored credentials.
    Logout,
    /// Refresh is a no-op alias that re-validates whoami (sessions are long-lived PATs/sessions).
    Refresh,
    /// Personal access tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCmd {
    /// Create a PAT (`repo`, `read:user` scopes by default).
    Create {
        #[arg(long, default_value = "cli")]
        note: String,
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
    },
    /// List PATs (token values redacted).
    List,
    /// Revoke a PAT by full token string.
    Revoke {
        token: String,
    },
}

pub async fn run(cmd: AuthCmd) -> anyhow::Result<()> {
    match cmd {
        AuthCmd::Register {
            user,
            password,
            hostname,
        } => {
            maybe_set_host(hostname)?;
            let cfg = safehub_client::ClientConfig::load()?;
            let mut client = HttpClient::new(&cfg, None)?;
            let token = client.register(&user, &password).await?;
            println!("Registered and logged in as {}", token.user);
        }
        AuthCmd::Login {
            user,
            secret,
            hostname,
        } => {
            maybe_set_host(hostname)?;
            let cfg = safehub_client::ClientConfig::load()?;
            let mut client = HttpClient::new(&cfg, None)?;
            let token = client.login(&user, &secret).await?;
            println!("Logged in as {}", token.user);
        }
        AuthCmd::Status => match safehub_client::Credentials::load()? {
            Some(c) => {
                let client = HttpClient::from_disk()?;
                match client.whoami().await {
                    Ok(u) => println!("Logged in as {u}"),
                    Err(e) => println!(
                        "Credentials present for {} but server check failed: {e}",
                        c.user()
                    ),
                }
            }
            None => println!("Not logged in"),
        },
        AuthCmd::Logout => {
            let path = safehub_client::ClientConfig::config_dir()?.join("credentials.json");
            if path.exists() {
                std::fs::remove_file(path)?;
                println!("Logged out");
            } else {
                println!("Not logged in");
            }
        }
        AuthCmd::Refresh => {
            let client = HttpClient::from_disk()?;
            let u = client.whoami().await?;
            println!("Session valid for {u}");
        }
        AuthCmd::Token { cmd } => match cmd {
            TokenCmd::Create { note, scopes } => {
                let client = HttpClient::from_disk()?;
                let pat = client.create_pat(&note, scopes).await?;
                if let Some(t) = &pat.token {
                    println!("Created PAT note={} scopes={:?}", pat.note, pat.scopes);
                    println!("{t}");
                } else {
                    println!("Created PAT id={}", pat.id);
                }
            }
            TokenCmd::List => {
                let client = HttpClient::from_disk()?;
                for p in client.list_pats().await? {
                    println!(
                        "{}\t{}\t{}\t{}",
                        p.id,
                        p.note,
                        p.scopes.join(","),
                        p.created_at
                    );
                }
            }
            TokenCmd::Revoke { token } => {
                let client = HttpClient::from_disk()?;
                client.revoke_pat(&token).await?;
                println!("Revoked");
            }
        },
    }
    Ok(())
}

fn maybe_set_host(hostname: Option<String>) -> anyhow::Result<()> {
    if let Some(host) = hostname {
        let mut cfg = safehub_client::ClientConfig::load().unwrap_or_default();
        cfg.server_url = host;
        cfg.save()?;
    }
    Ok(())
}
