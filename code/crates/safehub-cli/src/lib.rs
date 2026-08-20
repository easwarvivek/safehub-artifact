//! SafeHub CLI library — shared by the `safehub` / `shub` binaries; `sit` uses [`cmds`].
//!
//! VCS operations (`push` / `pull` / `clone` / …) are also available as
//! convenience aliases on `shub` / `safehub`; prefer the `sit` binary for
//! day-to-day VCS use.

pub mod cmds;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "shub",
    bin_name = "shub",
    version,
    about = "Private encrypted GitHub CLI (also installed as `safehub`). Use `sit` for VCS (push/pull/clone/…)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Browse a local git repository in a GitHub-like web UI.
    Browse {
        /// Path to a git working tree or repository.
        #[arg(long, short = 'C', default_value = ".")]
        repo: PathBuf,
        /// Listen address (localhost by default).
        #[arg(long, default_value = "127.0.0.1:8081")]
        listen: String,
    },
    /// Authenticate with a SafeHub server.
    Auth {
        #[command(subcommand)]
        cmd: cmds::auth::AuthCmd,
    },
    /// Manage remote configuration.
    Config {
        #[command(subcommand)]
        cmd: cmds::config::ConfigCmd,
    },
    /// Report the crypto actually linked into this binary.
    Crypto {
        #[command(subcommand)]
        cmd: cmds::crypto::CryptoCmd,
    },
    /// Create and inspect repositories.
    Repo {
        #[command(subcommand)]
        cmd: cmds::repo::RepoCmd,
    },
    /// Device (MLS leaf) management.
    Device {
        #[command(subcommand)]
        cmd: cmds::device::DeviceCmd,
    },
    /// Clone a repository (prefer `sit clone`).
    Clone {
        repo: String,
        dir: Option<String>,
    },
    /// Push via encrypted sit:// transport (prefer `sit push`).
    Push {
        #[arg(default_value = "sit")]
        remote: String,
        #[arg(default_value = "HEAD")]
        refspec: String,
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Pull / fetch via encrypted sit:// transport (prefer `sit pull`).
    Pull {
        #[arg(default_value = "sit")]
        remote: String,
    },
    /// Pull-request style collaboration commands.
    Pr {
        #[command(subcommand)]
        cmd: cmds::pr::PrCmd,
    },
    /// Issue tracker commands.
    Issue {
        #[command(subcommand)]
        cmd: cmds::issue::IssueCmd,
    },
    /// Encrypted releases (notes MLS; assets sealed CAS).
    Release {
        #[command(subcommand)]
        cmd: cmds::release::ReleaseCmd,
    },
    /// Actions runs (signed CI verdict app messages).
    Run {
        #[command(subcommand)]
        cmd: cmds::workflow::RunCmd,
    },
    /// Encrypted gists.
    Gist {
        #[command(subcommand)]
        cmd: cmds::gist::GistCmd,
    },
    /// Thin authenticated SafeHub control-plane API client.
    Api {
        #[command(subcommand)]
        cmd: cmds::api::ApiCmd,
    },
    /// Search issues / PRs / member-local code.
    Search {
        #[command(subcommand)]
        cmd: cmds::search::SearchCmd,
    },
    /// Organizations (encrypted membership directory).
    Org {
        #[command(subcommand)]
        cmd: cmds::org::OrgCmd,
    },
    /// Workflows (YAML in encrypted git + run messages).
    Workflow {
        #[command(subcommand)]
        cmd: cmds::workflow::WorkflowCmd,
    },
    /// Encrypted labels.
    Label {
        #[command(subcommand)]
        cmd: cmds::label::LabelCmd,
    },
    /// Runner secrets (sealed; never server plaintext).
    Secret {
        #[command(subcommand)]
        cmd: cmds::secret::SecretCmd,
    },
    /// Actions variables (sealed under group AEAD; never host plaintext).
    Variable {
        #[command(subcommand)]
        cmd: cmds::variable::VariableCmd,
    },
    /// Encrypted milestones (MLS app messages).
    Milestone {
        #[command(subcommand)]
        cmd: cmds::milestone::MilestoneCmd,
    },
    /// Draft encrypted codespace configs (not hosted VMs).
    Codespace {
        #[command(subcommand)]
        cmd: cmds::project::CodespaceCmd,
    },
    /// Encrypted project boards.
    Project {
        #[command(subcommand)]
        cmd: cmds::project::ProjectCmd,
    },
    /// Webhooks (explicitly unsupported — host-blind E2EE).
    Webhook {
        #[command(subcommand)]
        cmd: cmds::webhook::WebhookCmd,
    },
    /// Aggregate open issues/PRs from decrypted MLS inboxes (`gh status`).
    Status {
        #[command(flatten)]
        args: cmds::status::StatusArgs,
    },
    /// Local keychain / tip diagnostics.
    Doctor {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Decryptable collaboration inbox.
    Inbox {
        #[command(subcommand)]
        cmd: cmds::inbox::InboxCmd,
    },
    /// Encrypted LFS via sealed CAS.
    Lfs {
        #[command(subcommand)]
        cmd: cmds::lfs::LfsCmd,
    },
    /// Import plaintext git into encrypted bundles.
    Migrate {
        #[command(subcommand)]
        cmd: cmds::migrate::MigrateCmd,
    },
    /// Fetch MLS + tip; merge when in a checkout.
    Sync {
        #[arg(long)]
        repo: Option<String>,
    },
}

/// Entry point shared by the `safehub` and `shub` binaries (identical behavior).
pub async fn cli_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Browse { repo, listen } => {
            safehub_browse::run(safehub_browse::BrowseOptions {
                repo,
                listen: safehub_browse::parse_listen(&listen)?,
            })
            .await?
        }
        Commands::Auth { cmd } => cmds::auth::run(cmd).await?,
        Commands::Config { cmd } => cmds::config::run(cmd)?,
        Commands::Repo { cmd } => cmds::repo::run(cmd).await?,
        Commands::Device { cmd } => cmds::device::run(cmd).await?,
        Commands::Clone { repo, dir } => cmds::clone::run(&repo, dir.as_deref()).await?,
        Commands::Push {
            remote,
            refspec,
            force,
        } => cmds::push::run_with_force(&remote, &refspec, force).await?,
        Commands::Pull { remote } => cmds::pull::run(&remote).await?,
        Commands::Pr { cmd } => cmds::pr::run(cmd).await?,
        Commands::Issue { cmd } => cmds::issue::run(cmd).await?,
        Commands::Release { cmd } => cmds::release::run(cmd).await?,
        Commands::Run { cmd } => cmds::workflow::run_run(cmd).await?,
        Commands::Gist { cmd } => cmds::gist::run(cmd).await?,
        Commands::Api { cmd } => cmds::api::run(cmd).await?,
        Commands::Search { cmd } => cmds::search::run_search(cmd).await?,
        Commands::Org { cmd } => cmds::org::run(cmd).await?,
        Commands::Workflow { cmd } => cmds::workflow::run_workflow(cmd).await?,
        Commands::Label { cmd } => cmds::label::run(cmd).await?,
        Commands::Secret { cmd } => cmds::secret::run(cmd).await?,
        Commands::Variable { cmd } => cmds::variable::run(cmd).await?,
        Commands::Milestone { cmd } => cmds::milestone::run(cmd).await?,
        Commands::Codespace { cmd } => cmds::project::run_codespace(cmd).await?,
        Commands::Project { cmd } => cmds::project::run_project(cmd).await?,
        Commands::Webhook { cmd } => cmds::webhook::run(cmd).await?,
        Commands::Status { args } => cmds::status::run(args).await?,
        Commands::Crypto { cmd } => cmds::crypto::run(cmd).await?,
        Commands::Doctor { repo } => cmds::doctor::run(repo).await?,
        Commands::Inbox { cmd } => cmds::inbox::run(cmd).await?,
        Commands::Lfs { cmd } => cmds::lfs::run(cmd).await?,
        Commands::Migrate { cmd } => cmds::migrate::run(cmd).await?,
        Commands::Sync { repo } => {
            cmds::repo::run(cmds::repo::RepoCmd::Sync { repo }).await?;
        }
    }
    Ok(())
}
