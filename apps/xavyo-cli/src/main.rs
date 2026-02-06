//! xavyo CLI - Command-line interface for the xavyo platform
//!
//! This CLI enables developers to:
//! - Authenticate via device code OAuth flow
//! - View current identity and tenant context
//! - Provision new tenants
//! - Check tenant health and status
//! - Diagnose connection and configuration issues

// Allow dead code and deprecated warnings for features in development
#![allow(dead_code)]
#![allow(deprecated)]

use clap::{Parser, Subcommand};

mod api;
mod cache;
mod commands;
mod config;
mod credentials;
mod error;
mod interactive;
mod models;
mod output;

use error::CliResult;

/// xavyo CLI - Identity platform management
#[derive(Parser)]
#[command(name = "xavyo")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive setup wizard for new users
    Setup(commands::setup::SetupArgs),

    /// Create a new account in the system tenant
    Signup(commands::signup::SignupArgs),

    /// Authenticate with the xavyo platform
    Login(commands::login::LoginArgs),

    /// Clear stored credentials and log out
    Logout(commands::logout::LogoutArgs),

    /// Display current identity and tenant context
    Whoami(commands::whoami::WhoamiArgs),

    /// Provision a new tenant
    Init(commands::init::InitArgs),

    /// Show tenant health and configuration
    Status(commands::status::StatusArgs),

    /// Manage AI agents
    Agents(commands::agents::AgentsArgs),

    /// Manage API keys
    ApiKeys(commands::api_keys::ApiKeysArgs),

    /// Manage NHI credentials
    Credentials(commands::credentials::CredentialsArgs),

    /// Manage tools
    Tools(commands::tools::ToolsArgs),

    /// Test agent-tool authorization
    Authorize(commands::authorize::AuthorizeArgs),

    /// Diagnose connection and configuration issues
    Doctor(commands::doctor::DoctorArgs),

    /// Apply configuration from a YAML file
    Apply(commands::apply::ApplyArgs),

    /// Export current configuration to YAML
    Export(commands::export::ExportArgs),

    /// Generate shell completion scripts
    Completions(commands::completions::CompletionsArgs),

    /// Watch a configuration file and auto-apply changes
    Watch(commands::watch::WatchArgs),

    /// Pre-configured templates for quick setup
    Templates(commands::templates::TemplatesArgs),

    /// Manage tenant contexts (list, switch, current)
    Tenant(commands::tenant::TenantArgs),

    /// Check for updates and upgrade the CLI
    Upgrade(commands::upgrade::UpgradeArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = run(cli).await;

    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            e.print();
            std::process::exit(e.exit_code());
        }
    }
}

async fn run(cli: Cli) -> CliResult<()> {
    match cli.command {
        Commands::Setup(args) => commands::setup::execute(args).await,
        Commands::Signup(args) => commands::signup::execute(args).await,
        Commands::Login(args) => commands::login::execute(args).await,
        Commands::Logout(args) => commands::logout::execute(args).await,
        Commands::Whoami(args) => commands::whoami::execute(args).await,
        Commands::Init(args) => commands::init::execute(args).await,
        Commands::Status(args) => commands::status::execute(args).await,
        Commands::Agents(args) => commands::agents::execute(args).await,
        Commands::ApiKeys(args) => commands::api_keys::execute(args).await,
        Commands::Credentials(args) => commands::credentials::execute(args).await,
        Commands::Tools(args) => commands::tools::execute(args).await,
        Commands::Authorize(args) => commands::authorize::execute(args).await,
        Commands::Doctor(args) => commands::doctor::execute(args).await,
        Commands::Apply(args) => commands::apply::execute(args).await,
        Commands::Export(args) => commands::export::execute(args).await,
        Commands::Completions(args) => commands::completions::execute(args),
        Commands::Watch(args) => commands::watch::execute(args).await,
        Commands::Templates(args) => commands::templates::execute(args).await,
        Commands::Tenant(args) => commands::tenant::execute(args).await,
        Commands::Upgrade(args) => commands::upgrade::execute(args).await,
    }
}
