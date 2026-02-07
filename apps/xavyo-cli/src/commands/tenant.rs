//! Tenant management CLI commands
//!
//! Shows the currently active tenant context (from the JWT token).

use crate::config::ConfigPaths;
use crate::error::CliResult;
use crate::models::tenant::TenantCurrentOutput;
use crate::models::Session;
use clap::{Args, Subcommand};

/// Tenant management commands
#[derive(Args, Debug)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantCommands,
}

#[derive(Subcommand, Debug)]
pub enum TenantCommands {
    /// Show the currently active tenant
    Current(CurrentArgs),
}

/// Arguments for the current command
#[derive(Args, Debug)]
pub struct CurrentArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Execute tenant commands
pub async fn execute(args: TenantArgs) -> CliResult<()> {
    match args.command {
        TenantCommands::Current(current_args) => execute_current(current_args).await,
    }
}

/// Execute current command
async fn execute_current(args: CurrentArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;

    // Load current session
    let session = Session::load(&paths)?;

    match session {
        Some(session) if session.has_tenant() => {
            if args.json {
                let output = TenantCurrentOutput {
                    tenant_id: session.tenant_id.map(|id| id.to_string()),
                    tenant_name: session.tenant_name,
                    tenant_slug: session.tenant_slug,
                    role: session.tenant_role.map(|r| r.to_string()),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                print_tenant_details(&session);
            }
        }
        _ => {
            if args.json {
                let output = TenantCurrentOutput {
                    tenant_id: None,
                    tenant_name: None,
                    tenant_slug: None,
                    role: None,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("No tenant selected.");
                println!();
                println!("Tenant context is set from your JWT token at login.");
            }
        }
    }

    Ok(())
}

/// Print tenant details
fn print_tenant_details(session: &Session) {
    println!("Current Tenant");
    println!("{}", "\u{2501}".repeat(40));

    if let Some(ref id) = session.tenant_id {
        println!("ID:   {}", id);
    }
    if let Some(ref name) = session.tenant_name {
        println!("Name: {}", name);
    }
    if let Some(ref slug) = session.tenant_slug {
        println!("Slug: {}", slug);
    }
    if let Some(ref role) = session.tenant_role {
        println!("Role: {}", role);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_args_parsing() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: TenantCommands,
        }

        // Test current command
        let args = TestCli::parse_from(["test", "current"]);
        assert!(matches!(args.command, TenantCommands::Current(_)));

        // Test current with JSON flag
        let args = TestCli::parse_from(["test", "current", "--json"]);
        if let TenantCommands::Current(current_args) = args.command {
            assert!(current_args.json);
        }
    }
}
