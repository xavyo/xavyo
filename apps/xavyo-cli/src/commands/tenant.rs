//! Tenant management CLI commands (multi-tenant switching)
//!
//! Enables users to:
//! - List all tenants they have access to
//! - Switch between tenants without re-authentication
//! - View the currently active tenant context

use crate::api::{list_tenants, switch_tenant, ApiClient};
use crate::cache::store::{CacheStore, FileCacheStore, CACHE_KEY_TENANTS};
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::tenant::{
    TenantCurrentOutput, TenantInfo, TenantListResponse, TenantSwitchOutput,
};
use crate::models::Session;
use clap::{Args, Subcommand};
use uuid::Uuid;

/// Tenant management commands
#[derive(Args, Debug)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantCommands,
}

#[derive(Subcommand, Debug)]
pub enum TenantCommands {
    /// List all tenants you have access to
    List(ListArgs),
    /// Switch to a different tenant
    Switch(SwitchArgs),
    /// Show the currently active tenant
    Current(CurrentArgs),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of tenants to return
    #[arg(long, default_value = "50")]
    pub limit: u32,

    /// Pagination cursor from previous response
    #[arg(long)]
    pub after: Option<String>,

    /// Show all tenants (ignore limit)
    #[arg(long)]
    pub all: bool,

    /// Use cached data only (no network requests)
    #[arg(long)]
    pub offline: bool,

    /// Force refresh from server (ignore cache)
    #[arg(long)]
    pub refresh: bool,
}

/// Arguments for the switch command
#[derive(Args, Debug)]
pub struct SwitchArgs {
    /// Tenant identifier (slug, name, or UUID)
    /// If not provided, shows interactive selection
    pub identifier: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
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
        TenantCommands::List(list_args) => execute_list(list_args).await,
        TenantCommands::Switch(switch_args) => execute_switch(switch_args).await,
        TenantCommands::Current(current_args) => execute_current(current_args).await,
    }
}

/// Execute list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;

    // Handle offline mode
    if args.offline {
        return execute_list_offline(&paths, args.json);
    }

    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths.clone())?;

    // Get current session to determine which tenant is current
    let session = Session::load(&paths)?;

    // Determine limit
    let limit = if args.all { None } else { Some(args.limit) };

    let mut response = list_tenants(&client, limit, args.after.as_deref()).await?;

    // Mark the current tenant
    if let Some(ref session) = session {
        if let Some(current_tenant_id) = session.tenant_id {
            for tenant in &mut response.tenants {
                tenant.is_current = tenant.id == current_tenant_id;
            }
        }
    }

    // Cache the result for offline mode (unless refreshing)
    if !args.refresh {
        if let Ok(cache) = FileCacheStore::new(&paths) {
            let _ = cache.set(CACHE_KEY_TENANTS, &response, 3600); // 1 hour TTL
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.tenants.is_empty() {
        println!("No tenants found.");
        println!();
        println!("To create a new tenant:");
        println!("  xavyo init");
    } else {
        print_tenant_table(&response.tenants);
        println!();
        println!(
            "Showing {} of {} tenant(s)",
            response.tenants.len(),
            response.total
        );

        if response.has_more {
            if let Some(cursor) = &response.next_cursor {
                println!();
                println!(
                    "More tenants available. Use --after {} to see more.",
                    cursor
                );
            }
        }
    }

    Ok(())
}

/// Execute list command in offline mode
fn execute_list_offline(paths: &ConfigPaths, json: bool) -> CliResult<()> {
    let cache = FileCacheStore::new(paths)?;

    let entry = cache.get::<TenantListResponse>(CACHE_KEY_TENANTS)?;

    match entry {
        Some(cached) => {
            let is_expired = cached.is_expired();
            let response = cached.data;

            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.tenants.is_empty() {
                println!("No cached tenants found.");
            } else {
                print_tenant_table(&response.tenants);
                println!();
                println!("Showing {} tenant(s) (cached)", response.tenants.len());

                if is_expired {
                    println!();
                    println!("Warning: Cached data may be stale. Run 'xavyo tenant list --refresh' when online.");
                }
            }
            Ok(())
        }
        None => Err(CliError::Cache(
            "No cached tenant data available. Run 'xavyo tenant list' when online.".to_string(),
        )),
    }
}

/// Execute switch command
async fn execute_switch(args: SwitchArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths.clone())?;

    // Load current session
    let mut session = Session::load(&paths)?.ok_or(CliError::NotAuthenticated)?;

    // Determine target tenant
    let identifier = match args.identifier {
        Some(id) => id,
        None => {
            // Interactive selection
            return execute_switch_interactive(&client, &mut session, &paths, args.json).await;
        }
    };

    // Resolve the identifier to a tenant
    let tenant = resolve_tenant_identifier(&client, &identifier).await?;

    // Check if already on this tenant
    if session.tenant_id == Some(tenant.id) {
        if args.json {
            let output = TenantSwitchOutput {
                tenant_id: tenant.id.to_string(),
                tenant_name: tenant.name.clone(),
                tenant_slug: tenant.slug.clone(),
                role: tenant.role.to_string(),
                switched: false,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Already on tenant: {} ({})", tenant.name, tenant.slug);
        }
        return Ok(());
    }

    // Switch tenant via API (validates access)
    let response = switch_tenant(&client, tenant.id).await?;

    // Update local session
    session.set_tenant(
        response.tenant_id,
        response.tenant_name.clone(),
        response.tenant_slug.clone(),
        response.role,
    );
    session.save(&paths)?;

    if args.json {
        let output = TenantSwitchOutput {
            tenant_id: response.tenant_id.to_string(),
            tenant_name: response.tenant_name,
            tenant_slug: response.tenant_slug,
            role: response.role.to_string(),
            switched: true,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Switched to tenant: {} ({})",
            response.tenant_name, response.tenant_slug
        );
        println!("Role: {}", response.role);
    }

    Ok(())
}

/// Execute switch command with interactive selection
async fn execute_switch_interactive(
    client: &ApiClient,
    session: &mut Session,
    paths: &ConfigPaths,
    json: bool,
) -> CliResult<()> {
    // Check if running in a TTY
    if !atty::is(atty::Stream::Stdin) {
        return Err(CliError::InputError(
            "Tenant identifier required in non-interactive mode. Use: xavyo tenant switch <identifier>".to_string(),
        ));
    }

    // Get list of tenants
    let response = list_tenants(client, None, None).await?;

    if response.tenants.is_empty() {
        println!("No tenants available to switch to.");
        println!();
        println!("To create a new tenant:");
        println!("  xavyo init");
        return Ok(());
    }

    // Build selection items
    let items: Vec<String> = response
        .tenants
        .iter()
        .map(|t| {
            let current_marker = if session.tenant_id == Some(t.id) {
                " (current)"
            } else {
                ""
            };
            format!("{} ({}){}", t.name, t.role, current_marker)
        })
        .collect();

    // Show selection dialog
    let selection = dialoguer::Select::new()
        .with_prompt("Select a tenant")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| CliError::InputError(format!("Selection failed: {}", e)))?;

    let selected_tenant = &response.tenants[selection];

    // Check if already on this tenant
    if session.tenant_id == Some(selected_tenant.id) {
        if json {
            let output = TenantSwitchOutput {
                tenant_id: selected_tenant.id.to_string(),
                tenant_name: selected_tenant.name.clone(),
                tenant_slug: selected_tenant.slug.clone(),
                role: selected_tenant.role.to_string(),
                switched: false,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!(
                "Already on tenant: {} ({})",
                selected_tenant.name, selected_tenant.slug
            );
        }
        return Ok(());
    }

    // Switch tenant via API
    let switch_response = switch_tenant(client, selected_tenant.id).await?;

    // Update local session
    session.set_tenant(
        switch_response.tenant_id,
        switch_response.tenant_name.clone(),
        switch_response.tenant_slug.clone(),
        switch_response.role,
    );
    session.save(paths)?;

    if json {
        let output = TenantSwitchOutput {
            tenant_id: switch_response.tenant_id.to_string(),
            tenant_name: switch_response.tenant_name,
            tenant_slug: switch_response.tenant_slug,
            role: switch_response.role.to_string(),
            switched: true,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Switched to tenant: {} ({})",
            switch_response.tenant_name, switch_response.tenant_slug
        );
        println!("Role: {}", switch_response.role);
    }

    Ok(())
}

/// Resolve a tenant identifier (UUID, slug, or name) to a TenantInfo
async fn resolve_tenant_identifier(client: &ApiClient, identifier: &str) -> CliResult<TenantInfo> {
    // First, try to parse as UUID
    if let Ok(uuid) = Uuid::parse_str(identifier) {
        // Get tenant list and find by ID
        let response = list_tenants(client, None, None).await?;
        if let Some(tenant) = response.tenants.into_iter().find(|t| t.id == uuid) {
            return Ok(tenant);
        }
        return Err(CliError::TenantNotFound(identifier.to_string()));
    }

    // Get tenant list
    let response = list_tenants(client, None, None).await?;

    // Try to match by slug (exact, case-insensitive)
    let identifier_lower = identifier.to_lowercase();
    if let Some(tenant) = response
        .tenants
        .iter()
        .find(|t| t.slug.to_lowercase() == identifier_lower)
    {
        return Ok(tenant.clone());
    }

    // Try to match by name (case-insensitive)
    if let Some(tenant) = response
        .tenants
        .iter()
        .find(|t| t.name.to_lowercase() == identifier_lower)
    {
        return Ok(tenant.clone());
    }

    // No match found
    Err(CliError::TenantNotFound(identifier.to_string()))
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
                println!("To create a new tenant:");
                println!("  xavyo init");
                println!();
                println!("To switch to an existing tenant:");
                println!("  xavyo tenant list");
                println!("  xavyo tenant switch <slug>");
            }
        }
    }

    Ok(())
}

/// Print tenant table
fn print_tenant_table(tenants: &[TenantInfo]) {
    // Calculate column widths
    let name_width = tenants
        .iter()
        .map(|t| t.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let slug_width = tenants
        .iter()
        .map(|t| t.slug.len())
        .max()
        .unwrap_or(4)
        .max(4);

    // Print header
    println!(
        "{:<name_width$}  {:<slug_width$}  {:<8}  CURRENT",
        "NAME",
        "SLUG",
        "ROLE",
        name_width = name_width,
        slug_width = slug_width
    );

    // Print rows
    for tenant in tenants {
        let current_marker = if tenant.is_current { "*" } else { "" };
        println!(
            "{:<name_width$}  {:<slug_width$}  {:<8}  {}",
            tenant.name,
            tenant.slug,
            tenant.role,
            current_marker,
            name_width = name_width,
            slug_width = slug_width
        );
    }
}

/// Print tenant details
fn print_tenant_details(session: &Session) {
    println!("Current Tenant");
    println!("{}", "\u{2501}".repeat(40)); // ━ character

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

        // Test list command
        let args = TestCli::parse_from(["test", "list"]);
        assert!(matches!(args.command, TenantCommands::List(_)));

        // Test list with JSON flag
        let args = TestCli::parse_from(["test", "list", "--json"]);
        if let TenantCommands::List(list_args) = args.command {
            assert!(list_args.json);
        }

        // Test switch command
        let args = TestCli::parse_from(["test", "switch", "acme-corp"]);
        if let TenantCommands::Switch(switch_args) = args.command {
            assert_eq!(switch_args.identifier, Some("acme-corp".to_string()));
        }

        // Test switch without identifier
        let args = TestCli::parse_from(["test", "switch"]);
        if let TenantCommands::Switch(switch_args) = args.command {
            assert!(switch_args.identifier.is_none());
        }

        // Test current command
        let args = TestCli::parse_from(["test", "current"]);
        assert!(matches!(args.command, TenantCommands::Current(_)));
    }
}
