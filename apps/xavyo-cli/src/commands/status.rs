//! Status command - Show tenant health and configuration

use crate::api::{check_health_display, ApiClient};
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use crate::output::print_key_value;
use clap::Args;
use serde::Serialize;

/// Arguments for the status command
#[derive(Args)]
pub struct StatusArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// JSON output for status
#[derive(Serialize)]
struct StatusOutput {
    tenant: Option<TenantStatusOutput>,
    api_health: HealthOutput,
    auth_health: HealthOutput,
}

#[derive(Serialize)]
struct TenantStatusOutput {
    id: String,
    name: String,
    slug: String,
    status: String,
}

#[derive(Serialize)]
struct HealthOutput {
    endpoint: String,
    status: String,
    version: Option<String>,
}

/// Execute the status command
pub async fn execute(args: StatusArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    // Check if logged in
    let store = get_credential_store(&paths);
    if !store.exists() {
        return Err(CliError::NotAuthenticated);
    }

    // Load session
    let session = Session::load(&paths)?.ok_or(CliError::NotAuthenticated)?;

    // Create API client
    let client = ApiClient::new(config.clone(), paths.clone())?;

    // Check health endpoints
    let (api_status, api_version) = check_health_display(&client, &config.health_url()).await;
    let (auth_status, auth_version) =
        check_health_display(&client, &config.auth_health_url()).await;

    if args.json {
        // JSON output
        let tenant_output = if session.has_tenant() {
            Some(TenantStatusOutput {
                id: session.tenant_id.unwrap().to_string(),
                name: session.tenant_name.clone().unwrap_or_default(),
                slug: session.tenant_slug.clone().unwrap_or_default(),
                status: "Active".to_string(),
            })
        } else {
            None
        };

        let output = StatusOutput {
            tenant: tenant_output,
            api_health: HealthOutput {
                endpoint: config.api_url.clone(),
                status: api_status.display().to_string(),
                version: api_version,
            },
            auth_health: HealthOutput {
                endpoint: config.auth_url.clone(),
                status: auth_status.display().to_string(),
                version: auth_version,
            },
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        println!();

        // Tenant info
        if session.has_tenant() {
            let name = session.tenant_name.as_deref().unwrap_or("Unknown");
            let slug = session.tenant_slug.as_deref().unwrap_or("unknown");

            println!("Tenant: {name} ({slug})");
            print_key_value("  ID", &session.tenant_id.unwrap().to_string());
            print_key_value("  Status", "Active");
        } else {
            println!("Tenant: (none)");
            println!("  Run 'xavyo init <name>' to create a tenant");
        }

        println!();

        // API Health
        let use_color = std::env::var("NO_COLOR").is_err();
        println!("API Health:");
        print_key_value("  Endpoint", &config.api_url);
        if use_color {
            let color = match api_status.display() {
                "Healthy" => "\x1b[32m",
                "Degraded" => "\x1b[33m",
                _ => "\x1b[31m",
            };
            println!(
                "  Status:  {}{} {}\x1b[0m",
                color,
                api_status.symbol(),
                api_status.display()
            );
        } else {
            println!(
                "  Status:  {} {}",
                api_status.symbol(),
                api_status.display()
            );
        }
        if let Some(version) = &api_version {
            print_key_value("  Version", version);
        }

        println!();

        // Auth Health
        println!("Auth Health:");
        print_key_value("  Endpoint", &config.auth_url);
        if use_color {
            let color = match auth_status.display() {
                "Healthy" => "\x1b[32m",
                "Degraded" => "\x1b[33m",
                _ => "\x1b[31m",
            };
            println!(
                "  Status:  {}{} {}\x1b[0m",
                color,
                auth_status.symbol(),
                auth_status.display()
            );
        } else {
            println!(
                "  Status:  {} {}",
                auth_status.symbol(),
                auth_status.display()
            );
        }
        if let Some(version) = &auth_version {
            print_key_value("  Version", version);
        }

        println!();

        // Show troubleshooting hints if unhealthy
        if !api_status.is_operational() || !auth_status.is_operational() {
            println!("Troubleshooting:");
            println!("  - Check your internet connection");
            println!("  - Verify the API endpoints are correct");
            println!("  - Check https://status.xavyo.net for service status");
            println!();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_args() {
        let args = StatusArgs { json: true };
        assert!(args.json);
    }

    #[test]
    fn test_status_output_serialization() {
        let output = StatusOutput {
            tenant: Some(TenantStatusOutput {
                id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
                name: "Test Org".to_string(),
                slug: "test-org".to_string(),
                status: "Active".to_string(),
            }),
            api_health: HealthOutput {
                endpoint: "https://api.xavyo.net".to_string(),
                status: "Healthy".to_string(),
                version: Some("1.0.0".to_string()),
            },
            auth_health: HealthOutput {
                endpoint: "https://auth.xavyo.net".to_string(),
                status: "Healthy".to_string(),
                version: Some("1.0.0".to_string()),
            },
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("Test Org"));
        assert!(json.contains("Healthy"));
    }

    #[test]
    fn test_status_output_no_tenant() {
        let output = StatusOutput {
            tenant: None,
            api_health: HealthOutput {
                endpoint: "https://api.xavyo.net".to_string(),
                status: "Healthy".to_string(),
                version: None,
            },
            auth_health: HealthOutput {
                endpoint: "https://auth.xavyo.net".to_string(),
                status: "Healthy".to_string(),
                version: None,
            },
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"tenant\":null"));
    }
}
