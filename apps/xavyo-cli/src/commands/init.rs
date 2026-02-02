//! Init command - Provision a new tenant

use crate::api::{provision_tenant, ApiClient};
use crate::config::{Config, ConfigPaths};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::{ProvisionRequest, Session};
use crate::output::{
    print_header, print_info, print_key_value, print_next_steps, print_success, print_warning,
};
use clap::Args;
use serde::Serialize;

/// Arguments for the init command
#[derive(Args)]
pub struct InitArgs {
    /// Organization name for the new tenant
    pub name: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// JSON output for init
#[derive(Serialize)]
struct InitOutput {
    tenant: TenantOutput,
    admin: AdminOutput,
    oauth_client: OAuthClientOutput,
    endpoints: EndpointsOutput,
    next_steps: Vec<String>,
}

#[derive(Serialize)]
struct TenantOutput {
    id: String,
    slug: String,
    name: String,
}

#[derive(Serialize)]
struct AdminOutput {
    id: String,
    email: String,
    api_key: String,
}

#[derive(Serialize)]
struct OAuthClientOutput {
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
struct EndpointsOutput {
    api: String,
    auth: String,
}

/// Execute the init command
pub async fn execute(args: InitArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    // Check if logged in
    let store = get_credential_store(&paths);
    if !store.exists() {
        return Err(CliError::NotAuthenticated);
    }

    // Validate organization name
    let request = ProvisionRequest::new(args.name.clone());
    if let Err(msg) = request.validate() {
        return Err(CliError::Validation(msg.to_string()));
    }

    // Check if user already has a tenant
    if let Some(session) = Session::load(&paths)? {
        if session.has_tenant() && !args.json {
            print_warning(&format!(
                "You already have a tenant context: {} ({})",
                session.tenant_name.as_deref().unwrap_or("Unknown"),
                session.tenant_slug.as_deref().unwrap_or("unknown")
            ));
            print_info("Creating an additional tenant...");
            println!();
        }
    }

    // Create API client
    let client = ApiClient::new(config.clone(), paths.clone())?;

    // Provision tenant
    if !args.json {
        print_info(&format!("Creating tenant \"{}\"...", args.name));
    }

    let response = provision_tenant(&client, &request).await?;

    // Update session with new tenant context
    if let Some(mut session) = Session::load(&paths)? {
        session.set_tenant(
            response.tenant.id,
            response.tenant.name.clone(),
            response.tenant.slug.clone(),
        );
        session.save(&paths)?;
    }

    if args.json {
        // JSON output
        let output = InitOutput {
            tenant: TenantOutput {
                id: response.tenant.id.to_string(),
                slug: response.tenant.slug.clone(),
                name: response.tenant.name.clone(),
            },
            admin: AdminOutput {
                id: response.admin.id.to_string(),
                email: response.admin.email.clone(),
                api_key: response.admin.api_key.clone(),
            },
            oauth_client: OAuthClientOutput {
                client_id: response.oauth_client.client_id.clone(),
                client_secret: response.oauth_client.client_secret.clone(),
            },
            endpoints: EndpointsOutput {
                api: response.endpoints.api.clone(),
                auth: response.endpoints.auth.clone(),
            },
            next_steps: response.next_steps.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        print_success(&format!("Tenant \"{}\" created successfully!", args.name));

        print_header("TENANT CREATED");

        println!("Tenant:");
        print_key_value("  ID", &response.tenant.id.to_string());
        print_key_value("  Slug", &response.tenant.slug);
        print_key_value("  Name", &response.tenant.name);

        println!("\nAdmin:");
        print_key_value("  ID", &response.admin.id.to_string());
        print_key_value("  Email", &response.admin.email);

        println!("\nCredentials (save these - they won't be shown again):");
        print_key_value("  API Key", &response.admin.api_key);
        print_key_value("  Client ID", &response.oauth_client.client_id);
        print_key_value("  Client Secret", &response.oauth_client.client_secret);

        println!("\nEndpoints:");
        print_key_value("  API", &response.endpoints.api);
        print_key_value("  Auth", &response.endpoints.auth);

        print_next_steps(&response.next_steps);
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_args() {
        let args = InitArgs {
            name: "Test Org".to_string(),
            json: false,
        };
        assert_eq!(args.name, "Test Org");
        assert!(!args.json);
    }

    #[test]
    fn test_init_output_serialization() {
        let output = InitOutput {
            tenant: TenantOutput {
                id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
                slug: "test-org".to_string(),
                name: "Test Org".to_string(),
            },
            admin: AdminOutput {
                id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
                email: "admin@test.com".to_string(),
                api_key: "xavyo_sk_live_abc123".to_string(),
            },
            oauth_client: OAuthClientOutput {
                client_id: "test-org-default".to_string(),
                client_secret: "cs_live_xyz789".to_string(),
            },
            endpoints: EndpointsOutput {
                api: "https://api.xavyo.net".to_string(),
                auth: "https://auth.xavyo.net".to_string(),
            },
            next_steps: vec!["Save your credentials".to_string()],
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("Test Org"));
        assert!(json.contains("xavyo_sk_live_abc123"));
    }
}
