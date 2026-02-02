//! Whoami command - Display current identity

use crate::config::ConfigPaths;
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use crate::output::print_key_value;
use clap::Args;
use serde::Serialize;

/// Arguments for the whoami command
#[derive(Args)]
pub struct WhoamiArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// JSON output for whoami
#[derive(Serialize)]
struct WhoamiOutput {
    user_id: String,
    email: String,
    tenant_id: Option<String>,
    tenant_name: Option<String>,
    tenant_slug: Option<String>,
}

impl From<&Session> for WhoamiOutput {
    fn from(session: &Session) -> Self {
        Self {
            user_id: session.user_id.to_string(),
            email: session.email.clone(),
            tenant_id: session.tenant_id.map(|id| id.to_string()),
            tenant_name: session.tenant_name.clone(),
            tenant_slug: session.tenant_slug.clone(),
        }
    }
}

/// Execute the whoami command
pub async fn execute(args: WhoamiArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;

    // Check if logged in
    let store = get_credential_store(&paths);
    if !store.exists() {
        return Err(CliError::NotAuthenticated);
    }

    // Load session
    let session = Session::load(&paths)?.ok_or(CliError::NotAuthenticated)?;

    if args.json {
        // JSON output
        let output = WhoamiOutput::from(&session);
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        println!();
        print_key_value("User ID", &session.user_id.to_string());
        print_key_value("Email", &session.email);

        if let Some(tenant_id) = &session.tenant_id {
            println!();
            print_key_value("Tenant ID", &tenant_id.to_string());
            if let Some(name) = &session.tenant_name {
                print_key_value("Tenant Name", name);
            }
            if let Some(slug) = &session.tenant_slug {
                print_key_value("Tenant Slug", slug);
            }
        } else {
            println!();
            print_key_value("Tenant", "(none - run 'xavyo init' to create one)");
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_whoami_output_serialization() {
        let session = Session {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            tenant_id: Some(Uuid::new_v4()),
            tenant_name: Some("Test Org".to_string()),
            tenant_slug: Some("test-org".to_string()),
        };

        let output = WhoamiOutput::from(&session);
        let json = serde_json::to_string(&output).unwrap();

        assert!(json.contains("test@example.com"));
        assert!(json.contains("Test Org"));
    }

    #[test]
    fn test_whoami_output_no_tenant() {
        let session = Session {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            tenant_id: None,
            tenant_name: None,
            tenant_slug: None,
        };

        let output = WhoamiOutput::from(&session);
        assert!(output.tenant_id.is_none());
        assert!(output.tenant_name.is_none());
    }
}
