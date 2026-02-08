//! Verify command - Check email verification status and resend verification emails

use crate::api::{get_profile, resend_verification, ApiClient};
use crate::config::{Config, ConfigPaths, SYSTEM_TENANT_ID};
use crate::credentials::get_credential_store;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use crate::output::{print_info, print_success, print_warning};
use clap::{Args, Subcommand};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

/// Arguments for the verify command
#[derive(Args)]
pub struct VerifyArgs {
    #[command(subcommand)]
    pub command: VerifyCommands,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,
}

/// Verify subcommands
#[derive(Subcommand)]
pub enum VerifyCommands {
    /// Check current email verification status
    Status,

    /// Resend the verification email
    Resend(ResendArgs),
}

/// Arguments for the resend subcommand
#[derive(Args)]
pub struct ResendArgs {
    /// Email address to resend verification to (defaults to logged-in user's email)
    #[arg(long)]
    pub email: Option<String>,
}

/// JSON output for verify status
#[derive(Serialize)]
struct VerifyStatusOutput {
    email: String,
    email_verified: bool,
}

/// JSON output for verify resend
#[derive(Serialize)]
struct VerifyResendOutput {
    email: String,
    message: String,
}

/// Execute the verify command
pub async fn execute(args: VerifyArgs) -> CliResult<()> {
    let json = args.json;
    match args.command {
        VerifyCommands::Status => execute_status(json).await,
        VerifyCommands::Resend(resend_args) => execute_resend(resend_args, json).await,
    }
}

/// Check email verification status via GET /me/profile
async fn execute_status(json: bool) -> CliResult<()> {
    let api_client = ApiClient::from_defaults()?;

    if !json {
        println!();
        print_info("Checking email verification status...");
    }

    let profile = get_profile(&api_client).await?;

    if json {
        let output = VerifyStatusOutput {
            email: profile.email,
            email_verified: profile.email_verified,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!();
    if profile.email_verified {
        print_success(&format!("Email {} is verified.", profile.email));
    } else {
        print_warning(&format!("Email {} is NOT verified.", profile.email));
        println!();
        print_info("Run the following to resend the verification email:");
        println!("  xavyo verify resend");
    }

    Ok(())
}

/// Resolve the email to use: explicit arg > session > error
fn resolve_email(explicit: Option<String>, paths: &ConfigPaths) -> CliResult<String> {
    if let Some(email) = explicit {
        return Ok(email);
    }

    // Try to get email from session
    let store = get_credential_store(paths);
    if let Some(creds) = store.load()? {
        if !creds.is_expired() {
            if let Ok(Some(session)) = Session::load(paths) {
                return Ok(session.email);
            }
        }
    }

    Err(CliError::Validation(
        "No email specified and not logged in. Use --email <address> or log in first.".to_string(),
    ))
}

/// Resolve the tenant ID: session tenant > system tenant fallback
fn resolve_tenant_id(paths: &ConfigPaths) -> String {
    Session::load(paths)
        .ok()
        .flatten()
        .and_then(|s| s.tenant_id)
        .map(|id| id.to_string())
        .unwrap_or_else(|| SYSTEM_TENANT_ID.to_string())
}

/// Resend verification email via POST /auth/resend-verification
async fn execute_resend(args: ResendArgs, json: bool) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;

    let email = resolve_email(args.email, &paths)?;
    let tenant_id = resolve_tenant_id(&paths);

    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| CliError::Network(format!("Failed to create HTTP client: {e}")))?;

    if !json {
        println!();
        print_info(&format!("Requesting verification email for {email}..."));
    }

    let response = resend_verification(&client, &config, &email, &tenant_id).await?;

    if json {
        let output = VerifyResendOutput {
            email,
            message: response.message,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!();
    print_success(&response.message);
    println!();
    print_info("Check your inbox (and spam folder) for the verification link.");
    print_info("Run 'xavyo verify status' after verifying to confirm.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Credentials;
    use tempfile::TempDir;

    fn test_paths(dir: &std::path::Path) -> ConfigPaths {
        ConfigPaths {
            config_dir: dir.to_path_buf(),
            config_file: dir.join("config.json"),
            session_file: dir.join("session.json"),
            credentials_file: dir.join("credentials.enc"),
            cache_dir: dir.join("cache"),
            history_file: dir.join("shell_history"),
            version_history_dir: dir.join("history"),
        }
    }

    #[test]
    fn test_system_tenant_id_is_valid_uuid() {
        let parsed = uuid::Uuid::parse_str(SYSTEM_TENANT_ID);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_resolve_email_explicit_takes_priority() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        let result = resolve_email(Some("explicit@example.com".to_string()), &paths);
        assert_eq!(result.unwrap(), "explicit@example.com");
    }

    #[test]
    fn test_resolve_email_no_session_no_arg_fails() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        let result = resolve_email(None, &paths);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_email_reads_from_session() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        // Write a session file with an email
        let session = Session {
            user_id: uuid::Uuid::new_v4(),
            email: "session@example.com".to_string(),
            tenant_id: None,
            tenant_name: None,
            tenant_slug: None,
            tenant_role: None,
        };
        session.save(&paths).unwrap();

        // Write valid (non-expired) credentials
        let creds = Credentials::new("fake-token".to_string(), None, 3600);
        let store = get_credential_store(&paths);
        store.store(&creds).unwrap();

        let result = resolve_email(None, &paths);
        assert_eq!(result.unwrap(), "session@example.com");
    }

    #[test]
    fn test_resolve_email_explicit_overrides_session() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        // Write a session
        let session = Session {
            user_id: uuid::Uuid::new_v4(),
            email: "session@example.com".to_string(),
            tenant_id: None,
            tenant_name: None,
            tenant_slug: None,
            tenant_role: None,
        };
        session.save(&paths).unwrap();

        let creds = Credentials::new("fake-token".to_string(), None, 3600);
        let store = get_credential_store(&paths);
        store.store(&creds).unwrap();

        let result = resolve_email(Some("override@example.com".to_string()), &paths);
        assert_eq!(result.unwrap(), "override@example.com");
    }

    #[test]
    fn test_resolve_tenant_id_no_session_returns_system() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        let result = resolve_tenant_id(&paths);
        assert_eq!(result, SYSTEM_TENANT_ID);
    }

    #[test]
    fn test_resolve_tenant_id_reads_from_session() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());

        let tenant_id = uuid::Uuid::new_v4();
        let session = Session {
            user_id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            tenant_id: Some(tenant_id),
            tenant_name: Some("Test Org".to_string()),
            tenant_slug: Some("test-org".to_string()),
            tenant_role: None,
        };
        session.save(&paths).unwrap();

        let result = resolve_tenant_id(&paths);
        assert_eq!(result, tenant_id.to_string());
    }

    #[test]
    fn test_verify_status_output_serialization() {
        let output = VerifyStatusOutput {
            email: "test@example.com".to_string(),
            email_verified: true,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["email_verified"], true);
    }

    #[test]
    fn test_verify_status_output_unverified() {
        let output = VerifyStatusOutput {
            email: "new@example.com".to_string(),
            email_verified: false,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["email_verified"], false);
    }

    #[test]
    fn test_verify_resend_output_serialization() {
        let output = VerifyResendOutput {
            email: "user@example.com".to_string(),
            message: "Verification email sent.".to_string(),
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["email"], "user@example.com");
        assert_eq!(json["message"], "Verification email sent.");
    }
}
