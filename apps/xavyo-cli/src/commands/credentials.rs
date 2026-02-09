//! Credentials command - Top-level credential management for NHI agents (F-052)
//!
//! Provides direct access to credential operations without navigating
//! through the agents subcommand hierarchy.

use chrono::{DateTime, Duration, Utc};
use clap::{Args, Subcommand};
use uuid::Uuid;

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::interactive::{
    prompt_confirm, prompt_select, require_interactive, GRACE_PERIOD_OPTIONS,
};
use crate::models::agent::{
    NhiCredentialCreatedResponse, NhiCredentialResponse, RotateCredentialsRequest,
};

/// Top-level credentials command arguments
#[derive(Args, Debug)]
#[command(about = "Manage NHI credentials")]
pub struct CredentialsArgs {
    #[command(subcommand)]
    pub command: CredentialsCommands,
}

/// Subcommands for credential management
#[derive(Subcommand, Debug)]
pub enum CredentialsCommands {
    /// List credentials for an agent
    List(ListArgs),
    /// View detailed status of a credential
    Status(StatusArgs),
    /// Rotate a credential (generates new secret)
    Rotate(RotateArgs),
    /// Set credential expiration date (creates new credential)
    Expire(ExpireArgs),
}

/// Arguments for listing credentials
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Agent ID (UUID) whose credentials to list
    pub agent_id: String,

    /// Only show active credentials
    #[arg(long)]
    pub active_only: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for viewing credential status
#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Credential ID (UUID)
    pub credential_id: String,

    /// Agent ID (UUID) that owns the credential
    #[arg(long, short = 'a', required = true)]
    pub agent_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for rotating a credential
#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Credential ID being replaced (UUID) - for reference only; rotation creates a new credential
    pub credential_id: Option<String>,

    /// Use interactive mode with guided prompts
    #[arg(long, short = 'i')]
    pub interactive: bool,

    /// Agent ID (UUID) that owns the credential
    #[arg(long, short = 'a', required = true)]
    pub agent_id: String,

    /// Credential type (default: api_key)
    #[arg(long, short = 't', default_value = "api_key")]
    pub credential_type: String,

    /// Grace period in hours for old credential (0-168)
    #[arg(long, short = 'g')]
    pub grace_period_hours: Option<i32>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for setting credential expiration (creates new credential with specified expiration)
#[derive(Args, Debug)]
pub struct ExpireArgs {
    /// Credential ID being replaced (UUID) - for reference only; creates new credential
    pub credential_id: String,

    /// Agent ID (UUID) that owns the credential
    #[arg(long, short = 'a', required = true)]
    pub agent_id: String,

    /// New expiration date (ISO 8601 format, e.g., "2026-03-01T00:00:00Z")
    #[arg(long)]
    pub at: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// =============================================================================
// Helpers
// =============================================================================

/// Check if a credential is expiring soon (within 7 days)
fn is_expiring_soon(valid_until: &DateTime<Utc>) -> bool {
    let now = Utc::now();
    let seven_days = Duration::days(7);
    *valid_until <= now + seven_days
}

/// Check if a credential is expired
fn is_expired(valid_until: &DateTime<Utc>) -> bool {
    *valid_until <= Utc::now()
}

/// Format credential status for display
fn format_credential_status(cred: &NhiCredentialResponse) -> &'static str {
    if !cred.is_active {
        "Revoked"
    } else if is_expired(&cred.valid_until) {
        "Expired"
    } else if is_expiring_soon(&cred.valid_until) {
        "Expiring Soon"
    } else {
        "Active"
    }
}

/// Parse agent ID from string
fn parse_agent_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid agent ID '{id_str}'. Must be a valid UUID."
        ))
    })
}

/// Parse credential ID from string
fn parse_credential_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid credential ID '{id_str}'. Must be a valid UUID."
        ))
    })
}

/// Parse datetime from ISO 8601 string
fn parse_datetime(dt_str: &str) -> CliResult<DateTime<Utc>> {
    // Try full ISO 8601 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(dt_str) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try date-only format (assume midnight UTC)
    if let Ok(date) = chrono::NaiveDate::parse_from_str(dt_str, "%Y-%m-%d") {
        if let Some(datetime) = date.and_hms_opt(0, 0, 0) {
            return Ok(DateTime::from_naive_utc_and_offset(datetime, Utc));
        }
    }

    Err(CliError::Validation(format!(
        "Invalid datetime format '{dt_str}'. Use ISO 8601 format (e.g., '2026-03-01T00:00:00Z' or '2026-03-01')."
    )))
}

/// Validate that a date is in the future
fn validate_future_date(dt: &DateTime<Utc>) -> CliResult<()> {
    if *dt <= Utc::now() {
        return Err(CliError::Validation(
            "Expiration date must be in the future.".to_string(),
        ));
    }
    Ok(())
}

/// Validate credential type
fn validate_credential_type(cred_type: &str) -> CliResult<()> {
    match cred_type {
        "api_key" | "secret" | "certificate" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid credential type '{cred_type}'. Must be one of: api_key, secret, certificate"
        ))),
    }
}

// =============================================================================
// Command Execution
// =============================================================================

/// Execute the credentials command
pub async fn execute(args: CredentialsArgs) -> CliResult<()> {
    match args.command {
        CredentialsCommands::List(list_args) => execute_list(list_args).await,
        CredentialsCommands::Status(status_args) => execute_status(status_args).await,
        CredentialsCommands::Rotate(rotate_args) => execute_rotate(rotate_args).await,
        CredentialsCommands::Expire(expire_args) => execute_expire(expire_args).await,
    }
}

/// Execute the list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client
        .list_agent_credentials(agent_id, args.active_only)
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.items.is_empty() {
        println!("No credentials found for agent {agent_id}.");
        println!();
        println!(
            "Generate credentials with: xavyo credentials rotate <credential-id> -a {agent_id}"
        );
    } else {
        print_credentials_table(&response.items);
        println!();
        println!("Showing {} credential(s)", response.items.len());
    }

    Ok(())
}

/// Execute the status command
async fn execute_status(args: StatusArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;
    let credential_id = parse_credential_id(&args.credential_id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let credential = client.get_agent_credential(agent_id, credential_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&credential)?);
    } else {
        print_credential_status(&credential, &args.agent_id);
    }

    Ok(())
}

/// Execute the rotate command
async fn execute_rotate(args: RotateArgs) -> CliResult<()> {
    // Branch on interactive mode
    if args.interactive {
        return execute_rotate_interactive(args).await;
    }

    let agent_id = parse_agent_id(&args.agent_id)?;

    // Non-interactive mode: credential_id is required for reference
    if let Some(ref cred_id) = args.credential_id {
        let _credential_id = parse_credential_id(cred_id)?; // Validate format
    }

    // Validate credential type
    validate_credential_type(&args.credential_type)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Build the request
    let mut request = RotateCredentialsRequest::new(&args.credential_type);
    if let Some(hours) = args.grace_period_hours {
        if !(0..=168).contains(&hours) {
            return Err(CliError::Validation(
                "Grace period must be between 0 and 168 hours (1 week).".to_string(),
            ));
        }
        request = request.with_grace_period(hours);
    }

    // Rotate credentials
    let response = client.rotate_agent_credentials(agent_id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_rotate_success(&response);
    }

    Ok(())
}

/// Execute the rotate command in interactive mode (F-053)
async fn execute_rotate_interactive(args: RotateArgs) -> CliResult<()> {
    // Require interactive terminal
    require_interactive()?;

    let agent_id = parse_agent_id(&args.agent_id)?;

    println!();
    println!("Rotate Agent Credentials");
    println!("{}", "─".repeat(24));
    println!();

    // Get credential type (prompt if default)
    let credential_type = if args.credential_type != "api_key" {
        // User explicitly provided a type
        validate_credential_type(&args.credential_type)?;
        args.credential_type.clone()
    } else {
        prompt_credential_type()?
    };

    // Get grace period (prompt if not provided)
    let grace_period_hours = match args.grace_period_hours {
        Some(hours) => {
            if !(0..=168).contains(&hours) {
                return Err(CliError::Validation(
                    "Grace period must be between 0 and 168 hours (1 week).".to_string(),
                ));
            }
            Some(hours)
        }
        None => Some(prompt_grace_period()?),
    };

    // Confirm rotation
    let confirm = prompt_confirm(
        "Confirm rotation? Old credential will expire after grace period.",
        false,
    )?;

    if !confirm {
        println!("Operation cancelled. No changes were made.");
        return Ok(());
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Build the request
    let mut request = RotateCredentialsRequest::new(&credential_type);
    if let Some(hours) = grace_period_hours {
        request = request.with_grace_period(hours);
    }

    // Rotate credentials
    let response = client.rotate_agent_credentials(agent_id, request).await?;

    println!();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_rotate_success(&response);
    }

    Ok(())
}

/// Credential type option with description for interactive selection (F-053)
struct CredentialTypeOption {
    value: &'static str,
    description: &'static str,
}

impl std::fmt::Display for CredentialTypeOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<12} - {}", self.value, self.description)
    }
}

const CREDENTIAL_TYPE_OPTIONS: &[CredentialTypeOption] = &[
    CredentialTypeOption {
        value: "api_key",
        description: "Standard API key for authentication",
    },
    CredentialTypeOption {
        value: "secret",
        description: "Shared secret for HMAC signing",
    },
    CredentialTypeOption {
        value: "certificate",
        description: "X.509 certificate for mTLS",
    },
];

/// Prompt for credential type using interactive selection (F-053)
fn prompt_credential_type() -> CliResult<String> {
    let options: Vec<String> = CREDENTIAL_TYPE_OPTIONS
        .iter()
        .map(|o| format!("{o}"))
        .collect();

    let selection = prompt_select("Credential type", &options, 0)?;
    Ok(CREDENTIAL_TYPE_OPTIONS[selection].value.to_string())
}

/// Prompt for grace period using interactive selection (F-053)
fn prompt_grace_period() -> CliResult<i32> {
    let options: Vec<String> = GRACE_PERIOD_OPTIONS
        .iter()
        .map(|o| format!("{o}"))
        .collect();

    // Default to 24 hours (index 2)
    let selection = prompt_select("Grace period (old credential remains valid)", &options, 2)?;
    Ok(GRACE_PERIOD_OPTIONS[selection].hours)
}

/// Print successful rotation response
fn print_rotate_success(response: &NhiCredentialCreatedResponse) {
    println!("✓ Credential rotated successfully!");
    println!();
    println!("{}", "━".repeat(70));
    println!("⚠️  IMPORTANT: Save this secret now! It cannot be retrieved later.");
    println!("{}", "━".repeat(70));
    println!();
    println!("New Credential ID: {}", response.credential.id);
    println!("Type:              {}", response.credential.credential_type);
    println!();
    println!("Secret Value:");
    println!("  {}", response.secret_value);
    println!();
    println!(
        "Valid From:  {}",
        response
            .credential
            .valid_from
            .format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Valid Until: {}",
        response
            .credential
            .valid_until
            .format("%Y-%m-%d %H:%M:%S UTC")
    );

    if let Some(grace_ends) = response.grace_period_ends_at {
        println!();
        println!(
            "Grace Period Ends: {}",
            grace_ends.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("  Old credentials will remain valid until this time.");
    }

    println!();
    println!("{}", response.warning);
}

/// Execute the expire command
async fn execute_expire(args: ExpireArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;
    let _credential_id = parse_credential_id(&args.credential_id)?; // Validate format

    // Parse and validate expiration date
    let expires_at = parse_datetime(&args.at)?;
    validate_future_date(&expires_at)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Build the request with expiration
    let request = RotateCredentialsRequest::new("api_key").with_expires_at(expires_at);

    // Rotate credentials with expiration
    let response = client.rotate_agent_credentials(agent_id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("✓ New credential created with specified expiration!");
        println!();
        println!("{}", "━".repeat(70));
        println!("⚠️  IMPORTANT: Save this secret now! It cannot be retrieved later.");
        println!("{}", "━".repeat(70));
        println!();
        println!("Old Credential ID: {}", args.credential_id);
        println!("New Credential ID: {}", response.credential.id);
        println!(
            "Expiration:        {}",
            response
                .credential
                .valid_until
                .format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!();
        println!("Secret Value:");
        println!("  {}", response.secret_value);
        println!();
        println!(
            "Note: The old credential ({}) has been invalidated.",
            args.credential_id
        );
        println!("      Update your applications to use the new credential.");
        println!();
        println!("{}", response.warning);
    }

    Ok(())
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Print credentials list as a table
fn print_credentials_table(credentials: &[NhiCredentialResponse]) {
    println!(
        "{:<38} {:<12} {:<15} {:<22}",
        "ID", "TYPE", "STATUS", "VALID UNTIL"
    );
    println!("{}", "─".repeat(90));

    for cred in credentials {
        let status = format_credential_status(cred);
        let valid_until = cred.valid_until.format("%Y-%m-%d %H:%M UTC").to_string();

        // Add warning indicator for expiring soon
        let status_display = if status == "Expiring Soon" {
            format!("⚠ {status}")
        } else if status == "Expired" {
            format!("✗ {status}")
        } else {
            status.to_string()
        };

        println!(
            "{:<38} {:<12} {:<15} {:<22}",
            cred.id, cred.credential_type, status_display, valid_until
        );
    }
}

/// Print detailed credential status
fn print_credential_status(cred: &NhiCredentialResponse, agent_id: &str) {
    println!("Credential Status");
    println!("{}", "─".repeat(50));
    println!();
    println!("ID:           {}", cred.id);
    println!("Agent ID:     {agent_id}");
    println!("Type:         {}", cred.credential_type);
    println!("Status:       {}", format_credential_status(cred));
    println!(
        "Valid From:   {}",
        cred.valid_from.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Valid Until:  {}",
        cred.valid_until.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Created At:   {}",
        cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Show warnings
    if is_expired(&cred.valid_until) {
        println!();
        println!("✗ ERROR: This credential has expired and cannot be used.");
        println!(
            "  Rotate it: xavyo credentials rotate {} -a {}",
            cred.id, agent_id
        );
    } else if is_expiring_soon(&cred.valid_until) {
        let days_left = (cred.valid_until - Utc::now()).num_days();
        println!();
        println!(
            "⚠ WARNING: This credential expires in {} day(s)!",
            days_left.max(0)
        );
        println!(
            "  Consider rotating: xavyo credentials rotate {} -a {}",
            cred.id, agent_id
        );
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Duration};

    #[test]
    fn test_is_expiring_soon_within_7_days() {
        let now = Utc::now();
        let five_days = now + Duration::days(5);
        assert!(is_expiring_soon(&five_days));
    }

    #[test]
    fn test_is_expiring_soon_more_than_7_days() {
        let now = Utc::now();
        let ten_days = now + Duration::days(10);
        assert!(!is_expiring_soon(&ten_days));
    }

    #[test]
    fn test_is_expiring_soon_exactly_7_days() {
        let now = Utc::now();
        let seven_days = now + Duration::days(7);
        assert!(is_expiring_soon(&seven_days));
    }

    #[test]
    fn test_is_expiring_soon_past_date() {
        let now = Utc::now();
        let past = now - Duration::days(1);
        assert!(is_expiring_soon(&past)); // Past dates are "expiring soon" (already expired)
    }

    #[test]
    fn test_is_expired_past_date() {
        let now = Utc::now();
        let past = now - Duration::days(1);
        assert!(is_expired(&past));
    }

    #[test]
    fn test_is_expired_future_date() {
        let now = Utc::now();
        let future = now + Duration::days(1);
        assert!(!is_expired(&future));
    }

    #[test]
    fn test_parse_datetime_rfc3339() {
        let result = parse_datetime("2026-03-01T00:00:00Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn test_parse_datetime_date_only() {
        let result = parse_datetime("2026-03-01");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        let result = parse_datetime("not-a-date");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_future_date_future() {
        let future = Utc::now() + Duration::days(30);
        assert!(validate_future_date(&future).is_ok());
    }

    #[test]
    fn test_validate_future_date_past() {
        let past = Utc::now() - Duration::days(1);
        assert!(validate_future_date(&past).is_err());
    }

    #[test]
    fn test_list_args_parsing() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "list",
            "550e8400-e29b-41d4-a716-446655440000",
            "--active-only",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_status_args_parsing() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "status",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "-a",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_rotate_args_parsing() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "rotate",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "-a",
            "550e8400-e29b-41d4-a716-446655440000",
            "--credential-type",
            "api_key",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_expire_args_parsing() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "expire",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "-a",
            "550e8400-e29b-41d4-a716-446655440000",
            "--at",
            "2026-03-01T00:00:00Z",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_validate_credential_type_valid() {
        assert!(validate_credential_type("api_key").is_ok());
        assert!(validate_credential_type("secret").is_ok());
        assert!(validate_credential_type("certificate").is_ok());
    }

    #[test]
    fn test_validate_credential_type_invalid() {
        assert!(validate_credential_type("invalid").is_err());
    }

    // F-053: Interactive Mode Tests

    #[test]
    fn test_rotate_args_with_interactive_flag() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "rotate",
            "-i",
            "-a",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_rotate_args_interactive_with_explicit_type() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: CredentialsCommands,
        }

        let args = TestCli::try_parse_from([
            "test",
            "rotate",
            "--interactive",
            "-a",
            "550e8400-e29b-41d4-a716-446655440000",
            "-t",
            "certificate",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn test_grace_period_options_have_descriptions() {
        use crate::interactive::GRACE_PERIOD_OPTIONS;

        for option in GRACE_PERIOD_OPTIONS {
            // Each option should have a label and description
            assert!(!option.label.is_empty());
            assert!(!option.description.is_empty());
            // Hours should be in valid range
            assert!(option.hours >= 0 && option.hours <= 168);
            // The display format should include both
            let display = format!("{}", option);
            assert!(display.contains(option.label));
            assert!(display.contains(option.description));
        }
    }

    #[test]
    fn test_credential_type_options_display() {
        for option in CREDENTIAL_TYPE_OPTIONS {
            let display = format!("{}", option);
            assert!(display.contains(option.value));
            assert!(display.contains(option.description));
        }
    }
}
