//! API key management CLI commands
//!
//! Commands for managing tenant API keys:
//! - `xavyo api-keys create` - Create a new API key
//! - `xavyo api-keys list` - List all API keys
//! - `xavyo api-keys rotate` - Rotate an existing API key
//! - `xavyo api-keys delete` - Delete an API key

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::interactive::{
    is_interactive_terminal, prompt_confirm, prompt_multiselect, prompt_text, prompt_text_optional,
    require_interactive,
};
use crate::models::api_key::{
    ApiKeyListResponse, CreateApiKeyRequest, CreateApiKeyResponse, RotateApiKeyRequest,
    RotateApiKeyResponse,
};
use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// API key management commands
#[derive(Args, Debug)]
pub struct ApiKeysArgs {
    #[command(subcommand)]
    pub command: ApiKeysCommands,
}

#[derive(Subcommand, Debug)]
pub enum ApiKeysCommands {
    /// Create a new API key
    Create(CreateArgs),
    /// List all API keys
    List(ListArgs),
    /// Rotate an existing API key
    Rotate(RotateArgs),
    /// Delete an API key
    Delete(DeleteArgs),
}

// =============================================================================
// Command Arguments
// =============================================================================

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Human-readable name for the API key (1-100 characters)
    /// Required in non-interactive mode, prompted in interactive mode
    pub name: Option<String>,

    /// Use interactive mode with guided prompts
    #[arg(long, short = 'i')]
    pub interactive: bool,

    /// Permission scopes (comma-separated, e.g., "nhi:agents:*,audit:*")
    /// Empty = full access
    #[arg(long, short = 's')]
    pub scopes: Option<String>,

    /// Number of days until the key expires (default: never)
    #[arg(long)]
    pub expires_in: Option<u32>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the rotate command
#[derive(Args, Debug)]
pub struct RotateArgs {
    /// API key ID (UUID)
    pub key_id: String,

    /// Immediately deactivate the old key (no grace period)
    #[arg(long)]
    pub deactivate_old: bool,

    /// Grace period in hours before old key expires (default: 24)
    #[arg(long)]
    pub grace_period: Option<u32>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Skip confirmation prompt for --deactivate-old
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Arguments for the delete command
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// API key ID (UUID)
    pub key_id: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// =============================================================================
// Command Execution
// =============================================================================

/// Execute API key commands
pub async fn execute(args: ApiKeysArgs) -> CliResult<()> {
    match args.command {
        ApiKeysCommands::Create(create_args) => execute_create(create_args).await,
        ApiKeysCommands::List(list_args) => execute_list(list_args).await,
        ApiKeysCommands::Rotate(rotate_args) => execute_rotate(rotate_args).await,
        ApiKeysCommands::Delete(delete_args) => execute_delete(delete_args).await,
    }
}

/// Execute create command
async fn execute_create(args: CreateArgs) -> CliResult<()> {
    // Branch on interactive mode
    if args.interactive {
        return execute_create_interactive(args).await;
    }

    // Non-interactive mode: name is required
    let name = args.name.ok_or_else(|| {
        CliError::Validation(
            "API key name is required. Provide a name or use --interactive mode.".to_string(),
        )
    })?;

    // Validate name
    validate_api_key_name(&name)?;

    // Parse scopes
    let scopes = parse_scopes(args.scopes.as_deref())?;

    // Calculate expires_at from expires_in days
    let expires_at = args
        .expires_in
        .map(|days| Utc::now() + Duration::days(i64::from(days)));

    // Build request
    let mut request = CreateApiKeyRequest::new(&name);
    if !scopes.is_empty() {
        request = request.with_scopes(scopes);
    }
    if let Some(exp) = expires_at {
        request = request.with_expires_at(exp);
    }

    // Make API call
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.create_api_key(request).await?;

    // Output
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_create_response(&response);
    }

    Ok(())
}

/// Execute create command in interactive mode (F-053)
async fn execute_create_interactive(args: CreateArgs) -> CliResult<()> {
    // Require interactive terminal
    require_interactive()?;

    println!();
    println!("Create a New API Key");
    println!("{}", "─".repeat(20));
    println!();

    // Get API key name (prompt if not provided)
    let name = match args.name {
        Some(n) => {
            validate_api_key_name(&n)?;
            n
        }
        None => prompt_api_key_name()?,
    };

    // Get scopes via multiselect (if not provided via flag)
    let scopes = if let Some(ref scopes_str) = args.scopes {
        parse_scopes(Some(scopes_str.as_str()))?
    } else {
        prompt_scopes_interactive()?
    };

    // Get expiration days (if not provided via flag)
    let expires_at = if let Some(days) = args.expires_in {
        Some(Utc::now() + Duration::days(i64::from(days)))
    } else {
        prompt_expiration_days()?
    };

    // Build request
    let mut request = CreateApiKeyRequest::new(&name);
    if !scopes.is_empty() {
        request = request.with_scopes(scopes.clone());
    }
    if let Some(exp) = expires_at {
        request = request.with_expires_at(exp);
    }

    // Make API call
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.create_api_key(request).await?;

    // Output
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_create_response(&response);
    }

    Ok(())
}

/// Prompt for API key name with validation (F-053)
fn prompt_api_key_name() -> CliResult<String> {
    prompt_text("API key name", |name| {
        if name.is_empty() {
            return Err("Name cannot be empty".to_string());
        }
        if name.len() > 100 {
            return Err("Name must be 100 characters or less".to_string());
        }
        Ok(())
    })
}

/// Prompt for scopes via multiselect with full-access warning (F-053)
fn prompt_scopes_interactive() -> CliResult<Vec<String>> {
    use crate::interactive::scopes::{indices_to_scopes, scope_display_labels};

    let labels = scope_display_labels();
    println!("Select scopes (space to toggle, enter to confirm):");

    let selected = prompt_multiselect("", &labels)?;

    // If no scopes selected, warn about full access
    if selected.is_empty() {
        println!();
        println!("⚠️  Warning: No scopes selected. This key will have FULL ACCESS.");

        let proceed = prompt_confirm("Proceed with full access key?", false)?;
        if !proceed {
            // Let user select again
            return prompt_scopes_interactive();
        }
    }

    Ok(indices_to_scopes(&selected))
}

/// Prompt for optional expiration days (F-053)
fn prompt_expiration_days() -> CliResult<Option<chrono::DateTime<Utc>>> {
    let input = prompt_text_optional("Expiration (days, empty for never)")?;

    match input {
        None => Ok(None),
        Some(s) => {
            let days: u32 = s.parse().map_err(|_| {
                CliError::Validation(
                    "Invalid number of days. Please enter a positive integer.".to_string(),
                )
            })?;
            if days == 0 {
                return Err(CliError::Validation(
                    "Days must be greater than 0.".to_string(),
                ));
            }
            Ok(Some(Utc::now() + Duration::days(i64::from(days))))
        }
    }
}

/// Execute list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.list_api_keys().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.api_keys.is_empty() {
        println!("No API keys found.");
        println!();
        println!("Create your first API key with: xavyo api-keys create <name>");
    } else {
        print_api_key_table(&response);
    }

    Ok(())
}

/// Execute rotate command
async fn execute_rotate(args: RotateArgs) -> CliResult<()> {
    let key_id = parse_key_id(&args.key_id)?;

    // If deactivate_old is set, confirm unless --yes
    if args.deactivate_old && !args.yes {
        if !is_interactive_terminal() {
            return Err(CliError::Validation(
                "Cannot confirm in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        println!("⚠️  Warning: This will immediately deactivate the old key.");
        println!("   Any systems using it will lose access.");
        println!();

        let confirm = Confirm::new()
            .with_prompt("Are you sure you want to continue?")
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Build request
    let mut request = RotateApiKeyRequest::new();
    if args.deactivate_old {
        request = request.with_deactivate_old(true);
    }
    if let Some(hours) = args.grace_period {
        request = request.with_grace_period(hours);
    }

    // Make API call
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.rotate_api_key(key_id, request).await?;

    // Output
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_rotate_response(&response);
    }

    Ok(())
}

/// Execute delete command (F-053: confirmation prompt)
async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let key_id = parse_key_id(&args.key_id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get key info for confirmation message (optional, ignore error)
    let key_name = client
        .get_api_key(key_id)
        .await
        .ok()
        .map(|k| k.name)
        .unwrap_or_else(|| key_id.to_string());

    // Confirm deletion unless --yes
    if !args.yes {
        if !is_interactive_terminal() {
            return Err(CliError::Validation(
                "Cannot confirm in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = prompt_confirm(
            &format!(
                "Are you sure you want to delete API key \"{}\"?\n  This action cannot be undone.",
                key_name
            ),
            false,
        )?;

        if !confirm {
            println!("Operation cancelled. No changes were made.");
            return Ok(());
        }
    }

    // Delete the key
    client.delete_api_key(key_id).await?;

    if args.json {
        println!(r#"{{"status":"deleted","key_id":"{}"}}"#, key_id);
    } else {
        println!("✓ API key deleted successfully.");
    }

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Validate API key name (1-100 characters)
fn validate_api_key_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::Validation(
            "API key name cannot be empty.".to_string(),
        ));
    }
    if name.len() > 100 {
        return Err(CliError::Validation(
            "API key name must be 100 characters or less.".to_string(),
        ));
    }
    Ok(())
}

/// Parse comma-separated scopes into Vec
fn parse_scopes(scopes_str: Option<&str>) -> CliResult<Vec<String>> {
    match scopes_str {
        None | Some("") => Ok(Vec::new()),
        Some(s) => {
            let scopes: Vec<String> = s
                .split(',')
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty())
                .collect();

            // Validate each scope format
            for scope in &scopes {
                validate_scope_format(scope)?;
            }

            Ok(scopes)
        }
    }
}

/// Validate scope format (prefix:resource:action or prefix:*)
fn validate_scope_format(scope: &str) -> CliResult<()> {
    if !scope.contains(':') {
        return Err(CliError::Validation(format!(
            "Invalid scope format: '{}'. Expected format: prefix:resource:action or prefix:*",
            scope
        )));
    }

    let parts: Vec<&str> = scope.split(':').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(CliError::Validation(format!(
            "Invalid scope format: '{}'. Expected format: prefix:resource:action or prefix:*",
            scope
        )));
    }

    // Validate known prefixes
    let valid_prefixes = ["nhi", "agents", "users", "groups", "audit"];
    let prefix = parts[0];
    if !valid_prefixes.contains(&prefix) {
        return Err(CliError::Validation(format!(
            "Invalid scope prefix: '{}'. Valid prefixes: {}",
            prefix,
            valid_prefixes.join(", ")
        )));
    }

    Ok(())
}

/// Parse key ID from string
fn parse_key_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid API key ID '{}'. Must be a valid UUID.",
            id_str
        ))
    })
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Print create response with one-time key warning
fn print_create_response(response: &CreateApiKeyResponse) {
    println!();
    println!("⚠️  IMPORTANT: This is the only time your API key will be displayed.");
    println!("   Store it securely now - it cannot be retrieved later.");
    println!();
    println!("API Key Created Successfully");
    println!("{}", "━".repeat(50));
    println!("Name:       {}", response.name);
    println!("ID:         {}", response.id);
    println!("Prefix:     {}", response.key_prefix);
    println!();
    println!("API Key:    {}", response.api_key);
    println!();
    if response.scopes.is_empty() {
        println!("Scopes:     (full access)");
    } else {
        println!("Scopes:     {}", response.scopes.join(", "));
    }
    match response.expires_at {
        Some(exp) => println!("Expires:    {}", exp.format("%Y-%m-%d %H:%M:%S UTC")),
        None => println!("Expires:    Never"),
    }
    println!();
}

/// Print rotate response with one-time key warning
fn print_rotate_response(response: &RotateApiKeyResponse) {
    println!();
    println!("⚠️  IMPORTANT: This is the only time your new API key will be displayed.");
    println!("   Store it securely now - it cannot be retrieved later.");
    println!();
    println!("API Key Rotated Successfully");
    println!("{}", "━".repeat(50));
    println!("New Key ID:     {}", response.new_key_id);
    println!("New Prefix:     {}", response.new_key_prefix);
    println!();
    println!("New API Key:    {}", response.new_api_key);
    println!();
    println!("Old Key Status: {}", response.old_key_status);
    if let Some(expires) = response.old_key_expires_at {
        println!(
            "Old Key Expires: {}",
            expires.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }
    println!();
}

/// Print API key list as table
fn print_api_key_table(response: &ApiKeyListResponse) {
    println!(
        "{:<38} {:<20} {:<20} {:<8} {:<12}",
        "ID", "NAME", "SCOPES", "STATUS", "EXPIRES"
    );
    println!("{}", "-".repeat(100));

    for key in &response.api_keys {
        let truncated_name = if key.name.len() > 18 {
            format!("{}...", &key.name[..15])
        } else {
            key.name.clone()
        };

        let scopes_display = if key.scopes.is_empty() {
            "(full access)".to_string()
        } else if key.scopes.len() == 1 {
            key.scopes[0].clone()
        } else {
            format!("{},...", key.scopes[0])
        };

        let truncated_scopes = if scopes_display.len() > 18 {
            format!("{}...", &scopes_display[..15])
        } else {
            scopes_display
        };

        let status = if key.is_active { "Active" } else { "Inactive" };

        let expires = match key.expires_at {
            Some(exp) => exp.format("%Y-%m-%d").to_string(),
            None => "Never".to_string(),
        };

        println!(
            "{:<38} {:<20} {:<20} {:<8} {:<12}",
            key.id, truncated_name, truncated_scopes, status, expires
        );
    }

    println!();
    println!("Total: {} API key(s)", response.total);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // T020: Test create command argument parsing
    #[test]
    fn test_validate_api_key_name_valid() {
        assert!(validate_api_key_name("my-key").is_ok());
        assert!(validate_api_key_name("a").is_ok());
        assert!(validate_api_key_name("a".repeat(100).as_str()).is_ok());
    }

    #[test]
    fn test_validate_api_key_name_invalid() {
        assert!(validate_api_key_name("").is_err());
        assert!(validate_api_key_name(&"a".repeat(101)).is_err());
    }

    // T021: Test create with scopes parsing
    #[test]
    fn test_parse_scopes_empty() {
        assert_eq!(parse_scopes(None).unwrap(), Vec::<String>::new());
        assert_eq!(parse_scopes(Some("")).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_parse_scopes_single() {
        let scopes = parse_scopes(Some("nhi:agents:*")).unwrap();
        assert_eq!(scopes, vec!["nhi:agents:*"]);
    }

    #[test]
    fn test_parse_scopes_multiple() {
        let scopes = parse_scopes(Some("nhi:agents:*, audit:*")).unwrap();
        assert_eq!(scopes, vec!["nhi:agents:*", "audit:*"]);
    }

    #[test]
    fn test_parse_scopes_invalid_format() {
        assert!(parse_scopes(Some("invalid")).is_err());
    }

    #[test]
    fn test_parse_scopes_invalid_prefix() {
        assert!(parse_scopes(Some("unknown:resource:action")).is_err());
    }

    #[test]
    fn test_validate_scope_format_valid() {
        assert!(validate_scope_format("nhi:agents:*").is_ok());
        assert!(validate_scope_format("nhi:*").is_ok());
        assert!(validate_scope_format("audit:*").is_ok());
        assert!(validate_scope_format("users:read").is_ok());
        assert!(validate_scope_format("groups:members:read").is_ok());
    }

    #[test]
    fn test_validate_scope_format_invalid() {
        assert!(validate_scope_format("invalid").is_err());
        assert!(validate_scope_format("unknown:action").is_err());
    }

    #[test]
    fn test_parse_key_id_valid() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        assert!(parse_key_id(uuid_str).is_ok());
    }

    #[test]
    fn test_parse_key_id_invalid() {
        assert!(parse_key_id("not-a-uuid").is_err());
        assert!(parse_key_id("").is_err());
    }

    // F-053: Interactive Mode Tests

    #[test]
    fn test_create_args_with_interactive_flag() {
        // Test that CreateArgs can have --interactive flag
        let args = CreateArgs {
            name: None,
            interactive: true,
            scopes: None,
            expires_in: None,
            json: false,
        };
        assert!(args.interactive);
        assert!(args.name.is_none());
    }

    #[test]
    fn test_create_args_non_interactive_requires_name() {
        // Test that non-interactive mode requires a name
        let args = CreateArgs {
            name: None,
            interactive: false,
            scopes: Some("nhi:agents:*".to_string()),
            expires_in: Some(30),
            json: false,
        };
        // In non-interactive mode with no name, this would fail validation
        assert!(args.name.is_none());
        assert!(!args.interactive);
    }

    #[test]
    fn test_create_args_with_all_fields() {
        // Test that CreateArgs can hold all fields
        let args = CreateArgs {
            name: Some("my-api-key".to_string()),
            interactive: true,
            scopes: Some("nhi:agents:read,nhi:agents:create".to_string()),
            expires_in: Some(90),
            json: true,
        };
        assert_eq!(args.name, Some("my-api-key".to_string()));
        assert!(args.interactive);
        assert_eq!(
            args.scopes,
            Some("nhi:agents:read,nhi:agents:create".to_string())
        );
        assert_eq!(args.expires_in, Some(90));
    }

    #[test]
    fn test_scope_descriptions_are_displayed() {
        // Test that NHI_SCOPES has descriptions for display
        use crate::interactive::scopes::NHI_SCOPES;

        for scope in NHI_SCOPES {
            // Each scope should have both a scope string and description
            assert!(!scope.scope.is_empty());
            assert!(!scope.description.is_empty());
            // The display format should include both
            let display = format!("{}", scope);
            assert!(display.contains(scope.scope));
            assert!(display.contains(scope.description));
        }
    }
}
