//! Security policy management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::Session;
use clap::{Args, Subcommand};

/// Security policy management commands
#[derive(Args, Debug)]
pub struct PoliciesArgs {
    #[command(subcommand)]
    pub command: PoliciesCommands,
}

#[derive(Subcommand, Debug)]
pub enum PoliciesCommands {
    /// Get a security policy
    Get(GetArgs),
    /// Update a security policy from JSON
    Set(SetArgs),
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Policy type: session, password, lockout, mfa, webauthn, device
    pub policy_type: String,

    /// Tenant ID (defaults to current tenant)
    #[arg(long)]
    pub tenant_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Policy type: session, password, lockout, mfa, webauthn, device
    pub policy_type: String,

    /// Policy JSON (inline or @filename)
    pub policy_json: String,

    /// Tenant ID (defaults to current tenant)
    #[arg(long)]
    pub tenant_id: Option<String>,
}

pub async fn execute(args: PoliciesArgs) -> CliResult<()> {
    match args.command {
        PoliciesCommands::Get(a) => execute_get(a).await,
        PoliciesCommands::Set(a) => execute_set(a).await,
    }
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    validate_policy_type(&args.policy_type)?;

    let client = ApiClient::from_defaults()?;
    let tenant_id = resolve_tenant_id(args.tenant_id.as_deref(), client.paths())?;

    let policy = client.get_policy(tenant_id, &args.policy_type).await?;

    println!("{}", serde_json::to_string_pretty(&policy)?);

    Ok(())
}

async fn execute_set(args: SetArgs) -> CliResult<()> {
    validate_policy_type(&args.policy_type)?;

    let client = ApiClient::from_defaults()?;
    let tenant_id = resolve_tenant_id(args.tenant_id.as_deref(), client.paths())?;

    let policy_value: serde_json::Value = if args.policy_json.starts_with('@') {
        let path = &args.policy_json[1..];
        let content = std::fs::read_to_string(path)
            .map_err(|e| CliError::Io(format!("Failed to read policy file '{path}': {e}")))?;
        serde_json::from_str(&content)
            .map_err(|e| CliError::Validation(format!("Invalid JSON in file: {e}")))?
    } else {
        serde_json::from_str(&args.policy_json)
            .map_err(|e| CliError::Validation(format!("Invalid JSON: {e}")))?
    };

    let result = client
        .update_policy(tenant_id, &args.policy_type, &policy_value)
        .await?;

    println!("Policy updated successfully!");
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

fn validate_policy_type(ptype: &str) -> CliResult<()> {
    match ptype {
        "session" | "password" | "lockout" | "mfa" | "webauthn" | "device" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid policy type '{ptype}'. Must be one of: session, password, lockout, mfa, webauthn, device"
        ))),
    }
}

fn resolve_tenant_id(
    explicit: Option<&str>,
    paths: &crate::config::ConfigPaths,
) -> CliResult<uuid::Uuid> {
    if let Some(tid) = explicit {
        uuid::Uuid::parse_str(tid)
            .map_err(|_| CliError::Validation(format!("Invalid tenant ID '{tid}'.")))
    } else {
        Session::load(paths)?
            .and_then(|s| s.tenant_id)
            .ok_or_else(|| {
                CliError::Validation(
                    "No active tenant. Use --tenant-id or 'xavyo tenant switch' first.".to_string(),
                )
            })
    }
}
