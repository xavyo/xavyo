//! Agent management CLI commands

use crate::api::ApiClient;
use crate::batch::executor::{print_batch_summary, BatchExecutor, BatchOptions};
use crate::batch::file::BatchFile;
use crate::batch::filter::Filter;
use crate::cache::store::CACHE_KEY_AGENTS;
use crate::cache::{CacheStore, FileCacheStore};
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::agent::{
    AgentListResponse, AgentResponse, CreateAgentRequest, DryRunRotationPreview,
    NhiCredentialResponse, RevokeCredentialRequest, RotateCredentialsRequest,
};
use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

/// Agent management commands
#[derive(Args, Debug)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: AgentsCommands,
}

#[derive(Subcommand, Debug)]
pub enum AgentsCommands {
    /// List all AI agents in the current tenant
    List(ListArgs),
    /// Create a new AI agent (supports --batch for bulk creation)
    Create(CreateArgs),
    /// Get details of a specific agent
    Get(GetArgs),
    /// Update an existing agent (supports --batch for bulk updates)
    Update(UpdateArgs),
    /// Delete an AI agent (supports --filter and --all for bulk deletion)
    Delete(DeleteArgs),
    /// Manage agent credentials (F110)
    #[command(subcommand)]
    Credentials(CredentialsCommands),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of agents to return
    #[arg(long, default_value = "50")]
    pub limit: i32,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: i32,

    /// Force offline mode (use cached data only)
    #[arg(long)]
    pub offline: bool,

    /// Force refresh from server (bypass cache)
    #[arg(long)]
    pub refresh: bool,
}

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Agent name (alphanumeric, hyphens, underscores, 1-64 chars)
    /// Required for single agent creation, ignored when using --batch
    #[arg(required_unless_present = "batch")]
    pub name: Option<String>,

    /// Agent type: copilot, autonomous, workflow, orchestrator
    #[arg(long, short = 't')]
    pub r#type: Option<String>,

    /// AI model provider (e.g., anthropic, openai)
    #[arg(long)]
    pub model_provider: Option<String>,

    /// AI model name (e.g., claude-sonnet-4, gpt-4)
    #[arg(long)]
    pub model_name: Option<String>,

    /// Risk level: low, medium, high, critical
    #[arg(long, short = 'r')]
    pub risk_level: Option<String>,

    /// Agent description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    // Batch operation flags
    /// Create multiple agents from a YAML file
    #[arg(long, value_name = "FILE", conflicts_with = "name")]
    pub batch: Option<PathBuf>,

    /// Preview changes without making them (for batch operations)
    #[arg(long)]
    pub dry_run: bool,

    /// Stop on first error during batch operations
    #[arg(long)]
    pub stop_on_error: bool,
}

/// Arguments for the get command
#[derive(Args, Debug)]
pub struct GetArgs {
    /// Agent ID (UUID)
    pub id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the update command
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Agent ID (UUID) - required for single agent update
    #[arg(required_unless_present = "batch")]
    pub id: Option<String>,

    /// Risk level: low, medium, high, critical
    #[arg(long, short = 'r')]
    pub risk_level: Option<String>,

    /// Agent description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// AI model provider (e.g., anthropic, openai)
    #[arg(long)]
    pub model_provider: Option<String>,

    /// AI model name (e.g., claude-sonnet-4, gpt-4)
    #[arg(long)]
    pub model_name: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    // Batch operation flags
    /// Update multiple agents from a YAML file
    #[arg(long, value_name = "FILE", conflicts_with = "id")]
    pub batch: Option<PathBuf>,

    /// Preview changes without making them
    #[arg(long)]
    pub dry_run: bool,

    /// Stop on first error during batch operations
    #[arg(long)]
    pub stop_on_error: bool,
}

/// Arguments for the delete command
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Agent ID (UUID) - required for single agent deletion
    #[arg(required_unless_present_any = ["filter", "all"])]
    pub id: Option<String>,

    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,

    // Batch delete flags
    /// Delete agents matching a filter (e.g., "name=test-*")
    #[arg(long, value_name = "FILTER", conflicts_with_all = ["id", "all"])]
    pub filter: Option<String>,

    /// Delete ALL agents in the tenant (requires confirmation)
    #[arg(long, conflicts_with_all = ["id", "filter"])]
    pub all: bool,

    /// Preview deletion without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Output results as JSON
    #[arg(long)]
    pub json: bool,

    /// Stop on first error during batch delete
    #[arg(long)]
    pub stop_on_error: bool,
}

// =============================================================================
// Credential Commands (F110)
// =============================================================================

/// Subcommands for managing agent credentials
#[derive(Subcommand, Debug)]
pub enum CredentialsCommands {
    /// List credentials for an agent
    List(CredentialsListArgs),
    /// Get details of a specific credential
    Get(CredentialsGetArgs),
    /// Rotate credentials for an agent (generates new secret)
    Rotate(CredentialsRotateArgs),
    /// Revoke a specific credential
    Revoke(CredentialsRevokeArgs),
}

/// Arguments for listing credentials
#[derive(Args, Debug)]
pub struct CredentialsListArgs {
    /// Agent ID (UUID)
    pub agent_id: String,

    /// Only show active credentials
    #[arg(long)]
    pub active_only: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for getting a specific credential
#[derive(Args, Debug)]
pub struct CredentialsGetArgs {
    /// Agent ID (UUID)
    pub agent_id: String,

    /// Credential ID (UUID)
    pub credential_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for rotating credentials
#[derive(Args, Debug)]
pub struct CredentialsRotateArgs {
    /// Agent ID (UUID)
    pub agent_id: String,

    /// Credential type: api_key, secret, certificate
    #[arg(long, short = 't', default_value = "api_key")]
    pub credential_type: String,

    /// Grace period in hours for old credentials (default: 24, max: 168)
    #[arg(long, short = 'g')]
    pub grace_period_hours: Option<i32>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Preview rotation changes without making them
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt (required for non-interactive mode)
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Show detailed operation logging
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

/// Arguments for revoking a credential
#[derive(Args, Debug)]
pub struct CredentialsRevokeArgs {
    /// Agent ID (UUID)
    pub agent_id: String,

    /// Credential ID (UUID)
    pub credential_id: String,

    /// Reason for revocation
    #[arg(long, short = 'r', default_value = "Manual revocation via CLI")]
    pub reason: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
}

/// Execute agent commands
pub async fn execute(args: AgentsArgs) -> CliResult<()> {
    match args.command {
        AgentsCommands::List(list_args) => execute_list(list_args).await,
        AgentsCommands::Create(create_args) => execute_create(create_args).await,
        AgentsCommands::Get(get_args) => execute_get(get_args).await,
        AgentsCommands::Update(update_args) => execute_update(update_args).await,
        AgentsCommands::Delete(delete_args) => execute_delete(delete_args).await,
        AgentsCommands::Credentials(cred_cmd) => execute_credentials(cred_cmd).await,
    }
}

/// Execute credential subcommands
async fn execute_credentials(cmd: CredentialsCommands) -> CliResult<()> {
    match cmd {
        CredentialsCommands::List(args) => execute_credentials_list(args).await,
        CredentialsCommands::Get(args) => execute_credentials_get(args).await,
        CredentialsCommands::Rotate(args) => execute_credentials_rotate(args).await,
        CredentialsCommands::Revoke(args) => execute_credentials_revoke(args).await,
    }
}

/// Execute list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let cache = FileCacheStore::new(&paths)?;

    // Handle forced offline mode
    if args.offline {
        return execute_list_offline(&cache, &args);
    }

    // Try to fetch from API
    let client = ApiClient::new(config, paths.clone())?;
    let result = client.list_agents(args.limit, args.offset).await;

    match result {
        Ok(response) => {
            // Cache the response for offline use
            let ttl = cache.default_ttl();
            if let Err(e) = cache.set(CACHE_KEY_AGENTS, &response, ttl) {
                eprintln!("Warning: Failed to cache agents: {}", e);
            }

            print_agents_output(&response, args.json, false);
            Ok(())
        }
        Err(e) if !args.refresh => {
            // Try to fall back to cache on network errors
            if is_network_error(&e) {
                eprintln!("Network error, attempting to use cached data...");
                match execute_list_offline(&cache, &args) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(e), // Return original error if cache fails
                }
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

/// Execute list command using cached data
fn execute_list_offline(cache: &FileCacheStore, args: &ListArgs) -> CliResult<()> {
    let entry = cache
        .get::<AgentListResponse>(CACHE_KEY_AGENTS)?
        .ok_or_else(|| CliError::NoCacheAvailable("agents".to_string()))?;

    let is_stale = entry.is_expired();
    print_agents_output(&entry.data, args.json, true);

    if is_stale && !args.json {
        eprintln!();
        eprintln!("Warning: Cached data is stale. Run without --offline to refresh.");
    }

    Ok(())
}

/// Print agents output with optional offline indicator
fn print_agents_output(response: &AgentListResponse, json: bool, offline: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_default()
        );
    } else {
        if offline {
            println!("(offline - using cached data)");
            println!();
        }

        if response.agents.is_empty() {
            println!("No agents found.");
            println!();
            println!("Create your first agent with: xavyo agents create <name>");
        } else {
            print_agent_table(&response.agents);
            println!();
            println!(
                "Showing {} of {} agents",
                response.agents.len(),
                response.total
            );
        }
    }
}

/// Check if an error is a network-related error
fn is_network_error(e: &CliError) -> bool {
    matches!(e, CliError::Network(_) | CliError::ConnectionFailed(_))
}

/// Execute create command
async fn execute_create(args: CreateArgs) -> CliResult<()> {
    // Check for batch mode
    if let Some(ref batch_path) = args.batch {
        return execute_batch_create(batch_path.clone(), &args).await;
    }

    // Single agent creation - name is required
    let name = args.name.ok_or_else(|| {
        CliError::Validation("Agent name is required for single agent creation".to_string())
    })?;

    // Validate agent name
    validate_agent_name(&name)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get agent type (interactive or from flag)
    let agent_type = match args.r#type {
        Some(t) => {
            validate_agent_type(&t)?;
            t
        }
        None => prompt_agent_type()?,
    };

    // Get risk level (interactive or from flag)
    let risk_level = match args.risk_level {
        Some(r) => {
            validate_risk_level(&r)?;
            r
        }
        None => prompt_risk_level()?,
    };

    // Get model provider and name (optional, interactive if TTY)
    let (model_provider, model_name) = if args.model_provider.is_some() || args.model_name.is_some()
    {
        (args.model_provider, args.model_name)
    } else if atty::is(atty::Stream::Stdin) {
        prompt_model_info()?
    } else {
        (None, None)
    };

    // Build the request
    let request = CreateAgentRequest::new(name.clone(), agent_type)
        .with_model(model_provider, model_name)
        .with_risk_level(risk_level)
        .with_description(args.description);

    // Create the agent (with improved offline error message)
    let agent = match client.create_agent(request).await {
        Ok(agent) => agent,
        Err(e) if is_network_error(&e) => {
            return Err(CliError::OfflineWriteRejected("create agent".to_string()));
        }
        Err(e) => return Err(e),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        println!("✓ Agent created successfully!");
        println!();
        print_agent_details(&agent);
    }

    Ok(())
}

/// Execute batch create for agents
async fn execute_batch_create(batch_path: PathBuf, args: &CreateArgs) -> CliResult<()> {
    let batch = BatchFile::from_path(&batch_path)?;

    if batch.agents.is_empty() {
        return Err(CliError::Validation(
            "Batch file contains no agent definitions".to_string(),
        ));
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let executor = BatchExecutor::new(client);
    let options = BatchOptions {
        dry_run: args.dry_run,
        stop_on_error: args.stop_on_error,
        force: false,
        json: args.json,
    };

    let result = executor.create_agents(&batch, &options).await?;
    print_batch_summary(&result, args.json);

    if result.has_failures() && !args.json {
        std::process::exit(1);
    }

    Ok(())
}

/// Execute get command
async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_agent_id(&args.id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let agent = client.get_agent(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        print_agent_details(&agent);
    }

    Ok(())
}

/// Execute update command
async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    // Check for batch mode
    if let Some(ref batch_path) = args.batch {
        return execute_batch_update(batch_path.clone(), &args).await;
    }

    // Single agent update - id is required
    let id_str = args.id.as_ref().ok_or_else(|| {
        CliError::Validation("Agent ID is required for single agent update".to_string())
    })?;

    let id = parse_agent_id(id_str)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get existing agent
    let existing = client.get_agent(id).await?;

    // Build update request with changed fields
    let request = CreateAgentRequest::new(existing.name.clone(), existing.agent_type.clone())
        .with_risk_level(args.risk_level.unwrap_or(existing.risk_level.clone()))
        .with_model(
            args.model_provider.or(existing.model_provider.clone()),
            args.model_name.or(existing.model_name.clone()),
        )
        .with_description(args.description.or(existing.description.clone()));

    // Update the agent
    let agent = match client.update_agent(id, request).await {
        Ok(agent) => agent,
        Err(e) if is_network_error(&e) => {
            return Err(CliError::OfflineWriteRejected("update agent".to_string()));
        }
        Err(e) => return Err(e),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        println!("✓ Agent updated successfully!");
        println!();
        print_agent_details(&agent);
    }

    Ok(())
}

/// Execute batch update for agents
async fn execute_batch_update(batch_path: PathBuf, args: &UpdateArgs) -> CliResult<()> {
    let batch = BatchFile::from_path(&batch_path)?;

    if batch.agents.is_empty() {
        return Err(CliError::Validation(
            "Batch file contains no agent definitions".to_string(),
        ));
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let executor = BatchExecutor::new(client);
    let options = BatchOptions {
        dry_run: args.dry_run,
        stop_on_error: args.stop_on_error,
        force: false,
        json: args.json,
    };

    let result = executor.update_agents(&batch, &options).await?;
    print_batch_summary(&result, args.json);

    if result.has_failures() && !args.json {
        std::process::exit(1);
    }

    Ok(())
}

/// Execute delete command
async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    // Check for batch delete modes
    if args.all {
        return execute_delete_all(&args).await;
    }

    if let Some(ref filter_str) = args.filter {
        return execute_delete_by_filter(filter_str, &args).await;
    }

    // Single agent deletion - id is required
    let id_str = args.id.as_ref().ok_or_else(|| {
        CliError::Validation(
            "Agent ID is required. Use --filter or --all for batch deletion.".to_string(),
        )
    })?;

    let id = parse_agent_id(id_str)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get agent details for confirmation message
    let agent = client.get_agent(id).await?;

    // Confirm deletion unless --force is used
    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!(
                "Delete agent '{}'? This action cannot be undone.",
                agent.name
            ))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Delete the agent (with improved offline error message)
    match client.delete_agent(id).await {
        Ok(()) => {}
        Err(e) if is_network_error(&e) => {
            return Err(CliError::OfflineWriteRejected("delete agent".to_string()));
        }
        Err(e) => return Err(e),
    }

    println!("✓ Agent deleted: {}", agent.name);

    Ok(())
}

/// Execute delete by filter for agents
async fn execute_delete_by_filter(filter_str: &str, args: &DeleteArgs) -> CliResult<()> {
    let filter = Filter::parse(filter_str)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let executor = BatchExecutor::new(client);
    let options = BatchOptions {
        dry_run: args.dry_run,
        stop_on_error: args.stop_on_error,
        force: args.force,
        json: args.json,
    };

    let result = executor.delete_agents_by_filter(&filter, &options).await?;
    print_batch_summary(&result, args.json);

    if result.has_failures() && !args.json {
        std::process::exit(1);
    }

    Ok(())
}

/// Execute delete all agents
async fn execute_delete_all(args: &DeleteArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let executor = BatchExecutor::new(client);
    let options = BatchOptions {
        dry_run: args.dry_run,
        stop_on_error: args.stop_on_error,
        force: args.force,
        json: args.json,
    };

    let result = executor.delete_all_agents(&options).await?;

    if !args.dry_run && result.success_count > 0 {
        if args.json {
            print_batch_summary(&result, true);
        } else {
            println!();
            println!("✓ All agents deleted!");
        }
    }

    Ok(())
}

// =============================================================================
// Credential Command Implementations (F110)
// =============================================================================

/// Execute credentials list command
async fn execute_credentials_list(args: CredentialsListArgs) -> CliResult<()> {
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
        println!("No credentials found for agent {}.", agent_id);
        println!();
        println!(
            "Generate credentials with: xavyo agents credentials rotate {}",
            agent_id
        );
    } else {
        print_credentials_table(&response.items);
        println!();
        println!("Showing {} credential(s)", response.items.len());
    }

    Ok(())
}

/// Execute credentials get command
async fn execute_credentials_get(args: CredentialsGetArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;
    let credential_id = parse_credential_id(&args.credential_id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let credential = client.get_agent_credential(agent_id, credential_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&credential)?);
    } else {
        print_credential_details(&credential);
    }

    Ok(())
}

/// Execute credentials rotate command with UX improvements (C-007)
async fn execute_credentials_rotate(args: CredentialsRotateArgs) -> CliResult<()> {
    let start_time = Instant::now();
    let agent_id = parse_agent_id(&args.agent_id)?;

    // Validate credential type
    validate_credential_type(&args.credential_type)?;

    // Validate grace period early
    let grace_period_hours = args.grace_period_hours.unwrap_or(24);
    if !(0..=168).contains(&grace_period_hours) {
        return Err(CliError::Validation(
            "Grace period must be between 0 and 168 hours (1 week).".to_string(),
        ));
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // FR-006: Validate agent exists before starting rotation
    let agent = match client.get_agent(agent_id).await {
        Ok(agent) => agent,
        Err(CliError::NotFound(_)) => {
            return Err(CliError::NotFound(format!("Agent not found: {}", agent_id)));
        }
        Err(e) => {
            return Err(handle_rotation_error(e, &[], args.verbose));
        }
    };

    // Get current credentials for dry-run preview and rollback info
    let current_credentials = client
        .list_agent_credentials(agent_id, true)
        .await
        .unwrap_or_else(|_| crate::models::agent::NhiCredentialListResponse {
            items: vec![],
            total: 0,
        });

    // Calculate grace period end time
    let grace_period_ends_at = if grace_period_hours > 0 {
        Some(Utc::now() + Duration::hours(grace_period_hours as i64))
    } else {
        None
    };

    // FR-001: Handle --dry-run flag
    if args.dry_run {
        return execute_dry_run_preview(
            &agent,
            &args.credential_type,
            grace_period_hours,
            grace_period_ends_at,
            &current_credentials.items,
            args.json,
            args.verbose,
        );
    }

    // FR-008: Warn users when grace period is set to 0 hours
    if grace_period_hours == 0 && !args.yes {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Grace period of 0 hours requires --yes flag in non-interactive mode. Old credentials will be immediately invalidated.".to_string(),
            ));
        }

        println!();
        println!("⚠️  Warning: Grace period is set to 0 hours.");
        println!("    Old credentials will be immediately invalidated.");
        println!("    Running services may lose access.");
        println!();

        let confirm = Confirm::new()
            .with_prompt("Proceed anyway?")
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // FR-002: Confirmation prompt before rotation
    if !args.yes {
        // Check for non-interactive mode
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm rotation in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        // Show what will happen
        println!();
        println!("Rotate credentials for agent '{}'?", agent.name);
        println!();
        println!("⚠️  This will:");
        println!("  - Create a new {} credential", args.credential_type);
        if !current_credentials.items.is_empty() {
            println!(
                "  - Deprecate existing credentials ({}h grace period)",
                grace_period_hours
            );
            if grace_period_hours > 0 {
                println!("  - Old credentials will stop working after grace period");
            } else {
                println!("  - Old credentials will be immediately invalidated");
            }
        }
        println!();

        let confirm = Confirm::new()
            .with_prompt("Proceed with rotation?")
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // FR-003: Progress indicators during rotation
    let spinner = if !args.json {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .expect("Invalid progress bar template"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Step 1: Validating agent
    if let Some(ref pb) = spinner {
        pb.set_message("Validating agent...");
    }
    if args.verbose && !args.json {
        println!("  GET /nhi/agents/{} -> 200 OK", agent_id);
    }

    // Step 2: Generating new credentials
    if let Some(ref pb) = spinner {
        pb.set_message("Generating new credentials...");
    }

    // Build the request
    let mut request = RotateCredentialsRequest::new(&args.credential_type);
    if let Some(hours) = args.grace_period_hours {
        request = request.with_grace_period(hours);
    }

    if args.verbose && !args.json {
        println!("  Request: {:?}", request);
    }

    // Step 3: Attempt rotation with error handling (FR-004)
    if let Some(ref pb) = spinner {
        pb.set_message("Storing credentials...");
    }

    let response = match client.rotate_agent_credentials(agent_id, request).await {
        Ok(response) => response,
        Err(e) => {
            if let Some(pb) = spinner {
                pb.finish_and_clear();
            }
            // FR-004, FR-005: Display error with existing credentials info
            return Err(handle_rotation_error(
                e,
                &current_credentials.items,
                args.verbose,
            ));
        }
    };

    // Step 4: Complete
    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    let elapsed = start_time.elapsed();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        // FR-003: Success message
        println!("✓ Credentials rotated successfully!");
        println!();
        println!("{}", "━".repeat(60));
        println!("⚠️  IMPORTANT: Save this secret now! It cannot be retrieved later.");
        println!("{}", "━".repeat(60));
        println!();
        println!("Credential ID: {}", response.credential.id);
        println!("Type:          {}", response.credential.credential_type);
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
        println!(
            "Days Until Expiry: {}",
            response.credential.days_until_expiry
        );

        // FR-007: Show grace period timeline
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

        // FR-009: Timing information
        println!();
        println!("Operation completed in {:.2}s", elapsed.as_secs_f64());

        // FR-010: Verbose output
        if args.verbose {
            println!();
            println!("Verbose Details:");
            println!("  Agent ID: {}", agent_id);
            println!("  Agent Name: {}", agent.name);
            println!("  Credential Type: {}", args.credential_type);
            println!("  Grace Period: {} hours", grace_period_hours);
            println!(
                "  Previous Credentials: {}",
                current_credentials.items.len()
            );
        }
    }

    Ok(())
}

/// Execute dry-run preview for credential rotation (FR-001)
fn execute_dry_run_preview(
    agent: &AgentResponse,
    credential_type: &str,
    grace_period_hours: i32,
    grace_period_ends_at: Option<chrono::DateTime<Utc>>,
    current_credentials: &[NhiCredentialResponse],
    json: bool,
    verbose: bool,
) -> CliResult<()> {
    if json {
        let preview = DryRunRotationPreview {
            dry_run: true,
            agent_id: agent.id,
            agent_name: agent.name.clone(),
            credential_type: credential_type.to_string(),
            grace_period_hours,
            current_credentials: current_credentials.to_vec(),
            planned_changes: crate::models::agent::PlannedRotationChanges {
                action: "rotate".to_string(),
                new_credential_type: credential_type.to_string(),
                grace_period_ends_at,
                old_credentials_will_expire: !current_credentials.is_empty(),
            },
        };
        println!("{}", serde_json::to_string_pretty(&preview)?);
    } else {
        println!();
        println!("Rotation Preview (dry-run - no changes will be made)");
        println!("{}", "━".repeat(55));
        println!();
        println!("Agent: {} ({})", agent.name, agent.id);
        println!();

        if current_credentials.is_empty() {
            println!("Current credentials: None");
            println!();
            println!("After rotation:");
            println!("  New {} credential will be created", credential_type);
            println!("  Valid for: 365 days");
        } else {
            println!("Current credentials:");
            for cred in current_credentials {
                println!("  ID:          {}", cred.id);
                println!("  Type:        {}", cred.credential_type);
                println!(
                    "  Valid until: {}",
                    cred.valid_until.format("%Y-%m-%dT%H:%M:%SZ")
                );
                println!();
            }

            println!("After rotation:");
            println!("  New credential will be created");
            if grace_period_hours > 0 {
                println!(
                    "  Old credential enters {}-hour grace period",
                    grace_period_hours
                );
                if let Some(grace_ends) = grace_period_ends_at {
                    println!(
                        "  Old credential invalid after: {}",
                        grace_ends.format("%Y-%m-%dT%H:%M:%SZ")
                    );
                }
            } else {
                println!("  Old credentials immediately invalidated (grace period = 0)");
            }
        }

        println!();
        println!("No changes were made.");

        if verbose {
            println!();
            println!("Verbose Details:");
            println!("  Credential Type: {}", credential_type);
            println!("  Grace Period: {} hours", grace_period_hours);
        }
    }

    Ok(())
}

/// Handle rotation errors with informational rollback (FR-004, FR-005)
fn handle_rotation_error(
    error: CliError,
    current_credentials: &[NhiCredentialResponse],
    verbose: bool,
) -> CliError {
    // Print error message
    eprintln!();
    eprintln!("❌ Rotation failed: {}", error);
    eprintln!();

    // Show existing credentials are still valid
    if !current_credentials.is_empty() {
        eprintln!("Your existing credentials are still valid:");
        for cred in current_credentials {
            eprintln!(
                "  - {} ({}, valid until {})",
                cred.id,
                cred.credential_type,
                cred.valid_until.format("%Y-%m-%d")
            );
        }
        eprintln!();
    }

    // Provide recovery instructions based on error type
    match &error {
        CliError::Api { status, .. } => match *status {
            401 => {
                eprintln!("Please re-authenticate with: xavyo login");
                eprintln!("Then retry the rotation.");
            }
            403 => {
                eprintln!("You don't have permission to rotate credentials for this agent.");
                eprintln!("Contact your administrator for access.");
            }
            404 => {
                eprintln!("The agent or credential was not found.");
                eprintln!("Verify the agent ID and try again.");
            }
            409 => {
                eprintln!("A rotation is already in progress for this agent.");
                eprintln!("Please wait for the current rotation to complete and try again.");
            }
            429 => {
                eprintln!("Rate limit exceeded. Please wait a moment and try again.");
            }
            500..=599 => {
                eprintln!("Server error occurred. Please try again later.");
                eprintln!("If the problem persists, contact support.");
            }
            _ => {
                eprintln!("To retry, run the command again.");
            }
        },
        CliError::Network(_) => {
            eprintln!("Tip: Check your network connection and try again.");
        }
        _ => {
            eprintln!("To retry, run the command again.");
        }
    }

    if verbose {
        eprintln!();
        eprintln!("Error details: {:?}", error);
    }

    error
}

/// Execute credentials revoke command
async fn execute_credentials_revoke(args: CredentialsRevokeArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;
    let credential_id = parse_credential_id(&args.credential_id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Confirm revocation unless --force is used
    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm revocation in non-interactive mode. Use --force to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!(
                "Revoke credential {}? This action cannot be undone.",
                credential_id
            ))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Build the request
    let request = RevokeCredentialRequest::new(&args.reason);

    // Revoke the credential
    let response = client
        .revoke_agent_credential(agent_id, credential_id, request)
        .await?;

    println!("✓ Credential revoked successfully!");
    println!();
    println!("Credential ID: {}", response.id);
    println!(
        "Status:        {}",
        if response.is_active {
            "Active"
        } else {
            "Revoked"
        }
    );

    Ok(())
}

/// Validate credential type
fn validate_credential_type(cred_type: &str) -> CliResult<()> {
    match cred_type {
        "api_key" | "secret" | "certificate" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid credential type '{}'. Must be one of: api_key, secret, certificate",
            cred_type
        ))),
    }
}

/// Parse credential ID from string
fn parse_credential_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid credential ID '{}'. Must be a valid UUID.",
            id_str
        ))
    })
}

/// Print credentials list as a table
fn print_credentials_table(credentials: &[NhiCredentialResponse]) {
    // Print header
    println!(
        "{:<38} {:<12} {:<8} {:<22} {:<6}",
        "ID", "TYPE", "ACTIVE", "VALID UNTIL", "DAYS"
    );
    println!("{}", "-".repeat(90));

    // Print each credential
    for cred in credentials {
        let status = if cred.is_active { "Yes" } else { "No" };
        let valid_until = cred.valid_until.format("%Y-%m-%d %H:%M UTC").to_string();

        println!(
            "{:<38} {:<12} {:<8} {:<22} {:<6}",
            cred.id, cred.credential_type, status, valid_until, cred.days_until_expiry
        );
    }
}

/// Print detailed credential information
fn print_credential_details(cred: &NhiCredentialResponse) {
    println!("Credential Details");
    println!("{}", "━".repeat(50));
    println!("ID:                {}", cred.id);
    println!("NHI ID:            {}", cred.nhi_id);
    println!("Type:              {}", cred.credential_type);
    println!(
        "Status:            {}",
        if cred.is_active { "Active" } else { "Revoked" }
    );
    println!(
        "Valid From:        {}",
        cred.valid_from.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Valid Until:       {}",
        cred.valid_until.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("Days Until Expiry: {}", cred.days_until_expiry);
    println!(
        "Created At:        {}",
        cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

/// Validate agent name according to spec
fn validate_agent_name(name: &str) -> CliResult<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(CliError::Validation(
            "Agent name must be 1-64 characters.".to_string(),
        ));
    }

    // Must start with alphanumeric
    let first_char = name.chars().next().unwrap();
    if !first_char.is_alphanumeric() {
        return Err(CliError::Validation(
            "Agent name must start with a letter or number.".to_string(),
        ));
    }

    // Only alphanumeric, hyphens, and underscores allowed
    for ch in name.chars() {
        if !ch.is_alphanumeric() && ch != '-' && ch != '_' {
            return Err(CliError::Validation(
                "Invalid agent name. Use alphanumeric characters, hyphens, and underscores only."
                    .to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate agent type
fn validate_agent_type(agent_type: &str) -> CliResult<()> {
    match agent_type {
        "copilot" | "autonomous" | "workflow" | "orchestrator" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid agent type '{}'. Must be one of: copilot, autonomous, workflow, orchestrator",
            agent_type
        ))),
    }
}

/// Validate risk level
fn validate_risk_level(risk_level: &str) -> CliResult<()> {
    match risk_level {
        "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid risk level '{}'. Must be one of: low, medium, high, critical",
            risk_level
        ))),
    }
}

/// Parse agent ID from string
fn parse_agent_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid agent ID '{}'. Must be a valid UUID.",
            id_str
        ))
    })
}

/// Interactive prompt for agent type
fn prompt_agent_type() -> CliResult<String> {
    let types = vec![
        "copilot (human-assisted)",
        "autonomous (independent)",
        "workflow (task automation)",
        "orchestrator (multi-agent)",
    ];

    let selection = Select::new()
        .with_prompt("Select agent type")
        .items(&types)
        .default(0)
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))?;

    let agent_type = match selection {
        0 => "copilot",
        1 => "autonomous",
        2 => "workflow",
        3 => "orchestrator",
        _ => "copilot",
    };

    Ok(agent_type.to_string())
}

/// Interactive prompt for risk level
fn prompt_risk_level() -> CliResult<String> {
    let levels = vec!["low", "medium", "high", "critical"];

    let selection = Select::new()
        .with_prompt("Select risk level")
        .items(&levels)
        .default(1) // Default to "medium"
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))?;

    Ok(levels[selection].to_string())
}

/// Interactive prompt for model provider and name
fn prompt_model_info() -> CliResult<(Option<String>, Option<String>)> {
    let provider: String = Input::new()
        .with_prompt("Enter model provider (optional, press Enter to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| CliError::Io(e.to_string()))?;

    let provider = if provider.is_empty() {
        None
    } else {
        Some(provider)
    };

    let model_name: String = Input::new()
        .with_prompt("Enter model name (optional, press Enter to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| CliError::Io(e.to_string()))?;

    let model_name = if model_name.is_empty() {
        None
    } else {
        Some(model_name)
    };

    Ok((provider, model_name))
}

/// Print agent list as a table
fn print_agent_table(agents: &[AgentResponse]) {
    // Print header
    println!(
        "{:<38} {:<20} {:<12} {:<10} {:<8}",
        "ID", "NAME", "TYPE", "STATUS", "RISK"
    );
    println!("{}", "-".repeat(90));

    // Print each agent
    for agent in agents {
        let truncated_name = if agent.name.len() > 18 {
            format!("{}...", &agent.name[..15])
        } else {
            agent.name.clone()
        };

        println!(
            "{:<38} {:<20} {:<12} {:<10} {:<8}",
            agent.id, truncated_name, agent.agent_type, agent.status, agent.risk_level
        );
    }
}

/// Print detailed agent information
fn print_agent_details(agent: &AgentResponse) {
    println!("Agent: {}", agent.name);
    println!("{}", "━".repeat(45));
    println!("ID:          {}", agent.id);
    println!("Type:        {}", agent.agent_type);
    println!("Status:      {}", agent.status);
    println!("Risk Level:  {}", agent.risk_level);

    if let Some(ref desc) = agent.description {
        println!("Description: {}", desc);
    }

    if let (Some(ref provider), Some(ref model)) = (&agent.model_provider, &agent.model_name) {
        println!("Model:       {}/{}", provider, model);
    } else if let Some(ref provider) = agent.model_provider {
        println!("Model:       {}", provider);
    } else if let Some(ref model) = agent.model_name {
        println!("Model:       {}", model);
    }

    println!(
        "HITL:        {}",
        if agent.requires_human_approval {
            "Required"
        } else {
            "Not required"
        }
    );
    println!(
        "Created:     {}",
        agent.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Updated:     {}",
        agent.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_agent_name_valid() {
        assert!(validate_agent_name("my-bot").is_ok());
        assert!(validate_agent_name("MyBot123").is_ok());
        assert!(validate_agent_name("bot_1").is_ok());
        assert!(validate_agent_name("a").is_ok());
        assert!(validate_agent_name("1bot").is_ok());
    }

    #[test]
    fn test_validate_agent_name_invalid() {
        assert!(validate_agent_name("").is_err());
        assert!(validate_agent_name("-bot").is_err()); // Starts with hyphen
        assert!(validate_agent_name("_bot").is_err()); // Starts with underscore
        assert!(validate_agent_name("my bot").is_err()); // Contains space
        assert!(validate_agent_name("my.bot").is_err()); // Contains period
        assert!(validate_agent_name("my@bot").is_err()); // Contains @

        // Too long (> 64 chars)
        let long_name = "a".repeat(65);
        assert!(validate_agent_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_agent_type() {
        assert!(validate_agent_type("copilot").is_ok());
        assert!(validate_agent_type("autonomous").is_ok());
        assert!(validate_agent_type("workflow").is_ok());
        assert!(validate_agent_type("orchestrator").is_ok());
        assert!(validate_agent_type("invalid").is_err());
        assert!(validate_agent_type("COPILOT").is_err()); // Case sensitive
    }

    #[test]
    fn test_validate_risk_level() {
        assert!(validate_risk_level("low").is_ok());
        assert!(validate_risk_level("medium").is_ok());
        assert!(validate_risk_level("high").is_ok());
        assert!(validate_risk_level("critical").is_ok());
        assert!(validate_risk_level("invalid").is_err());
        assert!(validate_risk_level("LOW").is_err()); // Case sensitive
    }

    #[test]
    fn test_parse_agent_id() {
        let valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_agent_id(valid_uuid).is_ok());

        let invalid_uuid = "not-a-uuid";
        assert!(parse_agent_id(invalid_uuid).is_err());
    }

    // F110: Credential command tests

    #[test]
    fn test_validate_credential_type() {
        assert!(validate_credential_type("api_key").is_ok());
        assert!(validate_credential_type("secret").is_ok());
        assert!(validate_credential_type("certificate").is_ok());
        assert!(validate_credential_type("invalid").is_err());
        assert!(validate_credential_type("API_KEY").is_err()); // Case sensitive
    }

    #[test]
    fn test_parse_credential_id() {
        let valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_credential_id(valid_uuid).is_ok());

        let invalid_uuid = "not-a-uuid";
        assert!(parse_credential_id(invalid_uuid).is_err());

        let empty = "";
        assert!(parse_credential_id(empty).is_err());
    }
}
