//! Agent management CLI commands

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::agent::{
    AgentResponse, CreateAgentRequest, NhiCredentialResponse, RevokeCredentialRequest,
    RotateCredentialsRequest,
};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Select};
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
    /// Create a new AI agent
    Create(CreateArgs),
    /// Get details of a specific agent
    Get(GetArgs),
    /// Delete an AI agent
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
}

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Agent name (alphanumeric, hyphens, underscores, 1-64 chars)
    pub name: String,

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

/// Arguments for the delete command
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Agent ID (UUID)
    pub id: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
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
    let client = ApiClient::new(config, paths)?;

    let response = client.list_agents(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.agents.is_empty() {
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

    Ok(())
}

/// Execute create command
async fn execute_create(args: CreateArgs) -> CliResult<()> {
    // Validate agent name
    validate_agent_name(&args.name)?;

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
    let request = CreateAgentRequest::new(args.name.clone(), agent_type)
        .with_model(model_provider, model_name)
        .with_risk_level(risk_level)
        .with_description(args.description);

    // Create the agent
    let agent = client.create_agent(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        println!("✓ Agent created successfully!");
        println!();
        print_agent_details(&agent);
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

/// Execute delete command
async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_agent_id(&args.id)?;

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

    // Delete the agent
    client.delete_agent(id).await?;

    println!("✓ Agent deleted: {}", agent.name);

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

/// Execute credentials rotate command
async fn execute_credentials_rotate(args: CredentialsRotateArgs) -> CliResult<()> {
    let agent_id = parse_agent_id(&args.agent_id)?;

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

    Ok(())
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
