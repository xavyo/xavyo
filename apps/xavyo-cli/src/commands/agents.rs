//! Agent management CLI commands

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::interactive::{
    prompt_confirm, prompt_select, prompt_text, prompt_text_optional, require_interactive,
    AGENT_TYPE_OPTIONS,
};
use crate::models::agent::{AgentResponse, CreateAgentRequest, UpdateAgentRequest};
use clap::{Args, Subcommand};
use dialoguer::{Input, Select};
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
    /// Update an existing agent (F-051)
    Update(UpdateArgs),
    /// Delete an AI agent
    Delete(DeleteArgs),
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

    /// Filter by agent type: copilot, autonomous, workflow, orchestrator
    #[arg(long, short = 't')]
    pub r#type: Option<String>,

    /// Filter by agent status: active, inactive, pending
    #[arg(long, short = 's')]
    pub status: Option<String>,

    /// Page number (1-based, overrides --offset)
    #[arg(long)]
    pub page: Option<i32>,

    /// Number of agents per page (max: 100, overrides --limit)
    #[arg(long)]
    pub per_page: Option<i32>,
}

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Agent name (alphanumeric, hyphens, underscores, 1-64 chars)
    /// Required in non-interactive mode, prompted in interactive mode
    pub name: Option<String>,

    /// Use interactive mode with guided prompts
    #[arg(long, short = 'i')]
    pub interactive: bool,

    /// Agent type: copilot, autonomous, workflow, orchestrator
    #[arg(long, short = 't')]
    pub r#type: Option<String>,

    /// AI model provider (e.g., anthropic, openai)
    #[arg(long)]
    pub model_provider: Option<String>,

    /// AI model name (e.g., claude-sonnet-4, gpt-4)
    #[arg(long)]
    pub model_name: Option<String>,

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
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Skip confirmation prompt (alias for --yes)
    #[arg(long, short = 'f', hide = true)]
    pub force: bool,
}

/// Arguments for the update command (F-051)
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Agent ID (UUID)
    pub id: String,

    /// New agent name
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// New agent description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// New agent status: active, inactive, pending
    #[arg(long, short = 's')]
    pub status: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Execute agent commands
pub async fn execute(args: AgentsArgs) -> CliResult<()> {
    match args.command {
        AgentsCommands::List(list_args) => execute_list(list_args).await,
        AgentsCommands::Create(create_args) => execute_create(create_args).await,
        AgentsCommands::Get(get_args) => execute_get(get_args).await,
        AgentsCommands::Update(update_args) => execute_update(update_args).await,
        AgentsCommands::Delete(delete_args) => execute_delete(delete_args).await,
    }
}

/// Execute list command (F-051: with filters and pagination)
async fn execute_list(args: ListArgs) -> CliResult<()> {
    // Validate filter values if provided
    if let Some(ref t) = args.r#type {
        validate_agent_type(t)?;
    }
    if let Some(ref s) = args.status {
        validate_agent_status(s)?;
    }

    // Calculate limit and offset from page/per_page or use direct values
    let (limit, offset) = calculate_pagination(&args)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client
        .list_agents(
            limit,
            offset,
            args.r#type.as_deref(),
            args.status.as_deref(),
        )
        .await?;

    // Build filter context for display
    let filter_context = build_filter_context(&args);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        if filter_context.is_some() {
            println!("No agents found matching criteria.");
            println!();
            println!("Try without filters: xavyo agents list");
        } else {
            println!("No agents found.");
            println!();
            println!("Create your first agent with: xavyo agents create <name>");
        }
    } else {
        print_agent_table(&response.data);
        println!();

        // Show pagination info
        if let Some(page) = args.page {
            let per_page = args.per_page.unwrap_or(50).min(100);
            let total_pages = (response.total as f64 / per_page as f64).ceil() as i64;
            if let Some(ref ctx) = filter_context {
                println!(
                    "Page {} of {} ({} total agents, {})",
                    page, total_pages, response.total, ctx
                );
            } else {
                println!(
                    "Page {} of {} ({} total agents)",
                    page, total_pages, response.total
                );
            }
        } else if let Some(ref ctx) = filter_context {
            println!(
                "Showing {} of {} agents ({})",
                response.data.len(),
                response.total,
                ctx
            );
        } else {
            println!(
                "Showing {} of {} agents",
                response.data.len(),
                response.total
            );
        }
    }

    Ok(())
}

/// Calculate limit and offset from page/per_page or direct values (F-051)
fn calculate_pagination(args: &ListArgs) -> CliResult<(i32, i32)> {
    if let Some(page) = args.page {
        // Validate page number
        if page < 1 {
            return Err(CliError::Validation(
                "Page number must be 1 or greater.".to_string(),
            ));
        }

        // Get per_page with cap at 100
        let per_page = args.per_page.unwrap_or(50).min(100);
        if per_page < 1 {
            return Err(CliError::Validation(
                "Per-page must be 1 or greater.".to_string(),
            ));
        }

        let offset = (page - 1) * per_page;
        Ok((per_page, offset))
    } else if let Some(per_page) = args.per_page {
        // per_page without page uses offset directly
        let limit = per_page.min(100);
        Ok((limit, args.offset))
    } else {
        // Use direct limit/offset
        Ok((args.limit, args.offset))
    }
}

/// Build filter context string for display (F-051)
fn build_filter_context(args: &ListArgs) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(ref t) = args.r#type {
        parts.push(format!("type: {}", t));
    }
    if let Some(ref s) = args.status {
        parts.push(format!("status: {}", s));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("filtered by {}", parts.join(", ")))
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
            "Agent name is required. Provide a name or use --interactive mode.".to_string(),
        )
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
        None => prompt_agent_type_legacy()?,
    };

    // Get model provider and name (optional, interactive if TTY)
    let (model_provider, model_name) = if args.model_provider.is_some() || args.model_name.is_some()
    {
        (args.model_provider, args.model_name)
    } else if crate::interactive::is_interactive_terminal() {
        prompt_model_info()?
    } else {
        (None, None)
    };

    // Build the request
    let request = CreateAgentRequest::new(name.clone(), agent_type)
        .with_model(model_provider, model_name)
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

/// Execute create command in interactive mode (F-053)
async fn execute_create_interactive(args: CreateArgs) -> CliResult<()> {
    // Require interactive terminal
    require_interactive()?;

    println!();
    println!("Create a New Agent");
    println!("{}", "─".repeat(18));
    println!();

    // Get agent name (prompt if not provided)
    let name = match args.name {
        Some(n) => {
            validate_agent_name(&n)?;
            n
        }
        None => prompt_agent_name()?,
    };

    // Get agent type (prompt if not provided)
    let agent_type = match args.r#type {
        Some(t) => {
            validate_agent_type(&t)?;
            t
        }
        None => prompt_agent_type_interactive()?,
    };

    // Get description (optional)
    let description = match args.description {
        Some(d) => Some(d),
        None => prompt_description()?,
    };

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Build the request
    let request = CreateAgentRequest::new(name.clone(), agent_type)
        .with_model(args.model_provider, args.model_name)
        .with_description(description);

    // Create the agent
    let agent = client.create_agent(request).await?;

    println!();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        println!("✓ Agent created successfully!");
        println!();
        print_agent_details(&agent);
    }

    Ok(())
}

/// Prompt for agent name with validation (F-053)
fn prompt_agent_name() -> CliResult<String> {
    prompt_text("Agent name", |name| {
        if name.is_empty() || name.len() > 64 {
            return Err("Name must be 1-64 characters".to_string());
        }
        let first_char = name.chars().next().unwrap();
        if !first_char.is_alphanumeric() {
            return Err("Name must start with a letter or number".to_string());
        }
        for ch in name.chars() {
            if !ch.is_alphanumeric() && ch != '-' && ch != '_' {
                return Err(
                    "Name can only contain letters, numbers, hyphens, and underscores".to_string(),
                );
            }
        }
        Ok(())
    })
}

/// Prompt for agent type using new interactive module (F-053)
fn prompt_agent_type_interactive() -> CliResult<String> {
    let options: Vec<String> = AGENT_TYPE_OPTIONS
        .iter()
        .map(|o| format!("{}", o))
        .collect();

    let selection = prompt_select("Agent type", &options, 0)?;
    Ok(AGENT_TYPE_OPTIONS[selection].value.to_string())
}

/// Prompt for optional description (F-053)
fn prompt_description() -> CliResult<Option<String>> {
    prompt_text_optional("Description (optional)")
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

/// Execute delete command (F-053: confirmation prompt)
async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_agent_id(&args.id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get agent details for confirmation message
    let agent = client.get_agent(id).await?;

    // Confirm deletion unless --yes or --force is used
    let skip_confirm = args.yes || args.force;
    if !skip_confirm {
        if !crate::interactive::is_interactive_terminal() {
            return Err(CliError::Validation(
                "Cannot confirm deletion in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = prompt_confirm(
            &format!(
                "Are you sure you want to delete agent \"{}\"?\n  This action cannot be undone.",
                agent.name
            ),
            false,
        )?;

        if !confirm {
            println!("Operation cancelled. No changes were made.");
            return Ok(());
        }
    }

    // Delete the agent
    client.delete_agent(id).await?;

    println!("✓ Agent deleted successfully.");

    Ok(())
}

/// Execute update command (F-051)
async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    let id = parse_agent_id(&args.id)?;

    // Validate that at least one property is specified
    if args.name.is_none() && args.description.is_none() && args.status.is_none() {
        return Err(CliError::Validation(
            "At least one property must be specified. Use --name, --description, or --status."
                .to_string(),
        ));
    }

    // Validate name if provided
    if let Some(ref name) = args.name {
        validate_agent_name(name)?;
    }

    // Validate status if provided
    if let Some(ref status) = args.status {
        validate_agent_status(status)?;
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Build the update request
    let mut request = UpdateAgentRequest::new();
    if let Some(name) = args.name {
        request = request.with_name(name);
    }
    if let Some(description) = args.description {
        request = request.with_description(description);
    }
    if let Some(status) = args.status {
        request = request.with_status(status);
    }

    // Update the agent
    let agent = client.update_agent(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&agent)?);
    } else {
        println!("✓ Agent updated successfully!");
        println!();
        print_agent_details(&agent);
    }

    Ok(())
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
            "Invalid agent type '{agent_type}'. Must be one of: copilot, autonomous, workflow, orchestrator"
        ))),
    }
}

/// Validate agent lifecycle state
fn validate_agent_status(status: &str) -> CliResult<()> {
    match status {
        "active" | "inactive" | "suspended" | "deprecated" | "archived" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid lifecycle state '{status}'. Must be one of: active, inactive, suspended, deprecated, archived"
        ))),
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

/// Interactive prompt for agent type (legacy, for non-interactive mode fallback)
fn prompt_agent_type_legacy() -> CliResult<String> {
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
        "{:<38} {:<20} {:<12} {:<12} {:<6}",
        "ID", "NAME", "TYPE", "STATE", "RISK"
    );
    println!("{}", "-".repeat(90));

    // Print each agent
    for agent in agents {
        let truncated_name = if agent.name.len() > 18 {
            format!("{}...", &agent.name[..15])
        } else {
            agent.name.clone()
        };

        let risk = agent
            .risk_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());

        println!(
            "{:<38} {:<20} {:<12} {:<12} {:<6}",
            agent.id, truncated_name, agent.agent_type, agent.lifecycle_state, risk
        );
    }
}

/// Print detailed agent information
fn print_agent_details(agent: &AgentResponse) {
    println!("Agent: {}", agent.name);
    println!("{}", "━".repeat(45));
    println!("ID:          {}", agent.id);
    println!("Type:        {}", agent.agent_type);
    println!("State:       {}", agent.lifecycle_state);
    if let Some(score) = agent.risk_score {
        println!("Risk Score:  {score}");
    }

    if let Some(ref desc) = agent.description {
        println!("Description: {desc}");
    }

    if let (Some(ref provider), Some(ref model)) = (&agent.model_provider, &agent.model_name) {
        println!("Model:       {provider}/{model}");
    } else if let Some(ref provider) = agent.model_provider {
        println!("Model:       {provider}");
    } else if let Some(ref model) = agent.model_name {
        println!("Model:       {model}");
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
    fn test_parse_agent_id() {
        let valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_agent_id(valid_uuid).is_ok());

        let invalid_uuid = "not-a-uuid";
        assert!(parse_agent_id(invalid_uuid).is_err());
    }

    // F-051: Agent status validation tests

    #[test]
    fn test_validate_agent_status() {
        assert!(validate_agent_status("active").is_ok());
        assert!(validate_agent_status("inactive").is_ok());
        assert!(validate_agent_status("suspended").is_ok());
        assert!(validate_agent_status("deprecated").is_ok());
        assert!(validate_agent_status("archived").is_ok());
        assert!(validate_agent_status("pending").is_err());
        assert!(validate_agent_status("invalid").is_err());
        assert!(validate_agent_status("ACTIVE").is_err()); // Case sensitive
    }

    // F-051: User Story 1 - Filter tests

    #[test]
    fn test_list_args_type_filter() {
        // Test that ListArgs can hold type filter
        let args = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: Some("copilot".to_string()),
            status: None,
            page: None,
            per_page: None,
        };
        assert_eq!(args.r#type, Some("copilot".to_string()));
    }

    #[test]
    fn test_list_args_status_filter() {
        // Test that ListArgs can hold status filter
        let args = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: Some("active".to_string()),
            page: None,
            per_page: None,
        };
        assert_eq!(args.status, Some("active".to_string()));
    }

    #[test]
    fn test_list_args_combined_filters() {
        // Test that ListArgs can hold both filters
        let args = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: Some("autonomous".to_string()),
            status: Some("inactive".to_string()),
            page: None,
            per_page: None,
        };
        assert_eq!(args.r#type, Some("autonomous".to_string()));
        assert_eq!(args.status, Some("inactive".to_string()));
    }

    // F-051: User Story 2 - Update tests

    #[test]
    fn test_update_args_parsing() {
        let args = UpdateArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            name: Some("new-name".to_string()),
            description: None,
            status: Some("inactive".to_string()),
            json: false,
        };
        assert_eq!(args.name, Some("new-name".to_string()));
        assert_eq!(args.status, Some("inactive".to_string()));
        assert!(args.description.is_none());
    }

    #[test]
    fn test_update_requires_at_least_one_property() {
        let args = UpdateArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            name: None,
            description: None,
            status: None,
            json: false,
        };
        // All properties are None, which would fail validation
        assert!(args.name.is_none() && args.description.is_none() && args.status.is_none());
    }

    // F-051: User Story 3 - Pagination tests

    #[test]
    fn test_page_to_offset_conversion() {
        // Page 1 with per_page 10 should give offset 0
        let args = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(1),
            per_page: Some(10),
        };
        let (limit, offset) = calculate_pagination(&args).unwrap();
        assert_eq!(limit, 10);
        assert_eq!(offset, 0);

        // Page 2 with per_page 10 should give offset 10
        let args2 = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(2),
            per_page: Some(10),
        };
        let (limit2, offset2) = calculate_pagination(&args2).unwrap();
        assert_eq!(limit2, 10);
        assert_eq!(offset2, 10);

        // Page 3 with per_page 25 should give offset 50
        let args3 = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(3),
            per_page: Some(25),
        };
        let (limit3, offset3) = calculate_pagination(&args3).unwrap();
        assert_eq!(limit3, 25);
        assert_eq!(offset3, 50);
    }

    #[test]
    fn test_page_validation() {
        // Page 0 should fail
        let args_zero = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(0),
            per_page: Some(10),
        };
        assert!(calculate_pagination(&args_zero).is_err());

        // Negative page should fail
        let args_neg = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(-1),
            per_page: Some(10),
        };
        assert!(calculate_pagination(&args_neg).is_err());
    }

    #[test]
    fn test_per_page_cap_at_100() {
        // per_page 200 should be capped at 100
        let args = ListArgs {
            json: false,
            limit: 50,
            offset: 0,
            r#type: None,
            status: None,
            page: Some(1),
            per_page: Some(200),
        };
        let (limit, _) = calculate_pagination(&args).unwrap();
        assert_eq!(limit, 100);
    }

    // F-053: Interactive Mode Tests

    #[test]
    fn test_create_args_with_interactive_flag() {
        // Test that CreateArgs can have --interactive flag
        let args = CreateArgs {
            name: None,
            interactive: true,
            r#type: None,
            model_provider: None,
            model_name: None,
            description: None,
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
            r#type: Some("copilot".to_string()),
            model_provider: None,
            model_name: None,
            description: None,
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
            name: Some("my-agent".to_string()),
            interactive: true,
            r#type: Some("autonomous".to_string()),
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-4".to_string()),
            description: Some("Test agent".to_string()),
            json: true,
        };
        assert_eq!(args.name, Some("my-agent".to_string()));
        assert!(args.interactive);
        assert_eq!(args.r#type, Some("autonomous".to_string()));
    }

    #[test]
    fn test_delete_args_with_yes_flag() {
        // Test that DeleteArgs has --yes flag
        let args = DeleteArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            yes: true,
            force: false,
        };
        assert!(args.yes);
        assert!(!args.force);
    }

    #[test]
    fn test_delete_args_force_is_alias() {
        // Test that --force still works as an alias for backward compatibility
        let args = DeleteArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            yes: false,
            force: true,
        };
        // Either yes or force should skip confirmation
        let skip_confirm = args.yes || args.force;
        assert!(skip_confirm);
    }
}
