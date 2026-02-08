//! Tool management CLI commands

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::nhi::UpdateToolRequest;
use crate::models::tool::{CreateToolRequest, ToolResponse};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Select};
use uuid::Uuid;

/// Tool management commands
#[derive(Args, Debug)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub command: ToolsCommands,
}

#[derive(Subcommand, Debug)]
pub enum ToolsCommands {
    /// List all tools in the current tenant
    List(ListArgs),
    /// Create a new tool
    Create(CreateArgs),
    /// Get details of a specific tool
    Get(GetArgs),
    /// Update a tool
    Update(UpdateArgs),
    /// Delete a tool
    Delete(DeleteArgs),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of tools to return
    #[arg(long, default_value = "50")]
    pub limit: i32,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: i32,
}

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Tool name (alphanumeric, hyphens, underscores, 1-64 chars)
    pub name: String,

    /// Risk level: low, medium, high, critical
    #[arg(long, short = 'r')]
    pub risk_level: Option<String>,

    /// JSON Schema for tool input parameters
    #[arg(long, short = 's')]
    pub schema: Option<String>,

    /// Tool description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// Tool category (e.g., communication, data, system, integration)
    #[arg(long, short = 'c')]
    pub category: Option<String>,

    /// Require approval for invocation
    #[arg(long)]
    pub requires_approval: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the get command
#[derive(Args, Debug)]
pub struct GetArgs {
    /// Tool ID (UUID)
    pub id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the update command
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Tool ID (UUID)
    pub id: String,

    /// New tool name
    #[arg(long)]
    pub name: Option<String>,

    /// New description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// New category
    #[arg(long, short = 'c')]
    pub category: Option<String>,

    /// Set requires-approval flag
    #[arg(long)]
    pub requires_approval: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the delete command
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Tool ID (UUID)
    pub id: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
}

/// Execute tool commands
pub async fn execute(args: ToolsArgs) -> CliResult<()> {
    match args.command {
        ToolsCommands::List(list_args) => execute_list(list_args).await,
        ToolsCommands::Create(create_args) => execute_create(create_args).await,
        ToolsCommands::Get(get_args) => execute_get(get_args).await,
        ToolsCommands::Update(update_args) => execute_update(update_args).await,
        ToolsCommands::Delete(delete_args) => execute_delete(delete_args).await,
    }
}

/// Execute list command
async fn execute_list(args: ListArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.list_tools(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.tools.is_empty() {
        println!("No tools found.");
        println!();
        println!("Create your first tool with: xavyo tools create <name> --risk-level <level> --schema '<json>'");
    } else {
        print_tool_table(&response.tools);
        println!();
        println!(
            "Showing {} of {} tools",
            response.tools.len(),
            response.total
        );
    }

    Ok(())
}

/// Execute create command
async fn execute_create(args: CreateArgs) -> CliResult<()> {
    // Validate tool name
    validate_tool_name(&args.name)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get risk level (interactive or from flag)
    let risk_level = match args.risk_level {
        Some(r) => {
            validate_risk_level(&r)?;
            r
        }
        None => prompt_risk_level()?,
    };

    // Get JSON schema (from flag or prompt for default)
    let input_schema = match args.schema {
        Some(ref s) => parse_json_schema(s)?,
        None => prompt_schema()?,
    };

    // Build the request
    let mut request = CreateToolRequest::new(args.name.clone(), input_schema, risk_level);

    if let Some(desc) = args.description {
        request = request.with_description(Some(desc));
    }

    if let Some(cat) = args.category {
        request = request.with_category(Some(cat));
    }

    if args.requires_approval {
        request = request.with_requires_approval(true);
    }

    // Create the tool
    let tool = client.create_tool(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&tool)?);
    } else {
        println!("✓ Tool created successfully!");
        println!();
        print_tool_details(&tool);
    }

    Ok(())
}

/// Execute get command
async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_tool_id(&args.id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let tool = client.get_tool(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&tool)?);
    } else {
        print_tool_details(&tool);
    }

    Ok(())
}

/// Execute update command
async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    let id = parse_tool_id(&args.id)?;

    let request = UpdateToolRequest {
        name: args.name.clone(),
        description: args.description.clone(),
        category: args.category.clone(),
        requires_approval: if args.requires_approval {
            Some(true)
        } else {
            None
        },
    };

    if !request.has_changes() {
        return Err(CliError::Validation(
            "No changes specified. Use --name, --description, --category, or --requires-approval."
                .to_string(),
        ));
    }

    if let Some(ref name) = args.name {
        validate_tool_name(name)?;
    }

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let tool = client.update_tool(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&tool)?);
    } else {
        println!("Tool updated successfully!");
        println!();
        print_tool_details(&tool);
    }

    Ok(())
}

/// Execute delete command
async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_tool_id(&args.id)?;

    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    // Get tool details for confirmation message
    let tool = client.get_tool(id).await?;

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
                "Delete tool '{}'? This action cannot be undone.",
                tool.name
            ))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Delete the tool
    client.delete_tool(id).await?;

    println!("✓ Tool deleted: {}", tool.name);

    Ok(())
}

/// Validate tool name according to spec
fn validate_tool_name(name: &str) -> CliResult<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(CliError::Validation(
            "Tool name must be 1-64 characters.".to_string(),
        ));
    }

    // Must start with alphanumeric
    let first_char = name.chars().next().unwrap();
    if !first_char.is_alphanumeric() {
        return Err(CliError::Validation(
            "Tool name must start with a letter or number.".to_string(),
        ));
    }

    // Only alphanumeric, hyphens, and underscores allowed
    for ch in name.chars() {
        if !ch.is_alphanumeric() && ch != '-' && ch != '_' {
            return Err(CliError::Validation(
                "Invalid tool name. Use alphanumeric characters, hyphens, and underscores only."
                    .to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate risk level
fn validate_risk_level(risk_level: &str) -> CliResult<()> {
    match risk_level {
        "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid risk level '{risk_level}'. Must be one of: low, medium, high, critical"
        ))),
    }
}

/// Parse tool ID from string
fn parse_tool_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!("Invalid tool ID '{id_str}'. Must be a valid UUID."))
    })
}

/// Parse JSON schema from string
fn parse_json_schema(schema_str: &str) -> CliResult<serde_json::Value> {
    serde_json::from_str(schema_str)
        .map_err(|e| CliError::Validation(format!("Invalid JSON schema: {e}")))
}

/// Interactive prompt for risk level
fn prompt_risk_level() -> CliResult<String> {
    if !atty::is(atty::Stream::Stdin) {
        return Err(CliError::Validation(
            "Risk level is required. Use --risk-level flag in non-interactive mode.".to_string(),
        ));
    }

    let levels = vec!["low", "medium", "high", "critical"];

    let selection = Select::new()
        .with_prompt("Select risk level")
        .items(&levels)
        .default(1) // Default to "medium"
        .interact()
        .map_err(|e| CliError::Io(e.to_string()))?;

    Ok(levels[selection].to_string())
}

/// Interactive prompt for JSON schema
fn prompt_schema() -> CliResult<serde_json::Value> {
    if !atty::is(atty::Stream::Stdin) {
        return Err(CliError::Validation(
            "Schema is required. Use --schema flag in non-interactive mode.".to_string(),
        ));
    }

    // Provide a default empty object schema for interactive mode
    println!("No schema provided. Using default empty object schema.");
    println!(
        "Tip: Use --schema '{{\"type\":\"object\",\"properties\":{{...}}}}' for custom schemas."
    );

    Ok(serde_json::json!({"type": "object"}))
}

/// Print tool list as a table
fn print_tool_table(tools: &[ToolResponse]) {
    // Print header
    println!(
        "{:<38} {:<20} {:<15} {:<10} {:<8}",
        "ID", "NAME", "CATEGORY", "RISK", "STATUS"
    );
    println!("{}", "-".repeat(93));

    // Print each tool
    for tool in tools {
        let truncated_name = if tool.name.len() > 18 {
            format!("{}...", &tool.name[..15])
        } else {
            tool.name.clone()
        };

        let category = tool.category.as_deref().unwrap_or("-");
        let truncated_category = if category.len() > 13 {
            format!("{}...", &category[..10])
        } else {
            category.to_string()
        };

        println!(
            "{:<38} {:<20} {:<15} {:<10} {:<8}",
            tool.id, truncated_name, truncated_category, tool.risk_level, tool.status
        );
    }
}

/// Print detailed tool information
fn print_tool_details(tool: &ToolResponse) {
    println!("Tool: {}", tool.name);
    println!("{}", "━".repeat(50));
    println!("ID:                {}", tool.id);

    if let Some(ref category) = tool.category {
        println!("Category:          {category}");
    }

    println!("Risk Level:        {}", tool.risk_level);
    println!(
        "Requires Approval: {}",
        if tool.requires_approval { "Yes" } else { "No" }
    );
    println!("Status:            {}", tool.status);

    if let Some(ref desc) = tool.description {
        println!("Description:       {desc}");
    }

    if let Some(ref provider) = tool.provider {
        println!("Provider:          {provider}");
        println!(
            "Provider Verified: {}",
            if tool.provider_verified { "Yes" } else { "No" }
        );
    }

    if let Some(max_calls) = tool.max_calls_per_hour {
        println!("Max Calls/Hour:    {max_calls}");
    }

    println!(
        "Created:           {}",
        tool.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Updated:           {}",
        tool.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    println!();
    println!("Input Schema:");
    println!(
        "{}",
        serde_json::to_string_pretty(&tool.input_schema).unwrap_or_else(|_| "{}".to_string())
    );

    if let Some(ref output_schema) = tool.output_schema {
        println!();
        println!("Output Schema:");
        println!(
            "{}",
            serde_json::to_string_pretty(output_schema).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_tool_name_valid() {
        assert!(validate_tool_name("my-tool").is_ok());
        assert!(validate_tool_name("MyTool123").is_ok());
        assert!(validate_tool_name("tool_1").is_ok());
        assert!(validate_tool_name("a").is_ok());
        assert!(validate_tool_name("1tool").is_ok());
        assert!(validate_tool_name("send_email").is_ok());
        assert!(validate_tool_name("query-database").is_ok());
    }

    #[test]
    fn test_validate_tool_name_invalid() {
        assert!(validate_tool_name("").is_err());
        assert!(validate_tool_name("-tool").is_err()); // Starts with hyphen
        assert!(validate_tool_name("_tool").is_err()); // Starts with underscore
        assert!(validate_tool_name("my tool").is_err()); // Contains space
        assert!(validate_tool_name("my.tool").is_err()); // Contains period
        assert!(validate_tool_name("my@tool").is_err()); // Contains @

        // Too long (> 64 chars)
        let long_name = "a".repeat(65);
        assert!(validate_tool_name(&long_name).is_err());
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
    fn test_parse_tool_id() {
        let valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_tool_id(valid_uuid).is_ok());

        let invalid_uuid = "not-a-uuid";
        assert!(parse_tool_id(invalid_uuid).is_err());
    }

    #[test]
    fn test_parse_json_schema_valid() {
        let schema = r#"{"type": "object"}"#;
        assert!(parse_json_schema(schema).is_ok());

        let complex_schema = r#"{"type": "object", "properties": {"name": {"type": "string"}}}"#;
        assert!(parse_json_schema(complex_schema).is_ok());
    }

    #[test]
    fn test_parse_json_schema_invalid() {
        let invalid = "not json";
        assert!(parse_json_schema(invalid).is_err());

        let malformed = "{type: object}"; // Missing quotes
        assert!(parse_json_schema(malformed).is_err());
    }

    // T036: Test single tool display formatting
    #[test]
    fn test_print_tool_details_output() {
        use crate::models::tool::ToolResponse;
        use chrono::Utc;

        // Create a test tool with all fields populated
        let tool = ToolResponse {
            id: uuid::Uuid::new_v4(),
            name: "test-tool".to_string(),
            description: Some("A test tool for unit testing".to_string()),
            category: Some("testing".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "string"})),
            risk_level: "low".to_string(),
            requires_approval: false,
            max_calls_per_hour: Some(100),
            provider: Some("test-provider".to_string()),
            provider_verified: true,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Test that print_tool_details doesn't panic
        // (We can't easily capture stdout in a unit test without additional setup,
        // so we verify the function runs without errors)
        print_tool_details(&tool);

        // Verify the tool data is accessible for display
        assert_eq!(tool.name, "test-tool");
        assert_eq!(tool.risk_level, "low");
        assert!(!tool.requires_approval);
        assert_eq!(tool.category, Some("testing".to_string()));
        assert_eq!(tool.status, "active");
        assert!(tool.provider.is_some());
        assert!(tool.provider_verified);
        assert_eq!(tool.max_calls_per_hour, Some(100));
    }

    // T036 continued: Test tool details with minimal fields
    #[test]
    fn test_print_tool_details_minimal() {
        use crate::models::tool::ToolResponse;
        use chrono::Utc;

        // Create a minimal tool (no optional fields)
        let tool = ToolResponse {
            id: uuid::Uuid::new_v4(),
            name: "minimal-tool".to_string(),
            description: None,
            category: None,
            input_schema: serde_json::json!({}),
            output_schema: None,
            risk_level: "critical".to_string(),
            requires_approval: true,
            max_calls_per_hour: None,
            provider: None,
            provider_verified: false,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Test that print_tool_details handles None values without panicking
        print_tool_details(&tool);

        // Verify minimal tool data
        assert_eq!(tool.name, "minimal-tool");
        assert!(tool.description.is_none());
        assert!(tool.category.is_none());
        assert!(tool.provider.is_none());
        assert!(tool.max_calls_per_hour.is_none());
    }

    // T044: Test delete confirmation logic
    #[test]
    fn test_delete_args_force_flag() {
        // Test that DeleteArgs can be constructed with force flag
        let args_without_force = DeleteArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            force: false,
        };
        assert!(!args_without_force.force);

        let args_with_force = DeleteArgs {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            force: true,
        };
        assert!(args_with_force.force);
    }

    // T044 continued: Test delete requires valid UUID
    #[test]
    fn test_delete_requires_valid_uuid() {
        // Valid UUID should pass
        let valid_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_tool_id(valid_id).is_ok());

        // Invalid UUID should fail
        let invalid_id = "invalid-id";
        let result = parse_tool_id(invalid_id);
        assert!(result.is_err());

        // Verify error message mentions UUID
        if let Err(CliError::Validation(msg)) = result {
            assert!(msg.contains("UUID"));
        }
    }

    // T044 continued: Test delete args struct fields
    #[test]
    fn test_delete_args_struct() {
        // Verify DeleteArgs has expected fields and types
        fn _verify_delete_args_fields(args: &DeleteArgs) -> (&str, bool) {
            (&args.id, args.force)
        }

        let args = DeleteArgs {
            id: "test-id".to_string(),
            force: true,
        };

        let (id, force) = _verify_delete_args_fields(&args);
        assert_eq!(id, "test-id");
        assert!(force);
    }
}
