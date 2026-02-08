//! Apply configuration from YAML file

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::agent::CreateAgentRequest;
use crate::models::config::{
    AgentConfig, ApplyAction, ApplyChange, ApplyResult, ToolConfig, XavyoConfig,
};
use crate::models::tool::CreateToolRequest;
use clap::Args;
use dialoguer::Confirm;
use std::fs;
use std::path::PathBuf;

/// Apply configuration from a YAML file
#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Path to configuration file
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// Preview changes without applying
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Execute the apply command
pub async fn execute(args: ApplyArgs) -> CliResult<()> {
    // Load and parse configuration
    let config = load_config(&args.file)?;

    // Validate configuration
    validate_config(&config)?;

    // Set up API client
    let paths = ConfigPaths::new()?;
    let cli_config = Config::load(&paths)?;
    let client = ApiClient::new(cli_config, paths)?;

    // Fetch current state from API
    let (current_agents, current_tools) = fetch_current_state(&client).await?;

    // Compute changes
    let mut changes = compute_changes(&config, &current_agents, &current_tools);

    // If no changes needed
    if !changes.iter().any(|c| c.action != ApplyAction::Unchanged) {
        if args.json {
            let result = ApplyResult::new(args.dry_run, changes);
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("No changes required. Configuration is up to date.");
        }
        return Ok(());
    }

    // Display planned changes
    if !args.json {
        print_planned_changes(&changes, args.dry_run);
    }

    // In dry-run mode, just show what would happen
    if args.dry_run {
        if args.json {
            let result = ApplyResult::new(true, changes);
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Confirm before applying (unless --yes is passed)
    if !args.yes {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        let changes_count = changes
            .iter()
            .filter(|c| c.action == ApplyAction::Create || c.action == ApplyAction::Update)
            .count();

        let confirm = Confirm::new()
            .with_prompt(format!("Apply {changes_count} change(s)?"))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Apply changes
    apply_changes(&client, &config, &mut changes).await?;

    // Output results
    let result = ApplyResult::new(false, changes);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_apply_results(&result);
    }

    // Return error if any changes failed
    if result.summary.failed > 0 {
        return Err(CliError::Validation(format!(
            "{} change(s) failed",
            result.summary.failed
        )));
    }

    Ok(())
}

/// Load and parse YAML configuration file (public for reuse by watch command)
pub fn load_config(path: &PathBuf) -> CliResult<XavyoConfig> {
    if !path.exists() {
        return Err(CliError::Validation(format!(
            "File not found: {}",
            path.display()
        )));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| CliError::Io(format!("Failed to read file {}: {}", path.display(), e)))?;

    serde_yaml::from_str(&content).map_err(|e| {
        // Extract line/column info if available
        let location = if let Some(loc) = e.location() {
            format!(" at line {}, column {}", loc.line(), loc.column())
        } else {
            String::new()
        };
        CliError::Validation(format!("Invalid YAML{location}: {e}"))
    })
}

/// Validate configuration for required fields and valid values (public for reuse by watch command)
pub fn validate_config(config: &XavyoConfig) -> CliResult<()> {
    // Validate version
    if config.version != "1" {
        return Err(CliError::Validation(format!(
            "Unsupported config version '{}'. Only version '1' is supported.",
            config.version
        )));
    }

    // Validate agents
    for agent in &config.agents {
        validate_agent_config(agent)?;
    }

    // Validate tools
    for tool in &config.tools {
        validate_tool_config(tool)?;
    }

    // Check that tools referenced by agents exist in the config
    let tool_names: std::collections::HashSet<_> =
        config.tools.iter().map(|t| t.name.as_str()).collect();

    for agent in &config.agents {
        for tool_name in &agent.tools {
            if !tool_names.contains(tool_name.as_str()) {
                return Err(CliError::Validation(format!(
                    "Agent '{}' references undefined tool '{}'",
                    agent.name, tool_name
                )));
            }
        }
    }

    Ok(())
}

/// Validate a single agent configuration
fn validate_agent_config(agent: &AgentConfig) -> CliResult<()> {
    // Validate name
    if agent.name.is_empty() || agent.name.len() > 64 {
        return Err(CliError::Validation(format!(
            "Agent name '{}' must be 1-64 characters",
            agent.name
        )));
    }

    // Validate agent type
    match agent.agent_type.as_str() {
        "copilot" | "autonomous" | "workflow" | "orchestrator" => {}
        _ => {
            return Err(CliError::Validation(format!(
                "Invalid agent type '{}' for agent '{}'. Must be one of: copilot, autonomous, workflow, orchestrator",
                agent.agent_type, agent.name
            )));
        }
    }

    // Validate risk level
    match agent.risk_level.as_str() {
        "low" | "medium" | "high" | "critical" => {}
        _ => {
            return Err(CliError::Validation(format!(
                "Invalid risk level '{}' for agent '{}'. Must be one of: low, medium, high, critical",
                agent.risk_level, agent.name
            )));
        }
    }

    Ok(())
}

/// Validate a single tool configuration
fn validate_tool_config(tool: &ToolConfig) -> CliResult<()> {
    // Validate name
    if tool.name.is_empty() || tool.name.len() > 64 {
        return Err(CliError::Validation(format!(
            "Tool name '{}' must be 1-64 characters",
            tool.name
        )));
    }

    // Validate risk level
    match tool.risk_level.as_str() {
        "low" | "medium" | "high" | "critical" => {}
        _ => {
            return Err(CliError::Validation(format!(
                "Invalid risk level '{}' for tool '{}'. Must be one of: low, medium, high, critical",
                tool.risk_level, tool.name
            )));
        }
    }

    Ok(())
}

/// Fetch current agents and tools from the API (public for reuse by watch command)
pub async fn fetch_current_state(
    client: &ApiClient,
) -> CliResult<(
    Vec<crate::models::agent::AgentResponse>,
    Vec<crate::models::tool::ToolResponse>,
)> {
    // Fetch all agents (using large limit to get all)
    let agents_response = client.list_agents(1000, 0, None, None).await?;
    let agents = agents_response.data;

    // Fetch all tools
    let tools_response = client.list_tools(1000, 0).await?;
    let tools = tools_response.data;

    Ok((agents, tools))
}

/// Compare desired config against current state and compute changes (public for reuse by watch command)
pub fn compute_changes(
    config: &XavyoConfig,
    current_agents: &[crate::models::agent::AgentResponse],
    current_tools: &[crate::models::tool::ToolResponse],
) -> Vec<ApplyChange> {
    let mut changes = Vec::new();

    // Build lookup maps by name
    let agent_map: std::collections::HashMap<_, _> = current_agents
        .iter()
        .map(|a| (a.name.as_str(), a))
        .collect();

    let tool_map: std::collections::HashMap<_, _> =
        current_tools.iter().map(|t| (t.name.as_str(), t)).collect();

    // Check tools first (agents may depend on them)
    for tool_config in &config.tools {
        if let Some(existing) = tool_map.get(tool_config.name.as_str()) {
            // Tool exists - check if update needed
            let existing_desc = existing.description.as_deref().unwrap_or("");
            let config_desc = tool_config.description.as_str();
            let existing_risk_str = existing
                .risk_score
                .map(|s| s.to_string())
                .unwrap_or_default();
            let needs_update = existing_desc != config_desc
                || existing_risk_str != tool_config.risk_level
                || existing.input_schema != tool_config.input_schema;

            if needs_update {
                let mut details = Vec::new();
                if existing_risk_str != tool_config.risk_level {
                    details.push(format!(
                        "risk: {} → {}",
                        existing_risk_str, tool_config.risk_level
                    ));
                }
                if existing_desc != config_desc {
                    details.push("description changed".to_string());
                }
                if existing.input_schema != tool_config.input_schema {
                    details.push("input_schema changed".to_string());
                }
                changes.push(ApplyChange::update(
                    "tool",
                    &tool_config.name,
                    &details.join(", "),
                ));
            } else {
                changes.push(ApplyChange::unchanged("tool", &tool_config.name));
            }
        } else {
            // Tool doesn't exist - create
            changes.push(ApplyChange::create("tool", &tool_config.name));
        }
    }

    // Check agents
    for agent_config in &config.agents {
        if let Some(existing) = agent_map.get(agent_config.name.as_str()) {
            // Agent exists - check if update needed
            let needs_update = existing.description.as_deref()
                != agent_config.description.as_deref()
                || existing.agent_type != agent_config.agent_type
                || existing.model_provider.as_deref() != Some(agent_config.model_provider.as_str())
                || existing.model_name.as_deref() != Some(agent_config.model_name.as_str());

            if needs_update {
                let mut details = Vec::new();
                if existing.agent_type != agent_config.agent_type {
                    details.push(format!(
                        "agent_type: {} → {}",
                        existing.agent_type, agent_config.agent_type
                    ));
                }
                if existing.model_provider.as_deref() != Some(agent_config.model_provider.as_str())
                {
                    details.push(format!(
                        "model_provider: {} → {}",
                        existing.model_provider.as_deref().unwrap_or("-"),
                        agent_config.model_provider
                    ));
                }
                if existing.model_name.as_deref() != Some(agent_config.model_name.as_str()) {
                    details.push(format!(
                        "model_name: {} → {}",
                        existing.model_name.as_deref().unwrap_or("-"),
                        agent_config.model_name
                    ));
                }
                changes.push(ApplyChange::update(
                    "agent",
                    &agent_config.name,
                    &details.join(", "),
                ));
            } else {
                changes.push(ApplyChange::unchanged("agent", &agent_config.name));
            }
        } else {
            // Agent doesn't exist - create
            changes.push(ApplyChange::create("agent", &agent_config.name));
        }
    }

    changes
}

/// Apply the computed changes to the API (public for reuse by watch command)
pub async fn apply_changes(
    client: &ApiClient,
    config: &XavyoConfig,
    changes: &mut [ApplyChange],
) -> CliResult<()> {
    // Build lookup maps for config
    let tool_configs: std::collections::HashMap<_, _> =
        config.tools.iter().map(|t| (t.name.as_str(), t)).collect();

    let agent_configs: std::collections::HashMap<_, _> =
        config.agents.iter().map(|a| (a.name.as_str(), a)).collect();

    // Apply tool changes first (agents may reference tools)
    for change in changes.iter_mut() {
        if change.resource_type != "tool" {
            continue;
        }

        if change.action == ApplyAction::Unchanged {
            continue;
        }

        if let Some(tool_config) = tool_configs.get(change.name.as_str()) {
            match change.action {
                ApplyAction::Create => {
                    let request = CreateToolRequest::new(
                        tool_config.name.clone(),
                        tool_config.input_schema.clone(),
                    )
                    .with_description(Some(tool_config.description.clone()));

                    match client.create_tool(request).await {
                        Ok(_) => change.mark_success(),
                        Err(e) => change.mark_failed(&e.to_string()),
                    }
                }
                ApplyAction::Update => {
                    // Note: Update API not implemented yet, mark as success for now
                    // In a real implementation, we would call client.update_tool()
                    change.mark_failed("Tool updates are not yet supported");
                }
                _ => {}
            }
        }
    }

    // Apply agent changes
    for change in changes.iter_mut() {
        if change.resource_type != "agent" {
            continue;
        }

        if change.action == ApplyAction::Unchanged {
            continue;
        }

        if let Some(agent_config) = agent_configs.get(change.name.as_str()) {
            match change.action {
                ApplyAction::Create => {
                    let request = CreateAgentRequest::new(
                        agent_config.name.clone(),
                        agent_config.agent_type.clone(),
                    )
                    .with_model(
                        Some(agent_config.model_provider.clone()),
                        Some(agent_config.model_name.clone()),
                    )
                    .with_description(agent_config.description.clone());

                    match client.create_agent(request).await {
                        Ok(_) => change.mark_success(),
                        Err(e) => change.mark_failed(&e.to_string()),
                    }
                }
                ApplyAction::Update => {
                    // Note: Update API not implemented yet
                    change.mark_failed("Agent updates are not yet supported");
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Print planned changes in human-readable format (public for reuse by watch command)
pub fn print_planned_changes(changes: &[ApplyChange], dry_run: bool) {
    if dry_run {
        println!("Dry run - no changes will be made.");
        println!();
        println!("Would apply:");
    } else {
        println!("Planning changes:");
    }

    for change in changes {
        if change.action == ApplyAction::Unchanged {
            continue;
        }

        let color = change.action.color();
        let reset = "\x1b[0m";
        let symbol = change.action.symbol();

        print!("  {color}{symbol}{reset} ");
        print!(
            "{} {}: {}",
            change.action.display(),
            change.resource_type,
            change.name
        );

        if let Some(ref details) = change.details {
            print!(" ({details})");
        }

        println!();
    }

    // Print summary
    let creates = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Create)
        .count();
    let updates = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Update)
        .count();
    let unchanged = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Unchanged)
        .count();

    println!();
    println!("Summary: {creates} to create, {updates} to update, {unchanged} unchanged");
    println!();
}

/// Print results after applying changes
fn print_apply_results(result: &ApplyResult) {
    println!("Applying changes...");

    for change in &result.changes {
        if change.action == ApplyAction::Unchanged {
            continue;
        }

        let (symbol, color) = if change.status.as_deref() == Some("success") {
            ("✓", "\x1b[32m")
        } else if change.status.as_deref() == Some("failed") {
            ("✗", "\x1b[31m")
        } else {
            ("?", "\x1b[33m")
        };

        let reset = "\x1b[0m";

        print!(
            "  {}{}{} {} {}: {}",
            color,
            symbol,
            reset,
            if change.status.as_deref() == Some("success") {
                match change.action {
                    ApplyAction::Create => "Created",
                    ApplyAction::Update => "Updated",
                    _ => "Processed",
                }
            } else {
                "Failed"
            },
            change.resource_type,
            change.name
        );

        if let Some(ref error) = change.error {
            print!(" - {error}");
        }

        println!();
    }

    println!();

    if result.summary.failed > 0 {
        println!(
            "Applied {} change(s) with {} failure(s).",
            result.summary.created + result.summary.updated,
            result.summary.failed
        );
    } else {
        let total = result.summary.created + result.summary.updated;
        if total > 0 {
            println!("Applied {total} change(s) successfully.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_config_valid() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "autonomous".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude-sonnet-4".to_string(),
                risk_level: "medium".to_string(),
                description: None,
                tools: vec![],
            }],
            tools: vec![],
        };

        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_invalid_version() {
        let config = XavyoConfig {
            version: "2".to_string(),
            agents: vec![],
            tools: vec![],
        };

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_validate_config_invalid_agent_type() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "invalid".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "medium".to_string(),
                description: None,
                tools: vec![],
            }],
            tools: vec![],
        };

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("agent type"));
    }

    #[test]
    fn test_validate_config_invalid_risk_level() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "invalid".to_string(),
                description: None,
                tools: vec![],
            }],
            tools: vec![],
        };

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("risk level"));
    }

    #[test]
    fn test_validate_config_undefined_tool_reference() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "low".to_string(),
                description: None,
                tools: vec!["nonexistent-tool".to_string()],
            }],
            tools: vec![],
        };

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("undefined tool"));
    }

    #[test]
    fn test_validate_tool_config_valid() {
        let tool = ToolConfig {
            name: "test-tool".to_string(),
            description: "Test tool".to_string(),
            risk_level: "low".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        };

        assert!(validate_tool_config(&tool).is_ok());
    }

    #[test]
    fn test_validate_tool_config_invalid_risk() {
        let tool = ToolConfig {
            name: "test-tool".to_string(),
            description: "Test tool".to_string(),
            risk_level: "extreme".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        };

        let result = validate_tool_config(&tool);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_changes_all_new() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "new-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "low".to_string(),
                description: None,
                tools: vec![],
            }],
            tools: vec![ToolConfig {
                name: "new-tool".to_string(),
                description: "New tool".to_string(),
                risk_level: "low".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
        };

        let changes = compute_changes(&config, &[], &[]);

        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.action == ApplyAction::Create));
    }

    #[test]
    fn test_compute_changes_unchanged() {
        use chrono::Utc;

        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "existing-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "low".to_string(),
                description: None,
                tools: vec![],
            }],
            tools: vec![],
        };

        let current_agents = vec![crate::models::agent::AgentResponse {
            id: uuid::Uuid::new_v4(),
            name: "existing-agent".to_string(),
            description: None,
            agent_type: "copilot".to_string(),
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude".to_string()),
            lifecycle_state: "active".to_string(),
            risk_score: None,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];

        let changes = compute_changes(&config, &current_agents, &[]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, ApplyAction::Unchanged);
    }

    #[test]
    fn test_compute_changes_update_needed() {
        use chrono::Utc;

        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "existing-agent".to_string(),
                agent_type: "autonomous".to_string(), // Changed from copilot
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "high".to_string(), // Changed from low
                description: None,
                tools: vec![],
            }],
            tools: vec![],
        };

        let current_agents = vec![crate::models::agent::AgentResponse {
            id: uuid::Uuid::new_v4(),
            name: "existing-agent".to_string(),
            description: None,
            agent_type: "copilot".to_string(),
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude".to_string()),
            lifecycle_state: "active".to_string(),
            risk_score: None,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];

        let changes = compute_changes(&config, &current_agents, &[]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, ApplyAction::Update);
        assert!(changes[0].details.as_ref().unwrap().contains("agent_type"));
    }
}
