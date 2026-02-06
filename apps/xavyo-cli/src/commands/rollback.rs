//! Rollback command for restoring previous configuration states
//!
//! Allows users to undo apply operations by restoring configuration
//! snapshots saved during previous applies.

use clap::{Args, ValueEnum};
use dialoguer::Confirm;

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::diff::{compare_configs, format_diff, OutputFormat};
use crate::error::{CliError, CliResult};
use crate::history::VersionHistory;
use crate::models::agent::CreateAgentRequest;
use crate::models::config::XavyoConfig;
use crate::models::tool::CreateToolRequest;
use crate::verbose;

/// Arguments for the rollback command
#[derive(Args, Debug)]
#[command(
    about = "Rollback to a previous configuration version",
    long_about = "Restore server configuration to a previous state from local history.\n\n\
    The rollback command uses configuration snapshots saved during 'xavyo apply' operations.\n\
    By default, it rolls back to the most recent version before the last apply.\n\n\
    Examples:\n\
      xavyo rollback              # Rollback to previous version (with confirmation)\n\
      xavyo rollback --yes        # Rollback without confirmation\n\
      xavyo rollback --to 3       # Rollback to specific version 3\n\
      xavyo rollback --list       # List all available versions\n\
      xavyo rollback --dry-run    # Preview changes without applying"
)]
pub struct RollbackArgs {
    /// Rollback to a specific version number
    #[arg(long, value_name = "VERSION")]
    pub to: Option<u32>,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Show changes without applying them
    #[arg(long)]
    pub dry_run: bool,

    /// List all available versions
    #[arg(long)]
    pub list: bool,

    /// Output format for --list (table or json)
    #[arg(long, value_name = "FORMAT", default_value = "table")]
    pub output: ListOutputFormat,
}

/// Output format options for the list command
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ListOutputFormat {
    /// Display as formatted table (default)
    #[default]
    Table,
    /// Display as JSON
    Json,
}

/// Execute the rollback command
pub async fn execute(args: RollbackArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    paths.ensure_history_dir_exists()?;

    let history = VersionHistory::load(&paths.version_history_dir)?;

    // Handle --list flag
    if args.list {
        return list_versions(&history, &args.output);
    }

    // Check if there are any versions to rollback to
    if !history.has_versions() {
        return Err(CliError::NoHistoryAvailable);
    }

    // Determine target version
    let target_version = match args.to {
        Some(version) => {
            // Validate version exists
            if version == 0 {
                return Err(CliError::Validation(
                    "Version must be a positive number".to_string(),
                ));
            }
            history.get_version(version)?
        }
        None => {
            // Default to latest (most recent) version
            history.get_latest()?.ok_or(CliError::NoHistoryAvailable)?
        }
    };

    verbose!(
        "Target version: {} ({})",
        target_version.version,
        target_version.timestamp
    );

    // Set up API client
    let cli_config = Config::load(&paths)?;
    let api_client = ApiClient::new(cli_config, paths.clone())?;

    // Fetch current server state
    verbose!("Fetching current server state...");
    let current_config = fetch_current_state(&api_client).await?;

    // Compare configurations
    let diff_result = compare_configs(
        &current_config,
        &target_version.config,
        "current",
        format!("version {}", target_version.version),
    );

    // Check if there are any changes
    if diff_result.is_empty() {
        println!(
            "No changes needed. Server state already matches version {}.",
            target_version.version
        );
        return Ok(());
    }

    // Show the changes
    let use_color = std::env::var("NO_COLOR").is_err();
    let diff_output = format_diff(&diff_result, OutputFormat::Table, use_color);
    println!("\nChanges to apply:\n");
    println!("{}", diff_output);

    // Dry-run mode: show diff and exit
    if args.dry_run {
        println!("\n[Dry-run mode] No changes were made.");
        // Exit code 1 if there are changes, 0 if no changes
        if !diff_result.is_empty() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        let confirmed = Confirm::new()
            .with_prompt(format!(
                "Rollback to version {}? This will modify {} resource(s).",
                target_version.version,
                diff_result.changes_count()
            ))
            .default(false)
            .interact()?;

        if !confirmed {
            println!("Rollback cancelled.");
            return Ok(());
        }
    }

    // Apply the rollback
    verbose!("Applying changes...");
    apply_rollback(&api_client, &target_version.config).await?;

    println!(
        "\n✓ Successfully rolled back to version {} ({} agents, {} tools)",
        target_version.version,
        target_version.summary.agent_count,
        target_version.summary.tool_count
    );

    Ok(())
}

/// List all available versions
fn list_versions(history: &VersionHistory, output: &ListOutputFormat) -> CliResult<()> {
    let versions = history.list_versions()?;

    if versions.is_empty() {
        println!("No configuration history available.");
        return Ok(());
    }

    match output {
        ListOutputFormat::Json => {
            format_version_json(&versions)?;
        }
        ListOutputFormat::Table => {
            format_version_table(&versions);
        }
    }

    Ok(())
}

/// Format versions as a table
fn format_version_table(versions: &[crate::history::ConfigVersion]) {
    println!("Configuration History");
    println!("─────────────────────────────────────────────────────");
    println!("{:<9} {:<21} Summary", "Version", "Timestamp");
    println!("─────────────────────────────────────────────────────");

    for version in versions {
        let timestamp = version.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let summary = format!(
            "{} agents, {} tools",
            version.summary.agent_count, version.summary.tool_count
        );
        println!("{:>7}   {:<21} {}", version.version, timestamp, summary);
    }

    println!("─────────────────────────────────────────────────────");
    println!("Total: {} versions (showing newest first)", versions.len());
}

/// Format versions as JSON
fn format_version_json(versions: &[crate::history::ConfigVersion]) -> CliResult<()> {
    #[derive(serde::Serialize)]
    struct VersionListOutput {
        versions: Vec<VersionOutput>,
    }

    #[derive(serde::Serialize)]
    struct VersionOutput {
        version: u32,
        timestamp: String,
        summary: SummaryOutput,
    }

    #[derive(serde::Serialize)]
    struct SummaryOutput {
        agent_count: usize,
        tool_count: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    }

    let output = VersionListOutput {
        versions: versions
            .iter()
            .map(|v| VersionOutput {
                version: v.version,
                timestamp: v.timestamp.to_rfc3339(),
                summary: SummaryOutput {
                    agent_count: v.summary.agent_count,
                    tool_count: v.summary.tool_count,
                    source: v.summary.source.clone(),
                },
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{}", json);
    Ok(())
}

/// Fetch current server state (agents and tools)
async fn fetch_current_state(api_client: &ApiClient) -> CliResult<XavyoConfig> {
    // Fetch all agents (using large limit to get all)
    let agents_response = api_client.list_agents(1000, 0, None, None).await?;
    let agents = agents_response.agents;

    // Fetch all tools
    let tools_response = api_client.list_tools(1000, 0).await?;
    let tools = tools_response.tools;

    Ok(XavyoConfig {
        version: "1".to_string(),
        agents: agents.into_iter().map(|a| a.into()).collect(),
        tools: tools.into_iter().map(|t| t.into()).collect(),
    })
}

/// Apply the rollback by updating server state to match target config
async fn apply_rollback(api_client: &ApiClient, target_config: &XavyoConfig) -> CliResult<()> {
    // Get current state
    let current_agents_response = api_client.list_agents(1000, 0, None, None).await?;
    let current_agents = current_agents_response.agents;
    let current_tools_response = api_client.list_tools(1000, 0).await?;
    let current_tools = current_tools_response.tools;

    // Build maps of current state by name
    let current_agent_map: std::collections::HashMap<_, _> =
        current_agents.iter().map(|a| (a.name.clone(), a)).collect();
    let current_tool_map: std::collections::HashMap<_, _> =
        current_tools.iter().map(|t| (t.name.clone(), t)).collect();

    // Build maps of target state by name
    let target_agent_map: std::collections::HashMap<_, _> = target_config
        .agents
        .iter()
        .map(|a| (a.name.clone(), a))
        .collect();
    let target_tool_map: std::collections::HashMap<_, _> = target_config
        .tools
        .iter()
        .map(|t| (t.name.clone(), t))
        .collect();

    // Process agents
    // Delete agents not in target
    for (name, agent) in &current_agent_map {
        if !target_agent_map.contains_key(name) {
            verbose!("Deleting agent: {}", name);
            api_client.delete_agent(agent.id).await?;
        }
    }

    // Create or update agents in target
    for (name, target_agent) in &target_agent_map {
        let request: CreateAgentRequest = (*target_agent).clone().into();
        if let Some(current_agent) = current_agent_map.get(name) {
            // Update if different
            verbose!("Updating agent: {}", name);
            api_client.update_agent(current_agent.id, request).await?;
        } else {
            // Create new
            verbose!("Creating agent: {}", name);
            api_client.create_agent(request).await?;
        }
    }

    // Process tools
    // Delete tools not in target
    for (name, tool) in &current_tool_map {
        if !target_tool_map.contains_key(name) {
            verbose!("Deleting tool: {}", name);
            api_client.delete_tool(tool.id).await?;
        }
    }

    // Create or update tools in target
    for (name, target_tool) in &target_tool_map {
        let request: CreateToolRequest = (*target_tool).clone().into();
        if let Some(current_tool) = current_tool_map.get(name) {
            // Update if different
            verbose!("Updating tool: {}", name);
            api_client.update_tool(current_tool.id, request).await?;
        } else {
            // Create new
            verbose!("Creating tool: {}", name);
            api_client.create_tool(request).await?;
        }
    }

    Ok(())
}
