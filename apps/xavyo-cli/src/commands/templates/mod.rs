//! Templates command for pre-configured setups

mod customer_support;
mod data_pipeline;
mod saas_startup;
mod security_scanner;

use crate::api::ApiClient;
use crate::commands::apply::{
    apply_changes, compute_changes, fetch_current_state, print_planned_changes, validate_config,
};
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::config::{ApplyAction, XavyoConfig};
use clap::{Args, Subcommand};
use serde::Serialize;

// ============================================================================
// Template Types and Registry
// ============================================================================

/// A pre-configured template for quick setup
#[derive(Debug, Clone, Serialize)]
pub struct Template {
    /// Unique template name (e.g., "saas-startup")
    pub name: &'static str,
    /// Template category (e.g., "General", "Security")
    pub category: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Number of agents in this template
    pub agent_count: usize,
    /// Number of tools in this template
    pub tool_count: usize,
    /// The actual configuration
    #[serde(skip)]
    config_fn: fn() -> XavyoConfig,
}

impl Template {
    /// Create a new template
    pub const fn new(
        name: &'static str,
        category: &'static str,
        description: &'static str,
        agent_count: usize,
        tool_count: usize,
        config_fn: fn() -> XavyoConfig,
    ) -> Self {
        Self {
            name,
            category,
            description,
            agent_count,
            tool_count,
            config_fn,
        }
    }

    /// Get the configuration for this template
    pub fn config(&self) -> XavyoConfig {
        (self.config_fn)()
    }
}

/// Registry of all built-in templates
pub struct TemplateRegistry;

impl TemplateRegistry {
    /// Get all available templates
    pub fn all() -> Vec<Template> {
        vec![
            saas_startup::template(),
            customer_support::template(),
            security_scanner::template(),
            data_pipeline::template(),
        ]
    }

    /// Find a template by name
    pub fn find(name: &str) -> Option<Template> {
        Self::all().into_iter().find(|t| t.name == name)
    }

    /// Get list of all template names
    pub fn names() -> Vec<&'static str> {
        Self::all().iter().map(|t| t.name).collect()
    }
}

/// Helper to create a standard JSON schema for tools
pub fn object_schema(properties: &[(&str, &str, bool)]) -> serde_json::Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();

    for (name, type_str, is_required) in properties {
        props.insert(name.to_string(), serde_json::json!({ "type": type_str }));
        if *is_required {
            required.push(serde_json::Value::String(name.to_string()));
        }
    }

    serde_json::json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

// ============================================================================
// CLI Command Implementation
// ============================================================================

/// Templates command for managing pre-configured setups
#[derive(Args, Debug)]
pub struct TemplatesArgs {
    #[command(subcommand)]
    pub command: TemplatesCommand,
}

/// Templates subcommands
#[derive(Subcommand, Debug)]
pub enum TemplatesCommand {
    /// List all available templates
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show details of a specific template
    Show {
        /// Template name
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Apply a template to the current tenant
    Use {
        /// Template name
        name: String,
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
        /// Force update existing resources
        #[arg(long)]
        force: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Execute the templates command
pub async fn execute(args: TemplatesArgs) -> CliResult<()> {
    match args.command {
        TemplatesCommand::List { json } => list_templates(json),
        TemplatesCommand::Show { name, json } => show_template(&name, json),
        TemplatesCommand::Use {
            name,
            dry_run,
            yes,
            force,
            json,
        } => use_template(&name, dry_run, yes, force, json).await,
    }
}

/// List all available templates
fn list_templates(json_output: bool) -> CliResult<()> {
    let templates = TemplateRegistry::all();

    if json_output {
        let output: Vec<_> = templates
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "category": t.category,
                    "description": t.description,
                    "agent_count": t.agent_count,
                    "tool_count": t.tool_count
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("Available templates:");
    println!();

    // Calculate column widths
    let max_name = templates.iter().map(|t| t.name.len()).max().unwrap_or(10);
    let max_cat = templates
        .iter()
        .map(|t| t.category.len())
        .max()
        .unwrap_or(10);

    for t in &templates {
        println!(
            "  {:<width_name$}   {:<width_cat$}   {}",
            t.name,
            t.category,
            t.description,
            width_name = max_name,
            width_cat = max_cat
        );
        println!(
            "  {:<width_name$}   {:<width_cat$}   {} agent(s), {} tool(s)",
            "",
            "",
            t.agent_count,
            t.tool_count,
            width_name = max_name,
            width_cat = max_cat
        );
        println!();
    }

    println!("Use 'xavyo templates show <name>' to see template contents.");
    println!("Use 'xavyo templates use <name>' to apply a template.");

    Ok(())
}

/// Show details of a specific template
fn show_template(name: &str, json_output: bool) -> CliResult<()> {
    let template = TemplateRegistry::find(name).ok_or_else(|| {
        let available = TemplateRegistry::names().join(", ");
        CliError::Validation(format!(
            "Template '{name}' not found. Available templates: {available}"
        ))
    })?;

    let config = template.config();

    if json_output {
        let output = serde_json::json!({
            "name": template.name,
            "category": template.category,
            "description": template.description,
            "config": config
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("Template: {}", template.name);
    println!("Category: {}", template.category);
    println!("Description: {}", template.description);
    println!();
    println!("Contents:");
    println!("---");
    println!("{}", serde_yaml::to_string(&config)?);

    Ok(())
}

/// Apply a template to the current tenant
async fn use_template(
    name: &str,
    dry_run: bool,
    yes: bool,
    force: bool,
    json_output: bool,
) -> CliResult<()> {
    // Find the template
    let template = TemplateRegistry::find(name).ok_or_else(|| {
        let available = TemplateRegistry::names().join(", ");
        CliError::Validation(format!(
            "Template '{name}' not found. Available templates: {available}"
        ))
    })?;

    // Get the config
    let config = template.config();

    // Validate the config
    validate_config(&config)?;

    // Set up API client
    let paths = ConfigPaths::new()?;
    let cli_config = Config::load(&paths)?;
    let client = ApiClient::new(cli_config, paths)?;

    if !json_output {
        if dry_run {
            println!("[DRY RUN] Applying template: {}", template.name);
        } else {
            println!("Applying template: {}", template.name);
        }
    }

    // Fetch current state
    let (current_agents, current_tools) = fetch_current_state(&client).await?;

    // Compute changes
    let mut changes = compute_changes(&config, &current_agents, &current_tools);

    // Handle conflicts based on --force flag
    if !force {
        // Mark existing resources as skipped (unchanged)
        for change in &mut changes {
            if change.action == ApplyAction::Update {
                change.action = ApplyAction::Unchanged;
                change.details = Some("skipped (already exists)".to_string());
            }
        }
    }

    // If no changes needed
    if !changes
        .iter()
        .any(|c| c.action == ApplyAction::Create || c.action == ApplyAction::Update)
    {
        if json_output {
            let output = serde_json::json!({
                "template": template.name,
                "dry_run": dry_run,
                "created": 0,
                "skipped": changes.iter().filter(|c| c.action == ApplyAction::Unchanged).count(),
                "message": "All resources already exist"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("All resources already exist. Nothing to create.");
            if !force {
                println!("Use --force to update existing resources.");
            }
        }
        return Ok(());
    }

    // Display planned changes
    if !json_output {
        print_planned_changes(&changes, dry_run);
    }

    // In dry-run mode, just show what would happen
    if dry_run {
        if json_output {
            let output = serde_json::json!({
                "template": template.name,
                "dry_run": true,
                "would_create": changes.iter().filter(|c| c.action == ApplyAction::Create).count(),
                "would_update": changes.iter().filter(|c| c.action == ApplyAction::Update).count(),
                "unchanged": changes.iter().filter(|c| c.action == ApplyAction::Unchanged).count()
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        return Ok(());
    }

    // Confirm before applying (unless --yes is passed)
    if !yes && !json_output {
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

        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Apply {changes_count} change(s) from template '{name}'?"
            ))
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

    // Calculate results
    let created = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Create && c.status.as_deref() == Some("success"))
        .count();
    let updated = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Update && c.status.as_deref() == Some("success"))
        .count();
    let skipped = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Unchanged)
        .count();
    let failed = changes
        .iter()
        .filter(|c| c.status.as_deref() == Some("failed"))
        .count();

    if json_output {
        let output = serde_json::json!({
            "template": template.name,
            "dry_run": false,
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "failed": failed
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!();
        if failed > 0 {
            println!(
                "Template applied with errors: {created} created, {updated} updated, {skipped} skipped, {failed} failed"
            );
        } else {
            println!("Template applied successfully!");
            println!(
                "Created: {} agent(s), {} tool(s)",
                changes
                    .iter()
                    .filter(|c| c.resource_type == "agent"
                        && c.action == ApplyAction::Create
                        && c.status.as_deref() == Some("success"))
                    .count(),
                changes
                    .iter()
                    .filter(|c| c.resource_type == "tool"
                        && c.action == ApplyAction::Create
                        && c.status.as_deref() == Some("success"))
                    .count()
            );
            if skipped > 0 {
                println!("Skipped: {skipped} (already exist)");
            }
        }
    }

    // Return error if any changes failed
    if failed > 0 {
        return Err(CliError::Validation(format!("{failed} change(s) failed")));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_four_templates() {
        let templates = TemplateRegistry::all();
        assert_eq!(templates.len(), 4);
    }

    #[test]
    fn test_template_names() {
        let names = TemplateRegistry::names();
        assert!(names.contains(&"saas-startup"));
        assert!(names.contains(&"customer-support"));
        assert!(names.contains(&"security-scanner"));
        assert!(names.contains(&"data-pipeline"));
    }

    #[test]
    fn test_find_existing_template() {
        let template = TemplateRegistry::find("saas-startup");
        assert!(template.is_some());
        let t = template.unwrap();
        assert_eq!(t.name, "saas-startup");
    }

    #[test]
    fn test_find_nonexistent_template() {
        let template = TemplateRegistry::find("nonexistent");
        assert!(template.is_none());
    }

    #[test]
    fn test_template_config_generation() {
        let template = TemplateRegistry::find("saas-startup").unwrap();
        let config = template.config();
        assert_eq!(config.version, "1");
        assert!(!config.agents.is_empty());
        assert!(!config.tools.is_empty());
    }

    #[test]
    fn test_all_templates_have_valid_configs() {
        for template in TemplateRegistry::all() {
            let config = template.config();
            assert_eq!(config.version, "1");
            assert_eq!(config.agents.len(), template.agent_count);
            assert_eq!(config.tools.len(), template.tool_count);
        }
    }

    #[test]
    fn test_all_templates_pass_validation() {
        for template in TemplateRegistry::all() {
            let config = template.config();
            assert!(
                validate_config(&config).is_ok(),
                "Template {} failed validation",
                template.name
            );
        }
    }

    #[test]
    fn test_object_schema_helper() {
        let schema = object_schema(&[("query", "string", true), ("limit", "integer", false)]);

        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["query"]["type"], "string");
        assert_eq!(schema["properties"]["limit"]["type"], "integer");
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("query")));
    }

    #[test]
    fn test_template_agent_tool_references() {
        for template in TemplateRegistry::all() {
            let config = template.config();
            let tool_names: Vec<_> = config.tools.iter().map(|t| t.name.as_str()).collect();

            for agent in &config.agents {
                for tool_ref in &agent.tools {
                    assert!(
                        tool_names.contains(&tool_ref.as_str()),
                        "Template {} agent {} references non-existent tool {}",
                        template.name,
                        agent.name,
                        tool_ref
                    );
                }
            }
        }
    }
}
