//! Export current configuration to YAML

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};
use chrono::Utc;
use clap::Args;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Export current configuration to YAML
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Write to file instead of stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

/// Execute the export command
pub async fn execute(args: ExportArgs) -> CliResult<()> {
    // Set up API client
    let paths = ConfigPaths::new()?;
    let cli_config = Config::load(&paths)?;
    let client = ApiClient::new(cli_config, paths)?;

    // Fetch all resources
    let (agents, tools) = fetch_all_resources(&client).await?;

    // Build configuration
    let config = build_config(agents, tools);

    // Generate YAML with header comment
    let yaml = generate_yaml_output(&config)?;

    // Output to file or stdout
    if let Some(ref output_path) = args.output {
        write_to_file(output_path, &yaml)?;
        println!("Configuration exported to {}", output_path.display());
    } else {
        print!("{yaml}");
    }

    Ok(())
}

/// Fetch all agents and tools from the API
async fn fetch_all_resources(
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

/// Convert API responses to config format
fn build_config(
    agents: Vec<crate::models::agent::AgentResponse>,
    tools: Vec<crate::models::tool::ToolResponse>,
) -> XavyoConfig {
    let agent_configs: Vec<AgentConfig> = agents
        .into_iter()
        .map(|a| AgentConfig {
            name: a.name,
            agent_type: a.agent_type,
            model_provider: a.model_provider.unwrap_or_default(),
            model_name: a.model_name.unwrap_or_default(),
            risk_level: a
                .risk_score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "medium".to_string()),
            description: a.description,
            tools: vec![], // Tool assignments not tracked in agent response
        })
        .collect();

    let tool_configs: Vec<ToolConfig> = tools
        .into_iter()
        .map(|t| ToolConfig {
            name: t.name,
            description: t.description.unwrap_or_default(),
            risk_level: t
                .risk_score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            input_schema: t.input_schema,
        })
        .collect();

    XavyoConfig {
        version: "1".to_string(),
        agents: agent_configs,
        tools: tool_configs,
    }
}

/// Generate YAML output with header comments
fn generate_yaml_output(config: &XavyoConfig) -> CliResult<String> {
    let mut output = String::new();

    // Add header comment
    output.push_str(&format!(
        "# Generated at: {}\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    ));
    output.push('\n');

    // Generate YAML
    let yaml = serde_yaml::to_string(config)
        .map_err(|e| CliError::Validation(format!("Failed to serialize YAML: {e}")))?;

    output.push_str(&yaml);

    Ok(output)
}

/// Write content to file
fn write_to_file(path: &PathBuf, content: &str) -> CliResult<()> {
    let mut file = fs::File::create(path)
        .map_err(|e| CliError::Io(format!("Failed to create file {}: {}", path.display(), e)))?;

    file.write_all(content.as_bytes())
        .map_err(|e| CliError::Io(format!("Failed to write to file {}: {}", path.display(), e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_build_config_empty() {
        let config = build_config(vec![], vec![]);

        assert_eq!(config.version, "1");
        assert!(config.agents.is_empty());
        assert!(config.tools.is_empty());
    }

    #[test]
    fn test_build_config_with_agents() {
        let agents = vec![crate::models::agent::AgentResponse {
            id: uuid::Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: Some("Test description".to_string()),
            agent_type: "copilot".to_string(),
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-sonnet-4".to_string()),
            lifecycle_state: "active".to_string(),
            risk_score: Some(50),
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];

        let config = build_config(agents, vec![]);

        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "test-agent");
        assert_eq!(config.agents[0].agent_type, "copilot");
        assert_eq!(config.agents[0].model_provider, "anthropic");
        assert_eq!(config.agents[0].model_name, "claude-sonnet-4");
        assert_eq!(config.agents[0].risk_level, "50");
        assert_eq!(
            config.agents[0].description,
            Some("Test description".to_string())
        );
    }

    #[test]
    fn test_build_config_with_tools() {
        let tools = vec![crate::models::tool::ToolResponse {
            id: uuid::Uuid::new_v4(),
            name: "test-tool".to_string(),
            description: Some("Test tool description".to_string()),
            category: Some("data".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            risk_score: Some(25),
            requires_approval: false,
            max_calls_per_hour: None,
            provider: None,
            provider_verified: false,
            lifecycle_state: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];

        let config = build_config(vec![], tools);

        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].name, "test-tool");
        assert_eq!(config.tools[0].description, "Test tool description");
        assert_eq!(config.tools[0].risk_level, "25");
    }

    #[test]
    fn test_build_config_handles_none_values() {
        let agents = vec![crate::models::agent::AgentResponse {
            id: uuid::Uuid::new_v4(),
            name: "agent-no-model".to_string(),
            description: None,
            agent_type: "workflow".to_string(),
            model_provider: None,
            model_name: None,
            lifecycle_state: "active".to_string(),
            risk_score: None,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];

        let config = build_config(agents, vec![]);

        assert_eq!(config.agents[0].model_provider, "");
        assert_eq!(config.agents[0].model_name, "");
        assert!(config.agents[0].description.is_none());
    }

    #[test]
    fn test_generate_yaml_output_basic() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        };

        let yaml = generate_yaml_output(&config).unwrap();

        assert!(yaml.contains("# Generated at:"));
        assert!(yaml.contains("version: '1'") || yaml.contains("version: \"1\""));
    }

    #[test]
    fn test_generate_yaml_output_with_content() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "autonomous".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "high".to_string(),
                description: Some("Test".to_string()),
                tools: vec![],
            }],
            tools: vec![ToolConfig {
                name: "test-tool".to_string(),
                description: "A tool".to_string(),
                risk_level: "low".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
        };

        let yaml = generate_yaml_output(&config).unwrap();

        assert!(yaml.contains("agents:"));
        assert!(yaml.contains("name: test-agent"));
        assert!(yaml.contains("tools:"));
        assert!(yaml.contains("name: test-tool"));
    }
}
