//! Data Pipeline template - ETL agent for data processing

use super::{object_schema, Template};
use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};

/// Get the data-pipeline template
pub fn template() -> Template {
    Template::new(
        "data-pipeline",
        "Data Processing",
        "ETL agent for data pipelines",
        1, // 1 agent
        4, // 4 tools
        config,
    )
}

fn config() -> XavyoConfig {
    XavyoConfig {
        version: "1".to_string(),
        agents: vec![AgentConfig {
            name: "etl-agent".to_string(),
            agent_type: "workflow".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "medium".to_string(),
            description: Some("ETL agent for automated data pipeline operations".to_string()),
            tools: vec![
                "extract_data".to_string(),
                "transform_data".to_string(),
                "load_data".to_string(),
                "send_notification".to_string(),
            ],
        }],
        tools: vec![
            ToolConfig {
                name: "extract_data".to_string(),
                description: "Extract data from a source system".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("source", "string", true),
                    ("query", "string", true),
                    ("format", "string", false),
                ]),
            },
            ToolConfig {
                name: "transform_data".to_string(),
                description: "Transform data according to rules".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("data_id", "string", true),
                    ("transformation", "string", true),
                    ("validate", "boolean", false),
                ]),
            },
            ToolConfig {
                name: "load_data".to_string(),
                description: "Load transformed data into a target system".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("target", "string", true),
                    ("data_id", "string", true),
                    ("mode", "string", false),
                ]),
            },
            ToolConfig {
                name: "send_notification".to_string(),
                description: "Send pipeline completion notification".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("channel", "string", true),
                    ("message", "string", true),
                    ("status", "string", false),
                ]),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_metadata() {
        let t = template();
        assert_eq!(t.name, "data-pipeline");
        assert_eq!(t.category, "Data Processing");
        assert_eq!(t.agent_count, 1);
        assert_eq!(t.tool_count, 4);
    }

    #[test]
    fn test_config_agents() {
        let cfg = config();
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents[0].name, "etl-agent");
        assert_eq!(cfg.agents[0].agent_type, "workflow");
        assert_eq!(cfg.agents[0].risk_level, "medium");
    }

    #[test]
    fn test_config_tools() {
        let cfg = config();
        assert_eq!(cfg.tools.len(), 4);
        let tool_names: Vec<_> = cfg.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"extract_data"));
        assert!(tool_names.contains(&"transform_data"));
        assert!(tool_names.contains(&"load_data"));
        assert!(tool_names.contains(&"send_notification"));
    }

    #[test]
    fn test_agent_tool_references_exist() {
        let cfg = config();
        let tool_names: Vec<_> = cfg.tools.iter().map(|t| t.name.as_str()).collect();
        for agent in &cfg.agents {
            for tool_ref in &agent.tools {
                assert!(
                    tool_names.contains(&tool_ref.as_str()),
                    "Agent {} references non-existent tool {}",
                    agent.name,
                    tool_ref
                );
            }
        }
    }

    #[test]
    fn test_workflow_agent_type() {
        let cfg = config();
        assert_eq!(cfg.agents[0].agent_type, "workflow");
    }
}
