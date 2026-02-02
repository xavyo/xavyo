//! SaaS Startup template - Basic setup for SaaS applications

use super::{object_schema, Template};
use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};

/// Get the saas-startup template
pub fn template() -> Template {
    Template::new(
        "saas-startup",
        "General",
        "Basic setup for SaaS applications",
        1, // 1 agent
        3, // 3 tools
        config,
    )
}

fn config() -> XavyoConfig {
    XavyoConfig {
        version: "1".to_string(),
        agents: vec![AgentConfig {
            name: "api-assistant".to_string(),
            agent_type: "copilot".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "low".to_string(),
            description: Some("General-purpose API assistant for SaaS applications".to_string()),
            tools: vec![
                "read_database".to_string(),
                "send_notification".to_string(),
                "update_cache".to_string(),
            ],
        }],
        tools: vec![
            ToolConfig {
                name: "read_database".to_string(),
                description: "Read data from the application database".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("query", "string", true),
                    ("limit", "integer", false),
                ]),
            },
            ToolConfig {
                name: "send_notification".to_string(),
                description: "Send a notification to a user".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("user_id", "string", true),
                    ("message", "string", true),
                    ("channel", "string", false),
                ]),
            },
            ToolConfig {
                name: "update_cache".to_string(),
                description: "Update a cache entry".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("key", "string", true),
                    ("value", "string", true),
                    ("ttl", "integer", false),
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
        assert_eq!(t.name, "saas-startup");
        assert_eq!(t.category, "General");
        assert_eq!(t.agent_count, 1);
        assert_eq!(t.tool_count, 3);
    }

    #[test]
    fn test_config_agents() {
        let cfg = config();
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents[0].name, "api-assistant");
        assert_eq!(cfg.agents[0].agent_type, "copilot");
        assert_eq!(cfg.agents[0].risk_level, "low");
    }

    #[test]
    fn test_config_tools() {
        let cfg = config();
        assert_eq!(cfg.tools.len(), 3);
        let tool_names: Vec<_> = cfg.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"read_database"));
        assert!(tool_names.contains(&"send_notification"));
        assert!(tool_names.contains(&"update_cache"));
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
}
