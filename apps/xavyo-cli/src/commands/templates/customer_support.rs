//! Customer Support template - Support bot with CRM integration

use super::{object_schema, Template};
use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};

/// Get the customer-support template
pub fn template() -> Template {
    Template::new(
        "customer-support",
        "Customer Service",
        "Support bot with CRM integration",
        1, // 1 agent
        4, // 4 tools
        config,
    )
}

fn config() -> XavyoConfig {
    XavyoConfig {
        version: "1".to_string(),
        agents: vec![AgentConfig {
            name: "support-bot".to_string(),
            agent_type: "copilot".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "medium".to_string(),
            description: Some("Customer support bot with CRM access".to_string()),
            tools: vec![
                "read_customer".to_string(),
                "create_ticket".to_string(),
                "send_email".to_string(),
                "search_knowledge_base".to_string(),
            ],
        }],
        tools: vec![
            ToolConfig {
                name: "read_customer".to_string(),
                description: "Read customer information from CRM".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("customer_id", "string", true),
                    ("include_history", "boolean", false),
                ]),
            },
            ToolConfig {
                name: "create_ticket".to_string(),
                description: "Create a support ticket in the helpdesk system".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("customer_id", "string", true),
                    ("subject", "string", true),
                    ("description", "string", true),
                    ("priority", "string", false),
                ]),
            },
            ToolConfig {
                name: "send_email".to_string(),
                description: "Send an email to a customer".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("to", "string", true),
                    ("subject", "string", true),
                    ("body", "string", true),
                    ("template_id", "string", false),
                ]),
            },
            ToolConfig {
                name: "search_knowledge_base".to_string(),
                description: "Search the knowledge base for articles".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("query", "string", true),
                    ("limit", "integer", false),
                    ("category", "string", false),
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
        assert_eq!(t.name, "customer-support");
        assert_eq!(t.category, "Customer Service");
        assert_eq!(t.agent_count, 1);
        assert_eq!(t.tool_count, 4);
    }

    #[test]
    fn test_config_agents() {
        let cfg = config();
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents[0].name, "support-bot");
        assert_eq!(cfg.agents[0].agent_type, "copilot");
        assert_eq!(cfg.agents[0].risk_level, "medium");
    }

    #[test]
    fn test_config_tools() {
        let cfg = config();
        assert_eq!(cfg.tools.len(), 4);
        let tool_names: Vec<_> = cfg.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"read_customer"));
        assert!(tool_names.contains(&"create_ticket"));
        assert!(tool_names.contains(&"send_email"));
        assert!(tool_names.contains(&"search_knowledge_base"));
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
