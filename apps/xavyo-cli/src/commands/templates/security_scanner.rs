//! Security Scanner template - Autonomous security scanning agent

use super::{object_schema, Template};
use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};

/// Get the security-scanner template
pub fn template() -> Template {
    Template::new(
        "security-scanner",
        "Security",
        "Autonomous security scanning agent",
        1, // 1 agent
        3, // 3 tools
        config,
    )
}

fn config() -> XavyoConfig {
    XavyoConfig {
        version: "1".to_string(),
        agents: vec![AgentConfig {
            name: "security-scanner".to_string(),
            agent_type: "autonomous".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "high".to_string(),
            description: Some(
                "Autonomous security scanner that requires human approval for actions".to_string(),
            ),
            tools: vec![
                "scan_vulnerabilities".to_string(),
                "create_alert".to_string(),
                "generate_report".to_string(),
            ],
        }],
        tools: vec![
            ToolConfig {
                name: "scan_vulnerabilities".to_string(),
                description: "Scan a target for security vulnerabilities".to_string(),
                risk_level: "high".to_string(),
                input_schema: object_schema(&[
                    ("target", "string", true),
                    ("scan_type", "string", false),
                    ("depth", "string", false),
                ]),
            },
            ToolConfig {
                name: "create_alert".to_string(),
                description: "Create a security alert for detected issues".to_string(),
                risk_level: "medium".to_string(),
                input_schema: object_schema(&[
                    ("severity", "string", true),
                    ("title", "string", true),
                    ("description", "string", true),
                    ("affected_systems", "string", false),
                ]),
            },
            ToolConfig {
                name: "generate_report".to_string(),
                description: "Generate a security assessment report".to_string(),
                risk_level: "low".to_string(),
                input_schema: object_schema(&[
                    ("scan_id", "string", true),
                    ("format", "string", false),
                    ("include_remediation", "boolean", false),
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
        assert_eq!(t.name, "security-scanner");
        assert_eq!(t.category, "Security");
        assert_eq!(t.agent_count, 1);
        assert_eq!(t.tool_count, 3);
    }

    #[test]
    fn test_config_agents() {
        let cfg = config();
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents[0].name, "security-scanner");
        assert_eq!(cfg.agents[0].agent_type, "autonomous");
        assert_eq!(cfg.agents[0].risk_level, "high");
    }

    #[test]
    fn test_config_tools() {
        let cfg = config();
        assert_eq!(cfg.tools.len(), 3);
        let tool_names: Vec<_> = cfg.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"scan_vulnerabilities"));
        assert!(tool_names.contains(&"create_alert"));
        assert!(tool_names.contains(&"generate_report"));
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
    fn test_high_risk_agent() {
        let cfg = config();
        // Security scanner is high risk, should require approval
        assert_eq!(cfg.agents[0].risk_level, "high");
    }
}
