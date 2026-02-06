//! JSON format handling for import/export
//!
//! Provides JSON serialization/deserialization for XavyoConfig.
//! Uses the same structure as YAML for full round-trip compatibility.

use crate::error::{CliError, CliResult};
use crate::models::config::XavyoConfig;

/// Export configuration to JSON format with pretty-printing
///
/// # Arguments
/// * `config` - The configuration to export
///
/// # Returns
/// * `Ok(String)` - Pretty-printed JSON string
/// * `Err(CliError)` - If serialization fails
pub fn export_json(config: &XavyoConfig) -> CliResult<String> {
    serde_json::to_string_pretty(config)
        .map_err(|e| CliError::Validation(format!("Failed to serialize JSON: {}", e)))
}

/// Import configuration from JSON string
///
/// # Arguments
/// * `content` - JSON string content
///
/// # Returns
/// * `Ok(XavyoConfig)` - Parsed configuration
/// * `Err(CliError)` - If parsing fails with detailed error message
pub fn import_json(content: &str) -> CliResult<XavyoConfig> {
    serde_json::from_str(content).map_err(|e| {
        // Extract line/column info if available
        let location = format!(" at line {}, column {}", e.line(), e.column());
        CliError::Validation(format!("JSON parse error{}: {}", location, e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::{AgentConfig, ToolConfig};

    #[test]
    fn test_export_json_empty() {
        let config = XavyoConfig::default();
        let json = export_json(&config).unwrap();

        assert!(json.contains("\"version\": \"1\""));
        // Empty arrays should still be present or omitted based on serde config
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "1");
    }

    #[test]
    fn test_export_json_with_agents() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude-sonnet-4".to_string(),
                risk_level: "low".to_string(),
                description: Some("Test agent".to_string()),
                tools: vec![],
            }],
            tools: vec![],
        };

        let json = export_json(&config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["agents"][0]["name"], "test-agent");
        assert_eq!(parsed["agents"][0]["agent_type"], "copilot");
        assert_eq!(parsed["agents"][0]["model_provider"], "anthropic");
    }

    #[test]
    fn test_export_json_with_tools() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![ToolConfig {
                name: "test-tool".to_string(),
                description: "Test tool".to_string(),
                risk_level: "medium".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "input": {"type": "string"}
                    }
                }),
            }],
        };

        let json = export_json(&config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["tools"][0]["name"], "test-tool");
        assert_eq!(parsed["tools"][0]["risk_level"], "medium");
        assert_eq!(parsed["tools"][0]["input_schema"]["type"], "object");
    }

    #[test]
    fn test_import_json_basic() {
        let json = r#"{
            "version": "1",
            "agents": [
                {
                    "name": "imported-agent",
                    "agent_type": "autonomous",
                    "model_provider": "openai",
                    "model_name": "gpt-4",
                    "risk_level": "medium"
                }
            ],
            "tools": []
        }"#;

        let config = import_json(json).unwrap();
        assert_eq!(config.version, "1");
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "imported-agent");
        assert_eq!(config.agents[0].agent_type, "autonomous");
    }

    #[test]
    fn test_import_json_with_tools() {
        let json = r#"{
            "version": "1",
            "agents": [],
            "tools": [
                {
                    "name": "weather-tool",
                    "description": "Gets weather data",
                    "risk_level": "low",
                    "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}
                }
            ]
        }"#;

        let config = import_json(json).unwrap();
        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].name, "weather-tool");
        assert_eq!(config.tools[0].input_schema["type"], "object");
    }

    #[test]
    fn test_import_json_invalid_syntax() {
        let json = "{invalid json}";
        let result = import_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("JSON parse error"));
        assert!(err.contains("line"));
    }

    #[test]
    fn test_import_json_missing_required_field() {
        let json = r#"{"version": "1", "agents": [{"name": "test"}]}"#;
        let result = import_json(json);
        assert!(result.is_err());
        // Should fail because agent_type is missing
    }

    #[test]
    fn test_json_roundtrip() {
        let original = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "roundtrip-agent".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude-sonnet-4".to_string(),
                risk_level: "high".to_string(),
                description: Some("Description with \"quotes\" and special chars".to_string()),
                tools: vec!["tool1".to_string(), "tool2".to_string()],
            }],
            tools: vec![ToolConfig {
                name: "roundtrip-tool".to_string(),
                description: "Tool description".to_string(),
                risk_level: "critical".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["param1"],
                    "properties": {
                        "param1": {"type": "string"},
                        "param2": {"type": "integer"}
                    }
                }),
            }],
        };

        let json = export_json(&original).unwrap();
        let imported = import_json(&json).unwrap();

        assert_eq!(original.version, imported.version);
        assert_eq!(original.agents.len(), imported.agents.len());
        assert_eq!(original.tools.len(), imported.tools.len());
        assert_eq!(original.agents[0], imported.agents[0]);
        assert_eq!(original.tools[0], imported.tools[0]);
    }

    #[test]
    fn test_export_json_pretty_formatted() {
        let config = XavyoConfig::default();
        let json = export_json(&config).unwrap();

        // Pretty-printed JSON should have newlines
        assert!(json.contains('\n'));
        // Should have indentation
        assert!(json.contains("  "));
    }
}
