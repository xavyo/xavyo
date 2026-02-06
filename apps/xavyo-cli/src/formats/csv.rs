//! CSV format handling for import/export of agents and tools
//!
//! CSV format is designed for bulk management via spreadsheets:
//! - Agents: name, agent_type, model_provider, model_name, risk_level, description
//! - Tools: name, description, risk_level, input_schema (as JSON string)

use crate::error::{CliError, CliResult};
use crate::models::config::{AgentConfig, ToolConfig};
use serde::{Deserialize, Serialize};
use std::io::Write;

/// CSV record for agent data
///
/// Maps to AgentConfig with flat structure suitable for spreadsheet editing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CsvAgentRecord {
    /// Unique agent name
    pub name: String,
    /// Agent type: copilot, autonomous, workflow, orchestrator
    pub agent_type: String,
    /// AI provider: anthropic, openai, etc.
    pub model_provider: String,
    /// Model identifier: claude-sonnet-4, gpt-4, etc.
    pub model_name: String,
    /// Risk classification: low, medium, high, critical
    pub risk_level: String,
    /// Human-readable description (optional)
    #[serde(default)]
    pub description: String,
}

impl From<&AgentConfig> for CsvAgentRecord {
    fn from(agent: &AgentConfig) -> Self {
        Self {
            name: agent.name.clone(),
            agent_type: agent.agent_type.clone(),
            model_provider: agent.model_provider.clone(),
            model_name: agent.model_name.clone(),
            risk_level: agent.risk_level.clone(),
            description: agent.description.clone().unwrap_or_default(),
        }
    }
}

impl From<CsvAgentRecord> for AgentConfig {
    fn from(record: CsvAgentRecord) -> Self {
        Self {
            name: record.name,
            agent_type: record.agent_type,
            model_provider: record.model_provider,
            model_name: record.model_name,
            risk_level: record.risk_level,
            description: if record.description.is_empty() {
                None
            } else {
                Some(record.description)
            },
            tools: vec![],
        }
    }
}

/// CSV record for tool data
///
/// Maps to ToolConfig with input_schema as JSON string for CSV compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CsvToolRecord {
    /// Unique tool name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Risk classification: low, medium, high, critical
    pub risk_level: String,
    /// JSON-serialized input schema
    pub input_schema: String,
}

impl TryFrom<&ToolConfig> for CsvToolRecord {
    type Error = CliError;

    fn try_from(tool: &ToolConfig) -> Result<Self, Self::Error> {
        let input_schema = serde_json::to_string(&tool.input_schema).map_err(|e| {
            CliError::Validation(format!("Failed to serialize input_schema: {}", e))
        })?;

        Ok(Self {
            name: tool.name.clone(),
            description: tool.description.clone(),
            risk_level: tool.risk_level.clone(),
            input_schema,
        })
    }
}

impl TryFrom<CsvToolRecord> for ToolConfig {
    type Error = CliError;

    fn try_from(record: CsvToolRecord) -> Result<Self, Self::Error> {
        let input_schema: serde_json::Value =
            serde_json::from_str(&record.input_schema).map_err(|e| {
                CliError::Validation(format!(
                    "Invalid JSON in input_schema for tool '{}': {}",
                    record.name, e
                ))
            })?;

        Ok(Self {
            name: record.name,
            description: record.description,
            risk_level: record.risk_level,
            input_schema,
        })
    }
}

/// Export agents to CSV format
///
/// # Arguments
/// * `agents` - List of agent configurations
/// * `writer` - Output writer (file or stdout)
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(CliError)` - If serialization fails
pub fn export_agents_csv<W: Write>(agents: &[AgentConfig], writer: W) -> CliResult<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    for agent in agents {
        let record = CsvAgentRecord::from(agent);
        wtr.serialize(&record)
            .map_err(|e| CliError::Validation(format!("CSV write error: {}", e)))?;
    }

    wtr.flush()
        .map_err(|e| CliError::Io(format!("Failed to flush CSV: {}", e)))?;

    Ok(())
}

/// Export tools to CSV format
///
/// # Arguments
/// * `tools` - List of tool configurations
/// * `writer` - Output writer (file or stdout)
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(CliError)` - If serialization fails
pub fn export_tools_csv<W: Write>(tools: &[ToolConfig], writer: W) -> CliResult<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    for tool in tools {
        let record = CsvToolRecord::try_from(tool)?;
        wtr.serialize(&record)
            .map_err(|e| CliError::Validation(format!("CSV write error: {}", e)))?;
    }

    wtr.flush()
        .map_err(|e| CliError::Io(format!("Failed to flush CSV: {}", e)))?;

    Ok(())
}

/// Result of importing agents from CSV
pub struct CsvAgentImportResult {
    /// Successfully parsed agents
    pub agents: Vec<AgentConfig>,
    /// Errors encountered during parsing (line number, error message)
    pub errors: Vec<(usize, String)>,
}

/// Result of importing tools from CSV
pub struct CsvToolImportResult {
    /// Successfully parsed tools
    pub tools: Vec<ToolConfig>,
    /// Errors encountered during parsing (line number, error message)
    pub errors: Vec<(usize, String)>,
}

/// Import agents from CSV content
///
/// Processes all rows and collects errors for reporting.
///
/// # Arguments
/// * `content` - CSV string content
///
/// # Returns
/// * `CsvAgentImportResult` - Successfully parsed agents and any errors
pub fn import_agents_csv(content: &str) -> CsvAgentImportResult {
    let mut agents = Vec::new();
    let mut errors = Vec::new();

    let mut rdr = csv::Reader::from_reader(content.as_bytes());

    // Check headers
    if let Ok(headers) = rdr.headers() {
        let required = [
            "name",
            "agent_type",
            "model_provider",
            "model_name",
            "risk_level",
        ];
        let header_set: std::collections::HashSet<_> = headers.iter().collect();
        let missing: Vec<_> = required
            .iter()
            .filter(|h| !header_set.contains(*h))
            .collect();

        if !missing.is_empty() {
            errors.push((
                1,
                format!(
                    "CSV missing required columns: {}",
                    missing
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
            return CsvAgentImportResult { agents, errors };
        }
    }

    for (idx, result) in rdr.deserialize::<CsvAgentRecord>().enumerate() {
        let line_num = idx + 2; // +1 for 0-index, +1 for header
        match result {
            Ok(record) => {
                // Validate the record
                if let Err(e) = validate_agent_record(&record) {
                    errors.push((line_num, e));
                } else {
                    agents.push(record.into());
                }
            }
            Err(e) => {
                errors.push((line_num, format!("CSV parse error: {}", e)));
            }
        }
    }

    CsvAgentImportResult { agents, errors }
}

/// Import tools from CSV content
///
/// Processes all rows and collects errors for reporting.
///
/// # Arguments
/// * `content` - CSV string content
///
/// # Returns
/// * `CsvToolImportResult` - Successfully parsed tools and any errors
pub fn import_tools_csv(content: &str) -> CsvToolImportResult {
    let mut tools = Vec::new();
    let mut errors = Vec::new();

    let mut rdr = csv::Reader::from_reader(content.as_bytes());

    // Check headers
    if let Ok(headers) = rdr.headers() {
        let required = ["name", "description", "risk_level", "input_schema"];
        let header_set: std::collections::HashSet<_> = headers.iter().collect();
        let missing: Vec<_> = required
            .iter()
            .filter(|h| !header_set.contains(*h))
            .collect();

        if !missing.is_empty() {
            errors.push((
                1,
                format!(
                    "CSV missing required columns: {}",
                    missing
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
            return CsvToolImportResult { tools, errors };
        }
    }

    for (idx, result) in rdr.deserialize::<CsvToolRecord>().enumerate() {
        let line_num = idx + 2;
        match result {
            Ok(record) => {
                // Validate and convert
                if let Err(e) = validate_tool_record(&record) {
                    errors.push((line_num, e));
                } else {
                    match ToolConfig::try_from(record) {
                        Ok(tool) => tools.push(tool),
                        Err(e) => errors.push((line_num, e.to_string())),
                    }
                }
            }
            Err(e) => {
                errors.push((line_num, format!("CSV parse error: {}", e)));
            }
        }
    }

    CsvToolImportResult { tools, errors }
}

/// Validate an agent CSV record
fn validate_agent_record(record: &CsvAgentRecord) -> Result<(), String> {
    // Validate name
    if record.name.is_empty() {
        return Err("name is required".to_string());
    }
    if record.name.len() > 64 {
        return Err(format!("name '{}' exceeds 64 character limit", record.name));
    }

    // Validate agent_type
    match record.agent_type.as_str() {
        "copilot" | "autonomous" | "workflow" | "orchestrator" => {}
        _ => {
            return Err(format!(
                "Invalid agent_type '{}'. Must be one of: copilot, autonomous, workflow, orchestrator",
                record.agent_type
            ));
        }
    }

    // Validate risk_level
    match record.risk_level.as_str() {
        "low" | "medium" | "high" | "critical" => {}
        _ => {
            return Err(format!(
                "Invalid risk_level '{}'. Must be one of: low, medium, high, critical",
                record.risk_level
            ));
        }
    }

    Ok(())
}

/// Validate a tool CSV record
fn validate_tool_record(record: &CsvToolRecord) -> Result<(), String> {
    // Validate name
    if record.name.is_empty() {
        return Err("name is required".to_string());
    }
    if record.name.len() > 64 {
        return Err(format!("name '{}' exceeds 64 character limit", record.name));
    }

    // Validate risk_level
    match record.risk_level.as_str() {
        "low" | "medium" | "high" | "critical" => {}
        _ => {
            return Err(format!(
                "Invalid risk_level '{}'. Must be one of: low, medium, high, critical",
                record.risk_level
            ));
        }
    }

    // Validate input_schema is valid JSON
    if serde_json::from_str::<serde_json::Value>(&record.input_schema).is_err() {
        return Err(format!(
            "input_schema must be valid JSON for tool '{}'",
            record.name
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_agent_record_from_config() {
        let config = AgentConfig {
            name: "test-agent".to_string(),
            agent_type: "copilot".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "low".to_string(),
            description: Some("Test description".to_string()),
            tools: vec!["tool1".to_string()],
        };

        let record = CsvAgentRecord::from(&config);
        assert_eq!(record.name, "test-agent");
        assert_eq!(record.agent_type, "copilot");
        assert_eq!(record.description, "Test description");
    }

    #[test]
    fn test_csv_agent_record_to_config() {
        let record = CsvAgentRecord {
            name: "imported-agent".to_string(),
            agent_type: "autonomous".to_string(),
            model_provider: "openai".to_string(),
            model_name: "gpt-4".to_string(),
            risk_level: "medium".to_string(),
            description: String::new(),
        };

        let config: AgentConfig = record.into();
        assert_eq!(config.name, "imported-agent");
        assert!(config.description.is_none()); // Empty string becomes None
        assert!(config.tools.is_empty());
    }

    #[test]
    fn test_csv_tool_record_roundtrip() {
        let tool = ToolConfig {
            name: "test-tool".to_string(),
            description: "Test tool".to_string(),
            risk_level: "high".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"input": {"type": "string"}}
            }),
        };

        let record = CsvToolRecord::try_from(&tool).unwrap();
        let restored = ToolConfig::try_from(record).unwrap();

        assert_eq!(tool.name, restored.name);
        assert_eq!(tool.description, restored.description);
        assert_eq!(tool.risk_level, restored.risk_level);
        assert_eq!(tool.input_schema, restored.input_schema);
    }

    #[test]
    fn test_export_agents_csv() {
        let agents = vec![
            AgentConfig {
                name: "agent1".to_string(),
                agent_type: "copilot".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude-sonnet-4".to_string(),
                risk_level: "low".to_string(),
                description: Some("First agent".to_string()),
                tools: vec![],
            },
            AgentConfig {
                name: "agent2".to_string(),
                agent_type: "autonomous".to_string(),
                model_provider: "openai".to_string(),
                model_name: "gpt-4".to_string(),
                risk_level: "high".to_string(),
                description: None,
                tools: vec![],
            },
        ];

        let mut output = Vec::new();
        export_agents_csv(&agents, &mut output).unwrap();
        let csv_string = String::from_utf8(output).unwrap();

        assert!(
            csv_string.contains("name,agent_type,model_provider,model_name,risk_level,description")
        );
        assert!(csv_string.contains("agent1,copilot,anthropic,claude-sonnet-4,low,First agent"));
        assert!(csv_string.contains("agent2,autonomous,openai,gpt-4,high,"));
    }

    #[test]
    fn test_export_tools_csv() {
        let tools = vec![ToolConfig {
            name: "weather-tool".to_string(),
            description: "Gets weather data".to_string(),
            risk_level: "low".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }];

        let mut output = Vec::new();
        export_tools_csv(&tools, &mut output).unwrap();
        let csv_string = String::from_utf8(output).unwrap();

        assert!(csv_string.contains("name,description,risk_level,input_schema"));
        assert!(csv_string.contains("weather-tool"));
        assert!(csv_string.contains(r#""{""type"":""object""}""#));
    }

    #[test]
    fn test_import_agents_csv_basic() {
        let csv = r#"name,agent_type,model_provider,model_name,risk_level,description
test-agent,copilot,anthropic,claude-sonnet-4,low,Test agent
another,autonomous,openai,gpt-4,medium,
"#;

        let result = import_agents_csv(csv);
        assert!(result.errors.is_empty(), "Errors: {:?}", result.errors);
        assert_eq!(result.agents.len(), 2);
        assert_eq!(result.agents[0].name, "test-agent");
        assert_eq!(result.agents[1].name, "another");
    }

    #[test]
    fn test_import_agents_csv_missing_columns() {
        let csv = r#"name,agent_type
test,copilot
"#;

        let result = import_agents_csv(csv);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].1.contains("missing required columns"));
    }

    #[test]
    fn test_import_agents_csv_invalid_agent_type() {
        let csv = r#"name,agent_type,model_provider,model_name,risk_level,description
bad-agent,invalid_type,anthropic,claude,low,
"#;

        let result = import_agents_csv(csv);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].1.contains("Invalid agent_type"));
    }

    #[test]
    fn test_import_agents_csv_partial_failure() {
        let csv = r#"name,agent_type,model_provider,model_name,risk_level,description
good-agent,copilot,anthropic,claude-sonnet-4,low,
bad-agent,invalid,anthropic,claude,low,
another-good,autonomous,openai,gpt-4,medium,
"#;

        let result = import_agents_csv(csv);
        assert_eq!(result.agents.len(), 2); // Two good agents
        assert_eq!(result.errors.len(), 1); // One bad agent
        assert_eq!(result.errors[0].0, 3); // Line 3 (0-indexed line 1 + header + 1)
    }

    #[test]
    fn test_import_tools_csv_basic() {
        let csv = r#"name,description,risk_level,input_schema
test-tool,Test tool,low,"{""type"":""object""}"
"#;

        let result = import_tools_csv(csv);
        assert!(result.errors.is_empty(), "Errors: {:?}", result.errors);
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "test-tool");
    }

    #[test]
    fn test_import_tools_csv_invalid_json_schema() {
        let csv = r#"name,description,risk_level,input_schema
bad-tool,Test,low,{invalid json}
"#;

        let result = import_tools_csv(csv);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_csv_special_characters() {
        // Test RFC 4180 handling: commas, quotes, newlines in fields
        let csv = r#"name,agent_type,model_provider,model_name,risk_level,description
"agent,with,commas",copilot,anthropic,claude-sonnet-4,low,"Description with ""quotes"""
"#;

        let result = import_agents_csv(csv);
        assert!(result.errors.is_empty(), "Errors: {:?}", result.errors);
        assert_eq!(result.agents.len(), 1);
        assert_eq!(result.agents[0].name, "agent,with,commas");
        assert_eq!(
            result.agents[0].description,
            Some("Description with \"quotes\"".to_string())
        );
    }

    #[test]
    fn test_validate_agent_record_empty_name() {
        let record = CsvAgentRecord {
            name: String::new(),
            agent_type: "copilot".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude".to_string(),
            risk_level: "low".to_string(),
            description: String::new(),
        };

        assert!(validate_agent_record(&record).is_err());
    }

    #[test]
    fn test_validate_tool_record_invalid_risk() {
        let record = CsvToolRecord {
            name: "test".to_string(),
            description: "Test".to_string(),
            risk_level: "extreme".to_string(),
            input_schema: "{}".to_string(),
        };

        let err = validate_tool_record(&record).unwrap_err();
        assert!(err.contains("Invalid risk_level"));
    }
}
