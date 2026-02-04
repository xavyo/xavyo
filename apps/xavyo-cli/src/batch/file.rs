//! Batch file parsing for YAML batch operations
//!
//! Parses YAML files containing batch definitions for agents and tools.

use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

/// Maximum number of items allowed in a batch file
pub const MAX_BATCH_ITEMS: usize = 1000;

/// Batch file containing resource definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFile {
    /// List of agent definitions
    #[serde(default)]
    pub agents: Vec<AgentBatchEntry>,
    /// List of tool definitions
    #[serde(default)]
    pub tools: Vec<ToolBatchEntry>,
}

impl BatchFile {
    /// Parse a batch file from YAML string
    pub fn from_yaml(yaml: &str) -> CliResult<Self> {
        let batch: BatchFile = serde_yaml::from_str(yaml)
            .map_err(|e| CliError::Validation(format!("Invalid YAML: {}", e)))?;

        batch.validate()?;
        Ok(batch)
    }

    /// Load a batch file from disk
    pub fn from_path(path: &Path) -> CliResult<Self> {
        if !path.exists() {
            return Err(CliError::Validation(format!(
                "Batch file not found: {}",
                path.display()
            )));
        }

        let content = fs::read_to_string(path)
            .map_err(|e| CliError::Validation(format!("Failed to read batch file: {}", e)))?;

        Self::from_yaml(&content)
    }

    /// Validate the batch file contents
    fn validate(&self) -> CliResult<()> {
        // Check that at least one list has items
        if self.agents.is_empty() && self.tools.is_empty() {
            return Err(CliError::Validation(
                "Batch file must contain at least one agent or tool definition".to_string(),
            ));
        }

        // Check total item count
        let total_items = self.agents.len() + self.tools.len();
        if total_items > MAX_BATCH_ITEMS {
            return Err(CliError::Validation(format!(
                "Batch file contains {} items, maximum is {}",
                total_items, MAX_BATCH_ITEMS
            )));
        }

        // Validate each agent entry
        for (i, agent) in self.agents.iter().enumerate() {
            agent.validate().map_err(|e| {
                CliError::Validation(format!(
                    "Agent entry {} ({}): {}",
                    i + 1,
                    agent.name_or_id(),
                    e
                ))
            })?;
        }

        // Validate each tool entry
        for (i, tool) in self.tools.iter().enumerate() {
            tool.validate().map_err(|e| {
                CliError::Validation(format!(
                    "Tool entry {} ({}): {}",
                    i + 1,
                    tool.name_or_id(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Get total number of items
    #[allow(dead_code)]
    pub fn total_items(&self) -> usize {
        self.agents.len() + self.tools.len()
    }
}

/// Single agent definition within a batch file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBatchEntry {
    /// Agent ID (required for updates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Agent name (required for creates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Agent type: copilot, autonomous, workflow, orchestrator
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Risk level: low, medium, high, critical
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// AI model provider (e.g., anthropic, openai)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    /// AI model name (e.g., claude-sonnet-4)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Agent description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl AgentBatchEntry {
    /// Get name or ID for display purposes
    pub fn name_or_id(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.id.map(|id| id.to_string()))
            .unwrap_or_else(|| "<unnamed>".to_string())
    }

    /// Validate the entry for create operations
    pub fn validate_for_create(&self) -> CliResult<()> {
        // Name is required for create
        let name = self.name.as_ref().ok_or_else(|| {
            CliError::Validation("Agent name is required for create operations".to_string())
        })?;

        // Validate name format
        validate_name(name)?;

        // Type is required for create
        let agent_type = self.agent_type.as_ref().ok_or_else(|| {
            CliError::Validation("Agent type is required for create operations".to_string())
        })?;
        validate_agent_type(agent_type)?;

        // Risk level is required for create
        let risk_level = self.risk_level.as_ref().ok_or_else(|| {
            CliError::Validation("Risk level is required for create operations".to_string())
        })?;
        validate_risk_level(risk_level)?;

        Ok(())
    }

    /// Validate the entry for update operations
    pub fn validate_for_update(&self) -> CliResult<()> {
        // ID is required for update
        if self.id.is_none() {
            return Err(CliError::Validation(
                "Agent ID is required for update operations".to_string(),
            ));
        }

        // If agent_type is provided, validate it
        if let Some(ref agent_type) = self.agent_type {
            validate_agent_type(agent_type)?;
        }

        // If risk_level is provided, validate it
        if let Some(ref risk_level) = self.risk_level {
            validate_risk_level(risk_level)?;
        }

        Ok(())
    }

    /// Basic validation (common for both create and update during parsing)
    fn validate(&self) -> CliResult<()> {
        // Validate name format if present
        if let Some(ref name) = self.name {
            validate_name(name)?;
        }

        // Validate agent_type if present
        if let Some(ref agent_type) = self.agent_type {
            validate_agent_type(agent_type)?;
        }

        // Validate risk_level if present
        if let Some(ref risk_level) = self.risk_level {
            validate_risk_level(risk_level)?;
        }

        Ok(())
    }
}

/// Single tool definition within a batch file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBatchEntry {
    /// Tool ID (required for updates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Tool name (required for creates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Risk level: low, medium, high, critical
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// JSON Schema for tool input parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// Tool description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tool category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Whether tool requires approval
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
}

impl ToolBatchEntry {
    /// Get name or ID for display purposes
    pub fn name_or_id(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.id.map(|id| id.to_string()))
            .unwrap_or_else(|| "<unnamed>".to_string())
    }

    /// Validate the entry for create operations
    pub fn validate_for_create(&self) -> CliResult<()> {
        // Name is required for create
        let name = self.name.as_ref().ok_or_else(|| {
            CliError::Validation("Tool name is required for create operations".to_string())
        })?;

        // Validate name format
        validate_name(name)?;

        // Risk level is required for create
        let risk_level = self.risk_level.as_ref().ok_or_else(|| {
            CliError::Validation("Risk level is required for create operations".to_string())
        })?;
        validate_risk_level(risk_level)?;

        Ok(())
    }

    /// Validate the entry for update operations
    pub fn validate_for_update(&self) -> CliResult<()> {
        // ID is required for update
        if self.id.is_none() {
            return Err(CliError::Validation(
                "Tool ID is required for update operations".to_string(),
            ));
        }

        // If risk_level is provided, validate it
        if let Some(ref risk_level) = self.risk_level {
            validate_risk_level(risk_level)?;
        }

        Ok(())
    }

    /// Basic validation (common for both create and update during parsing)
    fn validate(&self) -> CliResult<()> {
        // Validate name format if present
        if let Some(ref name) = self.name {
            validate_name(name)?;
        }

        // Validate risk_level if present
        if let Some(ref risk_level) = self.risk_level {
            validate_risk_level(risk_level)?;
        }

        Ok(())
    }
}

/// Validate resource name format
fn validate_name(name: &str) -> CliResult<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(CliError::Validation(
            "Name must be 1-64 characters".to_string(),
        ));
    }

    // Must start with alphanumeric
    let first_char = name.chars().next().unwrap();
    if !first_char.is_alphanumeric() {
        return Err(CliError::Validation(
            "Name must start with a letter or number".to_string(),
        ));
    }

    // Only alphanumeric, hyphens, and underscores allowed
    for ch in name.chars() {
        if !ch.is_alphanumeric() && ch != '-' && ch != '_' {
            return Err(CliError::Validation(
                "Name can only contain alphanumeric characters, hyphens, and underscores"
                    .to_string(),
            ));
        }
    }

    // Check for consecutive hyphens
    if name.contains("--") {
        return Err(CliError::Validation(
            "Name cannot contain consecutive hyphens".to_string(),
        ));
    }

    Ok(())
}

/// Validate agent type
fn validate_agent_type(agent_type: &str) -> CliResult<()> {
    match agent_type {
        "copilot" | "autonomous" | "workflow" | "orchestrator" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid agent type '{}'. Must be one of: copilot, autonomous, workflow, orchestrator",
            agent_type
        ))),
    }
}

/// Validate risk level
fn validate_risk_level(risk_level: &str) -> CliResult<()> {
    match risk_level {
        "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid risk level '{}'. Must be one of: low, medium, high, critical",
            risk_level
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_file_from_yaml_agents() {
        let yaml = r#"
agents:
  - name: agent-1
    type: copilot
    risk_level: low
  - name: agent-2
    type: autonomous
    risk_level: medium
    description: Test agent
"#;

        let batch = BatchFile::from_yaml(yaml).unwrap();
        assert_eq!(batch.agents.len(), 2);
        assert!(batch.tools.is_empty());
        assert_eq!(batch.agents[0].name, Some("agent-1".to_string()));
        assert_eq!(batch.agents[0].agent_type, Some("copilot".to_string()));
        assert_eq!(batch.agents[1].description, Some("Test agent".to_string()));
    }

    #[test]
    fn test_batch_file_from_yaml_tools() {
        let yaml = r#"
tools:
  - name: tool-1
    risk_level: low
    description: A test tool
  - name: tool-2
    risk_level: high
    requires_approval: true
"#;

        let batch = BatchFile::from_yaml(yaml).unwrap();
        assert!(batch.agents.is_empty());
        assert_eq!(batch.tools.len(), 2);
        assert_eq!(batch.tools[0].name, Some("tool-1".to_string()));
        assert_eq!(batch.tools[1].requires_approval, Some(true));
    }

    #[test]
    fn test_batch_file_from_yaml_mixed() {
        let yaml = r#"
agents:
  - name: my-agent
    type: workflow
    risk_level: low
tools:
  - name: my-tool
    risk_level: medium
"#;

        let batch = BatchFile::from_yaml(yaml).unwrap();
        assert_eq!(batch.agents.len(), 1);
        assert_eq!(batch.tools.len(), 1);
        assert_eq!(batch.total_items(), 2);
    }

    #[test]
    fn test_batch_file_empty_error() {
        let yaml = r#"
agents: []
tools: []
"#;

        let result = BatchFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one"));
    }

    #[test]
    fn test_batch_file_invalid_yaml() {
        let yaml = "not: valid: yaml: [";

        let result = BatchFile::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_batch_entry_validate_for_create() {
        let valid = AgentBatchEntry {
            id: None,
            name: Some("test-agent".to_string()),
            agent_type: Some("copilot".to_string()),
            risk_level: Some("low".to_string()),
            model_provider: None,
            model_name: None,
            description: None,
        };

        assert!(valid.validate_for_create().is_ok());

        // Missing name
        let no_name = AgentBatchEntry {
            name: None,
            ..valid.clone()
        };
        assert!(no_name.validate_for_create().is_err());

        // Missing type
        let no_type = AgentBatchEntry {
            agent_type: None,
            ..valid.clone()
        };
        assert!(no_type.validate_for_create().is_err());

        // Missing risk level
        let no_risk = AgentBatchEntry {
            risk_level: None,
            ..valid.clone()
        };
        assert!(no_risk.validate_for_create().is_err());
    }

    #[test]
    fn test_agent_batch_entry_validate_for_update() {
        let valid = AgentBatchEntry {
            id: Some(Uuid::new_v4()),
            name: None,
            agent_type: None,
            risk_level: Some("high".to_string()),
            model_provider: None,
            model_name: None,
            description: Some("Updated description".to_string()),
        };

        assert!(valid.validate_for_update().is_ok());

        // Missing ID
        let no_id = AgentBatchEntry {
            id: None,
            ..valid.clone()
        };
        assert!(no_id.validate_for_update().is_err());
    }

    #[test]
    fn test_tool_batch_entry_validate_for_create() {
        let valid = ToolBatchEntry {
            id: None,
            name: Some("test-tool".to_string()),
            risk_level: Some("low".to_string()),
            input_schema: None,
            description: None,
            category: None,
            requires_approval: None,
        };

        assert!(valid.validate_for_create().is_ok());

        // Missing name
        let no_name = ToolBatchEntry {
            name: None,
            ..valid.clone()
        };
        assert!(no_name.validate_for_create().is_err());

        // Missing risk level
        let no_risk = ToolBatchEntry {
            risk_level: None,
            ..valid.clone()
        };
        assert!(no_risk.validate_for_create().is_err());
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("my-agent").is_ok());
        assert!(validate_name("agent_1").is_ok());
        assert!(validate_name("Agent123").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("1agent").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        // Empty
        assert!(validate_name("").is_err());

        // Too long
        let long_name = "a".repeat(65);
        assert!(validate_name(&long_name).is_err());

        // Starts with hyphen
        assert!(validate_name("-agent").is_err());

        // Starts with underscore
        assert!(validate_name("_agent").is_err());

        // Contains space
        assert!(validate_name("my agent").is_err());

        // Contains special chars
        assert!(validate_name("my@agent").is_err());

        // Consecutive hyphens
        assert!(validate_name("my--agent").is_err());
    }

    #[test]
    fn test_validate_agent_type() {
        assert!(validate_agent_type("copilot").is_ok());
        assert!(validate_agent_type("autonomous").is_ok());
        assert!(validate_agent_type("workflow").is_ok());
        assert!(validate_agent_type("orchestrator").is_ok());
        assert!(validate_agent_type("invalid").is_err());
        assert!(validate_agent_type("COPILOT").is_err());
    }

    #[test]
    fn test_validate_risk_level() {
        assert!(validate_risk_level("low").is_ok());
        assert!(validate_risk_level("medium").is_ok());
        assert!(validate_risk_level("high").is_ok());
        assert!(validate_risk_level("critical").is_ok());
        assert!(validate_risk_level("invalid").is_err());
        assert!(validate_risk_level("LOW").is_err());
    }

    #[test]
    fn test_agent_batch_entry_name_or_id() {
        let with_name = AgentBatchEntry {
            id: Some(Uuid::new_v4()),
            name: Some("test-agent".to_string()),
            agent_type: None,
            risk_level: None,
            model_provider: None,
            model_name: None,
            description: None,
        };
        assert_eq!(with_name.name_or_id(), "test-agent");

        let id = Uuid::new_v4();
        let with_id = AgentBatchEntry {
            id: Some(id),
            name: None,
            agent_type: None,
            risk_level: None,
            model_provider: None,
            model_name: None,
            description: None,
        };
        assert_eq!(with_id.name_or_id(), id.to_string());

        let neither = AgentBatchEntry {
            id: None,
            name: None,
            agent_type: None,
            risk_level: None,
            model_provider: None,
            model_name: None,
            description: None,
        };
        assert_eq!(neither.name_or_id(), "<unnamed>");
    }
}
