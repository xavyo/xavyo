//! Configuration models for xavyo CLI apply/export commands

use serde::{Deserialize, Serialize};

/// Root configuration object for YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XavyoConfig {
    /// Config format version (e.g., "1")
    pub version: String,
    /// List of agent definitions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentConfig>,
    /// List of tool definitions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolConfig>,
}

impl Default for XavyoConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            agents: Vec::new(),
            tools: Vec::new(),
        }
    }
}

/// Agent definition in configuration file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    /// Unique agent name
    pub name: String,
    /// Agent type: "autonomous" or "copilot"
    pub agent_type: String,
    /// Provider: "anthropic", "openai", etc.
    pub model_provider: String,
    /// Model identifier
    pub model_name: String,
    /// Risk level: "low", "medium", "high"
    pub risk_level: String,
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// List of tool names to grant
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
}

/// Tool definition in configuration file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolConfig {
    /// Unique tool name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Risk level: "low", "medium", "high"
    pub risk_level: String,
    /// JSON Schema for input validation
    pub input_schema: serde_json::Value,
}

/// Action to be taken for a resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyAction {
    /// Resource will be created
    Create,
    /// Resource exists and will be updated
    Update,
    /// Resource exists and matches config
    Unchanged,
    /// Operation failed
    Failed,
}

impl ApplyAction {
    /// Returns the symbol for this action
    pub fn symbol(&self) -> &'static str {
        match self {
            ApplyAction::Create => "+",
            ApplyAction::Update => "~",
            ApplyAction::Unchanged => "=",
            ApplyAction::Failed => "✗",
        }
    }

    /// Returns the display name for this action
    pub fn display(&self) -> &'static str {
        match self {
            ApplyAction::Create => "Create",
            ApplyAction::Update => "Update",
            ApplyAction::Unchanged => "No changes",
            ApplyAction::Failed => "Failed",
        }
    }

    /// Returns the color code for this action
    pub fn color(&self) -> &'static str {
        match self {
            ApplyAction::Create => "\x1b[32m",    // Green
            ApplyAction::Update => "\x1b[33m",    // Yellow
            ApplyAction::Unchanged => "\x1b[90m", // Gray
            ApplyAction::Failed => "\x1b[31m",    // Red
        }
    }
}

/// Individual change to be applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyChange {
    /// What action to take
    pub action: ApplyAction,
    /// Resource type ("agent" or "tool")
    pub resource_type: String,
    /// Resource name
    pub name: String,
    /// Additional info (what changed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Status after apply ("success", "failed", or None if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ApplyChange {
    /// Create a new change for creation
    pub fn create(resource_type: &str, name: &str) -> Self {
        Self {
            action: ApplyAction::Create,
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            details: None,
            status: None,
            error: None,
        }
    }

    /// Create a new change for update
    pub fn update(resource_type: &str, name: &str, details: &str) -> Self {
        Self {
            action: ApplyAction::Update,
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            details: Some(details.to_string()),
            status: None,
            error: None,
        }
    }

    /// Create a new unchanged marker
    pub fn unchanged(resource_type: &str, name: &str) -> Self {
        Self {
            action: ApplyAction::Unchanged,
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            details: None,
            status: Some("success".to_string()),
            error: None,
        }
    }

    /// Mark as successful
    pub fn mark_success(&mut self) {
        self.status = Some("success".to_string());
    }

    /// Mark as failed with error
    pub fn mark_failed(&mut self, error: &str) {
        self.action = ApplyAction::Failed;
        self.status = Some("failed".to_string());
        self.error = Some(error.to_string());
    }
}

/// Summary of apply operation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplySummary {
    /// Number of resources created
    pub created: usize,
    /// Number of resources updated
    pub updated: usize,
    /// Number of resources unchanged
    pub unchanged: usize,
    /// Number of failed operations
    pub failed: usize,
}

impl ApplySummary {
    /// Calculate summary from changes
    pub fn from_changes(changes: &[ApplyChange]) -> Self {
        let mut summary = Self::default();
        for change in changes {
            match change.action {
                ApplyAction::Create => {
                    if change.status.as_deref() == Some("success") {
                        summary.created += 1;
                    }
                }
                ApplyAction::Update => {
                    if change.status.as_deref() == Some("success") {
                        summary.updated += 1;
                    }
                }
                ApplyAction::Unchanged => summary.unchanged += 1,
                ApplyAction::Failed => summary.failed += 1,
            }
        }
        summary
    }

    /// Calculate planned summary (before apply)
    pub fn planned(changes: &[ApplyChange]) -> Self {
        let mut summary = Self::default();
        for change in changes {
            match change.action {
                ApplyAction::Create => summary.created += 1,
                ApplyAction::Update => summary.updated += 1,
                ApplyAction::Unchanged => summary.unchanged += 1,
                ApplyAction::Failed => summary.failed += 1,
            }
        }
        summary
    }

    /// Total number of changes (excluding unchanged)
    #[allow(dead_code)]
    pub fn total_changes(&self) -> usize {
        self.created + self.updated
    }

    /// Check if there are any changes to apply
    #[allow(dead_code)]
    pub fn has_changes(&self) -> bool {
        self.created > 0 || self.updated > 0
    }
}

/// Complete result of apply operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    /// Whether this was a dry run
    pub dry_run: bool,
    /// List of changes
    pub changes: Vec<ApplyChange>,
    /// Summary counts
    pub summary: ApplySummary,
}

impl ApplyResult {
    /// Create a new apply result
    pub fn new(dry_run: bool, changes: Vec<ApplyChange>) -> Self {
        let summary = if dry_run {
            ApplySummary::planned(&changes)
        } else {
            ApplySummary::from_changes(&changes)
        };
        Self {
            dry_run,
            changes,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xavyo_config_deserialization() {
        let yaml = r#"
version: "1"
agents:
  - name: test-agent
    agent_type: autonomous
    model_provider: anthropic
    model_name: claude-sonnet-4
    risk_level: medium
    description: Test agent
    tools:
      - test-tool
tools:
  - name: test-tool
    description: A test tool
    risk_level: low
    input_schema:
      type: object
      properties:
        input:
          type: string
"#;
        let config: XavyoConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.version, "1");
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "test-agent");
        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].name, "test-tool");
    }

    #[test]
    fn test_xavyo_config_minimal() {
        let yaml = r#"
version: "1"
"#;
        let config: XavyoConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.version, "1");
        assert!(config.agents.is_empty());
        assert!(config.tools.is_empty());
    }

    #[test]
    fn test_agent_config_deserialization() {
        let yaml = r#"
name: my-agent
agent_type: copilot
model_provider: openai
model_name: gpt-4
risk_level: low
"#;
        let agent: AgentConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(agent.name, "my-agent");
        assert_eq!(agent.agent_type, "copilot");
        assert!(agent.description.is_none());
        assert!(agent.tools.is_empty());
    }

    #[test]
    fn test_tool_config_deserialization() {
        let yaml = r#"
name: my-tool
description: A useful tool
risk_level: medium
input_schema:
  type: object
"#;
        let tool: ToolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tool.name, "my-tool");
        assert_eq!(tool.description, "A useful tool");
        assert_eq!(tool.risk_level, "medium");
    }

    #[test]
    fn test_apply_action_display() {
        assert_eq!(ApplyAction::Create.symbol(), "+");
        assert_eq!(ApplyAction::Update.symbol(), "~");
        assert_eq!(ApplyAction::Unchanged.symbol(), "=");
        assert_eq!(ApplyAction::Failed.symbol(), "✗");
    }

    #[test]
    fn test_apply_change_creation() {
        let change = ApplyChange::create("agent", "my-agent");
        assert_eq!(change.action, ApplyAction::Create);
        assert_eq!(change.resource_type, "agent");
        assert_eq!(change.name, "my-agent");
        assert!(change.status.is_none());
    }

    #[test]
    fn test_apply_change_mark_success() {
        let mut change = ApplyChange::create("tool", "my-tool");
        change.mark_success();
        assert_eq!(change.status, Some("success".to_string()));
    }

    #[test]
    fn test_apply_change_mark_failed() {
        let mut change = ApplyChange::create("agent", "bad-agent");
        change.mark_failed("API error");
        assert_eq!(change.action, ApplyAction::Failed);
        assert_eq!(change.status, Some("failed".to_string()));
        assert_eq!(change.error, Some("API error".to_string()));
    }

    #[test]
    fn test_apply_summary_from_changes() {
        let changes = vec![
            {
                let mut c = ApplyChange::create("agent", "a1");
                c.mark_success();
                c
            },
            {
                let mut c = ApplyChange::create("agent", "a2");
                c.mark_success();
                c
            },
            ApplyChange::unchanged("tool", "t1"),
            {
                let mut c = ApplyChange::update("tool", "t2", "changed");
                c.mark_success();
                c
            },
        ];
        let summary = ApplySummary::from_changes(&changes);
        assert_eq!(summary.created, 2);
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.unchanged, 1);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_apply_summary_has_changes() {
        let mut summary = ApplySummary::default();
        assert!(!summary.has_changes());

        summary.created = 1;
        assert!(summary.has_changes());
    }

    #[test]
    fn test_apply_result_serialization() {
        let changes = vec![ApplyChange::create("agent", "test")];
        let result = ApplyResult::new(false, changes);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":false"));
        assert!(json.contains("\"action\":\"create\""));
    }

    #[test]
    fn test_xavyo_config_serialization() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![AgentConfig {
                name: "test".to_string(),
                agent_type: "autonomous".to_string(),
                model_provider: "anthropic".to_string(),
                model_name: "claude".to_string(),
                risk_level: "low".to_string(),
                description: None,
                tools: Vec::new(),
            }],
            tools: Vec::new(),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("version: '1'") || yaml.contains("version: \"1\""));
        assert!(yaml.contains("name: test"));
    }

    #[test]
    fn test_config_round_trip() {
        let yaml = r#"
version: "1"
agents:
  - name: test-agent
    agent_type: autonomous
    model_provider: anthropic
    model_name: claude
    risk_level: medium
tools:
  - name: test-tool
    description: Test
    risk_level: low
    input_schema:
      type: object
"#;
        let config: XavyoConfig = serde_yaml::from_str(yaml).unwrap();
        let yaml_out = serde_yaml::to_string(&config).unwrap();
        let config2: XavyoConfig = serde_yaml::from_str(&yaml_out).unwrap();

        assert_eq!(config.version, config2.version);
        assert_eq!(config.agents.len(), config2.agents.len());
        assert_eq!(config.tools.len(), config2.tools.len());
    }
}
