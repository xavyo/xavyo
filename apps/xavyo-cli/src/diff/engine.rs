//! Diff engine for comparing xavyo configurations
//!
//! This module provides the comparison algorithm that produces
//! structured diff results from two XavyoConfig instances.

use crate::models::config::{AgentConfig, ToolConfig, XavyoConfig};

use super::result::{DiffItem, DiffResult, FieldChange, ResourceType};

/// Compare two configurations and produce a structured diff result
///
/// # Arguments
///
/// * `source` - The source/original configuration
/// * `target` - The target/new configuration
/// * `source_label` - Label for the source (e.g., "local", "config.yaml")
/// * `target_label` - Label for the target (e.g., "remote", "server")
///
/// # Returns
///
/// A `DiffResult` containing all differences between the configurations
pub fn compare_configs(
    source: &XavyoConfig,
    target: &XavyoConfig,
    source_label: impl Into<String>,
    target_label: impl Into<String>,
) -> DiffResult {
    let mut result = DiffResult::new(source_label, target_label);

    // Compare agents
    compare_agents(&source.agents, &target.agents, &mut result);

    // Compare tools
    compare_tools(&source.tools, &target.tools, &mut result);

    result
}

/// Compare agent configurations between source and target
fn compare_agents(source: &[AgentConfig], target: &[AgentConfig], result: &mut DiffResult) {
    // Build lookup maps by name
    let source_map: std::collections::HashMap<&str, &AgentConfig> =
        source.iter().map(|a| (a.name.as_str(), a)).collect();
    let target_map: std::collections::HashMap<&str, &AgentConfig> =
        target.iter().map(|a| (a.name.as_str(), a)).collect();

    // Find removed and modified agents (in source but not in target or different)
    for (name, source_agent) in &source_map {
        if let Some(target_agent) = target_map.get(name) {
            // Agent exists in both - check for modifications
            let field_changes = compare_agent_fields(source_agent, target_agent);
            if field_changes.is_empty() {
                result.add_unchanged();
            } else {
                let old_value = serde_json::to_value(source_agent).unwrap_or_default();
                let new_value = serde_json::to_value(target_agent).unwrap_or_default();
                result.add_item(DiffItem::modified(
                    ResourceType::Agent,
                    *name,
                    field_changes,
                    old_value,
                    new_value,
                ));
            }
        } else {
            // Agent only in source - removed
            let old_value = serde_json::to_value(source_agent).unwrap_or_default();
            result.add_item(DiffItem::removed(ResourceType::Agent, *name, old_value));
        }
    }

    // Find added agents (in target but not in source)
    for (name, target_agent) in &target_map {
        if !source_map.contains_key(name) {
            let new_value = serde_json::to_value(target_agent).unwrap_or_default();
            result.add_item(DiffItem::added(ResourceType::Agent, *name, new_value));
        }
    }
}

/// Compare tool configurations between source and target
fn compare_tools(source: &[ToolConfig], target: &[ToolConfig], result: &mut DiffResult) {
    // Build lookup maps by name
    let source_map: std::collections::HashMap<&str, &ToolConfig> =
        source.iter().map(|t| (t.name.as_str(), t)).collect();
    let target_map: std::collections::HashMap<&str, &ToolConfig> =
        target.iter().map(|t| (t.name.as_str(), t)).collect();

    // Find removed and modified tools (in source but not in target or different)
    for (name, source_tool) in &source_map {
        if let Some(target_tool) = target_map.get(name) {
            // Tool exists in both - check for modifications
            let field_changes = compare_tool_fields(source_tool, target_tool);
            if field_changes.is_empty() {
                result.add_unchanged();
            } else {
                let old_value = serde_json::to_value(source_tool).unwrap_or_default();
                let new_value = serde_json::to_value(target_tool).unwrap_or_default();
                result.add_item(DiffItem::modified(
                    ResourceType::Tool,
                    *name,
                    field_changes,
                    old_value,
                    new_value,
                ));
            }
        } else {
            // Tool only in source - removed
            let old_value = serde_json::to_value(source_tool).unwrap_or_default();
            result.add_item(DiffItem::removed(ResourceType::Tool, *name, old_value));
        }
    }

    // Find added tools (in target but not in source)
    for (name, target_tool) in &target_map {
        if !source_map.contains_key(name) {
            let new_value = serde_json::to_value(target_tool).unwrap_or_default();
            result.add_item(DiffItem::added(ResourceType::Tool, *name, new_value));
        }
    }
}

/// Compare two agent configurations and return field-level changes
fn compare_agent_fields(source: &AgentConfig, target: &AgentConfig) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    // Compare each field
    if source.agent_type != target.agent_type {
        changes.push(FieldChange::new(
            "agent_type",
            Some(serde_json::json!(source.agent_type)),
            Some(serde_json::json!(target.agent_type)),
        ));
    }

    if source.model_provider != target.model_provider {
        changes.push(FieldChange::new(
            "model_provider",
            Some(serde_json::json!(source.model_provider)),
            Some(serde_json::json!(target.model_provider)),
        ));
    }

    if source.model_name != target.model_name {
        changes.push(FieldChange::new(
            "model_name",
            Some(serde_json::json!(source.model_name)),
            Some(serde_json::json!(target.model_name)),
        ));
    }

    if source.risk_level != target.risk_level {
        changes.push(FieldChange::new(
            "risk_level",
            Some(serde_json::json!(source.risk_level)),
            Some(serde_json::json!(target.risk_level)),
        ));
    }

    if source.description != target.description {
        changes.push(FieldChange::new(
            "description",
            source.description.as_ref().map(|d| serde_json::json!(d)),
            target.description.as_ref().map(|d| serde_json::json!(d)),
        ));
    }

    if source.tools != target.tools {
        changes.push(FieldChange::new(
            "tools",
            Some(serde_json::json!(source.tools)),
            Some(serde_json::json!(target.tools)),
        ));
    }

    changes
}

/// Compare two tool configurations and return field-level changes
fn compare_tool_fields(source: &ToolConfig, target: &ToolConfig) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    if source.description != target.description {
        changes.push(FieldChange::new(
            "description",
            Some(serde_json::json!(source.description)),
            Some(serde_json::json!(target.description)),
        ));
    }

    if source.risk_level != target.risk_level {
        changes.push(FieldChange::new(
            "risk_level",
            Some(serde_json::json!(source.risk_level)),
            Some(serde_json::json!(target.risk_level)),
        ));
    }

    if source.input_schema != target.input_schema {
        changes.push(FieldChange::new(
            "input_schema",
            Some(source.input_schema.clone()),
            Some(target.input_schema.clone()),
        ));
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::result::ChangeType;

    fn make_agent(name: &str, agent_type: &str, risk_level: &str) -> AgentConfig {
        AgentConfig {
            name: name.to_string(),
            agent_type: agent_type.to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: risk_level.to_string(),
            description: None,
            tools: vec![],
        }
    }

    fn make_tool(name: &str, description: &str, risk_level: &str) -> ToolConfig {
        ToolConfig {
            name: name.to_string(),
            description: description.to_string(),
            risk_level: risk_level.to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    #[test]
    fn test_compare_configs_identical() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![make_agent("agent-a", "copilot", "low")],
            tools: vec![make_tool("tool-a", "Test tool", "low")],
        };

        let result = compare_configs(&config, &config, "file1.yaml", "file2.yaml");

        assert!(!result.has_changes());
        assert_eq!(result.unchanged_count, 2);
    }

    #[test]
    fn test_compare_configs_agent_added() {
        let source = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        };

        let target = XavyoConfig {
            version: "1".to_string(),
            agents: vec![make_agent("new-agent", "autonomous", "medium")],
            tools: vec![],
        };

        let result = compare_configs(&source, &target, "source", "target");

        assert!(result.has_changes());
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].name, "new-agent");
        assert_eq!(result.added[0].change_type, ChangeType::Added);
    }

    #[test]
    fn test_compare_configs_agent_removed() {
        let source = XavyoConfig {
            version: "1".to_string(),
            agents: vec![make_agent("old-agent", "copilot", "low")],
            tools: vec![],
        };

        let target = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        };

        let result = compare_configs(&source, &target, "source", "target");

        assert!(result.has_changes());
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].name, "old-agent");
        assert_eq!(result.removed[0].change_type, ChangeType::Removed);
    }

    #[test]
    fn test_compare_configs_agent_modified() {
        let source = XavyoConfig {
            version: "1".to_string(),
            agents: vec![make_agent("agent-a", "copilot", "low")],
            tools: vec![],
        };

        let target = XavyoConfig {
            version: "1".to_string(),
            agents: vec![make_agent("agent-a", "autonomous", "high")],
            tools: vec![],
        };

        let result = compare_configs(&source, &target, "source", "target");

        assert!(result.has_changes());
        assert_eq!(result.modified.len(), 1);
        assert_eq!(result.modified[0].name, "agent-a");
        assert_eq!(result.modified[0].change_type, ChangeType::Modified);

        let field_changes = result.modified[0].field_changes.as_ref().unwrap();
        assert_eq!(field_changes.len(), 2);

        let paths: Vec<&str> = field_changes.iter().map(|fc| fc.path.as_str()).collect();
        assert!(paths.contains(&"agent_type"));
        assert!(paths.contains(&"risk_level"));
    }

    #[test]
    fn test_compare_configs_tool_changes() {
        let source = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![
                make_tool("tool-a", "Original description", "low"),
                make_tool("tool-b", "Will be removed", "medium"),
            ],
        };

        let target = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![
                make_tool("tool-a", "Updated description", "low"),
                make_tool("tool-c", "New tool", "high"),
            ],
        };

        let result = compare_configs(&source, &target, "source", "target");

        assert!(result.has_changes());
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].name, "tool-c");

        assert_eq!(result.modified.len(), 1);
        assert_eq!(result.modified[0].name, "tool-a");

        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].name, "tool-b");
    }

    #[test]
    fn test_compare_configs_complex_scenario() {
        let source = XavyoConfig {
            version: "1".to_string(),
            agents: vec![
                make_agent("agent-a", "copilot", "low"),
                make_agent("agent-b", "autonomous", "medium"),
            ],
            tools: vec![
                make_tool("tool-a", "Tool A", "low"),
                make_tool("tool-b", "Tool B", "medium"),
            ],
        };

        let target = XavyoConfig {
            version: "1".to_string(),
            agents: vec![
                make_agent("agent-a", "autonomous", "high"), // modified
                make_agent("agent-c", "copilot", "low"),     // added
            ],
            tools: vec![
                make_tool("tool-a", "Tool A", "low"),          // unchanged
                make_tool("tool-c", "New Tool C", "critical"), // added
            ],
        };

        let result = compare_configs(&source, &target, "local", "remote");

        assert_eq!(result.total_changes(), 5); // 2 added, 1 modified, 2 removed
        assert_eq!(result.added.len(), 2);
        assert_eq!(result.modified.len(), 1);
        assert_eq!(result.removed.len(), 2);
        assert_eq!(result.unchanged_count, 1);
    }

    #[test]
    fn test_compare_agent_fields_all_different() {
        let source = AgentConfig {
            name: "agent".to_string(),
            agent_type: "copilot".to_string(),
            model_provider: "openai".to_string(),
            model_name: "gpt-4".to_string(),
            risk_level: "low".to_string(),
            description: Some("Old description".to_string()),
            tools: vec!["tool-a".to_string()],
        };

        let target = AgentConfig {
            name: "agent".to_string(),
            agent_type: "autonomous".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude-sonnet-4".to_string(),
            risk_level: "high".to_string(),
            description: Some("New description".to_string()),
            tools: vec!["tool-b".to_string()],
        };

        let changes = compare_agent_fields(&source, &target);

        assert_eq!(changes.len(), 6);
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"agent_type"));
        assert!(paths.contains(&"model_provider"));
        assert!(paths.contains(&"model_name"));
        assert!(paths.contains(&"risk_level"));
        assert!(paths.contains(&"description"));
        assert!(paths.contains(&"tools"));
    }

    #[test]
    fn test_compare_tool_fields() {
        let source = ToolConfig {
            name: "tool".to_string(),
            description: "Old".to_string(),
            risk_level: "low".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        };

        let target = ToolConfig {
            name: "tool".to_string(),
            description: "New".to_string(),
            risk_level: "high".to_string(),
            input_schema: serde_json::json!({"type": "string"}),
        };

        let changes = compare_tool_fields(&source, &target);

        assert_eq!(changes.len(), 3);
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"description"));
        assert!(paths.contains(&"risk_level"));
        assert!(paths.contains(&"input_schema"));
    }
}
