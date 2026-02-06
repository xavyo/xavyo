//! Diff result types for representing configuration differences
//!
//! This module defines the data structures used to represent the
//! results of comparing two xavyo configurations.

use serde::{Deserialize, Serialize};

/// Exit code when configurations are identical
pub const EXIT_NO_CHANGES: i32 = 0;

/// Exit code when differences are detected
pub const EXIT_CHANGES_FOUND: i32 = 1;

/// Exit code when an error occurs (file not found, parse error, auth error)
#[allow(dead_code)]
pub const EXIT_ERROR: i32 = 2;

/// Type of resource being compared
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// AI agent configuration
    Agent,
    /// Tool configuration
    Tool,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Agent => write!(f, "agent"),
            ResourceType::Tool => write!(f, "tool"),
        }
    }
}

/// Type of change detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// Resource exists in target but not in source
    Added,
    /// Resource exists in both with differences
    Modified,
    /// Resource exists in source but not in target
    Removed,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeType::Added => write!(f, "ADDED"),
            ChangeType::Modified => write!(f, "MODIFIED"),
            ChangeType::Removed => write!(f, "REMOVED"),
        }
    }
}

/// Represents a single field-level change within a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Dot-notation path to field (e.g., "credentials.rotation_days")
    pub path: String,
    /// Previous value (None if field was added)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<serde_json::Value>,
    /// New value (None if field was removed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
}

impl FieldChange {
    /// Create a new field change
    pub fn new(
        path: impl Into<String>,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
    ) -> Self {
        Self {
            path: path.into(),
            old_value,
            new_value,
        }
    }
}

/// Represents a single resource difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffItem {
    /// Type of resource (Agent, Tool)
    pub resource_type: ResourceType,
    /// Resource name/identifier
    pub name: String,
    /// Type of change (Added, Modified, Removed)
    pub change_type: ChangeType,
    /// For modifications, list of changed fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_changes: Option<Vec<FieldChange>>,
    /// Full old resource value (for removed/modified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<serde_json::Value>,
    /// Full new resource value (for added/modified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
}

impl DiffItem {
    /// Create a new diff item for an added resource
    pub fn added(
        resource_type: ResourceType,
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        Self {
            resource_type,
            name: name.into(),
            change_type: ChangeType::Added,
            field_changes: None,
            old_value: None,
            new_value: Some(value),
        }
    }

    /// Create a new diff item for a removed resource
    pub fn removed(
        resource_type: ResourceType,
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        Self {
            resource_type,
            name: name.into(),
            change_type: ChangeType::Removed,
            field_changes: None,
            old_value: Some(value),
            new_value: None,
        }
    }

    /// Create a new diff item for a modified resource
    pub fn modified(
        resource_type: ResourceType,
        name: impl Into<String>,
        field_changes: Vec<FieldChange>,
        old_value: serde_json::Value,
        new_value: serde_json::Value,
    ) -> Self {
        Self {
            resource_type,
            name: name.into(),
            change_type: ChangeType::Modified,
            field_changes: Some(field_changes),
            old_value: Some(old_value),
            new_value: Some(new_value),
        }
    }
}

/// Helper function for serde skip_serializing_if
fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// Represents the complete result of a configuration comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Resources present in target but not in source
    pub added: Vec<DiffItem>,
    /// Resources present in both with different values
    pub modified: Vec<DiffItem>,
    /// Resources present in source but not in target
    pub removed: Vec<DiffItem>,
    /// Count of resources that are identical
    #[serde(skip_serializing_if = "is_zero")]
    pub unchanged_count: usize,
    /// Label for source (e.g., "local", "config.yaml")
    pub source_label: String,
    /// Label for target (e.g., "remote", "server")
    pub target_label: String,
}

impl DiffResult {
    /// Create a new diff result
    pub fn new(source_label: impl Into<String>, target_label: impl Into<String>) -> Self {
        Self {
            added: Vec::new(),
            modified: Vec::new(),
            removed: Vec::new(),
            unchanged_count: 0,
            source_label: source_label.into(),
            target_label: target_label.into(),
        }
    }

    /// Returns true if any additions, modifications, or removals exist
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.modified.is_empty() || !self.removed.is_empty()
    }

    /// Returns true if no changes were detected
    pub fn is_empty(&self) -> bool {
        !self.has_changes()
    }

    /// Returns count of all changes (added + modified + removed)
    pub fn changes_count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }

    /// Returns count of all changes (added + modified + removed)
    #[allow(dead_code)]
    pub fn total_changes(&self) -> usize {
        self.changes_count()
    }

    /// Returns the appropriate exit code based on changes
    pub fn exit_code(&self) -> i32 {
        if self.has_changes() {
            EXIT_CHANGES_FOUND
        } else {
            EXIT_NO_CHANGES
        }
    }

    /// Add an item to the appropriate change category
    pub fn add_item(&mut self, item: DiffItem) {
        match item.change_type {
            ChangeType::Added => self.added.push(item),
            ChangeType::Modified => self.modified.push(item),
            ChangeType::Removed => self.removed.push(item),
        }
    }

    /// Increment the unchanged count
    pub fn add_unchanged(&mut self) {
        self.unchanged_count += 1;
    }
}

/// Summary of diff result for machine-readable output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Number of added resources
    pub added: usize,
    /// Number of modified resources
    pub modified: usize,
    /// Number of removed resources
    pub removed: usize,
    /// Number of unchanged resources
    #[serde(skip_serializing_if = "is_zero")]
    pub unchanged: usize,
}

impl From<&DiffResult> for DiffSummary {
    fn from(result: &DiffResult) -> Self {
        Self {
            added: result.added.len(),
            modified: result.modified.len(),
            removed: result.removed.len(),
            unchanged: result.unchanged_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ResourceType::Agent.to_string(), "agent");
        assert_eq!(ResourceType::Tool.to_string(), "tool");
    }

    #[test]
    fn test_change_type_display() {
        assert_eq!(ChangeType::Added.to_string(), "ADDED");
        assert_eq!(ChangeType::Modified.to_string(), "MODIFIED");
        assert_eq!(ChangeType::Removed.to_string(), "REMOVED");
    }

    #[test]
    fn test_diff_result_has_changes() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        assert!(!result.has_changes());

        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "test",
            serde_json::json!({}),
        ));
        assert!(result.has_changes());
    }

    #[test]
    fn test_diff_result_total_changes() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        assert_eq!(result.total_changes(), 0);

        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "a1",
            serde_json::json!({}),
        ));
        result.modified.push(DiffItem::modified(
            ResourceType::Agent,
            "a2",
            vec![],
            serde_json::json!({}),
            serde_json::json!({}),
        ));
        result.removed.push(DiffItem::removed(
            ResourceType::Tool,
            "t1",
            serde_json::json!({}),
        ));

        assert_eq!(result.total_changes(), 3);
    }

    #[test]
    fn test_diff_result_exit_code() {
        let result = DiffResult::new("file1.yaml", "file2.yaml");
        assert_eq!(result.exit_code(), EXIT_NO_CHANGES);

        let mut result_with_changes = DiffResult::new("file1.yaml", "file2.yaml");
        result_with_changes.added.push(DiffItem::added(
            ResourceType::Agent,
            "test",
            serde_json::json!({}),
        ));
        assert_eq!(result_with_changes.exit_code(), EXIT_CHANGES_FOUND);
    }

    #[test]
    fn test_diff_item_added() {
        let item = DiffItem::added(
            ResourceType::Agent,
            "my-agent",
            serde_json::json!({"name": "my-agent"}),
        );
        assert_eq!(item.resource_type, ResourceType::Agent);
        assert_eq!(item.name, "my-agent");
        assert_eq!(item.change_type, ChangeType::Added);
        assert!(item.old_value.is_none());
        assert!(item.new_value.is_some());
    }

    #[test]
    fn test_diff_item_removed() {
        let item = DiffItem::removed(
            ResourceType::Tool,
            "my-tool",
            serde_json::json!({"name": "my-tool"}),
        );
        assert_eq!(item.resource_type, ResourceType::Tool);
        assert_eq!(item.change_type, ChangeType::Removed);
        assert!(item.old_value.is_some());
        assert!(item.new_value.is_none());
    }

    #[test]
    fn test_field_change() {
        let change = FieldChange::new(
            "description",
            Some(serde_json::json!("old")),
            Some(serde_json::json!("new")),
        );
        assert_eq!(change.path, "description");
        assert_eq!(change.old_value, Some(serde_json::json!("old")));
        assert_eq!(change.new_value, Some(serde_json::json!("new")));
    }

    #[test]
    fn test_diff_summary_from_result() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "a1",
            serde_json::json!({}),
        ));
        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "a2",
            serde_json::json!({}),
        ));
        result.modified.push(DiffItem::modified(
            ResourceType::Tool,
            "t1",
            vec![],
            serde_json::json!({}),
            serde_json::json!({}),
        ));
        result.unchanged_count = 5;

        let summary = DiffSummary::from(&result);
        assert_eq!(summary.added, 2);
        assert_eq!(summary.modified, 1);
        assert_eq!(summary.removed, 0);
        assert_eq!(summary.unchanged, 5);
    }

    #[test]
    fn test_diff_result_serialization() {
        let mut result = DiffResult::new("local", "remote");
        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "test-agent",
            serde_json::json!({"name": "test-agent"}),
        ));

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"added\""));
        assert!(json.contains("test-agent"));
        assert!(json.contains("\"source_label\":\"local\""));
    }
}
