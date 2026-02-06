//! Output formatting for diff results
//!
//! This module provides formatting functions for displaying diff results
//! in various formats: colored table (default), JSON, and YAML.

use colored::Colorize;
use serde::{Deserialize, Serialize};

use super::result::{ChangeType, DiffItem, DiffResult, DiffSummary};

/// Output format for diff results
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Colored table format (default, human-readable)
    #[default]
    Table,
    /// JSON format (machine-readable)
    Json,
    /// YAML format (for config-as-code workflows)
    Yaml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "yaml" => Ok(OutputFormat::Yaml),
            _ => Err(format!(
                "Invalid output format: {}. Expected: table, json, yaml",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Yaml => write!(f, "yaml"),
        }
    }
}

/// Configuration for diff formatting
#[derive(Debug, Clone)]
pub struct DiffFormatter {
    /// Output format to use
    pub format: OutputFormat,
    /// Whether to use colored output
    pub use_color: bool,
}

impl Default for DiffFormatter {
    fn default() -> Self {
        Self {
            format: OutputFormat::Table,
            use_color: true,
        }
    }
}

impl DiffFormatter {
    /// Create a new formatter with the specified options
    pub fn new(format: OutputFormat, use_color: bool) -> Self {
        Self { format, use_color }
    }

    /// Format the diff result according to the configured format
    pub fn format(&self, result: &DiffResult) -> String {
        match self.format {
            OutputFormat::Table => self.format_table(result),
            OutputFormat::Json => format_json(result),
            OutputFormat::Yaml => format_yaml(result),
        }
    }

    /// Format as a colored table
    fn format_table(&self, result: &DiffResult) -> String {
        let mut output = String::new();

        if !result.has_changes() {
            output.push_str("Files are identical.\n");
            return output;
        }

        // Header
        output.push_str(&format!(
            "Comparing {} with {}\n\n",
            result.source_label, result.target_label
        ));
        output.push_str("Resource          Change     Details\n");
        output.push_str("────────────────────────────────────────────────────────────────\n");

        // Sort all items for consistent output
        let mut all_items: Vec<&DiffItem> = result
            .added
            .iter()
            .chain(result.modified.iter())
            .chain(result.removed.iter())
            .collect();
        all_items.sort_by(|a, b| {
            // Sort by resource type, then by name
            let type_cmp = format!("{}", a.resource_type).cmp(&format!("{}", b.resource_type));
            if type_cmp == std::cmp::Ordering::Equal {
                a.name.cmp(&b.name)
            } else {
                type_cmp
            }
        });

        for item in all_items {
            output.push_str(&self.format_change_line(item));
            output.push('\n');
        }

        output.push_str("────────────────────────────────────────────────────────────────\n");

        // Summary
        let summary = DiffSummary::from(result);
        output.push_str(&format!(
            "Summary: {} added, {} modified, {} removed\n",
            summary.added, summary.modified, summary.removed
        ));

        output
    }

    /// Format a single change line with optional coloring
    fn format_change_line(&self, item: &DiffItem) -> String {
        let resource_name = format!("{}/{}", item.resource_type, item.name);
        let change_type = format!("{}", item.change_type);
        let details = self.format_details(item);

        if self.use_color {
            let colored_change = match item.change_type {
                ChangeType::Added => change_type.green().to_string(),
                ChangeType::Modified => change_type.yellow().to_string(),
                ChangeType::Removed => change_type.red().to_string(),
            };

            let prefix = match item.change_type {
                ChangeType::Added => "+".green().to_string(),
                ChangeType::Modified => "~".yellow().to_string(),
                ChangeType::Removed => "-".red().to_string(),
            };

            format!(
                "{} {:<16} {:<10} {}",
                prefix, resource_name, colored_change, details
            )
        } else {
            let prefix = match item.change_type {
                ChangeType::Added => "+",
                ChangeType::Modified => "~",
                ChangeType::Removed => "-",
            };

            format!(
                "{} {:<16} {:<10} {}",
                prefix, resource_name, change_type, details
            )
        }
    }

    /// Format the details column for a diff item
    fn format_details(&self, item: &DiffItem) -> String {
        match item.change_type {
            ChangeType::Added | ChangeType::Removed => String::new(),
            ChangeType::Modified => {
                if let Some(ref field_changes) = item.field_changes {
                    field_changes
                        .iter()
                        .map(|fc| {
                            let old = fc
                                .old_value
                                .as_ref()
                                .map(format_value)
                                .unwrap_or_else(|| "(none)".to_string());
                            let new = fc
                                .new_value
                                .as_ref()
                                .map(format_value)
                                .unwrap_or_else(|| "(none)".to_string());
                            format!("{}: {} → {}", fc.path, old, new)
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    String::new()
                }
            }
        }
    }
}

/// Format a JSON value for display (truncate if too long)
fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > 30 {
                format!("\"{}...\"", &s[..27])
            } else {
                format!("\"{}\"", s)
            }
        }
        serde_json::Value::Null => "(null)".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else {
                format!("[{} items]", arr.len())
            }
        }
        serde_json::Value::Object(obj) => {
            if obj.is_empty() {
                "{}".to_string()
            } else {
                "{...}".to_string()
            }
        }
    }
}

/// Format diff result as JSON
pub fn format_json(result: &DiffResult) -> String {
    let output = JsonOutput::from(result);
    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

/// Format diff result as YAML
pub fn format_yaml(result: &DiffResult) -> String {
    let output = JsonOutput::from(result);
    serde_yaml::to_string(&output).unwrap_or_else(|_| "".to_string())
}

/// Public function to format diff results
pub fn format_diff(result: &DiffResult, format: OutputFormat, use_color: bool) -> String {
    let formatter = DiffFormatter::new(format, use_color);
    formatter.format(result)
}

/// JSON/YAML output structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonOutput {
    added: Vec<JsonDiffItem>,
    modified: Vec<JsonDiffItem>,
    removed: Vec<JsonDiffItem>,
    summary: DiffSummary,
}

impl From<&DiffResult> for JsonOutput {
    fn from(result: &DiffResult) -> Self {
        Self {
            added: result.added.iter().map(JsonDiffItem::from).collect(),
            modified: result.modified.iter().map(JsonDiffItem::from).collect(),
            removed: result.removed.iter().map(JsonDiffItem::from).collect(),
            summary: DiffSummary::from(result),
        }
    }
}

/// Simplified diff item for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonDiffItem {
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<JsonFieldChange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
}

impl From<&DiffItem> for JsonDiffItem {
    fn from(item: &DiffItem) -> Self {
        let value = match item.change_type {
            ChangeType::Added => item.new_value.clone(),
            ChangeType::Removed => item.old_value.clone(),
            ChangeType::Modified => None,
        };

        let changes = item
            .field_changes
            .as_ref()
            .map(|fcs| fcs.iter().map(JsonFieldChange::from).collect());

        Self {
            resource_type: item.resource_type.to_string(),
            name: item.name.clone(),
            changes,
            value,
        }
    }
}

/// Simplified field change for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonFieldChange {
    field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    old: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new: Option<serde_json::Value>,
}

impl From<&super::result::FieldChange> for JsonFieldChange {
    fn from(fc: &super::result::FieldChange) -> Self {
        Self {
            field: fc.path.clone(),
            old: fc.old_value.clone(),
            new: fc.new_value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::result::{DiffItem, FieldChange, ResourceType};

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(
            "table".parse::<OutputFormat>().unwrap(),
            OutputFormat::Table
        );
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("yaml".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Table.to_string(), "table");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Yaml.to_string(), "yaml");
    }

    #[test]
    fn test_format_table_no_changes() {
        let result = DiffResult::new("file1.yaml", "file2.yaml");
        let formatter = DiffFormatter::new(OutputFormat::Table, false);
        let output = formatter.format(&result);
        assert!(output.contains("Files are identical"));
    }

    #[test]
    fn test_format_table_with_changes() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "new-agent",
            serde_json::json!({"name": "new-agent"}),
        ));
        result.removed.push(DiffItem::removed(
            ResourceType::Tool,
            "old-tool",
            serde_json::json!({"name": "old-tool"}),
        ));

        let formatter = DiffFormatter::new(OutputFormat::Table, false);
        let output = formatter.format(&result);

        assert!(output.contains("new-agent"));
        assert!(output.contains("old-tool"));
        assert!(output.contains("ADDED"));
        assert!(output.contains("REMOVED"));
        assert!(output.contains("Summary:"));
    }

    #[test]
    fn test_format_table_modified_with_details() {
        let mut result = DiffResult::new("local", "remote");
        result.modified.push(DiffItem::modified(
            ResourceType::Agent,
            "my-agent",
            vec![FieldChange::new(
                "risk_level",
                Some(serde_json::json!("low")),
                Some(serde_json::json!("high")),
            )],
            serde_json::json!({}),
            serde_json::json!({}),
        ));

        let formatter = DiffFormatter::new(OutputFormat::Table, false);
        let output = formatter.format(&result);

        assert!(output.contains("MODIFIED"));
        assert!(output.contains("risk_level"));
        assert!(output.contains("\"low\" → \"high\""));
    }

    #[test]
    fn test_format_json() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        result.added.push(DiffItem::added(
            ResourceType::Agent,
            "test-agent",
            serde_json::json!({"name": "test-agent"}),
        ));

        let json = format_json(&result);

        assert!(json.contains("\"added\""));
        assert!(json.contains("test-agent"));
        assert!(json.contains("\"summary\""));

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn test_format_yaml() {
        let mut result = DiffResult::new("file1.yaml", "file2.yaml");
        result.added.push(DiffItem::added(
            ResourceType::Tool,
            "test-tool",
            serde_json::json!({"name": "test-tool"}),
        ));

        let yaml = format_yaml(&result);

        assert!(yaml.contains("added"));
        assert!(yaml.contains("test-tool"));
        assert!(yaml.contains("summary"));

        // Verify it's valid YAML
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(parsed.is_mapping());
    }

    #[test]
    fn test_format_value() {
        assert_eq!(format_value(&serde_json::json!("hello")), "\"hello\"");
        assert_eq!(format_value(&serde_json::json!(42)), "42");
        assert_eq!(format_value(&serde_json::json!(true)), "true");
        assert_eq!(format_value(&serde_json::json!(null)), "(null)");
        assert_eq!(format_value(&serde_json::json!([])), "[]");
        assert_eq!(format_value(&serde_json::json!([1, 2, 3])), "[3 items]");
        assert_eq!(format_value(&serde_json::json!({})), "{}");
        assert_eq!(format_value(&serde_json::json!({"a": 1})), "{...}");
    }

    #[test]
    fn test_format_value_truncates_long_strings() {
        let long_string = "a".repeat(50);
        let formatted = format_value(&serde_json::json!(long_string));
        assert!(formatted.len() < 40);
        assert!(formatted.contains("..."));
    }

    #[test]
    fn test_diff_formatter_default() {
        let formatter = DiffFormatter::default();
        assert_eq!(formatter.format, OutputFormat::Table);
        assert!(formatter.use_color);
    }

    #[test]
    fn test_format_diff_function() {
        let result = DiffResult::new("a", "b");
        let output = format_diff(&result, OutputFormat::Table, false);
        assert!(output.contains("Files are identical"));
    }
}
