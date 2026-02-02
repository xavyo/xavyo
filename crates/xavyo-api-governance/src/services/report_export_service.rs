//! Report export service for formatting report data.
//!
//! This service handles CSV and JSON export formatting.

use serde_json::json;
use xavyo_db::models::OutputFormat;
use xavyo_governance::error::{GovernanceError, Result};

use super::report_data_service::ReportData;

/// Service for exporting report data to various formats.
pub struct ReportExportService;

impl ReportExportService {
    /// Create a new export service.
    pub fn new() -> Self {
        Self
    }

    /// Export report data to the specified format.
    pub fn export(&self, data: &ReportData, format: OutputFormat) -> Result<ExportResult> {
        match format {
            OutputFormat::Json => self.export_json(data),
            OutputFormat::Csv => self.export_csv(data),
        }
    }

    /// Export data as JSON.
    fn export_json(&self, data: &ReportData) -> Result<ExportResult> {
        let output = json!({
            "columns": data.columns,
            "rows": data.rows,
            "total_count": data.total_count,
            "exported_at": chrono::Utc::now().to_rfc3339()
        });

        let content =
            serde_json::to_string_pretty(&output).map_err(GovernanceError::JsonSerialization)?;

        Ok(ExportResult {
            content,
            content_type: "application/json".to_string(),
            file_extension: "json".to_string(),
        })
    }

    /// Export data as CSV.
    fn export_csv(&self, data: &ReportData) -> Result<ExportResult> {
        let mut csv_content = String::new();

        // Write header row
        csv_content.push_str(&data.columns.join(","));
        csv_content.push('\n');

        // Write data rows
        for row in &data.rows {
            let row_values: Vec<String> = data
                .columns
                .iter()
                .map(|col| row.get(col).map(escape_csv_value).unwrap_or_default())
                .collect();
            csv_content.push_str(&row_values.join(","));
            csv_content.push('\n');
        }

        Ok(ExportResult {
            content: csv_content,
            content_type: "text/csv".to_string(),
            file_extension: "csv".to_string(),
        })
    }
}

impl Default for ReportExportService {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of exporting report data.
#[derive(Debug, Clone)]
pub struct ExportResult {
    /// The exported content as a string.
    pub content: String,
    /// MIME type of the content.
    pub content_type: String,
    /// Suggested file extension.
    pub file_extension: String,
}

/// Escape a JSON value for CSV output.
fn escape_csv_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            // Escape quotes and wrap in quotes if necessary
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.clone()
            }
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(escape_csv_value).collect();
            format!("\"{}\"", inner.join(";"))
        }
        serde_json::Value::Object(_) => {
            // For objects, serialize as JSON string
            let json_str = serde_json::to_string(value).unwrap_or_default();
            format!("\"{}\"", json_str.replace('"', "\"\""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv_simple() {
        assert_eq!(escape_csv_value(&json!("hello")), "hello");
        assert_eq!(escape_csv_value(&json!(42)), "42");
        assert_eq!(escape_csv_value(&json!(true)), "true");
        assert_eq!(escape_csv_value(&json!(null)), "");
    }

    #[test]
    fn test_escape_csv_with_comma() {
        assert_eq!(escape_csv_value(&json!("hello, world")), "\"hello, world\"");
    }

    #[test]
    fn test_escape_csv_with_quotes() {
        assert_eq!(
            escape_csv_value(&json!("say \"hello\"")),
            "\"say \"\"hello\"\"\""
        );
    }

    #[test]
    fn test_export_json() {
        let data = ReportData {
            columns: vec!["name".to_string(), "value".to_string()],
            rows: vec![
                json!({"name": "test1", "value": 100}),
                json!({"name": "test2", "value": 200}),
            ],
            total_count: 2,
        };

        let service = ReportExportService::new();
        let result = service.export(&data, OutputFormat::Json).unwrap();

        assert_eq!(result.content_type, "application/json");
        assert!(result.content.contains("\"total_count\": 2"));
    }

    #[test]
    fn test_export_csv() {
        let data = ReportData {
            columns: vec!["name".to_string(), "value".to_string()],
            rows: vec![
                json!({"name": "test1", "value": 100}),
                json!({"name": "test2", "value": 200}),
            ],
            total_count: 2,
        };

        let service = ReportExportService::new();
        let result = service.export(&data, OutputFormat::Csv).unwrap();

        assert_eq!(result.content_type, "text/csv");
        assert!(result.content.starts_with("name,value\n"));
        assert!(result.content.contains("test1,100"));
    }
}
