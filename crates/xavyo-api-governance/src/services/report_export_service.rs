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
    #[must_use]
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
            let mut row_values = Vec::with_capacity(data.columns.len());
            for col in &data.columns {
                let cell = match row.get(col) {
                    Some(v) => escape_csv_value(v)?,
                    None => String::new(),
                };
                row_values.push(cell);
            }
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
fn escape_csv_value(value: &serde_json::Value) -> Result<String> {
    Ok(match value {
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
            let mut inner = Vec::with_capacity(arr.len());
            for v in arr {
                inner.push(escape_csv_value(v)?);
            }
            format!("\"{}\"", inner.join(";"))
        }
        serde_json::Value::Object(_) => {
            let json_str =
                serde_json::to_string(value).map_err(GovernanceError::JsonSerialization)?;
            format!("\"{}\"", json_str.replace('"', "\"\""))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv_simple() {
        assert_eq!(escape_csv_value(&json!("hello")).unwrap(), "hello");
        assert_eq!(escape_csv_value(&json!(42)).unwrap(), "42");
        assert_eq!(escape_csv_value(&json!(true)).unwrap(), "true");
        assert_eq!(escape_csv_value(&json!(null)).unwrap(), "");
    }

    #[test]
    fn test_escape_csv_with_comma() {
        assert_eq!(
            escape_csv_value(&json!("hello, world")).unwrap(),
            "\"hello, world\""
        );
    }

    #[test]
    fn test_escape_csv_with_quotes() {
        assert_eq!(
            escape_csv_value(&json!("say \"hello\"")).unwrap(),
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

    #[test]
    fn csv_object_cells_do_not_empty_on_serialize_error() {
        let src = include_str!("report_export_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("serde_json::to_string(value)")
                && !production.contains("to_string(value).unwrap_or_default()"),
            "CSV object cells must fail closed when serialize fails"
        );
        let obj = json!({"k": "v"});
        let escaped = escape_csv_value(&obj).unwrap();
        assert!(escaped.contains("k"));
    }
}
