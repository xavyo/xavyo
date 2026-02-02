//! Batch export job runner for compliance reporting.
//!
//! Processes batch export requests: queries audit events by date range,
//! formats them into JSON Lines or CSV, and writes to a file.

use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::format::csv::CsvFormatter;
use crate::format::json::JsonFormatter;
use crate::format::EventFormatter;
use crate::models::{ExportFormat, SiemEvent};

/// Configuration for the batch exporter.
#[derive(Debug, Clone)]
pub struct BatchExporterConfig {
    /// Directory where export files are written.
    pub output_dir: PathBuf,
    /// Page size for cursor-based audit log queries.
    pub page_size: i64,
    /// Maximum file size in bytes (safety limit).
    pub max_file_size_bytes: i64,
    /// How long completed exports remain before expiry (default: 7 days).
    pub retention_days: i64,
}

impl Default for BatchExporterConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("/tmp/xavyo-siem-exports"),
            page_size: 1000,
            max_file_size_bytes: 500 * 1024 * 1024, // 500 MB
            retention_days: 7,
        }
    }
}

/// Result of a batch export operation.
#[derive(Debug)]
pub struct BatchExportResult {
    /// Total number of events written.
    pub total_events: i64,
    /// File path where the export was written.
    pub file_path: String,
    /// File size in bytes.
    pub file_size_bytes: i64,
    /// Expiry time for this export file.
    pub expires_at: DateTime<Utc>,
}

/// Writes a batch of SiemEvents to a file in the specified format.
///
/// This function is format-agnostic and works with any slice of SiemEvents.
/// In production, the caller fetches events page-by-page from the DB and
/// calls this to append to the output file.
pub fn write_batch_to_file(
    writer: &mut dyn Write,
    events: &[SiemEvent],
    format: ExportFormat,
    include_header: bool,
) -> Result<usize, std::io::Error> {
    let mut bytes_written = 0;

    match format {
        ExportFormat::Csv => {
            if include_header {
                let header = CsvFormatter::header_row();
                writeln!(writer, "{}", header)?;
                bytes_written += header.len() + 1;
            }
            let formatter = CsvFormatter::new();
            for event in events {
                let row = formatter
                    .format(event)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                writeln!(writer, "{}", row)?;
                bytes_written += row.len() + 1;
            }
        }
        ExportFormat::Json | ExportFormat::Cef | ExportFormat::SyslogRfc5424 => {
            // JSON Lines format for JSON; for CEF/syslog we also use one line per event
            let formatter: Box<dyn EventFormatter> = match format {
                ExportFormat::Json => Box::new(JsonFormatter::new()),
                ExportFormat::Cef => Box::new(crate::format::cef::CefFormatter::new()),
                ExportFormat::SyslogRfc5424 => {
                    Box::new(crate::format::syslog::SyslogFormatter::new(10, None))
                }
                _ => unreachable!(),
            };
            for event in events {
                let line = formatter
                    .format(event)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                writeln!(writer, "{}", line)?;
                bytes_written += line.len() + 1;
            }
        }
    }

    Ok(bytes_written)
}

/// Generate a unique file name for a batch export.
pub fn export_file_name(export_id: Uuid, format: ExportFormat) -> String {
    let extension = match format {
        ExportFormat::Csv => "csv",
        ExportFormat::Json => "jsonl",
        ExportFormat::Cef => "cef.log",
        ExportFormat::SyslogRfc5424 => "syslog.log",
    };
    format!("siem-export-{}.{}", export_id, extension)
}

/// Compute the expiry time for a completed export.
pub fn export_expires_at(retention_days: i64) -> DateTime<Utc> {
    Utc::now() + Duration::days(retention_days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventCategory;
    use chrono::Utc;
    use std::collections::HashMap;

    fn sample_events(count: usize) -> Vec<SiemEvent> {
        (0..count)
            .map(|i| SiemEvent {
                event_id: Uuid::new_v4(),
                event_type: format!("TEST_EVENT_{}", i),
                category: EventCategory::Authentication,
                tenant_id: Uuid::new_v4(),
                actor_id: Some(Uuid::new_v4()),
                actor_email: Some(format!("user{}@example.com", i)),
                timestamp: Utc::now(),
                severity: 3,
                event_name: format!("Test Event {}", i),
                source_ip: Some("10.0.0.1".to_string()),
                target_user: None,
                target_resource: None,
                action: "test".to_string(),
                outcome: "Success".to_string(),
                reason: None,
                session_id: None,
                request_id: None,
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_csv_batch_with_header() {
        let events = sample_events(3);
        let mut buf = Vec::new();
        let bytes = write_batch_to_file(&mut buf, &events, ExportFormat::Csv, true).unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4); // 1 header + 3 data rows
        assert!(lines[0].starts_with("timestamp,"));
        assert!(bytes > 0);
    }

    #[test]
    fn test_csv_batch_without_header() {
        let events = sample_events(2);
        let mut buf = Vec::new();
        write_batch_to_file(&mut buf, &events, ExportFormat::Csv, false).unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_json_batch_output() {
        let events = sample_events(2);
        let mut buf = Vec::new();
        write_batch_to_file(&mut buf, &events, ExportFormat::Json, false).unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line should be valid JSON
        for line in &lines {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }

    #[test]
    fn test_cef_batch_output() {
        let events = sample_events(2);
        let mut buf = Vec::new();
        write_batch_to_file(&mut buf, &events, ExportFormat::Cef, false).unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with("CEF:0|"));
        }
    }

    #[test]
    fn test_export_file_name() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            export_file_name(id, ExportFormat::Csv),
            "siem-export-550e8400-e29b-41d4-a716-446655440000.csv"
        );
        assert_eq!(
            export_file_name(id, ExportFormat::Json),
            "siem-export-550e8400-e29b-41d4-a716-446655440000.jsonl"
        );
    }

    #[test]
    fn test_export_expires_at() {
        let expires = export_expires_at(7);
        let now = Utc::now();
        assert!(expires > now);
        assert!(expires < now + Duration::days(8));
    }

    #[test]
    fn test_empty_event_batch() {
        let events: Vec<SiemEvent> = vec![];
        let mut buf = Vec::new();
        let bytes = write_batch_to_file(&mut buf, &events, ExportFormat::Json, false).unwrap();

        assert_eq!(bytes, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_csv_header_only_for_empty_batch() {
        let events: Vec<SiemEvent> = vec![];
        let mut buf = Vec::new();
        write_batch_to_file(&mut buf, &events, ExportFormat::Csv, true).unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1); // Header only
        assert!(lines[0].starts_with("timestamp,"));
    }
}
