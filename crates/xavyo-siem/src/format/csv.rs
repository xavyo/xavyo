//! CSV formatter for batch export.

use crate::format::{EventFormatter, FormatError};
use crate::models::SiemEvent;

/// CSV column headers.
pub const CSV_HEADERS: &[&str] = &[
    "timestamp",
    "event_type",
    "severity",
    "actor_id",
    "actor_email",
    "source_ip",
    "target_resource",
    "action",
    "outcome",
    "tenant_id",
];

/// CSV formatter (produces a single row per event, no header).
/// Use `csv_header_row()` to get the header line for batch exports.
#[derive(Default)]
pub struct CsvFormatter;

impl CsvFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self
    }

    /// Generate the CSV header row.
    #[must_use] 
    pub fn header_row() -> String {
        CSV_HEADERS.join(",")
    }
}

impl EventFormatter for CsvFormatter {
    fn format(&self, event: &SiemEvent) -> Result<String, FormatError> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            &event
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            &event.event_type,
            &event.severity.to_string(),
            &event.actor_id.map(|id| id.to_string()).unwrap_or_default(),
            event.actor_email.as_deref().unwrap_or(""),
            event.source_ip.as_deref().unwrap_or(""),
            event.target_resource.as_deref().unwrap_or(""),
            &event.action,
            &event.outcome,
            &event.tenant_id.to_string(),
        ])
        .map_err(|e| FormatError::FormatFailed(e.to_string()))?;

        let bytes = wtr
            .into_inner()
            .map_err(|e| FormatError::FormatFailed(e.to_string()))?;

        String::from_utf8(bytes)
            .map(|s| s.trim_end().to_string()) // Remove trailing newline
            .map_err(|e| FormatError::FormatFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventCategory;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn sample_event() -> SiemEvent {
        SiemEvent {
            event_id: Uuid::new_v4(),
            event_type: "AUTH_FAILURE".to_string(),
            category: EventCategory::Authentication,
            tenant_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            actor_id: Some(Uuid::new_v4()),
            actor_email: Some("test@example.com".to_string()),
            timestamp: Utc::now(),
            severity: 6,
            event_name: "Authentication Failed".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            target_user: Some("test@example.com".to_string()),
            target_resource: Some("login_endpoint".to_string()),
            action: "Login".to_string(),
            outcome: "Failure".to_string(),
            reason: None,
            session_id: None,
            request_id: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_csv_header_row() {
        let header = CsvFormatter::header_row();
        assert_eq!(
            header,
            "timestamp,event_type,severity,actor_id,actor_email,source_ip,target_resource,action,outcome,tenant_id"
        );
    }

    #[test]
    fn test_csv_output_has_correct_columns() {
        let formatter = CsvFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let fields: Vec<&str> = output.split(',').collect();
        // CSV with 10 columns
        assert_eq!(fields.len(), 10);
    }

    #[test]
    fn test_csv_contains_event_data() {
        let formatter = CsvFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        assert!(output.contains("AUTH_FAILURE"));
        assert!(output.contains("test@example.com"));
        assert!(output.contains("192.168.1.100"));
        assert!(output.contains("Login"));
        assert!(output.contains("Failure"));
    }

    #[test]
    fn test_csv_escapes_commas_in_values() {
        let formatter = CsvFormatter::new();
        let mut event = sample_event();
        event.action = "Login, Attempt".to_string();
        let output = formatter.format(&event).unwrap();

        // CSV should properly escape/quote the field with comma
        assert!(output.contains("\"Login, Attempt\""));
    }

    #[test]
    fn test_csv_handles_missing_optional_fields() {
        let formatter = CsvFormatter::new();
        let mut event = sample_event();
        event.actor_id = None;
        event.actor_email = None;
        event.source_ip = None;
        event.target_resource = None;

        let output = formatter.format(&event).unwrap();
        // Should still produce valid CSV with empty fields
        let fields: Vec<&str> = output.split(',').collect();
        assert_eq!(fields.len(), 10);
    }
}
