//! CEF v0 (Common Event Format) formatter.

use crate::format::{EventFormatter, FormatError};
use crate::models::{SiemEvent, PRODUCT_NAME, PRODUCT_VENDOR, PRODUCT_VERSION};

/// CEF v0 formatter.
#[derive(Default)]
pub struct CefFormatter;

impl CefFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self
    }

    /// Escape special characters in CEF header values (pipe and backslash).
    fn escape_header_value(value: &str) -> String {
        value.replace('\\', "\\\\").replace('|', "\\|")
    }

    /// Escape special characters in CEF extension values (equals and backslash).
    fn escape_extension_value(value: &str) -> String {
        value.replace('\\', "\\\\").replace('=', "\\=")
    }

    /// Map severity to CEF severity string (0-10).
    fn format_severity(severity: u8) -> String {
        severity.min(10).to_string()
    }

    /// Build the CEF extension key=value pairs.
    fn format_extensions(event: &SiemEvent) -> String {
        let mut parts: Vec<String> = Vec::new();

        if let Some(ref ip) = event.source_ip {
            parts.push(format!("src={}", Self::escape_extension_value(ip)));
        }

        if let Some(ref target) = event.target_user {
            parts.push(format!("duser={}", Self::escape_extension_value(target)));
        }

        if let Some(ref email) = event.actor_email {
            parts.push(format!("suser={}", Self::escape_extension_value(email)));
        }

        parts.push(format!(
            "act={}",
            Self::escape_extension_value(&event.action)
        ));
        parts.push(format!(
            "outcome={}",
            Self::escape_extension_value(&event.outcome)
        ));

        if let Some(ref reason) = event.reason {
            parts.push(format!("reason={}", Self::escape_extension_value(reason)));
        }

        // Custom extensions
        parts.push(format!(
            "cs1={} cs1Label=TenantId",
            Self::escape_extension_value(&event.tenant_id.to_string())
        ));

        if let Some(ref session_id) = event.session_id {
            parts.push(format!(
                "cs2={} cs2Label=SessionId",
                Self::escape_extension_value(&session_id.to_string())
            ));
        }

        if let Some(ref request_id) = event.request_id {
            parts.push(format!(
                "cs3={} cs3Label=RequestId",
                Self::escape_extension_value(request_id)
            ));
        }

        // Timestamp
        parts.push(format!(
            "rt={}",
            event.timestamp.format("%b %d %Y %H:%M:%S%.3f UTC")
        ));

        parts.join(" ")
    }
}

impl EventFormatter for CefFormatter {
    fn format(&self, event: &SiemEvent) -> Result<String, FormatError> {
        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            Self::escape_header_value(PRODUCT_VENDOR),
            Self::escape_header_value(PRODUCT_NAME),
            Self::escape_header_value(PRODUCT_VERSION),
            Self::escape_header_value(&event.event_type),
            Self::escape_header_value(&event.event_name),
            Self::format_severity(event.severity),
            Self::format_extensions(event)
        );
        Ok(header)
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
            reason: Some("InvalidCredentials".to_string()),
            session_id: Some(Uuid::new_v4()),
            request_id: Some("req-12345".to_string()),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_cef_header_structure() {
        let formatter = CefFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        assert!(output.starts_with("CEF:0|Xavyo|IDP|1.0.0|"));
        assert!(output.contains("AUTH_FAILURE"));
        assert!(output.contains("Authentication Failed"));
    }

    #[test]
    fn test_cef_severity_mapping() {
        let formatter = CefFormatter::new();
        let mut event = sample_event();
        event.severity = 6;
        let output = formatter.format(&event).unwrap();
        // Severity appears after event_name pipe
        assert!(output.contains("|6|"));
    }

    #[test]
    fn test_cef_extensions_present() {
        let formatter = CefFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        assert!(output.contains("src=192.168.1.100"));
        assert!(output.contains("act=Login"));
        assert!(output.contains("outcome=Failure"));
        assert!(output.contains("reason=InvalidCredentials"));
        assert!(output.contains("cs1Label=TenantId"));
        assert!(output.contains("cs2Label=SessionId"));
        assert!(output.contains("cs3Label=RequestId"));
    }

    #[test]
    fn test_cef_escape_header_pipe() {
        assert_eq!(CefFormatter::escape_header_value("a|b"), "a\\|b");
        assert_eq!(CefFormatter::escape_header_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_cef_escape_extension_equals() {
        assert_eq!(CefFormatter::escape_extension_value("a=b"), "a\\=b");
        assert_eq!(CefFormatter::escape_extension_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_cef_custom_extensions_cs1_to_cs3() {
        let formatter = CefFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        assert!(output.contains("cs1=550e8400-e29b-41d4-a716-446655440000 cs1Label=TenantId"));
        assert!(output.contains("cs3=req-12345 cs3Label=RequestId"));
    }

    #[test]
    fn test_cef_severity_clamped_to_10() {
        assert_eq!(CefFormatter::format_severity(15), "10");
        assert_eq!(CefFormatter::format_severity(0), "0");
        assert_eq!(CefFormatter::format_severity(10), "10");
    }
}
