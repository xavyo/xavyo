//! JSON structured formatter for SIEM export.

use crate::format::{EventFormatter, FormatError};
use crate::models::{SiemEvent, PRODUCT_NAME, PRODUCT_VERSION};
use serde_json::json;

/// JSON structured output formatter.
#[derive(Default)]
pub struct JsonFormatter;

impl JsonFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self
    }
}

impl EventFormatter for JsonFormatter {
    fn format(&self, event: &SiemEvent) -> Result<String, FormatError> {
        let mut obj = json!({
            "timestamp": event.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "event_type": format!("{}.{}", event.category.as_str(), event.outcome.to_lowercase()),
            "severity": event.severity,
            "severity_label": event.severity_label(),
            "tenant_id": event.tenant_id.to_string(),
            "action": event.action,
            "outcome": event.outcome,
            "product": format!("{} {}", "xavyo", PRODUCT_NAME),
            "product_version": PRODUCT_VERSION,
        });

        let map = obj.as_object_mut().unwrap();

        if let Some(ref actor_id) = event.actor_id {
            map.insert("actor_id".to_string(), json!(actor_id.to_string()));
        }
        if let Some(ref email) = event.actor_email {
            map.insert("actor_email".to_string(), json!(email));
        }
        if let Some(ref ip) = event.source_ip {
            map.insert("source_ip".to_string(), json!(ip));
        }
        if let Some(ref target) = event.target_resource {
            map.insert("target_resource".to_string(), json!(target));
        }
        if let Some(ref target_user) = event.target_user {
            map.insert("target_user".to_string(), json!(target_user));
        }
        if let Some(ref reason) = event.reason {
            map.insert("reason".to_string(), json!(reason));
        }
        if let Some(ref session_id) = event.session_id {
            map.insert("session_id".to_string(), json!(session_id.to_string()));
        }
        if let Some(ref request_id) = event.request_id {
            map.insert("request_id".to_string(), json!(request_id));
        }

        serde_json::to_string(&obj).map_err(|e| FormatError::SerializationError(e.to_string()))
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
            actor_id: Some(Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap()),
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
    fn test_json_output_is_valid_json() {
        let formatter = JsonFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn test_json_contains_required_fields() {
        let formatter = JsonFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("event_type").is_some());
        assert!(parsed.get("severity").is_some());
        assert!(parsed.get("severity_label").is_some());
        assert!(parsed.get("tenant_id").is_some());
        assert!(parsed.get("action").is_some());
        assert!(parsed.get("outcome").is_some());
        assert!(parsed.get("product").is_some());
        assert!(parsed.get("product_version").is_some());
    }

    #[test]
    fn test_json_contains_optional_fields() {
        let formatter = JsonFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(parsed.get("actor_id").is_some());
        assert!(parsed.get("actor_email").is_some());
        assert!(parsed.get("source_ip").is_some());
        assert!(parsed.get("target_resource").is_some());
        assert!(parsed.get("reason").is_some());
        assert!(parsed.get("session_id").is_some());
        assert!(parsed.get("request_id").is_some());
    }

    #[test]
    fn test_json_severity_label() {
        let formatter = JsonFormatter::new();
        let event = sample_event(); // severity=6
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["severity_label"], "Medium");
    }

    #[test]
    fn test_json_event_type_format() {
        let formatter = JsonFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Should be "category.outcome_lowercase"
        assert_eq!(parsed["event_type"], "authentication.failure");
    }

    #[test]
    fn test_json_product_info() {
        let formatter = JsonFormatter::new();
        let event = sample_event();
        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["product"], "xavyo IDP");
        assert_eq!(parsed["product_version"], "1.0.0");
    }

    #[test]
    fn test_json_omits_none_fields() {
        let formatter = JsonFormatter::new();
        let mut event = sample_event();
        event.actor_id = None;
        event.source_ip = None;
        event.reason = None;
        event.session_id = None;
        event.request_id = None;

        let output = formatter.format(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(parsed.get("actor_id").is_none());
        assert!(parsed.get("source_ip").is_none());
        assert!(parsed.get("reason").is_none());
        assert!(parsed.get("session_id").is_none());
        assert!(parsed.get("request_id").is_none());
    }
}
