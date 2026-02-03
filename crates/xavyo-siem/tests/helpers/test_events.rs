//! Test event generators for SIEM integration tests.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_siem::models::{EventCategory, SiemEvent};

/// Generate a sample audit event with specified type and tenant.
pub fn generate_audit_event(event_type: &str, tenant_id: Uuid) -> SiemEvent {
    SiemEvent {
        event_id: Uuid::new_v4(),
        event_type: event_type.to_string(),
        category: EventCategory::Authentication,
        tenant_id,
        actor_id: Some(Uuid::new_v4()),
        actor_email: Some("test@example.com".to_string()),
        timestamp: Utc::now(),
        severity: 5,
        event_name: format!("Test Event: {}", event_type),
        source_ip: Some("192.168.1.100".to_string()),
        target_user: Some("target@example.com".to_string()),
        target_resource: Some("login_endpoint".to_string()),
        action: "Login".to_string(),
        outcome: "Success".to_string(),
        reason: None,
        session_id: Some(Uuid::new_v4()),
        request_id: Some(format!("req-{}", Uuid::new_v4())),
        metadata: HashMap::new(),
    }
}

/// Generate an audit event with a specific timestamp.
pub fn generate_audit_event_with_timestamp(
    event_type: &str,
    tenant_id: Uuid,
    timestamp: DateTime<Utc>,
) -> SiemEvent {
    let mut event = generate_audit_event(event_type, tenant_id);
    event.timestamp = timestamp;
    event
}

/// Generate an audit event with a specific severity.
pub fn generate_audit_event_with_severity(
    event_type: &str,
    tenant_id: Uuid,
    severity: u8,
) -> SiemEvent {
    let mut event = generate_audit_event(event_type, tenant_id);
    event.severity = severity;
    event
}

/// Generate a batch of audit events.
pub fn generate_batch(count: usize, tenant_id: Uuid) -> Vec<SiemEvent> {
    (0..count)
        .map(|i| {
            let event_type = match i % 5 {
                0 => "AUTH_SUCCESS",
                1 => "AUTH_FAILURE",
                2 => "USER_CREATED",
                3 => "GROUP_MODIFIED",
                _ => "ACCESS_GRANTED",
            };
            let mut event = generate_audit_event(event_type, tenant_id);
            event.severity = ((i % 10) + 1) as u8;
            event
        })
        .collect()
}

/// Generate an event with special characters in string fields.
pub fn generate_event_with_special_chars(tenant_id: Uuid) -> SiemEvent {
    SiemEvent {
        event_id: Uuid::new_v4(),
        event_type: "SPECIAL_CHARS".to_string(),
        category: EventCategory::Security,
        tenant_id,
        actor_id: Some(Uuid::new_v4()),
        actor_email: Some("test\"user@example.com".to_string()),
        timestamp: Utc::now(),
        severity: 7,
        event_name: "Event with \"quotes\" and \\backslash".to_string(),
        source_ip: Some("10.0.0.1".to_string()),
        target_user: Some("user with spaces and ]brackets".to_string()),
        target_resource: Some("resource|with|pipes".to_string()),
        action: "Action=WithEquals".to_string(),
        outcome: "Success".to_string(),
        reason: Some("Reason with\nnewline".to_string()),
        session_id: Some(Uuid::new_v4()),
        request_id: None,
        metadata: HashMap::new(),
    }
}

/// Generate an event without optional fields.
pub fn generate_minimal_event(tenant_id: Uuid) -> SiemEvent {
    SiemEvent {
        event_id: Uuid::new_v4(),
        event_type: "MINIMAL_EVENT".to_string(),
        category: EventCategory::Administrative,
        tenant_id,
        actor_id: None,
        actor_email: None,
        timestamp: Utc::now(),
        severity: 3,
        event_name: "Minimal Event".to_string(),
        source_ip: None,
        target_user: None,
        target_resource: None,
        action: "MinimalAction".to_string(),
        outcome: "Success".to_string(),
        reason: None,
        session_id: None,
        request_id: None,
        metadata: HashMap::new(),
    }
}

/// Generate an event with high severity (critical).
pub fn generate_critical_event(tenant_id: Uuid) -> SiemEvent {
    SiemEvent {
        event_id: Uuid::new_v4(),
        event_type: "CRITICAL_SECURITY_ALERT".to_string(),
        category: EventCategory::SodViolation,
        tenant_id,
        actor_id: Some(Uuid::new_v4()),
        actor_email: Some("attacker@malicious.com".to_string()),
        timestamp: Utc::now(),
        severity: 10,
        event_name: "Critical Security Alert".to_string(),
        source_ip: Some("198.51.100.1".to_string()),
        target_user: Some("admin@company.com".to_string()),
        target_resource: Some("sensitive_data".to_string()),
        action: "Unauthorized Access Attempt".to_string(),
        outcome: "Failure".to_string(),
        reason: Some("SoD Violation Detected".to_string()),
        session_id: Some(Uuid::new_v4()),
        request_id: Some("req-critical-001".to_string()),
        metadata: {
            let mut m = HashMap::new();
            m.insert("alert_level".to_string(), "critical".to_string());
            m.insert("requires_action".to_string(), "true".to_string());
            m
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_audit_event() {
        let tenant_id = Uuid::new_v4();
        let event = generate_audit_event("AUTH_SUCCESS", tenant_id);

        assert_eq!(event.event_type, "AUTH_SUCCESS");
        assert_eq!(event.tenant_id, tenant_id);
        assert!(event.actor_id.is_some());
        assert!(event.source_ip.is_some());
    }

    #[test]
    fn test_generate_batch() {
        let tenant_id = Uuid::new_v4();
        let events = generate_batch(100, tenant_id);

        assert_eq!(events.len(), 100);
        for event in &events {
            assert_eq!(event.tenant_id, tenant_id);
        }
    }

    #[test]
    fn test_generate_event_with_special_chars() {
        let tenant_id = Uuid::new_v4();
        let event = generate_event_with_special_chars(tenant_id);

        assert!(event.actor_email.unwrap().contains('"'));
        assert!(event.event_name.contains('"'));
        assert!(event.event_name.contains('\\'));
    }

    #[test]
    fn test_generate_minimal_event() {
        let tenant_id = Uuid::new_v4();
        let event = generate_minimal_event(tenant_id);

        assert!(event.actor_id.is_none());
        assert!(event.source_ip.is_none());
        assert!(event.target_user.is_none());
    }

    #[test]
    fn test_generate_critical_event() {
        let tenant_id = Uuid::new_v4();
        let event = generate_critical_event(tenant_id);

        assert_eq!(event.severity, 10);
        assert_eq!(event.category, EventCategory::SodViolation);
    }
}
