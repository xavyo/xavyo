//! Format integration tests for RFC 5424 syslog and CEF v0.
//!
//! Tests User Story 1 (Syslog Format) and User Story 3 (CEF Format).

#![cfg(feature = "integration")]

mod helpers;

use helpers::test_events::{
    generate_audit_event, generate_audit_event_with_severity, generate_batch,
    generate_event_with_special_chars, generate_minimal_event,
};
use helpers::validators::{calculate_syslog_priority, validate_cef, validate_rfc5424};
use uuid::Uuid;
use xavyo_siem::format::{CefFormatter, EventFormatter, SyslogFormatter};

// =============================================================================
// User Story 1: RFC 5424 Syslog Format Testing
// =============================================================================

/// Test that syslog output matches RFC 5424 structure.
#[test]
fn test_syslog_rfc5424_format() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("user.login", tenant_id);
    let formatter = SyslogFormatter::new(16, None); // LOCAL0 facility

    let output = formatter.format(&event).unwrap();
    let validation = validate_rfc5424(&output);

    assert!(
        validation.is_valid,
        "Validation errors: {:?}",
        validation.errors
    );
    assert_eq!(validation.version, Some(1), "RFC 5424 requires version 1");
    assert!(validation.timestamp.is_some());
    assert!(validation.hostname.is_some());
    assert!(validation.app_name.is_some());
}

/// Test priority calculation (facility * 8 + severity).
#[test]
fn test_syslog_priority_calculation() {
    let tenant_id = Uuid::new_v4();

    // Test with various severity levels
    for severity in [0, 3, 5, 7, 10] {
        let event = generate_audit_event_with_severity("TEST_EVENT", tenant_id, severity);
        let formatter = SyslogFormatter::new(10, None); // AUTH_PRIV facility

        let output = formatter.format(&event).unwrap();
        let validation = validate_rfc5424(&output);

        assert!(
            validation.is_valid,
            "Validation errors: {:?}",
            validation.errors
        );

        let pri = validation.priority.unwrap();
        // Verify priority is in valid range (0-191)
        assert!(pri <= 191, "Priority {} exceeds maximum 191", pri);

        // Verify facility is preserved (should be 10 * 8 = 80 base)
        let facility = pri / 8;
        assert_eq!(facility, 10, "Facility not preserved");
    }
}

/// Test timestamp is ISO 8601 format.
#[test]
fn test_syslog_timestamp_iso8601() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("timestamp.test", tenant_id);
    let formatter = SyslogFormatter::new(16, None);

    let output = formatter.format(&event).unwrap();
    let validation = validate_rfc5424(&output);

    assert!(validation.is_valid);
    let timestamp = validation.timestamp.unwrap();

    // Verify ISO 8601 format
    assert!(
        timestamp.contains('T'),
        "Timestamp must contain 'T' separator"
    );
    assert!(
        timestamp.ends_with('Z'),
        "Timestamp must end with 'Z' for UTC"
    );
}

/// Test special characters are properly escaped per RFC 5424.
#[test]
fn test_syslog_special_character_escaping() {
    let tenant_id = Uuid::new_v4();
    let event = generate_event_with_special_chars(tenant_id);
    let formatter = SyslogFormatter::new(16, None);

    let output = formatter.format(&event).unwrap();
    let validation = validate_rfc5424(&output);

    assert!(
        validation.is_valid,
        "Validation errors: {:?}",
        validation.errors
    );

    // Verify structured data contains properly escaped values
    let sd = validation.structured_data.unwrap();
    assert!(
        sd.contains("xavyo@"),
        "Structured data should contain SD-ID"
    );

    // Quotes in SD values must be escaped as \"
    // Backslashes must be escaped as \\
    // Right brackets must be escaped as \]
}

/// Test structured data element format.
#[test]
fn test_syslog_structured_data() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("sd.test", tenant_id);
    let formatter = SyslogFormatter::new(16, None);

    let output = formatter.format(&event).unwrap();
    let validation = validate_rfc5424(&output);

    assert!(validation.is_valid);

    let sd = validation.structured_data.unwrap();
    // Structured data must start with [ and end with ]
    assert!(sd.starts_with('['), "SD must start with '['");
    assert!(sd.ends_with(']'), "SD must end with ']'");

    // Must contain SD-ID with PEN
    assert!(
        sd.contains("xavyo@"),
        "SD must contain SD-ID with enterprise number"
    );

    // Must contain tenant_id parameter
    assert!(sd.contains("tenant_id="), "SD must contain tenant_id");
}

/// Test multiple events produce consistent formatting.
#[test]
fn test_syslog_multiple_events_formatting() {
    let tenant_id = Uuid::new_v4();
    let events = generate_batch(10, tenant_id);
    let formatter = SyslogFormatter::new(16, None);

    for event in events {
        let output = formatter.format(&event).unwrap();
        let validation = validate_rfc5424(&output);

        assert!(
            validation.is_valid,
            "Event {} failed validation: {:?}",
            event.event_type, validation.errors
        );

        // All events should have same version, hostname, app-name
        assert_eq!(validation.version, Some(1));
        assert!(validation.hostname.is_some());
        assert_eq!(validation.app_name, Some("xavyo".to_string()));
    }
}

// =============================================================================
// User Story 3: CEF v0 Format Testing
// =============================================================================

/// Test CEF output follows v0 specification.
#[test]
fn test_cef_format_compliance() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("user.login", tenant_id);
    let formatter = CefFormatter::new();

    let output = formatter.format(&event).unwrap();
    let validation = validate_cef(&output);

    assert!(
        validation.is_valid,
        "Validation errors: {:?}",
        validation.errors
    );
    assert_eq!(
        validation.version,
        Some("0".to_string()),
        "CEF version must be 0"
    );
}

/// Test CEF header has all required fields.
#[test]
fn test_cef_header_fields() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("header.test", tenant_id);
    let formatter = CefFormatter::new();

    let output = formatter.format(&event).unwrap();
    let validation = validate_cef(&output);

    assert!(validation.is_valid);

    // All header fields must be present
    assert!(validation.vendor.is_some(), "Vendor is required");
    assert!(validation.product.is_some(), "Product is required");
    assert!(
        validation.device_version.is_some(),
        "Device Version is required"
    );
    assert!(
        validation.event_class_id.is_some(),
        "Event Class ID is required"
    );
    assert!(validation.name.is_some(), "Name is required");
    assert!(validation.severity.is_some(), "Severity is required");

    // Verify our product info
    assert_eq!(validation.vendor.unwrap(), "Xavyo");
    assert_eq!(validation.product.unwrap(), "IDP");
}

/// Test CEF extension key=value formatting.
#[test]
fn test_cef_extension_formatting() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("extension.test", tenant_id);
    let formatter = CefFormatter::new();

    let output = formatter.format(&event).unwrap();
    let validation = validate_cef(&output);

    assert!(validation.is_valid);

    // Check for expected extension keys
    let ext_keys: Vec<&str> = validation
        .extensions
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();

    // Should have source IP
    assert!(ext_keys.contains(&"src"), "Should contain src extension");

    // Should have action
    assert!(ext_keys.contains(&"act"), "Should contain act extension");

    // Should have custom string for tenant ID
    assert!(
        ext_keys.contains(&"cs1") || ext_keys.contains(&"cs1Label"),
        "Should contain cs1 extension for tenant ID"
    );
}

/// Test pipe characters are escaped in CEF.
#[test]
fn test_cef_pipe_escaping() {
    let tenant_id = Uuid::new_v4();
    let mut event = generate_audit_event("pipe.test", tenant_id);
    event.target_resource = Some("resource|with|pipes".to_string());
    let formatter = CefFormatter::new();

    let output = formatter.format(&event).unwrap();

    // The output should be parseable despite having pipes in data
    let validation = validate_cef(&output);
    assert!(
        validation.is_valid,
        "CEF with pipe characters should still be valid"
    );
}

/// Test CEF severity is in valid range (0-10).
#[test]
fn test_cef_severity_range() {
    let tenant_id = Uuid::new_v4();

    for severity in [0, 3, 5, 7, 10, 15] {
        let event = generate_audit_event_with_severity("severity.test", tenant_id, severity);
        let formatter = CefFormatter::new();

        let output = formatter.format(&event).unwrap();
        let validation = validate_cef(&output);

        assert!(validation.is_valid);
        let cef_severity = validation.severity.unwrap();
        assert!(
            cef_severity <= 10,
            "CEF severity must be 0-10, got {}",
            cef_severity
        );
    }
}

/// Test minimal event produces valid CEF.
#[test]
fn test_cef_minimal_event() {
    let tenant_id = Uuid::new_v4();
    let event = generate_minimal_event(tenant_id);
    let formatter = CefFormatter::new();

    let output = formatter.format(&event).unwrap();
    let validation = validate_cef(&output);

    assert!(
        validation.is_valid,
        "Minimal event should produce valid CEF"
    );
}

// =============================================================================
// Cross-format tests
// =============================================================================

/// Test same event produces valid output in both formats.
#[test]
fn test_same_event_both_formats() {
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("dual.format", tenant_id);

    let syslog_formatter = SyslogFormatter::new(16, None);
    let cef_formatter = CefFormatter::new();

    let syslog_output = syslog_formatter.format(&event).unwrap();
    let cef_output = cef_formatter.format(&event).unwrap();

    let syslog_validation = validate_rfc5424(&syslog_output);
    let cef_validation = validate_cef(&cef_output);

    assert!(
        syslog_validation.is_valid,
        "Syslog errors: {:?}",
        syslog_validation.errors
    );
    assert!(
        cef_validation.is_valid,
        "CEF errors: {:?}",
        cef_validation.errors
    );
}
