//! Integration tests for quota enforcement.
//!
//! F-QUOTA-ENFORCE: Tests for quota service and middleware.

use xavyo_api_tenants::middleware::{QuotaDetails, QuotaExceededError};
use xavyo_api_tenants::services::{QuotaCheck, QuotaType, TenantLimits};

/// Test `QuotaType` display implementation.
#[test]
fn test_quota_type_display() {
    assert_eq!(QuotaType::Mau.to_string(), "mau");
    assert_eq!(QuotaType::ApiCalls.to_string(), "api_calls");
    assert_eq!(QuotaType::AgentInvocations.to_string(), "agent_invocations");
}

/// Test `QuotaType` serialization.
#[test]
fn test_quota_type_serialization() {
    let quota = QuotaType::ApiCalls;
    let json = serde_json::to_string(&quota).unwrap();
    assert_eq!(json, "\"api_calls\"");

    let quota = QuotaType::Mau;
    let json = serde_json::to_string(&quota).unwrap();
    assert_eq!(json, "\"mau\"");

    let quota = QuotaType::AgentInvocations;
    let json = serde_json::to_string(&quota).unwrap();
    assert_eq!(json, "\"agent_invocations\"");
}

/// Test `QuotaType` deserialization.
#[test]
fn test_quota_type_deserialization() {
    let quota: QuotaType = serde_json::from_str("\"api_calls\"").unwrap();
    assert_eq!(quota, QuotaType::ApiCalls);

    let quota: QuotaType = serde_json::from_str("\"mau\"").unwrap();
    assert_eq!(quota, QuotaType::Mau);

    let quota: QuotaType = serde_json::from_str("\"agent_invocations\"").unwrap();
    assert_eq!(quota, QuotaType::AgentInvocations);
}

/// Test `QuotaCheck` serialization.
#[test]
fn test_quota_check_serialization() {
    let check = QuotaCheck {
        exceeded: true,
        quota_type: QuotaType::ApiCalls,
        current: 100500,
        limit: Some(100000),
        reset_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&check).unwrap();
    assert!(json.contains("\"exceeded\":true"));
    assert!(json.contains("\"quota_type\":\"api_calls\""));
    assert!(json.contains("\"current\":100500"));
    assert!(json.contains("\"limit\":100000"));
    assert!(json.contains("\"reset_at\""));
}

/// Test `QuotaCheck` with no limit.
#[test]
fn test_quota_check_no_limit() {
    let check = QuotaCheck {
        exceeded: false,
        quota_type: QuotaType::ApiCalls,
        current: 100500,
        limit: None,
        reset_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&check).unwrap();
    assert!(json.contains("\"exceeded\":false"));
    assert!(json.contains("\"limit\":null"));
}

/// Test `TenantLimits` default.
#[test]
fn test_tenant_limits_default() {
    let limits = TenantLimits::default();
    assert!(limits.max_mau.is_none());
    assert!(limits.max_api_calls.is_none());
    assert!(limits.max_agent_invocations.is_none());
}

/// Test `QuotaDetails` serialization.
#[test]
fn test_quota_details_serialization() {
    let details = QuotaDetails {
        quota_type: QuotaType::ApiCalls,
        current: 100500,
        limit: 100000,
        reset_at: "2024-02-01T00:00:00Z".to_string(),
    };

    let json = serde_json::to_string(&details).unwrap();
    assert!(json.contains("\"quota_type\":\"api_calls\""));
    assert!(json.contains("\"current\":100500"));
    assert!(json.contains("\"limit\":100000"));
    assert!(json.contains("\"reset_at\":\"2024-02-01T00:00:00Z\""));
}

/// Test `QuotaExceededError` serialization.
#[test]
fn test_quota_exceeded_error_serialization() {
    let error = QuotaExceededError {
        error: "quota_exceeded".to_string(),
        message: "Monthly API call limit exceeded".to_string(),
        details: QuotaDetails {
            quota_type: QuotaType::ApiCalls,
            current: 100500,
            limit: 100000,
            reset_at: "2024-02-01T00:00:00Z".to_string(),
        },
    };

    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("\"error\":\"quota_exceeded\""));
    assert!(json.contains("Monthly API call limit exceeded"));
    assert!(json.contains("\"details\""));
    assert!(json.contains("\"quota_type\":\"api_calls\""));
}

/// Test `QuotaExceededError` for MAU.
#[test]
fn test_quota_exceeded_error_mau() {
    let error = QuotaExceededError {
        error: "quota_exceeded".to_string(),
        message: "Monthly active user limit exceeded. Please upgrade your plan.".to_string(),
        details: QuotaDetails {
            quota_type: QuotaType::Mau,
            current: 550,
            limit: 500,
            reset_at: "2024-02-01T00:00:00Z".to_string(),
        },
    };

    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("\"quota_type\":\"mau\""));
    assert!(json.contains("\"current\":550"));
    assert!(json.contains("\"limit\":500"));
}

/// Test `QuotaExceededError` for agent invocations.
#[test]
fn test_quota_exceeded_error_agent_invocations() {
    let error = QuotaExceededError {
        error: "quota_exceeded".to_string(),
        message: "Monthly agent invocation limit exceeded".to_string(),
        details: QuotaDetails {
            quota_type: QuotaType::AgentInvocations,
            current: 10500,
            limit: 10000,
            reset_at: "2024-02-01T00:00:00Z".to_string(),
        },
    };

    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("\"quota_type\":\"agent_invocations\""));
    assert!(json.contains("\"current\":10500"));
    assert!(json.contains("\"limit\":10000"));
}

/// Test `QuotaCheck` exceeded state.
#[test]
fn test_quota_check_exceeded_state() {
    let exceeded_check = QuotaCheck {
        exceeded: true,
        quota_type: QuotaType::ApiCalls,
        current: 100500,
        limit: Some(100000),
        reset_at: chrono::Utc::now(),
    };

    assert!(exceeded_check.exceeded);
    assert!(exceeded_check.current > exceeded_check.limit.unwrap());

    let within_limit_check = QuotaCheck {
        exceeded: false,
        quota_type: QuotaType::ApiCalls,
        current: 50000,
        limit: Some(100000),
        reset_at: chrono::Utc::now(),
    };

    assert!(!within_limit_check.exceeded);
    assert!(within_limit_check.current < within_limit_check.limit.unwrap());
}

/// Test `QuotaType` equality.
#[test]
fn test_quota_type_equality() {
    assert_eq!(QuotaType::Mau, QuotaType::Mau);
    assert_eq!(QuotaType::ApiCalls, QuotaType::ApiCalls);
    assert_eq!(QuotaType::AgentInvocations, QuotaType::AgentInvocations);

    assert_ne!(QuotaType::Mau, QuotaType::ApiCalls);
    assert_ne!(QuotaType::ApiCalls, QuotaType::AgentInvocations);
    assert_ne!(QuotaType::Mau, QuotaType::AgentInvocations);
}
