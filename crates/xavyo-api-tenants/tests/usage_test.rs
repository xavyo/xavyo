//! Integration tests for tenant usage tracking handlers.
//!
//! F-USAGE-TRACK: Tests for usage metrics functionality.

use chrono::NaiveDate;
use uuid::Uuid;
use xavyo_api_tenants::models::{
    UsageHistoryQuery, UsageHistoryResponse, UsageLimits, UsageMetrics, UsagePeriod, UsageResponse,
};

/// Test UsageMetrics serialization.
#[test]
fn test_usage_metrics_serialization() {
    let metrics = UsageMetrics {
        mau_count: 150,
        api_calls: 45230,
        auth_events: 3200,
        agent_invocations: 500,
    };

    let json = serde_json::to_string(&metrics).unwrap();
    assert!(json.contains("\"mau_count\":150"));
    assert!(json.contains("\"api_calls\":45230"));
    assert!(json.contains("\"auth_events\":3200"));
    assert!(json.contains("\"agent_invocations\":500"));
}

/// Test UsageLimits serialization with values.
#[test]
fn test_usage_limits_serialization_with_values() {
    let limits = UsageLimits {
        max_mau: Some(500),
        max_api_calls: None,
        max_agent_invocations: Some(10000),
    };

    let json = serde_json::to_string(&limits).unwrap();
    assert!(json.contains("\"max_mau\":500"));
    // max_api_calls should be skipped when None
    assert!(!json.contains("max_api_calls"));
    assert!(json.contains("\"max_agent_invocations\":10000"));
}

/// Test UsageLimits default.
#[test]
fn test_usage_limits_default() {
    let limits = UsageLimits::default();
    assert!(limits.max_mau.is_none());
    assert!(limits.max_api_calls.is_none());
    assert!(limits.max_agent_invocations.is_none());
}

/// Test UsageResponse serialization.
#[test]
fn test_usage_response_serialization() {
    let response = UsageResponse {
        tenant_id: Uuid::new_v4(),
        period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
        metrics: UsageMetrics {
            mau_count: 100,
            api_calls: 5000,
            auth_events: 200,
            agent_invocations: 50,
        },
        limits: UsageLimits::default(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("period_start"));
    assert!(json.contains("period_end"));
    assert!(json.contains("metrics"));
    assert!(json.contains("limits"));
    assert!(json.contains("\"mau_count\":100"));
}

/// Test UsagePeriod serialization.
#[test]
fn test_usage_period_serialization() {
    let period = UsagePeriod {
        period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
        mau_count: 100,
        api_calls: 5000,
        auth_events: 200,
        agent_invocations: 50,
    };

    let json = serde_json::to_string(&period).unwrap();
    assert!(json.contains("period_start"));
    assert!(json.contains("period_end"));
    assert!(json.contains("\"mau_count\":100"));
    assert!(json.contains("\"api_calls\":5000"));
}

/// Test UsageHistoryResponse serialization.
#[test]
fn test_usage_history_response_serialization() {
    let response = UsageHistoryResponse {
        tenant_id: Uuid::new_v4(),
        periods: vec![
            UsagePeriod {
                period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
                mau_count: 100,
                api_calls: 5000,
                auth_events: 200,
                agent_invocations: 50,
            },
            UsagePeriod {
                period_start: NaiveDate::from_ymd_opt(2023, 12, 1).unwrap(),
                period_end: NaiveDate::from_ymd_opt(2023, 12, 31).unwrap(),
                mau_count: 95,
                api_calls: 4500,
                auth_events: 180,
                agent_invocations: 45,
            },
        ],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("periods"));
    assert!(json.contains("\"mau_count\":100"));
    assert!(json.contains("\"mau_count\":95"));
}

/// Test UsageHistoryResponse empty periods.
#[test]
fn test_usage_history_response_empty() {
    let response = UsageHistoryResponse {
        tenant_id: Uuid::new_v4(),
        periods: vec![],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("tenant_id"));
    assert!(json.contains("\"periods\":[]"));
}

/// Test UsageHistoryQuery validation - valid default.
#[test]
fn test_usage_history_query_validation_valid_default() {
    let query = UsageHistoryQuery::default();
    assert!(query.validate().is_none());
    assert_eq!(query.periods, 6);
}

/// Test UsageHistoryQuery validation - zero periods.
#[test]
fn test_usage_history_query_validation_zero_periods() {
    let query = UsageHistoryQuery { periods: 0 };
    let error = query.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("at least 1"));
}

/// Test UsageHistoryQuery validation - too many periods.
#[test]
fn test_usage_history_query_validation_too_many_periods() {
    let query = UsageHistoryQuery { periods: 25 };
    let error = query.validate();
    assert!(error.is_some());
    assert!(error.unwrap().contains("at most 24"));
}

/// Test UsageHistoryQuery validation - max periods.
#[test]
fn test_usage_history_query_validation_max_periods() {
    let query = UsageHistoryQuery { periods: 24 };
    assert!(query.validate().is_none());
}

/// Test UsageHistoryQuery validation - single period.
#[test]
fn test_usage_history_query_validation_single_period() {
    let query = UsageHistoryQuery { periods: 1 };
    assert!(query.validate().is_none());
}

/// Test UsageHistoryQuery deserialization with default.
#[test]
fn test_usage_history_query_deserialization_default() {
    let json = "{}";
    let query: UsageHistoryQuery = serde_json::from_str(json).unwrap();
    assert_eq!(query.periods, 6);
}

/// Test UsageHistoryQuery deserialization with value.
#[test]
fn test_usage_history_query_deserialization_with_value() {
    let json = r#"{"periods": 12}"#;
    let query: UsageHistoryQuery = serde_json::from_str(json).unwrap();
    assert_eq!(query.periods, 12);
}

/// Test UsageLimits full serialization (all values).
#[test]
fn test_usage_limits_full_serialization() {
    let limits = UsageLimits {
        max_mau: Some(1000),
        max_api_calls: Some(100000),
        max_agent_invocations: Some(5000),
    };

    let json = serde_json::to_string(&limits).unwrap();
    assert!(json.contains("\"max_mau\":1000"));
    assert!(json.contains("\"max_api_calls\":100000"));
    assert!(json.contains("\"max_agent_invocations\":5000"));
}
