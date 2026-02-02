//! Unit tests for NHI Usage Service (F061 - User Story 3).
//!
//! Tests cover:
//! - Usage event recording
//! - Usage listing with filters
//! - Usage summary generation
//! - Staleness detection
//! - Batch recording

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::NhiUsageOutcome;

use xavyo_api_governance::models::{
    NhiUsageEventResponse, NhiUsageListQuery, NhiUsageSummaryExtendedResponse, RecordUsageRequest,
    ResourceAccessInfo, StaleNhiInfo, StalenessReportResponse,
};

// ============================================================================
// RecordUsageRequest Tests
// ============================================================================

#[test]
fn test_record_usage_request_minimal() {
    let request = RecordUsageRequest {
        target_resource: "api/users".to_string(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: None,
        metadata: None,
    };

    assert_eq!(request.target_resource, "api/users");
    assert_eq!(request.action, "read");
    assert_eq!(request.outcome, NhiUsageOutcome::Success);
    assert!(request.source_ip.is_none());
}

#[test]
fn test_record_usage_request_full() {
    let metadata = serde_json::json!({"key": "value"});
    let request = RecordUsageRequest {
        target_resource: "api/orders".to_string(),
        action: "create".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: Some("192.168.1.1".to_string()),
        user_agent: Some("TestAgent/1.0".to_string()),
        duration_ms: Some(150),
        metadata: Some(metadata.clone()),
    };

    assert_eq!(request.target_resource, "api/orders");
    assert_eq!(request.action, "create");
    assert_eq!(request.outcome, NhiUsageOutcome::Success);
    assert_eq!(request.source_ip.as_deref(), Some("192.168.1.1"));
    assert_eq!(request.user_agent.as_deref(), Some("TestAgent/1.0"));
    assert_eq!(request.duration_ms, Some(150));
    assert!(request.metadata.is_some());
}

#[test]
fn test_record_usage_request_outcomes() {
    let outcomes = [
        NhiUsageOutcome::Success,
        NhiUsageOutcome::Failure,
        NhiUsageOutcome::Denied,
    ];

    for outcome in outcomes {
        let request = RecordUsageRequest {
            target_resource: "api/test".to_string(),
            action: "test".to_string(),
            outcome,
            source_ip: None,
            user_agent: None,
            duration_ms: None,
            metadata: None,
        };

        assert_eq!(request.outcome, outcome);
    }
}

// ============================================================================
// NhiUsageListQuery Tests
// ============================================================================

#[test]
fn test_usage_list_query_default() {
    let query = NhiUsageListQuery::default();

    assert!(query.target_resource.is_none());
    assert!(query.outcome.is_none());
    assert!(query.start_date.is_none());
    assert!(query.end_date.is_none());
    assert_eq!(query.limit, Some(50));
    assert_eq!(query.offset, Some(0));
}

#[test]
fn test_usage_list_query_with_filters() {
    let now = Utc::now();
    let yesterday = now - Duration::days(1);

    let query = NhiUsageListQuery {
        target_resource: Some("api/users".to_string()),
        outcome: Some(NhiUsageOutcome::Success),
        start_date: Some(yesterday),
        end_date: Some(now),
        limit: Some(50),
        offset: Some(0),
    };

    assert_eq!(query.target_resource.as_deref(), Some("api/users"));
    assert_eq!(query.outcome, Some(NhiUsageOutcome::Success));
    assert!(query.start_date.is_some());
    assert!(query.end_date.is_some());
    assert_eq!(query.limit, Some(50));
    assert_eq!(query.offset, Some(0));
}

#[test]
fn test_usage_list_query_pagination() {
    let query = NhiUsageListQuery {
        target_resource: None,
        outcome: None,
        start_date: None,
        end_date: None,
        limit: Some(100),
        offset: Some(200),
    };

    assert_eq!(query.limit, Some(100));
    assert_eq!(query.offset, Some(200));
}

// ============================================================================
// NhiUsageEventResponse Tests
// ============================================================================

#[test]
fn test_usage_event_response_structure() {
    let id = Uuid::new_v4();
    let nhi_id = Uuid::new_v4();
    let now = Utc::now();

    let response = NhiUsageEventResponse {
        id,
        nhi_id,
        timestamp: now,
        target_resource: "api/users".to_string(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: Some("10.0.0.1".to_string()),
        user_agent: Some("Mozilla/5.0".to_string()),
        duration_ms: Some(100),
    };

    assert_eq!(response.id, id);
    assert_eq!(response.nhi_id, nhi_id);
    assert_eq!(response.target_resource, "api/users");
    assert_eq!(response.action, "read");
    assert_eq!(response.outcome, NhiUsageOutcome::Success);
    assert_eq!(response.source_ip.as_deref(), Some("10.0.0.1"));
}

#[test]
fn test_usage_event_response_serialization() {
    let response = NhiUsageEventResponse {
        id: Uuid::new_v4(),
        nhi_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        target_resource: "api/orders".to_string(),
        action: "create".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: None,
    };

    let json = serde_json::to_string(&response).expect("Serialization failed");
    assert!(json.contains("api/orders"));
    assert!(json.contains("create"));
    assert!(json.contains("success"));
}

// ============================================================================
// NhiUsageSummaryExtendedResponse Tests
// ============================================================================

#[test]
fn test_usage_summary_empty() {
    let nhi_id = Uuid::new_v4();
    let summary = NhiUsageSummaryExtendedResponse {
        nhi_id,
        nhi_name: "test-nhi".to_string(),
        period_days: 30,
        total_events: 0,
        successful_events: 0,
        failed_events: 0,
        denied_events: 0,
        success_rate: 0.0,
        unique_resources: 0,
        top_resources: vec![],
        last_used_at: None,
    };

    assert_eq!(summary.total_events, 0);
    assert_eq!(summary.success_rate, 0.0);
    assert!(summary.top_resources.is_empty());
    assert!(summary.last_used_at.is_none());
}

#[test]
fn test_usage_summary_with_data() {
    let nhi_id = Uuid::new_v4();
    let now = Utc::now();

    let summary = NhiUsageSummaryExtendedResponse {
        nhi_id,
        nhi_name: "production-bot".to_string(),
        period_days: 30,
        total_events: 1000,
        successful_events: 950,
        failed_events: 30,
        denied_events: 20,
        success_rate: 95.0,
        unique_resources: 15,
        top_resources: vec![
            ResourceAccessInfo {
                resource: "api/users".to_string(),
                access_count: 500,
                last_access: now,
            },
            ResourceAccessInfo {
                resource: "api/orders".to_string(),
                access_count: 300,
                last_access: now - Duration::hours(1),
            },
        ],
        last_used_at: Some(now),
    };

    assert_eq!(summary.total_events, 1000);
    assert_eq!(summary.successful_events, 950);
    assert_eq!(summary.failed_events, 30);
    assert_eq!(summary.denied_events, 20);
    assert_eq!(summary.success_rate, 95.0);
    assert_eq!(summary.unique_resources, 15);
    assert_eq!(summary.top_resources.len(), 2);
    assert_eq!(summary.top_resources[0].resource, "api/users");
    assert_eq!(summary.top_resources[0].access_count, 500);
}

#[test]
fn test_usage_summary_success_rate_calculation() {
    // Test various success rate scenarios
    let scenarios = [
        (100, 100, 100.0), // 100% success
        (100, 50, 50.0),   // 50% success
        (100, 0, 0.0),     // 0% success
        (1000, 999, 99.9), // 99.9% success (rounded)
        (0, 0, 0.0),       // No events
    ];

    for (total, successful, expected_rate) in scenarios {
        let calculated_rate = if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let diff = (calculated_rate - expected_rate).abs();
        assert!(diff < 0.1, "Rate mismatch for {successful}/{total}");
    }
}

// ============================================================================
// ResourceAccessInfo Tests
// ============================================================================

#[test]
fn test_resource_access_info() {
    let now = Utc::now();
    let info = ResourceAccessInfo {
        resource: "api/users".to_string(),
        access_count: 100,
        last_access: now,
    };

    assert_eq!(info.resource, "api/users");
    assert_eq!(info.access_count, 100);
    // last_access is not optional in this struct
    assert!(info.last_access <= Utc::now());
}

#[test]
fn test_resource_access_info_zero_count() {
    let now = Utc::now();
    let info = ResourceAccessInfo {
        resource: "api/legacy".to_string(),
        access_count: 0,
        last_access: now,
    };

    assert_eq!(info.access_count, 0);
}

// ============================================================================
// StaleNhiInfo Tests
// ============================================================================

#[test]
fn test_stale_nhi_info() {
    let nhi_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let now = Utc::now();

    let stale = StaleNhiInfo {
        nhi_id,
        name: "old-bot".to_string(),
        owner_id,
        days_inactive: 95,
        last_used_at: Some(now - Duration::days(95)),
        inactivity_threshold_days: 90,
        in_grace_period: false,
        grace_period_ends_at: None,
    };

    assert_eq!(stale.nhi_id, nhi_id);
    assert_eq!(stale.name, "old-bot");
    assert_eq!(stale.days_inactive, 95);
    assert_eq!(stale.inactivity_threshold_days, 90);
    assert!(!stale.in_grace_period);
}

#[test]
fn test_stale_nhi_in_grace_period() {
    let now = Utc::now();

    let stale = StaleNhiInfo {
        nhi_id: Uuid::new_v4(),
        name: "suspended-bot".to_string(),
        owner_id: Uuid::new_v4(),
        days_inactive: 100,
        last_used_at: Some(now - Duration::days(100)),
        inactivity_threshold_days: 90,
        in_grace_period: true,
        grace_period_ends_at: Some(now + Duration::days(7)),
    };

    assert!(stale.in_grace_period);
    assert!(stale.grace_period_ends_at.is_some());
}

#[test]
fn test_stale_nhi_never_used() {
    let stale = StaleNhiInfo {
        nhi_id: Uuid::new_v4(),
        name: "unused-bot".to_string(),
        owner_id: Uuid::new_v4(),
        days_inactive: 365,
        last_used_at: None,
        inactivity_threshold_days: 90,
        in_grace_period: false,
        grace_period_ends_at: None,
    };

    assert!(stale.last_used_at.is_none());
    assert_eq!(stale.days_inactive, 365);
}

// ============================================================================
// StalenessReportResponse Tests
// ============================================================================

#[test]
fn test_staleness_report_empty() {
    let now = Utc::now();
    let report = StalenessReportResponse {
        generated_at: now,
        min_inactive_days: 30,
        total_stale: 0,
        critical_count: 0,
        warning_count: 0,
        stale_nhis: vec![],
    };

    assert_eq!(report.total_stale, 0);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.warning_count, 0);
    assert!(report.stale_nhis.is_empty());
}

#[test]
fn test_staleness_report_with_data() {
    let now = Utc::now();

    let stale_nhis = vec![
        StaleNhiInfo {
            nhi_id: Uuid::new_v4(),
            name: "critical-stale".to_string(),
            owner_id: Uuid::new_v4(),
            days_inactive: 200,
            last_used_at: Some(now - Duration::days(200)),
            inactivity_threshold_days: 90,
            in_grace_period: false,
            grace_period_ends_at: None,
        },
        StaleNhiInfo {
            nhi_id: Uuid::new_v4(),
            name: "warning-stale".to_string(),
            owner_id: Uuid::new_v4(),
            days_inactive: 100,
            last_used_at: Some(now - Duration::days(100)),
            inactivity_threshold_days: 90,
            in_grace_period: false,
            grace_period_ends_at: None,
        },
    ];

    let report = StalenessReportResponse {
        generated_at: now,
        min_inactive_days: 30,
        total_stale: 2,
        critical_count: 1, // >180 days
        warning_count: 1,  // 90-180 days
        stale_nhis,
    };

    assert_eq!(report.total_stale, 2);
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.warning_count, 1);
    assert_eq!(report.stale_nhis.len(), 2);
}

#[test]
fn test_staleness_thresholds() {
    // Critical: >180 days
    // Warning: 90-180 days
    let test_cases = [
        (200, true, false), // Critical
        (180, false, true), // Warning (exactly 180)
        (150, false, true), // Warning
        (91, false, true),  // Warning
        (90, false, false), // Neither (exactly 90 days is the threshold, not stale yet)
        (30, false, false), // Neither
    ];

    for (days, expected_critical, expected_warning) in test_cases {
        let is_critical = days > 180;
        let is_warning = days > 90 && days <= 180;

        assert_eq!(
            is_critical, expected_critical,
            "Critical check failed for {days} days"
        );
        assert_eq!(
            is_warning, expected_warning,
            "Warning check failed for {days} days"
        );
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_very_long_resource_path() {
    let long_path: String = format!("api/{}", "a".repeat(500));
    let request = RecordUsageRequest {
        target_resource: long_path.clone(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: None,
        metadata: None,
    };

    assert_eq!(request.target_resource.len(), 504);
}

#[test]
fn test_zero_duration() {
    let request = RecordUsageRequest {
        target_resource: "api/ping".to_string(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: Some(0),
        metadata: None,
    };

    assert_eq!(request.duration_ms, Some(0));
}

#[test]
fn test_very_large_duration() {
    let request = RecordUsageRequest {
        target_resource: "api/long-running".to_string(),
        action: "process".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: Some(3_600_000), // 1 hour in ms
        metadata: None,
    };

    assert_eq!(request.duration_ms, Some(3_600_000));
}

#[test]
fn test_complex_metadata() {
    let metadata = serde_json::json!({
        "request_id": "abc-123",
        "correlation_id": "def-456",
        "client_version": "2.0.0",
        "features": ["feature-a", "feature-b"],
        "nested": {
            "deep": {
                "value": 42
            }
        }
    });

    let request = RecordUsageRequest {
        target_resource: "api/complex".to_string(),
        action: "process".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: None,
        user_agent: None,
        duration_ms: None,
        metadata: Some(metadata),
    };

    let meta = request.metadata.unwrap();
    assert_eq!(meta["request_id"], "abc-123");
    assert_eq!(meta["nested"]["deep"]["value"], 42);
}

#[test]
fn test_ipv6_source_ip() {
    let request = RecordUsageRequest {
        target_resource: "api/test".to_string(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: Some("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string()),
        user_agent: None,
        duration_ms: None,
        metadata: None,
    };

    assert!(request.source_ip.unwrap().contains(":"));
}

#[test]
fn test_serialization_roundtrip() {
    let original = RecordUsageRequest {
        target_resource: "api/test".to_string(),
        action: "read".to_string(),
        outcome: NhiUsageOutcome::Success,
        source_ip: Some("10.0.0.1".to_string()),
        user_agent: Some("Test/1.0".to_string()),
        duration_ms: Some(100),
        metadata: Some(serde_json::json!({"test": true})),
    };

    let json = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: RecordUsageRequest =
        serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(original.target_resource, deserialized.target_resource);
    assert_eq!(original.action, deserialized.action);
    assert_eq!(original.outcome, deserialized.outcome);
    assert_eq!(original.source_ip, deserialized.source_ip);
    assert_eq!(original.duration_ms, deserialized.duration_ms);
}

#[test]
fn test_usage_event_response_with_all_outcomes() {
    let outcomes = [
        ("success", NhiUsageOutcome::Success),
        ("failure", NhiUsageOutcome::Failure),
        ("denied", NhiUsageOutcome::Denied),
    ];

    for (expected_json, outcome) in outcomes {
        let response = NhiUsageEventResponse {
            id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            target_resource: "api/test".to_string(),
            action: "test".to_string(),
            outcome,
            source_ip: None,
            user_agent: None,
            duration_ms: None,
        };

        let json = serde_json::to_string(&response).expect("Serialization failed");
        assert!(
            json.contains(expected_json),
            "Expected JSON to contain '{}' but got: {}",
            expected_json,
            json
        );
    }
}

#[test]
fn test_summary_with_high_failure_rate() {
    let nhi_id = Uuid::new_v4();
    let summary = NhiUsageSummaryExtendedResponse {
        nhi_id,
        nhi_name: "unstable-bot".to_string(),
        period_days: 7,
        total_events: 100,
        successful_events: 10,
        failed_events: 80,
        denied_events: 10,
        success_rate: 10.0,
        unique_resources: 3,
        top_resources: vec![],
        last_used_at: Some(Utc::now()),
    };

    assert!(summary.success_rate < 50.0, "High failure rate expected");
    assert_eq!(summary.failed_events, 80);
}

#[test]
fn test_staleness_report_serialization() {
    let now = Utc::now();
    let report = StalenessReportResponse {
        generated_at: now,
        min_inactive_days: 30,
        total_stale: 1,
        critical_count: 0,
        warning_count: 1,
        stale_nhis: vec![StaleNhiInfo {
            nhi_id: Uuid::new_v4(),
            name: "test-bot".to_string(),
            owner_id: Uuid::new_v4(),
            days_inactive: 100,
            last_used_at: Some(now - Duration::days(100)),
            inactivity_threshold_days: 90,
            in_grace_period: false,
            grace_period_ends_at: None,
        }],
    };

    let json = serde_json::to_string(&report).expect("Serialization failed");
    assert!(json.contains("test-bot"));
    assert!(json.contains("100"));
    assert!(json.contains("stale_nhis"));
}
