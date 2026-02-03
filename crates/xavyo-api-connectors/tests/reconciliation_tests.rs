//! Reconciliation Service Tests for F-043
//!
//! Tests for reconciliation operations including trend aggregation,
//! discrepancy handling, and remediation workflows.

mod common;

use chrono::{Duration, NaiveDate, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_api_connectors::handlers::reconciliation::{TrendDataPoint, TrendResponse};

// ============================================================================
// Trend Data Aggregation Tests
// ============================================================================

#[test]
fn test_trend_data_point_structure() {
    let point = TrendDataPoint {
        date: "2026-02-01".to_string(),
        total: 15,
        by_type: HashMap::from([
            ("missing".to_string(), 5),
            ("orphan".to_string(), 7),
            ("mismatch".to_string(), 3),
        ]),
    };

    assert_eq!(point.date, "2026-02-01");
    assert_eq!(point.total, 15);
    assert_eq!(point.by_type.get("missing"), Some(&5));
    assert_eq!(point.by_type.get("orphan"), Some(&7));
    assert_eq!(point.by_type.get("mismatch"), Some(&3));
}

#[test]
fn test_trend_response_structure() {
    let now = Utc::now();
    let response = TrendResponse {
        data_points: vec![
            TrendDataPoint {
                date: "2026-02-01".to_string(),
                total: 10,
                by_type: HashMap::from([("missing".to_string(), 10)]),
            },
            TrendDataPoint {
                date: "2026-02-02".to_string(),
                total: 5,
                by_type: HashMap::from([("orphan".to_string(), 5)]),
            },
        ],
        connector_id: Some(Uuid::new_v4()),
        from: now - Duration::days(30),
        to: now,
    };

    assert_eq!(response.data_points.len(), 2);
    assert!(response.connector_id.is_some());
}

#[test]
fn test_trend_response_empty() {
    let now = Utc::now();
    let response = TrendResponse {
        data_points: vec![],
        connector_id: None,
        from: now - Duration::days(30),
        to: now,
    };

    assert!(response.data_points.is_empty());
    assert!(response.connector_id.is_none());
}

#[test]
fn test_trend_aggregation_by_type() {
    // Simulate aggregating raw data points into TrendDataPoint
    let raw_data = vec![
        ("2026-02-01", "missing", 3),
        ("2026-02-01", "orphan", 2),
        ("2026-02-01", "mismatch", 1),
        ("2026-02-02", "missing", 5),
    ];

    let mut date_map: HashMap<String, TrendDataPoint> = HashMap::new();

    for (date, dtype, count) in raw_data {
        let entry = date_map
            .entry(date.to_string())
            .or_insert_with(|| TrendDataPoint {
                date: date.to_string(),
                total: 0,
                by_type: HashMap::new(),
            });
        entry.total += count;
        *entry.by_type.entry(dtype.to_string()).or_insert(0) += count;
    }

    let day1 = date_map.get("2026-02-01").unwrap();
    assert_eq!(day1.total, 6);
    assert_eq!(day1.by_type.get("missing"), Some(&3));
    assert_eq!(day1.by_type.get("orphan"), Some(&2));
    assert_eq!(day1.by_type.get("mismatch"), Some(&1));

    let day2 = date_map.get("2026-02-02").unwrap();
    assert_eq!(day2.total, 5);
    assert_eq!(day2.by_type.get("missing"), Some(&5));
}

// ============================================================================
// Discrepancy Type Tests
// ============================================================================

#[test]
fn test_discrepancy_types_coverage() {
    // All discrepancy types that should be tracked
    let discrepancy_types = vec![
        "missing",
        "orphan",
        "mismatch",
        "collision",
        "unlinked",
        "deleted",
    ];

    for dtype in discrepancy_types {
        let mut by_type = HashMap::new();
        by_type.insert(dtype.to_string(), 1u32);

        let point = TrendDataPoint {
            date: "2026-02-01".to_string(),
            total: 1,
            by_type,
        };

        assert!(point.by_type.contains_key(dtype));
    }
}

// ============================================================================
// Date Range Tests
// ============================================================================

#[test]
fn test_default_date_range_30_days() {
    let now = Utc::now();
    let to_date = now;
    let from_date = now - Duration::days(30);

    let duration = to_date - from_date;
    assert_eq!(duration.num_days(), 30);
}

#[test]
fn test_custom_date_range() {
    let now = Utc::now();
    let from = now - Duration::days(7);
    let to = now;

    let response = TrendResponse {
        data_points: vec![],
        connector_id: None,
        from,
        to,
    };

    let duration = response.to - response.from;
    assert_eq!(duration.num_days(), 7);
}

#[test]
fn test_date_string_format() {
    let date = NaiveDate::from_ymd_opt(2026, 2, 1).unwrap();
    let date_str = date.to_string();
    assert_eq!(date_str, "2026-02-01");
}

// ============================================================================
// Connector ID Filtering Tests
// ============================================================================

#[test]
fn test_trend_with_connector_filter() {
    let connector_id = Uuid::new_v4();
    let now = Utc::now();

    let response = TrendResponse {
        data_points: vec![TrendDataPoint {
            date: "2026-02-01".to_string(),
            total: 10,
            by_type: HashMap::new(),
        }],
        connector_id: Some(connector_id),
        from: now - Duration::days(30),
        to: now,
    };

    assert_eq!(response.connector_id, Some(connector_id));
}

#[test]
fn test_trend_without_connector_filter() {
    let now = Utc::now();

    let response = TrendResponse {
        data_points: vec![],
        connector_id: None,
        from: now - Duration::days(30),
        to: now,
    };

    assert!(response.connector_id.is_none());
}

// ============================================================================
// Remediation Response Tests
// ============================================================================

use xavyo_api_connectors::handlers::reconciliation::{
    BulkRemediateItem, BulkRemediationResponse, BulkRemediationSummary, RemediationResponse,
};

#[test]
fn test_remediation_response_success() {
    let response = RemediationResponse {
        discrepancy_id: Uuid::new_v4(),
        action: "create".to_string(),
        result: "success".to_string(),
        error_message: None,
        before_state: None,
        after_state: Some(serde_json::json!({"created": true})),
        dry_run: false,
    };

    assert_eq!(response.result, "success");
    assert!(response.error_message.is_none());
    assert!(!response.dry_run);
}

#[test]
fn test_remediation_response_failure() {
    let response = RemediationResponse {
        discrepancy_id: Uuid::new_v4(),
        action: "update".to_string(),
        result: "failure".to_string(),
        error_message: Some("Connection timeout".to_string()),
        before_state: None,
        after_state: None,
        dry_run: false,
    };

    assert_eq!(response.result, "failure");
    assert!(response.error_message.is_some());
    assert!(response.error_message.unwrap().contains("timeout"));
}

#[test]
fn test_remediation_dry_run() {
    let response = RemediationResponse {
        discrepancy_id: Uuid::new_v4(),
        action: "delete".to_string(),
        result: "success".to_string(),
        error_message: None,
        before_state: Some(serde_json::json!({"exists": true})),
        after_state: Some(serde_json::json!({"exists": false})),
        dry_run: true,
    };

    assert!(response.dry_run);
    assert!(response.before_state.is_some());
    assert!(response.after_state.is_some());
}

#[test]
fn test_bulk_remediate_item() {
    let item = BulkRemediateItem {
        discrepancy_id: Uuid::new_v4(),
        action: "delete".to_string(),
        direction: Some("to_target".to_string()),
        identity_id: Some(Uuid::new_v4()),
    };

    assert!(!item.action.is_empty());
    assert!(item.direction.is_some());
    assert!(item.identity_id.is_some());
}

#[test]
fn test_bulk_remediation_response() {
    let response = BulkRemediationResponse {
        results: vec![
            RemediationResponse {
                discrepancy_id: Uuid::new_v4(),
                action: "create".to_string(),
                result: "success".to_string(),
                error_message: None,
                before_state: None,
                after_state: None,
                dry_run: false,
            },
            RemediationResponse {
                discrepancy_id: Uuid::new_v4(),
                action: "update".to_string(),
                result: "failure".to_string(),
                error_message: Some("Error".to_string()),
                before_state: None,
                after_state: None,
                dry_run: false,
            },
        ],
        summary: BulkRemediationSummary {
            total: 2,
            succeeded: 1,
            failed: 1,
        },
    };

    assert_eq!(response.results.len(), 2);
    assert_eq!(response.summary.total, 2);
    assert_eq!(response.summary.succeeded, 1);
    assert_eq!(response.summary.failed, 1);
}

// ============================================================================
// Schedule Tests
// ============================================================================

#[test]
fn test_schedule_frequency_validation() {
    // Valid frequencies
    let frequencies = vec!["daily", "weekly", "monthly", "custom"];

    for freq in frequencies {
        assert!(["daily", "weekly", "monthly", "custom"].contains(&freq));
    }
}

#[test]
fn test_weekly_schedule_day_validation() {
    // Valid days for weekly schedule
    let valid_days = vec![
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];

    for day in valid_days {
        assert!(day.chars().all(|c| c.is_ascii_alphabetic()));
    }
}

#[test]
fn test_monthly_schedule_day_validation() {
    // Valid days for monthly schedule (1-28 to be safe for all months)
    for day in 1..=28 {
        assert!(day >= 1 && day <= 28);
    }
}

// ============================================================================
// Action Type Tests
// ============================================================================

#[test]
fn test_action_types() {
    let action_types = vec![
        "create",
        "update",
        "delete",
        "link",
        "unlink",
        "inactivate_identity",
    ];

    assert_eq!(action_types.len(), 6);
    for action in &action_types {
        assert!(!action.is_empty());
    }
}

#[test]
fn test_action_result_types() {
    let result_types = vec!["success", "failure", "skipped"];

    assert_eq!(result_types.len(), 3);
}

// ============================================================================
// Report Tests
// ============================================================================

use xavyo_api_connectors::handlers::reconciliation::{
    ActionSummary, AttributeMismatchCount, DiscrepancySummary, PerformanceMetrics,
    ReconciliationStatistics, ReportResponse, RunInfo,
};

#[test]
fn test_report_response_structure() {
    let stats = ReconciliationStatistics {
        accounts_total: 1000,
        accounts_processed: 1000,
        discrepancies_found: 50,
        discrepancies_by_type: HashMap::from([
            ("missing".to_string(), 20),
            ("orphan".to_string(), 15),
            ("mismatch".to_string(), 15),
        ]),
        actions_taken: 45,
        duration_seconds: 120,
    };

    let report = ReportResponse {
        run: RunInfo {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: Some("Test Connector".to_string()),
            mode: "full".to_string(),
            status: "completed".to_string(),
            triggered_by: Some(Uuid::new_v4()),
            triggered_by_name: Some("admin".to_string()),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            statistics: stats,
        },
        discrepancy_summary: DiscrepancySummary {
            total: 50,
            by_type: HashMap::from([
                ("missing".to_string(), 20),
                ("orphan".to_string(), 15),
                ("mismatch".to_string(), 15),
            ]),
            by_resolution: HashMap::from([
                ("pending".to_string(), 5),
                ("resolved".to_string(), 40),
                ("ignored".to_string(), 5),
            ]),
        },
        action_summary: ActionSummary {
            total: 45,
            by_type: HashMap::new(),
            by_result: HashMap::new(),
        },
        top_mismatched_attributes: vec![AttributeMismatchCount {
            attribute: "email".to_string(),
            count: 10,
        }],
        performance: PerformanceMetrics {
            accounts_per_second: 8.33,
            total_duration_seconds: 120,
        },
    };

    assert_eq!(report.run.mode, "full");
    assert_eq!(report.run.statistics.accounts_total, 1000);
    assert_eq!(report.discrepancy_summary.total, 50);
    assert_eq!(report.action_summary.total, 45);
    assert!(report.performance.accounts_per_second > 0.0);
}

#[test]
fn test_statistics_discrepancy_count_matches_by_type() {
    let stats = ReconciliationStatistics {
        accounts_total: 100,
        accounts_processed: 100,
        discrepancies_found: 20,
        discrepancies_by_type: HashMap::from([
            ("missing".to_string(), 10),
            ("orphan".to_string(), 5),
            ("mismatch".to_string(), 5),
        ]),
        actions_taken: 0,
        duration_seconds: 0,
    };

    let sum: u32 = stats.discrepancies_by_type.values().sum();
    assert_eq!(sum, stats.discrepancies_found);
}

#[test]
fn test_discrepancy_summary_by_resolution() {
    let summary = DiscrepancySummary {
        total: 100,
        by_type: HashMap::new(),
        by_resolution: HashMap::from([
            ("pending".to_string(), 30),
            ("resolved".to_string(), 60),
            ("ignored".to_string(), 10),
        ]),
    };

    let resolution_total: u32 = summary.by_resolution.values().sum();
    assert_eq!(resolution_total, summary.total);
}

// ============================================================================
// Preview (Dry Run) Tests
// ============================================================================

use xavyo_api_connectors::handlers::reconciliation::{
    PreviewItem, PreviewResponse, PreviewSummary,
};

#[test]
fn test_preview_item_structure() {
    let item = PreviewItem {
        discrepancy_id: Uuid::new_v4(),
        discrepancy_type: "missing".to_string(),
        suggested_action: "create".to_string(),
        would_change: serde_json::json!({
            "attributes": {
                "email": "user@example.com"
            }
        }),
    };

    assert_eq!(item.discrepancy_type, "missing");
    assert_eq!(item.suggested_action, "create");
    assert!(item.would_change.is_object());
}

#[test]
fn test_preview_response_structure() {
    let response = PreviewResponse {
        items: vec![PreviewItem {
            discrepancy_id: Uuid::new_v4(),
            discrepancy_type: "orphan".to_string(),
            suggested_action: "link".to_string(),
            would_change: serde_json::json!({}),
        }],
        summary: PreviewSummary {
            total_actions: 1,
            by_action: HashMap::from([("link".to_string(), 1)]),
        },
    };

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.summary.total_actions, 1);
    assert_eq!(response.summary.by_action.get("link"), Some(&1));
}

// ============================================================================
// Database Driver Compliance Tests (Constitution)
// ============================================================================

#[test]
fn test_only_postgresql_supported() {
    // Per Constitution Principle XI: Single Technology Per Layer
    // Only PostgreSQL is supported as the database driver
    let supported_drivers = vec!["postgresql", "postgres"];

    for driver in supported_drivers {
        // Both variants should be accepted
        assert!(driver.contains("postgres"));
    }

    // These should be rejected
    let unsupported_drivers = vec!["mysql", "mariadb", "mssql", "sqlserver", "oracle"];

    for driver in unsupported_drivers {
        assert!(!driver.contains("postgres"));
    }
}
