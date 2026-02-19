//! Unit tests for NHI Risk Service (F061 - User Story 4).
//!
//! Tests cover:
//! - Risk factor calculations
//! - Risk level thresholds
//! - Risk score response structures
//! - Risk summary aggregation

use chrono::{Duration, Utc};
use uuid::Uuid;

use xavyo_api_governance::models::{
    NhiRiskScoreListResponse, NhiRiskScoreResponse, RiskLevelSummary,
};
use xavyo_db::RiskLevel;

// ============================================================================
// NhiRiskScoreResponse Tests
// ============================================================================

#[test]
fn test_risk_score_response_structure() {
    let nhi_id = Uuid::new_v4();
    let now = Utc::now();

    let response = NhiRiskScoreResponse {
        nhi_id,
        total_score: 30,
        risk_level: RiskLevel::Medium,
        staleness_factor: 20,
        credential_age_factor: 0,
        access_scope_factor: 10,
        factor_breakdown: serde_json::json!({
            "staleness": {"days_inactive": 50},
            "access_scope": {"entitlement_count": 5}
        }),
        calculated_at: now,
        next_calculation_at: Some(now + Duration::hours(24)),
    };

    assert_eq!(response.nhi_id, nhi_id);
    assert_eq!(response.total_score, 30);
    assert_eq!(response.risk_level, RiskLevel::Medium);
    assert_eq!(response.staleness_factor, 20);
    assert_eq!(response.credential_age_factor, 0);
    assert_eq!(response.access_scope_factor, 10);
}

#[test]
fn test_risk_score_serialization() {
    let response = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 50,
        risk_level: RiskLevel::Medium,
        staleness_factor: 30,
        credential_age_factor: 0,
        access_scope_factor: 20,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    let json = serde_json::to_string(&response).expect("Serialization failed");
    assert!(json.contains("total_score"));
    assert!(json.contains("50"));
    assert!(json.contains("medium"));
    assert!(json.contains("staleness_factor"));
}

#[test]
fn test_risk_factors_sum_to_total() {
    let response = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 45,
        risk_level: RiskLevel::Medium,
        staleness_factor: 25,
        credential_age_factor: 0,
        access_scope_factor: 20,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    let factors_sum =
        response.staleness_factor + response.credential_age_factor + response.access_scope_factor;
    assert_eq!(factors_sum, response.total_score);
}

// ============================================================================
// Risk Level Tests
// ============================================================================

#[test]
fn test_risk_level_from_score_low() {
    // Score 0-25 = Low
    assert_eq!(level_from_score(0), RiskLevel::Low);
    assert_eq!(level_from_score(10), RiskLevel::Low);
    assert_eq!(level_from_score(25), RiskLevel::Low);
}

#[test]
fn test_risk_level_from_score_medium() {
    // Score 26-50 = Medium
    assert_eq!(level_from_score(26), RiskLevel::Medium);
    assert_eq!(level_from_score(35), RiskLevel::Medium);
    assert_eq!(level_from_score(50), RiskLevel::Medium);
}

#[test]
fn test_risk_level_from_score_high() {
    // Score 51-75 = High
    assert_eq!(level_from_score(51), RiskLevel::High);
    assert_eq!(level_from_score(65), RiskLevel::High);
    assert_eq!(level_from_score(75), RiskLevel::High);
}

#[test]
fn test_risk_level_from_score_critical() {
    // Score 76-100 = Critical
    assert_eq!(level_from_score(76), RiskLevel::Critical);
    assert_eq!(level_from_score(90), RiskLevel::Critical);
    assert_eq!(level_from_score(100), RiskLevel::Critical);
}

/// Helper function to determine risk level from score
fn level_from_score(score: i32) -> RiskLevel {
    match score {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

// ============================================================================
// Risk Factor Calculation Tests
// ============================================================================

#[test]
fn test_staleness_factor_calculation() {
    // Max points: 50
    // Max days: 180
    // Linear scaling: factor = days * 50 / 180

    let max_points = 50;
    let max_days = 180;

    // Test various day counts
    let test_cases = [
        (0, 0),    // 0 days = 0 points
        (36, 10),  // 36 days = 10 points
        (90, 25),  // 90 days = 25 points
        (144, 40), // 144 days = 40 points
        (180, 50), // 180 days = 50 points (max)
        (365, 50), // Over max = capped at max
    ];

    for (days, expected_points) in test_cases {
        let calculated = if days >= max_days {
            max_points
        } else {
            (days * max_points) / max_days
        };
        assert_eq!(
            calculated, expected_points,
            "Staleness factor mismatch for {} days",
            days
        );
    }
}

#[test]
fn test_access_scope_factor_calculation() {
    // Tiered calculation based on entitlement count

    let test_cases = [
        (0, 0), // No entitlements = 0 risk
        (1, 5), // 1-5 entitlements = 5 points
        (5, 5),
        (6, 10), // 6-10 entitlements = 10 points
        (10, 10),
        (11, 15), // 11-20 entitlements = 15 points
        (20, 15),
        (21, 20), // 21-50 entitlements = 20 points
        (50, 20),
        (51, 30), // 51+ entitlements = 30 points (max)
        (100, 30),
    ];

    for (entitlements, expected_points) in test_cases {
        let calculated = match entitlements {
            0 => 0,
            1..=5 => 5,
            6..=10 => 10,
            11..=20 => 15,
            21..=50 => 20,
            _ => 30,
        };
        assert_eq!(
            calculated, expected_points,
            "Access scope factor mismatch for {} entitlements",
            entitlements
        );
    }
}

// ============================================================================
// RiskLevelSummary Tests
// ============================================================================

#[test]
fn test_risk_level_summary_empty() {
    let summary = RiskLevelSummary {
        total: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
    };

    assert_eq!(summary.total, 0);
    assert_eq!(
        summary.low + summary.medium + summary.high + summary.critical,
        0
    );
}

#[test]
fn test_risk_level_summary_with_data() {
    let summary = RiskLevelSummary {
        total: 100,
        low: 50,
        medium: 30,
        high: 15,
        critical: 5,
    };

    assert_eq!(summary.total, 100);
    assert_eq!(
        summary.low + summary.medium + summary.high + summary.critical,
        100
    );
}

#[test]
fn test_risk_level_summary_serialization() {
    let summary = RiskLevelSummary {
        total: 50,
        low: 25,
        medium: 15,
        high: 8,
        critical: 2,
    };

    let json = serde_json::to_string(&summary).expect("Serialization failed");
    assert!(json.contains("total"));
    assert!(json.contains("50"));
    assert!(json.contains("low"));
    assert!(json.contains("medium"));
    assert!(json.contains("high"));
    assert!(json.contains("critical"));
}

// ============================================================================
// NhiRiskScoreListResponse Tests
// ============================================================================

#[test]
fn test_risk_score_list_response_empty() {
    let response = NhiRiskScoreListResponse {
        items: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert!(response.items.is_empty());
    assert_eq!(response.total, 0);
}

#[test]
fn test_risk_score_list_response_with_items() {
    let items = vec![
        NhiRiskScoreResponse {
            nhi_id: Uuid::new_v4(),
            total_score: 55,
            risk_level: RiskLevel::High,
            staleness_factor: 35,
            credential_age_factor: 0,
            access_scope_factor: 20,
            factor_breakdown: serde_json::json!({}),
            calculated_at: Utc::now(),
            next_calculation_at: None,
        },
        NhiRiskScoreResponse {
            nhi_id: Uuid::new_v4(),
            total_score: 20,
            risk_level: RiskLevel::Low,
            staleness_factor: 15,
            credential_age_factor: 0,
            access_scope_factor: 5,
            factor_breakdown: serde_json::json!({}),
            calculated_at: Utc::now(),
            next_calculation_at: None,
        },
    ];

    let response = NhiRiskScoreListResponse {
        items,
        total: 2,
        limit: 50,
        offset: 0,
    };

    assert_eq!(response.items.len(), 2);
    assert_eq!(response.total, 2);
    assert_eq!(response.items[0].risk_level, RiskLevel::High);
    assert_eq!(response.items[1].risk_level, RiskLevel::Low);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_max_risk_score() {
    // Maximum possible score: 50 + 0 + 50 = 100
    let response = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 100,
        risk_level: RiskLevel::Critical,
        staleness_factor: 50,
        credential_age_factor: 0,
        access_scope_factor: 50,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    assert_eq!(response.total_score, 100);
    assert_eq!(response.risk_level, RiskLevel::Critical);
}

#[test]
fn test_min_risk_score() {
    // Minimum possible score: 0
    let response = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 0,
        risk_level: RiskLevel::Low,
        staleness_factor: 0,
        credential_age_factor: 0,
        access_scope_factor: 0,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    assert_eq!(response.total_score, 0);
    assert_eq!(response.risk_level, RiskLevel::Low);
}

#[test]
fn test_boundary_scores() {
    // Test boundary values between risk levels
    let boundary_tests = [
        (25, RiskLevel::Low),
        (26, RiskLevel::Medium),
        (50, RiskLevel::Medium),
        (51, RiskLevel::High),
        (75, RiskLevel::High),
        (76, RiskLevel::Critical),
    ];

    for (score, expected_level) in boundary_tests {
        let level = level_from_score(score);
        assert_eq!(
            level, expected_level,
            "Boundary test failed for score {}",
            score
        );
    }
}

#[test]
fn test_factor_breakdown_structure() {
    let breakdown = serde_json::json!({
        "staleness": {
            "days_inactive": 90,
            "last_used_at": null,
            "created_at": "2024-01-01T00:00:00Z",
            "points": 20,
            "max_points": 50,
            "threshold_days": 180
        },
        "access_scope": {
            "entitlement_count": 8,
            "points": 10,
            "max_points": 50,
            "thresholds": {
                "low": "1-5 entitlements",
                "medium": "6-20 entitlements",
                "high": "21-50 entitlements",
                "critical": "51+ entitlements"
            }
        }
    });

    let response = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 30,
        risk_level: RiskLevel::Medium,
        staleness_factor: 20,
        credential_age_factor: 0,
        access_scope_factor: 10,
        factor_breakdown: breakdown.clone(),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    assert_eq!(response.factor_breakdown["staleness"]["points"], 20);
    assert_eq!(response.factor_breakdown["access_scope"]["points"], 10);
}

#[test]
fn test_next_calculation_at_optional() {
    let with_next = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 35,
        risk_level: RiskLevel::Medium,
        staleness_factor: 20,
        credential_age_factor: 0,
        access_scope_factor: 15,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: Some(Utc::now() + Duration::hours(24)),
    };

    let without_next = NhiRiskScoreResponse {
        nhi_id: Uuid::new_v4(),
        total_score: 35,
        risk_level: RiskLevel::Medium,
        staleness_factor: 20,
        credential_age_factor: 0,
        access_scope_factor: 15,
        factor_breakdown: serde_json::json!({}),
        calculated_at: Utc::now(),
        next_calculation_at: None,
    };

    assert!(with_next.next_calculation_at.is_some());
    assert!(without_next.next_calculation_at.is_none());
}
