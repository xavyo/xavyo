//! Integration tests for risk assessment (US5).
//!
//! These tests validate risk calculations with real data.

#![cfg(feature = "integration")]

mod common;

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_governance::types::{RiskLevel, RiskThresholds};

use common::TestContext;

// ============================================================================
// RA-001: Entitlement Factor Calculation
// ============================================================================

/// Test entitlement factor calculation.
///
/// Given user has entitlements with risk levels [Low, Medium, High]
/// When calculating risk score
/// Then entitlement factor contributes to the final score
#[tokio::test]
async fn test_ra_001_entitlement_factor_calculation() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // Risk levels: Low=10, Medium=40, High=70
    let entitlements = vec![RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];

    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &entitlements, 0)
        .await
        .expect("Failed to calculate risk");

    // Final score should be based on entitlement factor (no SoD violations)
    // avg(10, 40, 70) = 40, weighted at 0.6 = 24
    assert!(
        risk_score.score > 0,
        "Score should be positive with entitlements"
    );
    assert!(risk_score.score <= 100, "Score should be <= 100");

    // Check factors breakdown
    let entitlement_factor = risk_score.factors.iter().find(|f| f.name == "entitlements");
    assert!(
        entitlement_factor.is_some(),
        "Should have entitlement factor"
    );

    let factor = entitlement_factor.unwrap();
    assert!(
        factor.raw_value > 0.0,
        "Raw entitlement value should be positive"
    );
}

// ============================================================================
// RA-002: SoD Violation Factor Included
// ============================================================================

/// Test SoD violation factor in risk calculation.
///
/// Given user has 2 SoD violations
/// When calculating risk score
/// Then SoD factor contributes to the final score
#[tokio::test]
async fn test_ra_002_sod_violation_factor_included() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // No entitlements but 2 SoD violations
    let entitlements: Vec<RiskLevel> = vec![];
    let sod_violations = 2;

    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &entitlements, sod_violations)
        .await
        .expect("Failed to calculate risk");

    // Score should reflect SoD violations
    assert!(
        risk_score.score > 0,
        "Score should be positive with violations"
    );

    // Check factors breakdown
    let sod_factor = risk_score
        .factors
        .iter()
        .find(|f| f.name == "sod_violations");
    assert!(sod_factor.is_some(), "Should have SoD violation factor");

    let factor = sod_factor.unwrap();
    assert!(
        factor.raw_value > 0.0,
        "Raw SoD value should be positive with violations"
    );
}

/// Test combined entitlement and SoD factor.
#[tokio::test]
async fn test_combined_risk_factors() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // High-risk entitlements and SoD violations
    let entitlements = vec![RiskLevel::High, RiskLevel::Critical];
    let sod_violations = 3;

    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &entitlements, sod_violations)
        .await
        .expect("Failed to calculate risk");

    // Score should be higher with both factors
    assert!(
        risk_score.score > 50,
        "Combined factors should yield high score"
    );
    assert_eq!(risk_score.factors.len(), 2, "Should have 2 factors");
}

// ============================================================================
// RA-003: Risk History Recording
// ============================================================================

/// Test risk history is persisted and retrievable.
///
/// When calculating risk for user
/// And recording to history
/// Then history contains the assessment
/// And can be retrieved with get_risk_trend
#[tokio::test]
async fn test_ra_003_risk_history_recording() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // Calculate initial risk
    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(
            ctx.tenant_a,
            user_id,
            &[RiskLevel::Medium, RiskLevel::High],
            1,
        )
        .await
        .expect("Failed to calculate risk");

    // Record to history
    ctx.services
        .risk
        .record_risk_history(ctx.tenant_a, user_id, &risk_score)
        .await
        .expect("Failed to record history");

    // Retrieve trend (from 1 hour ago to catch the just-recorded entry)
    let trend = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_a, user_id, Utc::now() - Duration::hours(1))
        .await
        .expect("Failed to get trend");

    assert_eq!(trend.len(), 1, "Should have 1 history entry");
    assert_eq!(
        trend[0].score, risk_score.score,
        "Recorded score should match"
    );
    assert_eq!(trend[0].user_id, user_id);
    assert_eq!(trend[0].tenant_id, ctx.tenant_a);
}

/// Test multiple risk history entries.
#[tokio::test]
async fn test_multiple_risk_history_entries() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // Record multiple assessments over time
    for violations in [0, 1, 2, 3] {
        let risk_score = ctx
            .services
            .risk
            .calculate_user_risk(ctx.tenant_a, user_id, &[RiskLevel::Medium], violations)
            .await
            .expect("Failed to calculate risk");

        ctx.services
            .risk
            .record_risk_history(ctx.tenant_a, user_id, &risk_score)
            .await
            .expect("Failed to record history");

        // Small delay between entries
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Retrieve trend
    let trend = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_a, user_id, Utc::now() - Duration::hours(1))
        .await
        .expect("Failed to get trend");

    assert_eq!(trend.len(), 4, "Should have 4 history entries");

    // Verify trend is ordered (ascending by time)
    for i in 1..trend.len() {
        assert!(
            trend[i].recorded_at >= trend[i - 1].recorded_at,
            "History should be ordered by time"
        );
    }
}

// ============================================================================
// RA-004: Custom Threshold Application
// ============================================================================

/// Test custom thresholds are applied.
///
/// Given custom thresholds
/// When classifying a score
/// Then the appropriate risk level is returned
#[tokio::test]
async fn test_ra_004_custom_threshold_application() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // Set custom thresholds
    let custom_thresholds = RiskThresholds {
        tenant_id: ctx.tenant_a,
        low_max: 30,
        medium_max: 60,
        high_max: 90,
        updated_at: Utc::now(),
        updated_by: ctx.actor_id,
    };

    ctx.services
        .risk
        .configure_thresholds(ctx.tenant_a, custom_thresholds.clone(), ctx.actor_id)
        .await
        .expect("Failed to set thresholds");

    // Test classification with score that should be Medium (31-60)
    let classified = ctx
        .services
        .risk
        .get_risk_level(ctx.tenant_a, 45)
        .await
        .expect("Failed to classify");

    assert_eq!(
        classified,
        RiskLevel::Medium,
        "Score 45 should be Medium with custom thresholds (31-60)"
    );

    // Test Low threshold
    let low_classified = ctx
        .services
        .risk
        .get_risk_level(ctx.tenant_a, 25)
        .await
        .expect("Failed to classify");

    assert_eq!(low_classified, RiskLevel::Low, "Score 25 should be Low");
}

/// Test default thresholds when no custom ones set.
#[tokio::test]
async fn test_default_thresholds() {
    let ctx = TestContext::new();

    // No custom thresholds set - should use defaults
    let classified = ctx
        .services
        .risk
        .get_risk_level(ctx.tenant_a, 10)
        .await
        .expect("Failed to classify");

    assert_eq!(
        classified,
        RiskLevel::Low,
        "Low score should classify as Low"
    );
}

// ============================================================================
// Edge Case: Zero Entitlements Risk Calculation
// ============================================================================

/// Test risk calculation with zero entitlements.
#[tokio::test]
async fn test_zero_entitlements_risk_calculation() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // No entitlements at all
    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &[], 0)
        .await
        .expect("Failed to calculate risk");

    // With no entitlements and no violations, score should be 0
    assert_eq!(
        risk_score.score, 0,
        "Score should be 0 with no risk factors"
    );
}

/// Test risk with only SoD violations, no entitlements.
#[tokio::test]
async fn test_risk_with_only_violations() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // No entitlements but has violations
    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &[], 4)
        .await
        .expect("Failed to calculate risk");

    // Should have a score based on SoD violations only
    assert!(
        risk_score.score > 0,
        "Score should be positive with violations"
    );
}

// ============================================================================
// Additional Risk Tests
// ============================================================================

/// Test SoD violation factor caps at 100.
#[tokio::test]
async fn test_sod_factor_caps_at_100() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // 10 violations should cap the SoD factor
    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &[], 10)
        .await
        .expect("Failed to calculate risk");

    let sod_factor = risk_score
        .factors
        .iter()
        .find(|f| f.name == "sod_violations")
        .expect("Should have SoD factor");

    assert!(
        sod_factor.raw_value <= 100.0,
        "SoD factor raw value should cap at 100"
    );
}

/// Test risk score includes factor breakdown.
#[tokio::test]
async fn test_risk_score_includes_breakdown() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(
            ctx.tenant_a,
            user_id,
            &[RiskLevel::Medium, RiskLevel::High, RiskLevel::Critical],
            2,
        )
        .await
        .expect("Failed to calculate risk");

    // Verify breakdown structure
    assert_eq!(
        risk_score.factors.len(),
        2,
        "Should have 2 factors (entitlements and sod_violations)"
    );
    assert!(risk_score.score > 0, "Score should be positive");
}

/// Test tenant isolation in risk history.
#[tokio::test]
async fn test_risk_history_tenant_isolation() {
    let ctx = TestContext::with_predictable_ids();
    let user_id = Uuid::new_v4();

    // Record risk for tenant A
    let risk_a = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &[RiskLevel::High], 0)
        .await
        .expect("Failed to calculate risk");

    ctx.services
        .risk
        .record_risk_history(ctx.tenant_a, user_id, &risk_a)
        .await
        .expect("Failed to record history");

    // Record risk for tenant B (same user_id)
    let risk_b = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_b, user_id, &[RiskLevel::Low], 0)
        .await
        .expect("Failed to calculate risk");

    ctx.services
        .risk
        .record_risk_history(ctx.tenant_b, user_id, &risk_b)
        .await
        .expect("Failed to record history");

    // Get trends for each tenant
    let trend_a = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_a, user_id, Utc::now() - Duration::hours(1))
        .await
        .expect("Failed to get trend A");

    let trend_b = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_b, user_id, Utc::now() - Duration::hours(1))
        .await
        .expect("Failed to get trend B");

    // Verify isolation
    assert_eq!(trend_a.len(), 1);
    assert_eq!(trend_b.len(), 1);
    assert_ne!(
        trend_a[0].score, trend_b[0].score,
        "Tenants should have different scores"
    );
}
