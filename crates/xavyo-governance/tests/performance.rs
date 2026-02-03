//! Performance tests for xavyo-governance (US6).
//!
//! These tests validate acceptable performance with large datasets.
//! Run with: `cargo test -p xavyo-governance --features integration -- --ignored`

#![cfg(feature = "integration")]

mod common;

use std::time::Instant;
use uuid::Uuid;
use xavyo_governance::services::entitlement::{CreateEntitlementInput, EntitlementFilter, ListOptions};
use xavyo_governance::services::assignment::{AssignEntitlementInput, AssignmentStore};
use xavyo_governance::services::sod::CreateSodRuleInput;
use xavyo_governance::types::{RiskLevel, SodConflictType, SodSeverity};
use xavyo_governance::AuditStore;

use common::TestContext;

// ============================================================================
// PF-001: Large Entitlement List Performance
// ============================================================================

/// Test listing 1000+ entitlements completes under 1 second.
///
/// Given 1000 entitlements
/// When listing with pagination (page_size=100)
/// Then response time is under 1 second
#[tokio::test]
#[ignore] // Performance test - run with --ignored
async fn test_pf_001_large_entitlement_list_under_1_second() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create 1000 entitlements
    for i in 0..1000 {
        let risk = match i % 4 {
            0 => RiskLevel::Low,
            1 => RiskLevel::Medium,
            2 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Entitlement {:04}", i),
                    description: Some(format!("Performance test entitlement {}", i)),
                    risk_level: risk,
                    owner_id: None,
                    external_id: Some(format!("ext-{}", i)),
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
    }

    // Time the list operation
    let start = Instant::now();

    let results = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter::default(),
            &ListOptions {
                limit: 100,
                offset: 0,
            },
        )
        .await
        .expect("Failed to list entitlements");

    let duration = start.elapsed();

    // Verify results and timing
    assert_eq!(results.len(), 100, "Should return 100 entitlements");
    assert!(
        duration.as_secs() < 1,
        "List operation took {}ms, should be under 1000ms",
        duration.as_millis()
    );

    println!(
        "PF-001: Listed 100 entitlements from 1000 in {}ms",
        duration.as_millis()
    );
}

// ============================================================================
// PF-002: Assignment Filter Performance
// ============================================================================

/// Test filtering 10000+ assignments completes under 500ms.
///
/// Given 10000 assignments across 100 users
/// When filtering by specific user_id
/// Then response time is under 500ms
#[tokio::test]
#[ignore] // Performance test - run with --ignored
async fn test_pf_002_assignment_filter_under_500ms() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create 100 entitlements
    let mut entitlement_ids = Vec::new();
    for i in 0..100 {
        let e = ctx
            .services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Perf Entitlement {}", i),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
        entitlement_ids.push(e.id.into_inner());
    }

    // Create 100 users
    let mut user_ids = Vec::new();
    for _ in 0..100 {
        user_ids.push(Uuid::new_v4());
    }

    // Create 10000 assignments (100 entitlements * 100 users)
    for (u_idx, user_id) in user_ids.iter().enumerate() {
        for (e_idx, entitlement_id) in entitlement_ids.iter().enumerate() {
            ctx.services
                .assignment
                .assign(
                    ctx.tenant_a,
                    AssignEntitlementInput {
                        entitlement_id: *entitlement_id,
                        user_id: *user_id,
                        assigned_by: ctx.actor_id,
                        expires_at: None,
                        justification: Some(format!("Perf test u{}e{}", u_idx, e_idx)),
                    },
                )
                .await
                .expect("Failed to assign entitlement");
        }
    }

    // Pick a random user to filter
    let target_user = user_ids[50];

    // Time the filter operation
    let start = Instant::now();

    let assignments = ctx
        .stores
        .assignment_store
        .list_user_assignments(ctx.tenant_a, target_user)
        .await
        .expect("Failed to list assignments");

    let duration = start.elapsed();

    // Verify results and timing
    assert_eq!(assignments.len(), 100, "User should have 100 assignments");
    assert!(
        duration.as_millis() < 500,
        "Filter operation took {}ms, should be under 500ms",
        duration.as_millis()
    );

    println!(
        "PF-002: Filtered 100 assignments from 10000 in {}ms",
        duration.as_millis()
    );
}

// ============================================================================
// PF-003: SoD Validation Performance
// ============================================================================

/// Test SoD validation with 100+ entitlements under 500ms.
///
/// Given user with 100 entitlements
/// And 50 SoD rules
/// When running preventive validation
/// Then validation completes under 500ms
#[tokio::test]
#[ignore] // Performance test - run with --ignored
async fn test_pf_003_sod_validation_under_500ms() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create 100 entitlements
    let mut entitlement_ids = Vec::new();
    for i in 0..100 {
        let e = ctx
            .services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("SoD Perf Entitlement {}", i),
                    description: None,
                    risk_level: RiskLevel::Medium,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
        entitlement_ids.push(e.id.into_inner());
    }

    // Create 50 SoD rules (each with different entitlement pairs)
    for i in 0..50 {
        let idx1 = (i * 2) % 100;
        let idx2 = (i * 2 + 1) % 100;

        ctx.services
            .sod
            .create_rule(
                ctx.tenant_a,
                CreateSodRuleInput {
                    name: format!("SoD Rule {}", i),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![entitlement_ids[idx1], entitlement_ids[idx2]],
                    max_count: None,
                    severity: SodSeverity::Medium,
                    created_by: ctx.actor_id,
                },
            )
            .await
            .expect("Failed to create SoD rule");
    }

    // Assign 50 entitlements to user (avoiding violation for cleaner test)
    for i in 0..50 {
        ctx.services
            .assignment
            .assign(
                ctx.tenant_a,
                AssignEntitlementInput {
                    entitlement_id: entitlement_ids[i * 2], // Even indices only
                    user_id,
                    assigned_by: ctx.actor_id,
                    expires_at: None,
                    justification: Some(format!("SoD perf test {}", i)),
                },
            )
            .await
            .expect("Failed to assign entitlement");
    }

    // Get current entitlement IDs for validation
    let current: Vec<Uuid> = (0..50).map(|i| entitlement_ids[i * 2]).collect();

    // Time the validation operation
    let start = Instant::now();

    let result = ctx
        .services
        .sod_validation
        .validate_preventive(
            ctx.tenant_a,
            user_id,
            entitlement_ids[1], // Odd index - will trigger rule 0
            &current,
        )
        .await
        .expect("Validation failed");

    let duration = start.elapsed();

    // Verify timing
    assert!(
        duration.as_millis() < 500,
        "SoD validation took {}ms, should be under 500ms",
        duration.as_millis()
    );

    println!(
        "PF-003: SoD validation with 50 rules and 50 entitlements in {}ms",
        duration.as_millis()
    );

    // The result should show violations since we're adding an odd-indexed entitlement
    // which conflicts with entitlement[0]
    assert!(!result.is_valid, "Should detect SoD violation");
}

// ============================================================================
// PF-004: Audit Query Performance
// ============================================================================

/// Test audit query with 50000 events under 1 second.
///
/// Given 50000 audit events
/// When querying with time range filter
/// Then response time is under 1 second
#[tokio::test]
#[ignore] // Performance test - run with --ignored
async fn test_pf_004_audit_query_under_1_second() {
    use chrono::{Duration, Utc};
    use xavyo_governance::audit::{AuditEventFilter, EntitlementAuditAction, EntitlementAuditEventInput};

    let ctx = TestContext::new();

    // Create 50000 audit events
    let start_time = Utc::now();

    for i in 0..50000 {
        let action = match i % 6 {
            0 => EntitlementAuditAction::Created,
            1 => EntitlementAuditAction::Updated,
            2 => EntitlementAuditAction::Deleted,
            3 => EntitlementAuditAction::Assigned,
            4 => EntitlementAuditAction::Revoked,
            _ => EntitlementAuditAction::StatusChanged,
        };

        ctx.stores
            .audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id: ctx.tenant_a,
                entitlement_id: Some(Uuid::new_v4()),
                action,
                actor_id: ctx.actor_id,
                ..Default::default()
            })
            .await
            .expect("Failed to log audit event");
    }

    let end_time = Utc::now();

    // Time the query operation
    let start = Instant::now();

    let events = ctx
        .stores
        .audit_store
        .query_events(
            ctx.tenant_a,
            AuditEventFilter {
                from_date: Some(start_time - Duration::hours(1)),
                to_date: Some(end_time + Duration::hours(1)),
                limit: Some(1000),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to query events");

    let duration = start.elapsed();

    // Verify results and timing
    assert_eq!(events.len(), 1000, "Should return 1000 events");
    assert!(
        duration.as_secs() < 1,
        "Audit query took {}ms, should be under 1000ms",
        duration.as_millis()
    );

    println!(
        "PF-004: Queried 1000 audit events from 50000 in {}ms",
        duration.as_millis()
    );
}

// ============================================================================
// Additional Performance Tests
// ============================================================================

/// Test bulk entitlement creation performance.
#[tokio::test]
#[ignore] // Performance test
async fn test_bulk_entitlement_creation() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    let start = Instant::now();

    for i in 0..500 {
        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Bulk Entitlement {}", i),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
    }

    let duration = start.elapsed();

    println!(
        "Bulk creation: 500 entitlements in {}ms ({:.2} per sec)",
        duration.as_millis(),
        500.0 / duration.as_secs_f64()
    );

    // Should complete in reasonable time
    assert!(
        duration.as_secs() < 10,
        "Bulk creation too slow: {}ms",
        duration.as_millis()
    );
}

/// Test concurrent operations performance.
#[tokio::test]
#[ignore] // Performance test
async fn test_concurrent_reads() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create some entitlements first
    for i in 0..100 {
        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Concurrent Read {}", i),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
    }

    let start = Instant::now();

    // Perform 100 concurrent reads
    let mut handles = Vec::new();
    for _ in 0..100 {
        let services = TestContext::new();
        let tenant = ctx.tenant_a;

        let handle = tokio::spawn(async move {
            services
                .services
                .entitlement
                .list(
                    tenant,
                    &EntitlementFilter::default(),
                    &ListOptions { limit: 10, offset: 0 },
                )
                .await
        });
        handles.push(handle);
    }

    // Wait for all reads to complete
    for handle in handles {
        handle.await.expect("Task panicked").expect("Read failed");
    }

    let duration = start.elapsed();

    println!(
        "Concurrent reads: 100 parallel list operations in {}ms",
        duration.as_millis()
    );

    // Should complete in reasonable time
    assert!(
        duration.as_millis() < 2000,
        "Concurrent reads too slow: {}ms",
        duration.as_millis()
    );
}

/// Test risk calculation performance with many entitlements.
#[tokio::test]
#[ignore] // Performance test
async fn test_risk_calculation_performance() {
    let ctx = TestContext::new();
    let user_id = Uuid::new_v4();

    // Create a large set of risk levels
    let risk_levels: Vec<RiskLevel> = (0..1000)
        .map(|i| match i % 4 {
            0 => RiskLevel::Low,
            1 => RiskLevel::Medium,
            2 => RiskLevel::High,
            _ => RiskLevel::Critical,
        })
        .collect();

    let start = Instant::now();

    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(ctx.tenant_a, user_id, &risk_levels, 10)
        .await
        .expect("Failed to calculate risk");

    let duration = start.elapsed();

    println!(
        "Risk calculation: 1000 entitlements in {}ms",
        duration.as_millis()
    );

    // Should complete quickly
    assert!(
        duration.as_millis() < 100,
        "Risk calculation too slow: {}ms",
        duration.as_millis()
    );

    // Verify calculation
    assert!(risk_score.score > 0);
}
