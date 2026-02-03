//! Integration tests for multi-tenant isolation (US1).
//!
//! These tests verify complete tenant isolation across all governance services,
//! ensuring no cross-tenant data leakage.

#![cfg(feature = "integration")]

mod common;

use uuid::Uuid;
use xavyo_governance::services::entitlement::{CreateEntitlementInput, EntitlementFilter, ListOptions};
use xavyo_governance::services::assignment::{AssignEntitlementInput, AssignmentStore};
use xavyo_governance::services::sod::CreateSodRuleInput;
use xavyo_governance::types::{RiskLevel, SodConflictType, SodSeverity};
use chrono::{Duration, Utc};

use common::TestContext;

// ============================================================================
// TI-001: Entitlement Isolation Between Tenants
// ============================================================================

/// Test that tenant A's entitlements are NOT visible to tenant B.
///
/// Given tenant A has entitlement "Admin Access"
/// And tenant B has entitlement "User Access"
/// When tenant A lists all entitlements
/// Then only "Admin Access" is returned
/// And "User Access" is NOT visible
#[tokio::test]
async fn test_ti_001_entitlement_isolation_between_tenants() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create entitlement for tenant A
    let tenant_a_entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Admin Access".to_string(),
                description: Some("Admin entitlement for tenant A".to_string()),
                risk_level: RiskLevel::Critical,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create tenant A entitlement");

    // Create entitlement for tenant B
    let _tenant_b_entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_b,
            CreateEntitlementInput {
                application_id: app_id,
                name: "User Access".to_string(),
                description: Some("User entitlement for tenant B".to_string()),
                risk_level: RiskLevel::Low,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create tenant B entitlement");

    // List entitlements for tenant A
    let tenant_a_list = ctx
        .services
        .entitlement
        .list(ctx.tenant_a, &EntitlementFilter::default(), &ListOptions::default())
        .await
        .expect("Failed to list tenant A entitlements");

    // List entitlements for tenant B
    let tenant_b_list = ctx
        .services
        .entitlement
        .list(ctx.tenant_b, &EntitlementFilter::default(), &ListOptions::default())
        .await
        .expect("Failed to list tenant B entitlements");

    // Verify isolation
    assert_eq!(tenant_a_list.len(), 1, "Tenant A should have exactly 1 entitlement");
    assert_eq!(tenant_a_list[0].name, "Admin Access");
    assert_eq!(tenant_a_list[0].tenant_id, ctx.tenant_a);

    assert_eq!(tenant_b_list.len(), 1, "Tenant B should have exactly 1 entitlement");
    assert_eq!(tenant_b_list[0].name, "User Access");
    assert_eq!(tenant_b_list[0].tenant_id, ctx.tenant_b);

    // Verify cross-tenant access is denied
    let cross_tenant_get = ctx
        .services
        .entitlement
        .get(ctx.tenant_b, tenant_a_entitlement.id.into_inner())
        .await
        .expect("Get should not error");

    assert!(
        cross_tenant_get.is_none(),
        "Tenant B should NOT be able to access tenant A's entitlement"
    );
}

// ============================================================================
// TI-002: Assignment Isolation Between Tenants
// ============================================================================

/// Test that assignments are isolated between tenants.
///
/// Given user U1 in tenant A has assignment to "Admin Access"
/// When querying assignments from tenant B context
/// Then no assignments are returned
#[tokio::test]
async fn test_ti_002_assignment_isolation_between_tenants() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlement for tenant A
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Admin Access".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create entitlement");

    // Create assignment for tenant A
    let assignment = ctx
        .services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: entitlement.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Test assignment".to_string()),
            },
        )
        .await
        .expect("Failed to create assignment");

    // Try to access assignment from tenant B
    let cross_tenant_assignment = ctx
        .stores
        .assignment_store
        .get(ctx.tenant_b, assignment.id.into_inner())
        .await
        .expect("Get should not error");

    assert!(
        cross_tenant_assignment.is_none(),
        "Tenant B should NOT be able to access tenant A's assignment"
    );

    // List assignments for the same user from tenant B context
    let tenant_b_assignments = ctx
        .stores
        .assignment_store
        .list_user_assignments(ctx.tenant_b, user_id)
        .await
        .expect("List should not error");

    assert!(
        tenant_b_assignments.is_empty(),
        "Tenant B should see no assignments for user in tenant A context"
    );
}

// ============================================================================
// TI-003: SoD Rule Isolation Between Tenants
// ============================================================================

/// Test that SoD rules are isolated between tenants.
///
/// Given tenant A has SoD rule "No Admin+Delete"
/// When tenant B lists SoD rules
/// Then the list is empty
#[tokio::test]
async fn test_ti_003_sod_rule_isolation_between_tenants() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create entitlements for tenant A to use in SoD rule
    let edit_entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
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
        .expect("Failed to create Edit entitlement");

    let delete_entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Create SoD rule for tenant A
    let rule = ctx
        .services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Admin+Delete".to_string(),
                description: Some("Cannot have both admin and delete".to_string()),
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![
                    edit_entitlement.id.into_inner(),
                    delete_entitlement.id.into_inner(),
                ],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // List SoD rules for tenant A
    let tenant_a_rules = ctx
        .services
        .sod
        .list_rules(ctx.tenant_a)
        .await
        .expect("Failed to list tenant A rules");

    // List SoD rules for tenant B
    let tenant_b_rules = ctx
        .services
        .sod
        .list_rules(ctx.tenant_b)
        .await
        .expect("Failed to list tenant B rules");

    // Verify isolation
    assert_eq!(tenant_a_rules.len(), 1, "Tenant A should have 1 SoD rule");
    assert_eq!(tenant_a_rules[0].name, "No Admin+Delete");

    assert!(
        tenant_b_rules.is_empty(),
        "Tenant B should have no SoD rules"
    );

    // Verify cross-tenant access is denied
    let cross_tenant_rule = ctx
        .services
        .sod
        .get_rule(ctx.tenant_b, rule.id)
        .await
        .expect("Get should not error");

    assert!(
        cross_tenant_rule.is_none(),
        "Tenant B should NOT be able to access tenant A's SoD rule"
    );
}

// ============================================================================
// TI-004: Risk Data Isolation Between Tenants
// ============================================================================

/// Test that risk data is isolated between tenants.
///
/// Given tenant A has risk history for user U1
/// When tenant B queries risk trend for user U1
/// Then no history is returned
#[tokio::test]
async fn test_ti_004_risk_data_isolation_between_tenants() {
    let ctx = TestContext::with_predictable_ids();
    let user_id = Uuid::new_v4();

    // Calculate and record risk for user in tenant A
    let risk_score = ctx
        .services
        .risk
        .calculate_user_risk(
            ctx.tenant_a,
            user_id,
            &[RiskLevel::Low, RiskLevel::Medium, RiskLevel::High],
            1, // 1 SoD violation
        )
        .await
        .expect("Failed to calculate risk");

    // Record the risk to history
    ctx.services
        .risk
        .record_risk_history(ctx.tenant_a, user_id, &risk_score)
        .await
        .expect("Failed to record risk history");

    // Get risk trend for tenant A (since 30 days ago)
    let tenant_a_trend = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_a, user_id, Utc::now() - Duration::days(30))
        .await
        .expect("Failed to get tenant A risk trend");

    // Get risk trend for tenant B (same user ID)
    let tenant_b_trend = ctx
        .services
        .risk
        .get_risk_trend(ctx.tenant_b, user_id, Utc::now() - Duration::days(30))
        .await
        .expect("Failed to get tenant B risk trend");

    // Verify isolation
    assert_eq!(
        tenant_a_trend.len(),
        1,
        "Tenant A should have 1 risk history entry"
    );

    assert!(
        tenant_b_trend.is_empty(),
        "Tenant B should have no risk history for the same user ID"
    );
}

// ============================================================================
// Additional Isolation Tests
// ============================================================================

/// Test that entitlement counts are isolated between tenants.
#[tokio::test]
async fn test_entitlement_count_isolation() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create 3 entitlements for tenant A
    for i in 0..3 {
        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Tenant A Entitlement {}", i),
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

    // Create 1 entitlement for tenant B
    ctx.services
        .entitlement
        .create(
            ctx.tenant_b,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Tenant B Entitlement".to_string(),
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

    // Count for tenant A
    let tenant_a_count = ctx
        .services
        .entitlement
        .count(ctx.tenant_a, &EntitlementFilter::default())
        .await
        .expect("Failed to count tenant A entitlements");

    // Count for tenant B
    let tenant_b_count = ctx
        .services
        .entitlement
        .count(ctx.tenant_b, &EntitlementFilter::default())
        .await
        .expect("Failed to count tenant B entitlements");

    assert_eq!(tenant_a_count, 3, "Tenant A should have 3 entitlements");
    assert_eq!(tenant_b_count, 1, "Tenant B should have 1 entitlement");
}

/// Test that updates are tenant-isolated.
#[tokio::test]
async fn test_update_isolation() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create entitlement for tenant A
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Original Name".to_string(),
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

    // Try to update from tenant B context - should fail
    let update_result = ctx
        .services
        .entitlement
        .update(
            ctx.tenant_b,
            entitlement.id.into_inner(),
            xavyo_governance::services::entitlement::UpdateEntitlementInput {
                name: Some("Hacked Name".to_string()),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await;

    assert!(
        update_result.is_err(),
        "Update from wrong tenant should fail"
    );

    // Verify original is unchanged
    let unchanged = ctx
        .services
        .entitlement
        .get(ctx.tenant_a, entitlement.id.into_inner())
        .await
        .expect("Failed to get entitlement")
        .expect("Entitlement should exist");

    assert_eq!(
        unchanged.name, "Original Name",
        "Entitlement should be unchanged"
    );
}

/// Test that deletes are tenant-isolated.
#[tokio::test]
async fn test_delete_isolation() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create entitlement for tenant A
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Protected Entitlement".to_string(),
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

    // Try to delete from tenant B context - should fail
    let delete_result = ctx
        .services
        .entitlement
        .delete(ctx.tenant_b, entitlement.id.into_inner(), ctx.actor_id)
        .await;

    assert!(
        delete_result.is_err(),
        "Delete from wrong tenant should fail"
    );

    // Verify it still exists for tenant A
    let still_exists = ctx
        .services
        .entitlement
        .get(ctx.tenant_a, entitlement.id.into_inner())
        .await
        .expect("Failed to get entitlement");

    assert!(
        still_exists.is_some(),
        "Entitlement should still exist after cross-tenant delete attempt"
    );
}
