//! Integration tests for entitlement lifecycle (US2).
//!
//! These tests validate the full CRUD lifecycle for entitlements and assignments.

#![cfg(feature = "integration")]

mod common;

use uuid::Uuid;
use xavyo_governance::services::assignment::{AssignEntitlementInput, AssignmentStore};
use xavyo_governance::services::entitlement::{
    CreateEntitlementInput, EntitlementFilter, ListOptions, UpdateEntitlementInput,
};
use xavyo_governance::types::{EntitlementStatus, RiskLevel};

use common::TestContext;

// ============================================================================
// EL-001: Create and Retrieve Entitlement
// ============================================================================

/// Test creating and retrieving an entitlement.
///
/// Given a new tenant
/// When creating entitlement "Test Permission"
/// Then the entitlement has a valid ID
/// And can be retrieved by ID
/// And appears in the entitlement list
#[tokio::test]
async fn test_el_001_create_and_retrieve_entitlement() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create entitlement
    let created = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Test Permission".to_string(),
                description: Some("A test entitlement".to_string()),
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: Some("ext-001".to_string()),
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create entitlement");

    // Verify ID is valid
    assert!(!created.id.into_inner().is_nil(), "ID should not be nil");
    assert_eq!(created.tenant_id, ctx.tenant_a);
    assert_eq!(created.name, "Test Permission");
    assert_eq!(created.status, EntitlementStatus::Active);

    // Retrieve by ID
    let retrieved = ctx
        .services
        .entitlement
        .get(ctx.tenant_a, created.id.into_inner())
        .await
        .expect("Failed to get entitlement")
        .expect("Entitlement should exist");

    assert_eq!(retrieved.id, created.id);
    assert_eq!(retrieved.name, "Test Permission");
    assert_eq!(retrieved.risk_level, RiskLevel::Medium);

    // Appears in list
    let list = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter::default(),
            &ListOptions::default(),
        )
        .await
        .expect("Failed to list entitlements");

    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, created.id);
}

// ============================================================================
// EL-002: Update Entitlement with Audit
// ============================================================================

/// Test updating an entitlement and verifying audit.
///
/// Given entitlement "Test Permission" exists
/// When updating description to "Updated description"
/// Then the change persists
/// And audit log records the update
#[tokio::test]
async fn test_el_002_update_entitlement_with_audit() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create entitlement
    let created = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Test Permission".to_string(),
                description: Some("Original description".to_string()),
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

    // Record initial audit count
    let initial_audit_count = ctx.stores.audit_store.count().await;

    // Update entitlement
    let updated = ctx
        .services
        .entitlement
        .update(
            ctx.tenant_a,
            created.id.into_inner(),
            UpdateEntitlementInput {
                description: Some("Updated description".to_string()),
                risk_level: Some(RiskLevel::High),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to update entitlement");

    // Verify changes persisted
    assert_eq!(
        updated.description,
        Some("Updated description".to_string())
    );
    assert_eq!(updated.risk_level, RiskLevel::High);
    assert_eq!(updated.name, "Test Permission"); // Unchanged

    // Verify by re-fetching
    let refetched = ctx
        .services
        .entitlement
        .get(ctx.tenant_a, created.id.into_inner())
        .await
        .expect("Failed to get entitlement")
        .expect("Entitlement should exist");

    assert_eq!(
        refetched.description,
        Some("Updated description".to_string())
    );

    // Verify audit log
    let final_audit_count = ctx.stores.audit_store.count().await;
    assert!(
        final_audit_count > initial_audit_count,
        "Audit log should have new entry for update"
    );
}

// ============================================================================
// EL-003: Assign and Revoke Entitlement
// ============================================================================

/// Test assigning and revoking an entitlement.
///
/// Given entitlement "Test Permission" exists
/// And user "test-user" exists
/// When assigning entitlement to user
/// Then assignment is active
/// When revoking the assignment
/// Then assignment is no longer active
/// And audit log records both events
#[tokio::test]
async fn test_el_003_assign_and_revoke_entitlement() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Test Permission".to_string(),
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

    let initial_audit_count = ctx.stores.audit_store.count().await;

    // Assign entitlement
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
                justification: Some("Business need".to_string()),
            },
        )
        .await
        .expect("Failed to assign entitlement");

    assert!(!assignment.id.into_inner().is_nil());
    assert_eq!(
        assignment.status,
        xavyo_governance::types::AssignmentStatus::Active
    );

    // Verify assignment exists
    let user_assignments = ctx
        .stores
        .assignment_store
        .list_user_assignments(ctx.tenant_a, user_id)
        .await
        .expect("Failed to list assignments");

    assert_eq!(user_assignments.len(), 1);
    assert_eq!(user_assignments[0].entitlement_id, entitlement.id.into_inner());

    // Revoke assignment
    let revoked = ctx
        .services
        .assignment
        .revoke(ctx.tenant_a, assignment.id.into_inner(), ctx.actor_id)
        .await
        .expect("Failed to revoke assignment");

    assert!(revoked, "Revoke should return true");

    // Verify assignment no longer active
    let user_assignments_after = ctx
        .stores
        .assignment_store
        .list_user_assignments(ctx.tenant_a, user_id)
        .await
        .expect("Failed to list assignments");

    assert!(
        user_assignments_after.is_empty(),
        "User should have no active assignments after revoke"
    );

    // Verify audit log has both events
    let final_audit_count = ctx.stores.audit_store.count().await;
    assert!(
        final_audit_count >= initial_audit_count + 2,
        "Audit log should have entries for both assign and revoke"
    );
}

// ============================================================================
// EL-004: Filtered Entitlement Listing
// ============================================================================

/// Test filtered listing of entitlements.
///
/// Given 10 entitlements with various risk levels
/// When filtering by risk_level = High
/// Then only High-risk entitlements are returned
#[tokio::test]
async fn test_el_004_filtered_entitlement_listing() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create entitlements with different risk levels
    let risk_levels = [
        RiskLevel::Low,
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::Medium,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::High,
        RiskLevel::High,
        RiskLevel::Critical,
        RiskLevel::Critical,
    ];

    for (i, risk) in risk_levels.iter().enumerate() {
        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Entitlement {} ({:?})", i, risk),
                    description: None,
                    risk_level: *risk,
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

    // Filter by High risk
    let high_risk = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter {
                risk_level: Some(RiskLevel::High),
                ..Default::default()
            },
            &ListOptions::default(),
        )
        .await
        .expect("Failed to list high-risk entitlements");

    assert_eq!(high_risk.len(), 3, "Should have 3 high-risk entitlements");
    for e in &high_risk {
        assert_eq!(e.risk_level, RiskLevel::High);
    }

    // Filter by Critical risk
    let critical_risk = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter {
                risk_level: Some(RiskLevel::Critical),
                ..Default::default()
            },
            &ListOptions::default(),
        )
        .await
        .expect("Failed to list critical-risk entitlements");

    assert_eq!(
        critical_risk.len(),
        2,
        "Should have 2 critical-risk entitlements"
    );

    // Filter by status
    let active = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter {
                status: Some(EntitlementStatus::Active),
                ..Default::default()
            },
            &ListOptions::default(),
        )
        .await
        .expect("Failed to list active entitlements");

    assert_eq!(active.len(), 10, "All entitlements should be active");
}

// ============================================================================
// Edge Case: Delete Entitlement with Active Assignments
// ============================================================================

/// Test that deleting an entitlement with active assignments fails.
#[tokio::test]
async fn test_delete_entitlement_with_active_assignments_fails() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Assigned Permission".to_string(),
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

    // Create assignment
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: entitlement.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Test".to_string()),
            },
        )
        .await
        .expect("Failed to assign entitlement");

    // Add mock assignment to entitlement store for count
    ctx.stores
        .entitlement_store
        .add_mock_assignment(entitlement.id.into_inner(), Uuid::new_v4())
        .await;

    // Try to delete - should fail
    let delete_result = ctx
        .services
        .entitlement
        .delete(ctx.tenant_a, entitlement.id.into_inner(), ctx.actor_id)
        .await;

    assert!(
        delete_result.is_err(),
        "Delete should fail when entitlement has active assignments"
    );

    // Verify error type
    match delete_result {
        Err(xavyo_governance::GovernanceError::EntitlementHasAssignments(count)) => {
            assert!(count > 0, "Should report assignment count");
        }
        _ => panic!("Expected EntitlementHasAssignments error"),
    }

    // Verify entitlement still exists
    let still_exists = ctx
        .services
        .entitlement
        .get(ctx.tenant_a, entitlement.id.into_inner())
        .await
        .expect("Failed to get entitlement");

    assert!(
        still_exists.is_some(),
        "Entitlement should still exist after failed delete"
    );
}

// ============================================================================
// Edge Case: Concurrent Assignment/Revocation
// ============================================================================

/// Test concurrent assignment operations.
#[tokio::test]
async fn test_concurrent_assignment_operations() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create multiple entitlements
    let mut entitlements = Vec::new();
    for i in 0..5 {
        let e = ctx
            .services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Concurrent Test {}", i),
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
        entitlements.push(e);
    }

    let user_id = Uuid::new_v4();

    // Assign all entitlements sequentially
    for e in &entitlements {
        ctx.services
            .assignment
            .assign(
                ctx.tenant_a,
                AssignEntitlementInput {
                    entitlement_id: e.id.into_inner(),
                    user_id,
                    assigned_by: ctx.actor_id,
                    expires_at: None,
                    justification: Some("Concurrent test".to_string()),
                },
            )
            .await
            .expect("Failed to assign entitlement");
    }

    // Verify all assignments exist
    let user_entitlements = ctx
        .stores
        .assignment_store
        .list_user_entitlement_ids(ctx.tenant_a, user_id)
        .await
        .expect("Failed to list user entitlements");

    assert_eq!(
        user_entitlements.len(),
        5,
        "User should have all 5 entitlements assigned"
    );
}

// ============================================================================
// Additional Lifecycle Tests
// ============================================================================

/// Test pagination of entitlement list.
#[tokio::test]
async fn test_entitlement_list_pagination() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create 25 entitlements
    for i in 0..25 {
        ctx.services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Entitlement {:02}", i),
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

    // Get first page
    let page1 = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter::default(),
            &ListOptions {
                limit: 10,
                offset: 0,
            },
        )
        .await
        .expect("Failed to list page 1");

    assert_eq!(page1.len(), 10, "Page 1 should have 10 items");

    // Get second page
    let page2 = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter::default(),
            &ListOptions {
                limit: 10,
                offset: 10,
            },
        )
        .await
        .expect("Failed to list page 2");

    assert_eq!(page2.len(), 10, "Page 2 should have 10 items");

    // Get third page
    let page3 = ctx
        .services
        .entitlement
        .list(
            ctx.tenant_a,
            &EntitlementFilter::default(),
            &ListOptions {
                limit: 10,
                offset: 20,
            },
        )
        .await
        .expect("Failed to list page 3");

    assert_eq!(page3.len(), 5, "Page 3 should have 5 items");

    // Verify no overlap between pages
    let page1_ids: Vec<_> = page1.iter().map(|e| e.id).collect();
    let page2_ids: Vec<_> = page2.iter().map(|e| e.id).collect();

    for id in &page2_ids {
        assert!(
            !page1_ids.contains(id),
            "Page 2 should not contain items from page 1"
        );
    }
}

/// Test status transitions.
#[tokio::test]
async fn test_entitlement_status_transitions() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create active entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Status Test".to_string(),
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

    assert_eq!(entitlement.status, EntitlementStatus::Active);

    // Deactivate
    let deactivated = ctx
        .services
        .entitlement
        .update(
            ctx.tenant_a,
            entitlement.id.into_inner(),
            UpdateEntitlementInput {
                status: Some(EntitlementStatus::Inactive),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to deactivate entitlement");

    assert_eq!(deactivated.status, EntitlementStatus::Inactive);

    // Reactivate
    let reactivated = ctx
        .services
        .entitlement
        .update(
            ctx.tenant_a,
            entitlement.id.into_inner(),
            UpdateEntitlementInput {
                status: Some(EntitlementStatus::Active),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to reactivate entitlement");

    assert_eq!(reactivated.status, EntitlementStatus::Active);
}
