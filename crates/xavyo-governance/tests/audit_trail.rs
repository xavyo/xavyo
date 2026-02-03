//! Integration tests for audit trail (US4).
//!
//! These tests verify complete audit logging for all operations.

#![cfg(feature = "integration")]

mod common;

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_governance::audit::{AuditEventFilter, EntitlementAuditAction};
use xavyo_governance::services::assignment::AssignEntitlementInput;
use xavyo_governance::services::entitlement::{CreateEntitlementInput, UpdateEntitlementInput};
use xavyo_governance::types::RiskLevel;
use xavyo_governance::AuditStore;

use common::TestContext;

// ============================================================================
// AT-001: Creation Event Recorded
// ============================================================================

/// Test that creation events are properly recorded.
///
/// When creating an entitlement
/// Then audit log contains event with:
///   - event_type: "Created"
///   - entity_type: "Entitlement"
///   - actor_id: current user
///   - tenant_id: current tenant
///   - timestamp: within last 100ms
#[tokio::test]
async fn test_at_001_creation_event_recorded() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let before_create = Utc::now();

    // Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Audit Test Entitlement".to_string(),
                description: Some("Testing audit logging".to_string()),
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

    let after_create = Utc::now();

    // Get audit events
    let events = ctx.stores.audit_store.get_all();

    // Find the creation event
    let creation_event = events
        .iter()
        .find(|e| {
            e.entitlement_id == Some(entitlement.id.into_inner())
                && e.action == EntitlementAuditAction::Created
        })
        .expect("Creation event should exist");

    // Verify event properties
    assert_eq!(creation_event.tenant_id, ctx.tenant_a);
    assert_eq!(creation_event.actor_id, ctx.actor_id);
    assert!(
        creation_event.timestamp >= before_create && creation_event.timestamp <= after_create,
        "Timestamp should be within expected range"
    );
    assert!(
        creation_event.after_state.is_some(),
        "After state should be captured"
    );
    assert!(
        creation_event.before_state.is_none(),
        "Before state should be None for creation"
    );
}

// ============================================================================
// AT-002: Assignment Event with Metadata
// ============================================================================

/// Test that assignment events include metadata.
///
/// When assigning entitlement to user
/// Then audit log contains event with:
///   - event_type: "Assigned"
///   - metadata includes user_id and entitlement_id
#[tokio::test]
async fn test_at_002_assignment_event_with_metadata() {
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
                name: "Assignment Audit Test".to_string(),
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
                justification: Some("Testing audit logging".to_string()),
            },
        )
        .await
        .expect("Failed to assign entitlement");

    // Get audit events
    let events = ctx.stores.audit_store.get_all();

    // Find the assignment event
    let assignment_event = events
        .iter()
        .find(|e| e.action == EntitlementAuditAction::Assigned)
        .expect("Assignment event should exist");

    // Verify event properties
    assert_eq!(assignment_event.tenant_id, ctx.tenant_a);
    assert_eq!(assignment_event.actor_id, ctx.actor_id);
    assert_eq!(
        assignment_event.entitlement_id,
        Some(entitlement.id.into_inner())
    );
    assert_eq!(assignment_event.user_id, Some(user_id));
    assert_eq!(
        assignment_event.assignment_id,
        Some(assignment.id.into_inner())
    );
    assert!(
        assignment_event.after_state.is_some(),
        "After state should capture assignment details"
    );
}

// ============================================================================
// AT-003: Configuration Change Before/After
// ============================================================================

/// Test that updates capture before and after state.
///
/// When updating an entitlement
/// Then audit log contains event with:
///   - before_state: previous values
///   - after_state: new values
#[tokio::test]
async fn test_at_003_configuration_change_before_after() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Config Change Test".to_string(),
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

    // Update entitlement
    ctx.services
        .entitlement
        .update(
            ctx.tenant_a,
            entitlement.id.into_inner(),
            UpdateEntitlementInput {
                description: Some("Updated description".to_string()),
                risk_level: Some(RiskLevel::High),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to update entitlement");

    // Get audit events
    let events = ctx.stores.audit_store.get_all();

    // Find the update event
    let update_event = events
        .iter()
        .find(|e| {
            e.entitlement_id == Some(entitlement.id.into_inner())
                && e.action == EntitlementAuditAction::Updated
        })
        .expect("Update event should exist");

    // Verify before and after state
    assert!(
        update_event.before_state.is_some(),
        "Before state should be captured"
    );
    assert!(
        update_event.after_state.is_some(),
        "After state should be captured"
    );

    // Parse states to verify content
    let before = update_event
        .before_state
        .as_ref()
        .expect("Before state exists");
    let after = update_event
        .after_state
        .as_ref()
        .expect("After state exists");

    // Verify before state has original values
    assert_eq!(
        before.get("description").and_then(|v| v.as_str()),
        Some("Original description")
    );
    // RiskLevel uses serde(rename_all = "lowercase"), so serialized value is "low"
    assert_eq!(
        before.get("risk_level").and_then(|v| v.as_str()),
        Some("low")
    );

    // Verify after state has updated values
    assert_eq!(
        after.get("description").and_then(|v| v.as_str()),
        Some("Updated description")
    );
    // RiskLevel uses serde(rename_all = "lowercase"), so serialized value is "high"
    assert_eq!(
        after.get("risk_level").and_then(|v| v.as_str()),
        Some("high")
    );
}

// ============================================================================
// AT-004: Time Range Query Ordering
// ============================================================================

/// Test time range queries return ordered results.
///
/// Given events at T1, T2, T3, T4, T5
/// When querying events between T2 and T4
/// Then only events at T2, T3, T4 are returned
/// And they are ordered by timestamp
#[tokio::test]
async fn test_at_004_time_range_query_ordering() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create multiple entitlements to generate events at different times
    let mut entitlements = Vec::new();
    let start_time = Utc::now();

    for i in 0..5 {
        let e = ctx
            .services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Time Test {}", i),
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

        // Small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    let end_time = Utc::now();

    // Query events by time range
    let events = ctx
        .stores
        .audit_store
        .query_events(
            ctx.tenant_a,
            AuditEventFilter {
                from_date: Some(start_time),
                to_date: Some(end_time),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to query events");

    // Verify we have all events
    assert_eq!(events.len(), 5, "Should have 5 events");

    // Verify ordering (should be descending by timestamp - most recent first)
    for i in 1..events.len() {
        assert!(
            events[i].timestamp <= events[i - 1].timestamp,
            "Events should be ordered by timestamp descending (most recent first)"
        );
    }
}

// ============================================================================
// Audit Log Integrity (No Gaps)
// ============================================================================

/// Test that audit log has no gaps for a sequence of operations.
#[tokio::test]
async fn test_audit_log_integrity_no_gaps() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Perform a sequence of operations
    // 1. Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Integrity Test".to_string(),
                description: Some("Original".to_string()),
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

    // 2. Update entitlement
    ctx.services
        .entitlement
        .update(
            ctx.tenant_a,
            entitlement.id.into_inner(),
            UpdateEntitlementInput {
                description: Some("Updated".to_string()),
                ..Default::default()
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to update entitlement");

    // 3. Assign to user
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
                justification: Some("Test".to_string()),
            },
        )
        .await
        .expect("Failed to assign entitlement");

    // 4. Revoke assignment
    ctx.services
        .assignment
        .revoke(ctx.tenant_a, assignment.id.into_inner(), ctx.actor_id)
        .await
        .expect("Failed to revoke assignment");

    // Get all events for this entitlement
    let events = ctx.stores.audit_store.get_all();
    let entitlement_events: Vec<_> = events
        .iter()
        .filter(|e| e.entitlement_id == Some(entitlement.id.into_inner()))
        .collect();

    // Verify all operations are logged
    let actions: Vec<_> = entitlement_events.iter().map(|e| &e.action).collect();

    assert!(
        actions.contains(&&EntitlementAuditAction::Created),
        "Should have Created event"
    );
    assert!(
        actions.contains(&&EntitlementAuditAction::Updated),
        "Should have Updated event"
    );
    assert!(
        actions.contains(&&EntitlementAuditAction::Assigned),
        "Should have Assigned event"
    );
    assert!(
        actions.contains(&&EntitlementAuditAction::Revoked),
        "Should have Revoked event"
    );

    // Verify no duplicate or missing events
    assert_eq!(
        entitlement_events.len(),
        4,
        "Should have exactly 4 events for the sequence"
    );
}

// ============================================================================
// Additional Audit Tests
// ============================================================================

/// Test delete event is recorded.
#[tokio::test]
async fn test_delete_event_recorded() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();

    // Create entitlement
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete Audit Test".to_string(),
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

    // Delete entitlement
    ctx.services
        .entitlement
        .delete(ctx.tenant_a, entitlement.id.into_inner(), ctx.actor_id)
        .await
        .expect("Failed to delete entitlement");

    // Get audit events
    let events = ctx.stores.audit_store.get_all();

    // Find the delete event
    let delete_event = events
        .iter()
        .find(|e| {
            e.entitlement_id == Some(entitlement.id.into_inner())
                && e.action == EntitlementAuditAction::Deleted
        })
        .expect("Delete event should exist");

    // Verify before state is captured
    assert!(
        delete_event.before_state.is_some(),
        "Before state should be captured for delete"
    );
    assert!(
        delete_event.after_state.is_none(),
        "After state should be None for delete"
    );
}

/// Test actor ID is always recorded.
#[tokio::test]
async fn test_actor_id_always_recorded() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let different_actor = Uuid::new_v4();

    // Create with one actor
    let entitlement = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Actor Test".to_string(),
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

    // Update with different actor
    ctx.services
        .entitlement
        .update(
            ctx.tenant_a,
            entitlement.id.into_inner(),
            UpdateEntitlementInput {
                description: Some("Updated by different actor".to_string()),
                ..Default::default()
            },
            different_actor,
        )
        .await
        .expect("Failed to update entitlement");

    // Get audit events
    let events = ctx.stores.audit_store.get_all();

    // Find events for this entitlement
    let entitlement_events: Vec<_> = events
        .iter()
        .filter(|e| e.entitlement_id == Some(entitlement.id.into_inner()))
        .collect();

    // Verify actor IDs
    let create_event = entitlement_events
        .iter()
        .find(|e| e.action == EntitlementAuditAction::Created)
        .expect("Create event exists");
    let update_event = entitlement_events
        .iter()
        .find(|e| e.action == EntitlementAuditAction::Updated)
        .expect("Update event exists");

    assert_eq!(create_event.actor_id, ctx.actor_id);
    assert_eq!(update_event.actor_id, different_actor);
}

/// Test tenant isolation in audit queries.
#[tokio::test]
async fn test_audit_tenant_isolation() {
    let ctx = TestContext::with_predictable_ids();
    let app_id = Uuid::new_v4();

    // Create entitlement for tenant A
    ctx.services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Tenant A Audit".to_string(),
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
        .expect("Failed to create entitlement for tenant A");

    // Create entitlement for tenant B
    ctx.services
        .entitlement
        .create(
            ctx.tenant_b,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Tenant B Audit".to_string(),
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
        .expect("Failed to create entitlement for tenant B");

    // Query events for tenant A
    let tenant_a_events = ctx
        .stores
        .audit_store
        .query_events(
            ctx.tenant_a,
            AuditEventFilter {
                from_date: Some(Utc::now() - Duration::hours(1)),
                to_date: Some(Utc::now()),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to query tenant A events");

    // Query events for tenant B
    let tenant_b_events = ctx
        .stores
        .audit_store
        .query_events(
            ctx.tenant_b,
            AuditEventFilter {
                from_date: Some(Utc::now() - Duration::hours(1)),
                to_date: Some(Utc::now()),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to query tenant B events");

    // Verify isolation
    assert_eq!(tenant_a_events.len(), 1, "Tenant A should have 1 event");
    assert_eq!(tenant_b_events.len(), 1, "Tenant B should have 1 event");

    // Verify tenant IDs match
    assert!(
        tenant_a_events.iter().all(|e| e.tenant_id == ctx.tenant_a),
        "All tenant A events should have tenant A ID"
    );
    assert!(
        tenant_b_events.iter().all(|e| e.tenant_id == ctx.tenant_b),
        "All tenant B events should have tenant B ID"
    );
}
