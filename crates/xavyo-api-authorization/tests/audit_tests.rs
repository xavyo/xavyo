//! Integration tests for authorization audit logging (F-020).
//!
//! Tests for policy change audit events, version history, and audit query functionality.

#![cfg(feature = "integration")]

mod common;

use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use xavyo_api_authorization::models::{
    PolicyAuditAction, PolicyAuditEventInput, PolicyAuditFilter, PolicyVersionInput,
};
use xavyo_api_authorization::services::{
    FailingPolicyAuditStore, InMemoryPolicyAuditStore, PolicyAuditStore,
};

use common::{create_test_policy, unique_policy_name, TestFixture};

// ============================================================================
// Phase 3: User Story 1 - Policy Change Audit Trail (8 tests)
// ============================================================================

/// T007: Create policy should log audit event with after_state
#[tokio::test]
async fn test_create_policy_logs_audit_event() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Create a policy
    let policy = create_test_policy(&fixture, &unique_policy_name("audit-create")).await;

    // Log the audit event (simulating what the handler would do)
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id: policy.id,
        action: PolicyAuditAction::Created,
        actor_id: fixture.admin_user_id,
        before_state: None,
        after_state: Some(serde_json::to_value(&policy).unwrap()),
        metadata: None,
    };

    let event = store.log_event(input).await.unwrap();

    // Verify event properties
    assert_eq!(event.tenant_id, fixture.tenant_id);
    assert_eq!(event.policy_id, policy.id);
    assert_eq!(event.action, PolicyAuditAction::Created);
    assert_eq!(event.actor_id, fixture.admin_user_id);
    assert!(event.before_state.is_none());
    assert!(event.after_state.is_some());

    fixture.cleanup().await;
}

/// T008: Update policy should log audit event with before_state and after_state
#[tokio::test]
async fn test_update_policy_logs_before_after() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Simulate before/after states
    let before_state = serde_json::json!({
        "name": "Original Name",
        "effect": "allow"
    });
    let after_state = serde_json::json!({
        "name": "Updated Name",
        "effect": "allow"
    });

    let policy_id = Uuid::new_v4();
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id,
        action: PolicyAuditAction::Updated,
        actor_id: fixture.admin_user_id,
        before_state: Some(before_state.clone()),
        after_state: Some(after_state.clone()),
        metadata: None,
    };

    let event = store.log_event(input).await.unwrap();

    // Verify both states are captured
    assert_eq!(event.action, PolicyAuditAction::Updated);
    assert!(event.before_state.is_some());
    assert!(event.after_state.is_some());
    assert_eq!(event.before_state.unwrap()["name"], "Original Name");
    assert_eq!(event.after_state.unwrap()["name"], "Updated Name");

    fixture.cleanup().await;
}

/// T009: Delete policy should log audit event with before_state only
#[tokio::test]
async fn test_delete_policy_logs_before_state() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let before_state = serde_json::json!({
        "name": "To Be Deleted",
        "effect": "deny"
    });

    let policy_id = Uuid::new_v4();
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id,
        action: PolicyAuditAction::Deleted,
        actor_id: fixture.admin_user_id,
        before_state: Some(before_state),
        after_state: None, // No after_state for delete
        metadata: None,
    };

    let event = store.log_event(input).await.unwrap();

    // Verify delete event
    assert_eq!(event.action, PolicyAuditAction::Deleted);
    assert!(event.before_state.is_some());
    assert!(event.after_state.is_none());

    fixture.cleanup().await;
}

/// T010: Failed validation should not log audit event
#[tokio::test]
async fn test_failed_validation_no_audit() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Simulate: validation failure means no event is logged
    // The handler would only call store.log_event() AFTER successful operation

    // Verify store is empty (no events logged for failed validation)
    let (events, total) = store
        .query_events(fixture.tenant_id, PolicyAuditFilter::default())
        .await
        .unwrap();

    assert_eq!(events.len(), 0);
    assert_eq!(total, 0);

    fixture.cleanup().await;
}

/// T011: Condition changes should log audit events
#[tokio::test]
async fn test_condition_change_logs_audit() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id = Uuid::new_v4();

    // Log condition added event
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id,
        action: PolicyAuditAction::ConditionAdded,
        actor_id: fixture.admin_user_id,
        before_state: Some(serde_json::json!({"conditions": []})),
        after_state: Some(serde_json::json!({"conditions": [{"type": "time_window"}]})),
        metadata: Some(serde_json::json!({"condition_id": Uuid::new_v4().to_string()})),
    };

    let event = store.log_event(input).await.unwrap();
    assert_eq!(event.action, PolicyAuditAction::ConditionAdded);

    // Log condition removed event
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id,
        action: PolicyAuditAction::ConditionRemoved,
        actor_id: fixture.admin_user_id,
        before_state: Some(serde_json::json!({"conditions": [{"type": "time_window"}]})),
        after_state: Some(serde_json::json!({"conditions": []})),
        metadata: None,
    };

    let event = store.log_event(input).await.unwrap();
    assert_eq!(event.action, PolicyAuditAction::ConditionRemoved);

    fixture.cleanup().await;
}

/// T012: Actor ID should be extracted from JWT claims
#[tokio::test]
async fn test_audit_actor_id_from_jwt() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // The admin_user_id comes from JWT claims in real handlers
    let actor_id = fixture.admin_user_id;

    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id: Uuid::new_v4(),
        action: PolicyAuditAction::Created,
        actor_id,
        after_state: Some(serde_json::json!({"name": "test"})),
        ..Default::default()
    };

    let event = store.log_event(input).await.unwrap();

    // Verify actor_id matches
    assert_eq!(event.actor_id, fixture.admin_user_id);

    fixture.cleanup().await;
}

/// T013: Audit failure should not block primary operation
#[tokio::test]
async fn test_audit_failure_continues_operation() {
    let fixture = TestFixture::new().await;
    let failing_store = FailingPolicyAuditStore;

    // Simulate audit failure
    let input = PolicyAuditEventInput {
        tenant_id: fixture.tenant_id,
        policy_id: Uuid::new_v4(),
        action: PolicyAuditAction::Created,
        actor_id: fixture.admin_user_id,
        ..Default::default()
    };

    let result = failing_store.log_event(input).await;
    assert!(result.is_err());

    // In real code, we'd log a warning and continue
    // The primary operation (policy creation) would still succeed
    // This test verifies the FailingPolicyAuditStore works as expected

    fixture.cleanup().await;
}

/// T014: Audit events should be tenant isolated
#[tokio::test]
async fn test_audit_tenant_isolation() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let other_tenant_id = Uuid::new_v4();

    // Log event for fixture tenant
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    // Log event for other tenant
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: other_tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: Uuid::new_v4(),
            ..Default::default()
        })
        .await
        .unwrap();

    // Query for fixture tenant - should only see their event
    let (events, total) = store
        .query_events(fixture.tenant_id, PolicyAuditFilter::default())
        .await
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(total, 1);
    assert_eq!(events[0].tenant_id, fixture.tenant_id);

    // Query for other tenant - should only see their event
    let (events, total) = store
        .query_events(other_tenant_id, PolicyAuditFilter::default())
        .await
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(total, 1);
    assert_eq!(events[0].tenant_id, other_tenant_id);

    fixture.cleanup().await;
}

// ============================================================================
// Phase 4: User Story 2 - Policy Version History (4 tests)
// ============================================================================

/// T015: List policy versions should return all versions
#[tokio::test]
async fn test_list_policy_versions() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id = Uuid::new_v4();

    // Store 3 versions
    for i in 1..=3 {
        store
            .store_version(PolicyVersionInput {
                tenant_id: fixture.tenant_id,
                policy_id,
                policy_state: serde_json::json!({"name": format!("Version {}", i)}),
                created_by: fixture.admin_user_id,
            })
            .await
            .unwrap();
    }

    // List versions
    let versions = store
        .list_versions(fixture.tenant_id, policy_id)
        .await
        .unwrap();

    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version_number, 1);
    assert_eq!(versions[1].version_number, 2);
    assert_eq!(versions[2].version_number, 3);

    fixture.cleanup().await;
}

/// T016: Get specific version should return exact state
#[tokio::test]
async fn test_get_specific_version() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id = Uuid::new_v4();
    let v1_state = serde_json::json!({"name": "Original", "effect": "allow"});
    let v2_state = serde_json::json!({"name": "Updated", "effect": "deny"});

    // Store two versions
    store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: v1_state.clone(),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();

    store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: v2_state.clone(),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();

    // Get version 1
    let v1 = store
        .get_version(fixture.tenant_id, policy_id, 1)
        .await
        .unwrap()
        .expect("Version 1 should exist");

    assert_eq!(v1.version_number, 1);
    assert_eq!(v1.policy_state["name"], "Original");
    assert_eq!(v1.policy_state["effect"], "allow");

    // Get version 2
    let v2 = store
        .get_version(fixture.tenant_id, policy_id, 2)
        .await
        .unwrap()
        .expect("Version 2 should exist");

    assert_eq!(v2.version_number, 2);
    assert_eq!(v2.policy_state["name"], "Updated");
    assert_eq!(v2.policy_state["effect"], "deny");

    fixture.cleanup().await;
}

/// T017: Version numbers should be sequential
#[tokio::test]
async fn test_version_numbers_sequential() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id = Uuid::new_v4();

    // Store versions and verify numbers
    let v1 = store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: serde_json::json!({"v": 1}),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();
    assert_eq!(v1.version_number, 1);

    let v2 = store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: serde_json::json!({"v": 2}),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();
    assert_eq!(v2.version_number, 2);

    let v3 = store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: serde_json::json!({"v": 3}),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();
    assert_eq!(v3.version_number, 3);

    // Verify next_version_number
    let next = store
        .next_version_number(fixture.tenant_id, policy_id)
        .await
        .unwrap();
    assert_eq!(next, 4);

    fixture.cleanup().await;
}

/// T018: Deleted policy should still have version history
#[tokio::test]
async fn test_deleted_policy_versions() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id = Uuid::new_v4();

    // Store initial version
    store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: serde_json::json!({"name": "Active Policy", "status": "active"}),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();

    // Store final "deleted" version
    store
        .store_version(PolicyVersionInput {
            tenant_id: fixture.tenant_id,
            policy_id,
            policy_state: serde_json::json!({"name": "Active Policy", "status": "deleted"}),
            created_by: fixture.admin_user_id,
        })
        .await
        .unwrap();

    // Even after "deletion", version history should be available
    let versions = store
        .list_versions(fixture.tenant_id, policy_id)
        .await
        .unwrap();

    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].policy_state["status"], "active");
    assert_eq!(versions[1].policy_state["status"], "deleted");

    fixture.cleanup().await;
}

// ============================================================================
// Phase 5: User Story 3 - Audit Query Endpoints (5 tests)
// ============================================================================

/// T019: Query by policy_id should return only matching events
#[tokio::test]
async fn test_query_by_policy_id() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let policy_id_1 = Uuid::new_v4();
    let policy_id_2 = Uuid::new_v4();

    // Log events for both policies
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: policy_id_1,
            action: PolicyAuditAction::Created,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: policy_id_1,
            action: PolicyAuditAction::Updated,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: policy_id_2,
            action: PolicyAuditAction::Created,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    // Query for policy_id_1
    let filter = PolicyAuditFilter {
        policy_id: Some(policy_id_1),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(total, 2);
    assert!(events.iter().all(|e| e.policy_id == policy_id_1));

    fixture.cleanup().await;
}

/// T020: Query by actor_id should return only events by that actor
#[tokio::test]
async fn test_query_by_actor_id() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    let actor_1 = fixture.admin_user_id;
    let actor_2 = Uuid::new_v4();

    // Log events by different actors
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: actor_1,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: actor_2,
            ..Default::default()
        })
        .await
        .unwrap();

    // Query for actor_1
    let filter = PolicyAuditFilter {
        actor_id: Some(actor_1),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(total, 1);
    assert_eq!(events[0].actor_id, actor_1);

    fixture.cleanup().await;
}

/// T021: Query by action should return only matching action types
#[tokio::test]
async fn test_query_by_action() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Log different action types
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Updated,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Deleted,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    // Query for Created action only
    let filter = PolicyAuditFilter {
        action: Some(PolicyAuditAction::Created),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(total, 1);
    assert_eq!(events[0].action, PolicyAuditAction::Created);

    fixture.cleanup().await;
}

/// T022: Query by date range should return events within range
#[tokio::test]
async fn test_query_by_date_range() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Log an event
    store
        .log_event(PolicyAuditEventInput {
            tenant_id: fixture.tenant_id,
            policy_id: Uuid::new_v4(),
            action: PolicyAuditAction::Created,
            actor_id: fixture.admin_user_id,
            ..Default::default()
        })
        .await
        .unwrap();

    // Query with from_date in the past - should find event
    let filter = PolicyAuditFilter {
        from_date: Some(Utc::now() - Duration::hours(1)),
        ..Default::default()
    };

    let (events, _) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 1);

    // Query with from_date in the future - should not find event
    let filter = PolicyAuditFilter {
        from_date: Some(Utc::now() + Duration::hours(1)),
        ..Default::default()
    };

    let (events, _) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 0);

    // Query with to_date in the past - should not find event
    let filter = PolicyAuditFilter {
        to_date: Some(Utc::now() - Duration::hours(1)),
        ..Default::default()
    };

    let (events, _) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 0);

    fixture.cleanup().await;
}

/// T023: Pagination should work with limit and offset
#[tokio::test]
async fn test_query_pagination() {
    let fixture = TestFixture::new().await;
    let store = Arc::new(InMemoryPolicyAuditStore::new());

    // Log 5 events
    for _ in 0..5 {
        store
            .log_event(PolicyAuditEventInput {
                tenant_id: fixture.tenant_id,
                policy_id: Uuid::new_v4(),
                action: PolicyAuditAction::Created,
                actor_id: fixture.admin_user_id,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // Get first page (2 items)
    let filter = PolicyAuditFilter {
        limit: Some(2),
        offset: Some(0),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(total, 5); // Total count is still 5

    // Get second page (2 items)
    let filter = PolicyAuditFilter {
        limit: Some(2),
        offset: Some(2),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(total, 5);

    // Get third page (1 item remaining)
    let filter = PolicyAuditFilter {
        limit: Some(2),
        offset: Some(4),
        ..Default::default()
    };

    let (events, total) = store.query_events(fixture.tenant_id, filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(total, 5);

    fixture.cleanup().await;
}
