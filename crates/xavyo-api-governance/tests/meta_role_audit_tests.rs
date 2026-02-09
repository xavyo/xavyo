//! Meta-role audit unit tests (T078 - US5).
//!
//! Tests for audit event creation, filtering, and statistics for meta-role operations.
//! These tests verify compliance requirements for complete audit trail.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use xavyo_db::{
    CreateGovMetaRoleEvent, MetaRoleEventFilter, MetaRoleEventStats, MetaRoleEventType,
};

// ============================================================================
// Event Creation Tests
// ============================================================================

#[test]
fn test_create_event_with_all_fields() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Created,
        actor_id: Some(actor_id),
        changes: Some(json!({
            "after": {
                "name": "High Risk Policy",
                "priority": 100
            }
        })),
        affected_roles: Some(json!([role_id])),
        metadata: Some(json!({
            "source": "api",
            "request_id": "req-123"
        })),
    };

    assert_eq!(event.meta_role_id, Some(meta_role_id));
    assert_eq!(event.event_type, MetaRoleEventType::Created);
    assert_eq!(event.actor_id, Some(actor_id));
    assert!(event.changes.is_some());
    assert!(event.affected_roles.is_some());
    assert!(event.metadata.is_some());
}

#[test]
fn test_create_event_with_minimal_fields() {
    let event = CreateGovMetaRoleEvent {
        meta_role_id: None, // Cascade events may not have meta_role_id
        event_type: MetaRoleEventType::CascadeStarted,
        actor_id: None, // System events have no actor
        changes: None,
        affected_roles: None,
        metadata: Some(json!({"trigger": "criteria_change"})),
    };

    assert!(event.meta_role_id.is_none());
    assert!(event.actor_id.is_none());
    assert!(event.changes.is_none());
}

// ============================================================================
// Event Type Coverage Tests
// ============================================================================

#[test]
fn test_all_event_types_are_defined() {
    // Verify all required event types exist per spec
    let _created = MetaRoleEventType::Created;
    let _updated = MetaRoleEventType::Updated;
    let _deleted = MetaRoleEventType::Deleted;
    let _disabled = MetaRoleEventType::Disabled;
    let _enabled = MetaRoleEventType::Enabled;
    let _inheritance_applied = MetaRoleEventType::InheritanceApplied;
    let _inheritance_removed = MetaRoleEventType::InheritanceRemoved;
    let _conflict_detected = MetaRoleEventType::ConflictDetected;
    let _conflict_resolved = MetaRoleEventType::ConflictResolved;
    let _cascade_started = MetaRoleEventType::CascadeStarted;
    let _cascade_completed = MetaRoleEventType::CascadeCompleted;
    let _cascade_failed = MetaRoleEventType::CascadeFailed;
}

#[test]
fn test_created_event_structure() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Created,
        actor_id: Some(actor_id),
        changes: Some(json!({
            "after": {
                "name": "Security Controls",
                "description": "Applies security constraints",
                "priority": 100,
                "criteria_logic": "AND",
                "criteria": [
                    {"field": "risk_level", "operator": "eq", "value": "high"}
                ]
            }
        })),
        affected_roles: None,
        metadata: None,
    };

    let changes = event.changes.unwrap();
    assert!(changes.get("after").is_some());
    assert!(changes.get("after").unwrap().get("name").is_some());
}

#[test]
fn test_updated_event_with_before_after_diff() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Updated,
        actor_id: Some(actor_id),
        changes: Some(json!({
            "before": {
                "name": "Old Name",
                "priority": 100
            },
            "after": {
                "name": "New Name",
                "priority": 50
            }
        })),
        affected_roles: None,
        metadata: None,
    };

    let changes = event.changes.unwrap();
    assert!(changes.get("before").is_some());
    assert!(changes.get("after").is_some());
    assert_ne!(
        changes.get("before").unwrap().get("name"),
        changes.get("after").unwrap().get("name")
    );
}

#[test]
fn test_deleted_event_with_affected_roles() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let affected_roles: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Deleted,
        actor_id: Some(actor_id),
        changes: Some(json!({
            "before": {
                "name": "Deleted Meta-role",
                "status": "active"
            }
        })),
        affected_roles: Some(json!(affected_roles)),
        metadata: None,
    };

    let affected = event.affected_roles.unwrap();
    assert_eq!(affected.as_array().unwrap().len(), 5);
}

#[test]
fn test_disabled_event_with_reason() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Disabled,
        actor_id: Some(actor_id),
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "reason": "Policy review required",
            "affected_role_count": 42
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("reason").unwrap().as_str().unwrap(),
        "Policy review required"
    );
    assert_eq!(
        metadata
            .get("affected_role_count")
            .unwrap()
            .as_i64()
            .unwrap(),
        42
    );
}

#[test]
fn test_enabled_event_with_reactivation_count() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::Enabled,
        actor_id: Some(actor_id),
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "reactivated_role_count": 42
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata
            .get("reactivated_role_count")
            .unwrap()
            .as_i64()
            .unwrap(),
        42
    );
}

#[test]
fn test_inheritance_applied_event_with_match_reason() {
    let meta_role_id = Uuid::new_v4();
    let child_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::InheritanceApplied,
        actor_id: None, // System event
        changes: None,
        affected_roles: Some(json!([child_role_id])),
        metadata: Some(json!({
            "match_reason": {
                "criteria_matched": [
                    {"field": "risk_level", "operator": "eq", "value": "high", "actual": "high"}
                ],
                "match_score": 1.0
            }
        })),
    };

    let metadata = event.metadata.unwrap();
    assert!(metadata.get("match_reason").is_some());
}

#[test]
fn test_inheritance_removed_event_with_reason() {
    let meta_role_id = Uuid::new_v4();
    let child_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::InheritanceRemoved,
        actor_id: None, // System event - criteria no longer match
        changes: None,
        affected_roles: Some(json!([child_role_id])),
        metadata: Some(json!({
            "reason": "criteria_no_longer_match",
            "failed_criteria": {
                "field": "risk_level",
                "expected": "high",
                "actual": "medium"
            }
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("reason").unwrap().as_str().unwrap(),
        "criteria_no_longer_match"
    );
}

#[test]
fn test_conflict_detected_event() {
    let conflict_id = Uuid::new_v4();
    let meta_role_a_id = Uuid::new_v4();
    let meta_role_b_id = Uuid::new_v4();
    let affected_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_a_id),
        event_type: MetaRoleEventType::ConflictDetected,
        actor_id: None, // System event
        changes: None,
        affected_roles: Some(json!([affected_role_id])),
        metadata: Some(json!({
            "conflict_id": conflict_id,
            "meta_role_a_id": meta_role_a_id,
            "meta_role_b_id": meta_role_b_id,
            "conflict_type": "entitlement_conflict",
            "conflicting_items": {
                "entitlement_id": Uuid::new_v4(),
                "grant_meta_role": meta_role_a_id,
                "deny_meta_role": meta_role_b_id
            }
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("conflict_type").unwrap().as_str().unwrap(),
        "entitlement_conflict"
    );
}

#[test]
fn test_conflict_resolved_event() {
    let conflict_id = Uuid::new_v4();
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let winning_meta_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::ConflictResolved,
        actor_id: Some(actor_id),
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "conflict_id": conflict_id,
            "resolution_status": "resolved_priority",
            "resolution_choice": {
                "winning_meta_role_id": winning_meta_role_id,
                "resolution_reason": "priority"
            }
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("resolution_status").unwrap().as_str().unwrap(),
        "resolved_priority"
    );
}

#[test]
fn test_cascade_started_event() {
    let meta_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::CascadeStarted,
        actor_id: None, // System event
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "trigger": "entitlement_added",
            "expected_count": 150
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("trigger").unwrap().as_str().unwrap(),
        "entitlement_added"
    );
    assert_eq!(
        metadata.get("expected_count").unwrap().as_i64().unwrap(),
        150
    );
}

#[test]
fn test_cascade_completed_event() {
    let meta_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::CascadeCompleted,
        actor_id: None,
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "success_count": 148,
            "failure_count": 2,
            "duration_ms": 5432
        })),
    };

    let metadata = event.metadata.unwrap();
    assert_eq!(
        metadata.get("success_count").unwrap().as_i64().unwrap(),
        148
    );
    assert_eq!(metadata.get("failure_count").unwrap().as_i64().unwrap(), 2);
    assert_eq!(metadata.get("duration_ms").unwrap().as_i64().unwrap(), 5432);
}

#[test]
fn test_cascade_failed_event() {
    let meta_role_id = Uuid::new_v4();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_id),
        event_type: MetaRoleEventType::CascadeFailed,
        actor_id: None,
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "error": "Database connection timeout",
            "partial_success_count": 50,
            "remaining_count": 100
        })),
    };

    let metadata = event.metadata.unwrap();
    assert!(metadata.get("error").is_some());
}

// ============================================================================
// Event Filter Tests
// ============================================================================

#[test]
fn test_event_filter_default() {
    let filter = MetaRoleEventFilter::default();

    assert!(filter.meta_role_id.is_none());
    assert!(filter.event_type.is_none());
    assert!(filter.actor_id.is_none());
    assert!(filter.from_date.is_none());
    assert!(filter.to_date.is_none());
}

#[test]
fn test_event_filter_by_meta_role() {
    let meta_role_id = Uuid::new_v4();

    let filter = MetaRoleEventFilter {
        meta_role_id: Some(meta_role_id),
        event_type: None,
        actor_id: None,
        from_date: None,
        to_date: None,
    };

    assert_eq!(filter.meta_role_id, Some(meta_role_id));
}

#[test]
fn test_event_filter_by_event_type() {
    let filter = MetaRoleEventFilter {
        meta_role_id: None,
        event_type: Some(MetaRoleEventType::ConflictDetected),
        actor_id: None,
        from_date: None,
        to_date: None,
    };

    assert_eq!(filter.event_type, Some(MetaRoleEventType::ConflictDetected));
}

#[test]
fn test_event_filter_by_actor() {
    let actor_id = Uuid::new_v4();

    let filter = MetaRoleEventFilter {
        meta_role_id: None,
        event_type: None,
        actor_id: Some(actor_id),
        from_date: None,
        to_date: None,
    };

    assert_eq!(filter.actor_id, Some(actor_id));
}

#[test]
fn test_event_filter_by_date_range() {
    let from_date = Utc::now() - Duration::days(7);
    let to_date = Utc::now();

    let filter = MetaRoleEventFilter {
        meta_role_id: None,
        event_type: None,
        actor_id: None,
        from_date: Some(from_date),
        to_date: Some(to_date),
    };

    assert!(filter.from_date.is_some());
    assert!(filter.to_date.is_some());
    assert!(filter.from_date.unwrap() < filter.to_date.unwrap());
}

#[test]
fn test_event_filter_combined() {
    let meta_role_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let from_date = Utc::now() - Duration::hours(24);

    let filter = MetaRoleEventFilter {
        meta_role_id: Some(meta_role_id),
        event_type: Some(MetaRoleEventType::Updated),
        actor_id: Some(actor_id),
        from_date: Some(from_date),
        to_date: None,
    };

    assert!(filter.meta_role_id.is_some());
    assert!(filter.event_type.is_some());
    assert!(filter.actor_id.is_some());
    assert!(filter.from_date.is_some());
}

// ============================================================================
// Event Statistics Tests
// ============================================================================

#[test]
fn test_event_stats_structure() {
    let stats = MetaRoleEventStats {
        total: 100,
        created: 10,
        updated: 25,
        deleted: 5,
        disabled: 3,
        enabled: 2,
        inheritance_applied: 30,
        inheritance_removed: 8,
        conflict_detected: 7,
        conflict_resolved: 5,
        cascade_started: 3,
        cascade_completed: 2,
        cascade_failed: 0,
    };

    // Verify sum consistency (a helpful invariant check)
    let sum = stats.created
        + stats.updated
        + stats.deleted
        + stats.disabled
        + stats.enabled
        + stats.inheritance_applied
        + stats.inheritance_removed
        + stats.conflict_detected
        + stats.conflict_resolved
        + stats.cascade_started
        + stats.cascade_completed
        + stats.cascade_failed;

    assert_eq!(sum, stats.total);
}

#[test]
fn test_event_stats_empty() {
    let stats = MetaRoleEventStats {
        total: 0,
        created: 0,
        updated: 0,
        deleted: 0,
        disabled: 0,
        enabled: 0,
        inheritance_applied: 0,
        inheritance_removed: 0,
        conflict_detected: 0,
        conflict_resolved: 0,
        cascade_started: 0,
        cascade_completed: 0,
        cascade_failed: 0,
    };

    assert_eq!(stats.total, 0);
}

// ============================================================================
// Compliance / Audit Trail Tests
// ============================================================================

#[test]
fn test_audit_trail_actor_tracking() {
    // Verify user-initiated events have actor_id
    let actor_id = Uuid::new_v4();

    let user_event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::Updated,
        actor_id: Some(actor_id),
        changes: Some(json!({"before": {}, "after": {}})),
        affected_roles: None,
        metadata: None,
    };

    assert!(
        user_event.actor_id.is_some(),
        "User events must have actor_id"
    );
}

#[test]
fn test_audit_trail_system_events() {
    // Verify system events can have None actor
    let system_event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::InheritanceApplied,
        actor_id: None, // System-triggered
        changes: None,
        affected_roles: Some(json!([Uuid::new_v4()])),
        metadata: Some(json!({"match_reason": "criteria_match"})),
    };

    assert!(
        system_event.actor_id.is_none(),
        "System events should not require actor_id"
    );
}

#[test]
fn test_audit_trail_complete_change_tracking() {
    // For updates, both before and after states should be captured
    let update_event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::Updated,
        actor_id: Some(Uuid::new_v4()),
        changes: Some(json!({
            "before": {"priority": 100, "status": "active"},
            "after": {"priority": 50, "status": "active"}
        })),
        affected_roles: None,
        metadata: None,
    };

    let changes = update_event.changes.unwrap();
    assert!(
        changes.get("before").is_some(),
        "Updates must track before state"
    );
    assert!(
        changes.get("after").is_some(),
        "Updates must track after state"
    );
}

#[test]
fn test_audit_trail_delete_preserves_state() {
    // Deletions should preserve the final state for compliance
    let delete_event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::Deleted,
        actor_id: Some(Uuid::new_v4()),
        changes: Some(json!({
            "before": {
                "id": Uuid::new_v4(),
                "name": "Deleted Policy",
                "description": "This policy was deleted",
                "priority": 100,
                "status": "disabled",
                "criteria": [],
                "entitlements": [],
                "constraints": []
            }
        })),
        affected_roles: Some(json!([Uuid::new_v4(), Uuid::new_v4()])),
        metadata: None,
    };

    let changes = delete_event.changes.unwrap();
    assert!(
        changes.get("before").is_some(),
        "Deletes must preserve before state"
    );
    assert!(
        delete_event.affected_roles.is_some(),
        "Deletes should list affected roles"
    );
}

#[test]
fn test_audit_trail_conflict_tracking() {
    // Conflict events must identify all parties
    let meta_role_a = Uuid::new_v4();
    let meta_role_b = Uuid::new_v4();
    let affected_role = Uuid::new_v4();

    let conflict_event = CreateGovMetaRoleEvent {
        meta_role_id: Some(meta_role_a),
        event_type: MetaRoleEventType::ConflictDetected,
        actor_id: None,
        changes: None,
        affected_roles: Some(json!([affected_role])),
        metadata: Some(json!({
            "meta_role_a_id": meta_role_a,
            "meta_role_b_id": meta_role_b,
            "conflict_type": "entitlement_conflict"
        })),
    };

    let metadata = conflict_event.metadata.unwrap();
    assert!(metadata.get("meta_role_a_id").is_some());
    assert!(metadata.get("meta_role_b_id").is_some());
    assert!(metadata.get("conflict_type").is_some());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_event_with_large_affected_roles_list() {
    let affected_roles: Vec<Uuid> = (0..1000).map(|_| Uuid::new_v4()).collect();

    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::CascadeCompleted,
        actor_id: None,
        changes: None,
        affected_roles: Some(json!(affected_roles)),
        metadata: Some(json!({"success_count": 1000})),
    };

    let roles = event.affected_roles.unwrap();
    assert_eq!(roles.as_array().unwrap().len(), 1000);
}

#[test]
fn test_event_with_complex_metadata() {
    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::CascadeCompleted,
        actor_id: None,
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "trigger": "constraint_modified",
            "batches": [
                {"batch_num": 1, "success": 100, "failed": 0},
                {"batch_num": 2, "success": 100, "failed": 0},
                {"batch_num": 3, "success": 50, "failed": 2}
            ],
            "errors": [
                {"role_id": Uuid::new_v4(), "error": "Role not found"},
                {"role_id": Uuid::new_v4(), "error": "Constraint conflict"}
            ],
            "timing": {
                "started_at": "2024-01-15T10:00:00Z",
                "completed_at": "2024-01-15T10:05:32Z",
                "duration_ms": 332000
            }
        })),
    };

    let metadata = event.metadata.unwrap();
    assert!(metadata.get("batches").unwrap().as_array().is_some());
    assert!(metadata.get("errors").unwrap().as_array().is_some());
    assert!(metadata.get("timing").is_some());
}

#[test]
fn test_event_serialization() {
    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::Updated,
        actor_id: Some(Uuid::new_v4()),
        changes: Some(json!({"test": true})),
        affected_roles: None,
        metadata: None,
    };

    // Should serialize without panic
    let json_str = serde_json::to_string(&event).unwrap();
    // Event type serializes as snake_case: "updated"
    assert!(json_str.contains("updated"));

    // Should deserialize back
    let parsed: CreateGovMetaRoleEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.event_type, MetaRoleEventType::Updated);
}

// ============================================================================
// IGA Comparison: Audit Requirements
// ============================================================================
// IGA tracks:
// 1. Object history with delta computation
// 2. Simulation previews before changes
// 3. Task-based execution tracking
// 4. Approvals and policy evaluations
//
// Our implementation covers:
// - Before/after state tracking (delta)
// - Cascade tracking (analogous to tasks)
// - Conflict detection/resolution
// - All CRUD operations
// ============================================================================

#[test]
#[allow(non_snake_case)]
fn test_IGA_parity_delta_tracking() {
    // IGA stores operation deltas - we do similar with before/after
    let event = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::Updated,
        actor_id: Some(Uuid::new_v4()),
        changes: Some(json!({
            "before": {"name": "Old", "priority": 100},
            "after": {"name": "New", "priority": 50}
        })),
        affected_roles: None,
        metadata: None,
    };

    // Verify we can compute diff from stored data
    let changes = event.changes.unwrap();
    let before = changes.get("before").unwrap();
    let after = changes.get("after").unwrap();

    // Priority changed
    assert_ne!(before.get("priority"), after.get("priority"));
    // Name changed
    assert_ne!(before.get("name"), after.get("name"));
}

#[test]
#[allow(non_snake_case)]
fn test_IGA_parity_cascade_tracking() {
    // IGA tracks task execution - we track cascade execution
    let started = CreateGovMetaRoleEvent {
        meta_role_id: Some(Uuid::new_v4()),
        event_type: MetaRoleEventType::CascadeStarted,
        actor_id: None,
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "trigger": "entitlement_added",
            "expected_count": 200
        })),
    };

    let completed = CreateGovMetaRoleEvent {
        meta_role_id: started.meta_role_id,
        event_type: MetaRoleEventType::CascadeCompleted,
        actor_id: None,
        changes: None,
        affected_roles: None,
        metadata: Some(json!({
            "success_count": 198,
            "failure_count": 2,
            "duration_ms": 15000
        })),
    };

    // Verify cascade pair can be correlated by meta_role_id
    assert_eq!(started.meta_role_id, completed.meta_role_id);
}
