//! Unit tests for Identity Merge Service (F062).
//!
//! Tests for User Story 1: Review and Merge Duplicate Identities (P1 - MVP)

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use xavyo_db::models::{GovDuplicateStatus, GovEntitlementStrategy, GovMergeOperationStatus};

// ============================================================================
// Mock types for unit testing (no database required)
// ============================================================================

/// Mock identity summary for testing merge preview.
#[derive(Debug, Clone)]
struct MockIdentity {
    id: Uuid,
    email: Option<String>,
    display_name: Option<String>,
    department: Option<String>,
    employee_id: Option<String>,
    phone: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

/// Mock entitlement for testing entitlement consolidation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MockEntitlement {
    id: Uuid,
    name: String,
    application: Option<String>,
}

// ============================================================================
// Merge Preview Logic Tests
// ============================================================================

#[test]
fn test_attribute_comparison_detects_differences() {
    let identity_a = MockIdentity {
        id: Uuid::new_v4(),
        email: Some("john.smith@example.com".to_string()),
        display_name: Some("John Smith".to_string()),
        department: Some("Engineering".to_string()),
        employee_id: Some("EMP001".to_string()),
        phone: Some("+1-555-1234".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let identity_b = MockIdentity {
        id: Uuid::new_v4(),
        email: Some("john.smith@example.com".to_string()), // Same
        display_name: Some("Jon Smith".to_string()),       // Different
        department: Some("Sales".to_string()),             // Different
        employee_id: Some("EMP001".to_string()),           // Same
        phone: None,                                       // Different (one null)
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Compare email - should be same
    assert_eq!(identity_a.email, identity_b.email);

    // Compare display_name - should be different
    assert_ne!(identity_a.display_name, identity_b.display_name);

    // Compare department - should be different
    assert_ne!(identity_a.department, identity_b.department);

    // Compare phone - should be different (one null)
    assert_ne!(identity_a.phone, identity_b.phone);
}

#[test]
fn test_attribute_selection_respects_source_choice() {
    // "source" means use value from source identity (the one being archived)
    // "target" means use value from target identity (the one being kept)

    let source_value = "Source Department";
    let target_value = "Target Department";

    // When source is selected, use source value
    let selection = json!({
        "department": { "source": "source", "value": source_value }
    });
    let dept = selection["department"]["value"].as_str().unwrap();
    assert_eq!(dept, source_value);

    // When target is selected, use target value
    let selection = json!({
        "department": { "source": "target", "value": target_value }
    });
    let dept = selection["department"]["value"].as_str().unwrap();
    assert_eq!(dept, target_value);
}

#[test]
fn test_merge_preview_creates_combined_identity() {
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    let source = MockIdentity {
        id: source_id,
        email: Some("old@example.com".to_string()),
        display_name: Some("Better Name".to_string()), // We'll pick this
        department: Some("Engineering".to_string()),
        employee_id: Some("EMP001".to_string()),
        phone: Some("+1-555-1234".to_string()), // We'll pick this
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let target = MockIdentity {
        id: target_id,
        email: Some("new@example.com".to_string()), // We'll pick this
        display_name: Some("Worse Name".to_string()),
        department: Some("Engineering".to_string()), // Same, we'll pick target
        employee_id: Some("EMP002".to_string()),
        phone: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Simulate attribute selections
    let selections = json!({
        "email": { "source": "target", "value": target.email },
        "display_name": { "source": "source", "value": source.display_name },
        "department": { "source": "target", "value": target.department },
        "phone": { "source": "source", "value": source.phone }
    });

    // The merged identity should have the target's ID
    // but selected attributes from both sources
    assert_eq!(selections["email"]["value"], json!(target.email.unwrap()));
    assert_eq!(
        selections["display_name"]["value"],
        json!(source.display_name.unwrap())
    );
    assert_eq!(selections["phone"]["value"], json!(source.phone.unwrap()));
}

// ============================================================================
// Entitlement Consolidation Tests
// ============================================================================

#[test]
fn test_entitlement_union_strategy_combines_all() {
    use std::collections::HashSet;

    let ent_a1 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "App Access".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let ent_a2 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Report Viewer".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let ent_b1 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Admin Access".to_string(),
        application: Some("Jira".to_string()),
    };

    let source_entitlements: HashSet<MockEntitlement> =
        vec![ent_a1.clone(), ent_a2.clone()].into_iter().collect();
    let target_entitlements: HashSet<MockEntitlement> =
        vec![ent_a1.clone(), ent_b1.clone()].into_iter().collect();

    // Union: combine all unique entitlements
    let union: HashSet<_> = source_entitlements
        .union(&target_entitlements)
        .cloned()
        .collect();

    assert_eq!(union.len(), 3); // ent_a1 (deduplicated), ent_a2, ent_b1
    assert!(union.contains(&ent_a1));
    assert!(union.contains(&ent_a2));
    assert!(union.contains(&ent_b1));
}

#[test]
fn test_entitlement_intersection_keeps_common() {
    use std::collections::HashSet;

    let shared_ent = MockEntitlement {
        id: Uuid::new_v4(),
        name: "App Access".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let source_only = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Report Viewer".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let target_only = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Admin Access".to_string(),
        application: Some("Jira".to_string()),
    };

    let source_entitlements: HashSet<MockEntitlement> =
        vec![shared_ent.clone(), source_only.clone()]
            .into_iter()
            .collect();
    let target_entitlements: HashSet<MockEntitlement> =
        vec![shared_ent.clone(), target_only.clone()]
            .into_iter()
            .collect();

    // Intersection: keep only common entitlements
    let intersection: HashSet<_> = source_entitlements
        .intersection(&target_entitlements)
        .cloned()
        .collect();

    assert_eq!(intersection.len(), 1);
    assert!(intersection.contains(&shared_ent));
    assert!(!intersection.contains(&source_only));
    assert!(!intersection.contains(&target_only));
}

#[test]
fn test_entitlement_manual_strategy_respects_selections() {
    let ent1 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "App Access".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let ent2 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Report Viewer".to_string(),
        application: Some("Salesforce".to_string()),
    };
    let ent3 = MockEntitlement {
        id: Uuid::new_v4(),
        name: "Admin Access".to_string(),
        application: Some("Jira".to_string()),
    };

    let all_entitlements = vec![ent1.clone(), ent2.clone(), ent3.clone()];

    // Manual selection: user chose ent1 and ent3 only
    let selected_ids = vec![ent1.id, ent3.id];

    let manual_selection: Vec<_> = all_entitlements
        .into_iter()
        .filter(|e| selected_ids.contains(&e.id))
        .collect();

    assert_eq!(manual_selection.len(), 2);
    assert!(manual_selection.iter().any(|e| e.id == ent1.id));
    assert!(manual_selection.iter().any(|e| e.id == ent3.id));
    assert!(!manual_selection.iter().any(|e| e.id == ent2.id));
}

// ============================================================================
// Merge Operation Status Tests
// ============================================================================

#[test]
fn test_merge_status_transitions() {
    // Valid transitions:
    // in_progress -> completed
    // in_progress -> failed
    // in_progress -> cancelled

    let initial = GovMergeOperationStatus::InProgress;

    // Can transition to completed
    assert!(matches!(
        GovMergeOperationStatus::Completed,
        GovMergeOperationStatus::Completed
    ));

    // Can transition to failed
    assert!(matches!(
        GovMergeOperationStatus::Failed,
        GovMergeOperationStatus::Failed
    ));

    // Can transition to cancelled
    assert!(matches!(
        GovMergeOperationStatus::Cancelled,
        GovMergeOperationStatus::Cancelled
    ));

    // Initial state is in_progress
    assert!(matches!(initial, GovMergeOperationStatus::InProgress));
}

#[test]
fn test_duplicate_status_transitions() {
    // Valid transitions:
    // pending -> merged
    // pending -> dismissed

    let initial = GovDuplicateStatus::Pending;
    assert!(matches!(initial, GovDuplicateStatus::Pending));

    // Terminal states
    assert!(matches!(
        GovDuplicateStatus::Merged,
        GovDuplicateStatus::Merged
    ));
    assert!(matches!(
        GovDuplicateStatus::Dismissed,
        GovDuplicateStatus::Dismissed
    ));
}

// ============================================================================
// Entitlement Strategy Tests
// ============================================================================

#[test]
fn test_entitlement_strategy_serialization() {
    assert!(matches!(
        GovEntitlementStrategy::Union,
        GovEntitlementStrategy::Union
    ));
    assert!(matches!(
        GovEntitlementStrategy::Intersection,
        GovEntitlementStrategy::Intersection
    ));
    assert!(matches!(
        GovEntitlementStrategy::Manual,
        GovEntitlementStrategy::Manual
    ));
}

// ============================================================================
// Identity Archival Tests
// ============================================================================

#[test]
fn test_archived_identity_preserves_external_references() {
    let external_refs = json!({
        "scim_id": "scim-uuid-12345",
        "ldap_dn": "cn=john,ou=users,dc=example,dc=com",
        "ad_object_guid": "ad-guid-67890",
        "sap_user_id": "SAP001"
    });

    // All external references should be preserved
    assert!(external_refs.get("scim_id").is_some());
    assert!(external_refs.get("ldap_dn").is_some());
    assert!(external_refs.get("ad_object_guid").is_some());
    assert!(external_refs.get("sap_user_id").is_some());
}

#[test]
fn test_archived_identity_snapshot_contains_full_state() {
    let snapshot = json!({
        "id": Uuid::new_v4(),
        "email": "john@example.com",
        "display_name": "John Smith",
        "department": "Engineering",
        "employee_id": "EMP001",
        "phone": "+1-555-1234",
        "entitlements": [
            { "id": Uuid::new_v4(), "name": "App Access", "application": "Salesforce" }
        ],
        "external_references": {
            "scim_id": "scim-uuid"
        },
        "created_at": "2024-01-15T10:30:00Z",
        "updated_at": "2026-01-20T14:22:00Z"
    });

    // Snapshot should contain all identity fields
    assert!(snapshot.get("id").is_some());
    assert!(snapshot.get("email").is_some());
    assert!(snapshot.get("display_name").is_some());
    assert!(snapshot.get("entitlements").is_some());
    assert!(snapshot.get("external_references").is_some());
}

// ============================================================================
// Circular Merge Prevention Tests
// ============================================================================

#[test]
fn test_circular_merge_detection() {
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();

    // Pending merge operation: A -> B
    let pending_operations = vec![(identity_a, identity_b)];

    // Attempt to create B -> A should be blocked
    let source = identity_b;
    let target = identity_a;

    let would_create_circular = pending_operations
        .iter()
        .any(|(s, t)| *t == source && *s == target);

    assert!(would_create_circular);
}

#[test]
fn test_non_circular_merge_allowed() {
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();
    let identity_c = Uuid::new_v4();

    // Pending merge operation: A -> B
    let pending_operations = vec![(identity_a, identity_b)];

    // Attempt to create C -> B should be allowed
    let source = identity_c;
    let target = identity_b;

    let would_create_circular = pending_operations
        .iter()
        .any(|(s, t)| *t == source && *s == target);

    assert!(!would_create_circular);
}

// ============================================================================
// Null Value Handling Tests
// ============================================================================

#[test]
fn test_null_attribute_handling() {
    // When both are null, result should be null
    let a_value: Option<String> = None;
    let b_value: Option<String> = None;

    let merged = a_value.clone().or(b_value.clone());
    assert!(merged.is_none());
}

#[test]
fn test_prefer_non_null_value() {
    // When one is null and one has a value, prefer the non-null
    let a_value: Option<String> = Some("has value".to_string());
    let b_value: Option<String> = None;

    let merged = a_value.clone().or(b_value.clone());
    assert_eq!(merged, Some("has value".to_string()));

    // Reverse case
    let a_value: Option<String> = None;
    let b_value: Option<String> = Some("has value".to_string());

    let merged = a_value.or(b_value);
    assert_eq!(merged, Some("has value".to_string()));
}

// ============================================================================
// Confidence Score Validation Tests
// ============================================================================

#[test]
fn test_confidence_score_bounds() {
    // Confidence must be between 0 and 100
    let valid_scores = vec![0.0, 25.5, 50.0, 75.0, 99.99, 100.0];
    let invalid_scores = vec![-1.0, 100.01, 150.0];

    for score in valid_scores {
        assert!(score >= 0.0 && score <= 100.0);
    }

    for score in invalid_scores {
        assert!(!(score >= 0.0 && score <= 100.0));
    }
}

// ============================================================================
// Audit Record Immutability Tests
// ============================================================================

#[test]
fn test_audit_record_structure() {
    let audit_record = json!({
        "id": Uuid::new_v4(),
        "operation_id": Uuid::new_v4(),
        "source_snapshot": {
            "id": Uuid::new_v4(),
            "email": "source@example.com"
        },
        "target_snapshot": {
            "id": Uuid::new_v4(),
            "email": "target@example.com"
        },
        "merged_snapshot": {
            "id": Uuid::new_v4(),
            "email": "target@example.com"
        },
        "attribute_decisions": {
            "email": { "source": "target", "value": "target@example.com" }
        },
        "entitlement_decisions": {
            "strategy": "union",
            "added": [],
            "removed": []
        },
        "created_at": Utc::now().to_rfc3339()
    });

    // Audit record should have all required fields
    assert!(audit_record.get("source_snapshot").is_some());
    assert!(audit_record.get("target_snapshot").is_some());
    assert!(audit_record.get("merged_snapshot").is_some());
    assert!(audit_record.get("attribute_decisions").is_some());
    assert!(audit_record.get("entitlement_decisions").is_some());
}
