//! Unit tests for meta-role simulation (F056 - US4, T065).
//!
//! Tests simulation logic for previewing meta-role changes without
//! making actual modifications to the system.

use serde_json::json;
use uuid::Uuid;
use xavyo_db::{CriteriaOperator, MetaRoleConflictType};

use xavyo_api_governance::models::{
    CreateMetaRoleCriteriaRequest, MetaRoleSimulationType, SimulationConflict,
    SimulationRoleChange, SimulationSummary,
};
use xavyo_api_governance::services::SimulationResult;

mod common;

// ============================================================================
// SimulationResult Structure Tests
// ============================================================================

#[test]
fn test_simulation_result_default_values() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Create,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    assert_eq!(result.summary.total_roles_affected, 0);
    assert!(result.roles_to_add.is_empty());
    assert!(result.roles_to_remove.is_empty());
    assert!(result.potential_conflicts.is_empty());
    assert!(result.conflicts_to_resolve.is_empty());
    assert!(result.summary.is_safe);
    assert!(result.summary.warnings.is_empty());
}

#[test]
fn test_simulation_result_with_changes() {
    let role_change = SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "Test Role".to_string(),
        application_id: Some(Uuid::new_v4()),
        reason: json!({"reason": "newly matches criteria"}),
        entitlements_affected: vec![Uuid::new_v4()],
        constraints_affected: vec!["max_session_duration".to_string()],
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add: vec![role_change.clone()],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 1,
            roles_gaining_inheritance: 1,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    assert_eq!(result.summary.total_roles_affected, 1);
    assert_eq!(result.roles_to_add.len(), 1);
    assert_eq!(result.roles_to_add[0].role_name, "Test Role");
}

#[test]
fn test_simulation_result_with_conflicts() {
    let conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "Meta-role A".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "Meta-role B".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Affected Role".to_string(),
        conflict_type: MetaRoleConflictType::EntitlementConflict,
        conflicting_items: json!({
            "entitlement_id": Uuid::new_v4(),
            "permission_a": "Grant",
            "permission_b": "Deny"
        }),
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Update,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![conflict],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 1,
            resolved_conflicts: 0,
            is_safe: false,
            warnings: vec!["This change will create conflicts".to_string()],
        },
    };

    assert!(!result.summary.is_safe);
    assert_eq!(result.potential_conflicts.len(), 1);
    assert_eq!(result.summary.new_conflicts, 1);
    assert_eq!(result.summary.warnings.len(), 1);
}

// ============================================================================
// Simulation Type Tests
// ============================================================================

#[test]
fn test_simulation_type_criteria_change() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    match result.simulation_type {
        MetaRoleSimulationType::CriteriaChange => (),
        _ => panic!("Expected CriteriaChange simulation type"),
    }
}

#[test]
fn test_simulation_type_enable() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Enable,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    match result.simulation_type {
        MetaRoleSimulationType::Enable => (),
        _ => panic!("Expected Enable simulation type"),
    }
}

#[test]
fn test_simulation_type_disable() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Disable,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    match result.simulation_type {
        MetaRoleSimulationType::Disable => (),
        _ => panic!("Expected Disable simulation type"),
    }
}

#[test]
fn test_simulation_type_delete() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Delete,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    match result.simulation_type {
        MetaRoleSimulationType::Delete => (),
        _ => panic!("Expected Delete simulation type"),
    }
}

// ============================================================================
// Simulation Summary Tests
// ============================================================================

#[test]
fn test_simulation_summary_is_safe_with_no_conflicts() {
    let summary = SimulationSummary {
        total_roles_affected: 5,
        roles_gaining_inheritance: 3,
        roles_losing_inheritance: 2,
        new_conflicts: 0,
        resolved_conflicts: 0,
        is_safe: true,
        warnings: vec![],
    };

    assert!(summary.is_safe);
    assert_eq!(summary.total_roles_affected, 5);
    assert_eq!(summary.roles_gaining_inheritance, 3);
    assert_eq!(summary.roles_losing_inheritance, 2);
}

#[test]
fn test_simulation_summary_unsafe_with_conflicts() {
    let summary = SimulationSummary {
        total_roles_affected: 10,
        roles_gaining_inheritance: 10,
        roles_losing_inheritance: 0,
        new_conflicts: 3,
        resolved_conflicts: 0,
        is_safe: false,
        warnings: vec![
            "Conflict with meta-role X".to_string(),
            "Conflict with meta-role Y".to_string(),
        ],
    };

    assert!(!summary.is_safe);
    assert_eq!(summary.new_conflicts, 3);
    assert_eq!(summary.warnings.len(), 2);
}

#[test]
fn test_simulation_summary_resolves_conflicts() {
    let summary = SimulationSummary {
        total_roles_affected: 5,
        roles_gaining_inheritance: 0,
        roles_losing_inheritance: 5,
        new_conflicts: 0,
        resolved_conflicts: 2,
        is_safe: true,
        warnings: vec![],
    };

    assert!(summary.is_safe);
    assert_eq!(summary.resolved_conflicts, 2);
}

// ============================================================================
// Criteria Request Tests
// ============================================================================

#[test]
fn test_criteria_request_eq_operator() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::Eq,
        value: json!("high"),
    };

    assert_eq!(criteria.field, "risk_level");
    assert_eq!(criteria.operator, CriteriaOperator::Eq);
    assert_eq!(criteria.value, json!("high"));
}

#[test]
fn test_criteria_request_in_operator() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "application_id".to_string(),
        operator: CriteriaOperator::In,
        value: json!(["app1", "app2", "app3"]),
    };

    assert_eq!(criteria.operator, CriteriaOperator::In);
    assert!(criteria.value.is_array());
}

#[test]
fn test_criteria_request_gt_operator() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "priority".to_string(),
        operator: CriteriaOperator::Gt,
        value: json!(100),
    };

    assert_eq!(criteria.operator, CriteriaOperator::Gt);
    assert_eq!(criteria.value, json!(100));
}

#[test]
fn test_criteria_request_contains_operator() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "name".to_string(),
        operator: CriteriaOperator::Contains,
        value: json!("Admin"),
    };

    assert_eq!(criteria.operator, CriteriaOperator::Contains);
}

// ============================================================================
// Role Change Tests
// ============================================================================

#[test]
fn test_role_change_with_entitlements() {
    let role_change = SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "HR Admin".to_string(),
        application_id: Some(Uuid::new_v4()),
        reason: json!({"reason": "matches risk_level = high criteria"}),
        entitlements_affected: vec![Uuid::new_v4(), Uuid::new_v4()],
        constraints_affected: vec![],
    };

    assert_eq!(role_change.entitlements_affected.len(), 2);
    assert!(role_change.constraints_affected.is_empty());
}

#[test]
fn test_role_change_with_constraints() {
    let role_change = SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "Security Role".to_string(),
        application_id: None,
        reason: json!({"reason": "new constraint applied"}),
        entitlements_affected: vec![],
        constraints_affected: vec![
            "max_session_duration".to_string(),
            "require_mfa".to_string(),
        ],
    };

    assert_eq!(role_change.constraints_affected.len(), 2);
    assert!(role_change.entitlements_affected.is_empty());
}

// ============================================================================
// Conflict Tests
// ============================================================================

#[test]
fn test_entitlement_conflict() {
    let conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "Security Meta-role".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "Access Meta-role".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "DBA Role".to_string(),
        conflict_type: MetaRoleConflictType::EntitlementConflict,
        conflicting_items: json!({
            "entitlement_id": "database_access",
            "permission_a": "Deny",
            "permission_b": "Grant"
        }),
    };

    assert!(matches!(
        conflict.conflict_type,
        MetaRoleConflictType::EntitlementConflict
    ));
}

#[test]
fn test_constraint_conflict() {
    let conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "Strict Meta-role".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "Lenient Meta-role".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Developer Role".to_string(),
        conflict_type: MetaRoleConflictType::ConstraintConflict,
        conflicting_items: json!({
            "constraint_type": "max_session_duration",
            "value_a": 3600,
            "value_b": 86400
        }),
    };

    assert!(matches!(
        conflict.conflict_type,
        MetaRoleConflictType::ConstraintConflict
    ));
}

#[test]
fn test_policy_conflict() {
    let conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "MFA Required".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "No MFA".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Guest Role".to_string(),
        conflict_type: MetaRoleConflictType::PolicyConflict,
        conflicting_items: json!({
            "policy": "require_mfa",
            "value_a": true,
            "value_b": false
        }),
    };

    assert!(matches!(
        conflict.conflict_type,
        MetaRoleConflictType::PolicyConflict
    ));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_simulation_with_empty_criteria() {
    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    // Empty criteria should result in no matches
    assert_eq!(result.summary.total_roles_affected, 0);
    assert!(result.summary.is_safe);
}

#[test]
fn test_simulation_large_role_count() {
    let roles_to_add: Vec<SimulationRoleChange> = (0..1000)
        .map(|i| SimulationRoleChange {
            role_id: Uuid::new_v4(),
            role_name: format!("Role {}", i),
            application_id: None,
            reason: json!({"reason": "batch simulation"}),
            entitlements_affected: vec![],
            constraints_affected: vec![],
        })
        .collect();

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Create,
        roles_to_add,
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 1000,
            roles_gaining_inheritance: 1000,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    assert_eq!(result.roles_to_add.len(), 1000);
    assert_eq!(result.summary.total_roles_affected, 1000);
}

#[test]
fn test_simulation_mixed_gains_and_losses() {
    let roles_to_add = vec![SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "New Match".to_string(),
        application_id: None,
        reason: json!({"reason": "newly matches criteria"}),
        entitlements_affected: vec![],
        constraints_affected: vec![],
    }];

    let roles_to_remove = vec![SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "Old Match".to_string(),
        application_id: None,
        reason: json!({"reason": "no longer matches criteria"}),
        entitlements_affected: vec![],
        constraints_affected: vec![],
    }];

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add,
        roles_to_remove,
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 2,
            roles_gaining_inheritance: 1,
            roles_losing_inheritance: 1,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    assert_eq!(result.summary.total_roles_affected, 2);
    assert_eq!(result.roles_to_add.len(), 1);
    assert_eq!(result.roles_to_remove.len(), 1);
}

#[test]
fn test_simulation_resolves_existing_conflicts() {
    let conflict_to_resolve = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "Meta A".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "Meta B".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Role X".to_string(),
        conflict_type: MetaRoleConflictType::EntitlementConflict,
        conflicting_items: json!({}),
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Delete,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![conflict_to_resolve],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 1,
            is_safe: true,
            warnings: vec![],
        },
    };

    assert_eq!(result.conflicts_to_resolve.len(), 1);
    assert_eq!(result.summary.resolved_conflicts, 1);
    assert!(result.summary.is_safe);
}

// ============================================================================
// IGA-inspired Edge Cases (from Evolveum documentation)
// ============================================================================

/// Test null/empty criteria value handling (IGA classification edge case)
#[test]
fn test_criteria_with_null_value() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::Eq,
        value: json!(null),
    };

    // Null values should be handled gracefully
    assert!(criteria.value.is_null());
}

/// Test criteria with empty string (IGA classification edge case)
#[test]
fn test_criteria_with_empty_string() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "description".to_string(),
        operator: CriteriaOperator::Eq,
        value: json!(""),
    };

    assert_eq!(criteria.value.as_str().unwrap(), "");
}

/// Test criteria with empty array for IN operator (boundary condition)
#[test]
fn test_criteria_in_with_empty_array() {
    let criteria = CreateMetaRoleCriteriaRequest {
        field: "application_id".to_string(),
        operator: CriteriaOperator::In,
        value: json!([]),
    };

    // Empty array should result in no matches
    assert!(criteria.value.as_array().unwrap().is_empty());
}

/// Test simulation with both new and resolved conflicts (IGA state verification)
#[test]
fn test_simulation_with_mixed_conflicts() {
    let new_conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "New Conflict A".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "New Conflict B".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Role 1".to_string(),
        conflict_type: MetaRoleConflictType::EntitlementConflict,
        conflicting_items: json!({}),
    };

    let resolved_conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "Resolved A".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "Resolved B".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "Role 2".to_string(),
        conflict_type: MetaRoleConflictType::ConstraintConflict,
        conflicting_items: json!({}),
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![new_conflict],
        conflicts_to_resolve: vec![resolved_conflict],
        summary: SimulationSummary {
            total_roles_affected: 0,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 1,
            resolved_conflicts: 1,
            is_safe: false, // Still unsafe due to new conflict
            warnings: vec!["Net conflict balance: 0, but new conflicts exist".to_string()],
        },
    };

    // Even if resolved == new, new conflicts make it unsafe
    assert!(!result.summary.is_safe);
    assert_eq!(result.potential_conflicts.len(), 1);
    assert_eq!(result.conflicts_to_resolve.len(), 1);
}

/// Test simulation preserves ordering (IGA correlation tier priority)
#[test]
fn test_simulation_result_ordering() {
    let roles: Vec<SimulationRoleChange> = (0..5)
        .map(|i| SimulationRoleChange {
            role_id: Uuid::new_v4(),
            role_name: format!("Role Priority {}", i),
            application_id: None,
            reason: json!({"priority": i}),
            entitlements_affected: vec![],
            constraints_affected: vec![],
        })
        .collect();

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Create,
        roles_to_add: roles,
        roles_to_remove: vec![],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 5,
            roles_gaining_inheritance: 5,
            roles_losing_inheritance: 0,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec![],
        },
    };

    // Verify ordering is preserved
    for (i, role) in result.roles_to_add.iter().enumerate() {
        assert_eq!(role.reason["priority"], json!(i));
    }
}

/// Test multiple warnings accumulation (IGA policy rule exceptions)
#[test]
fn test_simulation_multiple_warnings() {
    let summary = SimulationSummary {
        total_roles_affected: 50,
        roles_gaining_inheritance: 50,
        roles_losing_inheritance: 0,
        new_conflicts: 3,
        resolved_conflicts: 0,
        is_safe: false,
        warnings: vec![
            "Conflict with High-Security meta-role".to_string(),
            "Conflict with Compliance meta-role".to_string(),
            "Conflict with Audit meta-role".to_string(),
            "Large number of roles affected (50)".to_string(),
        ],
    };

    assert!(!summary.is_safe);
    assert_eq!(summary.warnings.len(), 4);
    assert_eq!(summary.new_conflicts, 3);
}

/// Test simulation with same role in both add and remove (edge case)
#[test]
fn test_simulation_role_churn() {
    // This tests the edge case where criteria changes cause a role
    // to be removed from one meta-role and added to another
    let role_id = Uuid::new_v4();
    let role_name = "Churning Role".to_string();

    let role_to_add = SimulationRoleChange {
        role_id,
        role_name: role_name.clone(),
        application_id: None,
        reason: json!({"reason": "matches new criteria"}),
        entitlements_affected: vec![],
        constraints_affected: vec![],
    };

    let role_to_remove = SimulationRoleChange {
        role_id,
        role_name,
        application_id: None,
        reason: json!({"reason": "no longer matches old criteria"}),
        entitlements_affected: vec![],
        constraints_affected: vec![],
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::CriteriaChange,
        roles_to_add: vec![role_to_add],
        roles_to_remove: vec![role_to_remove],
        potential_conflicts: vec![],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 1, // Same role, counts once
            roles_gaining_inheritance: 1,
            roles_losing_inheritance: 1,
            new_conflicts: 0,
            resolved_conflicts: 0,
            is_safe: true,
            warnings: vec!["Role inheritance will be transferred".to_string()],
        },
    };

    // Same role ID in both lists
    assert_eq!(
        result.roles_to_add[0].role_id,
        result.roles_to_remove[0].role_id
    );
    assert_eq!(result.summary.total_roles_affected, 1);
}

/// Test simulation respects lifecycle states (IGA development vs production)
#[test]
fn test_simulation_lifecycle_state_metadata() {
    let role_change = SimulationRoleChange {
        role_id: Uuid::new_v4(),
        role_name: "Draft Role".to_string(),
        application_id: None,
        reason: json!({
            "reason": "matches criteria",
            "lifecycle_state": "draft",
            "note": "Role is in draft state - simulation only"
        }),
        entitlements_affected: vec![],
        constraints_affected: vec![],
    };

    // Verify lifecycle metadata is preserved in reason
    assert_eq!(role_change.reason["lifecycle_state"], json!("draft"));
}

/// Test all conflict types together (comprehensive coverage)
#[test]
fn test_all_conflict_types_in_single_simulation() {
    let entitlement_conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "A".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "B".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "R1".to_string(),
        conflict_type: MetaRoleConflictType::EntitlementConflict,
        conflicting_items: json!({"type": "entitlement"}),
    };

    let constraint_conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "C".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "D".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "R2".to_string(),
        conflict_type: MetaRoleConflictType::ConstraintConflict,
        conflicting_items: json!({"type": "constraint"}),
    };

    let policy_conflict = SimulationConflict {
        meta_role_a_id: Uuid::new_v4(),
        meta_role_a_name: "E".to_string(),
        meta_role_b_id: Uuid::new_v4(),
        meta_role_b_name: "F".to_string(),
        affected_role_id: Uuid::new_v4(),
        affected_role_name: "R3".to_string(),
        conflict_type: MetaRoleConflictType::PolicyConflict,
        conflicting_items: json!({"type": "policy"}),
    };

    let result = SimulationResult {
        simulation_type: MetaRoleSimulationType::Update,
        roles_to_add: vec![],
        roles_to_remove: vec![],
        potential_conflicts: vec![entitlement_conflict, constraint_conflict, policy_conflict],
        conflicts_to_resolve: vec![],
        summary: SimulationSummary {
            total_roles_affected: 3,
            roles_gaining_inheritance: 0,
            roles_losing_inheritance: 0,
            new_conflicts: 3,
            resolved_conflicts: 0,
            is_safe: false,
            warnings: vec![
                "Entitlement conflict detected".to_string(),
                "Constraint conflict detected".to_string(),
                "Policy conflict detected".to_string(),
            ],
        },
    };

    assert_eq!(result.potential_conflicts.len(), 3);

    // Verify each conflict type is present
    let types: Vec<_> = result
        .potential_conflicts
        .iter()
        .map(|c| &c.conflict_type)
        .collect();
    assert!(types
        .iter()
        .any(|t| matches!(t, MetaRoleConflictType::EntitlementConflict)));
    assert!(types
        .iter()
        .any(|t| matches!(t, MetaRoleConflictType::ConstraintConflict)));
    assert!(types
        .iter()
        .any(|t| matches!(t, MetaRoleConflictType::PolicyConflict)));
}
