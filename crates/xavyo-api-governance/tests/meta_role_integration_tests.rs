//! Integration tests for meta-role creation and auto-application (F056 - T020).
//!
//! Tests end-to-end scenarios including:
//! - Creating meta-roles and having them auto-apply to matching roles
//! - Inheritance lifecycle (create, suspend, reactivate, remove)
//! - Re-evaluation when roles change
//! - Bulk operations

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_governance::services::{MetaRoleMatchingService, MetaRoleService};
use xavyo_db::{
    CreateGovMetaRole, CreateGovMetaRoleConstraint, CreateGovMetaRoleCriteria,
    CreateGovMetaRoleEntitlement, CriteriaLogic, CriteriaOperator, InheritanceStatus,
    PermissionType,
};

// =========================================================================
// Auto-application on Meta-role Creation
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_meta_role_auto_applies_to_existing_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create 5 high-risk roles before creating meta-role
    let mut high_risk_roles = Vec::new();
    for _ in 0..5 {
        let role_id =
            create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
        high_risk_roles.push(role_id);
    }

    // Create 3 low-risk roles
    for _ in 0..3 {
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;
    }

    // Create meta-role matching high-risk
    let service = MetaRoleService::new(pool.clone());
    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let input = CreateGovMetaRole {
        name: "High Risk Security Policy".to_string(),
        description: Some("Auto-applies MFA and audit logging to high-risk roles".to_string()),
        priority: Some(10),
        criteria_logic: Some(CriteriaLogic::And),
    };

    let criteria = vec![CreateGovMetaRoleCriteria {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::Eq,
        value: serde_json::json!("High"),
    }];

    let meta_role = service
        .create(tenant_id, user_id, input, criteria)
        .await
        .unwrap();

    // Now manually trigger re-evaluation (auto-apply)
    let (added, removed) = matching_service
        .reevaluate_meta_role(tenant_id, meta_role.id)
        .await
        .unwrap();

    assert_eq!(added, 5, "Should have applied to 5 high-risk roles");
    assert_eq!(removed, 0, "No removals expected");

    // Verify inheritances exist
    let inheritances = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            meta_role.id,
            Some(InheritanceStatus::Active),
            100,
            0,
        )
        .await
        .unwrap();

    assert_eq!(inheritances.len(), 5);

    // All should be for high-risk roles
    for inh in &inheritances {
        assert!(high_risk_roles.contains(&inh.child_role_id));
    }

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Inheritance Lifecycle Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_inheritance_is_created_on_apply() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Test Apply", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply inheritance
    let match_reason = serde_json::json!({"test": true});
    let inheritance = matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, match_reason.clone())
        .await
        .unwrap();

    assert_eq!(inheritance.meta_role_id, meta_role_id);
    assert_eq!(inheritance.child_role_id, role_id);
    assert_eq!(inheritance.status, InheritanceStatus::Active);
    assert_eq!(inheritance.match_reason, match_reason);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_inheritance_idempotent_apply() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Idempotent", 100).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply twice
    let first = matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();

    let second = matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();

    // Should return same inheritance (idempotent)
    assert_eq!(first.id, second.id);

    // Should only have one inheritance
    let inheritances = matching_service
        .list_inheritances_by_meta_role(tenant_id, meta_role_id, None, 100, 0)
        .await
        .unwrap();

    assert_eq!(inheritances.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_inheritance_remove_and_reapply() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Remove Reapply", 100).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply
    let inheritance = matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();

    // Remove
    let removed = matching_service
        .remove_inheritance(tenant_id, inheritance.id)
        .await
        .unwrap();
    assert_eq!(removed.status, InheritanceStatus::Removed);

    // Re-apply should reactivate
    let reapplied = matching_service
        .apply_inheritance(
            tenant_id,
            meta_role_id,
            role_id,
            serde_json::json!({"reapplied": true}),
        )
        .await
        .unwrap();

    assert_eq!(reapplied.id, inheritance.id); // Same ID
    assert_eq!(reapplied.status, InheritanceStatus::Active);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disable_meta_role_suspends_inheritances() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create roles and meta-role with inheritances
    let role1 = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let role2 = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "To Disable", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply to both roles
    matching_service
        .apply_inheritance(tenant_id, meta_role_id, role1, serde_json::json!({}))
        .await
        .unwrap();
    matching_service
        .apply_inheritance(tenant_id, meta_role_id, role2, serde_json::json!({}))
        .await
        .unwrap();

    // Disable meta-role
    let service = MetaRoleService::new(pool.clone());
    service
        .disable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();

    // Inheritances should be suspended
    let active = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            100,
            0,
        )
        .await
        .unwrap();

    let suspended = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Suspended),
            100,
            0,
        )
        .await
        .unwrap();

    assert_eq!(active.len(), 0, "No active inheritances after disable");
    assert_eq!(suspended.len(), 2, "Both inheritances should be suspended");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_enable_meta_role_reactivates_inheritances() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Disable Enable", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());
    let service = MetaRoleService::new(pool.clone());

    // Apply, disable, then enable
    matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();
    service
        .disable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();
    service
        .enable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();

    // Inheritances should be active again
    let active = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            100,
            0,
        )
        .await
        .unwrap();

    assert_eq!(active.len(), 1, "Inheritance should be reactivated");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Re-evaluation Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_reevaluate_removes_no_longer_matching() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role matching specific app
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "App Specific", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "application_id",
        "eq",
        serde_json::json!(app_id.to_string()),
    )
    .await;

    // Create role in matching app
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply inheritance
    matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();

    // Now change the criteria to match a different app
    let other_app_id = create_test_application(&pool, tenant_id).await;

    // Delete old criterion and add new one
    let service = MetaRoleService::new(pool.clone());
    let criteria = service
        .list_criteria(tenant_id, meta_role_id)
        .await
        .unwrap();
    for c in criteria {
        service
            .remove_criterion(tenant_id, meta_role_id, c.id)
            .await
            .unwrap();
    }
    service
        .add_criterion(
            tenant_id,
            meta_role_id,
            CreateGovMetaRoleCriteria {
                field: "application_id".to_string(),
                operator: CriteriaOperator::Eq,
                value: serde_json::json!(other_app_id.to_string()),
            },
        )
        .await
        .unwrap();

    // Re-evaluate
    let (added, removed) = matching_service
        .reevaluate_meta_role(tenant_id, meta_role_id)
        .await
        .unwrap();

    assert_eq!(added, 0, "No new matches");
    assert_eq!(
        removed, 1,
        "Should remove inheritance that no longer matches"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_reevaluate_all_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create multiple meta-roles
    let high_risk_meta = create_test_meta_role(&pool, tenant_id, user_id, "High Risk", 10).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        high_risk_meta,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let critical_risk_meta =
        create_test_meta_role(&pool, tenant_id, user_id, "Critical Risk", 5).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        critical_risk_meta,
        "risk_level",
        "eq",
        serde_json::json!("Critical"),
    )
    .await;

    // Create roles
    create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "critical").await;
    create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Re-evaluate all roles against all meta-roles
    let (added, removed) = matching_service
        .reevaluate_all_roles(tenant_id)
        .await
        .unwrap();

    // 2 high-risk roles + 1 critical role = 3 inheritances
    assert_eq!(added, 3);
    assert_eq!(removed, 0);

    // Verify distributions
    let high_inh = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            high_risk_meta,
            Some(InheritanceStatus::Active),
            100,
            0,
        )
        .await
        .unwrap();
    let critical_inh = matching_service
        .list_inheritances_by_meta_role(
            tenant_id,
            critical_risk_meta,
            Some(InheritanceStatus::Active),
            100,
            0,
        )
        .await
        .unwrap();

    assert_eq!(high_inh.len(), 2);
    assert_eq!(critical_inh.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// List by Child Role Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_meta_roles_for_specific_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create role that will match multiple meta-roles
    let role_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;

    // Create multiple meta-roles matching different criteria
    let meta1 = create_test_meta_role(&pool, tenant_id, user_id, "Risk Policy", 10).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta1,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let meta2 = create_test_meta_role(&pool, tenant_id, user_id, "Owner Policy", 20).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta2,
        "owner_id",
        "eq",
        serde_json::json!(user_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Apply both
    matching_service
        .apply_inheritance(tenant_id, meta1, role_id, serde_json::json!({}))
        .await
        .unwrap();
    matching_service
        .apply_inheritance(tenant_id, meta2, role_id, serde_json::json!({}))
        .await
        .unwrap();

    // List by child role
    let inheritances = matching_service
        .list_inheritances_by_child_role(tenant_id, role_id, Some(InheritanceStatus::Active))
        .await
        .unwrap();

    assert_eq!(inheritances.len(), 2);
    let meta_role_ids: Vec<Uuid> = inheritances.iter().map(|i| i.meta_role_id).collect();
    assert!(meta_role_ids.contains(&meta1));
    assert!(meta_role_ids.contains(&meta2));

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Entitlement and Constraint Inheritance Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_meta_role_with_entitlements_and_constraints() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create additional entitlements to grant via meta-role
    let audit_entitlement = create_test_entitlement(&pool, tenant_id, app_id, None).await;
    let mfa_entitlement = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role with entitlements and constraints
    let service = MetaRoleService::new(pool.clone());
    let input = CreateGovMetaRole {
        name: "Security Policy".to_string(),
        description: None,
        priority: Some(10),
        criteria_logic: Some(CriteriaLogic::And),
    };

    let criteria = vec![CreateGovMetaRoleCriteria {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::Eq,
        value: serde_json::json!("High"),
    }];

    let meta_role = service
        .create(tenant_id, user_id, input, criteria)
        .await
        .unwrap();

    // Add entitlements to meta-role
    service
        .add_entitlement(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleEntitlement {
                entitlement_id: audit_entitlement,
                permission_type: Some(PermissionType::Grant),
            },
        )
        .await
        .unwrap();

    service
        .add_entitlement(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleEntitlement {
                entitlement_id: mfa_entitlement,
                permission_type: Some(PermissionType::Grant),
            },
        )
        .await
        .unwrap();

    // Add constraints
    service
        .add_constraint(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleConstraint {
                constraint_type: "require_mfa".to_string(),
                constraint_value: serde_json::json!(true),
            },
        )
        .await
        .unwrap();

    service
        .add_constraint(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleConstraint {
                constraint_type: "max_session_duration".to_string(),
                constraint_value: serde_json::json!(3600),
            },
        )
        .await
        .unwrap();

    // Verify meta-role has correct setup
    let entitlements = service
        .list_entitlements(tenant_id, meta_role.id)
        .await
        .unwrap();
    let constraints = service
        .list_constraints(tenant_id, meta_role.id)
        .await
        .unwrap();

    assert_eq!(entitlements.len(), 2);
    assert_eq!(constraints.len(), 2);

    // Verify constraint types
    let constraint_types: Vec<&str> = constraints
        .iter()
        .map(|c| c.constraint_type.as_str())
        .collect();
    assert!(constraint_types.contains(&"require_mfa"));
    assert!(constraint_types.contains(&"max_session_duration"));

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Tenant Isolation Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_meta_roles_are_tenant_isolated() {
    let pool = create_test_pool().await;

    let tenant1 = create_test_tenant(&pool).await;
    let tenant2 = create_test_tenant(&pool).await;

    let user1 = create_test_user(&pool, tenant1).await;
    let _user2 = create_test_user(&pool, tenant2).await;

    let app1 = create_test_application(&pool, tenant1).await;
    let app2 = create_test_application(&pool, tenant2).await;

    // Create roles in each tenant
    let role1 = create_test_entitlement_with_risk(&pool, tenant1, app1, None, "high").await;
    let role2 = create_test_entitlement_with_risk(&pool, tenant2, app2, None, "high").await;

    // Create meta-role in tenant1
    let meta_role1 = create_test_meta_role(&pool, tenant1, user1, "Tenant1 Policy", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant1,
        meta_role1,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Evaluate role in tenant1 - should match
    let result = matching_service
        .evaluate_role_matches(tenant1, role1)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    // Evaluate role in tenant2 - should not match (different tenant)
    let result = matching_service
        .evaluate_role_matches(tenant2, role2)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        0,
        "Tenant2 role should not match tenant1 meta-role"
    );

    cleanup_meta_role_data(&pool, tenant1).await;
    cleanup_meta_role_data(&pool, tenant2).await;
    cleanup_test_tenant(&pool, tenant1).await;
    cleanup_test_tenant(&pool, tenant2).await;
}

// =========================================================================
// Audit Event Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_inheritance_creates_audit_events() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Audit Events", 100).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());
    let service = MetaRoleService::new(pool.clone());

    // Apply inheritance
    matching_service
        .apply_inheritance(tenant_id, meta_role_id, role_id, serde_json::json!({}))
        .await
        .unwrap();

    // Check for audit events
    let events = service
        .list_events(tenant_id, meta_role_id, 100, 0)
        .await
        .unwrap();

    // Should have at least an InheritanceApplied event
    let inheritance_event = events
        .iter()
        .find(|e| format!("{:?}", e.event_type).contains("InheritanceApplied"));

    assert!(
        inheritance_event.is_some(),
        "Should have InheritanceApplied audit event"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Edge Cases from IGA standards Research
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_fr013_meta_roles_only_apply_to_regular_roles() {
    // FR-013: Meta-roles ONLY apply to regular roles, NOT to other meta-roles
    // This prevents circular inheritance chains
    // Note: The matching service evaluates against gov_entitlements (regular roles),
    // not against gov_meta_roles, so this is inherently satisfied by design.

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create parent meta-role
    let _parent_meta = create_test_meta_role(&pool, tenant_id, user_id, "Parent Meta", 10).await;

    // Create child meta-role
    let child_meta = create_test_meta_role(&pool, tenant_id, user_id, "Child Meta", 20).await;

    // The matching service only queries gov_entitlements, not gov_meta_roles
    // So parent_meta cannot match child_meta by design

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Try to evaluate - this should fail because child_meta is not a role
    let result = matching_service
        .evaluate_role_matches(tenant_id, child_meta)
        .await;

    // Should return NotFound because child_meta is not in gov_entitlements
    assert!(
        result.is_err(),
        "Should not find meta-role as a regular role"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_priority_determines_precedence() {
    // In case of conflicts, lower priority number wins (higher precedence)
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create meta-roles with different priorities
    let low_priority =
        create_test_meta_role(&pool, tenant_id, user_id, "Low Priority (100)", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        low_priority,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let high_priority =
        create_test_meta_role(&pool, tenant_id, user_id, "High Priority (10)", 10).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        high_priority,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let medium_priority =
        create_test_meta_role(&pool, tenant_id, user_id, "Medium Priority (50)", 50).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        medium_priority,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();

    assert_eq!(result.matching_meta_roles.len(), 3);

    // Verify ordering: 10, 50, 100
    assert_eq!(result.matching_meta_roles[0].priority, 10);
    assert_eq!(result.matching_meta_roles[1].priority, 50);
    assert_eq!(result.matching_meta_roles[2].priority, 100);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_large_scale_matching() {
    // Test with many roles to ensure performance is acceptable
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create 100 roles with various risk levels
    for i in 0..100 {
        let risk = match i % 4 {
            0 => "low",
            1 => "medium",
            2 => "high",
            _ => "critical",
        };
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, risk).await;
    }

    // Create meta-role matching high and critical (50 roles)
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "High/Critical", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "in",
        serde_json::json!(["High", "Critical"]),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Re-evaluate all
    let start = std::time::Instant::now();
    let (added, removed) = matching_service
        .reevaluate_meta_role(tenant_id, meta_role_id)
        .await
        .unwrap();
    let duration = start.elapsed();

    // Should match ~50 roles (high and critical)
    assert_eq!(added, 50);
    assert_eq!(removed, 0);

    // Performance sanity check - should complete within reasonable time
    assert!(
        duration.as_secs() < 30,
        "Re-evaluation took too long: {duration:?}"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
