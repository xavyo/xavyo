//! Unit tests for meta-role CRUD operations (F056 - T018).
//!
//! Tests meta-role creation, reading, updating, and deletion operations,
//! including validation rules and edge cases.

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_governance::services::MetaRoleService;
use xavyo_db::{
    CreateGovMetaRole, CreateGovMetaRoleConstraint, CreateGovMetaRoleCriteria,
    CreateGovMetaRoleEntitlement, CriteriaLogic, CriteriaOperator, MetaRoleFilter, MetaRoleStatus,
    PermissionType, UpdateGovMetaRole,
};

// =========================================================================
// Meta-role Creation Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_meta_role_with_defaults() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRole {
        name: "High Risk Security Policy".to_string(),
        description: Some("Applies to all high-risk roles".to_string()),
        priority: None,       // Should default to 100
        criteria_logic: None, // Should default to AND
    };

    let criteria = vec![CreateGovMetaRoleCriteria {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::Eq,
        value: serde_json::json!("High"),
    }];

    let result = service.create(tenant_id, user_id, input, criteria).await;
    assert!(
        result.is_ok(),
        "Failed to create meta-role: {:?}",
        result.err()
    );

    let meta_role = result.unwrap();
    assert_eq!(meta_role.name, "High Risk Security Policy");
    assert_eq!(meta_role.priority, 100); // Default priority
    assert_eq!(meta_role.criteria_logic, CriteriaLogic::And);
    assert_eq!(meta_role.status, MetaRoleStatus::Active);
    assert_eq!(meta_role.tenant_id, tenant_id);
    assert_eq!(meta_role.created_by, user_id);

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_meta_role_with_custom_priority() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRole {
        name: "Critical Security Policy".to_string(),
        description: None,
        priority: Some(10), // Higher precedence
        criteria_logic: Some(CriteriaLogic::Or),
    };

    let result = service.create(tenant_id, user_id, input, vec![]).await;
    assert!(result.is_ok());

    let meta_role = result.unwrap();
    assert_eq!(meta_role.priority, 10);
    assert_eq!(meta_role.criteria_logic, CriteriaLogic::Or);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_meta_role_duplicate_name_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = MetaRoleService::new(pool.clone());

    // Create first meta-role
    let input = CreateGovMetaRole {
        name: "Unique Name".to_string(),
        description: None,
        priority: None,
        criteria_logic: None,
    };
    let _ = service
        .create(tenant_id, user_id, input.clone(), vec![])
        .await
        .unwrap();

    // Try to create another with same name
    let result = service.create(tenant_id, user_id, input, vec![]).await;
    assert!(result.is_err(), "Should fail with duplicate name");

    let err = result.unwrap_err();
    assert!(
        format!("{err:?}").contains("MetaRoleNameExists")
            || format!("{err:?}").contains("Unique Name"),
        "Expected MetaRoleNameExists error, got: {err:?}"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_meta_role_with_invalid_criteria_field() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRole {
        name: "Test Meta-Role".to_string(),
        description: None,
        priority: None,
        criteria_logic: None,
    };

    let criteria = vec![CreateGovMetaRoleCriteria {
        field: "invalid_field_name".to_string(),
        operator: CriteriaOperator::Eq,
        value: serde_json::json!("value"),
    }];

    let result = service.create(tenant_id, user_id, input, criteria).await;
    assert!(result.is_err(), "Should fail with invalid criteria field");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Meta-role Read Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_meta_role_by_id() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Test Get", 50).await;

    let service = MetaRoleService::new(pool.clone());
    let result = service.get(tenant_id, meta_role_id).await;

    assert!(result.is_ok());
    let meta_role = result.unwrap();
    assert_eq!(meta_role.id, meta_role_id);
    assert_eq!(meta_role.name, "Test Get");
    assert_eq!(meta_role.priority, 50);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_meta_role_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = MetaRoleService::new(pool.clone());
    let result = service.get(tenant_id, Uuid::new_v4()).await;

    assert!(result.is_err(), "Should return not found error");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_meta_role_wrong_tenant() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let other_tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Tenant Isolation", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Should not find meta-role from different tenant
    let result = service.get(other_tenant_id, meta_role_id).await;
    assert!(
        result.is_err(),
        "Should not find meta-role from different tenant"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, other_tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_meta_roles_with_filter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create meta-roles with different priorities
    create_test_meta_role(&pool, tenant_id, user_id, "Low Priority", 200).await;
    create_test_meta_role(&pool, tenant_id, user_id, "High Priority", 10).await;
    create_test_meta_role(&pool, tenant_id, user_id, "Medium Priority", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // List all
    let (items, total) = service
        .list(tenant_id, &MetaRoleFilter::default(), 100, 0)
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(items.len(), 3);

    // Verify ordering by priority (ascending)
    assert_eq!(items[0].name, "High Priority");
    assert_eq!(items[1].name, "Medium Priority");
    assert_eq!(items[2].name, "Low Priority");

    // Filter by priority range
    let filter = MetaRoleFilter {
        priority_min: Some(50),
        priority_max: Some(150),
        ..Default::default()
    };
    let (items, total) = service.list(tenant_id, &filter, 100, 0).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(items[0].name, "Medium Priority");

    // Filter by name
    let filter = MetaRoleFilter {
        name_contains: Some("High".to_string()),
        ..Default::default()
    };
    let (items, total) = service.list(tenant_id, &filter, 100, 0).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(items[0].name, "High Priority");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_active_meta_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create active meta-roles
    create_test_meta_role(&pool, tenant_id, user_id, "Active 1", 100).await;
    let disable_id = create_test_meta_role(&pool, tenant_id, user_id, "To Disable", 50).await;
    create_test_meta_role(&pool, tenant_id, user_id, "Active 2", 200).await;

    let service = MetaRoleService::new(pool.clone());

    // Disable one
    service
        .disable(tenant_id, disable_id, user_id)
        .await
        .unwrap();

    // List active should only return 2
    let items = service.list_active(tenant_id).await.unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|m| m.status == MetaRoleStatus::Active));

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Meta-role Update Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Original Name", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let update = UpdateGovMetaRole {
        name: Some("Updated Name".to_string()),
        description: Some("Updated description".to_string()),
        priority: Some(25),
        criteria_logic: Some(CriteriaLogic::Or),
    };

    let result = service
        .update(tenant_id, meta_role_id, user_id, update)
        .await;
    assert!(result.is_ok());

    let updated = result.unwrap();
    assert_eq!(updated.name, "Updated Name");
    assert_eq!(updated.description, Some("Updated description".to_string()));
    assert_eq!(updated.priority, 25);
    assert_eq!(updated.criteria_logic, CriteriaLogic::Or);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_meta_role_partial() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Partial Update", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Only update priority
    let update = UpdateGovMetaRole {
        name: None,
        description: None,
        priority: Some(50),
        criteria_logic: None,
    };

    let result = service
        .update(tenant_id, meta_role_id, user_id, update)
        .await;
    assert!(result.is_ok());

    let updated = result.unwrap();
    assert_eq!(updated.name, "Partial Update"); // Unchanged
    assert_eq!(updated.priority, 50); // Changed

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_meta_role_duplicate_name_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "First Name", 100).await;
    create_test_meta_role(&pool, tenant_id, user_id, "Second Name", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Try to rename first to second's name
    let update = UpdateGovMetaRole {
        name: Some("Second Name".to_string()),
        description: None,
        priority: None,
        criteria_logic: None,
    };

    let result = service
        .update(tenant_id, meta_role_id, user_id, update)
        .await;
    assert!(result.is_err(), "Should fail with duplicate name");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Meta-role Enable/Disable Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disable_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "To Disable", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let result = service.disable(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_ok());

    let disabled = result.unwrap();
    assert_eq!(disabled.status, MetaRoleStatus::Disabled);

    // Verify it's actually disabled
    let fetched = service.get(tenant_id, meta_role_id).await.unwrap();
    assert_eq!(fetched.status, MetaRoleStatus::Disabled);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disable_already_disabled_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Already Disabled", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Disable first time
    service
        .disable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();

    // Try to disable again
    let result = service.disable(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_err(), "Should fail when already disabled");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_enable_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "To Enable", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Disable first
    service
        .disable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();

    // Enable
    let result = service.enable(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_ok());

    let enabled = result.unwrap();
    assert_eq!(enabled.status, MetaRoleStatus::Active);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_enable_already_active_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Already Active", 100).await;

    let service = MetaRoleService::new(pool.clone());

    // Try to enable when already active
    let result = service.enable(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_err(), "Should fail when already active");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Meta-role Delete Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "To Delete", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let result = service.delete(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_ok());

    // Verify it's deleted
    let get_result = service.get(tenant_id, meta_role_id).await;
    assert!(
        get_result.is_err(),
        "Meta-role should not exist after deletion"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_meta_role_with_active_inheritances_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Has Inheritances", 100).await;
    let child_role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Create active inheritance
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, child_role_id).await;

    let service = MetaRoleService::new(pool.clone());

    let result = service.delete(tenant_id, meta_role_id, user_id).await;
    assert!(result.is_err(), "Should fail with active inheritances");

    let err = result.unwrap_err();
    assert!(
        format!("{err:?}").contains("MetaRoleHasActiveInheritances"),
        "Expected MetaRoleHasActiveInheritances error, got: {err:?}"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Criteria Management Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_criterion_to_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "With Criteria", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let criterion = CreateGovMetaRoleCriteria {
        field: "risk_level".to_string(),
        operator: CriteriaOperator::In,
        value: serde_json::json!(["High", "Critical"]),
    };

    let result = service
        .add_criterion(tenant_id, meta_role_id, criterion)
        .await;
    assert!(result.is_ok());

    // List criteria
    let criteria = service
        .list_criteria(tenant_id, meta_role_id)
        .await
        .unwrap();
    assert_eq!(criteria.len(), 1);
    assert_eq!(criteria[0].field, "risk_level");
    assert_eq!(criteria[0].operator, CriteriaOperator::In);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_remove_criterion_from_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "With Criteria", 100).await;
    let criterion_id = create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let service = MetaRoleService::new(pool.clone());

    let result = service
        .remove_criterion(tenant_id, meta_role_id, criterion_id)
        .await;
    assert!(result.is_ok());

    // Verify removed
    let criteria = service
        .list_criteria(tenant_id, meta_role_id)
        .await
        .unwrap();
    assert_eq!(criteria.len(), 0);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Entitlement Management Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_entitlement_to_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "With Entitlements", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRoleEntitlement {
        entitlement_id,
        permission_type: Some(PermissionType::Grant),
    };

    let result = service
        .add_entitlement(tenant_id, meta_role_id, input)
        .await;
    assert!(result.is_ok());

    // List entitlements
    let entitlements = service
        .list_entitlements(tenant_id, meta_role_id)
        .await
        .unwrap();
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].entitlement_id, entitlement_id);
    assert_eq!(entitlements[0].permission_type, PermissionType::Grant);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_duplicate_entitlement_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Dup Entitlement", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRoleEntitlement {
        entitlement_id,
        permission_type: Some(PermissionType::Grant),
    };

    // Add first time - should succeed
    service
        .add_entitlement(tenant_id, meta_role_id, input.clone())
        .await
        .unwrap();

    // Add second time - should fail
    let result = service
        .add_entitlement(tenant_id, meta_role_id, input)
        .await;
    assert!(result.is_err(), "Should fail with duplicate entitlement");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Constraint Management Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_constraint_to_meta_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "With Constraints", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRoleConstraint {
        constraint_type: "require_mfa".to_string(),
        constraint_value: serde_json::json!(true),
    };

    let result = service.add_constraint(tenant_id, meta_role_id, input).await;
    assert!(result.is_ok());

    // List constraints
    let constraints = service
        .list_constraints(tenant_id, meta_role_id)
        .await
        .unwrap();
    assert_eq!(constraints.len(), 1);
    assert_eq!(constraints[0].constraint_type, "require_mfa");
    assert_eq!(constraints[0].constraint_value, serde_json::json!(true));

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_invalid_constraint_type_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Invalid Constraint", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRoleConstraint {
        constraint_type: "invalid_constraint_type".to_string(),
        constraint_value: serde_json::json!(true),
    };

    let result = service.add_constraint(tenant_id, meta_role_id, input).await;
    assert!(result.is_err(), "Should fail with invalid constraint type");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_duplicate_constraint_type_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Dup Constraint", 100).await;

    let service = MetaRoleService::new(pool.clone());

    let input = CreateGovMetaRoleConstraint {
        constraint_type: "require_mfa".to_string(),
        constraint_value: serde_json::json!(true),
    };

    // Add first time
    service
        .add_constraint(tenant_id, meta_role_id, input.clone())
        .await
        .unwrap();

    // Add second time with same type
    let result = service.add_constraint(tenant_id, meta_role_id, input).await;
    assert!(
        result.is_err(),
        "Should fail with duplicate constraint type"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_constraint_value() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Update Constraint", 100).await;
    let constraint_id = create_test_meta_role_constraint(
        &pool,
        tenant_id,
        meta_role_id,
        "max_session_duration",
        serde_json::json!(3600),
    )
    .await;

    let service = MetaRoleService::new(pool.clone());

    // Update constraint value
    let result = service
        .update_constraint(
            tenant_id,
            meta_role_id,
            constraint_id,
            serde_json::json!(7200),
        )
        .await;
    assert!(result.is_ok());

    let updated = result.unwrap();
    assert_eq!(updated.constraint_value, serde_json::json!(7200));

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Audit Trail Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_audit_events_created() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = MetaRoleService::new(pool.clone());

    // Create meta-role (should create audit event)
    let input = CreateGovMetaRole {
        name: "Audit Test".to_string(),
        description: None,
        priority: None,
        criteria_logic: None,
    };
    let meta_role = service
        .create(tenant_id, user_id, input, vec![])
        .await
        .unwrap();

    // Check events
    let events = service
        .list_events(tenant_id, meta_role.id, 100, 0)
        .await
        .unwrap();
    assert!(!events.is_empty(), "Should have audit events");

    // First event should be creation
    let created_event = events
        .iter()
        .find(|e| format!("{:?}", e.event_type).contains("Created"));
    assert!(created_event.is_some(), "Should have Created event");

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Priority Edge Cases (IGA-inspired)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_priority_ordering_for_conflict_resolution() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create meta-roles with different priorities
    // Lower number = higher precedence (like IGA)
    create_test_meta_role(&pool, tenant_id, user_id, "Critical (P1)", 1).await;
    create_test_meta_role(&pool, tenant_id, user_id, "High (P10)", 10).await;
    create_test_meta_role(&pool, tenant_id, user_id, "Normal (P100)", 100).await;
    create_test_meta_role(&pool, tenant_id, user_id, "Low (P1000)", 1000).await;

    let service = MetaRoleService::new(pool.clone());
    let (items, _) = service
        .list(tenant_id, &MetaRoleFilter::default(), 100, 0)
        .await
        .unwrap();

    // Verify ordering
    assert_eq!(items[0].priority, 1);
    assert_eq!(items[1].priority, 10);
    assert_eq!(items[2].priority, 100);
    assert_eq!(items[3].priority, 1000);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
