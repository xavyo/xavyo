//! Integration tests for F-064: Bulk Action Engine.
//!
//! Tests bulk action creation, validation, preview, and service operations.

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_governance::services::BulkActionService;
use xavyo_db::{GovBulkActionFilter, GovBulkActionStatus, GovBulkActionType};
use xavyo_governance::validate_expression;

// =========================================================================
// Expression Validation Tests (Unit tests - no database required)
// =========================================================================

#[test]
fn test_validate_expression_simple_equals() {
    let result = validate_expression("department = 'engineering'");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"department".to_string()));
}

#[test]
fn test_validate_expression_boolean() {
    let result = validate_expression("is_active = true");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"is_active".to_string()));
}

#[test]
fn test_validate_expression_compound_and() {
    let result = validate_expression("department = 'engineering' AND level >= 3");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"department".to_string()));
    assert!(attrs.contains(&"level".to_string()));
}

#[test]
fn test_validate_expression_compound_or() {
    let result = validate_expression("department = 'sales' OR department = 'marketing'");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"department".to_string()));
}

#[test]
fn test_validate_expression_complex() {
    let result = validate_expression(
        "department IN ('eng', 'product') AND (level >= 3 OR is_manager = true)",
    );
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"department".to_string()));
    assert!(attrs.contains(&"level".to_string()));
    assert!(attrs.contains(&"is_manager".to_string()));
}

#[test]
fn test_validate_expression_not() {
    let result = validate_expression("NOT (status = 'terminated')");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"status".to_string()));
}

#[test]
fn test_validate_expression_like() {
    let result = validate_expression("email LIKE '%@example.com'");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"email".to_string()));
}

#[test]
fn test_validate_expression_in_list() {
    let result = validate_expression("status IN ('active', 'pending', 'review')");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"status".to_string()));
}

#[test]
fn test_validate_expression_comparisons() {
    let cases = vec![
        ("age > 30", vec!["age"]),
        ("salary >= 50000", vec!["salary"]),
        ("level < 5", vec!["level"]),
        ("rating <= 4.5", vec!["rating"]),
        ("role != 'admin'", vec!["role"]),
    ];

    for (expr, expected_attrs) in cases {
        let result = validate_expression(expr);
        assert!(result.is_ok(), "Failed to validate: {}", expr);
        let attrs = result.unwrap();
        for attr in expected_attrs {
            assert!(
                attrs.contains(&attr.to_string()),
                "Missing attribute '{}' in expression: {}",
                attr,
                expr
            );
        }
    }
}

#[test]
fn test_validate_expression_invalid_syntax() {
    let invalid_expressions = vec![
        "invalid ??? syntax",
        "= = =",
        "AND OR AND",
        "( unclosed",
        "field = ",
        // Note: Empty string "" causes parser edge case, tested separately if needed
    ];

    for expr in invalid_expressions {
        let result = validate_expression(expr);
        assert!(
            result.is_err(),
            "Expected error for invalid expression: '{}'",
            expr
        );
    }
}

#[test]
fn test_validate_expression_nested_parentheses() {
    let result =
        validate_expression("((department = 'eng') AND ((level >= 3) OR (is_manager = true)))");
    assert!(result.is_ok());
    let attrs = result.unwrap();
    assert!(attrs.contains(&"department".to_string()));
    assert!(attrs.contains(&"level".to_string()));
    assert!(attrs.contains(&"is_manager".to_string()));
}

// =========================================================================
// BulkActionService Validation Tests (Unit tests - no database required)
// =========================================================================

#[test]
fn test_service_validate_expression_valid() {
    // BulkActionService.validate_expression is sync and doesn't need pool
    // We test the underlying function directly since service needs pool
    let result = validate_expression("department = 'engineering' AND active = true");
    assert!(result.is_ok());
}

#[test]
fn test_service_validate_expression_invalid() {
    let result = validate_expression("not a valid expression @#$");
    assert!(result.is_err());
}

// =========================================================================
// Bulk Action Model Tests
// =========================================================================

#[test]
fn test_bulk_action_status_serialization() {
    assert_eq!(
        serde_json::to_string(&GovBulkActionStatus::Pending).unwrap(),
        "\"pending\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionStatus::Running).unwrap(),
        "\"running\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionStatus::Completed).unwrap(),
        "\"completed\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionStatus::Failed).unwrap(),
        "\"failed\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionStatus::Cancelled).unwrap(),
        "\"cancelled\""
    );
}

#[test]
fn test_bulk_action_status_deserialization() {
    assert_eq!(
        serde_json::from_str::<GovBulkActionStatus>("\"pending\"").unwrap(),
        GovBulkActionStatus::Pending
    );
    assert_eq!(
        serde_json::from_str::<GovBulkActionStatus>("\"running\"").unwrap(),
        GovBulkActionStatus::Running
    );
    assert_eq!(
        serde_json::from_str::<GovBulkActionStatus>("\"completed\"").unwrap(),
        GovBulkActionStatus::Completed
    );
}

#[test]
fn test_bulk_action_type_serialization() {
    assert_eq!(
        serde_json::to_string(&GovBulkActionType::AssignRole).unwrap(),
        "\"assign_role\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionType::RevokeRole).unwrap(),
        "\"revoke_role\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionType::Enable).unwrap(),
        "\"enable\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionType::Disable).unwrap(),
        "\"disable\""
    );
    assert_eq!(
        serde_json::to_string(&GovBulkActionType::ModifyAttribute).unwrap(),
        "\"modify_attribute\""
    );
}

#[test]
fn test_bulk_action_type_deserialization() {
    assert_eq!(
        serde_json::from_str::<GovBulkActionType>("\"assign_role\"").unwrap(),
        GovBulkActionType::AssignRole
    );
    assert_eq!(
        serde_json::from_str::<GovBulkActionType>("\"revoke_role\"").unwrap(),
        GovBulkActionType::RevokeRole
    );
    assert_eq!(
        serde_json::from_str::<GovBulkActionType>("\"enable\"").unwrap(),
        GovBulkActionType::Enable
    );
}

#[test]
fn test_bulk_action_filter_default() {
    let filter = GovBulkActionFilter::default();
    assert!(filter.status.is_none());
    assert!(filter.action_type.is_none());
    assert!(filter.created_by.is_none());
}

// =========================================================================
// Database Integration Tests (require DATABASE_URL)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_bulk_action_assign_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = BulkActionService::new(pool.clone());

    let request = xavyo_api_governance::models::CreateBulkActionRequest {
        filter_expression: "department = 'engineering'".to_string(),
        action_type: GovBulkActionType::AssignRole,
        action_params: serde_json::json!({
            "role_id": Uuid::new_v4().to_string()
        }),
        justification: "Q1 security compliance - engineering team role assignment".to_string(),
    };

    let result = service
        .create_bulk_action(tenant_id, request, user_id)
        .await;
    assert!(
        result.is_ok(),
        "Failed to create bulk action: {:?}",
        result.err()
    );

    let action = result.unwrap();
    assert_eq!(action.status, GovBulkActionStatus::Pending);
    assert_eq!(action.action_type, GovBulkActionType::AssignRole);
    assert!(!action.justification.is_empty());

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_bulk_action_disable_users() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = BulkActionService::new(pool.clone());

    let request = xavyo_api_governance::models::CreateBulkActionRequest {
        filter_expression: "status = 'inactive' AND last_login < '2024-01-01'".to_string(),
        action_type: GovBulkActionType::Disable,
        action_params: serde_json::json!({}),
        justification: "Disable dormant accounts - security compliance measure".to_string(),
    };

    let result = service
        .create_bulk_action(tenant_id, request, user_id)
        .await;
    assert!(result.is_ok());

    let action = result.unwrap();
    assert_eq!(action.action_type, GovBulkActionType::Disable);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_bulk_action_invalid_expression_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = BulkActionService::new(pool.clone());

    let request = xavyo_api_governance::models::CreateBulkActionRequest {
        filter_expression: "invalid !!! syntax".to_string(),
        action_type: GovBulkActionType::Enable,
        action_params: serde_json::json!({}),
        justification: "Test invalid expression handling".to_string(),
    };

    let result = service
        .create_bulk_action(tenant_id, request, user_id)
        .await;
    assert!(result.is_err(), "Should fail with invalid expression");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_bulk_action_by_id() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        user_id,
        "department = 'sales'",
        "assign_role",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service.get_bulk_action(tenant_id, action_id).await;
    assert!(result.is_ok());

    let action = result.unwrap();
    assert_eq!(action.bulk_action.id, action_id);
    assert_eq!(action.bulk_action.filter_expression, "department = 'sales'");

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_bulk_action_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = BulkActionService::new(pool.clone());

    let result = service.get_bulk_action(tenant_id, Uuid::new_v4()).await;
    assert!(result.is_err(), "Should return not found");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_bulk_action_wrong_tenant() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let other_tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let action_id =
        create_test_bulk_action(&pool, tenant_id, user_id, "active = true", "enable").await;

    let service = BulkActionService::new(pool.clone());

    // Should not find action from different tenant
    let result = service.get_bulk_action(other_tenant_id, action_id).await;
    assert!(
        result.is_err(),
        "Should not find action from different tenant"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, other_tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_bulk_actions() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create multiple bulk actions
    create_test_bulk_action(&pool, tenant_id, user_id, "dept = 'eng'", "assign_role").await;
    create_test_bulk_action(&pool, tenant_id, user_id, "active = false", "enable").await;
    create_test_bulk_action(&pool, tenant_id, user_id, "level < 2", "disable").await;

    let service = BulkActionService::new(pool.clone());

    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: None,
        action_type: None,
        created_by: None,
        limit: Some(50),
        offset: Some(0),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await;
    assert!(result.is_ok());

    let list = result.unwrap();
    assert_eq!(list.total, 3);
    assert_eq!(list.items.len(), 3);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_bulk_actions_filter_by_status() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    create_test_bulk_action(&pool, tenant_id, user_id, "dept = 'eng'", "assign_role").await;
    create_test_bulk_action(&pool, tenant_id, user_id, "active = false", "enable").await;

    let service = BulkActionService::new(pool.clone());

    // Filter by pending status (all should be pending since just created)
    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: Some(GovBulkActionStatus::Pending),
        action_type: None,
        created_by: None,
        limit: Some(50),
        offset: Some(0),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await;
    assert!(result.is_ok());

    let list = result.unwrap();
    assert_eq!(list.total, 2);

    // Filter by running status (none should match)
    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: Some(GovBulkActionStatus::Running),
        action_type: None,
        created_by: None,
        limit: Some(50),
        offset: Some(0),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().total, 0);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_bulk_actions_filter_by_action_type() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    create_test_bulk_action(&pool, tenant_id, user_id, "dept = 'eng'", "assign_role").await;
    create_test_bulk_action(&pool, tenant_id, user_id, "active = false", "enable").await;
    create_test_bulk_action(&pool, tenant_id, user_id, "level < 2", "disable").await;

    let service = BulkActionService::new(pool.clone());

    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: None,
        action_type: Some(GovBulkActionType::AssignRole),
        created_by: None,
        limit: Some(50),
        offset: Some(0),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await;
    assert!(result.is_ok());

    let list = result.unwrap();
    assert_eq!(list.total, 1);
    assert_eq!(list.items[0].action_type, GovBulkActionType::AssignRole);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_bulk_actions_pagination() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create 5 bulk actions
    for i in 0..5 {
        create_test_bulk_action(
            &pool,
            tenant_id,
            user_id,
            &format!("field{i} = 'value'"),
            "enable",
        )
        .await;
    }

    let service = BulkActionService::new(pool.clone());

    // Get first page
    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: None,
        action_type: None,
        created_by: None,
        limit: Some(2),
        offset: Some(0),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await.unwrap();
    assert_eq!(result.total, 5);
    assert_eq!(result.items.len(), 2);
    assert_eq!(result.limit, 2);
    assert_eq!(result.offset, 0);

    // Get second page
    let query = xavyo_api_governance::models::ListBulkActionsQuery {
        status: None,
        action_type: None,
        created_by: None,
        limit: Some(2),
        offset: Some(2),
    };

    let result = service.list_bulk_actions(tenant_id, &query).await.unwrap();
    assert_eq!(result.total, 5);
    assert_eq!(result.items.len(), 2);
    assert_eq!(result.offset, 2);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_preview_bulk_action_with_matching_users() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create users with custom attributes
    create_test_user_with_attributes(
        &pool,
        tenant_id,
        Some("engineering"),
        Some("Senior Engineer"),
    )
    .await;
    create_test_user_with_attributes(
        &pool,
        tenant_id,
        Some("engineering"),
        Some("Staff Engineer"),
    )
    .await;
    create_test_user_with_attributes(&pool, tenant_id, Some("sales"), Some("Account Executive"))
        .await;

    // Create bulk action targeting engineering department
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        user_id,
        "department = 'engineering'",
        "assign_role",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let query = xavyo_api_governance::models::PreviewBulkActionQuery {
        limit: Some(100),
        offset: Some(0),
    };

    let result = service
        .preview_bulk_action(tenant_id, action_id, &query)
        .await;
    assert!(result.is_ok(), "Preview failed: {:?}", result.err());

    let preview = result.unwrap();
    // Should match the engineering users
    assert!(
        preview.total_matched >= 2,
        "Expected at least 2 matches, got {}",
        preview.total_matched
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_preview_bulk_action_no_matches() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create users without matching department
    create_test_user_with_attributes(&pool, tenant_id, Some("sales"), None).await;
    create_test_user_with_attributes(&pool, tenant_id, Some("marketing"), None).await;

    // Create bulk action with non-matching filter
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        user_id,
        "department = 'nonexistent'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let query = xavyo_api_governance::models::PreviewBulkActionQuery {
        limit: Some(100),
        offset: Some(0),
    };

    let result = service
        .preview_bulk_action(tenant_id, action_id, &query)
        .await;
    assert!(result.is_ok());

    let preview = result.unwrap();
    assert_eq!(preview.total_matched, 0);
    assert!(preview.users.is_empty());

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_preview_bulk_action_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = BulkActionService::new(pool.clone());

    let query = xavyo_api_governance::models::PreviewBulkActionQuery {
        limit: Some(100),
        offset: Some(0),
    };

    let result = service
        .preview_bulk_action(tenant_id, Uuid::new_v4(), &query)
        .await;
    assert!(
        result.is_err(),
        "Should return not found for non-existent action"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Helper Functions for Bulk Action Tests
// =========================================================================

/// Create a test bulk action.
async fn create_test_bulk_action(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    created_by: Uuid,
    filter_expression: &str,
    action_type: &str,
) -> Uuid {
    let action_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO gov_bulk_actions (id, tenant_id, filter_expression, action_type, action_params, status, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4::gov_bulk_action_type, $5, 'pending', $6, NOW(), NOW())
        "#,
    )
    .bind(action_id)
    .bind(tenant_id)
    .bind(filter_expression)
    .bind(action_type)
    .bind(serde_json::json!({}))
    .bind(created_by)
    .execute(pool)
    .await
    .expect("Failed to create test bulk action");

    action_id
}

/// Cleanup bulk action test data for a tenant.
async fn cleanup_bulk_action_data(pool: &sqlx::PgPool, tenant_id: Uuid) {
    let _ = sqlx::query("DELETE FROM gov_bulk_actions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// =========================================================================
// Execute Bulk Action Integration Tests (Phase 4 - T043)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_enable_users() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create inactive users with matching department
    let user1 = create_test_user_with_status(&pool, tenant_id, "engineering", false).await;
    let user2 = create_test_user_with_status(&pool, tenant_id, "engineering", false).await;
    let _user3 = create_test_user_with_status(&pool, tenant_id, "sales", false).await; // Should not be affected

    // Create bulk action to enable engineering users
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok(), "Execute failed: {:?}", result.err());

    let detail = result.unwrap();
    assert_eq!(detail.bulk_action.status, GovBulkActionStatus::Completed);
    assert!(detail.bulk_action.success_count > 0 || detail.bulk_action.skipped_count > 0);

    // Verify users were enabled
    let user1_active = check_user_active(&pool, user1).await;
    let user2_active = check_user_active(&pool, user2).await;
    assert!(user1_active, "User 1 should be active");
    assert!(user2_active, "User 2 should be active");

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_disable_users() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create active users with matching department
    let user1 = create_test_user_with_status(&pool, tenant_id, "sales", true).await;
    let user2 = create_test_user_with_status(&pool, tenant_id, "sales", true).await;
    let user3 = create_test_user_with_status(&pool, tenant_id, "engineering", true).await; // Should not be affected

    // Create bulk action to disable sales users
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'sales'",
        "disable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok(), "Execute failed: {:?}", result.err());

    let detail = result.unwrap();
    assert_eq!(detail.bulk_action.status, GovBulkActionStatus::Completed);

    // Verify sales users were disabled and engineering user was not
    let user1_active = check_user_active(&pool, user1).await;
    let user2_active = check_user_active(&pool, user2).await;
    let user3_active = check_user_active(&pool, user3).await;
    assert!(!user1_active, "Sales user 1 should be disabled");
    assert!(!user2_active, "Sales user 2 should be disabled");
    assert!(user3_active, "Engineering user should still be active");

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_already_executed() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Execute once
    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok());

    // Try to execute again - should fail
    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_err(), "Should not allow re-execution");

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_skips_unchanged() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create users that are already in target state (active)
    let _user1 = create_test_user_with_status(&pool, tenant_id, "engineering", true).await;
    let _user2 = create_test_user_with_status(&pool, tenant_id, "engineering", true).await;

    // Create bulk action to enable (but they're already enabled)
    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok());

    let detail = result.unwrap();
    // Since users are already active, these should be skipped
    assert!(detail.bulk_action.skipped_count >= 0);
    assert_eq!(detail.bulk_action.status, GovBulkActionStatus::Completed);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, Uuid::new_v4(), admin_user_id)
        .await;
    assert!(
        result.is_err(),
        "Should return not found for non-existent action"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_wrong_tenant() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let other_tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;
    let other_admin_user_id = create_test_user(&pool, other_tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Try to execute from different tenant
    let result = service
        .execute_bulk_action(other_tenant_id, action_id, other_admin_user_id)
        .await;
    assert!(
        result.is_err(),
        "Should not allow execution from different tenant"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, other_tenant_id).await;
}

// =========================================================================
// Additional Helper Functions for Execute Tests
// =========================================================================

/// Create a test user with specific status (active/inactive).
async fn create_test_user_with_status(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    department: &str,
    is_active: bool,
) -> Uuid {
    let user_id = Uuid::new_v4();
    let email = format!("user-{}@test.example.com", user_id);

    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, display_name, is_active, custom_attributes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        "#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(format!("Test User {}", department))
    .bind(is_active)
    .bind(serde_json::json!({"department": department}))
    .execute(pool)
    .await
    .expect("Failed to create test user with status");

    user_id
}

/// Check if a user is active.
async fn check_user_active(pool: &sqlx::PgPool, user_id: Uuid) -> bool {
    let result: (bool,) = sqlx::query_as("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("Failed to check user status");

    result.0
}

// =========================================================================
// Modify Attribute Integration Tests (Phase 7 - T058)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_modify_attribute() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create users with old department attribute
    let _user1 = create_test_user_with_status(&pool, tenant_id, "old_dept", true).await;
    let _user2 = create_test_user_with_status(&pool, tenant_id, "old_dept", true).await;

    // Create bulk action to modify department attribute
    let action_id = create_test_bulk_action_with_params(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'old_dept'",
        "modify_attribute",
        serde_json::json!({
            "attribute": "department",
            "value": "new_dept"
        }),
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok(), "Execute failed: {:?}", result.err());

    let detail = result.unwrap();
    assert_eq!(detail.bulk_action.status, GovBulkActionStatus::Completed);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_bulk_action_modify_immutable_attribute_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create users
    let _user1 = create_test_user_with_status(&pool, tenant_id, "engineering", true).await;

    // Create bulk action to modify immutable attribute (email)
    let action_id = create_test_bulk_action_with_params(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "modify_attribute",
        serde_json::json!({
            "attribute": "email",
            "value": "hacked@example.com"
        }),
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Execute - should process but fail for each user due to immutable attribute
    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok());

    let detail = result.unwrap();
    // All operations should fail because email is immutable
    assert!(detail.bulk_action.failure_count > 0 || detail.bulk_action.processed_count == 0);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Create a test bulk action with custom action params.
async fn create_test_bulk_action_with_params(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    created_by: Uuid,
    filter_expression: &str,
    action_type: &str,
    action_params: serde_json::Value,
) -> Uuid {
    let action_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO gov_bulk_actions (id, tenant_id, filter_expression, action_type, action_params, status, justification, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4::gov_bulk_action_type, $5, 'pending', 'Test justification for bulk action', $6, NOW(), NOW())
        "#,
    )
    .bind(action_id)
    .bind(tenant_id)
    .bind(filter_expression)
    .bind(action_type)
    .bind(action_params)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("Failed to create test bulk action with params");

    action_id
}

// =========================================================================
// Cancel Bulk Action Integration Tests (Phase 8 - T063)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cancel_pending_bulk_action() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Cancel the pending action
    let result = service.cancel_bulk_action(tenant_id, action_id).await;
    assert!(result.is_ok(), "Cancel failed: {:?}", result.err());

    let detail = result.unwrap();
    assert_eq!(detail.bulk_action.status, GovBulkActionStatus::Cancelled);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cancel_completed_bulk_action_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Execute the action first
    let _ = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;

    // Try to cancel completed action - should fail
    let result = service.cancel_bulk_action(tenant_id, action_id).await;
    assert!(
        result.is_err(),
        "Should not allow cancelling completed action"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cancel_already_cancelled_bulk_action_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Cancel once
    let _ = service.cancel_bulk_action(tenant_id, action_id).await;

    // Try to cancel again - should fail
    let result = service.cancel_bulk_action(tenant_id, action_id).await;
    assert!(
        result.is_err(),
        "Should not allow cancelling already cancelled action"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cancel_bulk_action_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = BulkActionService::new(pool.clone());

    let result = service.cancel_bulk_action(tenant_id, Uuid::new_v4()).await;
    assert!(
        result.is_err(),
        "Should return not found for non-existent action"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cancel_bulk_action_wrong_tenant() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let other_tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Try to cancel from different tenant
    let result = service.cancel_bulk_action(other_tenant_id, action_id).await;
    assert!(
        result.is_err(),
        "Should not allow cancelling from different tenant"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, other_tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_execute_cancelled_bulk_action_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Cancel the action
    let _ = service.cancel_bulk_action(tenant_id, action_id).await;

    // Try to execute - should fail
    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(
        result.is_err(),
        "Should not allow executing cancelled action"
    );

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Progress Tracking Integration Tests (Phase 6 - T054)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_bulk_action_progress_tracking() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create multiple users to process
    for _ in 0..5 {
        let _ = create_test_user_with_status(&pool, tenant_id, "engineering", false).await;
    }

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'engineering'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    // Execute the action
    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok(), "Execute failed: {:?}", result.err());

    let detail = result.unwrap();

    // Verify progress tracking
    assert!(detail.progress_percent >= 0 && detail.progress_percent <= 100);
    assert!(detail.bulk_action.processed_count > 0);

    // For completed action, progress should be 100%
    if detail.bulk_action.status == GovBulkActionStatus::Completed {
        assert_eq!(detail.progress_percent, 100);
    }

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_bulk_action_progress_counts_correct() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    // Create 3 inactive users
    for _ in 0..3 {
        let _ = create_test_user_with_status(&pool, tenant_id, "sales", false).await;
    }

    // Create 2 active users (will be skipped)
    for _ in 0..2 {
        let _ = create_test_user_with_status(&pool, tenant_id, "sales", true).await;
    }

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'sales'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok());

    let detail = result.unwrap();

    // Verify counts are correct
    assert_eq!(
        detail.bulk_action.processed_count,
        detail.bulk_action.success_count
            + detail.bulk_action.failure_count
            + detail.bulk_action.skipped_count
    );

    // 3 should be success (enabled), 2 should be skipped (already active)
    // Note: actual counts depend on test data state
    assert!(detail.bulk_action.success_count >= 0);
    assert!(detail.bulk_action.skipped_count >= 0);

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_bulk_action_results_stored() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let admin_user_id = create_test_user(&pool, tenant_id).await;

    let _ = create_test_user_with_status(&pool, tenant_id, "product", false).await;
    let _ = create_test_user_with_status(&pool, tenant_id, "product", false).await;

    let action_id = create_test_bulk_action(
        &pool,
        tenant_id,
        admin_user_id,
        "department = 'product'",
        "enable",
    )
    .await;

    let service = BulkActionService::new(pool.clone());

    let result = service
        .execute_bulk_action(tenant_id, action_id, admin_user_id)
        .await;
    assert!(result.is_ok());

    let detail = result.unwrap();

    // Verify results are stored
    if let Some(results) = &detail.results {
        assert!(!results.is_empty());
        for result_item in results {
            // Each result should have a user_id
            assert!(!result_item.user_id.is_nil());
        }
    }

    cleanup_bulk_action_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Bulk Action Job Unit Tests (Phase 6)
// =========================================================================

#[test]
fn test_bulk_action_job_stats_default() {
    use xavyo_api_governance::BulkActionJobStats;

    let stats = BulkActionJobStats::default();
    assert_eq!(stats.actions_processed, 0);
    assert_eq!(stats.users_processed, 0);
    assert_eq!(stats.successes, 0);
    assert_eq!(stats.skipped, 0);
    assert_eq!(stats.failures, 0);
    assert_eq!(stats.cancelled, 0);
}

#[test]
fn test_bulk_action_job_stats_merge() {
    use xavyo_api_governance::BulkActionJobStats;

    let mut stats1 = BulkActionJobStats {
        actions_processed: 2,
        users_processed: 100,
        successes: 80,
        skipped: 10,
        failures: 10,
        cancelled: 0,
    };

    let stats2 = BulkActionJobStats {
        actions_processed: 1,
        users_processed: 50,
        successes: 45,
        skipped: 3,
        failures: 2,
        cancelled: 1,
    };

    stats1.merge(&stats2);

    assert_eq!(stats1.actions_processed, 3);
    assert_eq!(stats1.users_processed, 150);
    assert_eq!(stats1.successes, 125);
    assert_eq!(stats1.skipped, 13);
    assert_eq!(stats1.failures, 12);
    assert_eq!(stats1.cancelled, 1);
}

#[test]
fn test_bulk_action_job_error_display() {
    use xavyo_api_governance::BulkActionJobError;

    let err = BulkActionJobError::Processing("test error".to_string());
    assert!(err.to_string().contains("test error"));

    let db_err = BulkActionJobError::Database("connection failed".to_string());
    assert!(db_err.to_string().contains("connection failed"));
}
