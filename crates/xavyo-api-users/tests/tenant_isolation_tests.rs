//! Integration tests for Multi-Tenant Isolation (User Story 2).
//!
//! These tests verify that tenant data is strictly isolated,
//! preventing cross-tenant data access or modification.
//!
//! Run with: `cargo test -p xavyo-api-users --features integration tenant_isolation -- --ignored`

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_users::models::{ListUsersQuery, UpdateUserRequest};
use xavyo_api_users::services::UserService;
use xavyo_core::TenantId;

// =========================================================================
// Multi-Tenant Isolation Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_returns_only_own_tenant() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    // Create users in tenant A
    let _user_a1 = create_test_user(&pool, tenant_a, &unique_email()).await;
    let _user_a2 = create_test_user(&pool, tenant_a, &unique_email()).await;

    // Create users in tenant B
    let _user_b1 = create_test_user(&pool, tenant_b, &unique_email()).await;

    let service = UserService::new(pool.clone());
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: None,
    };

    // List users from tenant A
    let result_a = service
        .list_users(TenantId::from_uuid(tenant_a), &query, &[])
        .await;

    assert!(result_a.is_ok(), "List users for tenant A should succeed");
    let list_a = result_a.unwrap();
    assert_eq!(
        list_a.pagination.total_count, 2,
        "Tenant A should have 2 users"
    );

    // List users from tenant B
    let result_b = service
        .list_users(TenantId::from_uuid(tenant_b), &query, &[])
        .await;

    assert!(result_b.is_ok(), "List users for tenant B should succeed");
    let list_b = result_b.unwrap();
    assert_eq!(
        list_b.pagination.total_count, 1,
        "Tenant B should have 1 user"
    );

    // Verify users are from correct tenants
    for user in &list_a.users {
        assert!(
            user.id != Uuid::nil(),
            "Tenant A users should have valid IDs"
        );
    }

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_user_from_other_tenant_returns_not_found() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    // Create user in tenant A
    let user_id = create_test_user(&pool, tenant_a, &unique_email()).await;

    let service = UserService::new(pool.clone());

    // Try to get user from tenant B context (should fail with not found)
    let result = service
        .get_user(
            TenantId::from_uuid(tenant_b),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;

    assert!(
        result.is_err(),
        "Should not find user from different tenant"
    );

    // Verify error is NotFound (not Forbidden - to avoid confirming existence)
    let err = result.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        err_string.contains("NotFound") || err_string.contains("not found"),
        "Error should be NotFound, got: {err_string}"
    );

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_user_from_other_tenant_returns_not_found() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    // Create user in tenant A
    let user_id = create_test_user(&pool, tenant_a, &unique_email()).await;

    let service = UserService::new(pool.clone());

    // Try to update user from tenant B context (should fail with not found)
    let request = UpdateUserRequest {
        email: Some(unique_email()),
        roles: None,
        is_active: None,
        username: None,
    };

    let result = service
        .update_user(
            TenantId::from_uuid(tenant_b),
            xavyo_core::UserId::from_uuid(user_id),
            &request,
        )
        .await;

    assert!(
        result.is_err(),
        "Should not be able to update user from different tenant"
    );

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_user_from_other_tenant_returns_not_found() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    // Create user in tenant A
    let user_id = create_test_user(&pool, tenant_a, &unique_email()).await;

    let service = UserService::new(pool.clone());

    // Try to delete user from tenant B context (should fail with not found)
    let result = service
        .deactivate_user(
            TenantId::from_uuid(tenant_b),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;

    assert!(
        result.is_err(),
        "Should not be able to delete user from different tenant"
    );

    // Verify user still exists in tenant A
    let get_result = service
        .get_user(
            TenantId::from_uuid(tenant_a),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;
    assert!(
        get_result.is_ok(),
        "User should still exist in original tenant"
    );

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_user_created_in_tenant_a_not_visible_to_tenant_b() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());

    // Create user in tenant A via service
    let request = xavyo_api_users::models::CreateUserRequest {
        email: unique_email(),
        password: "SecurePassword123!".to_string(),
        roles: vec![],
        username: None,
    };

    let create_result = service
        .create_user(TenantId::from_uuid(tenant_a), &request)
        .await;
    assert!(create_result.is_ok(), "User creation should succeed");
    let created_user = create_result.unwrap();

    // Try to get the user from tenant B context
    let get_result = service
        .get_user(
            TenantId::from_uuid(tenant_b),
            xavyo_core::UserId::from_uuid(created_user.id),
        )
        .await;
    assert!(
        get_result.is_err(),
        "User created in tenant A should not be visible to tenant B"
    );

    // List users in tenant B should not include the user
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: None,
    };
    let list_result = service
        .list_users(TenantId::from_uuid(tenant_b), &query, &[])
        .await;
    assert!(list_result.is_ok());
    let list = list_result.unwrap();
    assert_eq!(
        list.pagination.total_count, 0,
        "Tenant B should have no users"
    );

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_group_membership_tenant_isolation() {
    let pool = create_test_pool().await;
    let tenant_a = create_test_tenant(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    // Create group and user in tenant A
    let group_a = create_test_group(&pool, tenant_a, &unique_group_name()).await;
    let user_a = create_test_user(&pool, tenant_a, &unique_email()).await;
    add_user_to_group(&pool, tenant_a, group_a, user_a).await;

    // Create group in tenant B
    let _group_b = create_test_group(&pool, tenant_b, &unique_group_name()).await;

    // Verify group membership query is tenant-isolated
    let count_a: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_members WHERE tenant_id = $1")
        .bind(tenant_a)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

    assert_eq!(count_a.0, 1, "Tenant A should have 1 group member");

    let count_b: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_members WHERE tenant_id = $1")
        .bind(tenant_b)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

    assert_eq!(count_b.0, 0, "Tenant B should have 0 group members");

    cleanup_test_tenant(&pool, tenant_a).await;
    cleanup_test_tenant(&pool, tenant_b).await;
}
