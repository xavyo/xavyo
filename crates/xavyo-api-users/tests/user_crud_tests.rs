//! Integration tests for User CRUD operations (User Story 1).
//!
//! These tests verify that user management endpoints work correctly,
//! handling create, read, update, and delete operations with proper validation.
//!
//! Run with: `cargo test -p xavyo-api-users --features integration user_crud -- --ignored`

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_users::models::{CreateUserRequest, UpdateUserRequest};
use xavyo_api_users::services::UserService;
use xavyo_core::TenantId;

// =========================================================================
// User Creation Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_user_success() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());

    let request = CreateUserRequest {
        email: unique_email(),
        password: "SecurePassword123!".to_string(),
        roles: vec![],
        username: None,
    };

    let result = service
        .create_user(TenantId::from_uuid(tenant_id), &request)
        .await;

    assert!(result.is_ok(), "User creation should succeed");
    let user = result.unwrap();
    assert_eq!(user.email, request.email);
    assert!(user.is_active);
    assert!(!user.email_verified);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_user_with_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());

    let request = CreateUserRequest {
        email: unique_email(),
        password: "SecurePassword123!".to_string(),
        roles: vec!["admin".to_string(), "viewer".to_string()],
        username: None,
    };

    let result = service
        .create_user(TenantId::from_uuid(tenant_id), &request)
        .await;

    assert!(result.is_ok(), "User creation with roles should succeed");
    let user = result.unwrap();
    assert_eq!(user.roles.len(), 2);
    assert!(user.roles.contains(&"admin".to_string()));
    assert!(user.roles.contains(&"viewer".to_string()));

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_user_duplicate_email_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());
    let email = unique_email();

    // Create first user
    let request1 = CreateUserRequest {
        email: email.clone(),
        password: "SecurePassword123!".to_string(),
        roles: vec![],
        username: None,
    };
    let _ = service
        .create_user(TenantId::from_uuid(tenant_id), &request1)
        .await
        .unwrap();

    // Try to create another user with same email
    let request2 = CreateUserRequest {
        email,
        password: "DifferentPassword456!".to_string(),
        roles: vec![],
        username: None,
    };
    let result = service
        .create_user(TenantId::from_uuid(tenant_id), &request2)
        .await;

    assert!(result.is_err(), "Duplicate email should fail");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_user_validation_errors() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());

    // Test with empty email
    let request = CreateUserRequest {
        email: "".to_string(),
        password: "SecurePassword123!".to_string(),
        roles: vec![],
        username: None,
    };

    let result = service
        .create_user(TenantId::from_uuid(tenant_id), &request)
        .await;

    assert!(result.is_err(), "Empty email should fail validation");

    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// User Read Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_user_by_id() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let email = unique_email();
    let user_id = create_test_user(&pool, tenant_id, &email).await;

    let service = UserService::new(pool.clone());

    let result = service
        .get_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;

    assert!(result.is_ok(), "Get user by ID should succeed");
    let user = result.unwrap();
    assert_eq!(user.id, user_id);
    assert_eq!(user.email, email);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_user_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());
    let non_existent_id = Uuid::new_v4();

    let result = service
        .get_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(non_existent_id),
        )
        .await;

    assert!(result.is_err(), "Non-existent user should return error");

    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// User Update Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_user_email() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let original_email = unique_email();
    let user_id = create_test_user(&pool, tenant_id, &original_email).await;

    let service = UserService::new(pool.clone());
    let new_email = unique_email();

    let request = UpdateUserRequest {
        email: Some(new_email.clone()),
        roles: None,
        is_active: None,
        username: None,
    };

    let result = service
        .update_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
            &request,
        )
        .await;

    assert!(result.is_ok(), "Update user email should succeed");
    let user = result.unwrap();
    assert_eq!(user.email, new_email);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_user_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let email = unique_email();
    let user_id = create_test_user(&pool, tenant_id, &email).await;

    let service = UserService::new(pool.clone());

    let request = UpdateUserRequest {
        email: None,
        roles: Some(vec!["editor".to_string(), "reviewer".to_string()]),
        is_active: None,
        username: None,
    };

    let result = service
        .update_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
            &request,
        )
        .await;

    assert!(result.is_ok(), "Update user roles should succeed");
    let user = result.unwrap();
    assert_eq!(user.roles.len(), 2);
    assert!(user.roles.contains(&"editor".to_string()));
    assert!(user.roles.contains(&"reviewer".to_string()));

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_user_active_status() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let email = unique_email();
    let user_id = create_test_user(&pool, tenant_id, &email).await;

    let service = UserService::new(pool.clone());

    // Disable user
    let request = UpdateUserRequest {
        email: None,
        roles: None,
        is_active: Some(false),
        username: None,
    };

    let result = service
        .update_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
            &request,
        )
        .await;

    assert!(result.is_ok(), "Disabling user should succeed");
    let user = result.unwrap();
    assert!(!user.is_active, "User should be disabled");

    // Re-enable user
    let request = UpdateUserRequest {
        email: None,
        roles: None,
        is_active: Some(true),
        username: None,
    };

    let result = service
        .update_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
            &request,
        )
        .await;

    assert!(result.is_ok(), "Enabling user should succeed");
    let user = result.unwrap();
    assert!(user.is_active, "User should be enabled");

    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// User Delete Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_user() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let email = unique_email();
    let user_id = create_test_user(&pool, tenant_id, &email).await;

    let service = UserService::new(pool.clone());

    // Delete (deactivate) user
    let result = service
        .deactivate_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;

    assert!(result.is_ok(), "Delete user should succeed");

    // Verify user is deactivated
    let get_result = service
        .get_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(user_id),
        )
        .await;

    assert!(
        get_result.is_ok(),
        "User should still exist after deactivation"
    );
    let user = get_result.unwrap();
    assert!(!user.is_active, "User should be deactivated");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_user_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());
    let non_existent_id = Uuid::new_v4();

    let result = service
        .deactivate_user(
            TenantId::from_uuid(tenant_id),
            xavyo_core::UserId::from_uuid(non_existent_id),
        )
        .await;

    assert!(result.is_err(), "Delete non-existent user should fail");

    cleanup_test_tenant(&pool, tenant_id).await;
}
