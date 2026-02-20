//! Integration tests for Pagination and Filtering (User Story 3).
//!
//! These tests verify pagination and filtering for efficient retrieval
//! from large datasets.
//!
//! Run with: `cargo test -p xavyo-api-users --features integration pagination -- --ignored`

mod common;

use common::*;
use xavyo_api_users::models::ListUsersQuery;
use xavyo_api_users::services::UserService;
use xavyo_core::TenantId;

// =========================================================================
// Pagination Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_default_pagination() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create 5 users
    for _ in 0..5 {
        create_test_user(&pool, tenant_id, &unique_email()).await;
    }

    let service = UserService::new(pool.clone());
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: None,
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "List users should succeed");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 5, "Should return all 5 users");
    assert_eq!(list.pagination.total_count, 5);
    assert_eq!(list.pagination.offset, 0);
    assert!(list.pagination.limit >= 5);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_with_custom_page_size() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create 10 users
    for _ in 0..10 {
        create_test_user(&pool, tenant_id, &unique_email()).await;
    }

    let service = UserService::new(pool.clone());
    let query = ListUsersQuery {
        offset: None,
        limit: Some(3),
        email: None,
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "List users with limit should succeed");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 3, "Should return only 3 users");
    assert_eq!(list.pagination.total_count, 10, "Total count should be 10");
    assert_eq!(list.pagination.limit, 3);
    assert!(list.pagination.has_more, "Should have more pages");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_with_offset() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create 10 users
    for _ in 0..10 {
        create_test_user(&pool, tenant_id, &unique_email()).await;
    }

    let service = UserService::new(pool.clone());

    // Get first page
    let query1 = ListUsersQuery {
        offset: Some(0),
        limit: Some(3),
        email: None,
        is_active: None,
    };
    let result1 = service
        .list_users(TenantId::from_uuid(tenant_id), &query1, &[])
        .await
        .unwrap();

    // Get second page
    let query2 = ListUsersQuery {
        offset: Some(3),
        limit: Some(3),
        email: None,
        is_active: None,
    };
    let result2 = service
        .list_users(TenantId::from_uuid(tenant_id), &query2, &[])
        .await
        .unwrap();

    // Verify no overlap between pages
    let ids1: Vec<_> = result1.users.iter().map(|u| u.id).collect();
    let ids2: Vec<_> = result2.users.iter().map(|u| u.id).collect();

    for id in &ids1 {
        assert!(
            !ids2.contains(id),
            "Pages should not have overlapping users"
        );
    }

    assert_eq!(result1.users.len(), 3);
    assert_eq!(result2.users.len(), 3);
    assert_eq!(result2.pagination.offset, 3);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_filter_by_email() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create users with distinct email patterns
    create_test_user(&pool, tenant_id, "alice@company.com").await;
    create_test_user(&pool, tenant_id, "bob@company.com").await;
    create_test_user(&pool, tenant_id, "alice.smith@other.com").await;
    create_test_user(&pool, tenant_id, "charlie@example.org").await;

    let service = UserService::new(pool.clone());

    // Filter by "alice"
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: Some("alice".to_string()),
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "Filter by email should succeed");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 2, "Should find 2 users with 'alice'");
    for user in &list.users {
        assert!(
            user.email.to_lowercase().contains("alice"),
            "All users should contain 'alice' in email"
        );
    }

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_sort_by_created_at() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create users with small delay to ensure different timestamps
    let user1 = create_test_user(&pool, tenant_id, &unique_email()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let user2 = create_test_user(&pool, tenant_id, &unique_email()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let user3 = create_test_user(&pool, tenant_id, &unique_email()).await;

    let service = UserService::new(pool.clone());
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: None,
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "List users should succeed");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 3);

    // Default sort is by created_at DESC (newest first)
    assert_eq!(list.users[0].id, user3, "Newest user should be first");
    assert_eq!(list.users[1].id, user2);
    assert_eq!(list.users[2].id, user1, "Oldest user should be last");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_empty_results() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = UserService::new(pool.clone());
    let query = ListUsersQuery {
        offset: None,
        limit: None,
        email: None,
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "List empty users should succeed");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 0, "Should return empty list");
    assert_eq!(list.pagination.total_count, 0);
    assert!(!list.pagination.has_more);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_users_page_exceeds_available() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create 5 users
    for _ in 0..5 {
        create_test_user(&pool, tenant_id, &unique_email()).await;
    }

    let service = UserService::new(pool.clone());

    // Request page that exceeds available data
    let query = ListUsersQuery {
        offset: Some(100),
        limit: Some(10),
        email: None,
        is_active: None,
    };

    let result = service
        .list_users(TenantId::from_uuid(tenant_id), &query, &[])
        .await;

    assert!(result.is_ok(), "Exceeding page should not error");
    let list = result.unwrap();

    assert_eq!(list.users.len(), 0, "Should return empty list");
    assert_eq!(
        list.pagination.total_count, 5,
        "Total count should still be 5"
    );
    assert!(!list.pagination.has_more);

    cleanup_test_tenant(&pool, tenant_id).await;
}
