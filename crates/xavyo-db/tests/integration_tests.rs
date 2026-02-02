//! Integration tests for xavyo-db tenant isolation.
//!
//! These tests require a running PostgreSQL instance.
//! Run with: `cargo test -p xavyo-db --features integration`
//!
//! Prerequisites:
//! 1. Start the test environment: `./scripts/dev-env.sh start`
//! 2. Set DATABASE_URL (optional, defaults to test database)
//!
//! The test database URL defaults to:
//! `postgres://xavyo:xavyo_test_password@localhost:5432/xavyo_test`

#![cfg(feature = "integration")]

mod common;

use common::TestContext;
use xavyo_core::TenantId;
use xavyo_db::{clear_tenant_context, get_current_tenant, set_tenant_context};

#[tokio::test]
async fn test_connection_pool() {
    let ctx = TestContext::new().await;

    // Verify we can execute a simple query
    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(ctx.pool.inner())
        .await
        .expect("Failed to execute query");

    assert_eq!(row.0, 1);
}

#[tokio::test]
async fn test_migrations() {
    let ctx = TestContext::new().await;

    // Verify tenants table exists
    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM tenants")
        .fetch_one(ctx.pool.inner())
        .await;
    assert!(result.is_ok(), "tenants table should exist");

    // Verify users table exists
    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(ctx.pool.inner())
        .await;
    assert!(result.is_ok(), "users table should exist");
}

#[tokio::test]
async fn test_seed_data_accessible() {
    let ctx = TestContext::new().await;

    // Verify seed tenant exists (tenants table allows reads without context)
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001'::uuid",
    )
    .fetch_one(ctx.pool.inner())
    .await
    .expect("Failed to query tenants");
    assert_eq!(row.0, 1, "Seed tenant should exist");

    // To query users, we need to set tenant context (RLS is enforced)
    let seed_tenant_id =
        TenantId::from_uuid(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");
    set_tenant_context(&mut *tx, seed_tenant_id)
        .await
        .expect("Failed to set tenant context");

    // Verify seed admin user exists
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(TestContext::seed_admin_email())
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to query users");
    assert_eq!(row.0, 1, "Seed admin user should exist");

    tx.rollback().await.expect("Failed to rollback");
}

#[tokio::test]
async fn test_tenant_context_set_and_get() {
    let ctx = TestContext::new().await;

    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");

    // Initially no context
    let current = get_current_tenant(&mut *tx)
        .await
        .expect("Failed to get tenant context");
    assert!(current.is_none(), "Initial context should be None");

    // Set context
    let tenant_id = TenantId::new();
    set_tenant_context(&mut *tx, tenant_id)
        .await
        .expect("Failed to set tenant context");

    // Verify context is set
    let current = get_current_tenant(&mut *tx)
        .await
        .expect("Failed to get tenant context");
    assert_eq!(current, Some(tenant_id), "Context should match set value");

    // Clear context
    clear_tenant_context(&mut *tx)
        .await
        .expect("Failed to clear tenant context");

    // Verify context is cleared
    let current = get_current_tenant(&mut *tx)
        .await
        .expect("Failed to get tenant context");
    assert!(current.is_none(), "Context should be None after clear");

    tx.rollback().await.expect("Failed to rollback");
}

#[tokio::test]
async fn test_tenant_isolation_cannot_read_other_tenant_data() {
    let ctx = TestContext::new().await;

    // Use unique identifiers to avoid conflicts with parallel tests
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let slug_a = format!("tenant-iso-a-{}", unique_id);
    let slug_b = format!("tenant-iso-b-{}", unique_id);
    let email_a = format!("alice-{}@test.com", unique_id);
    let email_b = format!("bob-{}@test.com", unique_id);

    // Create two tenants
    let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
    let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

    // Create users for each tenant (bypassing RLS for setup via admin pool)
    ctx.create_user(tenant_a, &email_a, "hash_a").await;
    ctx.create_user(tenant_b, &email_b, "hash_b").await;

    // Now test isolation: set context to Tenant B
    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");
    set_tenant_context(&mut *tx, tenant_b)
        .await
        .expect("Failed to set context");

    // Count visible users - should only see Tenant B's user
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to count users");

    assert_eq!(row.0, 1, "Should only see 1 user (Tenant B's)");

    // Verify we see the correct user
    let row: (String,) = sqlx::query_as("SELECT email FROM users")
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to fetch user");

    assert_eq!(row.0, email_b, "Should see Tenant B's user, not Tenant A's");

    tx.rollback().await.expect("Failed to rollback");
    // Note: No cleanup() - using unique IDs prevents conflicts with parallel tests
}

#[tokio::test]
async fn test_tenant_can_read_own_data() {
    let ctx = TestContext::new().await;

    // Use unique slug to avoid conflicts with parallel tests
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let slug = format!("tenant-own-{}", unique_id);

    // Create tenant and users
    let tenant_a = ctx.create_tenant("Tenant A", &slug).await;
    let email1 = format!("alice-{}@test.com", unique_id);
    let email2 = format!("charlie-{}@test.com", unique_id);
    ctx.create_user(tenant_a, &email1, "hash_a").await;
    ctx.create_user(tenant_a, &email2, "hash_c").await;

    // Set context to Tenant A
    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");
    set_tenant_context(&mut *tx, tenant_a)
        .await
        .expect("Failed to set context");

    // Count visible users - should see both Tenant A's users
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to count users");

    assert_eq!(row.0, 2, "Should see both of Tenant A's users");

    tx.rollback().await.expect("Failed to rollback");
    // Note: No cleanup() - using unique IDs prevents conflicts with parallel tests
}

#[tokio::test]
async fn test_no_context_returns_no_rows() {
    let ctx = TestContext::new().await;

    // Use unique identifier to avoid conflicts with parallel tests
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let slug = format!("tenant-noctx-{}", unique_id);
    let email = format!("alice-{}@test.com", unique_id);

    // Create tenant and user
    let tenant_a = ctx.create_tenant("Tenant A", &slug).await;
    ctx.create_user(tenant_a, &email, "hash_a").await;

    // Query WITHOUT setting tenant context
    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");

    // Ensure no context is set
    clear_tenant_context(&mut *tx)
        .await
        .expect("Failed to clear context");

    // Count visible users - should be 0 (fail-safe default deny)
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to count users");

    assert_eq!(row.0, 0, "Should see 0 users when no tenant context is set");

    tx.rollback().await.expect("Failed to rollback");
    // Note: No cleanup() - using unique IDs prevents conflicts with parallel tests
}

#[tokio::test]
async fn test_tenant_cannot_insert_for_other_tenant() {
    let ctx = TestContext::new().await;

    // Use unique identifiers to avoid conflicts with parallel tests
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let slug_a = format!("tenant-ins-a-{}", unique_id);
    let slug_b = format!("tenant-ins-b-{}", unique_id);

    // Create two tenants
    let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
    let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

    // Set context to Tenant A
    let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");
    set_tenant_context(&mut *tx, tenant_a)
        .await
        .expect("Failed to set context");

    // Try to insert a user for Tenant B (should fail due to RLS WITH CHECK)
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_b.as_uuid()) // Wrong tenant!
    .bind(format!("malicious-{}@test.com", unique_id))
    .bind("hash")
    .execute(&mut *tx)
    .await;

    // The insert should fail because tenant_id doesn't match current_tenant
    assert!(
        result.is_err(),
        "INSERT for wrong tenant should fail due to RLS"
    );

    tx.rollback().await.expect("Failed to rollback");
    // Note: No cleanup() - using unique IDs prevents conflicts with parallel tests
}
