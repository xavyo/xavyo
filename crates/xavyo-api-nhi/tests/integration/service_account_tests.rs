//! Service account lifecycle integration tests.
//!
//! User Story 1: Service Account Lifecycle Tests
//!
//! Tests the complete service account lifecycle including:
//! - Create service account
//! - Read service account
//! - Update service account
//! - Suspend service account
//! - Reactivate service account
//! - Delete service account

use super::common::{
    create_test_pool, create_test_service_account, create_test_tenant, create_test_user,
    unique_email, unique_service_account_name, ServiceAccountRow,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Helper to set up test tenant and owner.
async fn setup_test_env(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant_id = create_test_tenant(pool).await;
    let owner_id = create_test_user(pool, tenant_id, &unique_email()).await;
    (tenant_id, owner_id)
}

/// Test: Create service account successfully.
///
/// Given no service account exists,
/// When creating a new service account via the database,
/// Then the service account is created with correct attributes.
#[tokio::test]
    #[ignore]
async fn test_create_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Verify the service account was created
    let row: ServiceAccountRow = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, purpose, owner_id, status::text as status
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    assert_eq!(row.id, sa_id);
    assert_eq!(row.tenant_id, tenant_id);
    assert_eq!(row.name, sa_name);
    assert_eq!(row.owner_id, owner_id);
    assert_eq!(row.status, "active");
}

/// Test: Get service account by ID.
///
/// Given a service account exists,
/// When fetching it by ID,
/// Then the correct service account is returned.
#[tokio::test]
    #[ignore]
async fn test_get_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Fetch the service account
    let row: ServiceAccountRow = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, purpose, owner_id, status::text as status
        FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    assert_eq!(row.id, sa_id);
    assert_eq!(row.name, sa_name);
    assert!(row.purpose.contains(&sa_name));
    assert_eq!(row.owner_id, owner_id);
    assert_eq!(row.status, "active");
}

/// Test: Update service account attributes.
///
/// Given a service account exists,
/// When updating its attributes,
/// Then the attributes are updated correctly.
#[tokio::test]
    #[ignore]
async fn test_update_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Update the service account
    let new_purpose = "Updated purpose for testing";
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET purpose = $1, updated_at = NOW()
        WHERE id = $2 AND tenant_id = $3
        ",
    )
    .bind(new_purpose)
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Update should succeed");

    // Verify the update
    let row = sqlx::query(
        r"
        SELECT purpose
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    let purpose: String = row.get("purpose");
    assert_eq!(purpose, new_purpose);
}

/// Test: Suspend service account.
///
/// Given an active service account,
/// When suspending it,
/// Then the status changes to suspended.
#[tokio::test]
    #[ignore]
async fn test_suspend_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Suspend the service account
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET status = 'suspended', updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Suspend should succeed");

    // Verify the status
    let row = sqlx::query(
        r"
        SELECT status::text as status
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    let status: String = row.get("status");
    assert_eq!(status, "suspended");
}

/// Test: Reactivate suspended service account.
///
/// Given a suspended service account,
/// When reactivating it,
/// Then the status changes back to active.
#[tokio::test]
    #[ignore]
async fn test_reactivate_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // First suspend
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET status = 'suspended', updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Suspend should succeed");

    // Then reactivate
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET status = 'active', updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Reactivate should succeed");

    // Verify the status
    let row = sqlx::query(
        r"
        SELECT status::text as status
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    let status: String = row.get("status");
    assert_eq!(status, "active");
}

/// Test: Delete service account.
///
/// Given a service account exists,
/// When deleting it,
/// Then the account is removed.
#[tokio::test]
    #[ignore]
async fn test_delete_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Verify it exists
    let exists_before: (i64,) = sqlx::query_as(
        r"
        SELECT COUNT(*) as count
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Count should work");

    assert_eq!(exists_before.0, 1);

    // Delete the service account
    sqlx::query(
        r"
        DELETE FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Delete should succeed");

    // Verify it's gone
    let exists_after: (i64,) = sqlx::query_as(
        r"
        SELECT COUNT(*) as count
        FROM gov_service_accounts
        WHERE id = $1
        ",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("Count should work");

    assert_eq!(exists_after.0, 0);
}
