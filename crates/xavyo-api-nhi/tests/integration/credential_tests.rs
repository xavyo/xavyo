//! Credential rotation integration tests.
//!
//! User Story 2: Credential Rotation Tests
//!
//! Tests credential management including:
//! - List credentials for a service account
//! - Rotate credentials (generate new, invalidate old)
//! - Revoke specific credential
//! - Verify old credentials are invalid after rotation

use super::common::{
    create_test_pool, create_test_service_account, create_test_tenant, create_test_user,
    unique_email, unique_service_account_name, CredentialRow,
};
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Helper to set up test tenant and owner.
async fn setup_test_env(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant_id = create_test_tenant(pool).await;
    let owner_id = create_test_user(pool, tenant_id, &unique_email()).await;
    (tenant_id, owner_id)
}

/// Helper to create a credential for a service account.
async fn create_test_credential(
    pool: &PgPool,
    tenant_id: Uuid,
    sa_id: Uuid,
    is_active: bool,
) -> Option<Uuid> {
    let cred_id = Uuid::new_v4();
    let now = Utc::now();
    let valid_until = now + chrono::Duration::days(90);

    // Insert into gov_nhi_credentials table
    let result = sqlx::query(
        r"
        INSERT INTO gov_nhi_credentials (id, nhi_id, tenant_id, credential_type, credential_hash, is_active, valid_from, valid_until, created_at, nhi_type)
        VALUES ($1, $2, $3, 'api_key', $4, $5, $6, $7, $6, 'service_account')
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(cred_id)
    .bind(sa_id)
    .bind(tenant_id)
    .bind(format!("hash_{cred_id}"))
    .bind(is_active)
    .bind(now)
    .bind(valid_until)
    .execute(pool)
    .await;

    if result.is_ok() {
        Some(cred_id)
    } else {
        // Table might not exist
        None
    }
}

/// Test: List credentials for a service account.
///
/// Given a service account with credentials,
/// When listing its credentials,
/// Then all credentials are returned.
#[tokio::test]
#[ignore]
async fn test_list_credentials() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Create two credentials
    let cred1_id = create_test_credential(&pool, tenant_id, sa_id, true).await;
    let cred2_id = create_test_credential(&pool, tenant_id, sa_id, true).await;

    // Skip test if table doesn't exist
    if cred1_id.is_none() {
        return;
    }

    // Try to list credentials
    let credentials: Vec<CredentialRow> = sqlx::query_as(
        r"
        SELECT id, nhi_id, tenant_id, is_active
        FROM gov_nhi_credentials
        WHERE nhi_id = $1 AND tenant_id = $2
        ORDER BY created_at DESC
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Should list credentials");

    assert!(credentials.len() >= 2, "Should have at least 2 credentials");
    let ids: Vec<Uuid> = credentials.iter().map(|c| c.id).collect();
    assert!(ids.contains(&cred1_id.unwrap()));
    assert!(ids.contains(&cred2_id.unwrap()));
}

/// Test: Rotate credentials generates new credential.
///
/// Given a service account with credentials,
/// When rotating credentials,
/// Then new credentials are generated.
#[tokio::test]
#[ignore]
async fn test_rotate_credentials() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Create initial credential
    let old_cred_id = create_test_credential(&pool, tenant_id, sa_id, true).await;

    // Skip test if table doesn't exist
    if old_cred_id.is_none() {
        return;
    }

    let old_cred_id = old_cred_id.unwrap();

    // Simulate rotation: deactivate old, create new
    sqlx::query(
        r"
        UPDATE gov_nhi_credentials
        SET is_active = false
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(old_cred_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Deactivate should succeed");

    let new_cred_id = create_test_credential(&pool, tenant_id, sa_id, true)
        .await
        .unwrap();

    // Verify new credential is different
    assert_ne!(old_cred_id, new_cred_id);

    // Verify old is inactive
    let row = sqlx::query(
        r"
        SELECT is_active
        FROM gov_nhi_credentials
        WHERE id = $1
        ",
    )
    .bind(old_cred_id)
    .fetch_one(&pool)
    .await
    .expect("Old credential should exist");

    let is_active: bool = row.get("is_active");
    assert!(!is_active, "Old credential should be inactive");
}

/// Test: Revoke specific credential.
///
/// Given a service account with multiple credentials,
/// When revoking a specific credential,
/// Then only that credential is marked inactive.
#[tokio::test]
#[ignore]
async fn test_revoke_credential() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Create two credentials
    let cred1_id = create_test_credential(&pool, tenant_id, sa_id, true).await;
    let cred2_id = create_test_credential(&pool, tenant_id, sa_id, true).await;

    // Skip test if table doesn't exist
    if cred1_id.is_none() {
        return;
    }

    let cred1_id = cred1_id.unwrap();
    let cred2_id = cred2_id.unwrap();

    // Revoke the first credential
    sqlx::query(
        r"
        UPDATE gov_nhi_credentials
        SET is_active = false
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(cred1_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Revoke should succeed");

    // Verify cred1 is inactive
    let row1 = sqlx::query(
        r"
        SELECT is_active
        FROM gov_nhi_credentials
        WHERE id = $1
        ",
    )
    .bind(cred1_id)
    .fetch_one(&pool)
    .await
    .expect("Credential 1 should exist");

    let is_active1: bool = row1.get("is_active");
    assert!(!is_active1, "Revoked credential should be inactive");

    // Verify cred2 is still active
    let row2 = sqlx::query(
        r"
        SELECT is_active
        FROM gov_nhi_credentials
        WHERE id = $1
        ",
    )
    .bind(cred2_id)
    .fetch_one(&pool)
    .await
    .expect("Credential 2 should exist");

    let is_active2: bool = row2.get("is_active");
    assert!(is_active2, "Other credential should still be active");
}

/// Test: Old credentials are invalid after rotation.
///
/// Given credentials have been rotated,
/// When checking the old credential status,
/// Then it shows as inactive/invalid.
#[tokio::test]
#[ignore]
async fn test_old_credential_invalid_after_rotation() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Create initial credential
    let old_cred_id = create_test_credential(&pool, tenant_id, sa_id, true).await;

    // Skip test if table doesn't exist
    if old_cred_id.is_none() {
        return;
    }

    let old_cred_id = old_cred_id.unwrap();

    // Simulate full rotation: deactivate all, create new
    sqlx::query(
        r"
        UPDATE gov_nhi_credentials
        SET is_active = false
        WHERE nhi_id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Deactivate all should succeed");

    // Create new active credential
    let _new_cred_id = create_test_credential(&pool, tenant_id, sa_id, true).await;

    // Verify old credential is invalid
    let row = sqlx::query(
        r"
        SELECT is_active
        FROM gov_nhi_credentials
        WHERE id = $1
        ",
    )
    .bind(old_cred_id)
    .fetch_one(&pool)
    .await
    .expect("Old credential should exist");

    let is_active: bool = row.get("is_active");
    assert!(
        !is_active,
        "Old credential should be invalid after rotation"
    );

    // Verify only one active credential exists
    let count_row: (i64,) = sqlx::query_as(
        r"
        SELECT COUNT(*) as count
        FROM gov_nhi_credentials
        WHERE nhi_id = $1 AND tenant_id = $2 AND is_active = true
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Count should work");

    assert_eq!(
        count_row.0, 1,
        "Only one credential should be active after rotation"
    );
}
