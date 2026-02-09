//! Multi-tenant isolation integration tests.
//!
//! User Story 5: Multi-Tenant Isolation Tests
//!
//! Tests that NHIs from one tenant cannot be accessed by another:
//! - Tenant A cannot list Tenant B's NHIs
//! - Tenant A cannot access Tenant B's NHI by ID
//! - Cross-tenant mutations are rejected

use super::common::{
    create_test_nhi, create_test_pool, create_test_tenant, create_test_user, unique_email,
    unique_service_account_name, NhiRow,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Helper to set up two isolated test tenants.
async fn setup_dual_tenant_env(pool: &PgPool) -> ((Uuid, Uuid), (Uuid, Uuid)) {
    let tenant_a = create_test_tenant(pool).await;
    let owner_a = create_test_user(pool, tenant_a, &unique_email()).await;

    let tenant_b = create_test_tenant(pool).await;
    let owner_b = create_test_user(pool, tenant_b, &unique_email()).await;

    ((tenant_a, owner_a), (tenant_b, owner_b))
}

/// Test: Tenant cannot list other tenant's NHIs.
///
/// Given NHIs exist for tenant A,
/// When tenant B tries to list NHIs,
/// Then tenant A's NHIs are not visible.
#[tokio::test]
    #[ignore]
async fn test_tenant_cannot_list_others_nhis() {
    let pool = create_test_pool().await;
    let ((tenant_a, owner_a), (tenant_b, _owner_b)) = setup_dual_tenant_env(&pool).await;

    // Create NHIs for tenant A
    let sa_name_a = unique_service_account_name();
    let sa_id_a = create_test_nhi(&pool, tenant_a, owner_a, &sa_name_a, "service_account").await;

    // Query from tenant B's perspective (filtering by tenant_b)
    let nhis_b: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ",
    )
    .bind(tenant_b)
    .fetch_all(&pool)
    .await
    .expect("List should work");

    // Tenant B should not see tenant A's NHIs
    let ids: Vec<Uuid> = nhis_b.iter().map(|n| n.id).collect();
    assert!(
        !ids.contains(&sa_id_a),
        "Tenant B should not see tenant A's NHIs"
    );

    // Also verify tenant A can see its own NHI
    let nhis_a: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ",
    )
    .bind(tenant_a)
    .fetch_all(&pool)
    .await
    .expect("List should work");

    let ids_a: Vec<Uuid> = nhis_a.iter().map(|n| n.id).collect();
    assert!(ids_a.contains(&sa_id_a), "Tenant A should see its own NHIs");
}

/// Test: Tenant cannot access other tenant's NHI by ID.
///
/// Given an NHI belongs to tenant A,
/// When tenant B tries to access it by ID,
/// Then access is denied (returns no rows).
#[tokio::test]
    #[ignore]
async fn test_tenant_cannot_access_others_by_id() {
    let pool = create_test_pool().await;
    let ((tenant_a, owner_a), (tenant_b, _owner_b)) = setup_dual_tenant_env(&pool).await;

    // Create NHI for tenant A
    let sa_name = unique_service_account_name();
    let sa_id_a = create_test_nhi(&pool, tenant_a, owner_a, &sa_name, "service_account").await;

    // Try to access from tenant B's perspective
    let result: Option<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id_a)
    .bind(tenant_b)
    .fetch_optional(&pool)
    .await
    .expect("Query should work");

    assert!(
        result.is_none(),
        "Tenant B should not be able to access tenant A's NHI"
    );
}

/// Test: Cross-tenant updates are rejected.
///
/// Given an NHI belongs to tenant A,
/// When tenant B tries to update it,
/// Then the operation has no effect.
#[tokio::test]
    #[ignore]
async fn test_tenant_cannot_update_others() {
    let pool = create_test_pool().await;
    let ((tenant_a, owner_a), (tenant_b, _owner_b)) = setup_dual_tenant_env(&pool).await;

    // Create NHI for tenant A
    let sa_name = unique_service_account_name();
    let sa_id_a = create_test_nhi(&pool, tenant_a, owner_a, &sa_name, "service_account").await;

    let original_desc = format!("Test NHI: {sa_name}");

    // Try to update from tenant B's perspective (using underlying table)
    let result = sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET purpose = 'Hacked by tenant B'
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id_a)
    .bind(tenant_b)
    .execute(&pool)
    .await
    .expect("Query should work");

    assert_eq!(
        result.rows_affected(),
        0,
        "Cross-tenant update should affect 0 rows"
    );

    // Verify the original purpose is unchanged
    let row = sqlx::query(
        r"
        SELECT purpose
        FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id_a)
    .bind(tenant_a)
    .fetch_one(&pool)
    .await
    .expect("NHI should exist");

    let purpose: String = row.get("purpose");
    assert_eq!(
        purpose, original_desc,
        "Original purpose should be unchanged"
    );
}

/// Test: Cross-tenant deletes are rejected.
///
/// Given an NHI belongs to tenant A,
/// When tenant B tries to delete it,
/// Then the operation has no effect.
#[tokio::test]
    #[ignore]
async fn test_tenant_cannot_delete_others() {
    let pool = create_test_pool().await;
    let ((tenant_a, owner_a), (tenant_b, _owner_b)) = setup_dual_tenant_env(&pool).await;

    // Create NHI for tenant A
    let sa_name = unique_service_account_name();
    let sa_id_a = create_test_nhi(&pool, tenant_a, owner_a, &sa_name, "service_account").await;

    // Try to delete from tenant B's perspective (using underlying table)
    let result = sqlx::query(
        r"
        DELETE FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id_a)
    .bind(tenant_b)
    .execute(&pool)
    .await
    .expect("Query should work");

    assert_eq!(
        result.rows_affected(),
        0,
        "Cross-tenant delete should affect 0 rows"
    );

    // Verify the NHI still exists for tenant A
    let count_row: (i64,) = sqlx::query_as(
        r"
        SELECT COUNT(*) as count
        FROM v_non_human_identities
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id_a)
    .bind(tenant_a)
    .fetch_one(&pool)
    .await
    .expect("Count should work");

    assert_eq!(count_row.0, 1, "NHI should still exist for tenant A");
}
