//! Unified NHI list integration tests.
//!
//! User Story 3: Unified NHI List Tests
//!
//! Tests the unified NHI listing endpoint including:
//! - List all NHIs (service accounts + agents)
//! - Filter by type
//! - Pagination
//! - Get NHI by ID

use super::common::{
    create_test_nhi, create_test_pool, create_test_tenant, create_test_user, unique_agent_name,
    unique_email, unique_service_account_name, NhiRow,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Helper to set up test tenant and owner.
async fn setup_test_env(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant_id = create_test_tenant(pool).await;
    let owner_id = create_test_user(pool, tenant_id, &unique_email()).await;
    (tenant_id, owner_id)
}

/// Test: List all NHIs returns both service accounts and agents.
///
/// Given multiple NHIs exist (service accounts and agents),
/// When listing via unified endpoint,
/// Then all NHIs are returned.
#[tokio::test]
    #[ignore]
async fn test_list_all_nhis() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    // Create service accounts
    let sa1_name = unique_service_account_name();
    let _sa1_id = create_test_nhi(&pool, tenant_id, owner_id, &sa1_name, "service_account").await;

    let sa2_name = unique_service_account_name();
    let _sa2_id = create_test_nhi(&pool, tenant_id, owner_id, &sa2_name, "service_account").await;

    // Create AI agents
    let agent1_name = unique_agent_name();
    let _agent1_id = create_test_nhi(&pool, tenant_id, owner_id, &agent1_name, "ai_agent").await;

    // Query all NHIs for this tenant
    let nhis: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        ",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Should list NHIs");

    // Should have at least 3 NHIs (2 service accounts + 1 agent)
    assert!(nhis.len() >= 3, "Should have at least 3 NHIs");

    // Verify we have both types
    let types: Vec<&str> = nhis.iter().map(|n| n.nhi_type.as_str()).collect();
    assert!(
        types.contains(&"service_account"),
        "Should have service accounts"
    );
    assert!(types.contains(&"ai_agent"), "Should have AI agents");
}

/// Test: Filter NHIs by type.
///
/// Given NHIs exist across multiple types,
/// When filtering by type,
/// Then only matching NHIs are returned.
#[tokio::test]
    #[ignore]
async fn test_filter_by_type() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    // Create mixed NHIs
    let sa_name = unique_service_account_name();
    let _sa_id = create_test_nhi(&pool, tenant_id, owner_id, &sa_name, "service_account").await;

    let agent_name = unique_agent_name();
    let _agent_id = create_test_nhi(&pool, tenant_id, owner_id, &agent_name, "ai_agent").await;

    // Filter for service accounts only
    let sa_nhis: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1 AND nhi_type = 'service_account'
        ",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Should list service accounts");

    for nhi in &sa_nhis {
        assert_eq!(nhi.nhi_type, "service_account");
    }

    // Filter for AI agents only
    let agent_nhis: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1 AND nhi_type = 'ai_agent'
        ",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Should list agents");

    for nhi in &agent_nhis {
        assert_eq!(nhi.nhi_type, "ai_agent");
    }
}

/// Test: Pagination works correctly.
///
/// Given many NHIs exist,
/// When paginating,
/// Then results are correctly paginated.
#[tokio::test]
    #[ignore]
async fn test_pagination() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    // Create 5 NHIs
    for i in 0..5 {
        let name = format!("pagination-test-{}-{}", i, Uuid::new_v4());
        let nhi_type = if i % 2 == 0 {
            "service_account"
        } else {
            "ai_agent"
        };
        create_test_nhi(&pool, tenant_id, owner_id, &name, nhi_type).await;
    }

    // Get total count
    let count_row: (i64,) = sqlx::query_as(
        r"
        SELECT COUNT(*) as count
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Count should work");

    assert!(count_row.0 >= 5, "Should have at least 5 NHIs");

    // Get first page (limit 2)
    let page1: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT 2 OFFSET 0
        ",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Page 1 should work");

    assert_eq!(page1.len(), 2, "First page should have 2 items");

    // Get second page (limit 2, offset 2)
    let page2: Vec<NhiRow> = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT 2 OFFSET 2
        ",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Page 2 should work");

    assert_eq!(page2.len(), 2, "Second page should have 2 items");
}

/// Test: Get NHI by ID.
///
/// Given an NHI exists,
/// When fetching by ID,
/// Then the correct NHI is returned.
#[tokio::test]
    #[ignore]
async fn test_get_nhi_by_id() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let nhi_name = unique_service_account_name();
    let nhi_id = create_test_nhi(&pool, tenant_id, owner_id, &nhi_name, "service_account").await;

    // Fetch by ID
    let row: NhiRow = sqlx::query_as(
        r"
        SELECT id, tenant_id, name, nhi_type, owner_id, status, risk_score
        FROM v_non_human_identities
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(nhi_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("NHI should exist");

    assert_eq!(row.id, nhi_id);
    assert_eq!(row.tenant_id, tenant_id);
    assert_eq!(row.name, nhi_name);
    assert_eq!(row.nhi_type, "service_account");
    assert_eq!(row.owner_id, owner_id);
    assert_eq!(row.status, "active");
    // Risk score defaults to 0 when no risk score record exists
    assert!(row.risk_score >= 0, "Risk score should be non-negative");
}
