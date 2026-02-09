//! Governance (risk/certification) integration tests.
//!
//! User Story 4: Risk Score and Certification Tests
//!
//! Tests governance features including:
//! - Get risk summary
//! - Certify service account
//! - Certification status persistence
//! - Risk score endpoint

use super::common::{
    create_test_nhi, create_test_pool, create_test_service_account, create_test_tenant,
    create_test_user, set_nhi_risk_score, unique_email, unique_service_account_name,
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

/// Test: Get risk summary returns statistics.
///
/// Given NHIs exist with various risk scores,
/// When getting risk summary,
/// Then aggregated statistics are returned.
#[tokio::test]
#[ignore]
async fn test_get_risk_summary() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    // Create NHIs with different risk scores
    let low_risk_name = format!("low-risk-nhi-{}", Uuid::new_v4());
    let low_risk_id = create_test_nhi(
        &pool,
        tenant_id,
        owner_id,
        &low_risk_name,
        "service_account",
    )
    .await;

    // Set low risk score
    set_nhi_risk_score(&pool, tenant_id, low_risk_id, 20).await;

    let high_risk_name = format!("high-risk-nhi-{}", Uuid::new_v4());
    let high_risk_id = create_test_nhi(
        &pool,
        tenant_id,
        owner_id,
        &high_risk_name,
        "service_account",
    )
    .await;

    // Set high risk score
    set_nhi_risk_score(&pool, tenant_id, high_risk_id, 80).await;

    // Query risk distribution
    let row = sqlx::query(
        r"
        SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE risk_score < 40) as low_risk,
            COUNT(*) FILTER (WHERE risk_score >= 40 AND risk_score < 70) as medium_risk,
            COUNT(*) FILTER (WHERE risk_score >= 70) as high_risk
        FROM v_non_human_identities
        WHERE tenant_id = $1
        ",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Risk query should succeed");

    let total: i64 = row.get("total");
    let low_risk: i64 = row.get("low_risk");
    let high_risk: i64 = row.get("high_risk");

    assert!(total >= 2, "Should have at least 2 NHIs");
    assert!(low_risk >= 1, "Should have at least 1 low risk NHI");
    assert!(high_risk >= 1, "Should have at least 1 high risk NHI");
}

/// Test: Certify service account marks it as certified.
///
/// Given an uncertified NHI,
/// When certifying it,
/// Then the NHI is marked as certified with timestamp.
#[tokio::test]
#[ignore]
async fn test_certify_service_account() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Certify the service account
    let now = Utc::now();
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET last_certified_at = $1, certified_by = $2, updated_at = NOW()
        WHERE id = $3 AND tenant_id = $4
        ",
    )
    .bind(now)
    .bind(owner_id)
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Certification should succeed");

    // Verify certification
    let row = sqlx::query(
        r"
        SELECT last_certified_at, certified_by
        FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    let last_certified_at: Option<chrono::DateTime<Utc>> = row.get("last_certified_at");
    let certified_by: Option<Uuid> = row.get("certified_by");

    assert!(
        last_certified_at.is_some(),
        "Should have certification timestamp"
    );
    assert_eq!(
        certified_by,
        Some(owner_id),
        "Should have certifier recorded"
    );
}

/// Test: Certification status is persisted and visible.
///
/// Given a certified NHI,
/// When getting its details,
/// Then certification status is correctly reflected.
#[tokio::test]
#[ignore]
async fn test_certification_status_persisted() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let sa_name = unique_service_account_name();
    let sa_id = create_test_service_account(&pool, tenant_id, owner_id, &sa_name).await;

    // Certify
    let cert_time = Utc::now();
    sqlx::query(
        r"
        UPDATE gov_service_accounts
        SET last_certified_at = $1, certified_by = $2, updated_at = NOW()
        WHERE id = $3 AND tenant_id = $4
        ",
    )
    .bind(cert_time)
    .bind(owner_id)
    .bind(sa_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Certification should succeed");

    // Fetch and verify
    let row = sqlx::query(
        r"
        SELECT id, name, last_certified_at, certified_by
        FROM gov_service_accounts
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Service account should exist");

    let id: Uuid = row.get("id");
    let last_certified_at: Option<chrono::DateTime<Utc>> = row.get("last_certified_at");
    let certified_by: Option<Uuid> = row.get("certified_by");

    assert_eq!(id, sa_id);
    assert!(
        last_certified_at.is_some(),
        "Certification time should be persisted"
    );
    assert_eq!(
        certified_by,
        Some(owner_id),
        "Certifier should be persisted"
    );
}

/// Test: Risk score endpoint returns score with factors.
///
/// Given an NHI exists,
/// When getting its risk score,
/// Then a risk score is returned.
#[tokio::test]
#[ignore]
async fn test_risk_score_endpoint() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id) = setup_test_env(&pool).await;

    let nhi_name = unique_service_account_name();
    let nhi_id = create_test_nhi(&pool, tenant_id, owner_id, &nhi_name, "service_account").await;

    // Set a specific risk score via gov_nhi_risk_scores
    set_nhi_risk_score(&pool, tenant_id, nhi_id, 45).await;

    // Fetch risk score from view
    let row = sqlx::query(
        r"
        SELECT id, name, risk_score
        FROM v_non_human_identities
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(nhi_id)
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("NHI should exist");

    let id: Uuid = row.get("id");
    let risk_score: i32 = row.get("risk_score");

    assert_eq!(id, nhi_id);
    assert_eq!(risk_score, 45);
}
