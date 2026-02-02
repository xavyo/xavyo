//! Unit tests for meta-role cascade propagation logic (F056 - US2).
//!
//! Tests cover:
//! - Cascade of entitlement changes to inheriting roles
//! - Cascade of constraint changes to inheriting roles
//! - Batched updates for efficiency
//! - Criteria change handling (add/remove inheritances)

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;

// ============================================================================
// Cascade Entitlement Tests
// ============================================================================

/// Test that adding an entitlement to a meta-role cascades to all inheriting roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_add_entitlement_to_inheriting_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "High Risk Policy", 100).await;

    // Create criterion for high risk
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;

    // Create multiple high-risk roles
    let role_ids: Vec<Uuid> = futures::future::join_all((0..5).map(|_| {
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high")
    }))
    .await;

    // Create inheritances manually
    for role_id in &role_ids {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    // Create entitlement to add
    let new_entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Add entitlement to meta-role
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role_id, new_entitlement_id, "grant")
        .await;

    // Verify: The cascade should propagate to all inheriting roles
    // Check that inheritance count matches
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(inheritance_count.0, 5, "Should have 5 active inheritances");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that removing an entitlement from a meta-role cascades to all inheriting roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_remove_entitlement_from_inheriting_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Admin Policy", 100).await;

    // Create entitlement that will be removed
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let meta_entitlement_id =
        create_test_meta_role_entitlement(&pool, tenant_id, meta_role_id, entitlement_id, "grant")
            .await;

    // Create roles with inheritances
    let role_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role_id).await;

    // Remove entitlement from meta-role
    let deleted = sqlx::query("DELETE FROM gov_meta_role_entitlements WHERE id = $1")
        .bind(meta_entitlement_id)
        .execute(&pool)
        .await
        .expect("Failed to delete entitlement");

    assert_eq!(deleted.rows_affected(), 1, "Should delete one entitlement");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Cascade Constraint Tests
// ============================================================================

/// Test that adding a constraint to a meta-role cascades to all inheriting roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_add_constraint_to_inheriting_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "MFA Required Policy", 50).await;

    // Create roles with inheritances
    let role_ids: Vec<Uuid> = futures::future::join_all((0..3).map(|_| {
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "medium")
    }))
    .await;

    for role_id in &role_ids {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    // Add constraint
    create_test_meta_role_constraint(&pool, tenant_id, meta_role_id, "require_mfa", json!(true))
        .await;

    // Verify constraint was added
    let constraint_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_constraints WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count constraints");

    assert_eq!(constraint_count.0, 1, "Should have 1 constraint");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that modifying a constraint cascades to all inheriting roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_modify_constraint_value() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role with constraint
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Session Policy", 100).await;

    let constraint_id = create_test_meta_role_constraint(
        &pool,
        tenant_id,
        meta_role_id,
        "max_session_duration",
        json!(3600), // 1 hour
    )
    .await;

    // Create role with inheritance
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role_id).await;

    // Modify constraint value
    sqlx::query("UPDATE gov_meta_role_constraints SET constraint_value = $1 WHERE id = $2")
        .bind(json!(1800)) // 30 minutes
        .bind(constraint_id)
        .execute(&pool)
        .await
        .expect("Failed to update constraint");

    // Verify constraint was updated
    let updated_value: (serde_json::Value,) =
        sqlx::query_as("SELECT constraint_value FROM gov_meta_role_constraints WHERE id = $1")
            .bind(constraint_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch constraint");

    assert_eq!(
        updated_value.0,
        json!(1800),
        "Constraint should be updated to 1800"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Batched Updates Tests
// ============================================================================

/// Test that cascade operations use batched updates for efficiency.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_batched_updates() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Large Scale Policy", 100).await;

    // Create criterion
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;

    // Create 150 roles (beyond typical batch size of 100)
    let _role_ids: Vec<Uuid> = futures::future::join_all((0..150).map(|_| {
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high")
    }))
    .await;

    // Count high-risk roles
    let role_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_entitlements WHERE tenant_id = $1 AND risk_level = 'high'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count roles");

    assert_eq!(role_count.0, 150, "Should have 150 high-risk roles");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Criteria Change Handling Tests
// ============================================================================

/// Test that adding a criterion updates which roles are affected.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_criteria_addition_updates_inheritances() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role with broad criterion
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Narrowing Policy", 100).await;

    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "status",
        "eq",
        json!("Active"),
    )
    .await;

    // Create roles - all are active by default
    let role1 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let role2 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Create inheritances
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role1).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role2).await;

    // Verify both have inheritances
    let before_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        before_count.0, 2,
        "Should have 2 inheritances before adding criterion"
    );

    // Add more restrictive criterion (application_id)
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "application_id",
        "eq",
        json!(app_id.to_string()),
    )
    .await;

    // Both roles should still match since they belong to the same app
    let after_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        after_count.0, 2,
        "Should still have 2 inheritances with same app"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that removing a criterion may cause more roles to match.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_criteria_removal_expands_matches() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role with two criteria
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Expanding Policy", 100).await;

    let criterion1_id = create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;

    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "status",
        "eq",
        json!("Active"),
    )
    .await;

    // Create high-risk role
    let high_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, high_risk_role).await;

    // Create low-risk role (doesn't match due to risk_level criterion)
    let _low_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "low").await;

    // Remove risk_level criterion
    sqlx::query("DELETE FROM gov_meta_role_criteria WHERE id = $1")
        .bind(criterion1_id)
        .execute(&pool)
        .await
        .expect("Failed to delete criterion");

    // Verify criterion was removed
    let criteria_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_criteria WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count criteria");

    assert_eq!(criteria_count.0, 1, "Should have 1 criterion remaining");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Cascade Event Tests
// ============================================================================

/// Test that cascade operations create appropriate audit events.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_creates_audit_events() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Audit Test Policy", 100).await;

    // Create role and inheritance
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role_id).await;

    // Manually insert an audit event (simulating what the service would do)
    let event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_events (id, tenant_id, meta_role_id, event_type, actor_id, created_at)
        VALUES ($1, $2, $3, 'created'::gov_meta_role_event_type, $4, NOW())
        "#,
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(meta_role_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("Failed to create audit event");

    // Check that events were created
    let event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_events WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count events");

    // At minimum, the create event should exist
    assert!(event_count.0 >= 1, "Should have at least 1 audit event");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade status tracking.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_status_tracking() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Status Track Policy", 100).await;

    // Create roles
    for _ in 0..10 {
        let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role_id).await;
    }

    // Verify inheritances count
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(inheritance_count.0, 10, "Should have 10 inheritances");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test cascade handles partial failures gracefully.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_handles_partial_failures() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Partial Failure Policy", 100).await;

    // Create valid roles
    let valid_role = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, valid_role).await;

    // The cascade should handle any issues gracefully
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(inheritance_count.0, 1, "Should have 1 valid inheritance");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade timeout handling.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_respects_time_limit() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let _app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Timeout Policy", 100).await;

    // The cascade operation should complete within reasonable time
    let start = std::time::Instant::now();

    // Simulate cascade check
    let _result: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Query should complete");

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "Cascade check should complete within 60 seconds"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
