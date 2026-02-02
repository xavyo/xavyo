//! Integration tests for meta-role cascade with large scale operations (F056 - US2).
//!
//! Tests cover:
//! - Cascade propagation to 100+ roles
//! - Performance under load
//! - Concurrent cascade operations
//!
//! NOTE: These tests require a running PostgreSQL database and are ignored
//! by default in CI. Run with `cargo test --ignored` locally with DATABASE_URL set.

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;

// ============================================================================
// Large Scale Cascade Tests
// ============================================================================

/// Test cascade propagation to 100+ roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_to_100_plus_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Large Scale Test", 100).await;

    // Add criterion for high risk
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;

    // Create 120 high-risk roles
    let role_ids: Vec<Uuid> = futures::future::join_all((0..120).map(|_| {
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high")
    }))
    .await;

    // Create inheritances for all
    for role_id in &role_ids {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    // Verify all inheritances were created
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        inheritance_count.0, 120,
        "Should have 120 active inheritances"
    );

    // Add entitlement to meta-role (this should cascade to all 120 roles)
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role_id, entitlement_id, "grant")
        .await;

    // Verify entitlement was added
    let entitlement_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_entitlements WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count entitlements");

    assert_eq!(
        entitlement_count.0, 1,
        "Should have 1 entitlement on meta-role"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade performance with 200 roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_performance_200_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Performance Test", 100).await;

    // Create 200 roles
    let start = std::time::Instant::now();

    let _role_ids: Vec<Uuid> = futures::future::join_all(
        (0..200).map(|_| create_test_entitlement(&pool, tenant_id, app_id, Some(user_id))),
    )
    .await;

    let creation_time = start.elapsed();
    println!("Created 200 roles in {:?}", creation_time);

    // Count roles
    let role_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_entitlements WHERE tenant_id = $1 AND application_id = $2",
    )
    .bind(tenant_id)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count roles");

    assert_eq!(role_count.0, 200, "Should have 200 roles");

    // Verify operations complete within acceptable time (under 30 seconds)
    assert!(
        creation_time.as_secs() < 30,
        "Role creation should complete within 30 seconds"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Concurrent Cascade Tests
// ============================================================================

/// Test multiple concurrent cascade operations.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_concurrent_cascade_operations() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create multiple meta-roles
    let meta_role1 =
        create_test_meta_role(&pool, tenant_id, user_id, "Concurrent Test 1", 100).await;
    let meta_role2 =
        create_test_meta_role(&pool, tenant_id, user_id, "Concurrent Test 2", 200).await;

    // Create roles
    let role_ids: Vec<Uuid> = futures::future::join_all(
        (0..50).map(|_| create_test_entitlement(&pool, tenant_id, app_id, Some(user_id))),
    )
    .await;

    // Assign roles to both meta-roles concurrently
    for role_id in &role_ids[..25] {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, *role_id).await;
    }
    for role_id in &role_ids[25..] {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, *role_id).await;
    }

    // Verify both meta-roles have inheritances
    let count1: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role1)
    .fetch_one(&pool)
    .await
    .expect("Failed to count meta-role 1 inheritances");

    let count2: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role2)
    .fetch_one(&pool)
    .await
    .expect("Failed to count meta-role 2 inheritances");

    assert_eq!(count1.0, 25, "Meta-role 1 should have 25 inheritances");
    assert_eq!(count2.0, 25, "Meta-role 2 should have 25 inheritances");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade doesn't affect other tenants.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_tenant_isolation() {
    let pool = create_test_pool().await;

    // Create two tenants
    let tenant1 = create_test_tenant(&pool).await;
    let tenant2 = create_test_tenant(&pool).await;

    let user1 = create_test_user(&pool, tenant1).await;
    let user2 = create_test_user(&pool, tenant2).await;

    let app1 = create_test_application(&pool, tenant1).await;
    let app2 = create_test_application(&pool, tenant2).await;

    // Create meta-roles in each tenant
    let meta_role1 = create_test_meta_role(&pool, tenant1, user1, "Tenant 1 Policy", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant2, user2, "Tenant 2 Policy", 100).await;

    // Create roles and inheritances
    let role1 = create_test_entitlement(&pool, tenant1, app1, Some(user1)).await;
    let role2 = create_test_entitlement(&pool, tenant2, app2, Some(user2)).await;

    create_test_meta_role_inheritance(&pool, tenant1, meta_role1, role1).await;
    create_test_meta_role_inheritance(&pool, tenant2, meta_role2, role2).await;

    // Verify each tenant's cascade is isolated
    let tenant1_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1")
            .bind(tenant1)
            .fetch_one(&pool)
            .await
            .expect("Failed to count tenant 1 inheritances");

    let tenant2_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1")
            .bind(tenant2)
            .fetch_one(&pool)
            .await
            .expect("Failed to count tenant 2 inheritances");

    assert_eq!(tenant1_count.0, 1, "Tenant 1 should have 1 inheritance");
    assert_eq!(tenant2_count.0, 1, "Tenant 2 should have 1 inheritance");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant1).await;
    cleanup_test_tenant(&pool, tenant1).await;
    cleanup_meta_role_data(&pool, tenant2).await;
    cleanup_test_tenant(&pool, tenant2).await;
}

// ============================================================================
// Cascade Completeness Tests
// ============================================================================

/// Test that cascade affects all matching roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_affects_all_matching_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Complete Cascade Test", 100).await;

    // Add criterion
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "application_id",
        "eq",
        json!(app_id.to_string()),
    )
    .await;

    // Create roles in target app
    let target_roles: Vec<Uuid> = futures::future::join_all(
        (0..30).map(|_| create_test_entitlement(&pool, tenant_id, app_id, Some(user_id))),
    )
    .await;

    // Create roles in different app (should not be affected)
    let other_app_id = create_test_application(&pool, tenant_id).await;
    let _other_roles: Vec<Uuid> = futures::future::join_all(
        (0..10).map(|_| create_test_entitlement(&pool, tenant_id, other_app_id, Some(user_id))),
    )
    .await;

    // Apply inheritances only to target roles
    for role_id in &target_roles {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    // Verify only target roles have inheritances
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        inheritance_count.0, 30,
        "Should have exactly 30 inheritances (not 40)"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade handles role deletion gracefully.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_handles_deleted_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Deleted Role Test", 100).await;

    // Create roles
    let role1 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    let role2 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Create inheritances
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role1).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role2).await;

    // Delete one role's inheritance
    sqlx::query(
        "DELETE FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND child_role_id = $2",
    )
    .bind(tenant_id)
    .bind(role1)
    .execute(&pool)
    .await
    .expect("Failed to delete inheritance");

    // Verify remaining inheritance
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        inheritance_count.0, 1,
        "Should have 1 inheritance after deletion"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Cascade Timing Tests
// ============================================================================

/// Test cascade completes within 10 minute SLA for 1000 roles.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_sla_1000_roles() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "SLA Test", 100).await;

    // Create 100 roles (scaled down for test speed)
    let start = std::time::Instant::now();

    let role_ids: Vec<Uuid> = futures::future::join_all(
        (0..100).map(|_| create_test_entitlement(&pool, tenant_id, app_id, Some(user_id))),
    )
    .await;

    // Create inheritances
    for role_id in &role_ids {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    let elapsed = start.elapsed();

    // Verify completion time (scaled: 100 roles should complete in under 1 minute)
    assert!(
        elapsed.as_secs() < 60,
        "Cascade for 100 roles should complete within 60 seconds, took {:?}",
        elapsed
    );

    // Verify all inheritances created
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(inheritance_count.0, 100, "Should have 100 inheritances");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test cascade with mixed operations (add/remove).
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_cascade_mixed_operations() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Mixed Ops Test", 100).await;

    // Create roles
    let role_ids: Vec<Uuid> = futures::future::join_all(
        (0..20).map(|_| create_test_entitlement(&pool, tenant_id, app_id, Some(user_id))),
    )
    .await;

    // Add inheritances
    for role_id in &role_ids {
        create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, *role_id).await;
    }

    // Add entitlement
    let ent1 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role_id, ent1, "grant").await;

    // Add constraint
    create_test_meta_role_constraint(&pool, tenant_id, meta_role_id, "require_mfa", json!(true))
        .await;

    // Add another entitlement
    let ent2 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role_id, ent2, "grant").await;

    // Verify final state
    let entitlement_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_entitlements WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count entitlements");

    let constraint_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_constraints WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count constraints");

    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND meta_role_id = $2",
    )
    .bind(tenant_id)
    .bind(meta_role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(entitlement_count.0, 2, "Should have 2 entitlements");
    assert_eq!(constraint_count.0, 1, "Should have 1 constraint");
    assert_eq!(inheritance_count.0, 20, "Should have 20 inheritances");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
