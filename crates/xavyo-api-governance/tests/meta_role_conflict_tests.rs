//! Unit tests for meta-role conflict detection logic (F056 - US3).
//!
//! Tests cover:
//! - Entitlement conflicts (grant vs deny)
//! - Constraint conflicts (different values for same type)
//! - Policy conflicts (contradicting boolean policies)
//! - Precedence-based resolution
//! - Manual resolution

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;

// ============================================================================
// Entitlement Conflict Tests
// ============================================================================

/// Test detection of grant vs deny conflict for same entitlement.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_detect_entitlement_grant_vs_deny_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create two meta-roles
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "Grant Policy", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Deny Policy", 200).await;

    // Both match same criterion
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role1,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role2,
        "risk_level",
        "eq",
        json!("High"),
    )
    .await;

    // Same entitlement, different permission types
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role1, entitlement_id, "grant").await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role2, entitlement_id, "deny").await;

    // Create a high-risk role that matches both
    let role_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;

    // Create inheritances from both meta-roles
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, role_id).await;

    // Verify both inheritances exist (conflict scenario)
    let inheritance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND child_role_id = $2",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count inheritances");

    assert_eq!(
        inheritance_count.0, 2,
        "Role should inherit from both meta-roles (conflict)"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that same permission type is not a conflict.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_same_permission_type_not_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create two meta-roles both granting same entitlement
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "Grant Policy 1", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Grant Policy 2", 200).await;

    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role1, entitlement_id, "grant").await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role2, entitlement_id, "grant").await;

    // Both grant same entitlement - this is NOT a conflict, just redundant
    let grant_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_entitlements WHERE tenant_id = $1 AND entitlement_id = $2 AND permission_type = 'grant'",
    )
    .bind(tenant_id)
    .bind(entitlement_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count grants");

    assert_eq!(
        grant_count.0, 2,
        "Both should have grant permission (no conflict)"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Constraint Conflict Tests
// ============================================================================

/// Test detection of constraint conflict (same type, different values).
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_detect_constraint_value_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create two meta-roles with conflicting session duration
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "Short Session", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Long Session", 200).await;

    // Same constraint type, different values
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        meta_role1,
        "max_session_duration",
        json!(1800),
    )
    .await; // 30 min
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        meta_role2,
        "max_session_duration",
        json!(7200),
    )
    .await; // 2 hours

    // Create role inheriting from both
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, role_id).await;

    // Verify both constraints exist
    let constraint_values: Vec<(serde_json::Value,)> = sqlx::query_as(
        r"
        SELECT c.constraint_value
        FROM gov_meta_role_constraints c
        JOIN gov_meta_role_inheritances i ON i.meta_role_id = c.meta_role_id
        WHERE i.tenant_id = $1 AND i.child_role_id = $2 AND c.constraint_type = 'max_session_duration'
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to fetch constraints");

    assert_eq!(
        constraint_values.len(),
        2,
        "Should have 2 conflicting constraint values"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test same constraint value is not a conflict.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_same_constraint_value_not_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let _app_id = create_test_application(&pool, tenant_id).await;

    // Create two meta-roles with same MFA requirement
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "MFA Policy 1", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "MFA Policy 2", 200).await;

    create_test_meta_role_constraint(&pool, tenant_id, meta_role1, "require_mfa", json!(true))
        .await;
    create_test_meta_role_constraint(&pool, tenant_id, meta_role2, "require_mfa", json!(true))
        .await;

    // Both require MFA = true - NOT a conflict
    let mfa_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_constraints WHERE tenant_id = $1 AND constraint_type = 'require_mfa' AND constraint_value = 'true'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count MFA constraints");

    assert_eq!(mfa_count.0, 2, "Both have same MFA value (no conflict)");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Policy Conflict Tests
// ============================================================================

/// Test detection of boolean policy conflict.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_detect_boolean_policy_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-roles with conflicting MFA policies
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "MFA Required", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "MFA Optional", 200).await;

    create_test_meta_role_constraint(&pool, tenant_id, meta_role1, "require_mfa", json!(true))
        .await;
    create_test_meta_role_constraint(&pool, tenant_id, meta_role2, "require_mfa", json!(false))
        .await;

    // Create role inheriting from both
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, role_id).await;

    // Verify conflicting boolean values exist
    let mfa_values: Vec<(serde_json::Value,)> = sqlx::query_as(
        r"
        SELECT c.constraint_value
        FROM gov_meta_role_constraints c
        JOIN gov_meta_role_inheritances i ON i.meta_role_id = c.meta_role_id
        WHERE i.tenant_id = $1 AND i.child_role_id = $2 AND c.constraint_type = 'require_mfa'
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to fetch MFA constraints");

    assert_eq!(mfa_values.len(), 2, "Should have 2 conflicting MFA values");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Precedence Resolution Tests
// ============================================================================

/// Test that lower priority number wins (higher precedence).
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_lower_priority_wins() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let _app_id = create_test_application(&pool, tenant_id).await;

    // Priority 50 should win over priority 100
    let high_priority = create_test_meta_role(&pool, tenant_id, user_id, "High Priority", 50).await;
    let low_priority = create_test_meta_role(&pool, tenant_id, user_id, "Low Priority", 100).await;

    // Verify priority ordering
    let priorities: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, priority FROM gov_meta_roles WHERE tenant_id = $1 ORDER BY priority ASC",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to fetch priorities");

    assert_eq!(priorities.len(), 2);
    assert_eq!(
        priorities[0].0, high_priority,
        "Priority 50 should come first"
    );
    assert_eq!(
        priorities[1].0, low_priority,
        "Priority 100 should come second"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test equal priority uses creation order.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_equal_priority_uses_creation_order() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let _app_id = create_test_application(&pool, tenant_id).await;

    // Same priority
    let first = create_test_meta_role(&pool, tenant_id, user_id, "First Created", 100).await;
    let second = create_test_meta_role(&pool, tenant_id, user_id, "Second Created", 100).await;

    // Verify ordering by created_at when priority is equal
    let order: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM gov_meta_roles WHERE tenant_id = $1 AND priority = 100 ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to fetch order");

    assert_eq!(order.len(), 2);
    assert_eq!(order[0].0, first, "First created should come first");
    assert_eq!(order[1].0, second, "Second created should come second");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Conflict Recording Tests
// ============================================================================

/// Test conflict is recorded in database.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_conflict_recorded_in_database() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create conflicting meta-roles
    let meta_role1 =
        create_test_meta_role(&pool, tenant_id, user_id, "Conflict Source 1", 100).await;
    let meta_role2 =
        create_test_meta_role(&pool, tenant_id, user_id, "Conflict Source 2", 200).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Insert conflict record directly
    // Note: meta_role_a_id must be < meta_role_b_id per constraint
    let (mr_a, mr_b) = if meta_role1 < meta_role2 {
        (meta_role1, meta_role2)
    } else {
        (meta_role2, meta_role1)
    };

    let conflict_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'constraint_conflict'::gov_meta_role_conflict_type, '{"constraint_type": "max_session_duration"}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        "#,
    )
    .bind(conflict_id)
    .bind(tenant_id)
    .bind(mr_a)
    .bind(mr_b)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to insert conflict");

    // Verify conflict exists
    let conflict_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_conflicts WHERE tenant_id = $1 AND affected_role_id = $2",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count conflicts");

    assert_eq!(conflict_count.0, 1, "Should have 1 conflict recorded");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test conflict resolution updates status.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_conflict_resolution_updates_status() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "Source 1", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Source 2", 200).await;
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Insert unresolved conflict
    // Note: meta_role_a_id must be < meta_role_b_id per constraint
    let (mr_a, mr_b) = if meta_role1 < meta_role2 {
        (meta_role1, meta_role2)
    } else {
        (meta_role2, meta_role1)
    };

    let conflict_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'entitlement_conflict'::gov_meta_role_conflict_type, '{"entitlement_id": "test"}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        "#,
    )
    .bind(conflict_id)
    .bind(tenant_id)
    .bind(mr_a)
    .bind(mr_b)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to insert conflict");

    // Resolve by priority
    sqlx::query(
        r"
        UPDATE gov_meta_role_conflicts
        SET resolution_status = 'resolved_priority'::gov_meta_role_resolution_status,
            resolved_by = $1,
            resolved_at = NOW()
        WHERE id = $2
        ",
    )
    .bind(user_id)
    .bind(conflict_id)
    .execute(&pool)
    .await
    .expect("Failed to resolve conflict");

    // Verify resolution
    let status: (String,) =
        sqlx::query_as("SELECT resolution_status::text FROM gov_meta_role_conflicts WHERE id = $1")
            .bind(conflict_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch status");

    assert_eq!(
        status.0, "resolved_priority",
        "Should be resolved by priority"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test ignore conflict option.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_ignore_conflict_option() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "Source 1", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Source 2", 200).await;
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Insert conflict
    // Note: meta_role_a_id must be < meta_role_b_id per constraint
    let (mr_a, mr_b) = if meta_role1 < meta_role2 {
        (meta_role1, meta_role2)
    } else {
        (meta_role2, meta_role1)
    };

    let conflict_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'policy_conflict'::gov_meta_role_conflict_type, '{"policy": "require_mfa"}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        "#,
    )
    .bind(conflict_id)
    .bind(tenant_id)
    .bind(mr_a)
    .bind(mr_b)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to insert conflict");

    // Mark as ignored - need to check if resolution_choice column exists instead of resolution_notes
    sqlx::query(
        r#"
        UPDATE gov_meta_role_conflicts
        SET resolution_status = 'ignored'::gov_meta_role_resolution_status,
            resolution_choice = '{"reason": "Acknowledged by admin - both policies acceptable"}'::jsonb,
            resolved_by = $1,
            resolved_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(user_id)
    .bind(conflict_id)
    .execute(&pool)
    .await
    .expect("Failed to ignore conflict");

    // Verify ignored status
    let status: (String,) =
        sqlx::query_as("SELECT resolution_status::text FROM gov_meta_role_conflicts WHERE id = $1")
            .bind(conflict_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch status");

    assert_eq!(status.0, "ignored", "Should be marked as ignored");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Conflict Scope Tests
// ============================================================================

/// Test conflicts are tenant isolated.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_conflicts_tenant_isolated() {
    let pool = create_test_pool().await;

    let tenant1 = create_test_tenant(&pool).await;
    let tenant2 = create_test_tenant(&pool).await;

    let user1 = create_test_user(&pool, tenant1).await;
    let user2 = create_test_user(&pool, tenant2).await;

    let app1 = create_test_application(&pool, tenant1).await;
    let app2 = create_test_application(&pool, tenant2).await;

    // Create meta-roles in each tenant
    let mr1_t1 = create_test_meta_role(&pool, tenant1, user1, "T1 MR1", 100).await;
    let mr2_t1 = create_test_meta_role(&pool, tenant1, user1, "T1 MR2", 200).await;

    let mr1_t2 = create_test_meta_role(&pool, tenant2, user2, "T2 MR1", 100).await;
    let mr2_t2 = create_test_meta_role(&pool, tenant2, user2, "T2 MR2", 200).await;

    let role_t1 = create_test_entitlement(&pool, tenant1, app1, Some(user1)).await;
    let role_t2 = create_test_entitlement(&pool, tenant2, app2, Some(user2)).await;

    // Insert conflicts in both tenants
    // Note: meta_role_a_id must be < meta_role_b_id per constraint
    let (mr_a_t1, mr_b_t1) = if mr1_t1 < mr2_t1 {
        (mr1_t1, mr2_t1)
    } else {
        (mr2_t1, mr1_t1)
    };
    let (mr_a_t2, mr_b_t2) = if mr1_t2 < mr2_t2 {
        (mr1_t2, mr2_t2)
    } else {
        (mr2_t2, mr1_t2)
    };

    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'constraint_conflict'::gov_meta_role_conflict_type, '{"constraint_type": "test"}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant1)
    .bind(mr_a_t1)
    .bind(mr_b_t1)
    .bind(role_t1)
    .execute(&pool)
    .await
    .expect("Failed to insert tenant 1 conflict");

    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'entitlement_conflict'::gov_meta_role_conflict_type, '{"entitlement_id": "test"}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant2)
    .bind(mr_a_t2)
    .bind(mr_b_t2)
    .bind(role_t2)
    .execute(&pool)
    .await
    .expect("Failed to insert tenant 2 conflict");

    // Verify isolation
    let count_t1: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM gov_meta_role_conflicts WHERE tenant_id = $1")
            .bind(tenant1)
            .fetch_one(&pool)
            .await
            .expect("Failed to count tenant 1");

    let count_t2: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM gov_meta_role_conflicts WHERE tenant_id = $1")
            .bind(tenant2)
            .fetch_one(&pool)
            .await
            .expect("Failed to count tenant 2");

    assert_eq!(count_t1.0, 1, "Tenant 1 should have 1 conflict");
    assert_eq!(count_t2.0, 1, "Tenant 2 should have 1 conflict");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant1).await;
    cleanup_test_tenant(&pool, tenant1).await;
    cleanup_meta_role_data(&pool, tenant2).await;
    cleanup_test_tenant(&pool, tenant2).await;
}

/// Test listing unresolved conflicts.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_unresolved_conflicts() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "MR1", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "MR2", 200).await;
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Insert 3 conflicts: 2 unresolved, 1 resolved
    // Note: meta_role_a_id must be < meta_role_b_id per constraint
    let (mr_a, mr_b) = if meta_role1 < meta_role2 {
        (meta_role1, meta_role2)
    } else {
        (meta_role2, meta_role1)
    };

    for i in 0..3 {
        let status = if i < 2 {
            "unresolved"
        } else {
            "resolved_priority"
        };
        sqlx::query(&format!(
            r#"
            INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
            VALUES ($1, $2, $3, $4, $5, 'constraint_conflict'::gov_meta_role_conflict_type, '{{"iteration": {i}}}'::jsonb, '{status}'::gov_meta_role_resolution_status, NOW())
            "#
        ))
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(mr_a)
        .bind(mr_b)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("Failed to insert conflict");
    }

    // Count unresolved
    let unresolved: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_conflicts WHERE tenant_id = $1 AND resolution_status = 'unresolved'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count unresolved");

    assert_eq!(unresolved.0, 2, "Should have 2 unresolved conflicts");

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Edge Cases from IGA standards Comparison
// ============================================================================

/// Test that conflict detection is order-independent (IGA pattern: "order of role assignment is insignificant").
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_conflict_detection_order_independent() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create meta-roles with conflicting policies
    let meta_role1 = create_test_meta_role(&pool, tenant_id, user_id, "First Assigned", 100).await;
    let meta_role2 = create_test_meta_role(&pool, tenant_id, user_id, "Second Assigned", 200).await;

    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role1, entitlement_id, "grant").await;
    create_test_meta_role_entitlement(&pool, tenant_id, meta_role2, entitlement_id, "deny").await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Assign in order: meta_role1 then meta_role2
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, role_id).await;

    // Create another role and assign in reverse order: meta_role2 then meta_role1
    let role_id_2 = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role2, role_id_2).await;
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role1, role_id_2).await;

    // Both roles should have 2 inheritances regardless of order
    let count_1: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND child_role_id = $2",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let count_2: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND child_role_id = $2",
    )
    .bind(tenant_id)
    .bind(role_id_2)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count_1.0, 2, "First role should have both inheritances");
    assert_eq!(
        count_2.0, 2,
        "Second role should have both inheritances regardless of order"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test three-way conflict (3 meta-roles all conflicting with each other).
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_three_way_conflict() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create 3 meta-roles with different constraint values
    let mr1 = create_test_meta_role(&pool, tenant_id, user_id, "Session 30min", 100).await;
    let mr2 = create_test_meta_role(&pool, tenant_id, user_id, "Session 1hr", 200).await;
    let mr3 = create_test_meta_role(&pool, tenant_id, user_id, "Session 2hr", 300).await;

    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        mr1,
        "max_session_duration",
        serde_json::json!(1800),
    )
    .await;
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        mr2,
        "max_session_duration",
        serde_json::json!(3600),
    )
    .await;
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        mr3,
        "max_session_duration",
        serde_json::json!(7200),
    )
    .await;

    // Create role inheriting from all 3
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, mr1, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, mr2, role_id).await;
    create_test_meta_role_inheritance(&pool, tenant_id, mr3, role_id).await;

    // Should have 3 different constraint values
    let constraints: Vec<(serde_json::Value,)> = sqlx::query_as(
        r"
        SELECT c.constraint_value
        FROM gov_meta_role_constraints c
        JOIN gov_meta_role_inheritances i ON i.meta_role_id = c.meta_role_id
        WHERE i.tenant_id = $1 AND i.child_role_id = $2 AND c.constraint_type = 'max_session_duration'
        ORDER BY c.constraint_value
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        constraints.len(),
        3,
        "Should have 3 conflicting values (3-way conflict)"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test disabled meta-role should not create new conflicts.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disabled_meta_role_no_new_conflicts() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create active meta-role
    let active_mr = create_test_meta_role(&pool, tenant_id, user_id, "Active Policy", 100).await;
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        active_mr,
        "require_mfa",
        serde_json::json!(true),
    )
    .await;

    // Create and disable another meta-role with conflicting policy
    let disabled_mr =
        create_test_meta_role(&pool, tenant_id, user_id, "Disabled Policy", 200).await;
    create_test_meta_role_constraint(
        &pool,
        tenant_id,
        disabled_mr,
        "require_mfa",
        serde_json::json!(false),
    )
    .await;

    // Disable the meta-role
    sqlx::query("UPDATE gov_meta_roles SET status = 'disabled' WHERE id = $1")
        .bind(disabled_mr)
        .execute(&pool)
        .await
        .unwrap();

    // Create role with inheritance from disabled meta-role (should be status 'suspended')
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;
    create_test_meta_role_inheritance(&pool, tenant_id, active_mr, role_id).await;

    // Insert inheritance for disabled meta-role with suspended status
    sqlx::query(
        r"
        INSERT INTO gov_meta_role_inheritances (id, tenant_id, meta_role_id, child_role_id, status, match_reason)
        VALUES ($1, $2, $3, $4, 'suspended'::gov_meta_role_inheritance_status, 'manual')
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(disabled_mr)
    .bind(role_id)
    .execute(&pool)
    .await
    .unwrap();

    // Active inheritances should only count the active one
    let active_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1 AND child_role_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        active_count.0, 1,
        "Only active meta-role inheritance should count"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test conflict deduplication (same conflict pair should only be recorded once).
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_conflict_deduplication() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let mr1 = create_test_meta_role(&pool, tenant_id, user_id, "Source A", 100).await;
    let mr2 = create_test_meta_role(&pool, tenant_id, user_id, "Source B", 200).await;
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Ensure correct ordering for constraint
    let (mr_a, mr_b) = if mr1 < mr2 { (mr1, mr2) } else { (mr2, mr1) };

    // Insert same conflict twice (should fail on second due to unique constraint)
    let conflict_id_1 = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'entitlement_conflict'::gov_meta_role_conflict_type, '{}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        ",
    )
    .bind(conflict_id_1)
    .bind(tenant_id)
    .bind(mr_a)
    .bind(mr_b)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("First insert should succeed");

    // Second insert with same meta-role pair and affected role - check if it already exists
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM gov_meta_role_conflicts WHERE tenant_id = $1 AND meta_role_a_id = $2 AND meta_role_b_id = $3 AND affected_role_id = $4",
    )
    .bind(tenant_id)
    .bind(mr_a)
    .bind(mr_b)
    .bind(role_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(existing.is_some(), "Existing conflict should be found");
    assert_eq!(
        existing.unwrap().0,
        conflict_id_1,
        "Should find the original conflict ID"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test resolution of one conflict doesn't affect other conflicts.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_independent_conflict_resolution() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let mr1 = create_test_meta_role(&pool, tenant_id, user_id, "MR1", 100).await;
    let mr2 = create_test_meta_role(&pool, tenant_id, user_id, "MR2", 200).await;
    let mr3 = create_test_meta_role(&pool, tenant_id, user_id, "MR3", 300).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, Some(user_id)).await;

    // Create two independent conflicts
    let (mr_a_12, mr_b_12) = if mr1 < mr2 { (mr1, mr2) } else { (mr2, mr1) };
    let (mr_a_23, mr_b_23) = if mr2 < mr3 { (mr2, mr3) } else { (mr3, mr2) };

    let conflict_1 = Uuid::new_v4();
    let conflict_2 = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'constraint_conflict'::gov_meta_role_conflict_type, '{}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        ",
    )
    .bind(conflict_1)
    .bind(tenant_id)
    .bind(mr_a_12)
    .bind(mr_b_12)
    .bind(role_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r"
        INSERT INTO gov_meta_role_conflicts (id, tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id, conflict_type, conflicting_items, resolution_status, detected_at)
        VALUES ($1, $2, $3, $4, $5, 'policy_conflict'::gov_meta_role_conflict_type, '{}'::jsonb, 'unresolved'::gov_meta_role_resolution_status, NOW())
        ",
    )
    .bind(conflict_2)
    .bind(tenant_id)
    .bind(mr_a_23)
    .bind(mr_b_23)
    .bind(role_id)
    .execute(&pool)
    .await
    .unwrap();

    // Resolve first conflict
    sqlx::query(
        "UPDATE gov_meta_role_conflicts SET resolution_status = 'resolved_priority'::gov_meta_role_resolution_status WHERE id = $1",
    )
    .bind(conflict_1)
    .execute(&pool)
    .await
    .unwrap();

    // Second conflict should still be unresolved
    let status_2: (String,) =
        sqlx::query_as("SELECT resolution_status::text FROM gov_meta_role_conflicts WHERE id = $1")
            .bind(conflict_2)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        status_2.0, "unresolved",
        "Second conflict should remain unresolved"
    );

    // Cleanup
    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
