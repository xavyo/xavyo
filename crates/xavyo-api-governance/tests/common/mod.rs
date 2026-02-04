//! Common test utilities for governance integration tests.
//!
//! These helper functions are used by integration tests.

#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

/// Create a test database pool.
pub async fn create_test_pool() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/xavyo_test".to_string());

    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Create a test tenant.
pub async fn create_test_tenant(pool: &PgPool) -> Uuid {
    let tenant_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO tenants (id, name, slug, created_at)
        VALUES ($1, $2, $3, NOW())
        ",
    )
    .bind(tenant_id)
    .bind(format!("Test Tenant {tenant_id}"))
    .bind(format!("test-{}", &tenant_id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("Failed to create test tenant");

    tenant_id
}

/// Create a test user.
pub async fn create_test_user(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, NOW(), NOW())
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(format!("user-{user_id}@test.com"))
    .bind("$argon2id$v=19$m=65536,t=3,p=4$dummy$hash") // Fake hash for testing
    .execute(pool)
    .await
    .expect("Failed to create test user");

    user_id
}

/// Create a test application.
pub async fn create_test_application(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let app_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_applications (id, tenant_id, name, app_type, status, description, created_at, updated_at)
        VALUES ($1, $2, $3, 'internal', 'active', $4, NOW(), NOW())
        ",
    )
    .bind(app_id)
    .bind(tenant_id)
    .bind(format!("Test App {app_id}"))
    .bind("A test application for integration tests")
    .execute(pool)
    .await
    .expect("Failed to create test application");

    app_id
}

/// Create a test entitlement.
pub async fn create_test_entitlement(
    pool: &PgPool,
    tenant_id: Uuid,
    application_id: Uuid,
    owner_id: Option<Uuid>,
) -> Uuid {
    let entitlement_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_entitlements (id, tenant_id, application_id, name, description, risk_level, status, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 'low', 'active', $6, NOW(), NOW())
        ",
    )
    .bind(entitlement_id)
    .bind(tenant_id)
    .bind(application_id)
    .bind(format!("Test Entitlement {entitlement_id}"))
    .bind("A test entitlement")
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("Failed to create test entitlement");

    entitlement_id
}

/// Create a test entitlement with specific risk level.
pub async fn create_test_entitlement_with_risk(
    pool: &PgPool,
    tenant_id: Uuid,
    application_id: Uuid,
    owner_id: Option<Uuid>,
    risk_level: &str,
) -> Uuid {
    let entitlement_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_entitlements (id, tenant_id, application_id, name, description, risk_level, status, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6::gov_risk_level, 'active'::gov_entitlement_status, $7, NOW(), NOW())
        ",
    )
    .bind(entitlement_id)
    .bind(tenant_id)
    .bind(application_id)
    .bind(format!("Test Entitlement {entitlement_id}"))
    .bind("A test entitlement")
    .bind(risk_level)
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("Failed to create test entitlement");

    entitlement_id
}

/// Create a test entitlement assignment.
pub async fn create_test_assignment(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    entitlement_id: Uuid,
) -> Uuid {
    let assignment_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, user_id, entitlement_id, status, granted_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, 'active', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(entitlement_id)
    .execute(pool)
    .await
    .expect("Failed to create test assignment");

    assignment_id
}

/// Create a test user with a manager.
pub async fn create_test_user_with_manager(
    pool: &PgPool,
    tenant_id: Uuid,
    manager_id: Uuid,
) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, manager_id, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(format!("user-{user_id}@test.com"))
    .bind("$argon2id$v=19$m=65536,t=3,p=4$dummy$hash")
    .bind(manager_id)
    .execute(pool)
    .await
    .expect("Failed to create test user with manager");

    user_id
}

/// Clean up test data for a tenant.
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies

    // F055: Micro-certification cleanup
    let _ = sqlx::query("DELETE FROM gov_micro_cert_events WHERE certification_id IN (SELECT id FROM gov_micro_certifications WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_micro_certifications WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_micro_cert_triggers WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // F052: Object Lifecycle States cleanup
    let _ = sqlx::query("DELETE FROM gov_bulk_state_operation_items WHERE operation_id IN (SELECT id FROM gov_bulk_state_operations WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_bulk_state_operations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_scheduled_transitions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_state_transition_audit WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_state_transition_requests WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_lifecycle_transitions WHERE config_id IN (SELECT id FROM gov_lifecycle_configs WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_lifecycle_states WHERE config_id IN (SELECT id FROM gov_lifecycle_configs WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_lifecycle_configs WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Access requests and approvals
    let _ = sqlx::query("DELETE FROM gov_approval_decisions WHERE request_id IN (SELECT id FROM gov_access_requests WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_access_requests WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_approval_steps WHERE workflow_id IN (SELECT id FROM gov_approval_workflows WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_approval_workflows WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_approval_delegations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_entitlement_assignments WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_entitlements WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_applications WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// =========================================================================
// Meta-role helpers (F056)
// =========================================================================

/// Create a test meta-role.
pub async fn create_test_meta_role(
    pool: &PgPool,
    tenant_id: Uuid,
    created_by: Uuid,
    name: &str,
    priority: i32,
) -> Uuid {
    let meta_role_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_meta_roles (id, tenant_id, name, description, priority, status, criteria_logic, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 'active', 'and', $6, NOW(), NOW())
        ",
    )
    .bind(meta_role_id)
    .bind(tenant_id)
    .bind(name)
    .bind(format!("Test meta-role: {name}"))
    .bind(priority)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("Failed to create test meta-role");

    meta_role_id
}

/// Create a test meta-role criterion.
pub async fn create_test_meta_role_criterion(
    pool: &PgPool,
    tenant_id: Uuid,
    meta_role_id: Uuid,
    field: &str,
    operator: &str,
    value: serde_json::Value,
) -> Uuid {
    let criterion_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_meta_role_criteria (id, tenant_id, meta_role_id, field, operator, value, created_at)
        VALUES ($1, $2, $3, $4, $5::gov_meta_role_criteria_operator, $6, NOW())
        ",
    )
    .bind(criterion_id)
    .bind(tenant_id)
    .bind(meta_role_id)
    .bind(field)
    .bind(operator)
    .bind(&value)
    .execute(pool)
    .await
    .expect("Failed to create test meta-role criterion");

    criterion_id
}

/// Create a test meta-role entitlement.
pub async fn create_test_meta_role_entitlement(
    pool: &PgPool,
    tenant_id: Uuid,
    meta_role_id: Uuid,
    entitlement_id: Uuid,
    permission_type: &str,
) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_meta_role_entitlements (id, tenant_id, meta_role_id, entitlement_id, permission_type, created_at)
        VALUES ($1, $2, $3, $4, $5::gov_meta_role_permission_type, NOW())
        ",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(meta_role_id)
    .bind(entitlement_id)
    .bind(permission_type)
    .execute(pool)
    .await
    .expect("Failed to create test meta-role entitlement");

    id
}

/// Create a test meta-role constraint.
pub async fn create_test_meta_role_constraint(
    pool: &PgPool,
    tenant_id: Uuid,
    meta_role_id: Uuid,
    constraint_type: &str,
    constraint_value: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_meta_role_constraints (id, tenant_id, meta_role_id, constraint_type, constraint_value, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(meta_role_id)
    .bind(constraint_type)
    .bind(&constraint_value)
    .execute(pool)
    .await
    .expect("Failed to create test meta-role constraint");

    id
}

/// Create a test meta-role inheritance.
pub async fn create_test_meta_role_inheritance(
    pool: &PgPool,
    tenant_id: Uuid,
    meta_role_id: Uuid,
    child_role_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO gov_meta_role_inheritances (id, tenant_id, meta_role_id, child_role_id, status, match_reason, matched_at, updated_at)
        VALUES ($1, $2, $3, $4, 'active'::gov_meta_role_inheritance_status, '{"test": true}', NOW(), NOW())
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(meta_role_id)
    .bind(child_role_id)
    .execute(pool)
    .await
    .expect("Failed to create test meta-role inheritance");

    id
}

/// Cleanup meta-role test data for a tenant.
pub async fn cleanup_meta_role_data(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies
    let _ = sqlx::query("DELETE FROM gov_meta_role_events WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_role_conflicts WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_role_inheritances WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_role_constraints WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_role_entitlements WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_role_criteria WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_meta_roles WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// =========================================================================
// Outlier Detection helpers (F059)
// =========================================================================

/// Create a test peer group.
pub async fn create_test_peer_group(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    group_type: &str,
    attribute_key: &str,
    attribute_value: &str,
) -> Uuid {
    let peer_group_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_peer_groups (id, tenant_id, name, group_type, attribute_key, attribute_value, user_count, created_at, updated_at)
        VALUES ($1, $2, $3, $4::gov_peer_group_type, $5, $6, 0, NOW(), NOW())
        ",
    )
    .bind(peer_group_id)
    .bind(tenant_id)
    .bind(name)
    .bind(group_type)
    .bind(attribute_key)
    .bind(attribute_value)
    .execute(pool)
    .await
    .expect("Failed to create test peer group");

    peer_group_id
}

/// Create a test outlier configuration.
pub async fn create_test_outlier_config(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let config_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_outlier_configurations (id, tenant_id, enabled, confidence_threshold, frequency_threshold, min_peer_group_size, created_at, updated_at)
        VALUES ($1, $2, true, 2.0, 0.1, 5, NOW(), NOW())
        ",
    )
    .bind(config_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create test outlier configuration");

    config_id
}

/// Create a test outlier analysis.
pub async fn create_test_outlier_analysis(pool: &PgPool, tenant_id: Uuid, status: &str) -> Uuid {
    let analysis_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_outlier_analyses (id, tenant_id, status, triggered_by, config_snapshot, total_users, outlier_count, started_at, created_at)
        VALUES ($1, $2, $3::gov_outlier_analysis_status, 'manual'::gov_outlier_trigger_type, '{}', 0, 0, NOW(), NOW())
        ",
    )
    .bind(analysis_id)
    .bind(tenant_id)
    .bind(status)
    .execute(pool)
    .await
    .expect("Failed to create test outlier analysis");

    analysis_id
}

/// Create a test outlier result.
pub async fn create_test_outlier_result(
    pool: &PgPool,
    tenant_id: Uuid,
    analysis_id: Uuid,
    user_id: Uuid,
    score: f64,
    classification: &str,
) -> Uuid {
    let result_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_outlier_results (id, tenant_id, analysis_id, user_id, overall_score, classification, peer_scores, factor_breakdown, created_at)
        VALUES ($1, $2, $3, $4, $5, $6::gov_outlier_classification, '[]', '{}', NOW())
        ",
    )
    .bind(result_id)
    .bind(tenant_id)
    .bind(analysis_id)
    .bind(user_id)
    .bind(score)
    .bind(classification)
    .execute(pool)
    .await
    .expect("Failed to create test outlier result");

    result_id
}

/// Create a test outlier alert.
pub async fn create_test_outlier_alert(
    pool: &PgPool,
    tenant_id: Uuid,
    analysis_id: Uuid,
    user_id: Uuid,
    score: f64,
    severity: &str,
) -> Uuid {
    let alert_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_outlier_alerts (id, tenant_id, analysis_id, user_id, alert_type, severity, score, classification, is_read, is_dismissed, created_at)
        VALUES ($1, $2, $3, $4, 'new_outlier'::gov_outlier_alert_type, $5::gov_outlier_alert_severity, $6, 'outlier'::gov_outlier_classification, false, false, NOW())
        ",
    )
    .bind(alert_id)
    .bind(tenant_id)
    .bind(analysis_id)
    .bind(user_id)
    .bind(severity)
    .bind(score)
    .execute(pool)
    .await
    .expect("Failed to create test outlier alert");

    alert_id
}

/// Cleanup outlier detection test data for a tenant.
pub async fn cleanup_outlier_data(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies
    let _ = sqlx::query("DELETE FROM gov_outlier_alerts WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_outlier_dispositions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_outlier_results WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_outlier_analyses WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_outlier_configurations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_peer_group_members WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_peer_groups WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// =========================================================================
// Enhanced Simulation helpers (F060)
// =========================================================================

/// Create a test user with department attribute.
/// Uses `custom_attributes` JSONB column per F070 schema.
pub async fn create_test_user_with_attributes(
    pool: &PgPool,
    tenant_id: Uuid,
    department: Option<&str>,
    title: Option<&str>,
) -> Uuid {
    let user_id = Uuid::new_v4();

    // Build custom_attributes JSON with department and title
    let mut attrs = serde_json::Map::new();
    if let Some(dept) = department {
        attrs.insert(
            "department".to_string(),
            serde_json::Value::String(dept.to_string()),
        );
    }
    if let Some(t) = title {
        attrs.insert(
            "title".to_string(),
            serde_json::Value::String(t.to_string()),
        );
    }
    let custom_attributes = serde_json::Value::Object(attrs);

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, custom_attributes, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(format!("user-{user_id}@test.com"))
    .bind("$argon2id$v=19$m=65536,t=3,p=4$dummy$hash")
    .bind(custom_attributes)
    .execute(pool)
    .await
    .expect("Failed to create test user with attributes");

    user_id
}

/// Create a test entitlement assignment with `target_type`.
pub async fn create_test_entitlement_assignment(
    pool: &PgPool,
    tenant_id: Uuid,
    target_id: Uuid,
    entitlement_id: Uuid,
) -> Uuid {
    let assignment_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(target_id)
    .bind(entitlement_id)
    .execute(pool)
    .await
    .expect("Failed to create test entitlement assignment");

    assignment_id
}

/// Cleanup enhanced simulation test data for a tenant.
pub async fn cleanup_simulation_data(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies
    let _ = sqlx::query("DELETE FROM gov_simulation_comparisons WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_batch_simulation_results WHERE simulation_id IN (SELECT id FROM gov_batch_simulations WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_batch_simulations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_policy_simulation_results WHERE simulation_id IN (SELECT id FROM gov_policy_simulations WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_policy_simulations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}
