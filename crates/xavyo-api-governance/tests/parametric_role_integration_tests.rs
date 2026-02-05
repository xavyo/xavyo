//! Integration tests for F057 Parametric Roles.
//!
//! These tests verify the full parametric role lifecycle including:
//! - Parameter definition and management
//! - Parametric assignment creation with values
//! - Validation constraints
//! - Temporal validity
//! - Audit trail

mod common;

use common::{
    cleanup_test_tenant, create_test_application, create_test_pool, create_test_tenant,
    create_test_user,
};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_db::{CreateGovRoleParameter, GovRoleParameter, ParameterConstraints, ParameterType};

// ============================================================================
// Test Setup Helpers
// ============================================================================

/// Create a test role (entitlement).
async fn create_test_role(pool: &PgPool, tenant_id: Uuid, application_id: Uuid) -> Uuid {
    let role_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_entitlements (id, tenant_id, application_id, name, description, risk_level, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 'low', 'active', NOW(), NOW())
        ",
    )
    .bind(role_id)
    .bind(tenant_id)
    .bind(application_id)
    .bind(format!("Parametric Role {role_id}"))
    .bind("A parametric role for integration tests")
    .execute(pool)
    .await
    .expect("Failed to create test role");

    role_id
}

/// Cleanup parametric role test data.
async fn cleanup_parametric_role_data(pool: &PgPool, tenant_id: Uuid) {
    let _ = sqlx::query("DELETE FROM gov_parameter_audit_events WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_role_assignment_parameters WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM gov_role_parameters WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// ============================================================================
// T064: Full Parametric Role Lifecycle Integration Test
// ============================================================================

/// Test the complete parametric role lifecycle:
/// 1. Create a role
/// 2. Add parameters to the role
/// 3. Assign the role to a user with parameter values
/// 4. Verify the assignment
/// 5. Update parameter values
/// 6. Revoke the assignment
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_full_parametric_role_lifecycle() {
    use xavyo_api_governance::services::ParameterService;
    use xavyo_db::SetGovAssignmentParameter;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let actor_id = user_id; // Use same user as actor for simplicity

    // 1. Create parameters on the role
    let param1 = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "database_name".to_string(),
            display_name: Some("Database Name".to_string()),
            description: Some("The database to access".to_string()),
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: Some(ParameterConstraints::string(Some(1), Some(255), None)),
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter 1");

    let param2 = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "access_level".to_string(),
            display_name: Some("Access Level".to_string()),
            description: Some("Read, write, or admin access".to_string()),
            parameter_type: ParameterType::Enum,
            is_required: Some(true),
            default_value: Some(serde_json::json!("read")),
            constraints: Some(ParameterConstraints::enumeration(vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
            ])),
            display_order: Some(1),
        },
    )
    .await
    .expect("Failed to create parameter 2");

    // Verify parameters are listed
    let params = GovRoleParameter::list_by_role(&pool, tenant_id, role_id)
        .await
        .expect("Failed to list parameters");
    assert_eq!(params.len(), 2);

    // 2. Validate parameter values
    let service = ParameterService::new(pool.clone());
    let mut values = HashMap::new();
    values.insert(param1.id, serde_json::json!("production_db"));
    values.insert(param2.id, serde_json::json!("write"));

    let validation_result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation failed");
    assert!(validation_result.is_valid);

    // 3. Create assignment with parameters
    let assignment_id = Uuid::new_v4();
    let parameter_hash = service
        .compute_parameter_hash(tenant_id, role_id, &values)
        .await
        .expect("Failed to compute hash");

    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', $5, NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .bind(&parameter_hash)
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    // Set parameter values
    service
        .set_assignment_parameters(
            tenant_id,
            assignment_id,
            actor_id,
            vec![
                SetGovAssignmentParameter {
                    parameter_id: param1.id,
                    value: serde_json::json!("production_db"),
                },
                SetGovAssignmentParameter {
                    parameter_id: param2.id,
                    value: serde_json::json!("write"),
                },
            ],
        )
        .await
        .expect("Failed to set parameters");

    // 4. Verify assignment
    let assignment =
        xavyo_db::GovEntitlementAssignment::find_by_id(&pool, tenant_id, assignment_id)
            .await
            .expect("Query failed")
            .expect("Assignment not found");
    assert_eq!(assignment.parameter_hash, Some(parameter_hash.clone()));

    let stored_values = service
        .get_assignment_parameters(tenant_id, assignment_id)
        .await
        .expect("Failed to get parameters");
    assert_eq!(stored_values.len(), 2);

    // 5. Update parameter values
    service
        .update_assignment_parameters(
            tenant_id,
            assignment_id,
            actor_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param2.id,
                value: serde_json::json!("admin"),
            }],
        )
        .await
        .expect("Failed to update parameters");

    // Verify audit trail
    let audit_events = service
        .list_assignment_audit(tenant_id, assignment_id)
        .await
        .expect("Failed to list audit");
    assert!(audit_events.len() >= 2); // Set + Update

    // 6. Revoke assignment
    service
        .revoke_parametric_assignment(
            tenant_id,
            assignment_id,
            actor_id,
            Some("Test cleanup".to_string()),
        )
        .await
        .expect("Failed to revoke");

    // Verify revoked (deletion)
    let revoked = xavyo_db::GovEntitlementAssignment::find_by_id(&pool, tenant_id, assignment_id)
        .await
        .expect("Query failed");
    assert!(revoked.is_none());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T065: Multiple Assignments with Different Parameters
// ============================================================================

/// Test that a user can have multiple assignments of the same role
/// with different parameter values.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_multiple_assignments_different_params() {
    use xavyo_api_governance::services::ParameterService;
    use xavyo_db::SetGovAssignmentParameter;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create database_name parameter
    let param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "database_name".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: None,
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let service = ParameterService::new(pool.clone());

    // Create assignments for different databases
    let databases = ["production_db", "staging_db", "development_db"];
    let mut assignment_ids = Vec::new();

    for db_name in databases {
        let mut values = HashMap::new();
        values.insert(param.id, serde_json::json!(db_name));

        let hash = service
            .compute_parameter_hash(tenant_id, role_id, &values)
            .await
            .expect("Failed to compute hash");

        let assignment_id = Uuid::new_v4();

        sqlx::query(
            r"
            INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
            VALUES ($1, $2, 'user', $3, $4, 'active', $5, NOW(), NOW(), NOW())
            ",
        )
        .bind(assignment_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(role_id)
        .bind(&hash)
        .execute(&pool)
        .await
        .expect("Failed to create assignment");

        service
            .set_assignment_parameters(
                tenant_id,
                assignment_id,
                user_id,
                vec![SetGovAssignmentParameter {
                    parameter_id: param.id,
                    value: serde_json::json!(db_name),
                }],
            )
            .await
            .expect("Failed to set parameters");

        assignment_ids.push(assignment_id);
    }

    // Verify all assignments exist
    let assignments = xavyo_db::GovEntitlementAssignment::list_parametric_by_user_and_role(
        &pool, tenant_id, user_id, role_id,
    )
    .await
    .expect("Failed to list assignments");

    assert_eq!(assignments.len(), 3);

    // Verify each has unique parameter hash
    let hashes: Vec<_> = assignments
        .iter()
        .filter_map(|a| a.parameter_hash.clone())
        .collect();
    assert_eq!(hashes.len(), 3);

    let unique_hashes: std::collections::HashSet<_> = hashes.into_iter().collect();
    assert_eq!(unique_hashes.len(), 3);

    // Revoke one and verify others remain
    service
        .revoke_parametric_assignment(tenant_id, assignment_ids[0], user_id, None)
        .await
        .expect("Failed to revoke");

    let remaining = xavyo_db::GovEntitlementAssignment::list_parametric_by_user_and_role(
        &pool, tenant_id, user_id, role_id,
    )
    .await
    .expect("Failed to list remaining");

    assert_eq!(remaining.len(), 2);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T066: Validation Rejection Scenarios
// ============================================================================

/// Test various validation rejection scenarios.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validation_rejection_scenarios() {
    use xavyo_api_governance::services::ParameterService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create various constrained parameters
    let required_string = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "required_field".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: None,
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let port_param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "port".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Integer,
            is_required: Some(true),
            default_value: None,
            constraints: Some(ParameterConstraints::integer(Some(1), Some(65535))),
            display_order: Some(1),
        },
    )
    .await
    .expect("Failed to create parameter");

    let env_param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "environment".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Enum,
            is_required: Some(true),
            default_value: None,
            constraints: Some(ParameterConstraints::enumeration(vec![
                "dev".to_string(),
                "staging".to_string(),
                "prod".to_string(),
            ])),
            display_order: Some(2),
        },
    )
    .await
    .expect("Failed to create parameter");

    let service = ParameterService::new(pool.clone());

    // Test 1: Missing required field
    let mut values = HashMap::new();
    values.insert(port_param.id, serde_json::json!(5432));
    values.insert(env_param.id, serde_json::json!("dev"));
    // required_field is missing

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation call failed");
    assert!(!result.is_valid);
    assert!(result.errors.iter().any(|e| e.contains("required_field")));

    // Test 2: Port out of range
    let mut values = HashMap::new();
    values.insert(required_string.id, serde_json::json!("test"));
    values.insert(port_param.id, serde_json::json!(70000)); // Too high
    values.insert(env_param.id, serde_json::json!("dev"));

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation call failed");
    assert!(!result.is_valid);
    assert!(result
        .results
        .iter()
        .any(|r| r.parameter_name == "port" && !r.is_valid));

    // Test 3: Invalid enum value
    let mut values = HashMap::new();
    values.insert(required_string.id, serde_json::json!("test"));
    values.insert(port_param.id, serde_json::json!(5432));
    values.insert(env_param.id, serde_json::json!("invalid_env"));

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation call failed");
    assert!(!result.is_valid);
    assert!(result
        .results
        .iter()
        .any(|r| r.parameter_name == "environment" && !r.is_valid));

    // Test 4: Wrong type (string where integer expected)
    let mut values = HashMap::new();
    values.insert(required_string.id, serde_json::json!("test"));
    values.insert(port_param.id, serde_json::json!("not_a_number"));
    values.insert(env_param.id, serde_json::json!("dev"));

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation call failed");
    assert!(!result.is_valid);

    // Test 5: All valid values should pass
    let mut values = HashMap::new();
    values.insert(required_string.id, serde_json::json!("valid_value"));
    values.insert(port_param.id, serde_json::json!(5432));
    values.insert(env_param.id, serde_json::json!("prod"));

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Validation call failed");
    assert!(result.is_valid);
    assert!(result.errors.is_empty());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T067: Temporal Validity Filtering
// ============================================================================

/// Test that temporal validity filtering works correctly.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_temporal_validity_filtering() {
    use xavyo_api_governance::services::ParameterService;
    use xavyo_db::SetGovAssignmentParameter;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create parameter
    let param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "database".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: None,
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let service = ParameterService::new(pool.clone());

    // Create assignments with different temporal states
    // 1. Currently active (no dates)
    let active_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'active_hash', NOW(), NOW(), NOW())
        ",
    )
    .bind(active_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create active assignment");

    service
        .set_assignment_parameters(
            tenant_id,
            active_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("active_db"),
            }],
        )
        .await
        .expect("Failed to set parameters");

    // 2. Future assignment (valid_from in future)
    let future_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, valid_from, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'future_hash', NOW() + INTERVAL '30 days', NOW(), NOW(), NOW())
        ",
    )
    .bind(future_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create future assignment");

    service
        .set_assignment_parameters(
            tenant_id,
            future_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("future_db"),
            }],
        )
        .await
        .expect("Failed to set parameters");

    // 3. Expired assignment (valid_to in past)
    let expired_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, valid_to, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'expired_hash', NOW() - INTERVAL '1 day', NOW() - INTERVAL '30 days', NOW(), NOW())
        ",
    )
    .bind(expired_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create expired assignment");

    service
        .set_assignment_parameters(
            tenant_id,
            expired_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("expired_db"),
            }],
        )
        .await
        .expect("Failed to set parameters");

    // Query active only (should return only the currently active one)
    let active_only = service
        .list_parametric_assignments_by_user(tenant_id, user_id, false)
        .await
        .expect("Failed to list active");

    // Should only include the one without temporal constraints
    assert!(active_only.iter().any(|a| a.id == active_id));
    assert!(!active_only.iter().any(|a| a.id == future_id));
    assert!(!active_only.iter().any(|a| a.id == expired_id));

    // Query including inactive (should return all)
    let all = service
        .list_parametric_assignments_by_user(tenant_id, user_id, true)
        .await
        .expect("Failed to list all");

    assert!(all.iter().any(|a| a.id == active_id));
    assert!(all.iter().any(|a| a.id == future_id));
    assert!(all.iter().any(|a| a.id == expired_id));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T068: Audit Trail Completeness
// ============================================================================

/// Test that the audit trail captures all parameter changes.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_audit_trail_completeness() {
    use xavyo_api_governance::services::ParameterService;
    use xavyo_db::SetGovAssignmentParameter;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create parameters
    let param1 = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "database".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: None,
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let param2 = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "port".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Integer,
            is_required: Some(false),
            default_value: Some(serde_json::json!(5432)),
            constraints: None,
            display_order: Some(1),
        },
    )
    .await
    .expect("Failed to create parameter");

    let service = ParameterService::new(pool.clone());

    // Create assignment
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'audit_hash', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    // Action 1: Set initial parameters
    service
        .set_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![
                SetGovAssignmentParameter {
                    parameter_id: param1.id,
                    value: serde_json::json!("initial_db"),
                },
                SetGovAssignmentParameter {
                    parameter_id: param2.id,
                    value: serde_json::json!(5432),
                },
            ],
        )
        .await
        .expect("Failed to set initial parameters");

    // Action 2: Update database
    service
        .update_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param1.id,
                value: serde_json::json!("updated_db"),
            }],
        )
        .await
        .expect("Failed to update database");

    // Action 3: Update port
    service
        .update_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param2.id,
                value: serde_json::json!(3306),
            }],
        )
        .await
        .expect("Failed to update port");

    // Verify audit trail
    let events = service
        .list_assignment_audit(tenant_id, assignment_id)
        .await
        .expect("Failed to list audit");

    // Should have at least 3 events: 1 set + 2 updates
    assert!(events.len() >= 3);

    // Verify event types
    let event_types: Vec<_> = events.iter().map(|e| e.event_type.to_string()).collect();
    assert!(event_types.contains(&"parameters_set".to_string()));
    assert!(
        event_types
            .iter()
            .filter(|t| *t == "parameters_updated")
            .count()
            >= 2
    );

    // Verify each event has actor_id (note: some may have None for system events)
    assert!(events.iter().filter(|e| e.actor_id.is_some()).count() > 0);

    // Query audit events with filter
    use xavyo_db::ParameterAuditFilter;
    let filter = ParameterAuditFilter {
        assignment_id: Some(assignment_id),
        event_type: None,
        actor_id: None,
        from_date: None,
        to_date: None,
    };

    let (filtered_events, count) = service
        .query_audit_events(tenant_id, &filter, 100, 0)
        .await
        .expect("Failed to query events");

    assert_eq!(filtered_events.len() as i64, count);
    assert!(count >= 3);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
