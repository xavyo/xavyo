//! Unit tests for F057 Parametric Roles.
//!
//! Tests for role parameter CRUD operations and parameter type validation.

mod common;

use common::{cleanup_test_tenant, create_test_application, create_test_pool, create_test_tenant};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::{CreateGovRoleParameter, GovRoleParameter, ParameterConstraints, ParameterType};

// ============================================================================
// Test Setup Helpers
// ============================================================================

/// Create a test role (entitlement that represents a role for parametric assignment).
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
    .bind(format!("Database Access Role {role_id}"))
    .bind("A parametric role for database access")
    .execute(pool)
    .await
    .expect("Failed to create test role");

    role_id
}

/// Cleanup parametric role test data.
async fn cleanup_parametric_role_data(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies
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
// T012: CRUD Tests for GovRoleParameter
// ============================================================================

/// Test creating a role parameter.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "database_name".to_string(),
        display_name: Some("Database Name".to_string()),
        description: Some("Name of the database to access".to_string()),
        parameter_type: ParameterType::String,
        is_required: Some(true),
        default_value: None,
        constraints: Some(ParameterConstraints::string(Some(1), Some(255), None)),
        display_order: Some(0),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create parameter");

    assert_eq!(param.name, "database_name");
    assert_eq!(param.display_name, Some("Database Name".to_string()));
    assert_eq!(param.parameter_type, ParameterType::String);
    assert!(param.is_required);
    assert_eq!(param.role_id, role_id);
    assert_eq!(param.tenant_id, tenant_id);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test listing role parameters.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_parameters() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create multiple parameters
    for i in 1..=3 {
        let input = CreateGovRoleParameter {
            name: format!("param_{i}"),
            display_name: Some(format!("Parameter {i}")),
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(i == 1),
            default_value: None,
            constraints: None,
            display_order: Some(i),
        };
        GovRoleParameter::create(&pool, tenant_id, role_id, input)
            .await
            .expect("Failed to create parameter");
    }

    let params = GovRoleParameter::list_by_role(&pool, tenant_id, role_id)
        .await
        .expect("Failed to list parameters");

    assert_eq!(params.len(), 3);
    // Verify sorted by display_order
    assert_eq!(params[0].display_order, 1);
    assert_eq!(params[1].display_order, 2);
    assert_eq!(params[2].display_order, 3);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test updating a role parameter.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "port".to_string(),
        display_name: Some("Port Number".to_string()),
        description: None,
        parameter_type: ParameterType::Integer,
        is_required: Some(false),
        default_value: Some(serde_json::json!(5432)),
        constraints: None,
        display_order: Some(0),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create parameter");

    let update = xavyo_db::UpdateGovRoleParameter {
        display_name: Some("Database Port".to_string()),
        description: Some("PostgreSQL port number".to_string()),
        is_required: Some(true),
        default_value: None, // Keep existing
        constraints: None,
        display_order: None,
    };

    let updated = GovRoleParameter::update(&pool, tenant_id, param.id, update)
        .await
        .expect("Failed to update parameter")
        .expect("Parameter not found");

    assert_eq!(updated.display_name, Some("Database Port".to_string()));
    assert_eq!(
        updated.description,
        Some("PostgreSQL port number".to_string())
    );
    assert!(updated.is_required);
    assert!(updated.default_value.is_none());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test deleting a role parameter.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "to_delete".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::Boolean,
        is_required: Some(false),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create parameter");

    // Verify it exists
    let found = GovRoleParameter::find_by_id(&pool, tenant_id, param.id)
        .await
        .expect("Query failed");
    assert!(found.is_some());

    // Delete it
    GovRoleParameter::delete(&pool, tenant_id, param.id)
        .await
        .expect("Failed to delete parameter");

    // Verify it's gone
    let not_found = GovRoleParameter::find_by_id(&pool, tenant_id, param.id)
        .await
        .expect("Query failed");
    assert!(not_found.is_none());

    // Cleanup
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test finding parameter by name.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_find_parameter_by_name() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "unique_name".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::String,
        is_required: Some(false),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };

    let created = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create parameter");

    let found = GovRoleParameter::find_by_name(&pool, tenant_id, role_id, "unique_name")
        .await
        .expect("Query failed")
        .expect("Parameter not found");

    assert_eq!(found.id, created.id);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T013: Parameter Type Validation Tests
// ============================================================================

/// Test string parameter with constraints.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_string_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "hostname".to_string(),
        display_name: Some("Host Name".to_string()),
        description: Some("Database hostname".to_string()),
        parameter_type: ParameterType::String,
        is_required: Some(true),
        default_value: Some(serde_json::json!("localhost")),
        constraints: Some(ParameterConstraints::string(
            Some(1),
            Some(255),
            Some("^[a-zA-Z0-9.-]+$".to_string()),
        )),
        display_order: Some(0),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create string parameter");

    assert_eq!(param.parameter_type, ParameterType::String);
    assert!(param.constraints.is_some());

    let constraints: ParameterConstraints =
        serde_json::from_value(param.constraints.unwrap()).expect("Invalid constraints");
    assert_eq!(constraints.min_length, Some(1));
    assert_eq!(constraints.max_length, Some(255));
    assert_eq!(constraints.pattern, Some("^[a-zA-Z0-9.-]+$".to_string()));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test integer parameter with min/max constraints.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_integer_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "port".to_string(),
        display_name: Some("Port Number".to_string()),
        description: Some("Database port (1-65535)".to_string()),
        parameter_type: ParameterType::Integer,
        is_required: Some(true),
        default_value: Some(serde_json::json!(5432)),
        constraints: Some(ParameterConstraints::integer(Some(1), Some(65535))),
        display_order: Some(1),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create integer parameter");

    assert_eq!(param.parameter_type, ParameterType::Integer);
    assert_eq!(param.default_value, Some(serde_json::json!(5432)));

    let constraints: ParameterConstraints =
        serde_json::from_value(param.constraints.unwrap()).expect("Invalid constraints");
    assert_eq!(constraints.min_value, Some(1));
    assert_eq!(constraints.max_value, Some(65535));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test boolean parameter.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_boolean_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "ssl_enabled".to_string(),
        display_name: Some("SSL Enabled".to_string()),
        description: Some("Enable SSL connection".to_string()),
        parameter_type: ParameterType::Boolean,
        is_required: Some(false),
        default_value: Some(serde_json::json!(true)),
        constraints: None, // Boolean has no constraints
        display_order: Some(2),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create boolean parameter");

    assert_eq!(param.parameter_type, ParameterType::Boolean);
    assert_eq!(param.default_value, Some(serde_json::json!(true)));
    assert!(param.constraints.is_none());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test date parameter with min/max date constraints.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_date_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "valid_until".to_string(),
        display_name: Some("Valid Until".to_string()),
        description: Some("Access validity date".to_string()),
        parameter_type: ParameterType::Date,
        is_required: Some(false),
        default_value: None,
        constraints: Some(ParameterConstraints::date(
            Some("2024-01-01".to_string()),
            Some("2030-12-31".to_string()),
        )),
        display_order: Some(3),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create date parameter");

    assert_eq!(param.parameter_type, ParameterType::Date);

    let constraints: ParameterConstraints =
        serde_json::from_value(param.constraints.unwrap()).expect("Invalid constraints");
    assert_eq!(constraints.min_date, Some("2024-01-01".to_string()));
    assert_eq!(constraints.max_date, Some("2030-12-31".to_string()));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test enum parameter with allowed values.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_enum_parameter() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "environment".to_string(),
        display_name: Some("Environment".to_string()),
        description: Some("Target environment".to_string()),
        parameter_type: ParameterType::Enum,
        is_required: Some(true),
        default_value: Some(serde_json::json!("development")),
        constraints: Some(ParameterConstraints::enumeration(vec![
            "development".to_string(),
            "staging".to_string(),
            "production".to_string(),
        ])),
        display_order: Some(4),
    };

    let param = GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create enum parameter");

    assert_eq!(param.parameter_type, ParameterType::Enum);
    assert_eq!(param.default_value, Some(serde_json::json!("development")));

    let constraints: ParameterConstraints =
        serde_json::from_value(param.constraints.unwrap()).expect("Invalid constraints");
    assert_eq!(
        constraints.allowed_values,
        Some(vec![
            "development".to_string(),
            "staging".to_string(),
            "production".to_string()
        ])
    );

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test `role_has_parameters` check.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_role_has_parameters() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Initially no parameters
    let has_params = GovRoleParameter::role_has_parameters(&pool, tenant_id, role_id)
        .await
        .expect("Query failed");
    assert!(!has_params);

    // Add a parameter
    let input = CreateGovRoleParameter {
        name: "test_param".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::String,
        is_required: Some(false),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };
    GovRoleParameter::create(&pool, tenant_id, role_id, input)
        .await
        .expect("Failed to create parameter");

    // Now has parameters
    let has_params = GovRoleParameter::role_has_parameters(&pool, tenant_id, role_id)
        .await
        .expect("Query failed");
    assert!(has_params);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test duplicate parameter name prevention.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_duplicate_parameter_name() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let input = CreateGovRoleParameter {
        name: "duplicate_name".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::String,
        is_required: Some(false),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };

    // First creation succeeds
    GovRoleParameter::create(&pool, tenant_id, role_id, input.clone())
        .await
        .expect("Failed to create first parameter");

    // Second creation with same name should fail due to unique constraint
    let result = GovRoleParameter::create(&pool, tenant_id, role_id, input).await;
    assert!(result.is_err());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
