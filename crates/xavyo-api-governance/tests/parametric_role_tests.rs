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

// ============================================================================
// T023: Parametric Assignment Creation Tests
// ============================================================================

/// Test creating an assignment with parameter values.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_assignment_with_params() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create a parameter on the role
    let param_input = CreateGovRoleParameter {
        name: "database_name".to_string(),
        display_name: Some("Database Name".to_string()),
        description: None,
        parameter_type: ParameterType::String,
        is_required: Some(true),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };
    let param = GovRoleParameter::create(&pool, tenant_id, role_id, param_input)
        .await
        .expect("Failed to create parameter");

    // Create an assignment
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
    .bind("hash_production_db")
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    // Set the parameter value
    sqlx::query(
        r"
        INSERT INTO gov_role_assignment_parameters (id, tenant_id, assignment_id, parameter_id, value, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(assignment_id)
    .bind(param.id)
    .bind(serde_json::json!("production_db"))
    .execute(&pool)
    .await
    .expect("Failed to set parameter value");

    // Verify the parameter value was stored
    let values =
        xavyo_db::GovRoleAssignmentParameter::list_by_assignment(&pool, tenant_id, assignment_id)
            .await
            .expect("Failed to list assignment parameters");

    assert_eq!(values.len(), 1);
    assert_eq!(values[0].parameter_id, param.id);
    assert_eq!(values[0].value, serde_json::json!("production_db"));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that missing required parameter values cause an error.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_missing_required_param() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create a required parameter
    let param_input = CreateGovRoleParameter {
        name: "required_param".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::String,
        is_required: Some(true),
        default_value: None,
        constraints: None,
        display_order: Some(0),
    };
    let param = GovRoleParameter::create(&pool, tenant_id, role_id, param_input)
        .await
        .expect("Failed to create parameter");

    // Validate with empty values - should fail
    let params = vec![param];
    let empty_values: HashMap<Uuid, serde_json::Value> = HashMap::new();

    let validation_service = ParameterValidationService::new();
    let result = validation_service.validate(&params, &empty_values);

    assert!(!result.is_valid);
    assert!(!result.errors.is_empty());
    assert!(result.errors.iter().any(|e| e.contains("required_param")));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that default values are applied for missing optional parameters.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_default_value_applied() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create an optional parameter with a default value
    let param_input = CreateGovRoleParameter {
        name: "port".to_string(),
        display_name: None,
        description: None,
        parameter_type: ParameterType::Integer,
        is_required: Some(false),
        default_value: Some(serde_json::json!(5432)),
        constraints: None,
        display_order: Some(0),
    };
    let param = GovRoleParameter::create(&pool, tenant_id, role_id, param_input)
        .await
        .expect("Failed to create parameter");

    // Validate with empty values - should pass because parameter is optional
    let params = vec![param.clone()];
    let empty_values: HashMap<Uuid, serde_json::Value> = HashMap::new();

    let validation_service = ParameterValidationService::new();
    let result = validation_service.validate(&params, &empty_values);

    assert!(result.is_valid);

    // Verify the parameter has a default value
    assert_eq!(param.default_value, Some(serde_json::json!(5432)));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T024: Parameter Hash Tests
// ============================================================================

/// Test that parameter hash is deterministic.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_parameter_hash_deterministic() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create some parameters
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
            default_value: None,
            constraints: None,
            display_order: Some(1),
        },
    )
    .await
    .expect("Failed to create parameter");

    let params = vec![param1.clone(), param2.clone()];
    let mut values = HashMap::new();
    values.insert(param1.id, serde_json::json!("production"));
    values.insert(param2.id, serde_json::json!(5432));

    // Compute hash multiple times
    let hash1 = ParameterValidationService::compute_parameter_hash(&params, &values);
    let hash2 = ParameterValidationService::compute_parameter_hash(&params, &values);
    let hash3 = ParameterValidationService::compute_parameter_hash(&params, &values);

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that different parameter values produce different hashes.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_parameter_hash_different_values() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

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

    let params = vec![param.clone()];

    let mut values1 = HashMap::new();
    values1.insert(param.id, serde_json::json!("production"));

    let mut values2 = HashMap::new();
    values2.insert(param.id, serde_json::json!("staging"));

    let hash1 = ParameterValidationService::compute_parameter_hash(&params, &values1);
    let hash2 = ParameterValidationService::compute_parameter_hash(&params, &values2);

    assert_ne!(hash1, hash2);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T034: Entitlement Parameter Context Tests
// ============================================================================

/// Test that entitlements include parameter values.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_entitlement_includes_params() {
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

    // Create assignment with parameter_hash
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_finance_db', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    // Set parameter value
    sqlx::query(
        r"
        INSERT INTO gov_role_assignment_parameters (id, tenant_id, assignment_id, parameter_id, value, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(assignment_id)
    .bind(param.id)
    .bind(serde_json::json!("finance_db"))
    .execute(&pool)
    .await
    .expect("Failed to set parameter value");

    // Verify assignment has parameter_hash set (indicating parametric assignment)
    let assignment =
        xavyo_db::GovEntitlementAssignment::find_by_id(&pool, tenant_id, assignment_id)
            .await
            .expect("Failed to find assignment")
            .expect("Assignment not found");

    assert!(assignment.parameter_hash.is_some());
    assert_eq!(assignment.parameter_hash.unwrap(), "hash_finance_db");

    // Verify parameter value is stored
    let values =
        xavyo_db::GovRoleAssignmentParameter::list_by_assignment(&pool, tenant_id, assignment_id)
            .await
            .expect("Failed to list parameters");

    assert_eq!(values.len(), 1);
    assert_eq!(values[0].value, serde_json::json!("finance_db"));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T039: Multiple Parametric Assignments Tests
// ============================================================================

/// Test that the same role can be assigned with different parameters.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_same_role_different_params() {
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

    // Create first assignment with "production_db"
    let assignment1_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_production', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment1_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create first assignment");

    sqlx::query(
        r"
        INSERT INTO gov_role_assignment_parameters (id, tenant_id, assignment_id, parameter_id, value, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(assignment1_id)
    .bind(param.id)
    .bind(serde_json::json!("production_db"))
    .execute(&pool)
    .await
    .expect("Failed to set first parameter value");

    // Create second assignment with "staging_db" (different hash)
    let assignment2_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_staging', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment2_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create second assignment");

    sqlx::query(
        r"
        INSERT INTO gov_role_assignment_parameters (id, tenant_id, assignment_id, parameter_id, value, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(assignment2_id)
    .bind(param.id)
    .bind(serde_json::json!("staging_db"))
    .execute(&pool)
    .await
    .expect("Failed to set second parameter value");

    // Verify both assignments exist
    let assignments = xavyo_db::GovEntitlementAssignment::list_parametric_by_user_and_role(
        &pool, tenant_id, user_id, role_id,
    )
    .await
    .expect("Failed to list assignments");

    assert_eq!(assignments.len(), 2);

    // Verify each has different parameter hash
    let hashes: Vec<_> = assignments
        .iter()
        .filter_map(|a| a.parameter_hash.clone())
        .collect();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&"hash_production".to_string()));
    assert!(hashes.contains(&"hash_staging".to_string()));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test revoking one parametric instance keeps the other.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_revoke_one_keeps_other() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create parameter
    let _param = GovRoleParameter::create(
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

    // Create two assignments
    let assignment1_id = Uuid::new_v4();
    let assignment2_id = Uuid::new_v4();

    for (id, hash) in [
        (assignment1_id, "hash_production"),
        (assignment2_id, "hash_staging"),
    ] {
        sqlx::query(
            r"
            INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
            VALUES ($1, $2, 'user', $3, $4, 'active', $5, NOW(), NOW(), NOW())
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(role_id)
        .bind(hash)
        .execute(&pool)
        .await
        .expect("Failed to create assignment");
    }

    // Revoke first assignment
    xavyo_db::GovEntitlementAssignment::revoke(&pool, tenant_id, assignment1_id)
        .await
        .expect("Failed to revoke assignment");

    // Verify second assignment still exists
    let remaining = xavyo_db::GovEntitlementAssignment::list_parametric_by_user_and_role(
        &pool, tenant_id, user_id, role_id,
    )
    .await
    .expect("Failed to list assignments");

    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, assignment2_id);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test that duplicate parameter values are rejected.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_duplicate_params_rejected() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create first assignment
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'same_hash', NOW(), NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create first assignment");

    // Try to create second assignment with same hash - should fail due to unique constraint
    let result = sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'same_hash', NOW(), NOW(), NOW())
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await;

    assert!(result.is_err());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T044/T045: Parameter Validation Tests
// ============================================================================

/// Test enum validation with allowed values.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_enum_validation() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let param = GovRoleParameter::create(
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
                "production".to_string(),
            ])),
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let params = vec![param.clone()];
    let validation_service = ParameterValidationService::new();

    // Valid value
    let mut valid_values = HashMap::new();
    valid_values.insert(param.id, serde_json::json!("staging"));
    let result = validation_service.validate(&params, &valid_values);
    assert!(result.is_valid);

    // Invalid value
    let mut invalid_values = HashMap::new();
    invalid_values.insert(param.id, serde_json::json!("superuser"));
    let result = validation_service.validate(&params, &invalid_values);
    assert!(!result.is_valid);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test integer range validation.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_integer_range() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let param = GovRoleParameter::create(
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
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let params = vec![param.clone()];
    let validation_service = ParameterValidationService::new();

    // Valid value
    let mut valid_values = HashMap::new();
    valid_values.insert(param.id, serde_json::json!(5432));
    let result = validation_service.validate(&params, &valid_values);
    assert!(result.is_valid);

    // Value too low
    let mut low_values = HashMap::new();
    low_values.insert(param.id, serde_json::json!(0));
    let result = validation_service.validate(&params, &low_values);
    assert!(!result.is_valid);

    // Value too high
    let mut high_values = HashMap::new();
    high_values.insert(param.id, serde_json::json!(70000));
    let result = validation_service.validate(&params, &high_values);
    assert!(!result.is_valid);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test string pattern validation.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_string_pattern() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "hostname".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::String,
            is_required: Some(true),
            default_value: None,
            constraints: Some(ParameterConstraints::string(
                Some(1),
                Some(255),
                Some("^[a-zA-Z0-9.-]+$".to_string()),
            )),
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let params = vec![param.clone()];
    let validation_service = ParameterValidationService::new();

    // Valid hostname
    let mut valid_values = HashMap::new();
    valid_values.insert(param.id, serde_json::json!("db.example.com"));
    let result = validation_service.validate(&params, &valid_values);
    assert!(result.is_valid);

    // Invalid hostname (contains space)
    let mut invalid_values = HashMap::new();
    invalid_values.insert(param.id, serde_json::json!("db example.com"));
    let result = validation_service.validate(&params, &invalid_values);
    assert!(!result.is_valid);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test date range validation.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_date_range() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterValidationService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    let param = GovRoleParameter::create(
        &pool,
        tenant_id,
        role_id,
        CreateGovRoleParameter {
            name: "valid_until".to_string(),
            display_name: None,
            description: None,
            parameter_type: ParameterType::Date,
            is_required: Some(true),
            default_value: None,
            constraints: Some(ParameterConstraints::date(
                Some("2024-01-01".to_string()),
                Some("2030-12-31".to_string()),
            )),
            display_order: Some(0),
        },
    )
    .await
    .expect("Failed to create parameter");

    let params = vec![param.clone()];
    let validation_service = ParameterValidationService::new();

    // Valid date
    let mut valid_values = HashMap::new();
    valid_values.insert(param.id, serde_json::json!("2025-06-15"));
    let result = validation_service.validate(&params, &valid_values);
    assert!(result.is_valid);

    // Date before min
    let mut early_values = HashMap::new();
    early_values.insert(param.id, serde_json::json!("2023-01-01"));
    let result = validation_service.validate(&params, &early_values);
    assert!(!result.is_valid);

    // Date after max
    let mut late_values = HashMap::new();
    late_values.insert(param.id, serde_json::json!("2035-01-01"));
    let result = validation_service.validate(&params, &late_values);
    assert!(!result.is_valid);

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test validate parameters endpoint success.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validate_parameters_success() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

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

    // Validate with correct values
    let mut values = HashMap::new();
    values.insert(param.id, serde_json::json!("my_database"));

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Failed to validate");

    assert!(result.is_valid);
    assert!(result.errors.is_empty());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test validate parameters endpoint failure.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validate_parameters_failure() {
    use std::collections::HashMap;
    use xavyo_api_governance::services::ParameterService;

    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;

    // Create required parameter
    let _param = GovRoleParameter::create(
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

    // Validate with empty values (missing required)
    let values: HashMap<Uuid, serde_json::Value> = HashMap::new();

    let result = service
        .validate_parameters(tenant_id, role_id, &values)
        .await
        .expect("Failed to validate");

    assert!(!result.is_valid);
    assert!(!result.errors.is_empty());

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T053: Temporal Validity Tests
// ============================================================================

/// Test assignment with valid_from in future is inactive.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_valid_from_future() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create assignment with valid_from in the future
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, valid_from, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_future', NOW() + INTERVAL '7 days', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create future assignment");

    // Query active assignments (should not include future ones)
    let active = xavyo_db::GovEntitlementAssignment::list_active_parametric_by_user(
        &pool, tenant_id, user_id, false,
    )
    .await
    .expect("Failed to list active");

    // The assignment should not be in active list if valid_from filter is applied
    assert!(active.iter().all(|a| a.id != assignment_id));

    // Query with include_inactive should show it
    let all = xavyo_db::GovEntitlementAssignment::list_active_parametric_by_user(
        &pool, tenant_id, user_id, true,
    )
    .await
    .expect("Failed to list all");

    assert!(all.iter().any(|a| a.id == assignment_id));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test assignment with valid_to in past is inactive.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_valid_to_past() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create assignment with valid_to in the past
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, valid_to, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_past', NOW() - INTERVAL '1 day', NOW() - INTERVAL '7 days', NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create past assignment");

    // Query active assignments (should not include expired ones)
    let active = xavyo_db::GovEntitlementAssignment::list_active_parametric_by_user(
        &pool, tenant_id, user_id, false,
    )
    .await
    .expect("Failed to list active");

    assert!(active.iter().all(|a| a.id != assignment_id));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test assignment within validity window is active.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_within_validity_window() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let role_id = create_test_role(&pool, tenant_id, app_id).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    // Create assignment within validity window
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, valid_from, valid_to, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_valid', NOW() - INTERVAL '1 day', NOW() + INTERVAL '7 days', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create valid assignment");

    // Query active assignments (should include this one)
    let active = xavyo_db::GovEntitlementAssignment::list_active_parametric_by_user(
        &pool, tenant_id, user_id, false,
    )
    .await
    .expect("Failed to list active");

    assert!(active.iter().any(|a| a.id == assignment_id));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// T058: Parameter Audit Event Tests
// ============================================================================

/// Test audit event is recorded when parameters are set.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_audit_parameters_set() {
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

    // Create assignment
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_audit', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    // Set parameters (this should create an audit event)
    let service = ParameterService::new(pool.clone());
    service
        .set_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("test_db"),
            }],
        )
        .await
        .expect("Failed to set parameters");

    // Verify audit event was created
    let events =
        xavyo_db::GovParameterAuditEvent::list_by_assignment(&pool, tenant_id, assignment_id)
            .await
            .expect("Failed to list audit events");

    assert!(!events.is_empty());
    assert!(events
        .iter()
        .any(|e| e.event_type.to_string() == "parameters_set"));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// Test audit event is recorded when parameters are updated.
#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_audit_parameters_updated() {
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

    // Create assignment
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO gov_entitlement_assignments (id, tenant_id, target_type, target_id, entitlement_id, status, parameter_hash, granted_at, created_at, updated_at)
        VALUES ($1, $2, 'user', $3, $4, 'active', 'hash_update', NOW(), NOW(), NOW())
        ",
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("Failed to create assignment");

    let service = ParameterService::new(pool.clone());

    // Set initial parameters
    service
        .set_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("old_db"),
            }],
        )
        .await
        .expect("Failed to set initial parameters");

    // Update parameters
    service
        .update_assignment_parameters(
            tenant_id,
            assignment_id,
            user_id,
            vec![SetGovAssignmentParameter {
                parameter_id: param.id,
                value: serde_json::json!("new_db"),
            }],
        )
        .await
        .expect("Failed to update parameters");

    // Verify audit events
    let events =
        xavyo_db::GovParameterAuditEvent::list_by_assignment(&pool, tenant_id, assignment_id)
            .await
            .expect("Failed to list audit events");

    assert!(events.len() >= 2);
    assert!(events
        .iter()
        .any(|e| e.event_type.to_string() == "parameters_set"));
    assert!(events
        .iter()
        .any(|e| e.event_type.to_string() == "parameters_updated"));

    // Cleanup
    cleanup_parametric_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// ============================================================================
// Additional User Creation Helper
// ============================================================================

/// Create a test user.
async fn create_test_user(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    common::create_test_user(pool, tenant_id).await
}
