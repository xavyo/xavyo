//! Integration tests for Custom Attributes (User Story 5).
//!
//! These tests verify that custom attribute definitions and user attribute values work correctly.
//!
//! Run with: `cargo test -p xavyo-api-users --features integration custom_attributes -- --ignored`

mod common;

use common::*;
use serde_json::json;
// Note: AttributeDefinitionService and UserAttributeService tested indirectly
// through database operations and AttributeAuditService
// TenantId not used - AttributeAuditService uses raw Uuid

// =========================================================================
// Attribute Definition Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_attribute_definition() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let attr_name = unique_attribute_name();

    let definition_id =
        create_test_attribute_definition(&pool, tenant_id, &attr_name, "string", false).await;

    // Verify definition was created
    let row: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT name, data_type, required FROM tenant_attribute_definitions WHERE id = $1 AND tenant_id = $2",
    )
    .bind(definition_id)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(row.is_some(), "Definition should exist");
    let (name, data_type, required) = row.unwrap();
    assert_eq!(name, attr_name);
    assert_eq!(data_type, "string");
    assert!(!required);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_set_user_custom_attribute() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let definition_id = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "string",
        false,
    )
    .await;

    let user_id = create_test_user(&pool, tenant_id, &unique_email()).await;

    let value = json!("test value");
    set_user_custom_attribute(&pool, user_id, definition_id, value.clone()).await;

    // Verify attribute value was set in users.custom_attributes JSONB
    // First look up the attribute name from the definition
    let (attr_name,): (String,) =
        sqlx::query_as("SELECT name FROM tenant_attribute_definitions WHERE id = $1")
            .bind(definition_id)
            .fetch_one(&pool)
            .await
            .expect("Definition lookup should succeed");

    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT custom_attributes FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&pool)
            .await
            .expect("Query should succeed");

    assert!(row.is_some(), "User should exist");
    let (custom_attrs,) = row.unwrap();
    let stored_value = custom_attrs
        .get(&attr_name)
        .expect("Attribute should be set");
    assert_eq!(*stored_value, value);

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_user_custom_attributes() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create multiple attribute definitions
    let attr1_id = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "string",
        false,
    )
    .await;

    let attr2_id = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "number",
        false,
    )
    .await;

    let user_id = create_test_user(&pool, tenant_id, &unique_email()).await;

    // Set values
    set_user_custom_attribute(&pool, user_id, attr1_id, json!("hello")).await;
    set_user_custom_attribute(&pool, user_id, attr2_id, json!(42)).await;

    // Query custom attributes from user's JSONB column
    let row: (serde_json::Value,) =
        sqlx::query_as("SELECT custom_attributes FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    let obj = row
        .0
        .as_object()
        .expect("custom_attributes should be an object");
    assert_eq!(obj.len(), 2, "User should have 2 custom attributes");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_required_attribute_validation() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create a required attribute definition
    let attr_name = unique_attribute_name();
    let _definition_id = create_test_attribute_definition(
        &pool, tenant_id, &attr_name, "string", true, // required = true
    )
    .await;

    // Create a user WITHOUT setting the required attribute
    let _user_id = create_test_user(&pool, tenant_id, &unique_email()).await;

    // Check if validation service detects missing required attribute
    let service = xavyo_api_users::services::AttributeAuditService::new(pool.clone());

    let result = service
        .audit_missing_required(tenant_id, None, 0, 100)
        .await;

    assert!(result.is_ok(), "Audit should succeed");
    let audit_result = result.unwrap();

    // The user should be flagged for missing required attribute
    assert!(
        !audit_result.users.is_empty() || audit_result.total_missing_count > 0,
        "User should be flagged for missing required attribute"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_attribute_validation_regex() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create attribute definition with regex validation (e.g., email pattern)
    let attr_name = unique_attribute_name();
    let _definition_id = create_test_attribute_definition_with_regex(
        &pool,
        tenant_id,
        &attr_name,
        "string",
        false,
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", // Email regex
    )
    .await;

    // Verify definition has validation_rules with pattern
    let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as(
        "SELECT validation_rules FROM tenant_attribute_definitions WHERE tenant_id = $1 AND name = $2",
    )
    .bind(tenant_id)
    .bind(&attr_name)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(row.is_some(), "Definition should exist");
    let (rules,) = row.unwrap();
    assert!(rules.is_some(), "Definition should have validation rules");
    let rules_obj = rules.unwrap();
    assert!(
        rules_obj.get("pattern").is_some(),
        "Validation rules should contain a pattern"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_attribute_data_type_validation() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create attribute definitions of different types
    let string_attr = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "string",
        false,
    )
    .await;

    let number_attr = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "number",
        false,
    )
    .await;

    let boolean_attr = create_test_attribute_definition(
        &pool,
        tenant_id,
        &unique_attribute_name(),
        "boolean",
        false,
    )
    .await;

    let user_id = create_test_user(&pool, tenant_id, &unique_email()).await;

    // Set values of correct types
    set_user_custom_attribute(&pool, user_id, string_attr, json!("text")).await;
    set_user_custom_attribute(&pool, user_id, number_attr, json!(123)).await;
    set_user_custom_attribute(&pool, user_id, boolean_attr, json!(true)).await;

    // Verify all values were stored correctly in users.custom_attributes JSONB
    let row: (serde_json::Value,) =
        sqlx::query_as("SELECT custom_attributes FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");

    let obj = row
        .0
        .as_object()
        .expect("custom_attributes should be an object");
    assert_eq!(obj.len(), 3, "User should have 3 custom attributes");

    // Verify types (look up attribute names from definitions)
    let (string_name,): (String,) =
        sqlx::query_as("SELECT name FROM tenant_attribute_definitions WHERE id = $1")
            .bind(string_attr)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (number_name,): (String,) =
        sqlx::query_as("SELECT name FROM tenant_attribute_definitions WHERE id = $1")
            .bind(number_attr)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (boolean_name,): (String,) =
        sqlx::query_as("SELECT name FROM tenant_attribute_definitions WHERE id = $1")
            .bind(boolean_attr)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        obj.get(&string_name).unwrap().is_string(),
        "String value should be string"
    );
    assert!(
        obj.get(&number_name).unwrap().is_number(),
        "Number value should be number"
    );
    assert!(
        obj.get(&boolean_name).unwrap().is_boolean(),
        "Boolean value should be boolean"
    );

    cleanup_test_tenant(&pool, tenant_id).await;
}
