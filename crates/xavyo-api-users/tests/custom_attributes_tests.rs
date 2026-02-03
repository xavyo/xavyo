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
        "SELECT name, data_type::text, required FROM user_attribute_definitions WHERE id = $1 AND tenant_id = $2",
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

    // Verify attribute value was set
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT value FROM user_custom_attributes WHERE user_id = $1 AND definition_id = $2",
    )
    .bind(user_id)
    .bind(definition_id)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(row.is_some(), "Attribute should be set");
    let (stored_value,) = row.unwrap();
    assert_eq!(stored_value, value);

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

    // Query all attributes for user
    let attrs: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT value FROM user_custom_attributes WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&pool)
            .await
            .expect("Query should succeed");

    assert_eq!(attrs.len(), 2, "User should have 2 custom attributes");

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

    // Verify definition has regex
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT validation_regex FROM user_attribute_definitions WHERE tenant_id = $1 AND name = $2",
    )
    .bind(tenant_id)
    .bind(&attr_name)
    .fetch_optional(&pool)
    .await
    .expect("Query should succeed");

    assert!(row.is_some(), "Definition should exist");
    let (regex,) = row.unwrap();
    assert!(regex.is_some(), "Definition should have validation regex");

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

    // Verify all values were stored correctly
    let attrs: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT value FROM user_custom_attributes WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .expect("Query should succeed");

    assert_eq!(attrs.len(), 3, "User should have 3 custom attributes");

    // Verify types
    assert!(attrs[0].0.is_string(), "First value should be string");
    assert!(attrs[1].0.is_number(), "Second value should be number");
    assert!(attrs[2].0.is_boolean(), "Third value should be boolean");

    cleanup_test_tenant(&pool, tenant_id).await;
}
