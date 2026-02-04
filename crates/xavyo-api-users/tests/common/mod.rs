//! Common test utilities for xavyo-api-users integration tests.
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

/// Create a test user with email and password.
pub async fn create_test_user(pool: &PgPool, tenant_id: Uuid, email: &str) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, NOW(), NOW())
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(email)
    .bind("$argon2id$v=19$m=65536,t=3,p=4$dummy$hash") // Fake hash for testing
    .execute(pool)
    .await
    .expect("Failed to create test user");

    user_id
}

/// Create a test user with roles.
pub async fn create_test_user_with_roles(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    roles: &[&str],
) -> Uuid {
    let user_id = Uuid::new_v4();
    let roles_array: Vec<String> = roles.iter().map(std::string::ToString::to_string).collect();

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, roles, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(email)
    .bind("$argon2id$v=19$m=65536,t=3,p=4$dummy$hash")
    .bind(&roles_array)
    .execute(pool)
    .await
    .expect("Failed to create test user with roles");

    user_id
}

/// Create a test group.
pub async fn create_test_group(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let group_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO groups (id, tenant_id, name, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        ",
    )
    .bind(group_id)
    .bind(tenant_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("Failed to create test group");

    group_id
}

/// Create a test group with parent.
pub async fn create_test_group_with_parent(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    parent_group_id: Uuid,
) -> Uuid {
    let group_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO groups (id, tenant_id, name, parent_group_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ",
    )
    .bind(group_id)
    .bind(tenant_id)
    .bind(name)
    .bind(parent_group_id)
    .execute(pool)
    .await
    .expect("Failed to create test group with parent");

    group_id
}

/// Add a user to a group.
pub async fn add_user_to_group(pool: &PgPool, tenant_id: Uuid, group_id: Uuid, user_id: Uuid) {
    sqlx::query(
        r"
        INSERT INTO group_members (group_id, user_id, tenant_id, created_at)
        VALUES ($1, $2, $3, NOW())
        ",
    )
    .bind(group_id)
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to add user to group");
}

/// Create a test attribute definition.
pub async fn create_test_attribute_definition(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    data_type: &str,
    required: bool,
) -> Uuid {
    let definition_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO user_attribute_definitions (id, tenant_id, name, display_name, data_type, required, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5::user_attribute_data_type, $6, NOW(), NOW())
        ",
    )
    .bind(definition_id)
    .bind(tenant_id)
    .bind(name)
    .bind(format!("Test {name}"))
    .bind(data_type)
    .bind(required)
    .execute(pool)
    .await
    .expect("Failed to create test attribute definition");

    definition_id
}

/// Create a test attribute definition with validation regex.
pub async fn create_test_attribute_definition_with_regex(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    data_type: &str,
    required: bool,
    validation_regex: &str,
) -> Uuid {
    let definition_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO user_attribute_definitions (id, tenant_id, name, display_name, data_type, required, validation_regex, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5::user_attribute_data_type, $6, $7, NOW(), NOW())
        ",
    )
    .bind(definition_id)
    .bind(tenant_id)
    .bind(name)
    .bind(format!("Test {name}"))
    .bind(data_type)
    .bind(required)
    .bind(validation_regex)
    .execute(pool)
    .await
    .expect("Failed to create test attribute definition with regex");

    definition_id
}

/// Set a custom attribute value on a user.
pub async fn set_user_custom_attribute(
    pool: &PgPool,
    user_id: Uuid,
    definition_id: Uuid,
    value: serde_json::Value,
) {
    sqlx::query(
        r"
        INSERT INTO user_custom_attributes (user_id, definition_id, value, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        ON CONFLICT (user_id, definition_id) DO UPDATE SET value = $3, updated_at = NOW()
        ",
    )
    .bind(user_id)
    .bind(definition_id)
    .bind(&value)
    .execute(pool)
    .await
    .expect("Failed to set user custom attribute");
}

/// Generate a unique email for testing.
pub fn unique_email() -> String {
    format!("test-{}@example.com", Uuid::new_v4())
}

/// Generate a unique group name for testing.
pub fn unique_group_name() -> String {
    format!("test-group-{}", Uuid::new_v4())
}

/// Generate a unique attribute name for testing.
/// Attribute names must match the pattern: ^[a-z][a-z0-9_]{0,63}$
pub fn unique_attribute_name() -> String {
    let uuid_str = Uuid::new_v4().to_string().replace('-', "");
    format!("attr_{}", &uuid_str[..8])
}

/// Clean up test data for a tenant.
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies

    // Custom attributes
    let _ = sqlx::query(
        "DELETE FROM user_custom_attributes WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)",
    )
    .bind(tenant_id)
    .execute(pool)
    .await;

    let _ = sqlx::query("DELETE FROM user_attribute_definitions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Group members
    let _ = sqlx::query("DELETE FROM group_members WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Groups (need to delete children first due to parent_group_id constraint)
    // First, remove parent references
    let _ = sqlx::query("UPDATE groups SET parent_group_id = NULL WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM groups WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Users
    let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Tenant
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}
