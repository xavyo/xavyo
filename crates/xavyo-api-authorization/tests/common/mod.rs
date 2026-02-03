//! Test helpers for xavyo-api-authorization integration tests.
//!
//! Provides utilities for setting up test database, mock services,
//! and common test fixtures for policy CRUD operations.

#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use xavyo_api_authorization::models::policy::{
    CreateConditionRequest, CreatePolicyRequest, PolicyResponse,
};
use xavyo_api_authorization::services::PolicyService;
use xavyo_auth::JwtClaims;
use xavyo_authorization::PolicyCache;

/// Test database URL environment variable.
pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";

/// Get test database connection pool.
///
/// Uses `TEST_DATABASE_URL` environment variable, falls back to default test database.
pub async fn get_test_pool() -> PgPool {
    let database_url = std::env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| "postgres://xavyo:xavyo@localhost:5432/xavyo_test".to_string());

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Create a test tenant and return its ID.
pub async fn create_test_tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let slug = format!("test-tenant-{}", &id.to_string()[..8]);

    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, settings, created_at)
        VALUES ($1, $2, $3, '{}', NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .bind(&slug)
    .bind(&slug)
    .execute(pool)
    .await
    .expect("Failed to create test tenant");

    id
}

/// Create a test user in a tenant and return its ID.
pub async fn create_test_user(pool: &PgPool, tenant_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, created_at, updated_at)
        VALUES ($1, $2, $3, 'test_hash', true, true, NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("Failed to create test user");

    id
}

/// Test fixture for policy CRUD integration tests.
pub struct TestFixture {
    pub pool: PgPool,
    pub tenant_id: Uuid,
    pub admin_user_id: Uuid,
    pub policy_cache: Arc<PolicyCache>,
}

impl TestFixture {
    /// Create a new test fixture with a fresh tenant and admin user.
    pub async fn new() -> Self {
        let pool = get_test_pool().await;
        let tenant_id = create_test_tenant(&pool).await;
        let admin_email = format!("admin-{}@test.com", &tenant_id.to_string()[..8]);
        let admin_user_id = create_test_user(&pool, tenant_id, &admin_email).await;
        let policy_cache = Arc::new(PolicyCache::new());

        Self {
            pool,
            tenant_id,
            admin_user_id,
            policy_cache,
        }
    }

    /// Get a policy service instance for this fixture.
    pub fn policy_service(&self) -> PolicyService {
        PolicyService::new(self.pool.clone(), self.policy_cache.clone())
    }

    /// Clean up the test fixture by removing all test data.
    pub async fn cleanup(&self) {
        // Delete policy conditions first (foreign key constraint)
        sqlx::query("DELETE FROM policy_conditions WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.pool)
            .await
            .ok();

        // Delete authorization policies
        sqlx::query("DELETE FROM authorization_policies WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.pool)
            .await
            .ok();

        // Delete users
        sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.pool)
            .await
            .ok();

        // Delete tenant
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(self.tenant_id)
            .execute(&self.pool)
            .await
            .ok();
    }
}

/// Create JwtClaims for an admin user (has "admin" role).
pub fn admin_claims(tenant_id: Uuid, user_id: Uuid) -> JwtClaims {
    JwtClaims::builder()
        .subject(user_id.to_string())
        .tenant_uuid(tenant_id)
        .roles(vec!["admin".to_string()])
        .expires_in_secs(3600)
        .build()
}

/// Create JwtClaims for a regular user (no "admin" role).
pub fn user_claims(tenant_id: Uuid, user_id: Uuid) -> JwtClaims {
    JwtClaims::builder()
        .subject(user_id.to_string())
        .tenant_uuid(tenant_id)
        .roles(vec!["user".to_string()])
        .expires_in_secs(3600)
        .build()
}

/// Create a minimal test policy for reuse in tests.
pub async fn create_test_policy(fixture: &TestFixture, name: &str) -> PolicyResponse {
    let service = fixture.policy_service();
    let request = CreatePolicyRequest {
        name: name.to_string(),
        description: Some("Test policy".to_string()),
        effect: "allow".to_string(),
        priority: Some(100),
        resource_type: Some("test_resource".to_string()),
        action: Some("read".to_string()),
        conditions: None,
    };

    service
        .create_policy(fixture.tenant_id, request, fixture.admin_user_id)
        .await
        .expect("Failed to create test policy")
}

/// Create a test policy with conditions.
pub async fn create_test_policy_with_conditions(
    fixture: &TestFixture,
    name: &str,
    conditions: Vec<CreateConditionRequest>,
) -> PolicyResponse {
    let service = fixture.policy_service();
    let request = CreatePolicyRequest {
        name: name.to_string(),
        description: Some("Test policy with conditions".to_string()),
        effect: "allow".to_string(),
        priority: Some(100),
        resource_type: Some("test_resource".to_string()),
        action: Some("read".to_string()),
        conditions: Some(conditions),
    };

    service
        .create_policy(fixture.tenant_id, request, fixture.admin_user_id)
        .await
        .expect("Failed to create test policy with conditions")
}

/// Generate a unique policy name for testing.
pub fn unique_policy_name(prefix: &str) -> String {
    format!("{}-{}", prefix, Uuid::new_v4().to_string()[..8].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_claims_has_admin_role() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let claims = admin_claims(tenant_id, user_id);
        assert!(claims.has_role("admin"));
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn user_claims_has_no_admin_role() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let claims = user_claims(tenant_id, user_id);
        assert!(!claims.has_role("admin"));
        assert!(claims.has_role("user"));
    }

    #[test]
    fn unique_policy_name_generates_unique_names() {
        let name1 = unique_policy_name("test");
        let name2 = unique_policy_name("test");
        assert_ne!(name1, name2);
        assert!(name1.starts_with("test-"));
    }
}
