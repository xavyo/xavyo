//! Common test utilities for xavyo-api-nhi integration tests.
//!
//! Provides shared utilities for test database setup, tenant creation,
//! and test data management.

#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
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
        r#"
        INSERT INTO tenants (id, name, slug, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(format!("Test Tenant {}", tenant_id))
    .bind(format!("test-{}", &tenant_id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("Failed to create test tenant");

    tenant_id
}

/// Create a test user (owner) for NHIs.
pub async fn create_test_user(pool: &PgPool, tenant_id: Uuid, email: &str) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
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

/// Create a test service account directly in the database.
pub async fn create_test_service_account(
    pool: &PgPool,
    tenant_id: Uuid,
    owner_id: Uuid,
    name: &str,
) -> Uuid {
    let sa_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO gov_service_accounts (id, tenant_id, user_id, name, purpose, owner_id, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(sa_id)
    .bind(tenant_id)
    .bind(owner_id) // user_id is same as owner for test
    .bind(name)
    .bind(format!("Test purpose for {}", name))
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("Failed to create test service account");

    sa_id
}

/// Create a test NHI record in the non_human_identities table.
pub async fn create_test_nhi(
    pool: &PgPool,
    tenant_id: Uuid,
    owner_id: Uuid,
    name: &str,
    nhi_type: &str,
) -> Uuid {
    let nhi_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO non_human_identities (
            id, tenant_id, name, description, nhi_type, owner_id, status,
            risk_score, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'active', 25, NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(nhi_id)
    .bind(tenant_id)
    .bind(name)
    .bind(format!("Test NHI: {}", name))
    .bind(nhi_type)
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("Failed to create test NHI");

    nhi_id
}

/// Generate a unique service account name.
pub fn unique_service_account_name() -> String {
    format!("sa-test-{}", Uuid::new_v4())
}

/// Generate a unique agent name.
pub fn unique_agent_name() -> String {
    format!("agent-test-{}", Uuid::new_v4())
}

/// Generate a unique email for testing.
pub fn unique_email() -> String {
    format!("test-{}@example.com", Uuid::new_v4())
}

/// Row struct for service account queries.
#[derive(Debug, FromRow)]
pub struct ServiceAccountRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub purpose: String,
    pub owner_id: Uuid,
    pub status: String,
}

/// Row struct for NHI queries.
#[derive(Debug, FromRow)]
pub struct NhiRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub nhi_type: String,
    pub owner_id: Uuid,
    pub status: String,
    pub risk_score: i32,
}

/// Row struct for credential queries.
#[derive(Debug, FromRow)]
pub struct CredentialRow {
    pub id: Uuid,
    pub nhi_id: Uuid,
    pub tenant_id: Uuid,
    pub is_active: bool,
}

/// Test context containing database pool and tenant IDs.
pub struct TestContext {
    pub pool: PgPool,
    pub tenant_a: Uuid,
    pub tenant_b: Uuid,
    pub owner_a: Uuid,
    pub owner_b: Uuid,
}

impl TestContext {
    /// Create a new test context with two isolated tenants.
    pub async fn new() -> Self {
        let pool = create_test_pool().await;
        let tenant_a = create_test_tenant(&pool).await;
        let tenant_b = create_test_tenant(&pool).await;
        let owner_a = create_test_user(&pool, tenant_a, &unique_email()).await;
        let owner_b = create_test_user(&pool, tenant_b, &unique_email()).await;

        Self {
            pool,
            tenant_a,
            tenant_b,
            owner_a,
            owner_b,
        }
    }

    /// Create a service account for tenant A.
    pub async fn create_service_account_a(&self, name: &str) -> Uuid {
        create_test_service_account(&self.pool, self.tenant_a, self.owner_a, name).await
    }

    /// Create a service account for tenant B.
    pub async fn create_service_account_b(&self, name: &str) -> Uuid {
        create_test_service_account(&self.pool, self.tenant_b, self.owner_b, name).await
    }

    /// Create an NHI for tenant A.
    pub async fn create_nhi_a(&self, name: &str, nhi_type: &str) -> Uuid {
        create_test_nhi(&self.pool, self.tenant_a, self.owner_a, name, nhi_type).await
    }

    /// Create an NHI for tenant B.
    pub async fn create_nhi_b(&self, name: &str, nhi_type: &str) -> Uuid {
        create_test_nhi(&self.pool, self.tenant_b, self.owner_b, name, nhi_type).await
    }
}

/// Clean up test data for a tenant.
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies

    // NHI certifications
    let _ = sqlx::query("DELETE FROM nhi_certifications WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // NHI credentials
    let _ = sqlx::query("DELETE FROM nhi_credentials WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Service accounts
    let _ = sqlx::query("DELETE FROM gov_service_accounts WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Non-human identities
    let _ = sqlx::query("DELETE FROM non_human_identities WHERE tenant_id = $1")
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
