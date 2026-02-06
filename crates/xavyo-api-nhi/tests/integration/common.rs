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
///
/// Uses `DATABASE_URL_SUPERUSER` (preferred) or `DATABASE_URL` for direct DB tests.
/// These integration tests perform direct SQL INSERT/UPDATE/DELETE so they need
/// superuser access (bypasses RLS).
pub async fn create_test_pool() -> PgPool {
    let database_url = env::var("DATABASE_URL_SUPERUSER")
        .or_else(|_| env::var("DATABASE_URL"))
        .unwrap_or_else(|_| {
            "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
        });

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
        ON CONFLICT (id) DO NOTHING
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

/// Create a test user (owner) for NHIs.
pub async fn create_test_user(pool: &PgPool, tenant_id: Uuid, email: &str) -> Uuid {
    let user_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
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

/// Create a test service account directly in the database.
pub async fn create_test_service_account(
    pool: &PgPool,
    tenant_id: Uuid,
    owner_id: Uuid,
    name: &str,
) -> Uuid {
    let sa_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO gov_service_accounts (id, tenant_id, user_id, name, purpose, owner_id, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(sa_id)
    .bind(tenant_id)
    .bind(owner_id) // user_id is same as owner for test
    .bind(name)
    .bind(format!("Test purpose for {name}"))
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("Failed to create test service account");

    sa_id
}

/// Create a test NHI record in the appropriate table based on `nhi_type`.
/// For '`service_account`' -> `gov_service_accounts` table
/// For '`ai_agent`' -> `ai_agents` table
pub async fn create_test_nhi(
    pool: &PgPool,
    tenant_id: Uuid,
    owner_id: Uuid,
    name: &str,
    nhi_type: &str,
) -> Uuid {
    let nhi_id = Uuid::new_v4();

    match nhi_type {
        "service_account" => {
            // Use nhi_id as user_id to ensure uniqueness
            sqlx::query(
                r"
                INSERT INTO gov_service_accounts (
                    id, tenant_id, user_id, name, purpose, owner_id, status,
                    created_at, updated_at
                )
                VALUES ($1, $2, $1, $3, $4, $5, 'active', NOW(), NOW())
                ON CONFLICT (id) DO NOTHING
                ",
            )
            .bind(nhi_id)
            .bind(tenant_id)
            .bind(name)
            .bind(format!("Test NHI: {name}"))
            .bind(owner_id)
            .execute(pool)
            .await
            .expect("Failed to create test service account");
        }
        "ai_agent" => {
            sqlx::query(
                r"
                INSERT INTO ai_agents (
                    id, tenant_id, name, description, agent_type, owner_id, status,
                    risk_level, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, 'autonomous', $5, 'active', 'low', NOW(), NOW())
                ON CONFLICT (id) DO NOTHING
                ",
            )
            .bind(nhi_id)
            .bind(tenant_id)
            .bind(name)
            .bind(format!("Test NHI: {name}"))
            .bind(owner_id)
            .execute(pool)
            .await
            .expect("Failed to create test AI agent");
        }
        _ => panic!("Unknown nhi_type: {nhi_type}"),
    }

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

/// Set risk score for an NHI via the `gov_nhi_risk_scores` table.
pub async fn set_nhi_risk_score(pool: &PgPool, tenant_id: Uuid, nhi_id: Uuid, score: i32) {
    let risk_level = match score {
        0..=39 => "low",
        40..=69 => "medium",
        70..=89 => "high",
        _ => "critical",
    };

    sqlx::query(
        r"
        INSERT INTO gov_nhi_risk_scores (id, tenant_id, nhi_id, total_score, risk_level, factor_breakdown, calculated_at)
        VALUES (gen_random_uuid(), $1, $2, $3, $4::gov_risk_level, '{}', NOW())
        ON CONFLICT (tenant_id, nhi_id) DO UPDATE SET total_score = $3, risk_level = $4::gov_risk_level, calculated_at = NOW()
        ",
    )
    .bind(tenant_id)
    .bind(nhi_id)
    .bind(score)
    .bind(risk_level)
    .execute(pool)
    .await
    .expect("Failed to set NHI risk score");
}

/// Clean up test data for a tenant.
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: Uuid) {
    // Delete in reverse order of dependencies

    // NHI risk scores (FK to gov_service_accounts)
    let _ = sqlx::query("DELETE FROM gov_nhi_risk_scores WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // NHI credentials
    let _ = sqlx::query("DELETE FROM gov_nhi_credentials WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // AI agents
    let _ = sqlx::query("DELETE FROM ai_agents WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;

    // Service accounts
    let _ = sqlx::query("DELETE FROM gov_service_accounts WHERE tenant_id = $1")
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
