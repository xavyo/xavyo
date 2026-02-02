//! Integration test helpers for xavyo-db.
//!
//! Provides utilities for setting up test databases, creating test data,
//! and managing the test environment.
//!
//! # Usage
//!
//! ```ignore
//! use crate::common::TestContext;
//!
//! #[tokio::test]
//! async fn my_integration_test() {
//!     let ctx = TestContext::new().await;
//!     // ... test code using ctx.pool ...
//!     ctx.cleanup().await;
//! }
//! ```

use std::sync::Once;
use xavyo_core::TenantId;
use xavyo_db::DbPool;

static INIT: Once = Once::new();

/// Initialize logging for tests (once).
pub fn init_test_logging() {
    INIT.call_once(|| {
        // Only initialize if RUST_LOG is set
        if std::env::var("RUST_LOG").is_ok() {
            tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init()
                .ok();
        }
    });
}

/// Get the database URL for the app user (non-superuser, RLS enforced).
pub fn get_app_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Get the database URL for the superuser (RLS bypassed, for setup operations).
pub fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context that provides database pools for testing.
///
/// - `pool`: Connected as `xavyo_app` (non-superuser), RLS policies are enforced.
///           Use this for all test queries that should respect tenant isolation.
/// - `admin_pool`: Connected as `xavyo` (superuser), bypasses RLS.
///                 Use this for setup/teardown operations (creating tenants, users).
pub struct TestContext {
    /// App user pool - RLS is enforced
    pub pool: DbPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    admin_pool: DbPool,
}

impl TestContext {
    /// Create a new test context with both app and admin database connections.
    ///
    /// The database should already be initialized via docker/postgres/init.sql.
    pub async fn new() -> Self {
        init_test_logging();

        let pool = DbPool::connect(&get_app_database_url()).await.expect(
            "Failed to connect as app user. Is PostgreSQL running? Try: ./scripts/dev-env.sh start",
        );

        let admin_pool = DbPool::connect(&get_superuser_database_url())
            .await
            .expect("Failed to connect as superuser");

        Self { pool, admin_pool }
    }

    /// Create a test tenant and return its ID.
    ///
    /// Uses the admin pool to bypass RLS.
    pub async fn create_tenant(&self, name: &str, slug: &str) -> TenantId {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(id.as_uuid())
            .bind(name)
            .bind(slug)
            .execute(self.admin_pool.inner())
            .await
            .expect("Failed to create test tenant");
        id
    }

    /// Create a test user for a tenant and return the user's ID.
    ///
    /// Uses the admin pool to bypass RLS.
    pub async fn create_user(
        &self,
        tenant_id: TenantId,
        email: &str,
        password_hash: &str,
    ) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash) VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(tenant_id.as_uuid())
        .bind(email)
        .bind(password_hash)
        .execute(self.admin_pool.inner())
        .await
        .expect("Failed to create test user");
        id
    }

    /// Get the well-known test tenant ID (from seed data).
    ///
    /// This matches the tenant created by docker/postgres/seed.sql.
    #[allow(dead_code)]
    pub fn seed_tenant_id() -> TenantId {
        TenantId::from_uuid(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("Invalid seed tenant UUID"),
        )
    }

    /// Get the well-known admin user email (from seed data).
    pub fn seed_admin_email() -> &'static str {
        "admin@test.xavyo.com"
    }

    /// Get the well-known regular user email (from seed data).
    #[allow(dead_code)]
    pub fn seed_user_email() -> &'static str {
        "user@test.xavyo.com"
    }

    /// Clean up test data created during tests.
    ///
    /// Uses admin pool to bypass RLS.
    /// Note: This does NOT remove seed data to avoid breaking other tests.
    /// Note: Currently unused as tests use unique IDs for parallel safety.
    #[allow(dead_code)]
    pub async fn cleanup(&self) {
        // Only clean up dynamically created test data, not seed data
        // Delete users that are not the seed users
        sqlx::query(
            "DELETE FROM users WHERE email NOT IN ('admin@test.xavyo.com', 'user@test.xavyo.com', 'inactive@test.xavyo.com')"
        )
        .execute(self.admin_pool.inner())
        .await
        .ok();

        // Delete tenants that are not the seed tenant
        sqlx::query("DELETE FROM tenants WHERE id != '00000000-0000-0000-0000-000000000001'::uuid")
            .execute(self.admin_pool.inner())
            .await
            .ok();
    }

    /// Full cleanup - removes ALL data including seed data.
    ///
    /// Use sparingly, only when you need a completely fresh database.
    #[allow(dead_code)]
    pub async fn full_cleanup(&self) {
        sqlx::query("DELETE FROM users")
            .execute(self.admin_pool.inner())
            .await
            .ok();
        sqlx::query("DELETE FROM tenants")
            .execute(self.admin_pool.inner())
            .await
            .ok();
    }
}
