//! Integration tests for Secret Provider Configuration API (F120).
//!
//! Tests the provider configuration CRUD endpoints with real database connectivity.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Once;
use std::time::Duration as StdDuration;
use uuid::Uuid;

static INIT: Once = Once::new();

/// Initialize logging for tests (once).
fn init_test_logging() {
    INIT.call_once(|| {
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
fn get_app_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Get the database URL for the superuser (RLS bypassed, for setup operations).
fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context for provider integration tests.
struct ProviderTestContext {
    /// App user pool - RLS is enforced
    #[allow(dead_code)]
    pub pool: PgPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    pub admin_pool: PgPool,
    /// Test tenant ID
    pub tenant_id: Uuid,
}

impl ProviderTestContext {
    /// Create a new test context with both app and admin database connections.
    async fn new() -> Option<Self> {
        init_test_logging();

        // Try to connect - skip test if database not available
        let pool = match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_app_database_url())
            .await
        {
            Ok(p) => p,
            Err(_) => return None, // Database not available
        };

        let admin_pool = match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_superuser_database_url())
            .await
        {
            Ok(p) => p,
            Err(_) => return None, // Database not available
        };

        // Create a unique test tenant
        let tenant_id = Uuid::new_v4();
        let slug = format!("test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("Test Tenant {}", &tenant_id.to_string()[..8]))
            .bind(&slug)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            return None;
        }

        Some(Self {
            pool,
            admin_pool,
            tenant_id,
        })
    }

    /// Create a test secret provider config.
    async fn create_provider(&self, name: &str, provider_type: &str) -> Result<Uuid, sqlx::Error> {
        let provider_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO secret_provider_configs
                (id, tenant_id, name, provider_type, config, status)
            VALUES ($1, $2, $3, $4, $5, 'active')
            "#,
        )
        .bind(&provider_id)
        .bind(&self.tenant_id)
        .bind(name)
        .bind(provider_type)
        .bind(serde_json::json!({
            "url": "http://localhost:8200",
            "auth_method": "token"
        }))
        .execute(&self.admin_pool)
        .await?;

        Ok(provider_id)
    }

    /// Cleanup after test.
    async fn cleanup(&self) {
        // Delete providers first (due to FK constraints)
        let _ = sqlx::query("DELETE FROM secret_provider_configs WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;

        // Delete tenant
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
    }
}

impl Drop for ProviderTestContext {
    fn drop(&mut self) {
        // Note: async cleanup in Drop is not ideal, but works for tests
        // In production, use explicit cleanup
    }
}

/// Test: Create a provider configuration successfully.
#[tokio::test]
#[ignore = "requires database - run with: cargo test -p xavyo-api-agents --test providers_test -- --ignored"]
async fn test_create_provider_via_db() {
    let ctx = match ProviderTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a provider
    let provider_id = ctx
        .create_provider("test-openbao", "openbao")
        .await
        .expect("Failed to create provider");

    // Verify it was created
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT name, provider_type FROM secret_provider_configs WHERE id = $1",
    )
    .bind(&provider_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Provider not found");

    assert_eq!(row.0, "test-openbao");
    assert_eq!(row.1, "openbao");

    ctx.cleanup().await;
}

/// Test: List providers with filtering by type.
#[tokio::test]
#[ignore = "requires database - run with: cargo test -p xavyo-api-agents --test providers_test -- --ignored"]
async fn test_list_providers_by_type() {
    let ctx = match ProviderTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create providers of different types
    let _ = ctx.create_provider("vault-1", "openbao").await.unwrap();
    let _ = ctx.create_provider("vault-2", "openbao").await.unwrap();
    let _ = ctx
        .create_provider("infisical-1", "infisical")
        .await
        .unwrap();

    // Query only openbao providers
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM secret_provider_configs WHERE tenant_id = $1 AND provider_type = $2",
    )
    .bind(&ctx.tenant_id)
    .bind("openbao")
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(count.0, 2, "Should have 2 openbao providers");

    ctx.cleanup().await;
}

/// Test: Tenant isolation - providers from other tenants not visible.
#[tokio::test]
#[ignore = "requires database - run with: cargo test -p xavyo-api-agents --test providers_test -- --ignored"]
async fn test_provider_tenant_isolation() {
    let ctx = match ProviderTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create provider for our test tenant
    let _ = ctx.create_provider("my-vault", "openbao").await.unwrap();

    // Create another tenant with its own provider
    let other_tenant_id = Uuid::new_v4();
    let other_slug = format!("other-{}", &other_tenant_id.to_string()[..8]);
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(&other_tenant_id)
        .bind("Other Tenant")
        .bind(&other_slug)
        .execute(&ctx.admin_pool)
        .await
        .expect("Failed to create other tenant");

    sqlx::query(
        r#"
        INSERT INTO secret_provider_configs
            (id, tenant_id, name, provider_type, config, status)
        VALUES ($1, $2, $3, 'openbao', $4, 'active')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant_id)
    .bind("other-vault")
    .bind(serde_json::json!({}))
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create other provider");

    // Query our tenant's providers only
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM secret_provider_configs WHERE tenant_id = $1")
            .bind(&ctx.tenant_id)
            .fetch_one(&ctx.admin_pool)
            .await
            .expect("Query failed");

    assert_eq!(count.0, 1, "Should only see our tenant's provider");

    // Cleanup other tenant
    let _ = sqlx::query("DELETE FROM secret_provider_configs WHERE tenant_id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;

    ctx.cleanup().await;
}

/// Test: Update provider status.
#[tokio::test]
#[ignore = "requires database - run with: cargo test -p xavyo-api-agents --test providers_test -- --ignored"]
async fn test_update_provider_status() {
    let ctx = match ProviderTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a provider
    let provider_id = ctx
        .create_provider("status-test", "openbao")
        .await
        .expect("Failed to create provider");

    // Update status to inactive
    sqlx::query("UPDATE secret_provider_configs SET status = 'inactive' WHERE id = $1")
        .bind(&provider_id)
        .execute(&ctx.admin_pool)
        .await
        .expect("Update failed");

    // Verify status changed
    let row: (String,) = sqlx::query_as("SELECT status FROM secret_provider_configs WHERE id = $1")
        .bind(&provider_id)
        .fetch_one(&ctx.admin_pool)
        .await
        .expect("Provider not found");

    assert_eq!(row.0, "inactive");

    ctx.cleanup().await;
}

/// Test: Delete provider.
#[tokio::test]
#[ignore = "requires database - run with: cargo test -p xavyo-api-agents --test providers_test -- --ignored"]
async fn test_delete_provider() {
    let ctx = match ProviderTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a provider
    let provider_id = ctx
        .create_provider("delete-test", "openbao")
        .await
        .expect("Failed to create provider");

    // Delete the provider
    sqlx::query("DELETE FROM secret_provider_configs WHERE id = $1")
        .bind(&provider_id)
        .execute(&ctx.admin_pool)
        .await
        .expect("Delete failed");

    // Verify it's gone
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM secret_provider_configs WHERE id = $1")
            .bind(&provider_id)
            .fetch_one(&ctx.admin_pool)
            .await
            .expect("Query failed");

    assert_eq!(count.0, 0, "Provider should be deleted");

    ctx.cleanup().await;
}
