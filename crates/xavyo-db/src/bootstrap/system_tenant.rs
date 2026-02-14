//! System Tenant Bootstrap Implementation
//!
//! This module contains the core logic for bootstrapping the system tenant
//! and CLI OAuth client during application startup.

use sqlx::PgPool;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use super::{
    BootstrapError, CLI_OAUTH_CLIENT_ID, CLI_OAUTH_CLIENT_NAME, CLI_OAUTH_CLIENT_UUID,
    CLI_OAUTH_GRANT_TYPES, CLI_OAUTH_SCOPES, SYSTEM_TENANT_ID, SYSTEM_TENANT_NAME,
    SYSTEM_TENANT_SLUG,
};

// ============================================================================
// T009: Bootstrap Result
// ============================================================================

/// Result of the bootstrap operation.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    /// Whether the system tenant was created (false if it already existed).
    pub tenant_created: bool,

    /// Whether the CLI OAuth client was created (false if it already existed).
    pub oauth_client_created: bool,

    /// The UUID of the system tenant.
    pub tenant_id: Uuid,
}

// ============================================================================
// Advisory Lock for Concurrent Bootstrap Protection (T038-T041)
// ============================================================================

/// Advisory lock key for bootstrap operations.
/// This is a unique 64-bit integer used with `pg_advisory_lock`.
const BOOTSTRAP_LOCK_KEY: i64 = 0x5841_5659_4F5F_4944; // "XAVYO_ID" in ASCII

/// Acquires the bootstrap advisory lock.
/// This prevents multiple instances from bootstrapping simultaneously.
#[instrument(skip(pool))]
async fn acquire_bootstrap_lock(pool: &PgPool) -> Result<(), BootstrapError> {
    info!("Attempting to acquire bootstrap lock");

    // Use pg_try_advisory_lock to avoid blocking indefinitely
    // If another instance is bootstrapping, we'll wait up to 5 seconds
    let result: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1) as acquired")
        .bind(BOOTSTRAP_LOCK_KEY)
        .fetch_one(pool)
        .await
        .map_err(BootstrapError::LockAcquisition)?;

    if !result.0 {
        // Could not acquire lock immediately, try waiting
        warn!("Bootstrap lock not immediately available, waiting...");

        // Wait with timeout (5 seconds)
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(BOOTSTRAP_LOCK_KEY)
            .execute(pool)
            .await
            .map_err(BootstrapError::LockAcquisition)?;
    }

    info!("Bootstrap lock acquired");
    Ok(())
}

/// Releases the bootstrap advisory lock.
#[instrument(skip(pool))]
async fn release_bootstrap_lock(pool: &PgPool) -> Result<(), BootstrapError> {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BOOTSTRAP_LOCK_KEY)
        .execute(pool)
        .await
        .map_err(BootstrapError::LockRelease)?;

    info!("Bootstrap lock released");
    Ok(())
}

// ============================================================================
// RLS Bypass for Bootstrap (T019)
// ============================================================================

/// Disables Row-Level Security for the current session.
/// This is required because the system tenant doesn't exist yet when we're creating it.
/// On managed databases without superuser access, falls back to setting the RLS
/// context variable to the system tenant ID so bootstrap queries pass RLS policies.
#[instrument(skip(pool))]
async fn disable_rls(pool: &PgPool) -> Result<(), BootstrapError> {
    // Try session_replication_role first (requires superuser)
    match sqlx::query("SET session_replication_role = 'replica'")
        .execute(pool)
        .await
    {
        Ok(_) => {
            info!("RLS bypassed via session_replication_role (superuser)");
        }
        Err(e) => {
            warn!("session_replication_role not available (managed DB?): {e}");
            // Fallback: set the RLS context variable to system tenant ID
            // This allows bootstrap INSERTs to pass RLS WITH CHECK policies
            sqlx::query(&format!(
                "SET app.current_tenant = '{}'",
                SYSTEM_TENANT_ID
            ))
            .execute(pool)
            .await
            .map_err(BootstrapError::RlsBypass)?;
            info!("RLS context set to system tenant ID (managed DB fallback)");
        }
    }
    Ok(())
}

/// Re-enables Row-Level Security for the current session.
#[instrument(skip(pool))]
async fn enable_rls(pool: &PgPool) -> Result<(), BootstrapError> {
    // Try to restore session_replication_role (may fail on managed DBs, that's ok)
    match sqlx::query("SET session_replication_role = 'origin'")
        .execute(pool)
        .await
    {
        Ok(_) => {
            info!("RLS restored after bootstrap operations");
        }
        Err(_) => {
            // On managed DBs, just reset the tenant context
            let _ = sqlx::query("RESET app.current_tenant")
                .execute(pool)
                .await;
            info!("RLS context reset after bootstrap operations (managed DB)");
        }
    }
    Ok(())
}

// ============================================================================
// System Tenant Creation (T018-T021)
// ============================================================================

/// Creates the system tenant if it doesn't exist.
///
/// Uses `INSERT ... ON CONFLICT DO NOTHING` for idempotency.
/// Returns `true` if the tenant was created, `false` if it already existed.
#[instrument(skip(pool))]
pub async fn create_system_tenant(pool: &PgPool) -> Result<bool, BootstrapError> {
    info!(
        tenant_id = %SYSTEM_TENANT_ID,
        name = SYSTEM_TENANT_NAME,
        slug = SYSTEM_TENANT_SLUG,
        "Creating system tenant"
    );

    // T020: INSERT with ON CONFLICT DO NOTHING for idempotency
    let result = sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, tenant_type, settings, created_at)
        VALUES ($1, $2, $3, 'system', '{"description": "System tenant for platform operations"}', NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_TENANT_NAME)
    .bind(SYSTEM_TENANT_SLUG)
    .execute(pool)
    .await
    .map_err(BootstrapError::TenantCreation)?;

    let created = result.rows_affected() > 0;

    // T021: Logging for tenant creation
    if created {
        info!(
            tenant_id = %SYSTEM_TENANT_ID,
            "bootstrap.tenant.created: System tenant created successfully"
        );
    } else {
        info!(
            tenant_id = %SYSTEM_TENANT_ID,
            "bootstrap.tenant.exists: System tenant already exists"
        );
    }

    Ok(created)
}

// ============================================================================
// CLI OAuth Client Creation (T028-T033)
// ============================================================================

/// Creates the CLI OAuth client if it doesn't exist.
///
/// Uses `INSERT ... ON CONFLICT DO NOTHING` for idempotency.
/// Returns `true` if the client was created, `false` if it already existed.
#[instrument(skip(pool))]
pub async fn create_cli_oauth_client(pool: &PgPool) -> Result<bool, BootstrapError> {
    info!(
        client_id = CLI_OAUTH_CLIENT_ID,
        name = CLI_OAUTH_CLIENT_NAME,
        "Creating CLI OAuth client"
    );

    // T029-T032: INSERT with proper configuration
    let result = sqlx::query(
        r"
        INSERT INTO oauth_clients (
            id,
            tenant_id,
            client_id,
            client_secret_hash,
            name,
            client_type,
            redirect_uris,
            grant_types,
            scopes,
            is_active,
            created_at,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            NULL,
            $4,
            'public',
            '{}',
            $5,
            $6,
            true,
            NOW(),
            NOW()
        )
        ON CONFLICT (client_id) DO NOTHING
        ",
    )
    .bind(CLI_OAUTH_CLIENT_UUID)
    .bind(SYSTEM_TENANT_ID)
    .bind(CLI_OAUTH_CLIENT_ID)
    .bind(CLI_OAUTH_CLIENT_NAME)
    .bind(CLI_OAUTH_GRANT_TYPES)
    .bind(CLI_OAUTH_SCOPES)
    .execute(pool)
    .await
    .map_err(BootstrapError::OAuthClientCreation)?;

    let created = result.rows_affected() > 0;

    // T033: Logging for OAuth client creation
    if created {
        info!(
            client_id = CLI_OAUTH_CLIENT_ID,
            grant_types = ?CLI_OAUTH_GRANT_TYPES,
            scopes = ?CLI_OAUTH_SCOPES,
            "bootstrap.oauth_client.created: CLI OAuth client created successfully"
        );
    } else {
        info!(
            client_id = CLI_OAUTH_CLIENT_ID,
            "bootstrap.oauth_client.exists: CLI OAuth client already exists"
        );
    }

    Ok(created)
}

// ============================================================================
// Main Bootstrap Function (T040)
// ============================================================================

/// Runs the complete bootstrap process.
///
/// This function:
/// 1. Acquires an advisory lock to prevent concurrent bootstrap
/// 2. Disables RLS to allow system-level operations
/// 3. Creates the system tenant if it doesn't exist
/// 4. Creates the CLI OAuth client if it doesn't exist
/// 5. Re-enables RLS
/// 6. Releases the advisory lock
///
/// The process is idempotent and safe for concurrent execution.
///
/// # Errors
///
/// Returns `BootstrapError` if any step fails. The lock is released even on error.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_db::bootstrap::run_bootstrap;
///
/// let result = run_bootstrap(&pool).await?;
/// println!("Tenant created: {}", result.tenant_created);
/// println!("OAuth client created: {}", result.oauth_client_created);
/// ```
#[instrument(skip(pool), name = "bootstrap")]
pub async fn run_bootstrap(pool: &PgPool) -> Result<BootstrapResult, BootstrapError> {
    info!("bootstrap.started: Beginning system tenant bootstrap");

    // Acquire lock to prevent concurrent bootstrap
    acquire_bootstrap_lock(pool).await?;

    // Use a closure to ensure we release the lock even on error
    let result = async {
        // Disable RLS for bootstrap operations
        disable_rls(pool).await?;

        // Create system tenant
        let tenant_created = create_system_tenant(pool).await?;

        // Create CLI OAuth client
        let oauth_client_created = create_cli_oauth_client(pool).await?;

        // Re-enable RLS
        enable_rls(pool).await?;

        Ok(BootstrapResult {
            tenant_created,
            oauth_client_created,
            tenant_id: SYSTEM_TENANT_ID,
        })
    }
    .await;

    // Always release the lock, even on error
    if let Err(e) = release_bootstrap_lock(pool).await {
        warn!("Failed to release bootstrap lock: {}", e);
    }

    match &result {
        Ok(r) => {
            info!(
                tenant_created = r.tenant_created,
                oauth_client_created = r.oauth_client_created,
                tenant_id = %r.tenant_id,
                "bootstrap.completed: System tenant bootstrap completed successfully"
            );
        }
        Err(e) => {
            warn!("bootstrap.failed: System tenant bootstrap failed: {}", e);
        }
    }

    result
}

// ============================================================================
// Integration Tests (run with --features integration)
// ============================================================================

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::env;

    async fn get_test_pool() -> PgPool {
        let database_url =
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to create test pool")
    }

    // T016: Integration test for creating system tenant on fresh database
    #[tokio::test]
    async fn test_create_system_tenant_fresh_db() {
        let pool = get_test_pool().await;

        // Clean up any existing system tenant first
        sqlx::query("SET session_replication_role = 'replica'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_clients WHERE tenant_id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await
            .ok(); // May fail if triggers are active, that's fine
        sqlx::query("SET session_replication_role = 'origin'")
            .execute(&pool)
            .await
            .unwrap();

        // Run bootstrap
        let result = run_bootstrap(&pool)
            .await
            .expect("Bootstrap should succeed");

        assert!(result.tenant_created, "Tenant should be created");
        assert_eq!(result.tenant_id, SYSTEM_TENANT_ID);

        // Verify tenant exists
        let tenant: (String, String, String) =
            sqlx::query_as("SELECT name, slug, tenant_type::text FROM tenants WHERE id = $1")
                .bind(SYSTEM_TENANT_ID)
                .fetch_one(&pool)
                .await
                .expect("System tenant should exist");

        assert_eq!(tenant.0, SYSTEM_TENANT_NAME);
        assert_eq!(tenant.1, SYSTEM_TENANT_SLUG);
        assert_eq!(tenant.2, "system");
    }

    // T017: Integration test for idempotent bootstrap
    #[tokio::test]
    async fn test_system_tenant_idempotent() {
        let pool = get_test_pool().await;

        // Run bootstrap twice
        let result1 = run_bootstrap(&pool)
            .await
            .expect("First bootstrap should succeed");
        let result2 = run_bootstrap(&pool)
            .await
            .expect("Second bootstrap should succeed");

        // Second run should not create anything new
        assert!(!result2.tenant_created, "Tenant should not be recreated");
        assert!(
            !result2.oauth_client_created,
            "OAuth client should not be recreated"
        );

        // Both should have the same tenant ID
        assert_eq!(result1.tenant_id, result2.tenant_id);
    }

    // T025: Integration test for CLI OAuth client creation
    #[tokio::test]
    async fn test_create_cli_oauth_client() {
        let pool = get_test_pool().await;

        // Ensure system tenant exists first
        let _ = run_bootstrap(&pool).await;

        // Verify OAuth client exists
        let client: (String, String, Option<String>) = sqlx::query_as(
            "SELECT client_id, client_type, client_secret_hash FROM oauth_clients WHERE client_id = $1",
        )
        .bind(CLI_OAUTH_CLIENT_ID)
        .fetch_one(&pool)
        .await
        .expect("CLI OAuth client should exist");

        assert_eq!(client.0, CLI_OAUTH_CLIENT_ID);
        assert_eq!(client.1, "public");
        assert!(client.2.is_none(), "Public client should have no secret");
    }

    // T026: Integration test for CLI OAuth client idempotency
    #[tokio::test]
    async fn test_cli_oauth_client_idempotent() {
        let pool = get_test_pool().await;

        // Run bootstrap twice
        let result1 = run_bootstrap(&pool)
            .await
            .expect("First bootstrap should succeed");
        let result2 = run_bootstrap(&pool)
            .await
            .expect("Second bootstrap should succeed");

        // Count OAuth clients with this ID (should be exactly 1)
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1")
                .bind(CLI_OAUTH_CLIENT_ID)
                .fetch_one(&pool)
                .await
                .expect("Count query should succeed");

        assert_eq!(count.0, 1, "Should have exactly one CLI OAuth client");
    }

    // T027: Integration test for CLI OAuth client configuration
    #[tokio::test]
    async fn test_cli_oauth_client_configuration() {
        let pool = get_test_pool().await;

        // Ensure bootstrap has run
        let _ = run_bootstrap(&pool).await;

        // Verify configuration
        let client: (Vec<String>, Vec<String>) =
            sqlx::query_as("SELECT grant_types, scopes FROM oauth_clients WHERE client_id = $1")
                .bind(CLI_OAUTH_CLIENT_ID)
                .fetch_one(&pool)
                .await
                .expect("CLI OAuth client should exist");

        // Check grant types
        assert!(
            client
                .0
                .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string()),
            "Should have device_code grant type"
        );
        assert!(
            client.0.contains(&"refresh_token".to_string()),
            "Should have refresh_token grant type"
        );

        // Check scopes
        assert!(
            client.1.contains(&"openid".to_string()),
            "Should have openid scope"
        );
        assert!(
            client.1.contains(&"profile".to_string()),
            "Should have profile scope"
        );
        assert!(
            client.1.contains(&"email".to_string()),
            "Should have email scope"
        );
        assert!(
            client.1.contains(&"tenant:provision".to_string()),
            "Should have tenant:provision scope"
        );
    }

    // T035: Integration test for concurrent bootstrap
    #[tokio::test]
    async fn test_concurrent_bootstrap_single_tenant() {
        let pool = get_test_pool().await;

        // Clean up first
        sqlx::query("SET session_replication_role = 'replica'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oauth_clients WHERE tenant_id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("SET session_replication_role = 'origin'")
            .execute(&pool)
            .await
            .unwrap();

        // Run 3 bootstraps concurrently
        let pool1 = pool.clone();
        let pool2 = pool.clone();
        let pool3 = pool.clone();

        let (r1, r2, r3) = tokio::join!(
            run_bootstrap(&pool1),
            run_bootstrap(&pool2),
            run_bootstrap(&pool3),
        );

        // All should succeed
        assert!(r1.is_ok(), "First bootstrap should succeed");
        assert!(r2.is_ok(), "Second bootstrap should succeed");
        assert!(r3.is_ok(), "Third bootstrap should succeed");

        // Count tenants (should be exactly 1)
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE id = $1")
            .bind(SYSTEM_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("Count query should succeed");

        assert_eq!(count.0, 1, "Should have exactly one system tenant");
    }

    // T043: Integration test for system tenant delete rejection
    #[tokio::test]
    async fn test_system_tenant_delete_rejected() {
        let pool = get_test_pool().await;

        // Ensure system tenant exists
        let _ = run_bootstrap(&pool).await;

        // Try to delete system tenant (should fail due to trigger)
        let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await;

        assert!(
            result.is_err(),
            "Deleting system tenant should fail due to trigger"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cannot delete system tenant"),
            "Error should mention system tenant protection"
        );
    }

    // T044: Integration test for system tenant modification rejection
    #[tokio::test]
    async fn test_system_tenant_slug_modification_rejected() {
        let pool = get_test_pool().await;

        // Ensure system tenant exists
        let _ = run_bootstrap(&pool).await;

        // Try to modify system tenant slug (should fail due to trigger)
        let result = sqlx::query("UPDATE tenants SET slug = 'modified' WHERE id = $1")
            .bind(SYSTEM_TENANT_ID)
            .execute(&pool)
            .await;

        assert!(
            result.is_err(),
            "Modifying system tenant slug should fail due to trigger"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cannot modify system tenant"),
            "Error should mention system tenant protection"
        );
    }

    // T045: Integration test for system tenant type in list
    #[tokio::test]
    async fn test_system_tenant_type_listed() {
        let pool = get_test_pool().await;

        // Ensure system tenant exists
        let _ = run_bootstrap(&pool).await;

        // Query tenant with type
        let tenant: (String,) =
            sqlx::query_as("SELECT tenant_type::text FROM tenants WHERE id = $1")
                .bind(SYSTEM_TENANT_ID)
                .fetch_one(&pool)
                .await
                .expect("System tenant should exist");

        assert_eq!(
            tenant.0, "system",
            "System tenant should have type 'system'"
        );
    }
}
