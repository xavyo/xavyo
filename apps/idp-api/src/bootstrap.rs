//! Application Bootstrap Module
//!
//! This module orchestrates the system tenant bootstrap during application startup.
//! It ensures the system tenant and CLI OAuth client are created before the
//! application starts accepting requests.

use sqlx::PgPool;
use tracing::{error, info, instrument, warn};

use xavyo_db::bootstrap::{run_bootstrap, BootstrapError, BootstrapResult};

/// Runs the application bootstrap process.
///
/// This function should be called during application startup, after the database
/// connection is established but before the HTTP server starts accepting requests.
///
/// # Process
///
/// 1. Calls `run_bootstrap()` to ensure the system tenant exists
/// 2. Logs the result of the bootstrap operation
/// 3. Returns an error if bootstrap fails (application should not start)
///
/// # Errors
///
/// Returns `BootstrapError` if the bootstrap process fails. The calling code
/// should treat this as a fatal error and prevent the application from starting.
///
/// # Example
///
/// ```rust,ignore
/// use idp_api::bootstrap::bootstrap_system;
///
/// // During application startup
/// let pool = create_database_pool().await?;
/// bootstrap_system(&pool).await?; // App should not start if this fails
/// start_http_server().await?;
/// ```
#[instrument(skip(pool), name = "app_bootstrap")]
pub async fn bootstrap_system(pool: &PgPool) -> Result<BootstrapResult, BootstrapError> {
    info!("bootstrap.started: Running application bootstrap");

    match run_bootstrap(pool).await {
        Ok(result) => {
            info!(
                tenant_created = result.tenant_created,
                oauth_client_created = result.oauth_client_created,
                tenant_id = %result.tenant_id,
                "bootstrap.completed: Application bootstrap completed successfully"
            );

            if result.tenant_created {
                info!("System tenant was created - this is a fresh installation");
            } else {
                info!("System tenant already existed - this is a restart or upgrade");
            }

            if result.oauth_client_created {
                info!("CLI OAuth client was created");
            }

            Ok(result)
        }
        Err(e) => {
            error!(
                error = %e,
                "bootstrap.failed: Application bootstrap failed - application cannot start"
            );
            Err(e)
        }
    }
}

/// Runs bootstrap and returns a boolean indicating success.
///
/// This is a convenience function that logs errors internally and returns
/// `false` on failure, suitable for use in startup sequences where the
/// caller wants to handle the failure differently.
#[allow(dead_code)] // Reserved for startup integration
#[instrument(skip(pool))]
pub async fn try_bootstrap_system(pool: &PgPool) -> bool {
    match bootstrap_system(pool).await {
        Ok(_) => true,
        Err(e) => {
            warn!(
                error = %e,
                "Bootstrap failed, but continuing (try_bootstrap mode)"
            );
            false
        }
    }
}
