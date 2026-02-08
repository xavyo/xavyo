//! Application Bootstrap Module
//!
//! This module orchestrates the system tenant bootstrap during application startup.
//! It ensures the system tenant, CLI OAuth client, and optionally a bootstrap admin
//! user are created before the application starts accepting requests.

use sqlx::PgPool;
use std::env;
use tracing::{error, info, instrument, warn};

use xavyo_auth::hash_password;
use xavyo_db::bootstrap::{run_bootstrap, BootstrapError, BootstrapResult, SYSTEM_TENANT_ID};

/// Runs the application bootstrap process.
///
/// This function should be called during application startup, after the database
/// connection is established but before the HTTP server starts accepting requests.
///
/// # Process
///
/// 1. Calls `run_bootstrap()` to ensure the system tenant exists
/// 2. Optionally creates a bootstrap admin user if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set
/// 3. Logs the result of the bootstrap operation
/// 4. Returns an error if bootstrap fails (application should not start)
///
/// # Environment Variables
///
/// - `ADMIN_EMAIL` — Email for the bootstrap admin user (optional)
/// - `ADMIN_PASSWORD` — Password for the bootstrap admin user (optional)
///
/// Both must be set to create the admin user. The admin is created with
/// `super_admin` role, email pre-verified, under the system tenant.
///
/// # Errors
///
/// Returns `BootstrapError` if the bootstrap process fails. The calling code
/// should treat this as a fatal error and prevent the application from starting.
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

            // Bootstrap admin user if ADMIN_EMAIL and ADMIN_PASSWORD are set
            bootstrap_admin_user(pool).await;

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

/// Creates a bootstrap admin user if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set.
///
/// The admin user is created under the system tenant with:
/// - `email_verified = true` (immediate login)
/// - `is_active = true`
/// - `super_admin` role
///
/// This operation is idempotent — if the user already exists, it is skipped.
async fn bootstrap_admin_user(pool: &PgPool) {
    let admin_email = match env::var("ADMIN_EMAIL") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    let admin_password = match env::var("ADMIN_PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            warn!("ADMIN_EMAIL is set but ADMIN_PASSWORD is not — skipping admin bootstrap");
            return;
        }
    };

    info!(email = %admin_email, "Bootstrapping admin user");

    // Hash password
    let password_hash = match hash_password(&admin_password) {
        Ok(h) => h,
        Err(e) => {
            error!(error = %e, "Failed to hash admin password — skipping admin bootstrap");
            return;
        }
    };

    // Insert user (idempotent via ON CONFLICT)
    let result = sqlx::query(
        r"
        INSERT INTO users (
            id, tenant_id, email, password_hash, display_name,
            is_active, email_verified, email_verified_at, created_at, updated_at
        )
        VALUES (
            gen_random_uuid(), $1, $2, $3, 'Admin',
            true, true, NOW(), NOW(), NOW()
        )
        ON CONFLICT (tenant_id, email) DO NOTHING
        ",
    )
    .bind(SYSTEM_TENANT_ID)
    .bind(&admin_email)
    .bind(&password_hash)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(email = %admin_email, "bootstrap.admin.created: Admin user created");

            // Fetch the user ID for role assignment
            let user_id: Result<(uuid::Uuid,), _> =
                sqlx::query_as("SELECT id FROM users WHERE tenant_id = $1 AND email = $2")
                    .bind(SYSTEM_TENANT_ID)
                    .bind(&admin_email)
                    .fetch_one(pool)
                    .await;

            if let Ok((uid,)) = user_id {
                // Assign super_admin role
                let _ = sqlx::query(
                    r"
                    INSERT INTO user_roles (user_id, role_name, created_at)
                    VALUES ($1, 'super_admin', NOW())
                    ON CONFLICT (user_id, role_name) DO NOTHING
                    ",
                )
                .bind(uid)
                .execute(pool)
                .await;

                info!(email = %admin_email, role = "super_admin", "bootstrap.admin.role: Admin role assigned");
            }
        }
        Ok(_) => {
            info!(email = %admin_email, "bootstrap.admin.exists: Admin user already exists");
        }
        Err(e) => {
            error!(error = %e, email = %admin_email, "Failed to create admin user");
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
