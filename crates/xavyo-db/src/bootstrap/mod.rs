//! System Tenant Bootstrap Module
//!
//! This module provides functionality to automatically bootstrap the system tenant
//! and CLI OAuth client when the IDP application starts for the first time.
//!
//! # Overview
//!
//! The system tenant (`00000000-0000-0000-0000-000000000001`) serves as the
//! authentication context for CLI users before they have their own tenant.
//! It contains the pre-registered OAuth client `xavyo-cli` for device code flow.
//!
//! # Usage
//!
//! ```rust,ignore
//! use xavyo_db::bootstrap::{run_bootstrap, BootstrapResult};
//!
//! let result = run_bootstrap(&pool).await?;
//! if result.tenant_created {
//!     info!("System tenant created");
//! }
//! ```

mod system_tenant;

pub use system_tenant::{
    create_cli_oauth_client, create_system_tenant, run_bootstrap, BootstrapResult,
};

use thiserror::Error;
use uuid::Uuid;

// ============================================================================
// T007: Constants for System Tenant
// ============================================================================

/// Well-known UUID for the system tenant.
/// This UUID is intentionally simple and predictable for easy identification.
pub const SYSTEM_TENANT_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

/// Name of the system tenant.
pub const SYSTEM_TENANT_NAME: &str = "xavyo-system";

/// Slug for the system tenant (used in URLs and lookups).
pub const SYSTEM_TENANT_SLUG: &str = "system";

// ============================================================================
// Constants for CLI OAuth Client
// ============================================================================

/// Well-known UUID for the CLI OAuth client.
pub const CLI_OAUTH_CLIENT_UUID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000002);

/// Client ID for the CLI OAuth client (used in OAuth flows).
pub const CLI_OAUTH_CLIENT_ID: &str = "xavyo-cli";

/// Human-readable name for the CLI OAuth client.
pub const CLI_OAUTH_CLIENT_NAME: &str = "Xavyo CLI";

/// Grant types enabled for the CLI OAuth client.
/// - `device_code`: For CLI authentication flow
/// - `refresh_token`: To refresh access tokens
pub const CLI_OAUTH_GRANT_TYPES: &[&str] = &[
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
];

/// Scopes available to the CLI OAuth client.
/// - openid: OIDC standard scope
/// - profile: User profile information
/// - email: User email address
/// - tenant:provision: Ability to create new tenants
pub const CLI_OAUTH_SCOPES: &[&str] = &["openid", "profile", "email", "tenant:provision"];

// ============================================================================
// T008: Bootstrap Error Types
// ============================================================================

/// Errors that can occur during the bootstrap process.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Failed to acquire the advisory lock for bootstrap.
    /// This typically means another instance is currently bootstrapping.
    #[error("Failed to acquire bootstrap lock: {0}")]
    LockAcquisition(#[source] sqlx::Error),

    /// Failed to release the advisory lock after bootstrap.
    #[error("Failed to release bootstrap lock: {0}")]
    LockRelease(#[source] sqlx::Error),

    /// Failed to create the system tenant in the database.
    #[error("Failed to create system tenant: {0}")]
    TenantCreation(#[source] sqlx::Error),

    /// Failed to create the CLI OAuth client in the database.
    #[error("Failed to create CLI OAuth client: {0}")]
    OAuthClientCreation(#[source] sqlx::Error),

    /// Failed to disable RLS for bootstrap operations.
    #[error("Failed to disable RLS for bootstrap: {0}")]
    RlsBypass(#[source] sqlx::Error),

    /// Failed to re-enable RLS after bootstrap operations.
    #[error("Failed to re-enable RLS after bootstrap: {0}")]
    RlsRestore(#[source] sqlx::Error),

    /// General database error during bootstrap.
    #[error("Database error during bootstrap: {0}")]
    Database(#[from] sqlx::Error),
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // T014: Unit test for system tenant constants
    #[test]
    fn test_system_tenant_constants() {
        // Verify SYSTEM_TENANT_ID is the expected well-known UUID
        assert_eq!(
            SYSTEM_TENANT_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );

        // Verify system tenant name and slug
        assert_eq!(SYSTEM_TENANT_NAME, "xavyo-system");
        assert_eq!(SYSTEM_TENANT_SLUG, "system");
    }

    // T024: Unit test for CLI OAuth client constants
    #[test]
    fn test_cli_oauth_client_constants() {
        // Verify CLI OAuth client ID
        assert_eq!(CLI_OAUTH_CLIENT_ID, "xavyo-cli");
        assert_eq!(CLI_OAUTH_CLIENT_NAME, "Xavyo CLI");

        // Verify CLI OAuth client UUID
        assert_eq!(
            CLI_OAUTH_CLIENT_UUID.to_string(),
            "00000000-0000-0000-0000-000000000002"
        );

        // Verify grant types include device_code
        assert!(CLI_OAUTH_GRANT_TYPES.contains(&"urn:ietf:params:oauth:grant-type:device_code"));
        assert!(CLI_OAUTH_GRANT_TYPES.contains(&"refresh_token"));

        // Verify scopes
        assert!(CLI_OAUTH_SCOPES.contains(&"openid"));
        assert!(CLI_OAUTH_SCOPES.contains(&"profile"));
        assert!(CLI_OAUTH_SCOPES.contains(&"email"));
        assert!(CLI_OAUTH_SCOPES.contains(&"tenant:provision"));
    }

    // T015: Unit test for BootstrapResult creation
    #[test]
    fn test_bootstrap_result_creation() {
        let result = BootstrapResult {
            tenant_created: true,
            oauth_client_created: true,
            tenant_id: SYSTEM_TENANT_ID,
        };

        assert!(result.tenant_created);
        assert!(result.oauth_client_created);
        assert_eq!(result.tenant_id, SYSTEM_TENANT_ID);

        // Test with no creation
        let result_no_create = BootstrapResult {
            tenant_created: false,
            oauth_client_created: false,
            tenant_id: SYSTEM_TENANT_ID,
        };

        assert!(!result_no_create.tenant_created);
        assert!(!result_no_create.oauth_client_created);
    }
}
