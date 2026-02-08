//! User-to-NHI permission management service.
//!
//! Manages user access permissions to NHI identities:
//! - Grant permissions with optional expiry
//! - Revoke permissions
//! - List permissions by user or NHI
//! - Check access (with permission hierarchy: admin > manage > use)
//! - Cascade revoke all permissions for an NHI (on archive)

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::nhi_identity::NhiIdentity;
use xavyo_db::models::nhi_user_permission::{CreateNhiUserPermission, NhiUserPermission};

use crate::error::NhiApiError;

/// Valid permission types for user-to-NHI grants.
const VALID_PERMISSION_TYPES: &[&str] = &["use", "manage", "admin"];

/// Service for managing user-to-NHI permissions.
pub struct NhiUserPermissionService;

impl NhiUserPermissionService {
    /// Grant a user permission to access an NHI.
    ///
    /// Validates:
    /// - NHI exists and is in `active` lifecycle state
    /// - Permission type is valid (use/manage/admin)
    /// - `expires_at`, if provided, is in the future
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        permission_type: &str,
        granted_by: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<NhiUserPermission, NhiApiError> {
        // 1. Validate permission type
        if !VALID_PERMISSION_TYPES.contains(&permission_type) {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid permission_type '{}'; must be one of: use, manage, admin",
                permission_type
            )));
        }

        // 2. Verify NHI exists and is active
        let nhi = NhiIdentity::find_by_id(pool, tenant_id, nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if !nhi.lifecycle_state.is_usable() {
            return Err(NhiApiError::BadRequest(format!(
                "NHI is in {} state; must be active to grant permissions",
                nhi.lifecycle_state
            )));
        }

        // 3. Validate expires_at is in the future if provided
        if let Some(exp) = expires_at {
            if exp <= Utc::now() {
                return Err(NhiApiError::BadRequest(
                    "expires_at must be in the future".into(),
                ));
            }
        }

        // 4. Create (or upsert) the permission
        let input = CreateNhiUserPermission {
            user_id,
            nhi_id,
            permission_type: permission_type.to_string(),
            granted_by: Some(granted_by),
            expires_at,
        };

        let perm = NhiUserPermission::grant(pool, tenant_id, input).await?;
        Ok(perm)
    }

    /// Revoke a user's permission on an NHI.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<bool, NhiApiError> {
        if !VALID_PERMISSION_TYPES.contains(&permission_type) {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid permission_type '{}'; must be one of: use, manage, admin",
                permission_type
            )));
        }

        let revoked = NhiUserPermission::revoke(pool, tenant_id, user_id, nhi_id, permission_type)
            .await
            .map_err(NhiApiError::Database)?;

        if !revoked {
            return Err(NhiApiError::NotFound);
        }

        Ok(revoked)
    }

    /// List users with permissions on a specific NHI.
    pub async fn list_by_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiUserPermission>, NhiApiError> {
        let perms = NhiUserPermission::list_by_nhi(pool, tenant_id, nhi_id, limit, offset).await?;
        Ok(perms)
    }

    /// List NHIs accessible by a specific user.
    pub async fn list_by_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiUserPermission>, NhiApiError> {
        let perms =
            NhiUserPermission::list_by_user(pool, tenant_id, user_id, limit, offset).await?;
        Ok(perms)
    }

    /// Check if a user has the required permission on an NHI.
    ///
    /// Permission hierarchy: admin > manage > use.
    /// Returns true if the user has the required permission or higher.
    pub async fn check_access(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        nhi_id: Uuid,
        required_type: &str,
    ) -> Result<bool, NhiApiError> {
        NhiUserPermission::check_permission(pool, tenant_id, user_id, nhi_id, required_type)
            .await
            .map_err(NhiApiError::Database)
    }

    /// Enforce access: if the user is not admin/super_admin, check permission.
    ///
    /// Returns Ok(()) if access is allowed, Err(Forbidden) otherwise.
    pub async fn enforce_access(
        pool: &PgPool,
        tenant_id: Uuid,
        claims: &xavyo_auth::JwtClaims,
        nhi_id: Uuid,
        required_permission: &str,
    ) -> Result<(), NhiApiError> {
        // Admin and super_admin bypass permission checks
        if claims.has_role("admin") || claims.has_role("super_admin") {
            return Ok(());
        }

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

        let has_access =
            Self::check_access(pool, tenant_id, user_id, nhi_id, required_permission).await?;

        if !has_access {
            return Err(NhiApiError::Forbidden);
        }

        Ok(())
    }

    /// Cascade revoke all user permissions for an NHI (called on archive).
    pub async fn cascade_revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, NhiApiError> {
        NhiUserPermission::revoke_all_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)
    }
}
