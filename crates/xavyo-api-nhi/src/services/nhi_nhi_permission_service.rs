//! NHI-to-NHI permission management service.
//!
//! Manages NHI calling/delegation permissions:
//! - Grant calling permissions between NHIs
//! - Revoke permissions
//! - List callers/callees for an NHI
//! - Cascade revoke all permissions for an NHI (on archive)

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::nhi_identity::NhiIdentity;
use xavyo_db::models::nhi_nhi_permission::{CreateNhiNhiPermission, NhiNhiPermission};

use crate::error::NhiApiError;

/// Valid permission types for NHI-to-NHI grants.
const VALID_PERMISSION_TYPES: &[&str] = &["call", "delegate"];

/// Service for managing NHI-to-NHI permissions.
pub struct NhiNhiPermissionService;

impl NhiNhiPermissionService {
    /// Grant an NHI calling/delegation permission to another NHI.
    ///
    /// Validates:
    /// - Both NHIs exist and are in `active` lifecycle state
    /// - Source and target are different (no self-reference)
    /// - Permission type is valid (call/delegate)
    /// - `expires_at`, if provided, is in the future
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        target_nhi_id: Uuid,
        permission_type: &str,
        allowed_actions: Option<serde_json::Value>,
        max_calls_per_hour: Option<i32>,
        granted_by: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<NhiNhiPermission, NhiApiError> {
        // 1. Validate permission type
        if !VALID_PERMISSION_TYPES.contains(&permission_type) {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid permission_type '{}'; must be one of: call, delegate",
                permission_type
            )));
        }

        // 2. Validate no self-reference
        if source_nhi_id == target_nhi_id {
            return Err(NhiApiError::BadRequest(
                "Source and target NHI must be different".into(),
            ));
        }

        // 3. Verify source NHI exists and is active
        let source = NhiIdentity::find_by_id(pool, tenant_id, source_nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if !source.lifecycle_state.is_usable() {
            return Err(NhiApiError::BadRequest(format!(
                "Source NHI is in {} state; must be active to grant permissions",
                source.lifecycle_state
            )));
        }

        // 4. Verify target NHI exists and is active
        let target = NhiIdentity::find_by_id(pool, tenant_id, target_nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if !target.lifecycle_state.is_usable() {
            return Err(NhiApiError::BadRequest(format!(
                "Target NHI is in {} state; must be active to grant permissions",
                target.lifecycle_state
            )));
        }

        // 5. Validate expires_at is in the future if provided
        if let Some(exp) = expires_at {
            if exp <= Utc::now() {
                return Err(NhiApiError::BadRequest(
                    "expires_at must be in the future".into(),
                ));
            }
        }

        // 6. Validate max_calls_per_hour is positive if provided
        if let Some(rate) = max_calls_per_hour {
            if rate <= 0 {
                return Err(NhiApiError::BadRequest(
                    "max_calls_per_hour must be positive".into(),
                ));
            }
        }

        // 7. Create (or upsert) the permission
        let input = CreateNhiNhiPermission {
            source_nhi_id,
            target_nhi_id,
            permission_type: permission_type.to_string(),
            allowed_actions,
            max_calls_per_hour,
            granted_by: Some(granted_by),
            expires_at,
        };

        let perm = NhiNhiPermission::grant(pool, tenant_id, input).await?;
        Ok(perm)
    }

    /// Revoke an NHI-to-NHI permission.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        target_nhi_id: Uuid,
        permission_type: &str,
    ) -> Result<bool, NhiApiError> {
        if !VALID_PERMISSION_TYPES.contains(&permission_type) {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid permission_type '{}'; must be one of: call, delegate",
                permission_type
            )));
        }

        let revoked = NhiNhiPermission::revoke(
            pool,
            tenant_id,
            source_nhi_id,
            target_nhi_id,
            permission_type,
        )
        .await
        .map_err(NhiApiError::Database)?;

        if !revoked {
            return Err(NhiApiError::NotFound);
        }

        Ok(revoked)
    }

    /// List NHIs that have calling permission TO a target NHI (callers).
    pub async fn list_callers(
        pool: &PgPool,
        tenant_id: Uuid,
        target_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiNhiPermission>, NhiApiError> {
        let perms =
            NhiNhiPermission::list_by_target(pool, tenant_id, target_nhi_id, limit, offset).await?;
        Ok(perms)
    }

    /// List NHIs that a source NHI has calling permission FOR (callees).
    pub async fn list_callees(
        pool: &PgPool,
        tenant_id: Uuid,
        source_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiNhiPermission>, NhiApiError> {
        let perms =
            NhiNhiPermission::list_by_source(pool, tenant_id, source_nhi_id, limit, offset).await?;
        Ok(perms)
    }

    /// Cascade revoke all NHI-to-NHI permissions involving an NHI (called on archive).
    pub async fn cascade_revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, NhiApiError> {
        NhiNhiPermission::revoke_all_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)
    }
}
