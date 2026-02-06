//! Profile management service (F027).
//!
//! Handles user profile operations: view, update, and security overview.

use crate::error::ApiAuthError;
use crate::models::{
    mfa_responses::{MfaMethod, MfaStatusResponse},
    ProfileResponse, SecurityOverviewResponse, UpdateProfileRequest,
};
use crate::services::{AlertService, DeviceService, MfaService, SessionService, WebAuthnService};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;
use xavyo_db::{set_tenant_context, User};

/// Profile management service.
#[derive(Clone)]
pub struct ProfileService {
    pool: PgPool,
}

impl ProfileService {
    /// Create a new profile service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // User Story 1: View and Update Profile
    // ========================================================================

    /// Get the current user's profile.
    pub async fn get_profile(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<ProfileResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::UserNotFound)?;

        Ok(ProfileResponse {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            first_name: user.first_name,
            last_name: user.last_name,
            avatar_url: user.avatar_url,
            email_verified: user.email_verified,
            created_at: user.created_at,
        })
    }

    /// Update the current user's profile.
    pub async fn update_profile(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<ProfileResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify user exists (include tenant_id for defense-in-depth)
        let _user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::UserNotFound)?;

        // Update profile with tenant isolation
        let updated = User::update_profile(
            &self.pool,
            tenant_id,
            user_id,
            request.display_name,
            request.first_name,
            request.last_name,
            request.avatar_url,
        )
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::UserNotFound)?;

        info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Profile updated"
        );

        Ok(ProfileResponse {
            id: updated.id,
            email: updated.email,
            display_name: updated.display_name,
            first_name: updated.first_name,
            last_name: updated.last_name,
            avatar_url: updated.avatar_url,
            email_verified: updated.email_verified,
            created_at: updated.created_at,
        })
    }

    // ========================================================================
    // User Story 4: View Security Overview
    // ========================================================================

    /// Get security overview for a user, aggregating data from multiple services.
    pub async fn get_security_overview(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        mfa_service: &MfaService,
        session_service: &SessionService,
        device_service: &DeviceService,
        alert_service: &AlertService,
    ) -> Result<SecurityOverviewResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get user for password dates (include tenant_id for defense-in-depth)
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::UserNotFound)?;

        // Get MFA status
        let mfa_status = mfa_service.get_status(user_id, tenant_id).await?;

        // Get active sessions count
        let sessions = session_service
            .get_user_sessions(user_id, tenant_id, None)
            .await?;
        let active_sessions_count = sessions.len() as i64;

        // Get trusted devices count
        let (devices, _) = device_service
            .get_user_devices(user_id, tenant_id, None)
            .await?;
        let trusted_devices_count = devices.iter().filter(|d| d.is_trusted).count() as i64;

        // Get unacknowledged alerts count
        let recent_security_alerts_count = alert_service
            .get_unacknowledged_count(user_id, tenant_id)
            .await?;

        // Build MFA methods list
        let mfa_methods = if mfa_status.totp_enabled {
            vec!["totp".to_string()]
        } else {
            vec![]
        };

        Ok(SecurityOverviewResponse {
            mfa_enabled: mfa_status.totp_enabled,
            mfa_methods,
            trusted_devices_count,
            active_sessions_count,
            last_password_change: user.password_changed_at,
            recent_security_alerts_count,
            password_expires_at: user.password_expires_at,
        })
    }

    // ========================================================================
    // User Story 5: View MFA Status
    // ========================================================================

    /// Get MFA status for a user.
    pub async fn get_mfa_status(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        mfa_service: &MfaService,
        webauthn_service: Option<&WebAuthnService>,
    ) -> Result<MfaStatusResponse, ApiAuthError> {
        let mfa_status = mfa_service.get_status(user_id, tenant_id).await?;

        // Check WebAuthn status (T070)
        let webauthn_enabled = if let Some(ws) = webauthn_service {
            ws.has_webauthn_enabled(user_id, tenant_id)
                .await
                .unwrap_or(false)
        } else {
            false
        };

        // Build available methods list (T069)
        let mut available_methods = Vec::new();
        if mfa_status.totp_enabled {
            available_methods.push(MfaMethod::Totp);
        }
        if webauthn_enabled {
            available_methods.push(MfaMethod::Webauthn);
        }
        if mfa_status.recovery_codes_remaining > 0 {
            available_methods.push(MfaMethod::Recovery);
        }

        Ok(MfaStatusResponse {
            totp_enabled: mfa_status.totp_enabled,
            webauthn_enabled,
            recovery_codes_remaining: mfa_status.recovery_codes_remaining,
            available_methods,
            setup_at: mfa_status.setup_at,
            last_used_at: mfa_status.last_used_at,
        })
    }
}

#[cfg(test)]
mod tests {
    // Integration tests will be in the tests/ directory
}
