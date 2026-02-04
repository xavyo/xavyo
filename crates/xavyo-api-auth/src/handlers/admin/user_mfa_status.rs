//! Admin MFA status handler.
//!
//! GET /`admin/users/:user_id/mfa/status` - View MFA status for any user.

use axum::{extract::Path, http::StatusCode, Extension, Json};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::set_tenant_context;

use crate::{
    error::ApiAuthError,
    models::{MfaMethod, MfaStatusResponse},
    services::{MfaService, WebAuthnService},
};
use std::sync::Arc;

/// GET /`admin/users/:user_id/mfa/status`
///
/// Get MFA status for a specific user (admin view).
/// Requires authentication and admin role.
pub async fn get_user_mfa_status(
    Extension(pool): Extension<PgPool>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(webauthn_service): Extension<Arc<WebAuthnService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(user_id): Path<Uuid>,
) -> Result<(StatusCode, Json<MfaStatusResponse>), ApiAuthError> {
    // Set tenant context
    let mut conn = pool.acquire().await.map_err(ApiAuthError::Database)?;
    set_tenant_context(&mut *conn, tenant_id)
        .await
        .map_err(ApiAuthError::DatabaseInternal)?;

    // Get MFA status for the specified user
    let status = mfa_service
        .get_status(user_id, *tenant_id.as_uuid())
        .await?;

    // Check WebAuthn status (T070)
    let webauthn_enabled = webauthn_service
        .has_webauthn_enabled(user_id, *tenant_id.as_uuid())
        .await
        .unwrap_or(false);

    // Build available methods list (T069)
    let mut available_methods = Vec::new();
    if status.totp_enabled {
        available_methods.push(MfaMethod::Totp);
    }
    if webauthn_enabled {
        available_methods.push(MfaMethod::Webauthn);
    }
    if status.recovery_codes_remaining > 0 {
        available_methods.push(MfaMethod::Recovery);
    }

    Ok((
        StatusCode::OK,
        Json(MfaStatusResponse {
            totp_enabled: status.totp_enabled,
            webauthn_enabled,
            recovery_codes_remaining: status.recovery_codes_remaining,
            available_methods,
            setup_at: status.setup_at,
            last_used_at: status.last_used_at,
        }),
    ))
}
