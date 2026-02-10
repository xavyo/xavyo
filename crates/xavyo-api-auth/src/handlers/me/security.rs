//! Security overview handlers (F027).
//!
//! GET /me/security - Get security overview
//! GET /me/mfa - Get MFA status

use crate::error::ApiAuthError;
use crate::models::{mfa_responses::MfaStatusResponse, SecurityOverviewResponse};
use crate::services::{
    AlertService, DeviceService, MfaService, ProfileService, SessionService, WebAuthnService,
};
use axum::{Extension, Json};
use std::sync::Arc;
use xavyo_core::{TenantId, UserId};

/// Handle GET /me/security request.
///
/// Returns a consolidated security overview aggregating MFA, devices,
/// sessions, and alerts.
///
/// # Response
///
/// - 200 OK: Security overview returned
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    get,
    path = "/me/security",
    responses(
        (status = 200, description = "Security overview returned", body = SecurityOverviewResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Security"
)]
pub async fn get_security_overview(
    Extension(profile_service): Extension<Arc<ProfileService>>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
) -> Result<Json<SecurityOverviewResponse>, ApiAuthError> {
    let overview = profile_service
        .get_security_overview(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            mfa_service.as_ref(),
            session_service.as_ref(),
            device_service.as_ref(),
            alert_service.as_ref(),
        )
        .await?;

    Ok(Json(overview))
}

/// Handle GET /me/mfa request.
///
/// Returns the user's MFA configuration status.
///
/// # Response
///
/// - 200 OK: MFA status returned
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    get,
    path = "/me/mfa",
    responses(
        (status = 200, description = "MFA status returned", body = MfaStatusResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Security"
)]
pub async fn get_mfa_status(
    Extension(profile_service): Extension<Arc<ProfileService>>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(webauthn_service): Extension<Arc<WebAuthnService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
) -> Result<Json<MfaStatusResponse>, ApiAuthError> {
    let status = profile_service
        .get_mfa_status(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            mfa_service.as_ref(),
            Some(webauthn_service.as_ref()),
        )
        .await?;

    Ok(Json(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::mfa_responses::MfaMethod;

    #[test]
    fn test_security_overview_response_serialization() {
        let response = SecurityOverviewResponse {
            mfa_enabled: true,
            mfa_methods: vec!["totp".to_string()],
            trusted_devices_count: 2,
            active_sessions_count: 3,
            last_password_change: Some(chrono::Utc::now()),
            recent_security_alerts_count: 1,
            password_expires_at: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"mfa_enabled\":true"));
        assert!(json.contains("\"mfa_methods\":[\"totp\"]"));
    }

    #[test]
    fn test_mfa_status_response_serialization() {
        let response = MfaStatusResponse {
            totp_enabled: true,
            webauthn_enabled: false,
            recovery_codes_remaining: 8,
            available_methods: vec![MfaMethod::Totp, MfaMethod::Recovery],
            setup_at: Some(chrono::Utc::now()),
            last_used_at: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"totp_enabled\":true"));
        assert!(json.contains("\"webauthn_enabled\":false"));
        assert!(json.contains("\"recovery_codes_remaining\":8"));
    }
}
