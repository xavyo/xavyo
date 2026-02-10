//! Shortcut handlers for /me/sessions and /me/devices (F027).
//!
//! These are convenience endpoints that delegate to existing handlers.
//! GET /me/sessions - Alias for sessions list
//! GET /me/devices - Alias for devices list

use crate::error::ApiAuthError;
use crate::models::session_responses::{SessionInfoResponse, SessionListResponse};
use crate::services::{DeviceService, SessionService};
use axum::{Extension, Json};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use xavyo_core::{TenantId, UserId};
use xavyo_db::UserDevice;

/// Response for GET /me/devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListResponse {
    /// List of devices.
    pub items: Vec<DeviceInfo>,

    /// Total number of devices.
    pub total: i64,

    /// ID of the current device (if fingerprint provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_device_id: Option<uuid::Uuid>,
}

/// Device information in the list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device ID.
    pub id: uuid::Uuid,

    /// Device name.
    pub device_name: Option<String>,

    /// Device type (desktop, mobile, tablet).
    pub device_type: Option<String>,

    /// Whether the device is trusted.
    pub is_trusted: bool,

    /// When the device was last seen.
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<UserDevice> for DeviceInfo {
    fn from(device: UserDevice) -> Self {
        Self {
            id: device.id,
            device_name: device.device_name,
            device_type: device.device_type,
            is_trusted: device.is_trusted,
            last_seen_at: Some(device.last_seen_at),
        }
    }
}

/// Handle GET /me/sessions request.
///
/// Returns the user's active sessions. This is an alias for the main
/// sessions list endpoint.
///
/// # Response
///
/// - 200 OK: Sessions list returned
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    get,
    path = "/me/sessions",
    responses(
        (status = 200, description = "Sessions list returned", body = SessionListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Profile"
)]
pub async fn get_me_sessions(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    _headers: HeaderMap,
) -> Result<Json<SessionListResponse>, ApiAuthError> {
    // Try to get current session ID from authorization header
    // This would require extracting the session ID from the JWT claims
    let current_session_id: Option<uuid::Uuid> = None; // Simplified for now

    let sessions = session_service
        .get_user_sessions(*user_id.as_uuid(), *tenant_id.as_uuid(), current_session_id)
        .await?;

    // Convert to response format
    let session_infos: Vec<SessionInfoResponse> = sessions
        .into_iter()
        .map(SessionInfoResponse::from)
        .collect();

    let total = session_infos.len();

    Ok(Json(SessionListResponse {
        sessions: session_infos,
        total,
    }))
}

/// Handle GET /me/devices request.
///
/// Returns the user's registered devices. This is an alias for the main
/// devices list endpoint.
///
/// # Response
///
/// - 200 OK: Devices list returned
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    get,
    path = "/me/devices",
    responses(
        (status = 200, description = "Devices list returned", body = DeviceListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Profile"
)]
pub async fn get_me_devices(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> Result<Json<DeviceListResponse>, ApiAuthError> {
    // Try to extract current device fingerprint from header
    let current_fingerprint = headers
        .get("X-Device-Fingerprint")
        .and_then(|v| v.to_str().ok());

    let (devices, current_device_id) = device_service
        .get_user_devices(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            current_fingerprint,
        )
        .await?;

    let device_infos: Vec<DeviceInfo> = devices.into_iter().map(DeviceInfo::from).collect();

    Ok(Json(DeviceListResponse {
        total: device_infos.len() as i64,
        items: device_infos,
        current_device_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_list_response_serialization() {
        let response = DeviceListResponse {
            items: vec![DeviceInfo {
                id: uuid::Uuid::new_v4(),
                device_name: Some("Work Laptop".to_string()),
                device_type: Some("desktop".to_string()),
                is_trusted: true,
                last_seen_at: Some(chrono::Utc::now()),
            }],
            total: 1,
            current_device_id: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"device_name\":\"Work Laptop\""));
        assert!(json.contains("\"is_trusted\":true"));
    }
}
