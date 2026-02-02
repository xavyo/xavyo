//! User device management handlers (F026).
//!
//! Handlers for device listing, trust management, renaming, and revocation.
//! These handlers are accessible to authenticated users for their own devices.

use axum::{extract::Path, http::StatusCode, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_core::{TenantId, UserId};

use crate::{
    error::ApiAuthError,
    models::{
        DeviceListResponse, DeviceResponse, RenameDeviceRequest, RenameDeviceResponse,
        TrustDeviceRequest, TrustDeviceResponse,
    },
    services::{DevicePolicyService, DeviceService},
};

// ============================================================================
// User Story 1: View My Devices
// ============================================================================

/// GET /devices
///
/// List all active (non-revoked) devices for the current user.
pub async fn list_devices(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(current_fingerprint): Extension<Option<String>>,
) -> Result<(StatusCode, Json<DeviceListResponse>), ApiAuthError> {
    let (devices, current_device_id) = device_service
        .get_user_devices(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            current_fingerprint.as_deref(),
        )
        .await?;

    let device_responses: Vec<DeviceResponse> = devices
        .into_iter()
        .map(|d| {
            let is_current = current_device_id.map(|id| id == d.id).unwrap_or(false);
            DeviceResponse::from_user_device(d, is_current)
        })
        .collect();

    let total = device_responses.len() as i64;

    Ok((
        StatusCode::OK,
        Json(DeviceListResponse {
            items: device_responses,
            total,
        }),
    ))
}

// ============================================================================
// User Story 2: Manage Device Trust
// ============================================================================

/// POST /devices/:id/trust
///
/// Mark a device as trusted. Optionally specify trust duration in days.
pub async fn trust_device(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(device_policy_service): Extension<Arc<DevicePolicyService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Path(device_id): Path<Uuid>,
    body: Option<Json<TrustDeviceRequest>>,
) -> Result<(StatusCode, Json<TrustDeviceResponse>), ApiAuthError> {
    // Check if trust is allowed by tenant policy
    let allow_mfa_bypass = device_policy_service
        .is_mfa_bypass_allowed(*tenant_id.as_uuid())
        .await?;

    if !allow_mfa_bypass {
        return Err(ApiAuthError::TrustNotAllowed);
    }

    // Get the requested duration and cap it to tenant maximum
    let requested_days = body.as_ref().and_then(|b| b.trust_duration_days);
    let capped_duration = device_policy_service
        .cap_trust_duration(*tenant_id.as_uuid(), requested_days)
        .await?;

    // Get default duration for when no duration specified
    let default_duration = device_policy_service
        .get_default_trust_duration(*tenant_id.as_uuid())
        .await?;

    let device = device_service
        .trust_device(
            device_id,
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            Some(capped_duration),
            default_duration,
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(TrustDeviceResponse {
            id: device.id,
            is_trusted: device.is_trusted,
            trust_expires_at: device.trust_expires_at,
        }),
    ))
}

/// DELETE /devices/:id/trust
///
/// Remove trust from a device.
pub async fn untrust_device(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Path(device_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TrustDeviceResponse>), ApiAuthError> {
    let device = device_service
        .untrust_device(device_id, *user_id.as_uuid(), *tenant_id.as_uuid())
        .await?;

    Ok((
        StatusCode::OK,
        Json(TrustDeviceResponse {
            id: device.id,
            is_trusted: device.is_trusted,
            trust_expires_at: device.trust_expires_at,
        }),
    ))
}

// ============================================================================
// User Story 3: Rename and Revoke Devices
// ============================================================================

/// PUT /devices/:id
///
/// Rename a device.
pub async fn rename_device(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Path(device_id): Path<Uuid>,
    Json(request): Json<RenameDeviceRequest>,
) -> Result<(StatusCode, Json<RenameDeviceResponse>), ApiAuthError> {
    // Validate name length
    let name = request.device_name.trim();
    if name.is_empty() {
        return Err(ApiAuthError::Validation(
            "device_name cannot be empty".to_string(),
        ));
    }
    if name.len() > 100 {
        return Err(ApiAuthError::Validation(
            "device_name cannot exceed 100 characters".to_string(),
        ));
    }

    let device = device_service
        .rename_device(device_id, *user_id.as_uuid(), *tenant_id.as_uuid(), name)
        .await?;

    Ok((
        StatusCode::OK,
        Json(RenameDeviceResponse {
            id: device.id,
            device_name: device.device_name.unwrap_or_default(),
        }),
    ))
}

/// DELETE /devices/:id
///
/// Revoke (soft-delete) a device.
pub async fn revoke_device(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<TenantId>,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    device_service
        .revoke_device(device_id, *user_id.as_uuid(), *tenant_id.as_uuid())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
