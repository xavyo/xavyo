//! Admin device management handlers (F026).
//!
//! Handlers for admin device listing, revocation, and policy management.
//! These handlers require admin privileges.

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_core::TenantId;

use crate::{
    error::ApiAuthError,
    models::{
        AdminListDevicesQuery, DeviceListResponse, DevicePolicyResponse, DeviceResponse,
        UpdateDevicePolicyRequest,
    },
    services::{DevicePolicyService, DeviceService},
};

// ============================================================================
// User Story 4: Admin Device Management
// ============================================================================

/// GET /`admin/users/:user_id/devices`
///
/// List all devices for a specific user (admin view).
/// Query params: `include_revoked=true` to include revoked devices.
pub async fn admin_list_user_devices(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<AdminListDevicesQuery>,
) -> Result<(StatusCode, Json<DeviceListResponse>), ApiAuthError> {
    let devices = device_service
        .get_user_devices_admin(user_id, *tenant_id.as_uuid(), query.include_revoked)
        .await?;

    let device_responses: Vec<DeviceResponse> = devices
        .into_iter()
        .map(|d| DeviceResponse::from_user_device_admin(d, query.include_revoked))
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

/// DELETE /`admin/users/:user_id/devices/:device_id`
///
/// Revoke a device for a specific user (admin action).
pub async fn admin_revoke_device(
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path((user_id, device_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiAuthError> {
    device_service
        .revoke_device_admin(device_id, user_id, *tenant_id.as_uuid())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// User Story 5: Tenant Device Policy Configuration
// ============================================================================

/// GET /admin/tenants/:tenant_id/device-policy
///
/// Get device policy for the tenant.
pub async fn get_device_policy(
    Extension(device_policy_service): Extension<Arc<DevicePolicyService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<DevicePolicyResponse>), ApiAuthError> {
    let policy = device_policy_service.get_device_policy(tenant_id).await?;

    Ok((StatusCode::OK, Json(policy.into())))
}

/// PUT /admin/tenants/:tenant_id/device-policy
///
/// Update device policy for the tenant.
pub async fn update_device_policy(
    Extension(device_policy_service): Extension<Arc<DevicePolicyService>>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateDevicePolicyRequest>,
) -> Result<(StatusCode, Json<DevicePolicyResponse>), ApiAuthError> {
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;
    let policy = device_policy_service
        .update_device_policy(tenant_id, request)
        .await?;

    Ok((StatusCode::OK, Json(policy.into())))
}
