//! Handlers for tenant settings management.
//!
//! F-SETTINGS-API: These endpoints are only accessible to system tenant administrators.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::{
    bootstrap::SYSTEM_TENANT_ID,
    models::{AdminAction, AdminAuditLog, AdminResourceType, CreateAuditLogEntry, Tenant},
};

use crate::error::TenantError;
use crate::models::{GetSettingsResponse, UpdateSettingsRequest, UpdateSettingsResponse};
use crate::router::TenantAppState;

/// PATCH /system/tenants/{id}/settings
///
/// Update tenant settings with partial merge.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    patch,
    path = "/system/tenants/{id}/settings",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to update settings for")
    ),
    request_body = UpdateSettingsRequest,
    responses(
        (status = 200, description = "Settings updated successfully", body = UpdateSettingsResponse),
        (status = 400, description = "Validation error", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_settings_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateSettingsRequest>,
) -> Result<Json<UpdateSettingsResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can update tenant settings".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Validate request
    if let Some(error) = request.validate() {
        return Err(TenantError::Validation(error));
    }

    // Check target tenant exists and is not system tenant
    let target_tenant = Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| {
            TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found"))
        })?;

    if target_tenant.is_system() {
        return Err(TenantError::Forbidden(
            "Cannot modify system tenant settings via this API".to_string(),
        ));
    }

    let old_settings = target_tenant.settings.clone();

    // Update settings with merge
    let updated_tenant = Tenant::update_settings(&state.pool, tenant_id, request.settings.clone())
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id: SYSTEM_TENANT_ID,
            admin_user_id,
            action: AdminAction::Update,
            resource_type: AdminResourceType::TenantSettings,
            resource_id: Some(tenant_id),
            old_value: Some(old_settings),
            new_value: Some(updated_tenant.settings.clone()),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        admin_user_id = %admin_user_id,
        "Tenant settings updated"
    );

    Ok(Json(UpdateSettingsResponse {
        tenant_id,
        settings: updated_tenant.settings,
        updated_at: Utc::now(),
    }))
}

/// GET /system/tenants/{id}/settings
///
/// Get current tenant settings.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/{id}/settings",
    params(
        ("id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Tenant settings", body = GetSettingsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_settings_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<GetSettingsResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can view tenant settings".to_string(),
        ));
    }

    // Get tenant
    let tenant = Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| {
            TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found"))
        })?;

    Ok(Json(GetSettingsResponse {
        tenant_id: tenant.id,
        settings: tenant.settings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_update_settings_response_serialization() {
        let response = UpdateSettingsResponse {
            tenant_id: Uuid::new_v4(),
            settings: json!({
                "limits": {"max_mau": 1000}
            }),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("settings"));
        assert!(json.contains("updated_at"));
    }

    #[test]
    fn test_get_settings_response_serialization() {
        let response = GetSettingsResponse {
            tenant_id: Uuid::new_v4(),
            settings: json!({
                "limits": {"max_mau": 500}
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("settings"));
        assert!(json.contains("max_mau"));
    }
}
