//! Handlers for tenant suspension and reactivation.
//!
//! F-SUSPEND: These endpoints are only accessible to system tenant administrators.

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
use crate::models::{
    ReactivateTenantResponse, SuspendTenantRequest, SuspendTenantResponse, TenantStatusResponse,
};
use crate::router::TenantAppState;

/// POST /system/tenants/{id}/suspend
///
/// Suspend a tenant, preventing all API access.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/suspend",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to suspend")
    ),
    request_body = SuspendTenantRequest,
    responses(
        (status = 200, description = "Tenant suspended successfully", body = SuspendTenantResponse),
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
pub async fn suspend_tenant_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<SuspendTenantRequest>,
) -> Result<Json<SuspendTenantResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can suspend tenants".to_string(),
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
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found")))?;

    if target_tenant.is_system() {
        return Err(TenantError::Forbidden(
            "Cannot suspend the system tenant".to_string(),
        ));
    }

    // FR-010: Idempotent operation - if already suspended, return success
    if target_tenant.is_suspended() {
        tracing::info!(
            tenant_id = %tenant_id,
            "Tenant already suspended (idempotent success)"
        );
        return Ok(Json(SuspendTenantResponse {
            tenant_id,
            suspended_at: target_tenant.suspended_at.unwrap_or_else(chrono::Utc::now),
            suspension_reason: target_tenant.suspension_reason.unwrap_or_default(),
        }));
    }

    // Suspend the tenant
    let suspended_tenant = Tenant::suspend(&state.pool, tenant_id, &request.reason)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id: SYSTEM_TENANT_ID,
            admin_user_id,
            action: AdminAction::Update,
            resource_type: AdminResourceType::Tenant,
            resource_id: Some(tenant_id),
            old_value: Some(serde_json::json!({
                "suspended_at": null,
                "suspension_reason": null
            })),
            new_value: Some(serde_json::json!({
                "suspended_at": suspended_tenant.suspended_at,
                "suspension_reason": suspended_tenant.suspension_reason
            })),
            ip_address: None, // Could extract from request if needed
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        admin_user_id = %admin_user_id,
        reason = %request.reason,
        "Tenant suspended"
    );

    Ok(Json(SuspendTenantResponse {
        tenant_id,
        suspended_at: suspended_tenant
            .suspended_at
            .unwrap_or_else(chrono::Utc::now),
        suspension_reason: request.reason,
    }))
}

/// POST /system/tenants/{id}/reactivate
///
/// Reactivate a suspended tenant, restoring API access.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/reactivate",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to reactivate")
    ),
    responses(
        (status = 200, description = "Tenant reactivated successfully", body = ReactivateTenantResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn reactivate_tenant_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<ReactivateTenantResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can reactivate tenants".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Check target tenant exists
    let target_tenant = Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found")))?;

    // FR-010: Idempotent operation - if not suspended, return success
    if !target_tenant.is_suspended() {
        tracing::info!(
            tenant_id = %tenant_id,
            "Tenant not suspended (idempotent success)"
        );
        return Ok(Json(ReactivateTenantResponse {
            tenant_id,
            reactivated_at: Utc::now(),
        }));
    }

    let old_suspended_at = target_tenant.suspended_at;
    let old_reason = target_tenant.suspension_reason.clone();

    // Reactivate the tenant
    Tenant::reactivate(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id: SYSTEM_TENANT_ID,
            admin_user_id,
            action: AdminAction::Update,
            resource_type: AdminResourceType::Tenant,
            resource_id: Some(tenant_id),
            old_value: Some(serde_json::json!({
                "suspended_at": old_suspended_at,
                "suspension_reason": old_reason
            })),
            new_value: Some(serde_json::json!({
                "suspended_at": null,
                "suspension_reason": null
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        admin_user_id = %admin_user_id,
        "Tenant reactivated"
    );

    Ok(Json(ReactivateTenantResponse {
        tenant_id,
        reactivated_at: Utc::now(),
    }))
}

/// GET /system/tenants/{id}
///
/// Get tenant details including suspension status.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/{id}",
    params(
        ("id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Tenant details", body = TenantStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_tenant_status_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<TenantStatusResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can view tenant status".to_string(),
        ));
    }

    // Get tenant
    let tenant = Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found")))?;

    let is_suspended = tenant.is_suspended();
    let is_deleted = tenant.is_deleted();

    Ok(Json(TenantStatusResponse {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        is_suspended,
        suspended_at: tenant.suspended_at,
        suspension_reason: tenant.suspension_reason,
        is_deleted,
        deleted_at: tenant.deleted_at,
        deletion_reason: tenant.deletion_reason,
        scheduled_purge_at: tenant.scheduled_purge_at,
        created_at: tenant.created_at,
    }))
}
