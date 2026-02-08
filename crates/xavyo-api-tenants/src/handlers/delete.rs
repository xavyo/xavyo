//! Handlers for tenant soft delete and restore.
//!
//! F-DELETE: These endpoints are only accessible to system tenant administrators.
//! Provides a 30-day grace period for recovery before permanent deletion.

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
    DeleteTenantRequest, DeleteTenantResponse, DeletedTenantInfo, DeletedTenantListResponse,
    RestoreTenantResponse,
};
use crate::router::TenantAppState;

/// Default grace period in days before permanent deletion.
const DEFAULT_GRACE_PERIOD_DAYS: i64 = 30;

/// Grace period for immediate deletion (1 day minimum for safety).
const IMMEDIATE_GRACE_PERIOD_DAYS: i64 = 1;

/// POST /system/tenants/{id}/delete
///
/// Soft delete a tenant, marking it for deletion with a grace period.
/// The tenant becomes inaccessible immediately but can be restored within the grace period.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/delete",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to delete")
    ),
    request_body = DeleteTenantRequest,
    responses(
        (status = 200, description = "Tenant marked for deletion", body = DeleteTenantResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
        (status = 409, description = "Tenant already deleted", body = ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_tenant_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<DeleteTenantRequest>,
) -> Result<Json<DeleteTenantResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can delete tenants".to_string(),
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
            "Cannot delete the system tenant".to_string(),
        ));
    }

    if target_tenant.is_deleted() {
        return Err(TenantError::Conflict(format!(
            "Tenant {tenant_id} is already deleted"
        )));
    }

    // Determine grace period
    let grace_period_days = if request.immediate {
        IMMEDIATE_GRACE_PERIOD_DAYS
    } else {
        DEFAULT_GRACE_PERIOD_DAYS
    };

    // Soft delete the tenant
    let deleted_tenant =
        Tenant::soft_delete(&state.pool, tenant_id, &request.reason, grace_period_days)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id: SYSTEM_TENANT_ID,
            admin_user_id,
            action: AdminAction::Delete,
            resource_type: AdminResourceType::Tenant,
            resource_id: Some(tenant_id),
            old_value: Some(serde_json::json!({
                "deleted_at": null,
                "deletion_reason": null,
                "scheduled_purge_at": null
            })),
            new_value: Some(serde_json::json!({
                "deleted_at": deleted_tenant.deleted_at,
                "deletion_reason": deleted_tenant.deletion_reason,
                "scheduled_purge_at": deleted_tenant.scheduled_purge_at,
                "immediate": request.immediate
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        admin_user_id = %admin_user_id,
        reason = %request.reason,
        immediate = %request.immediate,
        scheduled_purge_at = ?deleted_tenant.scheduled_purge_at,
        "Tenant soft deleted"
    );

    Ok(Json(DeleteTenantResponse {
        tenant_id,
        deleted_at: deleted_tenant.deleted_at.unwrap_or_else(chrono::Utc::now),
        scheduled_purge_at: deleted_tenant
            .scheduled_purge_at
            .unwrap_or_else(chrono::Utc::now),
        reason: request.reason,
    }))
}

/// POST /system/tenants/{id}/restore
///
/// Restore a soft-deleted tenant within the grace period.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/restore",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to restore")
    ),
    responses(
        (status = 200, description = "Tenant restored successfully", body = RestoreTenantResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
        (status = 409, description = "Tenant not deleted or purge already started", body = ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn restore_tenant_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<RestoreTenantResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can restore tenants".to_string(),
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

    if !target_tenant.is_deleted() {
        return Err(TenantError::Conflict(format!(
            "Tenant {tenant_id} is not deleted"
        )));
    }

    // Check if purge has already started (past scheduled_purge_at)
    if let Some(scheduled_purge_at) = target_tenant.scheduled_purge_at {
        if scheduled_purge_at <= Utc::now() {
            return Err(TenantError::Conflict(
                "Cannot restore tenant: purge process has already started".to_string(),
            ));
        }
    }

    let old_deleted_at = target_tenant.deleted_at;
    let old_reason = target_tenant.deletion_reason.clone();
    let old_scheduled_purge = target_tenant.scheduled_purge_at;

    // Restore the tenant
    Tenant::restore(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    let restored_at = Utc::now();

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
                "deleted_at": old_deleted_at,
                "deletion_reason": old_reason,
                "scheduled_purge_at": old_scheduled_purge
            })),
            new_value: Some(serde_json::json!({
                "deleted_at": null,
                "deletion_reason": null,
                "scheduled_purge_at": null,
                "restored_at": restored_at
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        admin_user_id = %admin_user_id,
        "Tenant restored from soft delete"
    );

    Ok(Json(RestoreTenantResponse {
        tenant_id,
        restored_at,
    }))
}

/// GET /system/tenants/deleted
///
/// List all soft-deleted tenants.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/deleted",
    responses(
        (status = 200, description = "List of deleted tenants", body = DeletedTenantListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_deleted_tenants_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<DeletedTenantListResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can list deleted tenants".to_string(),
        ));
    }

    // Get all deleted tenants
    let deleted_tenants = Tenant::list_deleted(&state.pool)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    let total = deleted_tenants.len();

    let deleted_tenant_infos: Vec<DeletedTenantInfo> = deleted_tenants
        .into_iter()
        .map(|t| DeletedTenantInfo {
            id: t.id,
            name: t.name,
            slug: t.slug,
            deleted_at: t.deleted_at.unwrap_or_else(chrono::Utc::now),
            scheduled_purge_at: t.scheduled_purge_at.unwrap_or_else(chrono::Utc::now),
            deletion_reason: t.deletion_reason,
        })
        .collect();

    Ok(Json(DeletedTenantListResponse {
        deleted_tenants: deleted_tenant_infos,
        total,
    }))
}
