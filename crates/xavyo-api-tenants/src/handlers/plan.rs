//! Handlers for tenant plan management.
//!
//! F-PLAN-MGMT: These endpoints are only accessible to system tenant administrators.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::bootstrap::SYSTEM_TENANT_ID;

use crate::error::TenantError;
use crate::models::{
    DowngradePlanRequest, PlanChangeResponse, PlanHistoryResponse, PlansListResponse,
    UpgradePlanRequest,
};
use crate::router::TenantAppState;

/// Query parameters for plan history.
#[derive(Debug, Deserialize)]
pub struct PlanHistoryQuery {
    /// Maximum number of entries to return (default 10, max 100).
    #[serde(default = "default_limit")]
    pub limit: i32,
}

fn default_limit() -> i32 {
    10
}

/// POST /system/tenants/{id}/plan/upgrade
///
/// Upgrade a tenant's plan (takes effect immediately).
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/plan/upgrade",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to upgrade")
    ),
    request_body = UpgradePlanRequest,
    responses(
        (status = 200, description = "Plan upgraded successfully", body = PlanChangeResponse),
        (status = 400, description = "Validation error (same tier, lower tier, invalid plan)", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "Plan Management",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn upgrade_plan_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpgradePlanRequest>,
) -> Result<Json<PlanChangeResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can upgrade plans".to_string(),
        ));
    }

    // Cannot upgrade system tenant
    if tenant_id == SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Cannot modify system tenant plan".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    let response = state
        .plan_service
        .upgrade_plan(tenant_id, request, admin_user_id, None, None)
        .await?;

    Ok(Json(response))
}

/// POST /system/tenants/{id}/plan/downgrade
///
/// Schedule a tenant plan downgrade (takes effect at next billing cycle).
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    post,
    path = "/system/tenants/{id}/plan/downgrade",
    params(
        ("id" = Uuid, Path, description = "Tenant ID to downgrade")
    ),
    request_body = DowngradePlanRequest,
    responses(
        (status = 200, description = "Downgrade scheduled successfully", body = PlanChangeResponse),
        (status = 400, description = "Validation error (same tier, higher tier, invalid plan, pending exists)", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "Plan Management",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn downgrade_plan_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<DowngradePlanRequest>,
) -> Result<Json<PlanChangeResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can downgrade plans".to_string(),
        ));
    }

    // Cannot downgrade system tenant
    if tenant_id == SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Cannot modify system tenant plan".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    let response = state
        .plan_service
        .downgrade_plan(tenant_id, request, admin_user_id, None, None)
        .await?;

    Ok(Json(response))
}

/// DELETE /system/tenants/{id}/plan/pending
///
/// Cancel a pending plan downgrade.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    delete,
    path = "/system/tenants/{id}/plan/pending",
    params(
        ("id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Pending downgrade cancelled", body = PlanChangeResponse),
        (status = 400, description = "No pending downgrade to cancel", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "Plan Management",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn cancel_downgrade_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<PlanChangeResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can cancel downgrades".to_string(),
        ));
    }

    // Cannot modify system tenant
    if tenant_id == SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Cannot modify system tenant plan".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    let response = state
        .plan_service
        .cancel_pending_downgrade(tenant_id, admin_user_id, None, None)
        .await?;

    Ok(Json(response))
}

/// GET /system/tenants/{id}/plan/history
///
/// Get plan change history for a tenant.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/{id}/plan/history",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
        ("limit" = Option<i32>, Query, description = "Maximum entries to return (default 10, max 100)")
    ),
    responses(
        (status = 200, description = "Plan history", body = PlanHistoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "Plan Management",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_plan_history_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<PlanHistoryQuery>,
) -> Result<Json<PlanHistoryResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can view plan history".to_string(),
        ));
    }

    // Clamp limit to 1-100
    let limit = query.limit.clamp(1, 100);

    let response = state
        .plan_service
        .get_plan_history(tenant_id, limit)
        .await?;

    Ok(Json(response))
}

/// GET /system/plans
///
/// List all available plan definitions.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/plans",
    responses(
        (status = 200, description = "List of available plans", body = PlansListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
    ),
    tag = "Plan Management",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_plans_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<PlansListResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can list plans".to_string(),
        ));
    }

    let response = state.plan_service.list_plans();

    Ok(Json(response))
}
