//! Handlers for tenant usage tracking API.
//!
//! F-USAGE-TRACK: Provides usage metrics for billing and quota enforcement.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::{bootstrap::SYSTEM_TENANT_ID, models::TenantUsageMetrics};

use crate::error::TenantError;
use crate::models::{
    UsageHistoryQuery, UsageHistoryResponse, UsageLimits, UsageMetrics, UsagePeriod, UsageResponse,
};
use crate::router::TenantAppState;

/// GET /system/tenants/{id}/usage
///
/// Get current usage metrics for a tenant.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/{id}/usage",
    params(
        ("id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Current usage metrics", body = UsageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_tenant_usage_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<UsageResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can view tenant usage".to_string(),
        ));
    }

    // Check tenant exists
    let tenant = xavyo_db::models::Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| {
            TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found"))
        })?;

    // Get or create current period metrics
    let metrics = TenantUsageMetrics::get_or_create_current(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Extract limits from tenant settings if available
    let limits = extract_limits_from_settings(&tenant.settings);

    Ok(Json(UsageResponse {
        tenant_id,
        period_start: metrics.period_start,
        period_end: metrics.period_end,
        metrics: UsageMetrics {
            mau_count: metrics.mau_count,
            api_calls: metrics.api_calls,
            auth_events: metrics.auth_events,
            agent_invocations: metrics.agent_invocations,
        },
        limits,
    }))
}

/// GET /system/tenants/{id}/usage/history
///
/// Get historical usage metrics for a tenant.
///
/// Requires authentication as a system tenant administrator.
#[utoipa::path(
    get,
    path = "/system/tenants/{id}/usage/history",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
        ("periods" = Option<usize>, Query, description = "Number of periods to retrieve (default: 6, max: 24)")
    ),
    responses(
        (status = 200, description = "Historical usage metrics", body = UsageHistoryResponse),
        (status = 400, description = "Invalid query parameters", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = crate::error::ErrorResponse),
        (status = 404, description = "Tenant not found", body = crate::error::ErrorResponse),
    ),
    tag = "System Administration",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_tenant_usage_history_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<UsageHistoryQuery>,
) -> Result<Json<UsageHistoryResponse>, TenantError> {
    // Verify caller is system tenant admin
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Only system tenant administrators can view tenant usage history".to_string(),
        ));
    }

    // Validate query
    if let Some(error) = query.validate() {
        return Err(TenantError::Validation(error));
    }

    // Check tenant exists
    let _tenant = xavyo_db::models::Tenant::find_by_id(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| {
            TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found"))
        })?;

    // Get historical metrics
    let history = TenantUsageMetrics::get_history(&state.pool, tenant_id, query.periods)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    let periods: Vec<UsagePeriod> = history
        .into_iter()
        .map(|m| UsagePeriod {
            period_start: m.period_start,
            period_end: m.period_end,
            mau_count: m.mau_count,
            api_calls: m.api_calls,
            auth_events: m.auth_events,
            agent_invocations: m.agent_invocations,
        })
        .collect();

    Ok(Json(UsageHistoryResponse { tenant_id, periods }))
}

/// Extract usage limits from tenant settings JSON.
fn extract_limits_from_settings(settings: &serde_json::Value) -> UsageLimits {
    let limits = settings.get("limits").cloned().unwrap_or_default();

    UsageLimits {
        max_mau: limits
            .get("max_mau")
            .and_then(serde_json::Value::as_i64)
            .map(|v| v as i32),
        max_api_calls: limits.get("max_api_calls").and_then(serde_json::Value::as_i64),
        max_agent_invocations: limits.get("max_agent_invocations").and_then(serde_json::Value::as_i64),
    }
}
