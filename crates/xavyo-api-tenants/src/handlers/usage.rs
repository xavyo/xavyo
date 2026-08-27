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
        (status = 403, description = "Forbidden - must be system tenant admin", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
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
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found")))?;

    // Get or create current period metrics
    let metrics = TenantUsageMetrics::get_or_create_current(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Extract limits from tenant settings if available
    let limits = extract_limits_from_settings(&tenant.settings)?;

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
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must be system tenant admin", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
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
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("Tenant {tenant_id} not found")))?;

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
/// Corrupt `limits` must not look like unlimited quotas.
fn extract_limits_from_settings(settings: &serde_json::Value) -> Result<UsageLimits, TenantError> {
    let Some(limits) = settings.get("limits") else {
        return Ok(UsageLimits {
            max_mau: None,
            max_api_calls: None,
            max_agent_invocations: None,
        });
    };
    if limits.is_null() {
        return Ok(UsageLimits {
            max_mau: None,
            max_api_calls: None,
            max_agent_invocations: None,
        });
    }
    let obj = limits.as_object().ok_or_else(|| {
        TenantError::Validation("tenant settings.limits must be an object".to_string())
    })?;

    Ok(UsageLimits {
        max_mau: optional_i64(obj.get("max_mau"), "max_mau")?.map(|v| v as i32),
        max_api_calls: optional_i64(obj.get("max_api_calls"), "max_api_calls")?,
        max_agent_invocations: optional_i64(
            obj.get("max_agent_invocations"),
            "max_agent_invocations",
        )?,
    })
}

fn optional_i64(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Option<i64>, TenantError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .ok_or_else(|| {
                TenantError::Validation(format!("tenant settings.limits.{field} must be a number"))
            })
            .map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_limits_does_not_treat_corrupt_json_as_unlimited() {
        let missing = extract_limits_from_settings(&serde_json::json!({})).unwrap();
        assert!(missing.max_mau.is_none());
        assert!(extract_limits_from_settings(&serde_json::json!({"limits": "nope"})).is_err());
        assert!(
            extract_limits_from_settings(&serde_json::json!({"limits": {"max_mau": "10"}}))
                .is_err()
        );
        let ok =
            extract_limits_from_settings(&serde_json::json!({"limits": {"max_mau": 50}})).unwrap();
        assert_eq!(ok.max_mau, Some(50));

        let src = include_str!("usage.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("unwrap_or_default()"),
            "usage GET must not hide corrupt limits as unlimited"
        );
    }
}
