//! HTTP handlers for License Analytics (F065).
//!
//! Provides endpoints for license usage analytics including a dashboard
//! overview and cost optimization recommendations.

use axum::{extract::State, Extension, Json};
use xavyo_auth::JwtClaims;

use axum::extract::Query;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::license::{ExpiringLicensesResponse, LicenseDashboardResponse, LicenseRecommendation},
    router::GovernanceState,
};

/// Get the license analytics dashboard.
///
/// Returns summary statistics, per-pool metrics, cost breakdowns by vendor,
/// and recent audit events for the tenant's license portfolio.
#[utoipa::path(
    get,
    path = "/governance/license-analytics/dashboard",
    tag = "Governance - License Management",
    responses(
        (status = 200, description = "License dashboard data", body = LicenseDashboardResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_dashboard(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<LicenseDashboardResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let dashboard = state
        .license_analytics_service
        .get_dashboard(tenant_id)
        .await?;

    Ok(Json(dashboard))
}

/// Get license optimization recommendations.
///
/// Analyzes the tenant's license portfolio and returns actionable
/// recommendations such as underutilized pools, high utilization warnings,
/// expiring licenses, and reclamation opportunities with potential savings.
#[utoipa::path(
    get,
    path = "/governance/license-analytics/recommendations",
    tag = "Governance - License Management",
    responses(
        (status = 200, description = "License recommendations", body = Vec<LicenseRecommendation>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_recommendations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<Vec<LicenseRecommendation>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let recommendations = state
        .license_analytics_service
        .get_recommendations(tenant_id)
        .await?;

    Ok(Json(recommendations))
}

/// Query parameters for expiring licenses endpoint.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct ExpiringLicensesParams {
    /// Number of days to look ahead (default: 90).
    #[serde(default = "default_within_days")]
    pub within_days: i64,
}

fn default_within_days() -> i64 {
    90
}

/// Get expiring license pools.
///
/// Returns pools that will expire within the specified number of days,
/// ordered by soonest expiration first.
#[utoipa::path(
    get,
    path = "/governance/license-analytics/expiring",
    tag = "Governance - License Management",
    params(ExpiringLicensesParams),
    responses(
        (status = 200, description = "Expiring license pools", body = ExpiringLicensesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_expiring_pools(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ExpiringLicensesParams>,
) -> ApiResult<Json<ExpiringLicensesResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .license_expiration_service
        .get_expiring_pools(tenant_id, params.within_days)
        .await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_within_days() {
        assert_eq!(default_within_days(), 90);
    }

    #[test]
    fn test_expiring_params_default() {
        let json = "{}";
        let params: ExpiringLicensesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.within_days, 90);
    }

    #[test]
    fn test_expiring_params_custom() {
        let json = r#"{"within_days": 30}"#;
        let params: ExpiringLicensesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.within_days, 30);
    }
}
