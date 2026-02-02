//! Correlation Statistics Handlers
//!
//! REST API handlers for correlation statistics and trends.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{
        CorrelationStatisticsResponse, CorrelationTrendsResponse, ListCorrelationStatsQuery,
        ListCorrelationTrendsQuery,
    },
    router::GovernanceState,
};

/// Get correlation statistics
///
/// Returns correlation statistics for a connector, including match rates,
/// confidence distributions, and performance metrics.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/statistics",
    tag = "Governance - Correlation Statistics",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListCorrelationStatsQuery,
    ),
    responses(
        (status = 200, description = "Correlation statistics retrieved", body = CorrelationStatisticsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_statistics(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListCorrelationStatsQuery>,
) -> ApiResult<Json<CorrelationStatisticsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let statistics = state
        .correlation_stats_service
        .get_statistics(tenant_id, connector_id, &query)
        .await?;

    Ok(Json(statistics))
}

/// Get correlation trends
///
/// Returns time-series correlation trend data for a connector, showing how
/// correlation metrics change over time.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/statistics/trends",
    tag = "Governance - Correlation Statistics",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListCorrelationTrendsQuery,
    ),
    responses(
        (status = 200, description = "Correlation trends retrieved", body = CorrelationTrendsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_trends(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListCorrelationTrendsQuery>,
) -> ApiResult<Json<CorrelationTrendsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let trends = state
        .correlation_stats_service
        .get_trends(tenant_id, connector_id, &query)
        .await?;

    Ok(Json(trends))
}
