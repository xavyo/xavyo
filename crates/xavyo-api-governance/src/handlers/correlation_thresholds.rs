//! HTTP handlers for correlation threshold management (F067).

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{CorrelationThresholdResponse, UpsertCorrelationThresholdRequest},
    router::GovernanceState,
};

/// Get correlation thresholds for a connector.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/thresholds",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Correlation thresholds retrieved", body = CorrelationThresholdResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_thresholds(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> ApiResult<Json<CorrelationThresholdResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_threshold_service
        .get(tenant_id, connector_id)
        .await?;

    Ok(Json(result))
}

/// Upsert correlation thresholds for a connector.
#[utoipa::path(
    put,
    path = "/governance/connectors/{connector_id}/correlation/thresholds",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = UpsertCorrelationThresholdRequest,
    responses(
        (status = 200, description = "Correlation thresholds upserted", body = CorrelationThresholdResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn upsert_correlation_thresholds(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<UpsertCorrelationThresholdRequest>,
) -> ApiResult<Json<CorrelationThresholdResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_threshold_service
        .upsert(tenant_id, connector_id, request)
        .await?;

    Ok(Json(result))
}
