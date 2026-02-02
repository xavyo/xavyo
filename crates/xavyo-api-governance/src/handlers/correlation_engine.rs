//! HTTP handlers for correlation engine execution and job tracking (F067).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::GovCorrelationTrigger;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{CorrelationJobStatusResponse, TriggerCorrelationRequest},
    router::GovernanceState,
    services::CorrelationEngineService,
};

/// Trigger correlation evaluation for a connector's uncorrelated accounts.
///
/// Accepts an optional list of account IDs to evaluate. If omitted, all
/// uncorrelated accounts for the connector are evaluated. Returns a 202
/// Accepted response with a job identifier for tracking progress.
#[utoipa::path(
    post,
    path = "/governance/connectors/{connector_id}/correlation/evaluate",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = TriggerCorrelationRequest,
    responses(
        (status = 202, description = "Correlation job accepted", body = CorrelationJobStatusResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_correlation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<TriggerCorrelationRequest>,
) -> ApiResult<(StatusCode, Json<CorrelationJobStatusResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Default trigger to Manual since TriggerCorrelationRequest does not
    // currently carry a trigger_type field.
    let trigger = GovCorrelationTrigger::Manual;

    let job_id = state
        .correlation_engine_service
        .trigger_batch_evaluation(tenant_id, connector_id, request.account_ids, trigger)
        .await?;

    let job_status = state
        .correlation_engine_service
        .get_job_status(tenant_id, job_id)
        .await?;

    let response = CorrelationEngineService::job_status_to_response(&job_status);

    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Get the status of a correlation job.
///
/// Returns current progress including counts of auto-confirmed, review-queued,
/// no-match, and errored accounts.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/jobs/{job_id}",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("job_id" = Uuid, Path, description = "Correlation job ID")
    ),
    responses(
        (status = 200, description = "Correlation job status retrieved", body = CorrelationJobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_job_status(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_connector_id, job_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<CorrelationJobStatusResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let job_status = state
        .correlation_engine_service
        .get_job_status(tenant_id, job_id)
        .await?;

    let response = CorrelationEngineService::job_status_to_response(&job_status);

    Ok(Json(response))
}
