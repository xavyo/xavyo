//! Reconciliation run handlers for orphan account detection.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ListReconciliationRunsQuery, ReconciliationRunListResponse, ReconciliationRunResponse,
    ReconciliationScheduleResponse, TriggerReconciliationRequest, UpsertScheduleRequest,
};
use crate::router::GovernanceState;

/// Trigger a new reconciliation run for orphan account detection.
#[utoipa::path(
    post,
    path = "/governance/reconciliation-runs",
    tag = "Governance - Orphan Detection",
    request_body = TriggerReconciliationRequest,
    responses(
        (status = 201, description = "Reconciliation run started", body = ReconciliationRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Reconciliation already running"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_reconciliation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(_request): Json<TriggerReconciliationRequest>,
) -> ApiResult<(StatusCode, Json<ReconciliationRunResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let run = state
        .reconciliation_service
        .trigger_reconciliation(tenant_id, Some(user_id))
        .await?;

    Ok((StatusCode::CREATED, Json(run)))
}

/// Get a reconciliation run by ID.
#[utoipa::path(
    get,
    path = "/governance/reconciliation-runs/{id}",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 200, description = "Reconciliation run details", body = ReconciliationRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_reconciliation_run(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReconciliationRunResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let run = state.reconciliation_service.get_run(tenant_id, id).await?;

    Ok(Json(run))
}

/// List reconciliation runs with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/reconciliation-runs",
    tag = "Governance - Orphan Detection",
    params(ListReconciliationRunsQuery),
    responses(
        (status = 200, description = "List of reconciliation runs", body = ReconciliationRunListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_reconciliation_runs(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListReconciliationRunsQuery>,
) -> ApiResult<Json<ReconciliationRunListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .reconciliation_service
        .list_runs(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Cancel a running reconciliation.
#[utoipa::path(
    post,
    path = "/governance/reconciliation-runs/{id}/cancel",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 200, description = "Reconciliation cancelled", body = ReconciliationRunResponse),
        (status = 400, description = "Run not in running state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_reconciliation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReconciliationRunResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let run = state
        .reconciliation_service
        .cancel_run(tenant_id, id)
        .await?;

    Ok(Json(run))
}

// =============================================================================
// Schedule Handlers
// =============================================================================

/// Get the current reconciliation schedule.
#[utoipa::path(
    get,
    path = "/governance/reconciliation-schedule",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "Current schedule", body = Option<ReconciliationScheduleResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<Option<ReconciliationScheduleResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state.reconciliation_service.get_schedule(tenant_id).await?;

    Ok(Json(schedule))
}

/// Create or update the reconciliation schedule.
#[utoipa::path(
    put,
    path = "/governance/reconciliation-schedule",
    tag = "Governance - Orphan Detection",
    request_body = UpsertScheduleRequest,
    responses(
        (status = 200, description = "Schedule updated", body = ReconciliationScheduleResponse),
        (status = 400, description = "Invalid schedule parameters"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn upsert_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<UpsertScheduleRequest>,
) -> ApiResult<Json<ReconciliationScheduleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state
        .reconciliation_service
        .upsert_schedule(tenant_id, request)
        .await?;

    Ok(Json(schedule))
}

/// Delete the reconciliation schedule.
#[utoipa::path(
    delete,
    path = "/governance/reconciliation-schedule",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 204, description = "Schedule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .reconciliation_service
        .delete_schedule(tenant_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Trigger scheduled reconciliation runs (for external scheduler).
///
/// This endpoint is typically called by a cron job or scheduler service.
#[utoipa::path(
    post,
    path = "/governance/reconciliation-schedule/trigger",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "Number of runs triggered", body = Vec<(Uuid, Uuid)>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_scheduled_runs(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<Vec<(Uuid, Uuid)>>> {
    // Verify user is authorized (could add admin check here)
    let _ = claims.tenant_id().ok_or(ApiGovernanceError::Unauthorized)?;

    let triggered = state
        .reconciliation_service
        .trigger_scheduled_runs()
        .await?;

    Ok(Json(triggered))
}
