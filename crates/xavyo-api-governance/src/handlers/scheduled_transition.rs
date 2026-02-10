//! HTTP handlers for scheduled state transitions (F052).
//!
//! These handlers provide endpoints for scheduling future state transitions,
//! listing scheduled transitions, and cancelling pending schedules.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use crate::{
    error::ApiResult,
    models::{
        ListScheduledTransitionsQuery, ScheduledTransitionListResponse, ScheduledTransitionResponse,
    },
    router::GovernanceState,
};
use xavyo_auth::JwtClaims;

/// Default batch size for processing due transitions.
const DEFAULT_BATCH_SIZE: i64 = 100;

/// List scheduled transitions.
///
/// Returns a paginated list of scheduled transitions with optional filters.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/scheduled",
    params(ListScheduledTransitionsQuery),
    responses(
        (status = 200, description = "List of scheduled transitions"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Scheduled Transitions"
)]
pub async fn list_scheduled_transitions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListScheduledTransitionsQuery>,
) -> ApiResult<Json<ScheduledTransitionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let scheduled = state
        .scheduled_transition_service
        .list_scheduled_transitions(tenant_id, &params)
        .await?;
    Ok(Json(scheduled))
}

/// Get a scheduled transition by ID.
///
/// Returns detailed information about a scheduled transition.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/scheduled/{schedule_id}",
    params(
        ("schedule_id" = Uuid, Path, description = "Scheduled transition ID")
    ),
    responses(
        (status = 200, description = "Scheduled transition details", body = ScheduledTransitionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scheduled transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Scheduled Transitions"
)]
pub async fn get_scheduled_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(schedule_id): Path<Uuid>,
) -> ApiResult<Json<ScheduledTransitionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let scheduled = state
        .scheduled_transition_service
        .get_scheduled_transition(tenant_id, schedule_id)
        .await?;
    Ok(Json(scheduled))
}

/// Cancel a scheduled transition.
///
/// Cancels a pending scheduled transition. Only pending transitions can be cancelled.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/scheduled/{schedule_id}/cancel",
    params(
        ("schedule_id" = Uuid, Path, description = "Scheduled transition ID")
    ),
    responses(
        (status = 200, description = "Scheduled transition cancelled", body = ScheduledTransitionResponse),
        (status = 400, description = "Transition cannot be cancelled (already executed or cancelled)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scheduled transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Scheduled Transitions"
)]
pub async fn cancel_scheduled_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(schedule_id): Path<Uuid>,
) -> ApiResult<Json<ScheduledTransitionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| crate::error::ApiGovernanceError::Unauthorized)?;
    let scheduled = state
        .scheduled_transition_service
        .cancel_scheduled_transition(tenant_id, schedule_id, user_id)
        .await?;
    Ok(Json(scheduled))
}

/// Trigger processing of due scheduled transitions.
///
/// This endpoint is typically called by a background job scheduler.
/// Processes all scheduled transitions that are due for execution.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/scheduled/trigger-due",
    responses(
        (status = 200, description = "Due transitions processed"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Scheduled Transitions"
)]
pub async fn trigger_due_transitions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<StatusCode> {
    // Just verify the caller is authenticated
    let _tenant_id = claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?;

    // Process due transitions across all tenants with default batch size
    state
        .scheduled_transition_service
        .process_due_transitions(DEFAULT_BATCH_SIZE)
        .await?;
    Ok(StatusCode::OK)
}
