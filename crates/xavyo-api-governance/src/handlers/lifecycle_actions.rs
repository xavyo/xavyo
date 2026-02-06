//! Lifecycle action handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::LifecycleActionFilter;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    LifecycleActionListResponse, LifecycleActionResponse, ListLifecycleActionsQuery,
};
use crate::router::GovernanceState;

/// List lifecycle actions with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/lifecycle-actions",
    tag = "Governance - Lifecycle",
    params(ListLifecycleActionsQuery),
    responses(
        (status = 200, description = "List of lifecycle actions", body = LifecycleActionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_actions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListLifecycleActionsQuery>,
) -> ApiResult<Json<LifecycleActionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = LifecycleActionFilter {
        event_id: query.event_id,
        action_type: query.action_type,
        assignment_id: query.assignment_id,
        pending: query.pending,
    };

    let (actions, total) = state
        .lifecycle_event_service
        .list_actions(tenant_id, &filter, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(LifecycleActionListResponse {
        items: actions.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Cancel a scheduled revocation action.
#[utoipa::path(
    post,
    path = "/governance/lifecycle-actions/{id}/cancel",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Action ID")
    ),
    responses(
        (status = 200, description = "Action cancelled", body = LifecycleActionResponse),
        (status = 400, description = "Cannot cancel this action"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LifecycleActionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let action = state
        .lifecycle_event_service
        .cancel_scheduled_action(tenant_id, id)
        .await?;

    Ok(Json(action.into()))
}

/// Execute due scheduled revocations (admin trigger).
#[utoipa::path(
    post,
    path = "/governance/lifecycle-actions/execute-due",
    tag = "Governance - Lifecycle",
    responses(
        (status = 200, description = "Due actions executed", body = Vec<LifecycleActionResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_due_actions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<Vec<LifecycleActionResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let executed = state
        .lifecycle_event_service
        .execute_due_revocations(tenant_id)
        .await?;

    Ok(Json(executed.into_iter().map(Into::into).collect()))
}
