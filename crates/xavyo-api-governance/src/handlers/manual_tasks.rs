//! HTTP handlers for manual provisioning tasks (F064).
//!
//! Provides endpoints for IT operators to manage their provisioning workload.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

#[allow(unused_imports)]
use crate::models::{ManualProvisioningTaskListResponse, ManualProvisioningTaskResponse};
use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::{
        ConfirmManualTaskRequest, ListManualTasksQuery, ManualTaskDashboardResponse,
        ManualTaskListResponse, ManualTaskResponse, RejectManualTaskRequest,
    },
    router::GovernanceState,
};

/// Helper to extract user ID from claims.
fn user_id_from_claims(claims: &JwtClaims) -> Result<Uuid, ApiGovernanceError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)
}

/// List manual provisioning tasks.
#[utoipa::path(
    get,
    path = "/governance/manual-tasks",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("status" = Option<Vec<String>>, Query, description = "Filter by status"),
        ("application_id" = Option<Uuid>, Query, description = "Filter by application"),
        ("user_id" = Option<Uuid>, Query, description = "Filter by target user"),
        ("sla_breached" = Option<bool>, Query, description = "Filter by SLA breach status"),
        ("assignee_id" = Option<Uuid>, Query, description = "Filter by assignee"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "Manual tasks retrieved", body = ManualProvisioningTaskListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_manual_tasks(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListManualTasksQuery>,
) -> ApiResult<Json<ManualTaskListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .manual_task_service
        .list_tasks(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get a manual provisioning task by ID.
#[utoipa::path(
    get,
    path = "/governance/manual-tasks/{id}",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Manual task retrieved", body = ManualProvisioningTaskResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.manual_task_service.get_task(tenant_id, id).await?;

    Ok(Json(result))
}

/// Confirm a manual provisioning task as completed.
#[utoipa::path(
    post,
    path = "/governance/manual-tasks/{id}/confirm",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    request_body = ConfirmManualTaskRequest,
    responses(
        (status = 200, description = "Task confirmed", body = ManualProvisioningTaskResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn confirm_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ConfirmManualTaskRequest>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let confirmed_by = user_id_from_claims(&claims)?;

    let result = state
        .manual_task_service
        .confirm_task(tenant_id, id, confirmed_by, request.notes.as_deref())
        .await?;

    Ok(Json(result))
}

/// Reject a manual provisioning task.
#[utoipa::path(
    post,
    path = "/governance/manual-tasks/{id}/reject",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    request_body = RejectManualTaskRequest,
    responses(
        (status = 200, description = "Task rejected", body = ManualProvisioningTaskResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RejectManualTaskRequest>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rejected_by = user_id_from_claims(&claims)?;

    let result = state
        .manual_task_service
        .reject_task(tenant_id, id, rejected_by, &request.reason)
        .await?;

    Ok(Json(result))
}

/// Cancel a manual provisioning task.
#[utoipa::path(
    post,
    path = "/governance/manual-tasks/{id}/cancel",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task cancelled", body = ManualProvisioningTaskResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let cancelled_by = user_id_from_claims(&claims)?;

    let result = state
        .manual_task_service
        .cancel_task(tenant_id, id, cancelled_by, None)
        .await?;

    Ok(Json(result))
}

/// Get dashboard metrics for manual tasks.
#[utoipa::path(
    get,
    path = "/governance/manual-tasks/dashboard",
    tag = "Governance - Manual Provisioning Tasks",
    responses(
        (status = 200, description = "Dashboard metrics retrieved", body = ManualTaskDashboardResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_manual_task_dashboard(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<ManualTaskDashboardResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .manual_task_service
        .get_dashboard_metrics(tenant_id)
        .await?;

    Ok(Json(result))
}

/// Claim a manual task (assign to current user).
#[utoipa::path(
    post,
    path = "/governance/manual-tasks/{id}/claim",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task claimed", body = ManualProvisioningTaskResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 409, description = "Task already claimed"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn claim_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let assignee_id = user_id_from_claims(&claims)?;

    let result = state
        .manual_task_service
        .claim_task(tenant_id, id, assignee_id)
        .await?;

    Ok(Json(result))
}

/// Start working on a manual task (set to `in_progress`).
#[utoipa::path(
    post,
    path = "/governance/manual-tasks/{id}/start",
    tag = "Governance - Manual Provisioning Tasks",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task started", body = ManualProvisioningTaskResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn start_manual_task(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ManualTaskResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.manual_task_service.start_task(tenant_id, id).await?;

    Ok(Json(result))
}
