//! A2A (Agent-to-Agent) Protocol HTTP handlers.
//!
//! Implements endpoints for asynchronous task management:
//! - POST /a2a/tasks - Create a new task
//! - GET /a2a/tasks - List tasks
//! - GET /a2a/tasks/{id} - Get task status
//! - POST /a2a/tasks/{id}/cancel - Cancel a task
//!
//! Migrated from xavyo-api-agents (Feature 205).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use tracing::debug;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::NhiApiError;
use crate::models::{
    A2aTaskListResponse, A2aTaskResponse, CancelA2aTaskResponse, CreateA2aTaskRequest,
    CreateA2aTaskResponse, ListA2aTasksQuery,
};
use crate::services::a2a_service;
use crate::state::NhiState;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, NhiApiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| NhiApiError::BadRequest("Missing tenant ID in claims".to_string()))
}

/// Extract `agent_id` from JWT claims (subject claim).
fn extract_agent_id(claims: &JwtClaims) -> Result<Uuid, NhiApiError> {
    Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid agent ID in JWT subject".to_string()))
}

/// POST /a2a/tasks - Create a new asynchronous task.
///
/// If the caller is an admin/super_admin user (not an NHI agent), they can
/// specify `source_agent_id` in the request body to create tasks on behalf
/// of an agent. If the JWT subject is an NHI identity, it is used as the source.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/a2a/tasks",
    request_body = CreateA2aTaskRequest,
    responses(
        (status = 201, description = "Task created", body = CreateA2aTaskResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Forbidden"),
    ),
    tag = "A2A Tasks"
))]
pub async fn create_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateA2aTaskRequest>,
) -> Result<(StatusCode, Json<CreateA2aTaskResponse>), NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let caller_id = extract_agent_id(&claims)?;

    // Determine the source NHI: either from the request body (admin acting on behalf)
    // or from the JWT subject (direct agent-to-agent call)
    let source_nhi_id = if let Some(explicit_source) = request.source_agent_id {
        // Admin users can specify a source agent
        if !claims.has_role("admin") && !claims.has_role("super_admin") {
            return Err(NhiApiError::Forbidden);
        }
        explicit_source
    } else {
        caller_id
    };

    debug!(
        tenant_id = %tenant_id,
        source_nhi_id = %source_nhi_id,
        target_agent_id = %request.target_agent_id,
        task_type = %request.task_type,
        "Creating A2A task"
    );

    let response = a2a_service::create_task(&state.pool, tenant_id, source_nhi_id, request).await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /a2a/tasks - List tasks created by the authenticated agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/a2a/tasks",
    responses(
        (status = 200, description = "List of A2A tasks", body = A2aTaskListResponse),
        (status = 400, description = "Invalid request"),
    ),
    tag = "A2A Tasks"
))]
pub async fn list_tasks(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListA2aTasksQuery>,
) -> Result<Json<A2aTaskListResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;
    let is_admin = claims.has_role("admin") || claims.has_role("super_admin");

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        is_admin = is_admin,
        state_filter = ?query.state,
        "Listing A2A tasks"
    );

    let response =
        a2a_service::list_tasks(&state.pool, tenant_id, agent_id, is_admin, query).await?;

    Ok(Json(response))
}

/// GET /a2a/tasks/{id} - Get task status.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/a2a/tasks/{id}",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 200, description = "Task details", body = A2aTaskResponse),
        (status = 404, description = "Task not found"),
    ),
    tag = "A2A Tasks"
))]
pub async fn get_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<A2aTaskResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;
    let is_admin = claims.has_role("admin") || claims.has_role("super_admin");

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        task_id = %task_id,
        "Getting A2A task status"
    );

    let response =
        a2a_service::get_task(&state.pool, tenant_id, agent_id, is_admin, task_id).await?;

    Ok(Json(response))
}

/// POST /a2a/tasks/{id}/cancel - Cancel a task.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/a2a/tasks/{id}/cancel",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 200, description = "Task cancelled", body = CancelA2aTaskResponse),
        (status = 404, description = "Task not found"),
        (status = 409, description = "Task cannot be cancelled"),
    ),
    tag = "A2A Tasks"
))]
pub async fn cancel_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<CancelA2aTaskResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;
    let is_admin = claims.has_role("admin") || claims.has_role("super_admin");

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        task_id = %task_id,
        "Cancelling A2A task"
    );

    let response =
        a2a_service::cancel_task(&state.pool, tenant_id, agent_id, is_admin, task_id).await?;

    Ok(Json(response))
}
