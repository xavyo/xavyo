//! A2A (Agent-to-Agent) Protocol HTTP handlers.
//!
//! Implements endpoints for asynchronous task management:
//! - POST /a2a/tasks - Create a new task
//! - GET /a2a/tasks - List tasks
//! - GET /a2a/tasks/{id} - Get task status
//! - POST /a2a/tasks/{id}/cancel - Cancel a task

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use tracing::debug;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::ApiAgentsError;
use crate::models::{
    A2aTaskListResponse, A2aTaskResponse, CancelA2aTaskResponse, CreateA2aTaskRequest,
    CreateA2aTaskResponse, ListA2aTasksQuery,
};
use crate::router::AgentsState;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenantId)
}

/// Extract agent_id from JWT claims.
/// For A2A endpoints, the agent_id should be in the subject claim.
fn extract_agent_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAgentsError::MissingAgentId)
}

/// POST /a2a/tasks - Create a new asynchronous task.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/a2a/tasks",
    tag = "A2A Tasks",
    operation_id = "createA2aTask",
    request_body = CreateA2aTaskRequest,
    responses(
        (status = 201, description = "Task created", body = CreateA2aTaskResponse),
        (status = 400, description = "Invalid request", body = A2aErrorResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Target agent not found", body = A2aErrorResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_task(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateA2aTaskRequest>,
) -> Result<(StatusCode, Json<CreateA2aTaskResponse>), ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        target_agent_id = %request.target_agent_id,
        task_type = %request.task_type,
        "Creating A2A task"
    );

    let response = state
        .a2a_service
        .create_task(tenant_id, agent_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /a2a/tasks - List tasks created by the authenticated agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/a2a/tasks",
    tag = "A2A Tasks",
    operation_id = "listA2aTasks",
    params(
        ("state" = Option<String>, Query, description = "Filter by task state"),
        ("target_agent_id" = Option<Uuid>, Query, description = "Filter by target agent"),
        ("limit" = Option<i32>, Query, description = "Maximum number of results"),
        ("offset" = Option<i32>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of tasks", body = A2aTaskListResponse),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_tasks(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListA2aTasksQuery>,
) -> Result<Json<A2aTaskListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        state_filter = ?query.state,
        "Listing A2A tasks"
    );

    let response = state
        .a2a_service
        .list_tasks(tenant_id, agent_id, query)
        .await?;

    Ok(Json(response))
}

/// GET /a2a/tasks/{id} - Get task status.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/a2a/tasks/{id}",
    tag = "A2A Tasks",
    operation_id = "getA2aTask",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task details", body = A2aTaskResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Task not found", body = A2aErrorResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_task(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<A2aTaskResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        task_id = %task_id,
        "Getting A2A task status"
    );

    let response = state.a2a_service.get_task(tenant_id, task_id).await?;

    Ok(Json(response))
}

/// POST /a2a/tasks/{id}/cancel - Cancel a task.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/a2a/tasks/{id}/cancel",
    tag = "A2A Tasks",
    operation_id = "cancelA2aTask",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task cancelled", body = CancelA2aTaskResponse),
        (status = 400, description = "Task cannot be cancelled", body = A2aErrorResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Task not found", body = A2aErrorResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn cancel_task(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<CancelA2aTaskResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        task_id = %task_id,
        "Cancelling A2A task"
    );

    let response = state.a2a_service.cancel_task(tenant_id, task_id).await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_a2a_handler_modules_compile() {
        // Verify the handlers compile correctly
    }
}
