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
pub async fn create_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateA2aTaskRequest>,
) -> Result<(StatusCode, Json<CreateA2aTaskResponse>), NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        target_agent_id = %request.target_agent_id,
        task_type = %request.task_type,
        "Creating A2A task"
    );

    let response = a2a_service::create_task(&state.pool, tenant_id, agent_id, request).await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /a2a/tasks - List tasks created by the authenticated agent.
pub async fn list_tasks(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListA2aTasksQuery>,
) -> Result<Json<A2aTaskListResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        state_filter = ?query.state,
        "Listing A2A tasks"
    );

    let response = a2a_service::list_tasks(&state.pool, tenant_id, agent_id, query).await?;

    Ok(Json(response))
}

/// GET /a2a/tasks/{id} - Get task status.
pub async fn get_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<A2aTaskResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        task_id = %task_id,
        "Getting A2A task status"
    );

    let response = a2a_service::get_task(&state.pool, tenant_id, agent_id, task_id).await?;

    Ok(Json(response))
}

/// POST /a2a/tasks/{id}/cancel - Cancel a task.
pub async fn cancel_task(
    State(state): State<NhiState>,
    Extension(claims): Extension<JwtClaims>,
    Path(task_id): Path<Uuid>,
) -> Result<Json<CancelA2aTaskResponse>, NhiApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent_id = extract_agent_id(&claims)?;

    debug!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        task_id = %task_id,
        "Cancelling A2A task"
    );

    let response = a2a_service::cancel_task(&state.pool, tenant_id, agent_id, task_id).await?;

    Ok(Json(response))
}
