//! Agent management handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    requests::CanOperateRequest, responses::CanOperateResponse, AgentListResponse, AgentResponse,
    CreateAgentRequest, ListAgentsQuery, UpdateAgentRequest,
};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract `user_id` from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims.sub.parse().map_err(|_| ApiAgentsError::MissingUser)
}

/// POST /agents - Create a new agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents",
    tag = "AI Agents",
    operation_id = "createAgent",
    request_body = CreateAgentRequest,
    responses(
        (status = 201, description = "Agent created", body = AgentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Agent name already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    let agent = state
        .agent_service
        .create(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(agent)))
}

/// GET /agents - List agents.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents",
    tag = "AI Agents",
    operation_id = "listAgents",
    params(ListAgentsQuery),
    responses(
        (status = 200, description = "List of agents", body = AgentListResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_agents(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAgentsQuery>,
) -> Result<Json<AgentListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state.agent_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// GET /agents/{id} - Get agent by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{id}",
    tag = "AI Agents",
    operation_id = "getAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent details", body = AgentResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let agent = state.agent_service.get(tenant_id, id).await?;

    Ok(Json(agent))
}

/// PATCH /agents/{id} - Update agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/agents/{id}",
    tag = "AI Agents",
    operation_id = "updateAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = UpdateAgentRequest,
    responses(
        (status = 200, description = "Agent updated", body = AgentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let agent = state.agent_service.update(tenant_id, id, request).await?;

    Ok(Json(agent))
}

/// DELETE /agents/{id} - Delete agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/agents/{id}",
    tag = "AI Agents",
    operation_id = "deleteAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 204, description = "Agent deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state.agent_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /agents/{id}/suspend - Suspend agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{id}/suspend",
    tag = "AI Agents",
    operation_id = "suspendAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent suspended", body = AgentResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found"),
        (status = 409, description = "Agent already suspended")
    ),
    security(("bearerAuth" = []))
))]
pub async fn suspend_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let agent = state.agent_service.suspend(tenant_id, id).await?;

    Ok(Json(agent))
}

/// POST /agents/{id}/reactivate - Reactivate suspended agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{id}/reactivate",
    tag = "AI Agents",
    operation_id = "reactivateAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent reactivated", body = AgentResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found"),
        (status = 409, description = "Agent not suspended")
    ),
    security(("bearerAuth" = []))
))]
pub async fn reactivate_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let agent = state.agent_service.reactivate(tenant_id, id).await?;

    Ok(Json(agent))
}

/// POST /agents/{id}/can-operate - Check if a user can operate an agent.
///
/// Part of the three-layer authorization model (F123):
/// 1. User can operate agent (this endpoint)
/// 2. Agent is active and valid
/// 3. Agent has permission for specific tool
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{id}/can-operate",
    tag = "AI Agents",
    operation_id = "canOperateAgent",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = CanOperateRequest,
    responses(
        (status = 200, description = "Operation check result", body = CanOperateResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn can_operate_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<CanOperateRequest>,
) -> Result<Json<CanOperateResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .agent_service
        .can_operate(tenant_id, agent_id, request.user_id)
        .await?;

    Ok(Json(response))
}
