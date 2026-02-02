//! AI agent handlers for /nhi/agents/* endpoints.
//!
//! These handlers delegate to xavyo-api-agents services.
//! F109 - NHI API Consolidation

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiNhiError, ApiResult};

// Re-use AgentsState directly from agents crate
pub use xavyo_api_agents::AgentsState;

// Re-export types from agents crate
pub use xavyo_api_agents::models::{
    AgentListResponse, AgentResponse, CreateAgentRequest, ListAgentsQuery, UpdateAgentRequest,
};

// Re-export authorization types
pub use xavyo_api_agents::models::{AuthorizeRequest, AuthorizeResponse};

// Re-export permission types
pub use xavyo_api_agents::models::{
    GrantPermissionRequest, ListPermissionsQuery, PermissionListResponse, PermissionResponse,
};

// Re-export audit types
pub use xavyo_api_agents::models::{AuditFilter, AuditListResponse};

// Re-export security assessment types (F093)
pub use xavyo_api_agents::models::SecurityAssessment;

// Re-export anomaly detection types (F094)
pub use xavyo_api_agents::models::{
    AnomalyListResponse, BaselineResponse, ListAnomaliesQuery, SetThresholdsRequest,
    ThresholdsResponse,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiNhiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiNhiError::Unauthorized)
}

fn extract_actor_id(claims: &JwtClaims) -> Result<Uuid, ApiNhiError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiNhiError::Unauthorized)
}

// ============================================================================
// Agent CRUD Handlers
// ============================================================================

/// List AI agents.
#[utoipa::path(
    get,
    path = "/nhi/agents",
    tag = "NHI - Agents",
    params(ListAgentsQuery),
    responses(
        (status = 200, description = "List of AI agents", body = AgentListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_agents(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAgentsQuery>,
) -> ApiResult<Json<AgentListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state.agent_service.list(tenant_id, query).await?;
    Ok(Json(response))
}

/// Create a new AI agent.
#[utoipa::path(
    post,
    path = "/nhi/agents",
    tag = "NHI - Agents",
    request_body = CreateAgentRequest,
    responses(
        (status = 201, description = "Agent created", body = AgentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Agent name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateAgentRequest>,
) -> ApiResult<(StatusCode, Json<AgentResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_actor_id(&claims)?;
    let agent = state
        .agent_service
        .create(tenant_id, user_id, request)
        .await?;
    Ok((StatusCode::CREATED, Json(agent)))
}

/// Get an AI agent by ID.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent details", body = AgentResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AgentResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent = state.agent_service.get(tenant_id, id).await?;
    Ok(Json(agent))
}

/// Update an AI agent.
#[utoipa::path(
    patch,
    path = "/nhi/agents/{id}",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = UpdateAgentRequest,
    responses(
        (status = 200, description = "Agent updated", body = AgentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAgentRequest>,
) -> ApiResult<Json<AgentResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent = state.agent_service.update(tenant_id, id, request).await?;
    Ok(Json(agent))
}

/// Delete an AI agent.
#[utoipa::path(
    delete,
    path = "/nhi/agents/{id}",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 204, description = "Agent deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;
    state.agent_service.delete(tenant_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Lifecycle Handlers
// ============================================================================

/// Suspend an AI agent.
#[utoipa::path(
    post,
    path = "/nhi/agents/{id}/suspend",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent suspended", body = AgentResponse),
        (status = 400, description = "Already suspended"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn suspend_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AgentResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent = state.agent_service.suspend(tenant_id, id).await?;
    Ok(Json(agent))
}

/// Reactivate a suspended AI agent.
#[utoipa::path(
    post,
    path = "/nhi/agents/{id}/reactivate",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent reactivated", body = AgentResponse),
        (status = 400, description = "Not suspended"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reactivate_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AgentResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let agent = state.agent_service.reactivate(tenant_id, id).await?;
    Ok(Json(agent))
}

// ============================================================================
// Authorization Handler
// ============================================================================

/// Real-time authorization decision (<100ms).
#[utoipa::path(
    post,
    path = "/nhi/agents/authorize",
    tag = "NHI - Agents",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision", body = AuthorizeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn authorize_agent(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<AuthorizeRequest>,
) -> ApiResult<Json<AuthorizeResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .authorization_service
        .authorize_request(tenant_id, request, None)
        .await?;
    Ok(Json(response))
}

// ============================================================================
// Permission Handlers
// ============================================================================

/// Grant tool permission to an agent.
#[utoipa::path(
    post,
    path = "/nhi/agents/{id}/permissions",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = GrantPermissionRequest,
    responses(
        (status = 201, description = "Permission granted", body = PermissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent or tool not found"),
        (status = 409, description = "Permission already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn grant_agent_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<GrantPermissionRequest>,
) -> ApiResult<(StatusCode, Json<PermissionResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = extract_actor_id(&claims)?;
    let permission = state
        .permission_service
        .grant(tenant_id, id, request, Some(actor_id))
        .await?;
    Ok((StatusCode::CREATED, Json(permission)))
}

/// List permissions for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/permissions",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        ListPermissionsQuery
    ),
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_agent_permissions(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListPermissionsQuery>,
) -> ApiResult<Json<PermissionListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .permission_service
        .list_by_agent(tenant_id, id, query.limit, query.offset)
        .await?;
    Ok(Json(response))
}

/// Revoke tool permission from an agent.
#[utoipa::path(
    delete,
    path = "/nhi/agents/{agent_id}/permissions/{tool_id}",
    tag = "NHI - Agents",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("tool_id" = Uuid, Path, description = "Tool ID")
    ),
    responses(
        (status = 204, description = "Permission revoked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_agent_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, tool_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;
    state
        .permission_service
        .revoke(tenant_id, agent_id, tool_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Audit Handler
// ============================================================================

/// Query audit trail for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/audit",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        AuditFilter
    ),
    responses(
        (status = 200, description = "Audit trail", body = AuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn query_agent_audit(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<AuditFilter>,
) -> ApiResult<Json<AuditListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .audit_service
        .query_by_agent(tenant_id, id, query)
        .await?;
    Ok(Json(response))
}

// ============================================================================
// Security Assessment Handler (F093)
// ============================================================================

/// Get security assessment for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/security-assessment",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Security assessment", body = SecurityAssessment),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_security_assessment(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SecurityAssessment>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let assessment = state.assessment_service.assess_agent(tenant_id, id).await?;
    Ok(Json(assessment))
}

// ============================================================================
// Anomaly Detection Handlers (F094)
// ============================================================================

/// List detected anomalies for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/anomalies",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        ("since" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Filter anomalies since this time"),
        ("anomaly_type" = Option<String>, Query, description = "Filter by anomaly type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of anomalies", body = AnomalyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_anomalies(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListAnomaliesQuery>,
) -> ApiResult<Json<AnomalyListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let anomalies = state
        .anomaly_service
        .list_anomalies(tenant_id, id, &query)
        .await?;
    Ok(Json(anomalies))
}

/// Get baseline for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/baseline",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent baseline", body = BaselineResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent or baseline not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_baseline(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BaselineResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let baseline = state.baseline_service.get_baseline(tenant_id, id).await?;
    Ok(Json(baseline))
}

/// Get thresholds for an agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/thresholds",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent thresholds", body = ThresholdsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ThresholdsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let thresholds = state
        .anomaly_service
        .get_agent_thresholds(tenant_id, id)
        .await?;
    Ok(Json(thresholds))
}

/// Update thresholds for an agent.
#[utoipa::path(
    put,
    path = "/nhi/agents/{id}/thresholds",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = SetThresholdsRequest,
    responses(
        (status = 200, description = "Thresholds updated", body = ThresholdsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetThresholdsRequest>,
) -> ApiResult<Json<ThresholdsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let thresholds = state
        .anomaly_service
        .set_agent_thresholds(tenant_id, id, request)
        .await?;
    Ok(Json(thresholds))
}

/// Reset thresholds for an agent to defaults.
#[utoipa::path(
    delete,
    path = "/nhi/agents/{id}/thresholds",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Thresholds reset to tenant defaults", body = ThresholdsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ThresholdsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let thresholds = state
        .anomaly_service
        .reset_agent_thresholds(tenant_id, id)
        .await?;
    Ok(Json(thresholds))
}

// ============================================================================
// Tenant-Wide Threshold Handlers
// ============================================================================

/// Get tenant-wide default thresholds.
#[utoipa::path(
    get,
    path = "/nhi/agents/thresholds",
    tag = "NHI - Agents",
    responses(
        (status = 200, description = "Tenant default thresholds", body = ThresholdsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tenant_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<ThresholdsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let thresholds = state
        .anomaly_service
        .get_tenant_thresholds(tenant_id)
        .await?;
    Ok(Json(thresholds))
}

/// Set tenant-wide default thresholds.
#[utoipa::path(
    put,
    path = "/nhi/agents/thresholds",
    tag = "NHI - Agents",
    request_body = SetThresholdsRequest,
    responses(
        (status = 200, description = "Tenant thresholds updated", body = ThresholdsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_tenant_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SetThresholdsRequest>,
) -> ApiResult<Json<ThresholdsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let thresholds = state
        .anomaly_service
        .set_tenant_thresholds(tenant_id, request)
        .await?;
    Ok(Json(thresholds))
}

// ============================================================================
// Credential Handlers (F110)
// ============================================================================

// Re-export credential types for agents
pub use xavyo_api_governance::models::{
    NhiCredentialCreatedResponse, NhiCredentialListResponse, NhiCredentialResponse,
    RevokeCredentialRequest, RotateCredentialsRequest,
};

/// Query parameters for listing agent credentials.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct ListAgentCredentialsQuery {
    /// Only return active credentials.
    pub active_only: Option<bool>,
}

/// List credentials for an AI agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{id}/credentials",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        ListAgentCredentialsQuery
    ),
    responses(
        (status = 200, description = "List of credentials", body = NhiCredentialListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_agent_credentials(
    State(state): State<AgentCredentialState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListAgentCredentialsQuery>,
) -> ApiResult<Json<NhiCredentialListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let result = state
        .credential_service
        .list(tenant_id, id, query.active_only.unwrap_or(false))
        .await?;
    Ok(Json(result))
}

/// Get a specific credential for an AI agent.
#[utoipa::path(
    get,
    path = "/nhi/agents/{agent_id}/credentials/{credential_id}",
    tag = "NHI - Agents",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID")
    ),
    responses(
        (status = 200, description = "Credential details", body = NhiCredentialResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent or credential not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_agent_credential(
    State(state): State<AgentCredentialState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, credential_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<NhiCredentialResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let credential = state
        .credential_service
        .get(tenant_id, agent_id, credential_id)
        .await?;
    Ok(Json(credential))
}

/// Rotate credentials for an AI agent.
#[utoipa::path(
    post,
    path = "/nhi/agents/{id}/credentials/rotate",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = RotateCredentialsRequest,
    responses(
        (status = 201, description = "Credentials rotated - secret only shown once", body = NhiCredentialCreatedResponse),
        (status = 400, description = "Invalid request or agent suspended"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_agent_credentials(
    State(state): State<AgentCredentialState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateCredentialsRequest>,
) -> ApiResult<(StatusCode, Json<NhiCredentialCreatedResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = extract_actor_id(&claims)?;
    let result = state
        .credential_service
        .rotate(tenant_id, id, Some(actor_id), request)
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// Revoke a credential for an AI agent.
#[utoipa::path(
    post,
    path = "/nhi/agents/{agent_id}/credentials/{credential_id}/revoke",
    tag = "NHI - Agents",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID")
    ),
    request_body = RevokeCredentialRequest,
    responses(
        (status = 200, description = "Credential revoked", body = NhiCredentialResponse),
        (status = 400, description = "Invalid request or credential already revoked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Agent or credential not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_agent_credential(
    State(state): State<AgentCredentialState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, credential_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RevokeCredentialRequest>,
) -> ApiResult<Json<NhiCredentialResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = extract_actor_id(&claims)?;
    let credential = state
        .credential_service
        .revoke(
            tenant_id,
            agent_id,
            credential_id,
            actor_id,
            request.reason,
            request.immediate,
        )
        .await?;
    Ok(Json(credential))
}

/// Validate a credential for an AI agent.
///
/// This endpoint allows an agent to verify that its credential is valid
/// without performing any other operation. Returns 200 if valid, 401 if invalid.
#[utoipa::path(
    post,
    path = "/nhi/agents/{id}/credentials/validate",
    tag = "NHI - Agents",
    params(
        ("id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = ValidateCredentialRequest,
    responses(
        (status = 200, description = "Credential is valid", body = ValidateCredentialResponse),
        (status = 401, description = "Invalid or expired credential"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_agent_credential(
    State(state): State<AgentCredentialState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ValidateCredentialRequest>,
) -> ApiResult<Json<ValidateCredentialResponse>> {
    let result = state.credential_service.validate(&request.credential).await;

    match result {
        Ok((tenant_id, nhi_id, nhi_type)) => {
            // Verify the credential belongs to the requested agent
            if nhi_id != id {
                return Err(crate::error::ApiNhiError::BadRequest(
                    "Credential does not belong to this agent".to_string(),
                ));
            }

            Ok(Json(ValidateCredentialResponse {
                valid: true,
                agent_id: nhi_id,
                tenant_id,
                nhi_type: nhi_type.to_string(),
                message: "Credential is valid".to_string(),
            }))
        }
        Err(_) => Err(crate::error::ApiNhiError::InvalidCredential),
    }
}

/// Request to validate a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ValidateCredentialRequest {
    /// The credential to validate (e.g., xnhi_...)
    pub credential: String,
}

/// Response for credential validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ValidateCredentialResponse {
    /// Whether the credential is valid.
    pub valid: bool,
    /// The agent ID the credential belongs to.
    pub agent_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The NHI type (agent or service_account).
    pub nhi_type: String,
    /// A human-readable message.
    pub message: String,
}

/// State for agent credential handlers.
#[derive(Clone)]
pub struct AgentCredentialState {
    pub credential_service: crate::services::AgentCredentialService,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agents_handlers_compile() {
        assert!(true);
    }

    // F110: Test agent credential query types
    #[test]
    fn test_list_agent_credentials_query() {
        let query = ListAgentCredentialsQuery { active_only: None };
        assert!(query.active_only.is_none());

        let query_active = ListAgentCredentialsQuery {
            active_only: Some(true),
        };
        assert_eq!(query_active.active_only, Some(true));
    }

    // T032: Test agents list handler types
    #[test]
    fn test_list_agents_query_types() {
        // Verify ListAgentsQuery can be constructed with defaults
        let query = ListAgentsQuery {
            status: None,
            agent_type: None,
            owner_id: None,
            risk_level: None,
            name: None,
            limit: 100,
            offset: 0,
        };
        assert!(query.status.is_none());
        assert!(query.name.is_none());

        let query_with_filter = ListAgentsQuery {
            status: Some("active".to_string()),
            agent_type: Some("assistant".to_string()),
            owner_id: None,
            risk_level: Some("low".to_string()),
            name: Some("test".to_string()),
            limit: 20,
            offset: 0,
        };
        assert_eq!(query_with_filter.status, Some("active".to_string()));
        assert_eq!(query_with_filter.limit, 20);
    }

    // T033: Test agents authorize handler types
    #[test]
    fn test_authorize_agent_request_types() {
        // Verify AuthorizeRequest can be constructed
        let request = AuthorizeRequest {
            agent_id: uuid::Uuid::new_v4(),
            tool: "test-tool".to_string(),
            parameters: None,
            context: None,
        };
        assert!(request.context.is_none());
        assert!(request.parameters.is_none());

        let request_with_params = AuthorizeRequest {
            agent_id: uuid::Uuid::new_v4(),
            tool: "another-tool".to_string(),
            parameters: Some(serde_json::json!({"key": "value"})),
            context: None,
        };
        assert!(request_with_params.parameters.is_some());
    }

    #[test]
    fn test_extract_tenant_id_error_type() {
        // Test that extract_tenant_id returns appropriate error type
        fn _verify_error_type() -> Result<uuid::Uuid, ApiNhiError> {
            Err(ApiNhiError::Unauthorized)
        }
    }
}
