//! Audit query handlers.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{AuditFilter, AuditListResponse};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// GET /agents/{id}/audit - Query agent audit trail.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{id}/audit",
    tag = "AI Agent Audit",
    operation_id = "queryAgentAudit",
    params(
        ("id" = Uuid, Path, description = "Agent ID"),
        AuditFilter
    ),
    responses(
        (status = 200, description = "Audit trail", body = AuditListResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn query_audit(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(filter): Query<AuditFilter>,
) -> Result<Json<AuditListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .audit_service
        .query_by_agent(tenant_id, agent_id, filter)
        .await?;

    Ok(Json(response))
}
