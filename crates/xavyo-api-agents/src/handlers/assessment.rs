//! Security Assessment handlers for the AI Agent Security API (F093).
//!
//! Implements the security assessment endpoint that evaluates AI agent
//! security posture against the arXiv:2511.03841 14-point vulnerability framework.

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::SecurityAssessment;
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// GET /agents/{id}/security-assessment
///
/// Performs a comprehensive security assessment of an AI agent based on the
/// arXiv:2511.03841 14-point vulnerability framework.
///
/// Returns:
/// - Overall security score (0-100)
/// - Risk level (low, medium, high, critical)
/// - All 14 vulnerability check results
/// - Compliance status for OWASP Agentic, A2A Protocol, MCP OAuth
/// - Actionable recommendations for failed/warning checks
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/security-assessment",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID to assess")
    ),
    responses(
        (status = 200, description = "Security assessment completed", body = SecurityAssessment),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Agent not found")
    ),
    security(
        ("bearer" = [])
    ),
    tag = "Security Assessment"
))]
pub async fn get_agent_security_assessment(
    State(state): State<AgentsState>,
    claims: axum::Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<SecurityAssessment>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let assessment = state
        .assessment_service
        .assess_agent(tenant_id, agent_id)
        .await?;

    Ok(Json(assessment))
}

// Handler tests require a mock database and are covered in integration tests.
