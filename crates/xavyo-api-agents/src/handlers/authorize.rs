//! Authorization handler for real-time tool authorization decisions.

use axum::{extract::State, http::HeaderMap, Extension, Json};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{AuthorizeRequest, AuthorizeResponse};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract client IP from headers.
fn extract_source_ip(headers: &HeaderMap) -> Option<String> {
    // Try X-Forwarded-For first
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = value.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    // Fall back to X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return Some(value.to_string());
        }
    }

    None
}

/// POST /agents/authorize - Make authorization decision.
///
/// Returns sub-100ms authorization decisions for agent tool invocations.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/authorize",
    tag = "AI Agent Authorization",
    operation_id = "authorizeAgentAction",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision", body = AuthorizeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn authorize(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    headers: HeaderMap,
    Json(request): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let source_ip = extract_source_ip(&headers);

    let response = state
        .authorization_service
        .authorize_request(tenant_id, request, source_ip.as_deref())
        .await?;

    Ok(Json(response))
}
