//! Credential request handlers for Dynamic Secrets Provisioning (F120).
//!
//! Implements the POST /agents/{id}/credentials/request endpoint.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::CredentialRequest;
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;
use xavyo_db::models::credential_request_audit::{CredentialErrorCode, CredentialRequestOutcome};

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// POST /agents/{id}/credentials/request - Request ephemeral credentials.
///
/// This endpoint allows AI agents to request just-in-time credentials for
/// accessing external resources. The credentials are:
/// - Time-limited (TTL specified in request or defaulted from secret type config)
/// - Rate-limited (per agent, per secret type)
/// - Fully audited (every request is logged)
/// - Permission-checked (agent must have permission for the secret type)
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/credentials/request",
    tag = "Credentials",
    operation_id = "requestCredentials",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID")
    ),
    request_body = CredentialRequest,
    responses(
        (status = 200, description = "Credentials issued successfully", body = CredentialResponse,
         headers(
             ("X-RateLimit-Remaining" = i32, description = "Remaining requests in current window"),
             ("X-RateLimit-Reset" = String, description = "When rate limit window resets (ISO 8601)")
         )),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Agent suspended or permission denied"),
        (status = 404, description = "Agent or secret type not found"),
        (status = 429, description = "Rate limit exceeded",
         headers(
             ("Retry-After" = i32, description = "Seconds until rate limit resets")
         )),
        (status = 502, description = "Secret provider unavailable")
    ),
    security(("bearerAuth" = []))
))]
pub async fn request_credentials(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(request): Json<CredentialRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let source_ip = connect_info.map(|ci| ci.0.ip().to_string());

    // Request credentials from the service
    match state
        .credential_service
        .request_credential(tenant_id, agent_id, request.clone(), source_ip.as_deref())
        .await
    {
        Ok((response, rate_info)) => {
            // Build response with rate limit headers
            let mut resp = (StatusCode::OK, Json(response)).into_response();
            if let Ok(val) = rate_info.remaining.to_string().parse() {
                resp.headers_mut().insert("X-RateLimit-Remaining", val);
            }
            if let Ok(val) = rate_info.reset_at.to_rfc3339().parse() {
                resp.headers_mut().insert("X-RateLimit-Reset", val);
            }
            Ok(resp)
        }
        Err(e) => {
            // Log denied requests for audit
            if let Some(cred_service) = state.credential_service_opt() {
                let (outcome, error_code) = error_to_audit_info(&e);
                let _ = cred_service
                    .log_denied_request(
                        tenant_id,
                        agent_id,
                        &request.secret_type,
                        outcome,
                        error_code,
                        &e.to_string(),
                        &request,
                        source_ip.as_deref(),
                    )
                    .await;
            }
            Err(e)
        }
    }
}

/// Convert an API error to audit outcome and error code.
fn error_to_audit_info(err: &ApiAgentsError) -> (CredentialRequestOutcome, CredentialErrorCode) {
    match err {
        ApiAgentsError::AgentNotFound => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::AgentNotFound,
        ),
        ApiAgentsError::AgentNotActive => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::AgentSuspended,
        ),
        ApiAgentsError::AgentExpired => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::AgentExpired,
        ),
        ApiAgentsError::SecretTypeNotFound(_) => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::SecretTypeNotFound,
        ),
        ApiAgentsError::SecretTypeDisabled(_) => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::SecretTypeDisabled,
        ),
        ApiAgentsError::SecretPermissionDenied(_) => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::PermissionDenied,
        ),
        ApiAgentsError::SecretPermissionExpired => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::PermissionExpired,
        ),
        ApiAgentsError::CredentialRateLimitExceeded(_, _) => (
            CredentialRequestOutcome::RateLimited,
            CredentialErrorCode::RateLimitExceeded,
        ),
        ApiAgentsError::SecretProviderUnavailable(_) => (
            CredentialRequestOutcome::Error,
            CredentialErrorCode::ProviderUnavailable,
        ),
        ApiAgentsError::InvalidTtl(_) => (
            CredentialRequestOutcome::Denied,
            CredentialErrorCode::InvalidTtl,
        ),
        _ => (
            CredentialRequestOutcome::Error,
            CredentialErrorCode::InternalError,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_to_audit_info_mapping() {
        let (outcome, code) = error_to_audit_info(&ApiAgentsError::AgentNotFound);
        assert!(matches!(outcome, CredentialRequestOutcome::Denied));
        assert!(matches!(code, CredentialErrorCode::AgentNotFound));

        let (outcome, code) =
            error_to_audit_info(&ApiAgentsError::CredentialRateLimitExceeded(10, 10));
        assert!(matches!(outcome, CredentialRequestOutcome::RateLimited));
        assert!(matches!(code, CredentialErrorCode::RateLimitExceeded));

        let (outcome, code) = error_to_audit_info(&ApiAgentsError::SecretProviderUnavailable(
            "test".to_string(),
        ));
        assert!(matches!(outcome, CredentialRequestOutcome::Error));
        assert!(matches!(code, CredentialErrorCode::ProviderUnavailable));
    }
}
