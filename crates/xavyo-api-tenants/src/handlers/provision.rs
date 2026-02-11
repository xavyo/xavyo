//! Provision handler for tenant creation.

use axum::{body::Body, extract::State, http::Request, Extension, Json};
use xavyo_api_auth::middleware::extract_client_ip;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};
use xavyo_db::bootstrap::SYSTEM_TENANT_ID;

use crate::error::TenantError;
use crate::models::{ProvisionContext, ProvisionTenantRequest, ProvisionTenantResponse, TokenInfo};
use crate::router::TenantAppState;

/// POST /tenants/provision
///
/// Create a new tenant with all necessary resources.
///
/// Requires authentication against the system tenant.
///
/// # Request Body
///
/// - `organization_name`: Human-readable name for the new tenant (1-100 chars)
///
/// # Response
///
/// On success (201 Created):
/// - `tenant`: Created tenant details (id, slug, name)
/// - `admin`: Admin user details (id, email, `api_key`)
/// - `oauth_client`: OAuth client credentials (`client_id`, `client_secret`)
/// - `endpoints`: API endpoint URLs
/// - `next_steps`: Suggested actions for getting started
///
/// # Errors
///
/// - 400 Bad Request: Invalid organization name or validation error
/// - 401 Unauthorized: Missing or invalid JWT token
/// - 403 Forbidden: User not authenticated against system tenant
#[utoipa::path(
    post,
    path = "/tenants/provision",
    request_body = ProvisionTenantRequest,
    responses(
        (status = 201, description = "Tenant provisioned successfully", body = ProvisionTenantResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - must authenticate against system tenant", body = ErrorResponse),
    ),
    tag = "Tenant Provisioning",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn provision_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    request_parts: Request<Body>,
) -> Result<(axum::http::StatusCode, Json<ProvisionTenantResponse>), TenantError> {
    // Extract context from request before consuming it
    let ip_address = extract_client_ip(&request_parts);
    let user_agent = request_parts
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    // Parse request body
    let body_bytes = axum::body::to_bytes(request_parts.into_body(), 1024 * 1024)
        .await
        .map_err(|e| TenantError::Validation(format!("Failed to read request body: {e}")))?;

    let request: ProvisionTenantRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| TenantError::Validation(format!("Invalid JSON: {e}")))?;

    // Extract email from JWT claims
    let email = claims
        .email
        .as_ref()
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing email".to_string()))?;

    // Extract user_id from JWT claims for audit (sub is the user ID as string)
    let admin_user_id = claims
        .sub
        .parse::<uuid::Uuid>()
        .map_err(|_| TenantError::Unauthorized("JWT claims sub is not a valid UUID".to_string()))?;

    // Verify user is authenticated against the system tenant
    // System tenant check - users must authenticate against system tenant first
    let tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if tenant_id != SYSTEM_TENANT_ID {
        return Err(TenantError::Forbidden(
            "Tenant provisioning requires authentication against the system tenant".to_string(),
        ));
    }

    // Validate the request
    if let Some(error) = request.validate() {
        return Err(TenantError::Validation(error));
    }

    // Build provision context for audit logging
    let context = ProvisionContext {
        system_tenant_id: tenant_id,
        admin_user_id,
        ip_address: ip_address.clone(),
        user_agent: user_agent.clone(),
    };

    // Provision the tenant
    let mut response = state
        .provisioning_service
        .provision(request, email, context)
        .await?;

    // Issue JWT tokens scoped to the new tenant with super_admin role
    let new_tenant_id = TenantId::from_uuid(response.tenant.id);
    let new_user_id = UserId::from_uuid(admin_user_id);
    let (access_token, refresh_token, expires_in) = state
        .token_service
        .create_tokens(
            new_user_id,
            new_tenant_id,
            vec!["super_admin".to_string()],
            Some(email.clone()),
            user_agent.clone(),
            ip_address.as_deref().and_then(|ip| ip.parse().ok()),
        )
        .await
        .map_err(|e| TenantError::Internal(format!("Failed to create tokens: {e}")))?;

    response.tokens = TokenInfo {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
    };

    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_validation_empty() {
        let request = ProvisionTenantRequest {
            organization_name: String::new(),
        };
        assert!(request.validate().is_some());
    }

    #[test]
    fn test_request_validation_valid() {
        let request = ProvisionTenantRequest {
            organization_name: "Acme Corp".to_string(),
        };
        assert!(request.validate().is_none());
    }
}
