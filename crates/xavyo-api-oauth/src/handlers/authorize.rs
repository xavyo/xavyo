//! Authorization endpoint handlers.

use crate::csrf;
use crate::error::OAuthError;
use crate::models::{AuthorizationErrorResponse, AuthorizationRequest, ConsentRequest};
use crate::router::OAuthState;
use axum::{
    extract::{Query, State},
    http::header::SET_COOKIE,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use uuid::Uuid;

/// Initiates the authorization code flow. Validates the request and
/// redirects to login/consent if not authenticated.
///
/// SECURITY: This endpoint validates the redirect_uri against the client's
/// registered URIs to prevent open redirect attacks and authorization code theft.
#[utoipa::path(
    get,
    path = "/oauth/authorize",
    params(AuthorizationRequest),
    responses(
        (status = 302, description = "Redirect to login or consent page"),
        (status = 400, description = "Invalid authorization request"),
    ),
    tag = "OAuth2"
)]
pub async fn authorize_handler(
    State(state): State<OAuthState>,
    headers: axum::http::HeaderMap,
    Query(request): Query<AuthorizationRequest>,
) -> Result<Response, OAuthError> {
    // Validate the authorization request parameters
    state
        .authorization_service
        .validate_authorization_request(&request)?;

    // Parse and validate client_id format
    let _client_uuid = Uuid::parse_str(&request.client_id)
        .map_err(|_| OAuthError::InvalidClient("Invalid client_id format".to_string()))?;

    // SECURITY: Extract tenant context and validate redirect_uri.
    // The tenant can be derived from:
    // 1. X-Tenant-ID header (set by reverse proxy based on domain)
    // 2. A tenant subdomain (extracted by middleware)
    // 3. A tenant cookie (for single-domain multi-tenant deployments)
    let tenant_id = extract_tenant_from_request(&headers)?;

    // SECURITY: Look up the client and validate redirect_uri BEFORE proceeding.
    // This prevents authorization code theft via open redirect attacks.
    let client = state
        .client_service
        .get_client_by_client_id(tenant_id, &request.client_id)
        .await?;

    // Check client is active
    if !client.is_active {
        return Err(OAuthError::InvalidClient(
            "Client is not active".to_string(),
        ));
    }

    // SECURITY: Validate redirect_uri against registered URIs (strict exact match)
    state
        .client_service
        .validate_redirect_uri(&client, &request.redirect_uri)?;

    // Validate requested scopes
    let _validated_scope = state
        .client_service
        .validate_scopes(&client, &request.scope)?;

    // Validate authorization_code grant is allowed for this client
    state
        .client_service
        .validate_grant_type(&client, "authorization_code")?;

    // F082-US6: Generate CSRF token for consent form
    let csrf_secret = state.csrf_secret();
    let (csrf_token, csrf_sig) = csrf::generate_csrf_token(csrf_secret);

    // Build the consent/login URL with all parameters preserved, including CSRF
    let consent_url = format!(
        "/oauth/consent?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}{}&csrf_token={}&csrf_sig={}",
        urlencoding::encode(&request.client_id),
        urlencoding::encode(&request.redirect_uri),
        urlencoding::encode(&request.scope),
        urlencoding::encode(&request.state),
        urlencoding::encode(&request.code_challenge),
        urlencoding::encode(&request.code_challenge_method),
        request.nonce.as_ref().map_or(String::new(), |n| format!("&nonce={}", urlencoding::encode(n))),
        urlencoding::encode(&csrf_token),
        urlencoding::encode(&csrf_sig),
    );

    // F082-US6: Set CSRF token as HttpOnly cookie (double-submit cookie pattern)
    let cookie_value = format!(
        "csrf_token={}; HttpOnly; SameSite=Strict; Path=/oauth; Max-Age=600",
        csrf_token
    );
    let mut response = Redirect::to(&consent_url).into_response();
    if let Ok(header_val) = cookie_value.parse() {
        response.headers_mut().insert(SET_COOKIE, header_val);
    }

    Ok(response)
}

/// Processes user consent and issues authorization code on approval.
#[utoipa::path(
    post,
    path = "/oauth/authorize/consent",
    request_body = ConsentRequest,
    responses(
        (status = 302, description = "Redirect with authorization code or error"),
        (status = 400, description = "Invalid consent request"),
    ),
    tag = "OAuth2"
)]
pub async fn consent_handler(
    State(_state): State<OAuthState>,
    headers: axum::http::HeaderMap,
    Form(request): Form<ConsentRequest>,
) -> Result<Response, OAuthError> {
    // F082-US6: Validate CSRF token (double-submit cookie pattern)
    {
        let csrf_secret = _state.csrf_secret();
        let form_token = request.csrf_token.as_deref().unwrap_or("");
        let form_sig = request.csrf_sig.as_deref().unwrap_or("");

        // Extract CSRF token from cookie
        let cookie_token = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|c| {
                    let c = c.trim();
                    c.strip_prefix("csrf_token=").map(|v| v.to_string())
                })
            })
            .unwrap_or_default();

        // Validate: form token must match cookie token, and HMAC must be valid
        let csrf_valid = !form_token.is_empty()
            && form_token == cookie_token
            && csrf::validate_csrf_token(form_token, form_sig, csrf_secret);

        if !csrf_valid {
            tracing::warn!(
                target: "security",
                event_type = "csrf_failed",
                outcome = "rejected",
                "CSRF validation failed on OAuth consent form"
            );
            return Err(OAuthError::InvalidRequest(
                "CSRF validation failed".to_string(),
            ));
        }
    }

    // Check if user denied consent
    if !request.approved {
        let error_response = AuthorizationErrorResponse {
            error: "access_denied".to_string(),
            error_description: Some("The user denied the authorization request".to_string()),
            state: Some(request.state.clone()),
        };

        let redirect_url = build_error_redirect(&request.redirect_uri, &error_response);
        return Ok(Redirect::to(&redirect_url).into_response());
    }

    // Parse client_id
    let _client_uuid = Uuid::parse_str(&request.client_id)
        .map_err(|_| OAuthError::InvalidClient("Invalid client_id format".to_string()))?;

    // In a real implementation, we would:
    // 1. Get the authenticated user from the session
    // 2. Get the tenant_id from the user's context
    // For now, we'll need these to be provided somehow

    // TODO: Get user_id and tenant_id from authenticated session
    // For now, return an error indicating this needs proper implementation
    // This is a placeholder that demonstrates the flow

    // In a real scenario, you would have middleware that:
    // 1. Verifies the user is authenticated
    // 2. Extracts user_id and tenant_id from the session
    // 3. Makes them available via request extensions

    // Placeholder: In production, extract from session
    // let user_id = extract_user_from_session(&request);
    // let tenant_id = extract_tenant_from_session(&request);

    // For demonstration, we'll return an error indicating session is needed
    Err(OAuthError::InvalidRequest(
        "User authentication required. This endpoint needs integration with session management."
            .to_string(),
    ))

    // The code below shows what would happen with proper session integration:
    /*
    // Generate authorization code
    let code = state
        .authorization_service
        .create_authorization_code(
            tenant_id,
            client_uuid,
            user_id,
            &request.redirect_uri,
            &request.scope,
            &request.code_challenge,
            &request.code_challenge_method,
            request.nonce.as_deref(),
        )
        .await?;

    // Build redirect URL with code and state
    let redirect_url = format!(
        "{}?code={}&state={}",
        request.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&request.state)
    );

    Ok(Redirect::to(&redirect_url).into_response())
    */
}

/// Extract tenant ID from request headers.
///
/// SECURITY: This function extracts the tenant context for pre-authentication
/// OAuth endpoints. The tenant ID is expected in the X-Tenant-ID header,
/// which should be set by the reverse proxy/load balancer based on the
/// incoming domain or subdomain.
///
/// In a production deployment, this header should ONLY be trusted from
/// the internal network (i.e., set by the reverse proxy, not by clients).
fn extract_tenant_from_request(headers: &axum::http::HeaderMap) -> Result<Uuid, OAuthError> {
    let tenant_header = headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing X-Tenant-ID header in authorize request");
            OAuthError::InvalidRequest(
                "Tenant context required. Ensure X-Tenant-ID header is set.".to_string(),
            )
        })?;

    Uuid::parse_str(tenant_header).map_err(|_| {
        tracing::warn!(tenant_header = %tenant_header, "Invalid X-Tenant-ID format");
        OAuthError::InvalidRequest("Invalid tenant ID format".to_string())
    })
}

/// Build an error redirect URL with query parameters.
fn build_error_redirect(redirect_uri: &str, error: &AuthorizationErrorResponse) -> String {
    let mut url = format!(
        "{}?error={}",
        redirect_uri,
        urlencoding::encode(&error.error)
    );

    if let Some(ref desc) = error.error_description {
        url.push_str(&format!("&error_description={}", urlencoding::encode(desc)));
    }

    if let Some(ref state) = error.state {
        url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }

    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_error_redirect_with_all_fields() {
        let error = AuthorizationErrorResponse {
            error: "access_denied".to_string(),
            error_description: Some("User denied access".to_string()),
            state: Some("abc123".to_string()),
        };

        let url = build_error_redirect("https://example.com/callback", &error);

        assert!(url.starts_with("https://example.com/callback?"));
        assert!(url.contains("error=access_denied"));
        assert!(url.contains("error_description=User%20denied%20access"));
        assert!(url.contains("state=abc123"));
    }

    #[test]
    fn test_build_error_redirect_minimal() {
        let error = AuthorizationErrorResponse {
            error: "invalid_request".to_string(),
            error_description: None,
            state: None,
        };

        let url = build_error_redirect("https://example.com/callback", &error);

        assert_eq!(url, "https://example.com/callback?error=invalid_request");
    }
}
