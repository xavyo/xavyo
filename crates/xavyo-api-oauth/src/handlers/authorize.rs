//! Authorization endpoint handlers.

use crate::csrf;
use crate::error::OAuthError;
use crate::models::AuthorizationRequest;
use crate::router::OAuthState;
use axum::{
    extract::{Query, State},
    http::header::SET_COOKIE,
    response::{IntoResponse, Redirect, Response},
};
use uuid::Uuid;

/// Initiates the authorization code flow. Validates the request and
/// redirects to login/consent if not authenticated.
///
/// SECURITY: This endpoint validates the `redirect_uri` against the client's
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
    // RFC 9126: if a `request_uri` (PAR) is supplied, atomically consume the
    // pushed request and proceed with ITS parameters — any other supplied query
    // params (besides client_id, used for binding) are ignored per §4.
    let used_par = request.request_uri.is_some();
    let request = if let Some(request_uri) = request.request_uri.clone() {
        let tenant_id = extract_tenant_from_request(&headers, request.tenant.as_deref())?;
        consume_par(&state, tenant_id, &request_uri, &request.client_id).await?
    } else {
        request
    };

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
    // 2. A ?tenant= query parameter (for browser-redirect OAuth flows)
    let tenant_id = extract_tenant_from_request(&headers, request.tenant.as_deref())?;

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

    // FAPI 2.0 §5.3.2.2: a profile client MUST use PAR — reject a direct
    // (non-`request_uri`) authorization request.
    if client.requires_par() && !used_par {
        return Err(OAuthError::InvalidRequest(
            "this client requires a pushed authorization request (RFC 9126)".to_string(),
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
    let frontend_base = required_frontend_url(state.frontend_url.as_deref())?;
    let consent_url = format!(
        "{frontend_base}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}{}{}&csrf_token={}&csrf_sig={}&tenant={}",
        urlencoding::encode(&request.client_id),
        urlencoding::encode(&request.redirect_uri),
        urlencoding::encode(&request.scope),
        urlencoding::encode(&request.state),
        urlencoding::encode(&request.code_challenge),
        urlencoding::encode(&request.code_challenge_method),
        request.nonce.as_ref().map_or(String::new(), |n| format!("&nonce={}", urlencoding::encode(n))),
        // RFC 9396: preserve authorization_details across the consent round-trip
        // so the frontend echoes it back to POST /oauth/authorize/grant.
        request.authorization_details.as_ref().map_or(String::new(), |d| format!("&authorization_details={}", urlencoding::encode(d))),
        urlencoding::encode(&csrf_token),
        urlencoding::encode(&csrf_sig),
        tenant_id,
    );

    // F082-US6: Set CSRF token as HttpOnly cookie (double-submit cookie pattern)
    let cookie_value =
        format!("csrf_token={csrf_token}; HttpOnly; SameSite=Strict; Path=/oauth; Max-Age=600");
    let mut response = Redirect::to(&consent_url).into_response();
    if let Ok(header_val) = cookie_value.parse() {
        response.headers_mut().insert(SET_COOKIE, header_val);
    }

    Ok(response)
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
/// Atomically consume a PAR `request_uri` and return the pushed authorization
/// request (RFC 9126 §4). Single-use: a second use of the same `request_uri`
/// returns `invalid_request`. The presented `client_id` must match the one the
/// request was pushed with.
async fn consume_par(
    state: &OAuthState,
    tenant_id: Uuid,
    request_uri: &str,
    presented_client_id: &str,
) -> Result<AuthorizationRequest, OAuthError> {
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!("PAR consume: failed to acquire connection: {e}");
        OAuthError::Internal("Database error".to_string())
    })?;
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("PAR consume: failed to set tenant context: {e}");
            OAuthError::Internal("Database error".to_string())
        })?;

    let stored = xavyo_db::models::PushedAuthRequest::consume(&mut *conn, tenant_id, request_uri)
        .await
        .map_err(|e| {
            tracing::error!("PAR consume: query failed: {e}");
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or_else(|| {
            OAuthError::InvalidRequest(
                "request_uri is invalid, expired, or already used".to_string(),
            )
        })?;

    // Bind: the client_id presented at /authorize must match the pushed one.
    if !presented_client_id.is_empty() && presented_client_id != stored.client_id {
        return Err(OAuthError::InvalidRequest(
            "client_id does not match the pushed authorization request".to_string(),
        ));
    }

    Ok(AuthorizationRequest {
        response_type: stored.response_type,
        client_id: stored.client_id,
        redirect_uri: stored.redirect_uri,
        scope: stored.scope,
        state: stored.state,
        code_challenge: stored.code_challenge,
        code_challenge_method: stored.code_challenge_method,
        nonce: stored.nonce,
        tenant: Some(tenant_id.to_string()),
        request_uri: None,
        // RFC 9396: carry the pushed authorization_details (stored as JSONB) back
        // into the request as its JSON-string wire form.
        authorization_details: stored.authorization_details.map(|v| v.to_string()),
    })
}

pub(crate) fn extract_tenant_from_request(
    headers: &axum::http::HeaderMap,
    query_tenant: Option<&str>,
) -> Result<Uuid, OAuthError> {
    // Try X-Tenant-ID header first, then fall back to ?tenant= query parameter
    // (browser redirects cannot set custom headers)
    let tenant_str = headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .or(query_tenant)
        .ok_or_else(|| {
            tracing::warn!("Missing tenant context in authorize request");
            OAuthError::InvalidRequest(
                "Tenant context required. Set X-Tenant-ID header or pass ?tenant= query parameter."
                    .to_string(),
            )
        })?;

    Uuid::parse_str(tenant_str).map_err(|_| {
        tracing::warn!(tenant_str = %tenant_str, "Invalid tenant ID format");
        OAuthError::InvalidRequest("Invalid tenant ID format".to_string())
    })
}

/// Consent redirect base. Missing frontend URL must not become a relative path.
fn required_frontend_url(frontend_url: Option<&str>) -> Result<&str, OAuthError> {
    frontend_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::Internal("frontend_url is not configured".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_redirect_requires_frontend_url() {
        assert_eq!(
            required_frontend_url(Some("https://app.example.com")).unwrap(),
            "https://app.example.com"
        );
        assert!(required_frontend_url(None).is_err());
        assert!(required_frontend_url(Some("")).is_err());
        assert!(required_frontend_url(Some("   ")).is_err());
        let src = include_str!("authorize.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("required_frontend_url(")
                && !production.contains("unwrap_or(\"\")"),
            "OAuth consent redirect must not use an empty frontend_url"
        );
    }
}
