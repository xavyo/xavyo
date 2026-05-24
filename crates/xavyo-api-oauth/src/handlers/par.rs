//! Pushed Authorization Request endpoint (RFC 9126).
//!
//! `POST /oauth/par` lets a client push the authorization request parameters to
//! the AS over the back channel, receiving a single-use `request_uri` to present
//! at `GET /oauth/authorize`. Keeps params out of the front-channel URL.

use crate::error::OAuthError;
use crate::handlers::authorize::extract_tenant_from_request;
use crate::models::{AuthorizationRequest, ClientType, ParResponse, PushedAuthRequestForm};
use crate::router::OAuthState;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use xavyo_db::models::{CreatePushedAuthRequest, PushedAuthRequest, REQUEST_URI_PREFIX};

/// `request_uri` lifetime (RFC 9126 §2.2: SHOULD be short-lived).
const PAR_TTL_SECS: i64 = 90;

/// Handle `POST /oauth/par`.
///
/// Authenticates the client (confidential: secret via body or Basic header;
/// public: PKCE only), validates the authorization request exactly as the
/// front channel would, stores it, and returns an opaque single-use
/// `request_uri` with `Cache-Control: no-store`.
#[utoipa::path(
    post,
    path = "/oauth/par",
    request_body(content = PushedAuthRequestForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 201, description = "Request stored; returns request_uri", body = ParResponse),
        (status = 400, description = "Invalid authorization request"),
        (status = 401, description = "Invalid client credentials"),
    ),
    tag = "OAuth2"
)]
pub async fn par_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(form): Form<PushedAuthRequestForm>,
) -> Result<Response, OAuthError> {
    let tenant_id = extract_tenant_from_request(&headers, form.tenant.as_deref())?;

    // Validate the request with the same rules as the front-channel endpoint.
    let auth_req = AuthorizationRequest {
        response_type: form.response_type.clone(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
        nonce: form.nonce.clone(),
        tenant: form.tenant.clone(),
        request_uri: None,
        authorization_details: form.authorization_details.clone(),
    };
    state
        .authorization_service
        .validate_authorization_request(&auth_req)?;

    // RFC 9396: validate + canonicalize authorization_details before storing.
    let authorization_details = crate::rar_validation::validate_authorization_details(
        form.authorization_details.as_deref(),
    )?;

    // Look up the client and enforce active + redirect_uri + scopes + grant type.
    let client = state
        .client_service
        .get_client_by_client_id(tenant_id, &form.client_id)
        .await?;
    if !client.is_active {
        return Err(OAuthError::InvalidClient(
            "Client is not active".to_string(),
        ));
    }
    // Client authentication. `private_key_jwt` (RFC 7523) takes precedence when
    // a `client_assertion` is present — the FAPI 2.0 strong-auth method (FAPI
    // also requires PAR itself to be client-authenticated, §5.3.2.2).
    if let Some(assertion) = form.client_assertion.as_deref() {
        if let Some(t) = form.client_assertion_type.as_deref() {
            if t != xavyo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER {
                return Err(OAuthError::InvalidRequest(
                    "unsupported client_assertion_type".to_string(),
                ));
            }
        }
        let jwks = client.jwks.as_ref().ok_or_else(|| {
            OAuthError::InvalidClient("client is not configured for private_key_jwt".to_string())
        })?;
        let par_endpoint = format!("{}/oauth/par", state.issuer.trim_end_matches('/'));
        let audiences = [state.issuer.as_str(), par_endpoint.as_str()];
        state
            .client_service
            .verify_client_assertion(tenant_id, &client.client_id, assertion, &audiences, jwks)
            .await?;
    } else if client.client_type == ClientType::Confidential {
        let secret = form
            .client_secret
            .clone()
            .or_else(|| basic_auth_secret(&headers, &form.client_id))
            .ok_or_else(|| {
                OAuthError::InvalidClient(
                    "client_secret is required for confidential clients".to_string(),
                )
            })?;
        let _ = state
            .client_service
            .verify_client_credentials(tenant_id, &form.client_id, &secret)
            .await?;
    }
    state
        .client_service
        .validate_redirect_uri(&client, &form.redirect_uri)?;
    let _ = state.client_service.validate_scopes(&client, &form.scope)?;
    state
        .client_service
        .validate_grant_type(&client, "authorization_code")?;

    // Mint an unguessable, single-use request_uri (256-bit reference).
    let request_uri = generate_request_uri();
    let expires_at = Utc::now() + Duration::seconds(PAR_TTL_SECS);

    // Store under tenant RLS context on a dedicated connection.
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!("PAR: failed to acquire connection: {e}");
        OAuthError::Internal("Failed to store pushed authorization request".to_string())
    })?;
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("PAR: failed to set tenant context: {e}");
            OAuthError::Internal("Failed to store pushed authorization request".to_string())
        })?;
    PushedAuthRequest::create(
        &mut *conn,
        CreatePushedAuthRequest {
            request_uri: request_uri.clone(),
            tenant_id,
            client_id: form.client_id,
            redirect_uri: form.redirect_uri,
            scope: form.scope,
            state: form.state,
            code_challenge: form.code_challenge,
            code_challenge_method: form.code_challenge_method,
            nonce: form.nonce,
            response_type: form.response_type,
            expires_at,
            authorization_details,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("PAR: failed to store request: {e}");
        OAuthError::Internal("Failed to store pushed authorization request".to_string())
    })?;

    // RFC 9126 §2.2: 201 + Cache-Control: no-store.
    let mut response = (
        StatusCode::CREATED,
        Json(ParResponse {
            request_uri,
            expires_in: PAR_TTL_SECS,
        }),
    )
        .into_response();
    if let Ok(v) = header::HeaderValue::from_str("no-store") {
        response.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    Ok(response)
}

/// Mint an unguessable single-use `request_uri`: the RFC 9126 URN prefix plus a
/// base64url-no-pad encoding of 32 CSPRNG bytes (256-bit reference).
fn generate_request_uri() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{}{}", REQUEST_URI_PREFIX, URL_SAFE_NO_PAD.encode(bytes))
}

/// Extract a client secret from an HTTP Basic `Authorization` header, if the
/// username matches `client_id`. Returns `None` otherwise.
fn basic_auth_secret(headers: &HeaderMap, client_id: &str) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(b64).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, secret) = decoded.split_once(':')?;
    if user == client_id {
        Some(secret.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_uri_format_and_uniqueness() {
        let a = generate_request_uri();
        let b = generate_request_uri();
        assert!(a.starts_with(REQUEST_URI_PREFIX));
        // 32 bytes base64url-no-pad = 43 chars after the prefix.
        assert_eq!(a.len(), REQUEST_URI_PREFIX.len() + 43);
        assert_ne!(a, b, "request_uris must be unique");
        let suffix = &a[REQUEST_URI_PREFIX.len()..];
        assert!(!suffix.contains('=') && !suffix.contains('+') && !suffix.contains('/'));
    }

    #[test]
    fn test_basic_auth_secret_parsing() {
        // "client-1:s3cret" base64 = Y2xpZW50LTE6czNjcmV0
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Basic Y2xpZW50LTE6czNjcmV0".parse().unwrap(),
        );
        assert_eq!(
            basic_auth_secret(&h, "client-1"),
            Some("s3cret".to_string())
        );
        // Username mismatch → None (won't leak secret to a different client_id).
        assert_eq!(basic_auth_secret(&h, "other-client"), None);
        // No header → None.
        assert_eq!(basic_auth_secret(&HeaderMap::new(), "client-1"), None);
    }
}
