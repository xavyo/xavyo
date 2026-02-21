//! OIDC RP-Initiated Logout 1.0 handler.
//!
//! Implements the `end_session_endpoint` per the OIDC RP-Initiated Logout specification.
//!
//! - `GET /oauth/logout` or `POST /oauth/logout` — initiates logout.
//! - Accepts `id_token_hint`, `post_logout_redirect_uri`, `state`, and `client_id` params.
//! - Validates the `id_token_hint` JWT signature (expired tokens accepted per spec).
//! - Validates `post_logout_redirect_uri` against the client's registered URIs.
//! - Revokes the user's sessions.
//! - Redirects to `post_logout_redirect_uri` (303) or returns JSON success (200).

use crate::error::OAuthError;
use crate::router::OAuthState;
use crate::services::token::IdTokenClaims;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Parameters for the OIDC RP-Initiated Logout endpoint.
///
/// Accepted via query string (GET) or form body (POST).
#[derive(Debug, Deserialize)]
pub struct EndSessionParams {
    /// Previously issued ID token passed as a hint about the end-user's
    /// current authenticated session. The token MAY be expired.
    pub id_token_hint: Option<String>,

    /// URI to which the RP is requesting that the end-user's user-agent
    /// be redirected after logout has been performed.
    pub post_logout_redirect_uri: Option<String>,

    /// Opaque value used by the RP to maintain state between the logout
    /// request and the callback to the `post_logout_redirect_uri`.
    pub state: Option<String>,

    /// OAuth 2.0 client identifier of the RP. Used to identify the client
    /// when `id_token_hint` is not provided.
    pub client_id: Option<String>,
}

/// Response body returned when no post-logout redirect URI is provided.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LogoutResponse {
    /// Success message.
    pub message: String,
}

/// Decoded identity from a validated `id_token_hint`.
struct IdTokenIdentity {
    /// The user's subject identifier (user ID).
    user_id: Uuid,
    /// The tenant identifier.
    tenant_id: Option<Uuid>,
    /// The audience (client_id) from the token.
    client_id: String,
}

/// OIDC RP-Initiated Logout 1.0 endpoint.
///
/// Accepts both GET (query params) and POST (form body). The handler:
///
/// 1. Validates `id_token_hint` if provided (signature verification, issuer check).
/// 2. Validates `post_logout_redirect_uri` against the client's registered URIs.
/// 3. Revokes all user sessions if the user is identified.
/// 4. Redirects to `post_logout_redirect_uri` (303) or returns 200 JSON.
#[utoipa::path(
    get,
    path = "/oauth/logout",
    params(
        ("id_token_hint" = Option<String>, Query, description = "Previously issued ID token (may be expired)"),
        ("post_logout_redirect_uri" = Option<String>, Query, description = "URI to redirect after logout"),
        ("state" = Option<String>, Query, description = "Opaque state value for the RP"),
        ("client_id" = Option<String>, Query, description = "OAuth2 client identifier"),
    ),
    responses(
        (status = 200, description = "Logged out successfully (no redirect URI)", body = LogoutResponse),
        (status = 303, description = "Redirect to post-logout URI"),
        (status = 400, description = "Invalid request"),
    ),
    tag = "OIDC"
)]
pub async fn end_session_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    query_params: Option<Query<EndSessionParams>>,
    form_params: Option<Form<EndSessionParams>>,
) -> Result<Response, OAuthError> {
    // Merge GET query params and POST form params (POST takes precedence).
    let params = match (form_params, query_params) {
        (Some(Form(p)), _) => p,
        (_, Some(Query(p))) => p,
        (None, None) => EndSessionParams {
            id_token_hint: None,
            post_logout_redirect_uri: None,
            state: None,
            client_id: None,
        },
    };

    let tenant_uuid = super::client_auth::extract_tenant_from_header(&headers)?;

    // Input length validation to prevent abuse.
    if let Some(ref hint) = params.id_token_hint {
        if hint.len() > 8192 {
            return Err(OAuthError::InvalidRequest(
                "id_token_hint too large".to_string(),
            ));
        }
    }
    if let Some(ref state_val) = params.state {
        if state_val.len() > 512 {
            return Err(OAuthError::InvalidRequest(
                "state parameter too large".to_string(),
            ));
        }
    }
    if let Some(ref uri) = params.post_logout_redirect_uri {
        if uri.len() > 2048 {
            return Err(OAuthError::InvalidRequest(
                "post_logout_redirect_uri too large".to_string(),
            ));
        }
    }

    // Step 1: Validate id_token_hint if provided.
    let identity = if let Some(ref id_token_hint) = params.id_token_hint {
        match validate_id_token_hint(&state, id_token_hint) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "id_token_hint validation failed, proceeding without identity"
                );
                None
            }
        }
    } else {
        None
    };

    // Step 2: Determine the effective client_id.
    // Per OIDC RP-Initiated Logout §2.1: if both id_token_hint and client_id
    // are supplied, they MUST match. Reject mismatches.
    let effective_client_id = match (
        identity.as_ref().map(|id| id.client_id.clone()),
        params.client_id.clone(),
    ) {
        (Some(token_aud), Some(explicit_id)) if token_aud != explicit_id => {
            tracing::warn!(
                token_aud = %token_aud,
                explicit_client_id = %explicit_id,
                "client_id parameter does not match id_token_hint audience"
            );
            return Err(OAuthError::InvalidRequest(
                "client_id does not match id_token_hint audience".to_string(),
            ));
        }
        (Some(token_aud), _) => Some(token_aud),
        (None, explicit) => explicit,
    };

    // Step 3: Validate post_logout_redirect_uri if provided.
    let validated_redirect_uri = if let Some(ref redirect_uri) = params.post_logout_redirect_uri {
        validate_post_logout_redirect_uri(
            &state,
            tenant_uuid,
            effective_client_id.as_deref(),
            redirect_uri,
        )
        .await
    } else {
        None
    };

    // Step 4: Revoke user sessions and refresh tokens if user is identified.
    if let Some(ref id) = identity {
        // Use the tenant_id from the id_token_hint if available, otherwise
        // fall back to the tenant_id from the request extension.
        let session_tenant = id.tenant_id.unwrap_or(tenant_uuid);
        if let Err(e) = revoke_user_sessions(&state, session_tenant, id.user_id).await {
            tracing::error!(
                user_id = %id.user_id,
                tenant_id = %session_tenant,
                error = %e,
                "Failed to revoke user sessions during logout"
            );
        }
        // Also revoke all OAuth2 refresh tokens for this user
        if let Err(e) = state
            .token_service
            .revoke_user_tokens(session_tenant, id.user_id)
            .await
        {
            tracing::error!(
                user_id = %id.user_id,
                tenant_id = %session_tenant,
                error = %e,
                "Failed to revoke refresh tokens during logout"
            );
        }
    }

    // Step 5: Build response.
    if let Some(redirect_uri) = validated_redirect_uri {
        // Build the redirect URL, appending state if present.
        // Use proper URL parsing to handle fragments and existing query params correctly.
        let redirect_url = if let Some(ref state_value) = params.state {
            let mut parsed = url::Url::parse(&redirect_uri).map_err(|_| {
                OAuthError::InvalidRequest("Invalid post_logout_redirect_uri".to_string())
            })?;
            parsed.query_pairs_mut().append_pair("state", state_value);
            parsed.to_string()
        } else {
            redirect_uri
        };

        tracing::info!(
            redirect_uri = %redirect_url,
            user_id = ?identity.as_ref().map(|id| id.user_id),
            "OIDC RP-Initiated Logout: redirecting"
        );

        Ok(Redirect::to(&redirect_url).into_response())
    } else {
        tracing::info!(
            user_id = ?identity.as_ref().map(|id| id.user_id),
            "OIDC RP-Initiated Logout: no redirect URI"
        );

        Ok((
            StatusCode::OK,
            Json(LogoutResponse {
                message: "Logged out successfully".to_string(),
            }),
        )
            .into_response())
    }
}

/// Validate the `id_token_hint` JWT.
///
/// Decodes the JWT header to find the `kid`, locates the matching signing key,
/// and verifies the signature. Per OIDC RP-Initiated Logout, expired tokens
/// are accepted (`validate_exp = false`).
///
/// Validates that `iss` matches the configured issuer.
fn validate_id_token_hint(
    state: &OAuthState,
    id_token_hint: &str,
) -> Result<IdTokenIdentity, OAuthError> {
    // Decode the JWT header to extract the kid.
    let header = decode_header(id_token_hint).map_err(|e| {
        OAuthError::InvalidRequest(format!(
            "Invalid id_token_hint: failed to decode header: {e}"
        ))
    })?;

    // Find the matching public key by kid.
    let public_key_pem = if let Some(ref kid) = header.kid {
        if let Some(key) = state.find_key_by_kid(kid) {
            key.public_key_pem.as_bytes().to_vec()
        } else {
            // SECURITY: Do not fall back to the active key when kid is provided
            // but not found. This could allow forged tokens signed with a different
            // key to be accepted if the active key happens to match.
            return Err(OAuthError::InvalidRequest(format!(
                "Invalid id_token_hint: unknown key ID '{kid}'"
            )));
        }
    } else {
        // No kid in the token header; use the active public key.
        state.public_key.clone()
    };

    // Build validation: accept expired tokens, validate issuer, skip audience.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_exp = false;
    validation.set_issuer(&[&state.issuer]);
    // Audience is not validated here because we extract it as the client_id.
    validation.validate_aud = false;

    let decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).map_err(|e| {
        tracing::error!(error = %e, "Failed to create decoding key from public key PEM");
        OAuthError::Internal("Failed to create decoding key".to_string())
    })?;

    let token_data =
        decode::<IdTokenClaims>(id_token_hint, &decoding_key, &validation).map_err(|e| {
            OAuthError::InvalidRequest(format!(
                "Invalid id_token_hint: signature verification failed: {e}"
            ))
        })?;

    let claims = token_data.claims;

    // Extract user_id from sub.
    let user_id = claims.sub.parse::<Uuid>().map_err(|_| {
        OAuthError::InvalidRequest("Invalid id_token_hint: sub is not a valid UUID".to_string())
    })?;

    Ok(IdTokenIdentity {
        user_id,
        tenant_id: claims.tid,
        client_id: claims.aud,
    })
}

/// Validate a `post_logout_redirect_uri` against the client's registered URIs.
///
/// Returns `Some(uri)` if the URI is valid, `None` otherwise.
/// Per the OIDC spec, invalid URIs are silently ignored (no error returned).
async fn validate_post_logout_redirect_uri(
    state: &OAuthState,
    tenant_id: Uuid,
    effective_client_id: Option<&str>,
    redirect_uri: &str,
) -> Option<String> {
    // The client_id must be identifiable to validate the redirect URI.
    let client_id = match effective_client_id {
        Some(id) => id,
        None => {
            tracing::debug!(
                "post_logout_redirect_uri provided but no client_id identifiable; ignoring redirect"
            );
            return None;
        }
    };

    // Look up the client.
    let client = match state
        .client_service
        .get_client_by_client_id(tenant_id, client_id)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                client_id = %client_id,
                error = %e,
                "Failed to look up client for post_logout_redirect_uri validation; ignoring redirect"
            );
            return None;
        }
    };

    // Inactive clients should not participate in logout redirects.
    if !client.is_active {
        tracing::debug!(
            client_id = %client_id,
            "Client is inactive; ignoring post_logout_redirect_uri"
        );
        return None;
    }

    // Check if the requested URI is in the client's registered list.
    // Use URL-parsed comparison for case-insensitive host matching and port normalization,
    // consistent with redirect_uri validation in the authorize endpoint.
    let normalized_request = url::Url::parse(redirect_uri).ok().map(|u| u.to_string());
    let matched = normalized_request.as_ref().and_then(|norm_req| {
        client
            .post_logout_redirect_uris
            .iter()
            .find(|uri| url::Url::parse(uri).ok().map(|u| u.to_string()).as_ref() == Some(norm_req))
            .map(|_| norm_req.clone())
    });

    if matched.is_some() {
        matched
    } else {
        tracing::debug!(
            client_id = %client_id,
            redirect_uri = %redirect_uri,
            registered_uris = ?client.post_logout_redirect_uris,
            "post_logout_redirect_uri not in client's registered list; ignoring redirect"
        );
        None
    }
}

/// Revoke all sessions for a user within a tenant.
///
/// Deletes all entries from `user_sessions` for the given user and tenant,
/// with RLS context set for tenant isolation.
async fn revoke_user_sessions(
    state: &OAuthState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, OAuthError> {
    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!("Failed to acquire connection for session revocation: {e}");
        OAuthError::Internal("Failed to acquire database connection".to_string())
    })?;

    // Set tenant context for RLS on this connection.
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to set tenant context: {e}");
            OAuthError::Internal("Failed to set tenant context".to_string())
        })?;

    let result = sqlx::query("DELETE FROM user_sessions WHERE tenant_id = $1 AND user_id = $2")
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                error = %e,
                "Failed to delete user sessions"
            );
            OAuthError::Internal("Failed to revoke user sessions".to_string())
        })?;

    let rows_deleted = result.rows_affected();
    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        sessions_revoked = rows_deleted,
        "User sessions revoked during OIDC logout"
    );

    Ok(rows_deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_session_params_deserialize_empty() {
        let params: EndSessionParams = serde_json::from_str("{}").unwrap();
        assert!(params.id_token_hint.is_none());
        assert!(params.post_logout_redirect_uri.is_none());
        assert!(params.state.is_none());
        assert!(params.client_id.is_none());
    }

    #[test]
    fn test_end_session_params_deserialize_full() {
        let json = r#"{
            "id_token_hint": "eyJ...",
            "post_logout_redirect_uri": "https://example.com/logout-callback",
            "state": "abc123",
            "client_id": "my-client"
        }"#;
        let params: EndSessionParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.id_token_hint.unwrap(), "eyJ...");
        assert_eq!(
            params.post_logout_redirect_uri.unwrap(),
            "https://example.com/logout-callback"
        );
        assert_eq!(params.state.unwrap(), "abc123");
        assert_eq!(params.client_id.unwrap(), "my-client");
    }

    #[test]
    fn test_logout_response_serialization() {
        let response = LogoutResponse {
            message: "Logged out successfully".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"message\":\"Logged out successfully\""));
    }
}
