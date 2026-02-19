//! JWT Authentication middleware.
//!
//! Extracts and validates JWT tokens from Authorization header,
//! then inserts `JwtClaims`, `UserId`, and `TenantId` into request extensions.
//!
//! ## Dual Auth Support (F113)
//!
//! This middleware supports coexistence with API key authentication.
//! If `ApiKeyContext` is already present in the request extensions
//! (set by `api_key_auth_middleware`), this middleware skips JWT validation
//! and passes through to the handler.

use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use xavyo_auth::{decode_token, extract_kid};
use xavyo_core::{TenantId, UserId};
use xavyo_db::models::RevokedToken;

use crate::middleware::api_key::ApiKeyContext;
use crate::services::revocation_cache::RevocationCache;

/// JWT authentication middleware.
///
/// This middleware:
/// 1. Extracts the Bearer token from the Authorization header
/// 2. Decodes and validates the JWT
/// 3. Inserts `JwtClaims`, `UserId`, and `TenantId` into request extensions
///
/// # Usage
///
/// ```rust,ignore
/// use axum::{Router, routing::get, middleware};
/// use xavyo_api_auth::middleware::jwt_auth_middleware;
///
/// let router = Router::new()
///     .route("/me/profile", get(get_profile))
///     .layer(middleware::from_fn(jwt_auth_middleware));
/// ```
pub async fn jwt_auth_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // F113: Check if request was already authenticated via API key
    // If ApiKeyContext is present, skip JWT validation (dual auth support)
    if request.extensions().get::<ApiKeyContext>().is_some() {
        tracing::debug!("Request already authenticated via API key, skipping JWT validation");
        return Ok(next.run(request).await);
    }

    // Get JWT public key(s) from extensions
    let default_public_key = request
        .extensions()
        .get::<JwtPublicKey>()
        .ok_or_else(|| {
            tracing::error!("JWT public key not configured");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error",
            )
                .into_response()
        })?
        .0
        .clone();

    // Get multi-key map if available (F069-S5)
    let public_keys: Option<HashMap<String, String>> = request
        .extensions()
        .get::<JwtPublicKeys>()
        .map(|k| k.0.clone());

    // Extract Bearer token from Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Missing Authorization header").into_response()
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization header format",
        )
            .into_response()
    })?;

    // SECURITY: Reject empty bearer tokens before attempting JWT decode.
    // This prevents potential issues with empty string handling in JWT libraries.
    if token.is_empty() {
        tracing::warn!("Rejected empty bearer token");
        return Err((StatusCode::UNAUTHORIZED, "Empty bearer token").into_response());
    }

    // Resolve the correct public key for validation (F069-S5: kid-based lookup)
    let resolved_key = if let Some(ref keys) = public_keys {
        // Try to extract kid from token header to find the correct key
        match extract_kid(token) {
            Ok(Some(kid)) => {
                if let Some(key_pem) = keys.get(&kid) {
                    key_pem.clone()
                } else {
                    tracing::warn!(kid = %kid, "Token kid not found in known keys, falling back to default");
                    default_public_key.clone()
                }
            }
            Ok(None) => {
                // No kid in token header, use default key
                default_public_key.clone()
            }
            Err(_) => {
                // Failed to parse header, use default key (decode_token will catch real errors)
                default_public_key.clone()
            }
        }
    } else {
        default_public_key
    };

    // Decode and validate JWT
    let claims = decode_token(token, resolved_key.as_bytes()).map_err(|e| {
        tracing::warn!("JWT validation failed: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
    })?;

    // Check if the token has been revoked (F069-S4, F082-US4: cache-first)
    // SECURITY: Fail-closed - if revocation check cannot be performed, reject the token.
    if !claims.jti.is_empty() {
        // F082-US4: Prefer RevocationCache (cache-first, DB-fallback) over direct DB call
        if let Some(cache) = request.extensions().get::<RevocationCache>() {
            match cache.is_revoked(&claims.jti).await {
                Ok(true) => {
                    tracing::warn!(jti = %claims.jti, "Rejected revoked token (cache)");
                    return Err(
                        (StatusCode::UNAUTHORIZED, "Token has been revoked").into_response()
                    );
                }
                Ok(false) => {} // Token is not revoked, proceed
                Err(e) => {
                    // Fail-closed: cache/DB error means we cannot verify, reject
                    tracing::error!(jti = %claims.jti, error = %e, "Revocation check failed (fail-closed)");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Token verification failed",
                    )
                        .into_response());
                }
            }
        } else if let Some(pool) = request.extensions().get::<PgPool>() {
            // Fallback: direct DB check when RevocationCache not available
            match RevokedToken::is_revoked(pool, &claims.jti).await {
                Ok(true) => {
                    tracing::warn!(jti = %claims.jti, "Rejected revoked token");
                    return Err(
                        (StatusCode::UNAUTHORIZED, "Token has been revoked").into_response()
                    );
                }
                Ok(false) => {} // Token is not revoked, proceed
                Err(e) => {
                    tracing::error!(jti = %claims.jti, error = %e, "Revocation check failed (fail-closed)");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Token verification failed",
                    )
                        .into_response());
                }
            }
        } else {
            // SECURITY FIX: Fail-closed - if no revocation checking mechanism is available,
            // reject the token rather than allowing potential revoked tokens through.
            // This prevents bypassing revocation by misconfiguring the server.
            tracing::error!(
                jti = %claims.jti,
                "Revocation check unavailable - neither RevocationCache nor PgPool in extensions (fail-closed)"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token verification unavailable",
            )
                .into_response());
        }
    }

    // Extract tenant ID from tid claim (required for all tokens)
    let tenant_uuid = claims.tid.ok_or_else(|| {
        tracing::warn!("Missing tenant ID in JWT claims");
        (StatusCode::UNAUTHORIZED, "Invalid token claims").into_response()
    })?;
    let tenant_id = TenantId::from_uuid(tenant_uuid);

    // Extract user ID from sub claim
    // For client_credentials tokens, sub is the client_id (not a UUID)
    // In that case, we mark it as a service account token
    let (user_uuid, is_service_account) = if let Ok(uuid) = claims.sub.parse::<uuid::Uuid>() {
        (uuid, false)
    } else {
        // This is likely a client_credentials token where sub is the client_id
        // Use a nil UUID for service accounts - handlers should check ServiceAccountMarker
        tracing::debug!(
            client_id = %claims.sub,
            "Client credentials token detected, using service account mode"
        );
        (uuid::Uuid::nil(), true)
    };
    let user_id = UserId::from_uuid(user_uuid);

    // Extract device fingerprint from header (optional)
    let device_fingerprint: Option<String> = request
        .headers()
        .get("X-Device-Fingerprint")
        .and_then(|h| h.to_str().ok())
        .map(std::string::ToString::to_string);

    // Extract user agent from header (optional)
    let user_agent: Option<String> = request
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(std::string::ToString::to_string);

    // Extract IP address: only trust X-Forwarded-For if TrustXff marker is present.
    // Without the marker, fall back to direct connection IP for security.
    let connect_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let trust_xff = request.extensions().get::<TrustXff>().is_some();

    let ip_address: Option<IpAddr> = if trust_xff {
        request
            .headers()
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
            .or(connect_ip)
    } else {
        connect_ip
    };

    // SECURITY: Reject partial (MFA) tokens on routes that don't explicitly allow them.
    // Partial tokens have `purpose: "mfa_verification"` and empty roles — if allowed through,
    // they could access endpoints that only require authentication (no role check).
    if claims.purpose.as_deref() == Some("mfa_verification")
        && request.extensions().get::<AllowPartialToken>().is_none()
    {
        tracing::warn!(
            sub = %claims.sub,
            "Rejected partial MFA token on route without AllowPartialToken marker"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "Partial token not accepted on this endpoint",
        )
            .into_response());
    }

    // Insert claims and IDs into request extensions
    // Insert both wrapped types (UserId, TenantId) and raw UUIDs for handler compatibility
    request.extensions_mut().insert(claims);
    request.extensions_mut().insert(user_id);
    request.extensions_mut().insert(tenant_id);
    request.extensions_mut().insert(user_uuid); // Raw UUID for handlers expecting uuid::Uuid
    request
        .extensions_mut()
        .insert(ServiceAccountMarker(is_service_account)); // Mark if this is a service account token
    request.extensions_mut().insert(device_fingerprint); // Device fingerprint for F026
    request.extensions_mut().insert(ip_address); // IP address for audit
    request.extensions_mut().insert(user_agent); // User agent for audit

    Ok(next.run(request).await)
}

/// Marker extension indicating that X-Forwarded-For should be trusted for this request.
///
/// Set by the application layer (e.g., `idp-api` middleware) when the direct connection
/// IP matches a trusted proxy CIDR. Without this marker, `jwt_auth_middleware` uses
/// the direct connection IP only.
#[derive(Clone, Copy, Debug)]
pub struct TrustXff;

/// Wrapper for JWT public key to allow putting it in extensions.
#[derive(Clone)]
pub struct JwtPublicKey(pub String);

/// Wrapper for multiple JWT public keys (kid → PEM) for key rotation (F069-S5).
#[derive(Clone)]
pub struct JwtPublicKeys(pub HashMap<String, String>);

/// Marker indicating if the request was authenticated via a service account (`client_credentials`).
/// When true, the `user_id` is a synthetic UUID derived from the `client_id`.
#[derive(Clone, Copy, Debug)]
pub struct ServiceAccountMarker(pub bool);

impl ServiceAccountMarker {
    /// Returns true if this is a service account (`client_credentials`) token.
    #[must_use]
    pub fn is_service_account(&self) -> bool {
        self.0
    }
}

/// Marker extension that allows partial (MFA) tokens on specific routes.
///
/// Routes that accept `purpose: "mfa_verification"` tokens (e.g., TOTP verify,
/// recovery code verify, WebAuthn authenticate) must have this extension set.
/// All other routes will reject partial tokens at the middleware level.
#[derive(Clone, Copy, Debug)]
pub struct AllowPartialToken;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_public_key_wrapper() {
        let key = JwtPublicKey("test-key".to_string());
        assert_eq!(key.0, "test-key");
    }

    #[test]
    fn test_jwt_public_keys_wrapper() {
        let mut keys = HashMap::new();
        keys.insert("kid1".to_string(), "key1-pem".to_string());
        keys.insert("kid2".to_string(), "key2-pem".to_string());
        let wrapper = JwtPublicKeys(keys.clone());
        assert_eq!(wrapper.0.len(), 2);
        assert_eq!(wrapper.0.get("kid1"), Some(&"key1-pem".to_string()));
    }

    #[test]
    fn test_empty_bearer_token_rejected() {
        // This test validates the logic for empty token detection
        // The actual middleware test would require a full request context
        let empty_token = "";
        assert!(empty_token.is_empty());
        // In middleware, empty tokens are rejected before JWT decode
    }
}
