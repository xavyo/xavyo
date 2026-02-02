//! API Key Authentication middleware.
//!
//! Extracts and validates API keys from Authorization header,
//! then inserts TenantId, UserId, and ApiKeyContext into request extensions.
//!
//! # Key Format
//!
//! API keys use the prefix `xavyo_sk_` followed by a random suffix.
//! The full key is hashed with SHA-256 for database lookup.
//!
//! # Usage
//!
//! ```rust,ignore
//! use axum::{Router, routing::get, middleware};
//! use xavyo_api_auth::middleware::api_key_auth_middleware;
//!
//! let router = Router::new()
//!     .route("/v1/agents", get(list_agents))
//!     .layer(middleware::from_fn(api_key_auth_middleware));
//! ```
//!
//! # Dual Auth Support
//!
//! This middleware passes through requests that don't have an API key
//! (no `xavyo_sk_` prefix), allowing JWT middleware to handle them:
//!
//! ```rust,ignore
//! let router = Router::new()
//!     .route("/v1/agents", get(list_agents))
//!     .layer(middleware::from_fn(api_key_auth_middleware))
//!     .layer(middleware::from_fn(jwt_auth_middleware));
//! ```

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::{TenantId, UserId};
use xavyo_db::models::ApiKey;

/// API key prefix for xavyo API keys.
const API_KEY_PREFIX: &str = "xavyo_sk_";

/// Minimum interval (in seconds) between `last_used_at` updates.
///
/// This debouncing reduces database writes while still providing
/// meaningful usage tracking. Set to 60 seconds by default.
const LAST_USED_DEBOUNCE_SECS: i64 = 60;

/// Timeout (in seconds) for the async `last_used_at` update.
///
/// Prevents the update from blocking indefinitely during graceful shutdown.
const LAST_USED_UPDATE_TIMEOUT_SECS: u64 = 5;

/// Context information extracted from a valid API key.
///
/// This is inserted into request extensions for handlers that need
/// API key metadata like scopes.
#[derive(Clone, Debug)]
pub struct ApiKeyContext {
    /// The API key's unique identifier.
    pub key_id: Uuid,
    /// Human-readable name of the API key.
    pub key_name: String,
    /// Allowed API scopes (empty means all scopes).
    pub scopes: Vec<String>,
}

/// Errors that can occur during API key authentication.
#[derive(Debug, Clone)]
pub enum ApiKeyError {
    /// Authorization header is missing.
    MissingAuthHeader,
    /// Authorization header format is invalid (not "Bearer <token>").
    InvalidFormat,
    /// The API key was not found in the database.
    NotFound,
    /// The API key has expired.
    Expired,
    /// The API key has been revoked (is_active = false).
    Revoked,
    /// The API key's tenant doesn't match X-Tenant-ID header.
    TenantMismatch,
    /// Database or infrastructure error.
    InternalError,
}

impl IntoResponse for ApiKeyError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiKeyError::MissingAuthHeader => {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header")
            }
            ApiKeyError::InvalidFormat => (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header format",
            ),
            // Use generic message for NotFound to prevent key enumeration
            ApiKeyError::NotFound => (StatusCode::UNAUTHORIZED, "Invalid API key"),
            ApiKeyError::Expired => (StatusCode::UNAUTHORIZED, "API key has expired"),
            ApiKeyError::Revoked => (StatusCode::UNAUTHORIZED, "API key has been revoked"),
            ApiKeyError::TenantMismatch => (StatusCode::UNAUTHORIZED, "Tenant mismatch"),
            ApiKeyError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication service unavailable",
            ),
        };

        let body = serde_json::json!({
            "error": "unauthorized",
            "message": message
        });

        (status, axum::Json(body)).into_response()
    }
}

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(request: &Request<Body>) -> Option<&str> {
    request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

/// Check if a token is an API key (starts with `xavyo_sk_`).
fn is_api_key(token: &str) -> bool {
    token.starts_with(API_KEY_PREFIX)
}

/// Compute the SHA-256 hash of an API key for database lookup.
fn compute_key_hash(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extract tenant ID from X-Tenant-ID header if present.
fn extract_tenant_header(request: &Request<Body>) -> Option<Uuid> {
    request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<Uuid>().ok())
}

/// Validate an API key against the database.
///
/// Returns the ApiKey record if valid, or an appropriate error.
async fn validate_api_key(
    pool: &PgPool,
    token: &str,
    tenant_header: Option<Uuid>,
) -> Result<ApiKey, ApiKeyError> {
    let key_hash = compute_key_hash(token);

    // Look up the key by hash
    let api_key = ApiKey::find_by_hash(pool, &key_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error during API key lookup");
            ApiKeyError::InternalError
        })?
        .ok_or_else(|| {
            tracing::warn!("API key not found (hash lookup failed)");
            ApiKeyError::NotFound
        })?;

    // Check if key is active
    if !api_key.is_active {
        tracing::warn!(key_id = %api_key.id, "Rejected revoked API key");
        return Err(ApiKeyError::Revoked);
    }

    // Check if key is expired
    if let Some(expires_at) = api_key.expires_at {
        if chrono::Utc::now() > expires_at {
            tracing::warn!(key_id = %api_key.id, "Rejected expired API key");
            return Err(ApiKeyError::Expired);
        }
    }

    // Validate tenant header if provided
    if let Some(header_tenant) = tenant_header {
        if header_tenant != api_key.tenant_id {
            tracing::warn!(
                key_id = %api_key.id,
                key_tenant = %api_key.tenant_id,
                header_tenant = %header_tenant,
                "API key tenant mismatch with X-Tenant-ID header"
            );
            return Err(ApiKeyError::TenantMismatch);
        }
    }

    Ok(api_key)
}

/// API key authentication middleware.
///
/// This middleware:
/// 1. Extracts the Bearer token from the Authorization header
/// 2. If the token starts with `xavyo_sk_`, validates it as an API key
/// 3. If valid, inserts TenantId, UserId, and ApiKeyContext into request extensions
/// 4. If the token is not an API key, passes through to allow JWT middleware to handle it
///
/// # Dual Auth Support
///
/// When a request contains a non-API-key token (e.g., JWT), this middleware
/// passes the request through unchanged. Stack this middleware before JWT
/// middleware to support both authentication methods:
///
/// ```rust,ignore
/// let router = Router::new()
///     .route("/v1/agents", get(list_agents))
///     .layer(middleware::from_fn(api_key_auth_middleware))
///     .layer(middleware::from_fn(jwt_auth_middleware));
/// ```
///
/// # Required Extensions
///
/// The router must have `PgPool` in its extensions for database access.
pub async fn api_key_auth_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract Bearer token
    let token = match extract_bearer_token(&request) {
        Some(t) => t,
        None => {
            // No Authorization header - pass through for JWT middleware or return error
            // For dual-auth support, we pass through to let JWT middleware handle
            return Ok(next.run(request).await);
        }
    };

    // Check if this is an API key
    if !is_api_key(token) {
        // Not an API key - pass through for JWT middleware to handle
        tracing::debug!("Token is not an API key, passing through to next middleware");
        return Ok(next.run(request).await);
    }

    // Reject empty API key suffix
    if token.len() <= API_KEY_PREFIX.len() {
        tracing::warn!("Rejected empty API key suffix");
        return Err(ApiKeyError::InvalidFormat.into_response());
    }

    // Get database pool from extensions
    let pool = request
        .extensions()
        .get::<PgPool>()
        .ok_or_else(|| {
            tracing::error!("PgPool not configured in router extensions");
            ApiKeyError::InternalError.into_response()
        })?
        .clone();

    // Extract tenant header if present
    let tenant_header = extract_tenant_header(&request);

    // Validate the API key
    let api_key = validate_api_key(&pool, token, tenant_header)
        .await
        .map_err(|e| e.into_response())?;

    // Log successful authentication
    tracing::debug!(
        key_id = %api_key.id,
        tenant_id = %api_key.tenant_id,
        user_id = %api_key.user_id,
        key_name = %api_key.name,
        "API key authentication successful"
    );

    // Create context for handlers
    let api_key_context = ApiKeyContext {
        key_id: api_key.id,
        key_name: api_key.name.clone(),
        scopes: api_key.scopes.clone(),
    };

    // Insert extensions
    let tenant_id = TenantId::from_uuid(api_key.tenant_id);
    let user_id = UserId::from_uuid(api_key.user_id);

    // F113: Create synthetic JwtClaims for handler compatibility
    // Many handlers extract tenant_id/user_id from JwtClaims extension
    // This allows API key authentication to work with existing handlers
    let now = Utc::now().timestamp();
    let synthetic_claims = JwtClaims {
        sub: api_key.user_id.to_string(),
        iss: "xavyo-api-key".to_string(),
        aud: vec!["xavyo-api".to_string()],
        exp: now + 86400, // Claims valid for 24h (though API key validity is checked at auth time)
        iat: now,
        jti: format!("api-key-{}", api_key.id),
        tid: Some(api_key.tenant_id),
        roles: vec!["api_key".to_string()], // Special role to indicate API key auth
        purpose: None,
        email: None,
    };

    request.extensions_mut().insert(synthetic_claims);
    request.extensions_mut().insert(tenant_id);
    request.extensions_mut().insert(user_id);
    // F113: Removed duplicate raw UUID insertions - use typed TenantId/UserId instead
    // Raw Uuid extensions were causing ambiguity (second insert overwrites first)
    request.extensions_mut().insert(api_key_context);
    request.extensions_mut().insert(api_key.clone()); // Full ApiKey for advanced use cases

    // Update last_used_at asynchronously with debouncing
    // F113: Only update if enough time has passed since last update to reduce DB writes
    let should_update = api_key.last_used_at.is_none_or(|last_used| {
        let elapsed = Utc::now().signed_duration_since(last_used);
        elapsed.num_seconds() > LAST_USED_DEBOUNCE_SECS
    });

    if should_update {
        let key_id = api_key.id;
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            // Timeout to prevent blocking during graceful shutdown
            match tokio::time::timeout(
                std::time::Duration::from_secs(LAST_USED_UPDATE_TIMEOUT_SECS),
                ApiKey::update_last_used(&pool_clone, key_id),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::debug!(key_id = %key_id, "Updated API key last_used_at");
                }
                Ok(Err(e)) => {
                    tracing::warn!(key_id = %key_id, error = %e, "Failed to update API key last_used_at");
                }
                Err(_) => {
                    tracing::warn!(key_id = %key_id, "API key last_used_at update timed out");
                }
            }
        });
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token_valid() {
        use axum::http::Request;

        let request = Request::builder()
            .header("Authorization", "Bearer xavyo_sk_abc123")
            .body(Body::empty())
            .unwrap();

        let token = extract_bearer_token(&request);
        assert_eq!(token, Some("xavyo_sk_abc123"));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        use axum::http::Request;

        let request = Request::builder().body(Body::empty()).unwrap();

        let token = extract_bearer_token(&request);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        use axum::http::Request;

        let request = Request::builder()
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let token = extract_bearer_token(&request);
        assert_eq!(token, None);
    }

    #[test]
    fn test_is_api_key_valid() {
        assert!(is_api_key("xavyo_sk_abc123def456"));
        assert!(is_api_key("xavyo_sk_a"));
    }

    #[test]
    fn test_is_api_key_invalid() {
        assert!(!is_api_key("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(!is_api_key("Bearer xavyo_sk_abc123"));
        assert!(!is_api_key("sk_abc123"));
        assert!(!is_api_key(""));
    }

    #[test]
    fn test_compute_key_hash() {
        let hash = compute_key_hash("xavyo_sk_test123");
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        // Verify deterministic
        assert_eq!(hash, compute_key_hash("xavyo_sk_test123"));
        // Different inputs produce different hashes
        assert_ne!(hash, compute_key_hash("xavyo_sk_test456"));
    }

    #[test]
    fn test_api_key_error_responses() {
        // Test that errors produce correct status codes
        let missing = ApiKeyError::MissingAuthHeader.into_response();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let not_found = ApiKeyError::NotFound.into_response();
        assert_eq!(not_found.status(), StatusCode::UNAUTHORIZED);

        let expired = ApiKeyError::Expired.into_response();
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);

        let revoked = ApiKeyError::Revoked.into_response();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);

        let internal = ApiKeyError::InternalError.into_response();
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_api_key_context_clone() {
        let ctx = ApiKeyContext {
            key_id: Uuid::new_v4(),
            key_name: "Test Key".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let cloned = ctx.clone();
        assert_eq!(ctx.key_id, cloned.key_id);
        assert_eq!(ctx.key_name, cloned.key_name);
        assert_eq!(ctx.scopes, cloned.scopes);
    }
}
