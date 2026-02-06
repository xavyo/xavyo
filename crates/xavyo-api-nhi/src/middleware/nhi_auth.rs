//! NHI (Non-Human Identity) Authentication middleware.
//!
//! F110 - Allows AI agents and service accounts to authenticate using their own
//! credentials (API keys/secrets) instead of user JWTs.
//!
//! This middleware:
//! 1. Extracts the Bearer token from the Authorization header
//! 2. Checks if it's an NHI credential (starts with "xnhi_")
//! 3. Validates the credential against the database
//! 4. Inserts `NhiAuthContext` into request extensions
//!
//! # Token Format
//!
//! NHI tokens have the format: `xnhi_<base64-encoded-random-bytes>`
//!
//! # Usage
//!
//! ```rust,ignore
//! use axum::{Router, routing::get, middleware};
//! use xavyo_api_nhi::middleware::nhi_auth_middleware;
//!
//! let router = Router::new()
//!     .route("/mcp/tools", get(list_tools))
//!     .layer(middleware::from_fn_with_state(credential_service, nhi_auth_middleware));
//! ```

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::{GovNhiCredential, NhiEntityType};

/// NHI credential validation service.
///
/// This is a re-export wrapper around the credential service for the middleware.
#[derive(Clone)]
pub struct NhiCredentialService {
    pool: PgPool,
}

impl NhiCredentialService {
    /// Create a new NHI credential service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Validate a credential and return the associated NHI information.
    ///
    /// Returns (`tenant_id`, `nhi_id`, `nhi_type`) if valid.
    pub async fn validate(
        &self,
        credential: &str,
    ) -> Result<(Uuid, Uuid, NhiEntityType), NhiAuthError> {
        // Find the credential by validating against stored hashes
        let credentials = GovNhiCredential::find_all_active_for_auth(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Database error during credential lookup: {}", e);
                NhiAuthError::Internal
            })?;

        // Validate the credential against each stored hash
        for cred in credentials {
            if cred.verify_credential(credential) {
                // Check if credential is within valid time window
                let now = chrono::Utc::now();
                if now < cred.valid_from {
                    continue; // Not yet valid
                }
                if now > cred.valid_until {
                    continue; // Expired
                }

                return Ok((cred.tenant_id, cred.nhi_id, cred.nhi_type));
            }
        }

        Err(NhiAuthError::InvalidCredential)
    }
}

/// Context inserted into request extensions after successful NHI authentication.
#[derive(Clone, Debug)]
pub struct NhiAuthContext {
    /// The credential ID that was used for authentication.
    pub credential_id: Uuid,
    /// The NHI ID (agent or service account ID).
    pub nhi_id: Uuid,
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The type of NHI (agent or service account).
    pub nhi_type: NhiEntityType,
}

/// NHI authentication errors.
#[derive(Debug, Clone)]
pub enum NhiAuthError {
    /// Missing Authorization header.
    MissingHeader,
    /// Invalid Authorization header format.
    InvalidFormat,
    /// Invalid or expired credential.
    InvalidCredential,
    /// Credential has been revoked.
    Revoked,
    /// Internal server error.
    Internal,
}

impl IntoResponse for NhiAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            NhiAuthError::MissingHeader => {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header")
            }
            NhiAuthError::InvalidFormat => (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header format",
            ),
            NhiAuthError::InvalidCredential => {
                (StatusCode::UNAUTHORIZED, "Invalid or expired credential")
            }
            NhiAuthError::Revoked => (StatusCode::UNAUTHORIZED, "Credential has been revoked"),
            NhiAuthError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error during authentication",
            ),
        };

        (status, message).into_response()
    }
}

/// NHI authentication middleware.
///
/// This middleware authenticates requests using NHI credentials (xnhi_...).
/// It supports both AI agents and service accounts.
///
/// After successful authentication, it inserts `NhiAuthContext` and `TenantId`
/// into the request extensions.
///
/// # Token Detection
///
/// The middleware only handles tokens that start with `xnhi_`. Other tokens
/// are passed through to the next middleware (e.g., JWT auth).
///
/// # Grace Period Support
///
/// During credential rotation, both the old and new credentials are valid
/// for a configurable grace period. This is handled by checking `is_active`
/// and `valid_until` fields.
pub async fn nhi_auth_middleware(
    State(service): State<Arc<NhiCredentialService>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract Bearer token from Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if let Some(token) = header.strip_prefix("Bearer ") {
                token
            } else {
                // Not a Bearer token, pass through to next middleware
                return Ok(next.run(request).await);
            }
        }
        None => {
            // No Authorization header, pass through to next middleware
            return Ok(next.run(request).await);
        }
    };

    // Check if this is an NHI credential (starts with "xnhi_")
    if !token.starts_with("xnhi_") {
        // Not an NHI credential, pass through to next middleware (e.g., JWT auth)
        return Ok(next.run(request).await);
    }

    // Validate the NHI credential
    let (tenant_id, nhi_id, nhi_type) = service.validate(token).await.map_err(|e| {
        tracing::warn!("NHI credential validation failed: {:?}", e);
        e.into_response()
    })?;

    // Create auth context
    // Note: We don't have credential_id here since we validated by hash
    // We could add a lookup to get the credential_id if needed
    let context = NhiAuthContext {
        credential_id: Uuid::nil(), // Not available in current flow
        nhi_id,
        tenant_id,
        nhi_type,
    };

    // Insert context into request extensions
    request.extensions_mut().insert(context);
    request
        .extensions_mut()
        .insert(TenantId::from_uuid(tenant_id));

    // Also insert raw UUIDs for handler compatibility
    request.extensions_mut().insert(tenant_id);
    request.extensions_mut().insert(nhi_id);

    tracing::debug!(
        nhi_id = %nhi_id,
        tenant_id = %tenant_id,
        nhi_type = ?nhi_type,
        "NHI authentication successful"
    );

    Ok(next.run(request).await)
}

/// Combined middleware that tries NHI auth first, then falls back to JWT.
///
/// This middleware allows routes to accept both NHI credentials and user JWTs.
/// It first checks if the token is an NHI credential (starts with "xnhi_"),
/// and if not, passes through to the JWT auth middleware.
///
/// # Usage
///
/// ```rust,ignore
/// let router = Router::new()
///     .route("/mcp/tools", get(list_tools))
///     .layer(middleware::from_fn_with_state(
///         (nhi_service, jwt_public_key),
///         combined_auth_middleware
///     ));
/// ```
#[allow(dead_code)] // Reserved for future route integration
pub async fn nhi_or_jwt_auth_middleware(
    State(service): State<Arc<NhiCredentialService>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract token to check type
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            if token.starts_with("xnhi_") {
                // NHI credential - use NHI auth
                return nhi_auth_middleware(State(service), request, next).await;
            }
        }
    }

    // Not an NHI credential - pass through (JWT middleware should handle it)
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_auth_error_responses() {
        let err = NhiAuthError::MissingHeader;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let err = NhiAuthError::InvalidCredential;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let err = NhiAuthError::Internal;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_nhi_auth_context_clone() {
        let context = NhiAuthContext {
            credential_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_type: NhiEntityType::Agent,
        };
        let cloned = context.clone();
        assert_eq!(cloned.nhi_id, context.nhi_id);
        assert_eq!(cloned.tenant_id, context.tenant_id);
    }

    #[test]
    fn test_nhi_credential_prefix() {
        // Test that NHI tokens start with the correct prefix
        let token = "xnhi_abc123";
        assert!(token.starts_with("xnhi_"));

        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
        assert!(!jwt.starts_with("xnhi_"));
    }
}
