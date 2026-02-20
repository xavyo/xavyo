//! Error types for OIDC Federation.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// Result type for federation operations.
pub type FederationResult<T> = Result<T, FederationError>;

/// Federation error types.
#[derive(Debug, Error)]
pub enum FederationError {
    // Configuration errors
    #[error("Identity provider not found: {0}")]
    IdpNotFound(Uuid),

    #[error("Identity provider is disabled: {0}")]
    IdpDisabled(Uuid),

    #[error("Invalid IdP configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Discovery failed for issuer {issuer}: {message}")]
    DiscoveryFailed { issuer: String, message: String },

    #[error("IdP validation failed: {0}")]
    ValidationFailed(String),

    // Authentication flow errors
    #[error("Authentication session not found or expired")]
    SessionNotFound,

    #[error("Invalid state parameter")]
    InvalidState,

    #[error("PKCE verification failed")]
    PkceVerificationFailed,

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("ID token validation failed: {0}")]
    IdTokenValidationFailed(String),

    #[error("Authentication failed at IdP: {error}")]
    IdpAuthenticationFailed {
        error: String,
        description: Option<String>,
    },

    // User provisioning errors
    #[error("Required claim missing: {0}")]
    RequiredClaimMissing(String),

    #[error("User provisioning failed: {0}")]
    ProvisioningFailed(String),

    #[error("User already linked to different IdP")]
    UserAlreadyLinked,

    // Domain/HRD errors
    #[error("Domain not configured for any IdP: {0}")]
    DomainNotConfigured(String),

    #[error("Domain already exists: {0}")]
    DomainAlreadyExists(String),

    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),

    // Security errors
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    // Infrastructure errors
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    // Authorization errors
    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    // Conflict errors
    #[error("Cannot delete IdP: {0} users are still linked")]
    IdpHasLinkedUsers(i64),

    #[error("Issuer URL already configured for this tenant")]
    IssuerAlreadyExists,

    // Additional auth flow errors
    #[error("Session has expired")]
    SessionExpired,

    #[error("IdP returned error: {error} - {description}")]
    IdpError { error: String, description: String },

    #[error("Invalid callback: {0}")]
    InvalidCallback(String),

    #[error("Invalid ID token: {0}")]
    InvalidIdToken(String),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    #[error("Failed to issue tokens: {0}")]
    TokenIssueFailed(String),

    #[error("Identity link not found")]
    LinkNotFound,

    #[error("Invalid email address: {0}")]
    InvalidEmail(String),

    #[error("Invalid claim mapping: {0}")]
    InvalidClaimMapping(String),

    #[error("Missing required claim: {0}")]
    MissingRequiredClaim(String),

    // JWT verification errors (F-045)
    #[error("Token verification failed: {0}")]
    TokenVerificationFailed(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid issuer: {0}")]
    InvalidIssuer(String),

    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchFailed(String),

    #[error("JWKS key not found: {0}")]
    JwksKeyNotFound(String),
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for FederationError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            // 400 Bad Request
            FederationError::InvalidConfiguration(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_configuration",
                msg.clone(),
            ),
            FederationError::InvalidState => (
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "Invalid state parameter".to_string(),
            ),
            FederationError::InvalidDomain(domain) => (
                StatusCode::BAD_REQUEST,
                "invalid_domain",
                format!("Invalid domain format: {domain}"),
            ),
            FederationError::RequiredClaimMissing(claim) => (
                StatusCode::BAD_REQUEST,
                "required_claim_missing",
                format!("Required claim missing: {claim}"),
            ),

            // 401 Unauthorized
            FederationError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required".to_string(),
            ),
            FederationError::SessionNotFound => (
                StatusCode::UNAUTHORIZED,
                "session_expired",
                "Authentication session not found or expired".to_string(),
            ),
            FederationError::IdpAuthenticationFailed { error, description } => {
                // SECURITY: Log IdP-provided details internally but return generic message.
                tracing::warn!(
                    idp_error = %error,
                    idp_description = ?description,
                    "IdP authentication failed (details not reflected to client)"
                );
                (
                    StatusCode::UNAUTHORIZED,
                    "authentication_failed",
                    "Authentication failed at identity provider".to_string(),
                )
            }

            // 403 Forbidden
            FederationError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            FederationError::IdpDisabled(_id) => {
                // R9: Don't leak IdP UUID to unauthenticated callers
                tracing::debug!(idp_id = %_id, "IdP is disabled");
                (
                    StatusCode::FORBIDDEN,
                    "idp_disabled",
                    "Identity provider is disabled".to_string(),
                )
            }

            // 404 Not Found
            FederationError::IdpNotFound(id) => (
                StatusCode::NOT_FOUND,
                "idp_not_found",
                format!("Identity provider {id} not found"),
            ),
            FederationError::DomainNotConfigured(_domain) => (
                StatusCode::NOT_FOUND,
                "domain_not_configured",
                "Domain not configured for any identity provider".to_string(),
            ),

            // 409 Conflict
            FederationError::DomainAlreadyExists(domain) => (
                StatusCode::CONFLICT,
                "domain_exists",
                format!("Domain {domain} is already configured"),
            ),
            FederationError::UserAlreadyLinked => (
                StatusCode::CONFLICT,
                "user_already_linked",
                "User is already linked to a different IdP".to_string(),
            ),
            FederationError::IdpHasLinkedUsers(count) => (
                StatusCode::CONFLICT,
                "idp_has_users",
                format!("Cannot delete IdP: {count} users are still linked"),
            ),
            FederationError::IssuerAlreadyExists => (
                StatusCode::CONFLICT,
                "issuer_exists",
                "Issuer URL is already configured for this tenant".to_string(),
            ),

            // 422 Unprocessable Entity
            FederationError::DiscoveryFailed { issuer, message } => {
                tracing::warn!("Discovery failed for {issuer}: {message}");
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "discovery_failed",
                    "Failed to discover OIDC endpoints for the configured issuer".to_string(),
                )
            }
            FederationError::ValidationFailed(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                msg.clone(),
            ),
            FederationError::TokenExchangeFailed(msg) => {
                tracing::error!("Token exchange failed: {}", msg);
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "token_exchange_failed",
                    "Token exchange with identity provider failed".to_string(),
                )
            }
            FederationError::IdTokenValidationFailed(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "id_token_invalid",
                msg.clone(),
            ),
            FederationError::PkceVerificationFailed => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "pkce_failed",
                "PKCE verification failed".to_string(),
            ),
            FederationError::ProvisioningFailed(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "provisioning_failed",
                msg.clone(),
            ),
            FederationError::InvalidIdToken(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_id_token",
                msg.clone(),
            ),
            FederationError::InvalidClaimMapping(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_claim_mapping",
                msg.clone(),
            ),
            FederationError::MissingRequiredClaim(claim) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "missing_required_claim",
                format!("Missing required claim: {claim}"),
            ),
            FederationError::InvalidEmail(email) => {
                // SECURITY: Do not reflect user-supplied email in error response (content injection risk).
                tracing::debug!(email_input = ?email, "Invalid email address submitted");
                (
                    StatusCode::BAD_REQUEST,
                    "invalid_email",
                    "Invalid email address format".to_string(),
                )
            }
            FederationError::InvalidCallback(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_callback", msg.clone())
            }
            FederationError::IdpError { error, description } => {
                // SECURITY: Never reflect IdP-controlled error/description in response body.
                // Use Debug format (?), not Display (%), to prevent log injection via ANSI codes/newlines.
                tracing::warn!(
                    idp_error = ?error,
                    idp_description = ?description,
                    "IdP returned error (not reflected to client)"
                );
                (
                    StatusCode::BAD_REQUEST,
                    "idp_error",
                    "The identity provider returned an error".to_string(),
                )
            }
            FederationError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                "session_expired",
                "Authentication session has expired".to_string(),
            ),
            FederationError::UserNotFound(id) => (
                StatusCode::NOT_FOUND,
                "user_not_found",
                format!("User {id} not found"),
            ),
            FederationError::LinkNotFound => (
                StatusCode::NOT_FOUND,
                "link_not_found",
                "Identity link not found".to_string(),
            ),
            FederationError::TokenIssueFailed(msg) => {
                tracing::error!("Token issue failed: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "token_issue_failed",
                    "Failed to issue tokens".to_string(),
                )
            }
            FederationError::TokenVerificationFailed(msg) => {
                tracing::warn!("Token verification failed: {}", msg);
                (
                    StatusCode::UNAUTHORIZED,
                    "token_verification_failed",
                    "Token verification failed".to_string(),
                )
            }
            FederationError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "token_expired",
                "Token has expired".to_string(),
            ),
            FederationError::InvalidIssuer(iss) => {
                // SECURITY: Do not echo attacker-controlled issuer string in response.
                tracing::warn!(issuer = ?iss, "Invalid or untrusted issuer");
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid_issuer",
                    "Invalid or untrusted issuer".to_string(),
                )
            }
            FederationError::JwksFetchFailed(msg) => {
                tracing::error!("JWKS fetch failed: {}", msg);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "jwks_fetch_failed",
                    "Failed to fetch identity provider keys".to_string(),
                )
            }
            FederationError::JwksKeyNotFound(kid) => {
                // SECURITY: Do not echo attacker-controlled kid value in response.
                tracing::warn!(kid = ?kid, "JWKS signing key not found");
                (
                    StatusCode::UNAUTHORIZED,
                    "jwks_key_not_found",
                    "Signing key not found".to_string(),
                )
            }

            // 500 Internal Server Error
            FederationError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Database error occurred".to_string(),
                )
            }
            FederationError::HttpRequest(msg) => {
                tracing::error!("HTTP request error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "http_error",
                    "Failed to communicate with external service".to_string(),
                )
            }
            FederationError::EncryptionFailed(msg) => {
                tracing::error!("Encryption error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "encryption_error",
                    "Security operation failed".to_string(),
                )
            }
            FederationError::DecryptionFailed(msg) => {
                tracing::error!("Decryption error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "decryption_error",
                    "Security operation failed".to_string(),
                )
            }
            FederationError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error".to_string(),
                )
            }
        };

        let body = ErrorResponse {
            error: error_code.to_string(),
            message,
            details: None,
        };

        (status, Json(body)).into_response()
    }
}

impl From<reqwest::Error> for FederationError {
    fn from(err: reqwest::Error) -> Self {
        FederationError::HttpRequest(err.to_string())
    }
}
