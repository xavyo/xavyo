//! Social authentication error types.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// Provider type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    Google,
    Microsoft,
    Apple,
    Github,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Google => write!(f, "google"),
            ProviderType::Microsoft => write!(f, "microsoft"),
            ProviderType::Apple => write!(f, "apple"),
            ProviderType::Github => write!(f, "github"),
        }
    }
}

impl std::str::FromStr for ProviderType {
    type Err = SocialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(ProviderType::Google),
            "microsoft" => Ok(ProviderType::Microsoft),
            "apple" => Ok(ProviderType::Apple),
            "github" => Ok(ProviderType::Github),
            _ => Err(SocialError::InvalidProvider {
                provider: s.to_string(),
            }),
        }
    }
}

/// Social authentication errors.
#[derive(Debug, Error)]
pub enum SocialError {
    #[error("Provider '{provider}' is not available or disabled for this tenant")]
    ProviderUnavailable { provider: ProviderType },

    #[error("Invalid provider: {provider}")]
    InvalidProvider { provider: String },

    #[error("Invalid OAuth callback: {reason}")]
    InvalidCallback { reason: String },

    #[error("Token exchange failed with provider {provider}: HTTP {status}")]
    TokenExchangeFailed { provider: ProviderType, status: u16 },

    #[error("Failed to fetch user info from {provider}")]
    UserInfoFailed { provider: ProviderType },

    #[error("Account linking required: email already exists for user {existing_user_id}")]
    AccountLinkingRequired {
        existing_user_id: Uuid,
        /// SECURITY: email stored for internal use only; never exposed in Display/logs.
        email: String,
    },

    #[error("Social account already linked to another user")]
    AlreadyLinkedToOther,

    #[error("Cannot unlink: {reason}")]
    UnlinkForbidden { reason: String },

    #[error("Social connection not found")]
    ConnectionNotFound,

    #[error("Encryption error: {operation}")]
    EncryptionError { operation: String },

    #[error("Invalid state parameter: {reason}")]
    InvalidState { reason: String },

    #[error("PKCE verification failed")]
    PkceVerificationFailed,

    #[error("Provider configuration error: {message}")]
    ConfigurationError { message: String },

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("HTTP client error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {message}")]
    InternalError { message: String },
}

/// Error response structure for API responses.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SocialError {
    /// Get the error code for API responses.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            SocialError::ProviderUnavailable { .. } => "provider_unavailable",
            SocialError::InvalidProvider { .. } => "invalid_provider",
            SocialError::InvalidCallback { .. } => "invalid_callback",
            SocialError::TokenExchangeFailed { .. } => "token_exchange_failed",
            SocialError::UserInfoFailed { .. } => "user_info_failed",
            SocialError::AccountLinkingRequired { .. } => "account_linking_required",
            SocialError::AlreadyLinkedToOther => "already_linked",
            SocialError::UnlinkForbidden { .. } => "unlink_forbidden",
            SocialError::ConnectionNotFound => "connection_not_found",
            SocialError::EncryptionError { .. } => "encryption_error",
            SocialError::InvalidState { .. } => "invalid_state",
            SocialError::PkceVerificationFailed => "pkce_failed",
            SocialError::ConfigurationError { .. } => "configuration_error",
            SocialError::DatabaseError(_) => "database_error",
            SocialError::HttpError(_) => "http_error",
            SocialError::JsonError(_) => "json_error",
            SocialError::JwtError(_) => "jwt_error",
            SocialError::InternalError { .. } => "internal_error",
        }
    }

    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            SocialError::ProviderUnavailable { .. } => StatusCode::FORBIDDEN,
            SocialError::InvalidProvider { .. } => StatusCode::BAD_REQUEST,
            SocialError::InvalidCallback { .. } => StatusCode::BAD_REQUEST,
            SocialError::TokenExchangeFailed { .. } => StatusCode::BAD_GATEWAY,
            SocialError::UserInfoFailed { .. } => StatusCode::BAD_GATEWAY,
            SocialError::AccountLinkingRequired { .. } => StatusCode::CONFLICT,
            SocialError::AlreadyLinkedToOther => StatusCode::CONFLICT,
            SocialError::UnlinkForbidden { .. } => StatusCode::FORBIDDEN,
            SocialError::ConnectionNotFound => StatusCode::NOT_FOUND,
            SocialError::EncryptionError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SocialError::InvalidState { .. } => StatusCode::BAD_REQUEST,
            SocialError::PkceVerificationFailed => StatusCode::BAD_REQUEST,
            SocialError::ConfigurationError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SocialError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SocialError::HttpError(_) => StatusCode::BAD_GATEWAY,
            SocialError::JsonError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SocialError::JwtError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SocialError::InternalError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for SocialError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // Security: never expose PII (like email) in error responses.
        let details: Option<serde_json::Value> = None;
        let message = match &self {
            SocialError::DatabaseError(e) => {
                tracing::error!("Social database error: {:?}", e);
                "A database error occurred".to_string()
            }
            SocialError::HttpError(e) => {
                tracing::error!("Social HTTP error: {:?}", e);
                "An HTTP client error occurred".to_string()
            }
            SocialError::JsonError(e) => {
                tracing::error!("Social JSON error: {:?}", e);
                "A data processing error occurred".to_string()
            }
            SocialError::JwtError(e) => {
                tracing::error!("Social JWT error: {:?}", e);
                "A token processing error occurred".to_string()
            }
            SocialError::InternalError { message } => {
                tracing::error!("Social internal error: {}", message);
                "An internal error occurred".to_string()
            }
            SocialError::EncryptionError { operation } => {
                tracing::error!("Social encryption error: {}", operation);
                "An encryption error occurred".to_string()
            }
            SocialError::ConfigurationError { .. } => {
                tracing::error!("Social configuration error");
                "A provider configuration error occurred".to_string()
            }
            // SECURITY: AccountLinkingRequired contains email address in the error variant.
            // Never expose the email in the HTTP response — return a generic message instead.
            SocialError::AccountLinkingRequired {
                existing_user_id,
                email: _,
            } => {
                tracing::info!(
                    target: "social_auth",
                    user_id = %existing_user_id,
                    "Account linking required for existing user (email not logged for privacy)"
                );
                // Generic message without email to prevent PII leakage
                "An account with this email already exists. Please link your accounts.".to_string()
            }
            // SECURITY: Sanitize errors that may contain IdP-controlled or library-internal details.
            SocialError::InvalidCallback { .. } => "Invalid OAuth callback".to_string(),
            SocialError::InvalidState { reason } => {
                tracing::warn!("Invalid OAuth state: {}", reason);
                "Invalid or expired state parameter".to_string()
            }
            SocialError::TokenExchangeFailed { provider, status } => {
                tracing::warn!(provider = %provider, status = %status, "Token exchange failed");
                format!("Token exchange failed with {provider}")
            }
            SocialError::UserInfoFailed { provider } => {
                format!("Failed to fetch user info from {provider}")
            }
            _ => self.to_string(),
        };
        let body = ErrorResponse {
            error: self.error_code().to_string(),
            message,
            details,
        };

        (status, axum::Json(body)).into_response()
    }
}

/// Result type alias for social operations.
pub type SocialResult<T> = Result<T, SocialError>;
