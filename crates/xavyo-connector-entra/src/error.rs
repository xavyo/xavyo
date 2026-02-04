//! Error types for the Entra ID connector.

use thiserror::Error;

/// Result type alias using `EntraError`.
pub type EntraResult<T> = Result<T, EntraError>;

/// Errors that can occur when interacting with Entra ID.
#[derive(Debug, Error)]
pub enum EntraError {
    /// Configuration validation error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// `OAuth2` authentication error.
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Token refresh failed.
    #[error("Token refresh failed: {0}")]
    TokenRefresh(String),

    /// Microsoft Graph API error.
    #[error("Graph API error: {code} - {message}")]
    GraphApi {
        code: String,
        message: String,
        inner_error: Option<String>,
    },

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Sync operation error.
    #[error("Sync error: {0}")]
    Sync(String),

    /// Provisioning operation error.
    #[error("Provisioning error: {0}")]
    Provisioning(String),

    /// Delta token expired or invalid.
    #[error("Delta token expired, full sync required")]
    DeltaTokenExpired,

    /// Connection test failed.
    #[error("Connection test failed: {0}")]
    ConnectionTest(String),

    /// Resource not found.
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Circuit breaker is open, requests are being rejected.
    #[error("Circuit breaker open, failing fast")]
    CircuitOpen,

    /// Request queue is full.
    #[error("Request queue full ({queue_depth} requests pending)")]
    QueueFull { queue_depth: usize },

    /// Maximum retry attempts exceeded.
    #[error("Maximum retries ({attempts}) exceeded for rate limit")]
    MaxRetriesExceeded { attempts: u32 },
}
