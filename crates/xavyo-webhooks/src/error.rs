//! Error types for the webhook system.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Webhook system error variants.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("SSRF protection: {0}")]
    SsrfDetected(String),

    #[error("Subscription limit ({limit}) reached for tenant")]
    SubscriptionLimitExceeded { limit: i64 },

    #[error("Subscription not found")]
    SubscriptionNotFound,

    #[error("Delivery not found")]
    DeliveryNotFound,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Invalid request: {0}")]
    Validation(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

/// JSON error response returned by webhook API endpoints.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub status: u16,
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            WebhookError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            WebhookError::InvalidUrl(_) => (StatusCode::BAD_REQUEST, "invalid_url"),
            WebhookError::SsrfDetected(_) => (StatusCode::BAD_REQUEST, "ssrf_detected"),
            WebhookError::SubscriptionLimitExceeded { .. } => {
                (StatusCode::CONFLICT, "subscription_limit_exceeded")
            }
            WebhookError::SubscriptionNotFound => (StatusCode::NOT_FOUND, "subscription_not_found"),
            WebhookError::DeliveryNotFound => (StatusCode::NOT_FOUND, "delivery_not_found"),
            WebhookError::EncryptionFailed(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "encryption_error")
            }
            WebhookError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            WebhookError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            WebhookError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let body = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            status: status.as_u16(),
        };

        (status, axum::Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, WebhookError>;
