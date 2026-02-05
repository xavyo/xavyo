//! Error types for the bulk user import API (F086).
//!
//! Uses RFC 7807 Problem Details for HTTP APIs, consistent with xavyo-api-auth.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for error type URIs.
const ERROR_BASE_URL: &str = "https://xavyo.net/errors/import";

/// RFC 7807 Problem Details structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub error_type: String,

    /// Short human-readable summary.
    pub title: String,

    /// HTTP status code.
    pub status: u16,

    /// Human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// URI of the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    /// Create a new `ProblemDetails` instance.
    #[must_use]
    pub fn new(error_type: &str, title: &str, status: StatusCode) -> Self {
        Self {
            error_type: format!("{ERROR_BASE_URL}/{error_type}"),
            title: title.to_string(),
            status: status.as_u16(),
            detail: None,
            instance: None,
        }
    }

    /// Add detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Import API errors.
#[derive(Debug, Error)]
pub enum ImportError {
    /// File exceeds maximum allowed size.
    #[error("File too large: {0}")]
    FileTooLarge(String),

    /// CSV contains too many data rows.
    #[error("Too many rows: {0}")]
    TooManyRows(String),

    /// Uploaded file is not a valid CSV.
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),

    /// Required CSV headers are missing.
    #[error("Missing required headers: {0}")]
    MissingHeaders(String),

    /// CSV parsing failed.
    #[error("Invalid CSV: {0}")]
    InvalidCsv(String),

    /// Another import is already running for this tenant.
    #[error("Concurrent import in progress")]
    ConcurrentImport,

    /// Import job not found.
    #[error("Job not found")]
    JobNotFound,

    /// User not found.
    #[error("User not found")]
    UserNotFound,

    /// Invitation token is invalid.
    #[error("Invalid invitation token")]
    InvalidToken,

    /// Invitation token has expired.
    #[error("Invitation token expired")]
    TokenExpired,

    /// Invitation has already been accepted.
    #[error("Invitation already accepted")]
    TokenAlreadyUsed,

    /// Password does not meet tenant policy.
    #[error("Password policy violation: {0}")]
    PasswordPolicyViolation(String),

    /// Missing or invalid authentication.
    #[error("Unauthorized")]
    Unauthorized,

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl ImportError {
    /// Convert to `ProblemDetails`.
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            ImportError::FileTooLarge(msg) => ProblemDetails::new(
                "file-too-large",
                "File Too Large",
                StatusCode::PAYLOAD_TOO_LARGE,
            )
            .with_detail(msg.clone()),

            ImportError::TooManyRows(msg) => {
                ProblemDetails::new("too-many-rows", "Too Many Rows", StatusCode::BAD_REQUEST)
                    .with_detail(msg.clone())
            }

            ImportError::InvalidFileType(msg) => ProblemDetails::new(
                "invalid-file-type",
                "Invalid File Type",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            ImportError::MissingHeaders(msg) => ProblemDetails::new(
                "missing-headers",
                "Missing Required Headers",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            ImportError::InvalidCsv(msg) => {
                ProblemDetails::new("invalid-csv", "Invalid CSV", StatusCode::BAD_REQUEST)
                    .with_detail(msg.clone())
            }

            ImportError::ConcurrentImport => ProblemDetails::new(
                "concurrent-import",
                "Concurrent Import",
                StatusCode::CONFLICT,
            )
            .with_detail(
                "Another import is already running for this tenant. Please wait for it to complete.",
            ),

            ImportError::JobNotFound => {
                ProblemDetails::new("job-not-found", "Job Not Found", StatusCode::NOT_FOUND)
                    .with_detail("The requested import job was not found.")
            }

            ImportError::UserNotFound => {
                ProblemDetails::new("user-not-found", "User Not Found", StatusCode::NOT_FOUND)
                    .with_detail("The requested user was not found.")
            }

            ImportError::InvalidToken => ProblemDetails::new(
                "invalid-token",
                "Invalid Token",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The invitation token is invalid."),

            ImportError::TokenExpired => ProblemDetails::new(
                "token-expired",
                "Token Expired",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The invitation token has expired. Please request a new invitation."),

            ImportError::TokenAlreadyUsed => ProblemDetails::new(
                "token-already-used",
                "Invitation Already Accepted",
                StatusCode::GONE,
            )
            .with_detail("This invitation has already been accepted."),

            ImportError::PasswordPolicyViolation(msg) => ProblemDetails::new(
                "password-policy-violation",
                "Password Policy Violation",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            ImportError::Unauthorized => {
                ProblemDetails::new("unauthorized", "Unauthorized", StatusCode::UNAUTHORIZED)
                    .with_detail("Authentication required.")
            }

            ImportError::Internal(msg) => {
                tracing::error!(error = %msg, "Internal import error");
                ProblemDetails::new(
                    "internal-error",
                    "Internal Server Error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .with_detail("An internal error occurred. Please try again later.")
            }

            ImportError::Database(err) => {
                tracing::error!(error = %err, "Database error in import");
                ProblemDetails::new(
                    "database-error",
                    "Database Error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .with_detail("A database error occurred. Please try again later.")
            }
        }
    }

    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            ImportError::FileTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ImportError::TooManyRows(_) => StatusCode::BAD_REQUEST,
            ImportError::InvalidFileType(_) => StatusCode::BAD_REQUEST,
            ImportError::MissingHeaders(_) => StatusCode::BAD_REQUEST,
            ImportError::InvalidCsv(_) => StatusCode::BAD_REQUEST,
            ImportError::ConcurrentImport => StatusCode::CONFLICT,
            ImportError::JobNotFound => StatusCode::NOT_FOUND,
            ImportError::UserNotFound => StatusCode::NOT_FOUND,
            ImportError::InvalidToken => StatusCode::NOT_FOUND,
            ImportError::TokenExpired => StatusCode::NOT_FOUND,
            ImportError::TokenAlreadyUsed => StatusCode::GONE,
            ImportError::PasswordPolicyViolation(_) => StatusCode::BAD_REQUEST,
            ImportError::Unauthorized => StatusCode::UNAUTHORIZED,
            ImportError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ImportError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ImportError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let problem = self.to_problem_details();

        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );

        response
    }
}
