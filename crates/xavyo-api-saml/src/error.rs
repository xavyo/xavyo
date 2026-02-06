//! SAML-specific error types

use crate::session::SessionError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Result type for SAML operations
pub type SamlResult<T> = Result<T, SamlError>;

/// SAML-specific errors
#[derive(Debug, Error)]
pub enum SamlError {
    /// Invalid or malformed `AuthnRequest`
    #[error("Invalid AuthnRequest: {0}")]
    InvalidAuthnRequest(String),

    /// Session-related errors (replay attack, expired, not found)
    #[error("Session error: {0}")]
    SessionError(#[from] SessionError),

    /// Unknown or unregistered Service Provider
    #[error("Unknown Service Provider: {0}")]
    UnknownServiceProvider(String),

    /// Service Provider is disabled
    #[error("Service Provider is disabled: {0}")]
    DisabledServiceProvider(String),

    /// Invalid or expired SP certificate
    #[error("Invalid SP certificate: {0}")]
    InvalidSpCertificate(String),

    /// Signature validation failed
    #[error("Signature validation failed: {0}")]
    SignatureValidationFailed(String),

    /// No active `IdP` signing certificate
    #[error("No active IdP signing certificate for tenant")]
    NoActiveCertificate,

    /// Certificate parsing error
    #[error("Certificate parsing error: {0}")]
    CertificateParseError(String),

    /// Private key error
    #[error("Private key error: {0}")]
    PrivateKeyError(String),

    /// Assertion generation failed
    #[error("Assertion generation failed: {0}")]
    AssertionGenerationFailed(String),

    /// Metadata generation failed
    #[error("Metadata generation failed: {0}")]
    MetadataGenerationFailed(String),

    /// User not authenticated
    #[error("User not authenticated")]
    NotAuthenticated,

    /// Invalid `NameID` format
    #[error("Unsupported NameID format: {0}")]
    UnsupportedNameIdFormat(String),

    /// ACS URL mismatch
    #[error("ACS URL mismatch: expected one of {expected:?}, got {actual}")]
    AcsUrlMismatch {
        expected: Vec<String>,
        actual: String,
    },

    /// Entity ID already exists
    #[error("Entity ID already exists: {0}")]
    EntityIdConflict(String),

    /// Service Provider not found
    #[error("Service Provider not found: {0}")]
    ServiceProviderNotFound(String),

    /// Certificate not found
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    /// Invalid attribute mapping
    #[error("Invalid attribute mapping: {0}")]
    InvalidAttributeMapping(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Error response body
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_status: Option<String>,
}

impl IntoResponse for SamlError {
    fn into_response(self) -> Response {
        let (status, error_code, saml_status) = match &self {
            SamlError::SessionError(e) => match e {
                SessionError::NotFound(_) => (
                    StatusCode::BAD_REQUEST,
                    "unknown_request",
                    Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
                ),
                SessionError::Expired { .. } => (
                    StatusCode::BAD_REQUEST,
                    "request_expired",
                    Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
                ),
                SessionError::AlreadyConsumed { .. } => (
                    StatusCode::BAD_REQUEST,
                    "replay_attack_detected",
                    Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
                ),
                SessionError::DuplicateRequestId(_) => (
                    StatusCode::CONFLICT,
                    "duplicate_request",
                    Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
                ),
                SessionError::StorageError(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_storage_error",
                    Some("urn:oasis:names:tc:SAML:2.0:status:Responder"),
                ),
            },
            SamlError::InvalidAuthnRequest(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
            ),
            SamlError::UnknownServiceProvider(_) => (StatusCode::NOT_FOUND, "unknown_sp", None),
            SamlError::DisabledServiceProvider(_) => (StatusCode::NOT_FOUND, "disabled_sp", None),
            SamlError::InvalidSpCertificate(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_certificate",
                Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
            ),
            SamlError::SignatureValidationFailed(_) => (
                StatusCode::BAD_REQUEST,
                "signature_validation_failed",
                Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
            ),
            SamlError::NoActiveCertificate => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "no_active_certificate",
                Some("urn:oasis:names:tc:SAML:2.0:status:Responder"),
            ),
            SamlError::CertificateParseError(_) => {
                (StatusCode::BAD_REQUEST, "certificate_parse_error", None)
            }
            SamlError::PrivateKeyError(_) => (StatusCode::BAD_REQUEST, "private_key_error", None),
            SamlError::AssertionGenerationFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "assertion_generation_failed",
                Some("urn:oasis:names:tc:SAML:2.0:status:Responder"),
            ),
            SamlError::MetadataGenerationFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata_generation_failed",
                None,
            ),
            SamlError::NotAuthenticated => (
                StatusCode::UNAUTHORIZED,
                "not_authenticated",
                Some("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
            ),
            SamlError::UnsupportedNameIdFormat(_) => (
                StatusCode::BAD_REQUEST,
                "unsupported_nameid_format",
                Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
            ),
            SamlError::AcsUrlMismatch { .. } => (
                StatusCode::BAD_REQUEST,
                "acs_url_mismatch",
                Some("urn:oasis:names:tc:SAML:2.0:status:Requester"),
            ),
            SamlError::EntityIdConflict(_) => (StatusCode::CONFLICT, "entity_id_conflict", None),
            SamlError::ServiceProviderNotFound(_) => (StatusCode::NOT_FOUND, "sp_not_found", None),
            SamlError::CertificateNotFound(_) => {
                (StatusCode::NOT_FOUND, "certificate_not_found", None)
            }
            SamlError::InvalidAttributeMapping(_) => {
                (StatusCode::BAD_REQUEST, "invalid_attribute_mapping", None)
            }
            SamlError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error", None)
            }
            SamlError::InternalError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
            }
        };

        let message = match &self {
            SamlError::DatabaseError(e) => {
                tracing::error!("SAML database error: {:?}", e);
                "A database error occurred".to_string()
            }
            SamlError::InternalError(msg) => {
                tracing::error!("SAML internal error: {}", msg);
                "An internal error occurred".to_string()
            }
            SamlError::SessionError(SessionError::StorageError(msg)) => {
                tracing::error!("SAML session storage error: {}", msg);
                "A session storage error occurred".to_string()
            }
            SamlError::CertificateParseError(_) => "Certificate parsing error".to_string(),
            SamlError::PrivateKeyError(_) => {
                tracing::error!("SAML private key error");
                "A private key error occurred".to_string()
            }
            SamlError::AssertionGenerationFailed(_) => {
                tracing::error!("SAML assertion generation failed");
                "Assertion generation failed".to_string()
            }
            SamlError::MetadataGenerationFailed(_) => {
                tracing::error!("SAML metadata generation failed");
                "Metadata generation failed".to_string()
            }
            SamlError::SignatureValidationFailed(_) => "Signature validation failed".to_string(),
            SamlError::InvalidAuthnRequest(_) => "Invalid SAML authentication request".to_string(),
            SamlError::InvalidSpCertificate(_) => {
                "Invalid Service Provider certificate".to_string()
            }
            SamlError::AcsUrlMismatch { .. } => {
                "ACS URL does not match any registered URL".to_string()
            }
            SamlError::InvalidAttributeMapping(_) => {
                "Invalid attribute mapping configuration".to_string()
            }
            // Safe user-facing messages (contain only client-provided IDs/values)
            SamlError::SessionError(_)
            | SamlError::UnknownServiceProvider(_)
            | SamlError::DisabledServiceProvider(_)
            | SamlError::NoActiveCertificate
            | SamlError::NotAuthenticated
            | SamlError::UnsupportedNameIdFormat(_)
            | SamlError::EntityIdConflict(_)
            | SamlError::ServiceProviderNotFound(_)
            | SamlError::CertificateNotFound(_) => self.to_string(),
        };

        let body = ErrorResponse {
            error: error_code.to_string(),
            message,
            saml_status: saml_status.map(String::from),
        };

        (status, Json(body)).into_response()
    }
}
