//! mTLS Middleware for Agent Authentication (F127).
//!
//! This middleware validates client certificates for mTLS authentication
//! and extracts agent identity from the certificate Subject Alternative Name.

use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use sqlx::PgPool;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::services::{
    CertificateService, MtlsService as MtlsValidationService, MtlsValidationResult,
};

/// Configuration for mTLS middleware.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Whether mTLS is required (if false, mTLS is optional).
    pub required: bool,

    /// Whether to check certificate revocation.
    pub check_revocation: bool,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            required: true,
            check_revocation: true,
        }
    }
}

impl MtlsConfig {
    /// Create a new mTLS configuration with required mTLS.
    pub fn required() -> Self {
        Self {
            required: true,
            ..Default::default()
        }
    }

    /// Create a new mTLS configuration with optional mTLS.
    pub fn optional() -> Self {
        Self {
            required: false,
            ..Default::default()
        }
    }

    /// Enable or disable revocation checking.
    pub fn with_revocation_check(mut self, check: bool) -> Self {
        self.check_revocation = check;
        self
    }
}

/// Agent identity extracted from mTLS certificate.
#[derive(Debug, Clone)]
pub struct MtlsIdentity {
    /// Tenant ID from certificate SAN.
    pub tenant_id: Uuid,

    /// Agent ID from certificate SAN.
    pub agent_id: Uuid,

    /// Certificate serial number.
    pub serial_number: String,

    /// Certificate fingerprint (SHA-256).
    pub fingerprint: String,

    /// Certificate expiration timestamp.
    pub expires_at: i64,
}

impl From<&MtlsValidationResult> for MtlsIdentity {
    fn from(result: &MtlsValidationResult) -> Self {
        Self {
            tenant_id: result.tenant_id.unwrap_or_default(),
            agent_id: result.agent_id.unwrap_or_default(),
            serial_number: result.serial_number.clone().unwrap_or_default(),
            fingerprint: result.fingerprint.clone().unwrap_or_default(),
            expires_at: result.expires_at.map(|t| t.timestamp()).unwrap_or(0),
        }
    }
}

/// Tower Layer for mTLS authentication.
#[derive(Clone)]
pub struct MtlsLayer {
    config: Arc<MtlsConfig>,
    validation_service: Arc<MtlsValidationService>,
}

impl MtlsLayer {
    /// Create a new mTLS layer with the given configuration and database pool.
    pub fn new(
        config: MtlsConfig,
        pool: PgPool,
        certificate_service: Arc<CertificateService>,
    ) -> Self {
        let validation_service = Arc::new(MtlsValidationService::new(pool, certificate_service));
        Self {
            config: Arc::new(config),
            validation_service,
        }
    }

    /// Create a new mTLS layer with an existing validation service.
    pub fn with_service(
        config: MtlsConfig,
        validation_service: Arc<MtlsValidationService>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            validation_service,
        }
    }
}

impl<S> Layer<S> for MtlsLayer {
    type Service = MtlsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MtlsMiddleware {
            inner,
            config: self.config.clone(),
            validation_service: self.validation_service.clone(),
        }
    }
}

/// Tower Service for mTLS authentication.
#[derive(Clone)]
pub struct MtlsMiddleware<S> {
    inner: S,
    config: Arc<MtlsConfig>,
    validation_service: Arc<MtlsValidationService>,
}

impl<S> MtlsMiddleware<S> {
    /// Get the mTLS configuration.
    pub fn config(&self) -> &MtlsConfig {
        &self.config
    }
}

impl<S> Service<Request> for MtlsMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let config = self.config.clone();
        let validation_service = self.validation_service.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Check for pre-extracted identity (from TLS termination proxy)
            if req.extensions().get::<MtlsIdentity>().is_some() {
                // Identity already set by upstream (e.g., TLS termination proxy)
                return inner.call(req).await;
            }

            // Extract client certificate from request headers
            // In production, this comes from:
            // 1. Direct TLS: rustls/native-tls provides via request extensions
            // 2. Proxy: X-Client-Cert header (URL-encoded PEM from nginx/envoy)
            // 3. AWS ALB: X-Amzn-Mtls-Clientcert header
            let client_cert = extract_client_certificate(&req);

            if client_cert.is_none() {
                if config.required {
                    return Ok(MtlsError::CertificateRequired.into_response());
                }
                // mTLS is optional and no cert provided - continue without identity
                return inner.call(req).await;
            }

            let cert_pem = client_cert.unwrap();

            // Validate certificate using the validation service
            let validation_result = match validation_service.validate_certificate(&cert_pem).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!("mTLS validation error: {:?}", e);
                    return Ok(MtlsError::ValidationFailed(e.to_string()).into_response());
                }
            };

            // Check validation result
            if !validation_result.is_valid {
                let error = validation_result
                    .error
                    .as_deref()
                    .unwrap_or("Unknown error");
                tracing::warn!("mTLS certificate validation failed: {}", error);

                // Map specific error types
                return Ok(match error {
                    e if e.contains("expired") => MtlsError::CertificateExpired,
                    e if e.contains("revoked") => MtlsError::CertificateRevoked,
                    e if e.contains("not found") => MtlsError::UntrustedCertificate,
                    e if e.contains("not yet valid") => MtlsError::CertificateNotYetValid,
                    e if e.contains("mismatch") => MtlsError::IdentityMismatch,
                    _ => MtlsError::InvalidCertificate(error.to_string()),
                }
                .into_response());
            }

            // Extract identity from validation result
            let identity = MtlsIdentity::from(&validation_result);

            tracing::debug!(
                tenant_id = %identity.tenant_id,
                agent_id = %identity.agent_id,
                fingerprint = %identity.fingerprint,
                "mTLS authentication successful"
            );

            // Insert identity into request extensions for downstream handlers
            req.extensions_mut().insert(identity);

            // Continue with the request
            inner.call(req).await
        })
    }
}

/// Extract client certificate from request headers.
///
/// Supports multiple header formats used by different proxies/load balancers:
/// - `X-Client-Cert`: Common format (URL-encoded or plain PEM)
/// - `X-Amzn-Mtls-Clientcert`: AWS ALB
/// - `X-SSL-Client-Cert`: nginx
/// - `X-Forwarded-Client-Cert`: Envoy
fn extract_client_certificate(req: &Request) -> Option<String> {
    // Try different header names in order of preference
    let headers = [
        "X-Client-Cert",
        "X-Amzn-Mtls-Clientcert",
        "X-SSL-Client-Cert",
    ];

    for header_name in headers {
        if let Some(value) = req.headers().get(header_name) {
            if let Ok(cert_str) = value.to_str() {
                // URL-decode if needed (some proxies URL-encode the PEM)
                let decoded = if cert_str.contains('%') {
                    urlencoding::decode(cert_str)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| cert_str.to_string())
                } else {
                    cert_str.to_string()
                };

                // Validate it looks like a PEM certificate
                if decoded.contains("-----BEGIN CERTIFICATE-----") {
                    return Some(decoded);
                }
            }
        }
    }

    // Check X-Forwarded-Client-Cert (Envoy format: Hash=xxx;Cert="xxx";...)
    if let Some(value) = req.headers().get("X-Forwarded-Client-Cert") {
        if let Ok(xfcc) = value.to_str() {
            // Parse XFCC format to extract Cert field
            for part in xfcc.split(';') {
                let part = part.trim();
                if let Some(cert_part) = part.strip_prefix("Cert=\"") {
                    if let Some(cert) = cert_part.strip_suffix('"') {
                        let decoded = urlencoding::decode(cert)
                            .map(|s| s.into_owned())
                            .unwrap_or_else(|_| cert.to_string());
                        if decoded.contains("-----BEGIN CERTIFICATE-----") {
                            return Some(decoded);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Errors from mTLS middleware.
#[derive(Debug, Clone)]
pub enum MtlsError {
    /// Client certificate is required but not provided.
    CertificateRequired,

    /// Client certificate is invalid.
    InvalidCertificate(String),

    /// Client certificate has expired.
    CertificateExpired,

    /// Client certificate is not yet valid.
    CertificateNotYetValid,

    /// Client certificate has been revoked.
    CertificateRevoked,

    /// Client certificate is not trusted (unknown CA).
    UntrustedCertificate,

    /// Certificate identity doesn't match claimed identity.
    IdentityMismatch,

    /// Certificate validation failed.
    ValidationFailed(String),
}

impl IntoResponse for MtlsError {
    fn into_response(self) -> Response {
        let (status, error_type, title, message) = match &self {
            MtlsError::CertificateRequired => (
                StatusCode::UNAUTHORIZED,
                "certificate-required",
                "Certificate Required",
                "Client certificate required for mTLS authentication".to_string(),
            ),
            MtlsError::InvalidCertificate(msg) => (
                StatusCode::UNAUTHORIZED,
                "invalid-certificate",
                "Invalid Certificate",
                msg.clone(),
            ),
            MtlsError::CertificateExpired => (
                StatusCode::UNAUTHORIZED,
                "certificate-expired",
                "Certificate Expired",
                "Client certificate has expired".to_string(),
            ),
            MtlsError::CertificateNotYetValid => (
                StatusCode::UNAUTHORIZED,
                "certificate-not-yet-valid",
                "Certificate Not Yet Valid",
                "Client certificate is not yet valid".to_string(),
            ),
            MtlsError::CertificateRevoked => (
                StatusCode::UNAUTHORIZED,
                "certificate-revoked",
                "Certificate Revoked",
                "Client certificate has been revoked".to_string(),
            ),
            MtlsError::UntrustedCertificate => (
                StatusCode::UNAUTHORIZED,
                "untrusted-certificate",
                "Untrusted Certificate",
                "Client certificate is not trusted".to_string(),
            ),
            MtlsError::IdentityMismatch => (
                StatusCode::UNAUTHORIZED,
                "identity-mismatch",
                "Identity Mismatch",
                "Certificate identity doesn't match claimed identity".to_string(),
            ),
            MtlsError::ValidationFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "validation-failed",
                "Validation Failed",
                msg.clone(),
            ),
        };

        // Return RFC 7807 Problem Details response
        let body = serde_json::json!({
            "type": format!("https://xavyo.net/errors/agents/mtls-{}", error_type),
            "title": title,
            "status": status.as_u16(),
            "detail": message,
        });

        Response::builder()
            .status(status)
            .header("Content-Type", "application/problem+json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtls_config_default() {
        let config = MtlsConfig::default();
        assert!(config.required);
        assert!(config.check_revocation);
    }

    #[test]
    fn test_mtls_config_optional() {
        let config = MtlsConfig::optional();
        assert!(!config.required);
    }

    #[test]
    fn test_mtls_config_with_revocation() {
        let config = MtlsConfig::required().with_revocation_check(false);
        assert!(!config.check_revocation);
    }

    #[test]
    fn test_mtls_identity() {
        let identity = MtlsIdentity {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            serial_number: "01ABCDEF".to_string(),
            fingerprint: "AB:CD:EF:...".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 86400,
        };

        assert!(!identity.serial_number.is_empty());
    }

    #[test]
    fn test_mtls_error_response() {
        let error = MtlsError::CertificateRequired;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_mtls_error_expired() {
        let error = MtlsError::CertificateExpired;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_mtls_error_revoked() {
        let error = MtlsError::CertificateRevoked;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_mtls_error_validation_failed() {
        let error = MtlsError::ValidationFailed("DB connection failed".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
