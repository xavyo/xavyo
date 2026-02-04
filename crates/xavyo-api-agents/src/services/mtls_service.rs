//! mTLS Service for certificate validation and agent identity extraction (F127).
//!
//! This service handles:
//! - Certificate chain validation against trusted CAs
//! - Agent identity extraction from certificate SANs
//! - Revocation status checking (via CRL/OCSP)
//! - Certificate expiry validation

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use x509_parser::prelude::*;

use xavyo_db::models::agent_certificate::AgentCertificate;
use xavyo_db::models::certificate_authority::CertificateAuthority;

use crate::error::ApiAgentsError;
use crate::services::CertificateService;

/// Result of mTLS certificate validation.
#[derive(Debug, Clone)]
pub struct MtlsValidationResult {
    /// Whether the certificate is valid.
    pub is_valid: bool,
    /// The tenant ID extracted from the certificate SAN.
    pub tenant_id: Option<Uuid>,
    /// The agent ID extracted from the certificate SAN.
    pub agent_id: Option<Uuid>,
    /// The certificate record from the database (if found).
    pub certificate: Option<AgentCertificate>,
    /// Validation error message (if any).
    pub error: Option<String>,
    /// Certificate fingerprint (SHA-256).
    pub fingerprint: Option<String>,
    /// Certificate serial number.
    pub serial_number: Option<String>,
    /// Certificate expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl MtlsValidationResult {
    /// Create a successful validation result.
    #[must_use] 
    pub fn success(
        tenant_id: Uuid,
        agent_id: Uuid,
        certificate: AgentCertificate,
        fingerprint: String,
    ) -> Self {
        Self {
            is_valid: true,
            tenant_id: Some(tenant_id),
            agent_id: Some(agent_id),
            certificate: Some(certificate.clone()),
            error: None,
            fingerprint: Some(fingerprint),
            serial_number: Some(certificate.serial_number),
            expires_at: Some(certificate.not_after),
        }
    }

    /// Create a failed validation result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            is_valid: false,
            tenant_id: None,
            agent_id: None,
            certificate: None,
            error: Some(error.into()),
            fingerprint: None,
            serial_number: None,
            expires_at: None,
        }
    }
}

/// Service for mTLS certificate validation.
pub struct MtlsService {
    pool: PgPool,
    certificate_service: Arc<CertificateService>,
}

impl MtlsService {
    /// Create a new `MtlsService`.
    #[must_use] 
    pub fn new(pool: PgPool, certificate_service: Arc<CertificateService>) -> Self {
        Self {
            pool,
            certificate_service,
        }
    }

    /// Validate a client certificate presented during mTLS handshake.
    ///
    /// This performs the following checks:
    /// 1. Parse and validate the X.509 certificate format
    /// 2. Check certificate expiry (not before, not after)
    /// 3. Extract agent identity from SAN URIs
    /// 4. Verify the certificate exists in our database
    /// 5. Check revocation status
    /// 6. Validate the certificate chain against trusted CAs
    ///
    /// # Arguments
    /// * `certificate_pem` - The client certificate in PEM format
    ///
    /// # Returns
    /// Validation result with agent identity if successful.
    pub async fn validate_certificate(
        &self,
        certificate_pem: &str,
    ) -> Result<MtlsValidationResult, ApiAgentsError> {
        // Parse PEM certificate
        let cert_der = match ::pem::parse(certificate_pem) {
            Ok(pem) => pem,
            Err(e) => {
                return Ok(MtlsValidationResult::failure(format!(
                    "Failed to parse PEM: {e}"
                )));
            }
        };

        // Parse X.509 certificate
        let (_, x509_cert) = match X509Certificate::from_der(cert_der.contents()) {
            Ok(cert) => cert,
            Err(e) => {
                return Ok(MtlsValidationResult::failure(format!(
                    "Failed to parse X.509: {e:?}"
                )));
            }
        };

        // Check certificate validity period
        let now = Utc::now();
        let not_before = DateTime::from_timestamp(x509_cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(x509_cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        if now < not_before {
            return Ok(MtlsValidationResult::failure(
                "Certificate is not yet valid",
            ));
        }

        if now > not_after {
            return Ok(MtlsValidationResult::failure("Certificate has expired"));
        }

        // Calculate fingerprint
        let fingerprint = calculate_fingerprint(cert_der.contents());

        // Extract agent identity from SAN
        let (tenant_id, agent_id) = match self.extract_agent_identity(&x509_cert) {
            Ok(ids) => ids,
            Err(e) => {
                return Ok(MtlsValidationResult::failure(format!(
                    "Failed to extract agent identity: {e}"
                )));
            }
        };

        // Look up certificate in database by fingerprint
        let certificate = match self
            .certificate_service
            .find_by_fingerprint_any_tenant(&fingerprint)
            .await?
        {
            Some(cert) => cert,
            None => {
                return Ok(MtlsValidationResult::failure(
                    "Certificate not found in database",
                ));
            }
        };

        // Verify certificate belongs to the claimed agent
        if certificate.agent_id != agent_id {
            return Ok(MtlsValidationResult::failure(
                "Certificate agent ID mismatch",
            ));
        }

        if certificate.tenant_id != tenant_id {
            return Ok(MtlsValidationResult::failure(
                "Certificate tenant ID mismatch",
            ));
        }

        // Check if certificate is revoked
        if certificate.is_revoked() {
            return Ok(MtlsValidationResult::failure(
                "Certificate has been revoked",
            ));
        }

        // Check certificate status
        if !certificate.is_active() {
            return Ok(MtlsValidationResult::failure(format!(
                "Certificate status is '{}'",
                certificate.status
            )));
        }

        // Validate certificate chain against CA
        if let Err(e) = self
            .validate_certificate_chain(&x509_cert, certificate.ca_id)
            .await
        {
            return Ok(MtlsValidationResult::failure(format!(
                "Chain validation failed: {e}"
            )));
        }

        Ok(MtlsValidationResult::success(
            tenant_id,
            agent_id,
            certificate,
            fingerprint,
        ))
    }

    /// Extract agent identity (`tenant_id`, `agent_id`) from certificate SANs.
    ///
    /// Looks for URI SANs in the format:
    /// `xavyo:tenant:{tenant_uuid}:agent:{agent_uuid}`
    fn extract_agent_identity(
        &self,
        cert: &X509Certificate,
    ) -> Result<(Uuid, Uuid), ApiAgentsError> {
        // Get Subject Alternative Names extension
        let san_ext = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);

        let san_ext = san_ext.ok_or_else(|| {
            ApiAgentsError::MtlsValidationFailed(
                "No Subject Alternative Name extension".to_string(),
            )
        })?;

        // Parse SAN extension
        let san = match san_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san,
            _ => {
                return Err(ApiAgentsError::MtlsValidationFailed(
                    "Failed to parse SAN extension".to_string(),
                ));
            }
        };

        // Look for xavyo URI in SANs
        for name in &san.general_names {
            if let GeneralName::URI(uri) = name {
                if let Some((tenant_id, agent_id)) = parse_xavyo_uri(uri) {
                    return Ok((tenant_id, agent_id));
                }
            }
        }

        Err(ApiAgentsError::MtlsValidationFailed(
            "No valid xavyo URI found in certificate SANs".to_string(),
        ))
    }

    /// Validate certificate chain against the issuing CA.
    ///
    /// Performs cryptographic signature verification to ensure the certificate
    /// was actually signed by the claimed CA.
    async fn validate_certificate_chain(
        &self,
        cert: &X509Certificate<'_>,
        ca_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        // Get the CA certificate
        let ca = CertificateAuthority::find_by_id_any_tenant(&self.pool, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        // Verify CA is active
        if !ca.is_active {
            return Err(ApiAgentsError::MtlsValidationFailed(
                "Issuing CA is not active".to_string(),
            ));
        }

        // Parse CA certificate
        let ca_pem = ::pem::parse(&ca.certificate_pem).map_err(|e| {
            ApiAgentsError::MtlsValidationFailed(format!("Failed to parse CA PEM: {e}"))
        })?;

        let (_, ca_cert) = X509Certificate::from_der(ca_pem.contents()).map_err(|e| {
            ApiAgentsError::MtlsValidationFailed(format!("Failed to parse CA X.509: {e:?}"))
        })?;

        // 1. Verify the certificate's issuer DN matches the CA's subject DN
        if cert.issuer() != ca_cert.subject() {
            return Err(ApiAgentsError::MtlsValidationFailed(
                "Certificate issuer DN does not match CA subject DN".to_string(),
            ));
        }

        // 2. Verify certificate signature using CA public key
        // x509-parser's verify feature provides cryptographic signature verification
        let ca_public_key = ca_cert.public_key();
        cert.verify_signature(Some(ca_public_key)).map_err(|e| {
            ApiAgentsError::MtlsValidationFailed(format!(
                "Certificate signature verification failed: {e:?}"
            ))
        })?;

        // 3. Check CA basic constraints - must be a CA
        if let Ok(Some(bc)) = ca_cert.basic_constraints() {
            if !bc.value.ca {
                return Err(ApiAgentsError::MtlsValidationFailed(
                    "Issuing certificate is not a CA".to_string(),
                ));
            }
        }

        // 4. Check CA key usage - must allow certificate signing
        if let Ok(Some(ku)) = ca_cert.key_usage() {
            if !ku.value.key_cert_sign() {
                return Err(ApiAgentsError::MtlsValidationFailed(
                    "CA certificate does not allow certificate signing".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Check if a certificate is revoked (via database lookup).
    ///
    /// This is a fast path that checks our revocation database.
    /// For external verification, use CRL or OCSP endpoints.
    ///
    /// Note: Uses `any_tenant` lookup since this is for mTLS validation
    /// where tenant is extracted from the certificate itself.
    pub async fn is_certificate_revoked(&self, fingerprint: &str) -> Result<bool, ApiAgentsError> {
        match self
            .certificate_service
            .find_by_fingerprint_any_tenant(fingerprint)
            .await?
        {
            Some(cert) => Ok(cert.is_revoked()),
            None => Ok(false), // Unknown certificate - not in our system
        }
    }

    /// Get certificate details by fingerprint.
    ///
    /// Note: Uses `any_tenant` lookup since this is for mTLS validation
    /// where tenant is extracted from the certificate itself.
    pub async fn get_certificate_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<AgentCertificate>, ApiAgentsError> {
        self.certificate_service
            .find_by_fingerprint_any_tenant(fingerprint)
            .await
    }
}

/// Parse a xavyo URI to extract `tenant_id` and `agent_id`.
///
/// Format: `xavyo:tenant:{tenant_uuid}:agent:{agent_uuid}`
fn parse_xavyo_uri(uri: &str) -> Option<(Uuid, Uuid)> {
    let parts: Vec<&str> = uri.split(':').collect();

    // Expected format: ["xavyo", "tenant", "{uuid}", "agent", "{uuid}"]
    if parts.len() != 5 {
        return None;
    }

    if parts[0] != "xavyo" || parts[1] != "tenant" || parts[3] != "agent" {
        return None;
    }

    let tenant_id = Uuid::parse_str(parts[2]).ok()?;
    let agent_id = Uuid::parse_str(parts[4]).ok()?;

    Some((tenant_id, agent_id))
}

/// Calculate SHA-256 fingerprint of DER-encoded certificate.
fn calculate_fingerprint(der_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xavyo_uri_valid() {
        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let uri = format!("xavyo:tenant:{}:agent:{}", tenant_id, agent_id);

        let result = parse_xavyo_uri(&uri);
        assert!(result.is_some());

        let (parsed_tenant, parsed_agent) = result.unwrap();
        assert_eq!(parsed_tenant, tenant_id);
        assert_eq!(parsed_agent, agent_id);
    }

    #[test]
    fn test_parse_xavyo_uri_invalid_format() {
        assert!(parse_xavyo_uri("invalid").is_none());
        assert!(parse_xavyo_uri("xavyo:tenant:invalid:agent:invalid").is_none());
        assert!(parse_xavyo_uri("other:tenant:00000000-0000-0000-0000-000000000000:agent:00000000-0000-0000-0000-000000000001").is_none());
    }

    #[test]
    fn test_parse_xavyo_uri_wrong_prefix() {
        let uri = "other:tenant:00000000-0000-0000-0000-000000000000:agent:00000000-0000-0000-0000-000000000001";
        assert!(parse_xavyo_uri(uri).is_none());
    }

    #[test]
    fn test_validation_result_success() {
        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let cert = AgentCertificate {
            id: Uuid::new_v4(),
            tenant_id,
            agent_id,
            serial_number: "ABC123".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint_sha256: "AA:BB:CC".to_string(),
            subject_dn: "CN=test".to_string(),
            issuer_dn: "CN=CA".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(90),
            status: "active".to_string(),
            ca_id: Uuid::new_v4(),
            revoked_at: None,
            revocation_reason: None,
            created_at: Utc::now(),
            created_by: None,
        };

        let result =
            MtlsValidationResult::success(tenant_id, agent_id, cert, "AA:BB:CC".to_string());

        assert!(result.is_valid);
        assert_eq!(result.tenant_id, Some(tenant_id));
        assert_eq!(result.agent_id, Some(agent_id));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_validation_result_failure() {
        let result = MtlsValidationResult::failure("Test error");

        assert!(!result.is_valid);
        assert!(result.tenant_id.is_none());
        assert!(result.agent_id.is_none());
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = calculate_fingerprint(data);

        assert!(fingerprint.contains(":"));
        // SHA-256 produces 32 bytes = 64 hex chars + 31 colons = 95 chars
        assert_eq!(fingerprint.len(), 32 * 3 - 1);
    }
}
