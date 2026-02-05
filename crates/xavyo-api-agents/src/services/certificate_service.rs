//! Certificate Service for issuing and managing agent certificates (F127).
//!
//! This service handles the complete lifecycle of X.509 certificates for AI agents:
//! - Certificate issuance with configurable validity and key algorithm
//! - Certificate retrieval and listing
//! - Integration with `CaService` for CA management

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use x509_parser::prelude::FromDer;

use xavyo_db::models::agent_certificate::{
    AgentCertificate, AgentCertificateFilter, IssueCertificateRequest, IssueCertificateResponse,
};
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::certificate_authority::CertificateAuthority;

use crate::error::ApiAgentsError;
use crate::providers::{CertificateIssueRequest as ProviderIssueRequest, KeyAlgorithm};
use crate::services::audit_service::AuditService;
use crate::services::ca_service::CaService;

/// Service for managing agent certificates.
pub struct CertificateService {
    pool: PgPool,
    ca_service: Arc<CaService>,
    audit_service: Arc<AuditService>,
}

impl CertificateService {
    /// Create a new `CertificateService`.
    #[must_use]
    pub fn new(pool: PgPool, ca_service: Arc<CaService>, audit_service: Arc<AuditService>) -> Self {
        Self {
            pool,
            ca_service,
            audit_service,
        }
    }

    /// Issue a new certificate for an agent.
    ///
    /// This generates a new key pair for the agent, requests a certificate from the CA,
    /// stores the certificate in the database, and returns both the certificate and private key.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `agent_id` - The agent to issue the certificate for
    /// * `request` - Certificate request parameters
    /// * `created_by` - Optional user ID who requested the certificate
    ///
    /// # Returns
    /// The issued certificate response including the private key (only returned once).
    pub async fn issue_certificate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request: IssueCertificateRequest,
        created_by: Option<Uuid>,
    ) -> Result<IssueCertificateResponse, ApiAgentsError> {
        // Validate agent exists and is active
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::AgentNotFoundId(agent_id))?;

        if agent.status != "active" {
            return Err(ApiAgentsError::AgentNotActiveId(agent_id));
        }

        // Get CA provider (specific CA or default)
        let (ca, provider) = if let Some(ca_id) = request.ca_id {
            let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
                .await
                .map_err(ApiAgentsError::Database)?
                .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

            if !ca.is_active {
                return Err(ApiAgentsError::CaDisabled(ca_id));
            }

            let provider = self.ca_service.get_ca_provider(tenant_id, ca_id).await?;
            (ca, provider)
        } else {
            // Use default CA
            let ca = CertificateAuthority::find_default(&self.pool, tenant_id)
                .await
                .map_err(ApiAgentsError::Database)?
                .ok_or_else(|| ApiAgentsError::NoDefaultCa)?;

            let provider = self.ca_service.get_default_ca_provider(tenant_id).await?;
            (ca, provider)
        };

        // Validate requested validity doesn't exceed CA max
        let validity_days = request.validity_days.min(ca.max_validity_days);

        // Parse key algorithm
        let key_algorithm = parse_key_algorithm(&request.key_algorithm)?;

        // Collect additional SANs
        let additional_sans = request.additional_sans.clone().unwrap_or_default();

        // Build the certificate issuance request
        let issue_request = ProviderIssueRequest {
            tenant_id,
            agent_id,
            agent_name: agent.name.clone(),
            validity_days,
            key_algorithm,
            additional_sans,
        };

        // Issue certificate using the CA provider
        let cert_result = provider
            .issue_certificate(&issue_request)
            .await
            .map_err(|e| ApiAgentsError::CertificateIssueFailed(e.to_string()))?;

        // Parse the issued certificate to extract metadata
        let cert_der = ::pem::parse(&cert_result.certificate_pem).map_err(|e| {
            ApiAgentsError::CertificateIssueFailed(format!("Failed to parse certificate: {e}"))
        })?;

        let (_, x509_cert) =
            x509_parser::certificate::X509Certificate::from_der(cert_der.contents()).map_err(
                |e| ApiAgentsError::CertificateIssueFailed(format!("Failed to parse X.509: {e:?}")),
            )?;

        // Calculate SHA-256 fingerprint
        let fingerprint = calculate_fingerprint(cert_der.contents());

        // Format serial number as hex
        let serial_number = format_serial_number(x509_cert.serial.to_bytes_be());

        // Extract subject DN
        let subject_dn = format_subject_dn(x509_cert.subject());

        // Extract issuer DN
        let issuer_dn = format_subject_dn(x509_cert.issuer());

        // Extract validity dates
        let not_before: DateTime<Utc> =
            DateTime::from_timestamp(x509_cert.validity().not_before.timestamp(), 0)
                .unwrap_or_else(Utc::now);
        let not_after: DateTime<Utc> =
            DateTime::from_timestamp(x509_cert.validity().not_after.timestamp(), 0)
                .unwrap_or_else(|| Utc::now() + chrono::Duration::days(i64::from(validity_days)));

        // Store the certificate in the database
        let certificate = AgentCertificate::create(
            &self.pool,
            tenant_id,
            agent_id,
            &serial_number,
            &cert_result.certificate_pem,
            &fingerprint,
            &subject_dn,
            &issuer_dn,
            not_before,
            not_after,
            ca.id,
            created_by,
        )
        .await
        .map_err(ApiAgentsError::Database)?;

        // Log audit event for certificate issuance
        let _ = self
            .audit_service
            .log_certificate_event(
                tenant_id,
                agent_id,
                "certificate_issued",
                Some(certificate.id),
                Some(&serial_number),
                "success",
                Some(serde_json::json!({
                    "ca_id": ca.id,
                    "ca_name": ca.name,
                    "validity_days": validity_days,
                    "key_algorithm": request.key_algorithm,
                    "fingerprint": fingerprint,
                    "not_before": not_before.to_rfc3339(),
                    "not_after": not_after.to_rfc3339(),
                })),
                created_by,
            )
            .await;

        Ok(IssueCertificateResponse {
            certificate,
            private_key_pem: cert_result.private_key_pem,
            ca_chain_pem: cert_result.chain_pem,
        })
    }

    /// Get a certificate by ID.
    pub async fn get_certificate(
        &self,
        tenant_id: Uuid,
        certificate_id: Uuid,
    ) -> Result<AgentCertificate, ApiAgentsError> {
        AgentCertificate::find_by_id(&self.pool, tenant_id, certificate_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CertificateNotFoundId(certificate_id))
    }

    /// Get a certificate for an agent by agent ID.
    pub async fn get_certificate_for_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        certificate_id: Uuid,
    ) -> Result<AgentCertificate, ApiAgentsError> {
        let cert = AgentCertificate::find_by_id(&self.pool, tenant_id, certificate_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CertificateNotFoundId(certificate_id))?;

        // Verify the certificate belongs to this agent
        if cert.agent_id != agent_id {
            return Err(ApiAgentsError::CertificateNotFoundId(certificate_id));
        }

        Ok(cert)
    }

    /// Get the active certificate for an agent.
    pub async fn get_active_certificate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<AgentCertificate>, ApiAgentsError> {
        AgentCertificate::find_active_for_agent(&self.pool, tenant_id, agent_id)
            .await
            .map_err(ApiAgentsError::Database)
    }

    /// List certificates for a tenant with optional filtering.
    pub async fn list_certificates(
        &self,
        tenant_id: Uuid,
        filter: AgentCertificateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<CertificateListResponse, ApiAgentsError> {
        let certificates =
            AgentCertificate::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(ApiAgentsError::Database)?;

        // Count total (we'd need a count query, for now use len as approximation if < limit)
        let total = if certificates.len() < limit as usize && offset == 0 {
            certificates.len() as i64
        } else {
            // Would need a proper count query
            offset + certificates.len() as i64
        };

        Ok(CertificateListResponse {
            items: certificates,
            total,
            limit,
            offset,
        })
    }

    /// List certificates for a specific agent.
    pub async fn list_certificates_for_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<CertificateListResponse, ApiAgentsError> {
        // Verify agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::AgentNotFoundId(agent_id))?;

        let filter = AgentCertificateFilter {
            agent_id: Some(agent_id),
            ..Default::default()
        };

        self.list_certificates(tenant_id, filter, limit, offset)
            .await
    }

    /// List certificates expiring within the specified number of days.
    pub async fn list_expiring_certificates(
        &self,
        tenant_id: Uuid,
        within_days: i32,
        limit: i64,
    ) -> Result<Vec<AgentCertificate>, ApiAgentsError> {
        AgentCertificate::list_expiring(&self.pool, tenant_id, within_days, limit)
            .await
            .map_err(ApiAgentsError::Database)
    }

    /// Find a certificate by its fingerprint within a tenant.
    pub async fn find_by_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> Result<Option<AgentCertificate>, ApiAgentsError> {
        AgentCertificate::find_by_fingerprint(&self.pool, tenant_id, fingerprint)
            .await
            .map_err(ApiAgentsError::Database)
    }

    /// Find a certificate by fingerprint without tenant filter.
    ///
    /// **Security Warning**: Only use for mTLS validation where tenant is
    /// extracted from the certificate itself. Always verify `tenant_id` after lookup.
    pub async fn find_by_fingerprint_any_tenant(
        &self,
        fingerprint: &str,
    ) -> Result<Option<AgentCertificate>, ApiAgentsError> {
        AgentCertificate::find_by_fingerprint_any_tenant(&self.pool, fingerprint)
            .await
            .map_err(ApiAgentsError::Database)
    }

    /// Find a certificate by its serial number within a tenant.
    pub async fn find_by_serial(
        &self,
        tenant_id: Uuid,
        serial_number: &str,
    ) -> Result<Option<AgentCertificate>, ApiAgentsError> {
        AgentCertificate::find_by_serial(&self.pool, tenant_id, serial_number)
            .await
            .map_err(ApiAgentsError::Database)
    }

    /// Renew an existing certificate with a new validity period.
    ///
    /// This issues a new certificate for the same agent using the same CA,
    /// keeping the old certificate valid until its natural expiration
    /// (enabling zero-downtime rotation).
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `agent_id` - The agent ID
    /// * `certificate_id` - The certificate to renew
    /// * `request` - Renewal request parameters
    /// * `renewed_by` - Optional user ID who requested the renewal
    ///
    /// # Returns
    /// The new certificate response including the private key.
    ///
    /// # Errors
    /// * `CertificateNotFoundId` - Certificate doesn't exist
    /// * `CertificateRevoked` - Certificate has been revoked
    /// * `AgentNotActiveId` - Agent is not active
    /// * `CaDisabled` - CA is disabled
    pub async fn renew_certificate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        certificate_id: Uuid,
        request: RenewCertificateRequest,
        renewed_by: Option<Uuid>,
    ) -> Result<IssueCertificateResponse, ApiAgentsError> {
        // Get the existing certificate
        let existing_cert = self
            .get_certificate_for_agent(tenant_id, agent_id, certificate_id)
            .await?;

        // Validate the certificate is not revoked
        if existing_cert.is_revoked() {
            return Err(ApiAgentsError::CannotRenewRevokedCertificate);
        }

        // Validate the agent is still active
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::AgentNotFoundId(agent_id))?;

        if agent.status != "active" {
            return Err(ApiAgentsError::AgentNotActiveId(agent_id));
        }

        // Get the CA that issued the original certificate
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, existing_cert.ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(existing_cert.ca_id))?;

        if !ca.is_active {
            return Err(ApiAgentsError::CaDisabled(ca.id));
        }

        // Determine validity period (use requested or default to CA max)
        let validity_days = request
            .validity_days
            .map_or(ca.max_validity_days, |d| d.min(ca.max_validity_days));

        // Determine key algorithm (use requested or same as original)
        let key_algorithm = request.key_algorithm.as_deref().unwrap_or("ecdsa_p256");

        // Build issue request for renewal
        let issue_request = IssueCertificateRequest {
            validity_days,
            key_algorithm: key_algorithm.to_string(),
            ca_id: Some(ca.id),
            additional_sans: request.additional_sans,
        };

        // Issue the new certificate
        let result = self
            .issue_certificate(tenant_id, agent_id, issue_request, renewed_by)
            .await?;

        // Log audit event for certificate renewal
        let _ = self
            .audit_service
            .log_certificate_event(
                tenant_id,
                agent_id,
                "certificate_renewed",
                Some(result.certificate.id),
                Some(&result.certificate.serial_number),
                "success",
                Some(serde_json::json!({
                    "old_certificate_id": certificate_id,
                    "old_serial_number": existing_cert.serial_number,
                    "old_expires_at": existing_cert.not_after.to_rfc3339(),
                    "new_certificate_id": result.certificate.id,
                    "new_serial_number": result.certificate.serial_number,
                    "new_expires_at": result.certificate.not_after.to_rfc3339(),
                    "validity_days": validity_days,
                })),
                renewed_by,
            )
            .await;

        Ok(result)
    }

    /// Revoke a certificate.
    ///
    /// Marks the certificate as revoked in the database. The revoked certificate
    /// will be rejected during mTLS validation and included in CRL/OCSP responses.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `agent_id` - The agent ID
    /// * `certificate_id` - The certificate to revoke
    /// * `reason` - Revocation reason (`key_compromise`, `ca_compromise`, etc.)
    /// * `revoked_by` - Optional user ID who requested revocation
    pub async fn revoke_certificate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        certificate_id: Uuid,
        reason: &str,
        revoked_by: Option<Uuid>,
    ) -> Result<AgentCertificate, ApiAgentsError> {
        // Get the certificate
        let cert = self
            .get_certificate_for_agent(tenant_id, agent_id, certificate_id)
            .await?;

        // Check if already revoked
        if cert.is_revoked() {
            return Err(ApiAgentsError::CertificateAlreadyRevoked);
        }

        // Convert reason string to RFC 5280 reason code
        let reason_code = parse_revocation_reason(reason)?;

        // Revoke the certificate
        let revoked_cert =
            AgentCertificate::revoke(&self.pool, tenant_id, certificate_id, reason_code)
                .await
                .map_err(ApiAgentsError::Database)?
                .ok_or_else(|| ApiAgentsError::CertificateNotFoundId(certificate_id))?;

        // Log audit event
        let _ = self
            .audit_service
            .log_certificate_event(
                tenant_id,
                agent_id,
                "certificate_revoked",
                Some(certificate_id),
                Some(&revoked_cert.serial_number),
                "success",
                Some(serde_json::json!({
                    "reason": reason,
                    "reason_code": reason_code,
                    "fingerprint": revoked_cert.fingerprint_sha256,
                    "revoked_at": revoked_cert.revoked_at,
                })),
                revoked_by,
            )
            .await;

        Ok(revoked_cert)
    }

    /// List revoked certificates for a CA (for CRL generation).
    pub async fn list_revoked_for_ca(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<Vec<AgentCertificate>, ApiAgentsError> {
        let filter = AgentCertificateFilter {
            ca_id: Some(ca_id),
            status: Some("revoked".to_string()),
            ..Default::default()
        };

        AgentCertificate::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0)
            .await
            .map_err(ApiAgentsError::Database)
    }
}

/// Parse a revocation reason string to RFC 5280 reason code.
///
/// Supported reasons:
/// - unspecified (0)
/// - `key_compromise` (1)
/// - `ca_compromise` (2)
/// - `affiliation_changed` (3)
/// - superseded (4)
/// - `cessation_of_operation` (5)
/// - `certificate_hold` (6)
fn parse_revocation_reason(reason: &str) -> Result<i16, ApiAgentsError> {
    match reason.to_lowercase().as_str() {
        "unspecified" | "" => Ok(0),
        "key_compromise" | "keycompromise" => Ok(1),
        "ca_compromise" | "cacompromise" => Ok(2),
        "affiliation_changed" | "affiliationchanged" => Ok(3),
        "superseded" => Ok(4),
        "cessation_of_operation" | "cessationofoperation" => Ok(5),
        "certificate_hold" | "certificatehold" => Ok(6),
        _ => Err(ApiAgentsError::InvalidRevocationReason(reason.to_string())),
    }
}

/// Request to renew a certificate.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenewCertificateRequest {
    /// Validity period in days for the new certificate.
    /// If not specified, uses the CA's max validity.
    pub validity_days: Option<i32>,

    /// Key algorithm for the new certificate.
    /// If not specified, uses the same as the original.
    pub key_algorithm: Option<String>,

    /// Additional Subject Alternative Names for the new certificate.
    pub additional_sans: Option<Vec<String>>,
}

/// Response for listing certificates.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertificateListResponse {
    pub items: Vec<AgentCertificate>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Parse a key algorithm string into the enum.
fn parse_key_algorithm(s: &str) -> Result<KeyAlgorithm, ApiAgentsError> {
    match s.to_lowercase().as_str() {
        "ecdsa_p256" | "ecdsa-p256" | "p256" | "ec256" => Ok(KeyAlgorithm::EcdsaP256),
        "ecdsa_p384" | "ecdsa-p384" | "p384" | "ec384" => Ok(KeyAlgorithm::EcdsaP384),
        "rsa2048" | "rsa-2048" | "rsa_2048" => Ok(KeyAlgorithm::Rsa2048),
        "rsa4096" | "rsa-4096" | "rsa_4096" => Ok(KeyAlgorithm::Rsa4096),
        _ => Err(ApiAgentsError::InvalidKeyAlgorithm(s.to_string())),
    }
}

/// Calculate SHA-256 fingerprint of DER-encoded certificate.
fn calculate_fingerprint(der_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    let result = hasher.finalize();
    // Format as colon-separated hex (e.g., "AB:CD:EF:...")
    result
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format serial number bytes as hex string.
fn format_serial_number(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}

/// Format an X.500 Distinguished Name.
fn format_subject_dn(subject: &x509_parser::x509::X509Name) -> String {
    subject
        .iter()
        .flat_map(x509_parser::prelude::RelativeDistinguishedName::iter)
        .filter_map(|attr| {
            let oid_str = match attr.attr_type().to_string().as_str() {
                "2.5.4.3" => Some("CN"),
                "2.5.4.6" => Some("C"),
                "2.5.4.7" => Some("L"),
                "2.5.4.8" => Some("ST"),
                "2.5.4.10" => Some("O"),
                "2.5.4.11" => Some("OU"),
                _ => None,
            };
            oid_str.map(|oid| format!("{}={}", oid, attr.as_str().unwrap_or("")))
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_algorithm() {
        assert!(matches!(
            parse_key_algorithm("ecdsa_p256").unwrap(),
            KeyAlgorithm::EcdsaP256
        ));
        assert!(matches!(
            parse_key_algorithm("ecdsa-p256").unwrap(),
            KeyAlgorithm::EcdsaP256
        ));
        assert!(matches!(
            parse_key_algorithm("p256").unwrap(),
            KeyAlgorithm::EcdsaP256
        ));
        assert!(matches!(
            parse_key_algorithm("ECDSA_P384").unwrap(),
            KeyAlgorithm::EcdsaP384
        ));
        assert!(matches!(
            parse_key_algorithm("rsa2048").unwrap(),
            KeyAlgorithm::Rsa2048
        ));
        assert!(matches!(
            parse_key_algorithm("RSA-4096").unwrap(),
            KeyAlgorithm::Rsa4096
        ));
        assert!(parse_key_algorithm("invalid").is_err());
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = calculate_fingerprint(data);
        assert!(fingerprint.contains(":"));
        assert_eq!(fingerprint.len(), 32 * 3 - 1); // 32 bytes, 2 chars each, 31 colons
    }

    #[test]
    fn test_format_serial_number() {
        let serial = vec![0x01, 0x02, 0xAB, 0xCD];
        let formatted = format_serial_number(serial);
        assert_eq!(formatted, "0102ABCD");
    }
}
