//! Revocation Service for CRL and OCSP operations (F127).
//!
//! This service handles certificate revocation list (CRL) generation and
//! OCSP (Online Certificate Status Protocol) responses:
//! - CRL generation for a CA (with actual X.509 DER/PEM output)
//! - OCSP response handling
//!
//! The actual certificate revocation is handled by `CertificateService`.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::agent_certificate::AgentCertificate;
use xavyo_db::models::certificate_authority::CertificateAuthority;

use crate::error::ApiAgentsError;
use crate::providers::{RevocationReason, RevokedCertEntry};
use crate::services::ca_service::CaService;
use crate::services::certificate_service::CertificateService;

/// Service for CRL and OCSP operations.
pub struct RevocationService {
    pool: PgPool,
    certificate_service: Arc<CertificateService>,
    ca_service: Option<Arc<CaService>>,
}

/// A single entry in the CRL.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrlEntry {
    /// Certificate serial number (hex-encoded).
    pub serial_number: String,
    /// Date and time when the certificate was revoked.
    pub revocation_date: DateTime<Utc>,
    /// RFC 5280 revocation reason code.
    pub reason_code: i16,
}

/// Certificate Revocation List response.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrlResponse {
    /// CA that issued this CRL.
    pub issuer: CrlIssuer,
    /// When this CRL was generated.
    pub this_update: DateTime<Utc>,
    /// When the next CRL will be published.
    pub next_update: DateTime<Utc>,
    /// List of revoked certificates.
    pub revoked_certificates: Vec<CrlEntry>,
    /// CRL number (increments with each generation).
    pub crl_number: i64,
    /// PEM-encoded CRL (if generated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_pem: Option<String>,
}

/// CRL issuer information.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrlIssuer {
    /// CA ID.
    pub ca_id: Uuid,
    /// CA common name.
    pub common_name: String,
    /// CA subject DN.
    pub subject_dn: String,
}

/// OCSP request.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OcspRequest {
    /// Issuer name hash (hex-encoded SHA-1).
    #[serde(default)]
    pub issuer_name_hash: Option<String>,
    /// Issuer key hash (hex-encoded SHA-1).
    #[serde(default)]
    pub issuer_key_hash: Option<String>,
    /// Certificate serial number to check (hex-encoded).
    pub serial_number: String,
}

/// OCSP response.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OcspResponse {
    /// Status of the response (successful, `malformed_request`, `internal_error`, etc.).
    pub response_status: String,
    /// Certificate status (good, revoked, unknown).
    pub cert_status: String,
    /// Serial number checked.
    pub serial_number: String,
    /// Time this response was produced.
    pub produced_at: DateTime<Utc>,
    /// Time of this status check.
    pub this_update: DateTime<Utc>,
    /// Next update time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<DateTime<Utc>>,
    /// If revoked, when it was revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_time: Option<DateTime<Utc>>,
    /// If revoked, the reason code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<i16>,
}

impl RevocationService {
    /// Create a new `RevocationService`.
    #[must_use] 
    pub fn new(pool: PgPool, certificate_service: Arc<CertificateService>) -> Self {
        Self {
            pool,
            certificate_service,
            ca_service: None,
        }
    }

    /// Create a new `RevocationService` with CA service for CRL generation.
    #[must_use] 
    pub fn with_ca_service(
        pool: PgPool,
        certificate_service: Arc<CertificateService>,
        ca_service: Arc<CaService>,
    ) -> Self {
        Self {
            pool,
            certificate_service,
            ca_service: Some(ca_service),
        }
    }

    /// Generate a CRL for a specific CA.
    ///
    /// Returns a list of all revoked certificates for the CA in CRL format.
    /// If a CA service is configured, also generates the actual X.509 CRL in PEM format.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `ca_id` - The CA to generate the CRL for
    ///
    /// # Returns
    /// CRL response containing revoked certificates and optionally the PEM-encoded CRL.
    pub async fn generate_crl(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<CrlResponse, ApiAgentsError> {
        // Get CA
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        // Get revoked certificates
        let revoked_certs = self
            .certificate_service
            .list_revoked_for_ca(tenant_id, ca_id)
            .await?;

        // Build CRL entries for the JSON response
        let revoked_certificates: Vec<CrlEntry> = revoked_certs
            .iter()
            .filter_map(|cert| {
                cert.revoked_at.map(|revoked_at| CrlEntry {
                    serial_number: cert.serial_number.clone(),
                    revocation_date: revoked_at,
                    reason_code: cert.revocation_reason.unwrap_or(0),
                })
            })
            .collect();

        let now = Utc::now();
        // CRL is valid for 24 hours by default
        let next_update = now + Duration::hours(24);

        // CRL number based on timestamp
        let crl_number = now.timestamp();

        // Generate actual X.509 CRL PEM if CA service is available
        let crl_pem = if let Some(ref ca_service) = self.ca_service {
            // Build entries for the CA provider
            let provider_entries: Vec<RevokedCertEntry> = revoked_certs
                .iter()
                .filter_map(|cert| {
                    cert.revoked_at.map(|revoked_at| RevokedCertEntry {
                        serial_number: cert.serial_number.clone(),
                        revocation_time: revoked_at.timestamp(),
                        reason_code: RevocationReason::from_i16(
                            cert.revocation_reason.unwrap_or(0),
                        )
                        .unwrap_or(RevocationReason::Unspecified),
                    })
                })
                .collect();

            // Get the CA provider and generate the CRL
            match ca_service.get_ca_provider(tenant_id, ca_id).await {
                Ok(provider) => {
                    match provider.generate_crl(&provider_entries, crl_number).await {
                        Ok(crl_der) => {
                            // Convert DER to PEM
                            let pem = pem::Pem::new("X509 CRL", crl_der);
                            Some(pem::encode(&pem))
                        }
                        Err(e) => {
                            // Log but don't fail - CRL PEM is optional
                            tracing::warn!("Failed to generate CRL PEM: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get CA provider for CRL generation: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(CrlResponse {
            issuer: CrlIssuer {
                ca_id: ca.id,
                common_name: ca.name.clone(),
                subject_dn: ca.subject_dn.clone(),
            },
            this_update: now,
            next_update,
            revoked_certificates,
            crl_number,
            crl_pem,
        })
    }

    /// Handle an OCSP request.
    ///
    /// Checks the revocation status of a certificate and returns an OCSP response.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `ca_id` - The CA that issued the certificate
    /// * `request` - OCSP request parameters
    ///
    /// # Returns
    /// OCSP response with certificate status.
    pub async fn handle_ocsp(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
        request: OcspRequest,
    ) -> Result<OcspResponse, ApiAgentsError> {
        let now = Utc::now();

        // Validate CA exists
        let _ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        // Find certificate by serial number within tenant
        let cert = AgentCertificate::find_by_serial(&self.pool, tenant_id, &request.serial_number)
            .await
            .map_err(ApiAgentsError::Database)?;

        match cert {
            Some(cert) => {
                // Verify certificate was issued by this CA
                if cert.ca_id != ca_id {
                    return Ok(OcspResponse {
                        response_status: "successful".to_string(),
                        cert_status: "unknown".to_string(),
                        serial_number: request.serial_number,
                        produced_at: now,
                        this_update: now,
                        next_update: Some(now + Duration::hours(1)),
                        revocation_time: None,
                        revocation_reason: None,
                    });
                }

                if cert.is_revoked() {
                    Ok(OcspResponse {
                        response_status: "successful".to_string(),
                        cert_status: "revoked".to_string(),
                        serial_number: request.serial_number,
                        produced_at: now,
                        this_update: now,
                        next_update: Some(now + Duration::hours(1)),
                        revocation_time: cert.revoked_at,
                        revocation_reason: cert.revocation_reason,
                    })
                } else if cert.not_after < now {
                    // Expired but not revoked - still "good" per OCSP
                    Ok(OcspResponse {
                        response_status: "successful".to_string(),
                        cert_status: "good".to_string(),
                        serial_number: request.serial_number,
                        produced_at: now,
                        this_update: now,
                        next_update: Some(now + Duration::hours(1)),
                        revocation_time: None,
                        revocation_reason: None,
                    })
                } else {
                    Ok(OcspResponse {
                        response_status: "successful".to_string(),
                        cert_status: "good".to_string(),
                        serial_number: request.serial_number,
                        produced_at: now,
                        this_update: now,
                        next_update: Some(now + Duration::hours(1)),
                        revocation_time: None,
                        revocation_reason: None,
                    })
                }
            }
            None => {
                // Certificate not found - status unknown
                Ok(OcspResponse {
                    response_status: "successful".to_string(),
                    cert_status: "unknown".to_string(),
                    serial_number: request.serial_number,
                    produced_at: now,
                    this_update: now,
                    next_update: Some(now + Duration::hours(1)),
                    revocation_time: None,
                    revocation_reason: None,
                })
            }
        }
    }

    /// Check if a certificate is revoked by serial number.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `serial_number` - The certificate serial number
    ///
    /// # Returns
    /// True if the certificate is revoked.
    pub async fn is_revoked(
        &self,
        tenant_id: Uuid,
        serial_number: &str,
    ) -> Result<bool, ApiAgentsError> {
        let cert = AgentCertificate::find_by_serial(&self.pool, tenant_id, serial_number)
            .await
            .map_err(ApiAgentsError::Database)?;

        Ok(cert.is_some_and(|c| c.is_revoked()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_entry_serialization() {
        let entry = CrlEntry {
            serial_number: "01A2B3C4".to_string(),
            revocation_date: Utc::now(),
            reason_code: 1,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("01A2B3C4"));
        assert!(json.contains("reason_code"));
    }

    #[test]
    fn test_ocsp_request_deserialization() {
        let json = r#"{
            "serial_number": "DEADBEEF",
            "issuer_name_hash": "abc123"
        }"#;

        let req: OcspRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.serial_number, "DEADBEEF");
        assert_eq!(req.issuer_name_hash, Some("abc123".to_string()));
    }

    #[test]
    fn test_ocsp_response_serialization() {
        let resp = OcspResponse {
            response_status: "successful".to_string(),
            cert_status: "good".to_string(),
            serial_number: "DEADBEEF".to_string(),
            produced_at: Utc::now(),
            this_update: Utc::now(),
            next_update: Some(Utc::now()),
            revocation_time: None,
            revocation_reason: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("successful"));
        assert!(json.contains("good"));
        // Should not contain revocation fields when None
        assert!(!json.contains("revocation_time"));
    }
}
