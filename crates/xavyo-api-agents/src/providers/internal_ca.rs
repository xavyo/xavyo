//! Internal Certificate Authority Provider (F127).
//!
//! This provider uses rcgen to generate certificates signed by an internal CA.
//! The CA private key can be stored encrypted in the database or referenced
//! from xavyo-secrets.

use async_trait::async_trait;
use chrono::{Datelike, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevocationReason as RcgenRevocationReason, RevokedCertParams, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::prelude::*;

use super::{
    CaProvider, CaProviderError, CaResult, CertificateIssueRequest, CertificateRenewRequest,
    CertificateRevokeRequest, CertificateStatus, CertificateValidation, IssuedCertificate,
    KeyAlgorithm, RevocationReason, RevocationResult, RevokedCertEntry,
};

/// Internal CA provider configuration.
#[derive(Debug, Clone)]
pub struct InternalCaConfig {
    /// CA ID in the database.
    pub ca_id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// PEM-encoded CA certificate.
    pub ca_certificate_pem: String,

    /// PEM-encoded CA private key (decrypted).
    pub ca_private_key_pem: Option<String>,

    /// Encrypted CA private key (if stored in DB).
    pub encrypted_private_key: Option<Vec<u8>>,

    /// Reference to private key in xavyo-secrets.
    pub private_key_ref: Option<String>,

    /// Subject DN of the CA.
    pub ca_subject_dn: String,

    /// Maximum certificate validity in days.
    pub max_validity_days: i32,

    /// CRL distribution point URL.
    pub crl_url: Option<String>,

    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
}

/// Internal Certificate Authority provider.
///
/// Uses rcgen for certificate generation and x509-parser for validation.
pub struct InternalCaProvider {
    config: InternalCaConfig,
    /// Cached CA key pair (loaded on first use).
    /// Prepared for performance optimization but not yet used.
    #[allow(dead_code)]
    ca_key_pair: Option<KeyPair>,
}

impl InternalCaProvider {
    /// Create a new internal CA provider.
    #[must_use]
    pub fn new(config: InternalCaConfig) -> Self {
        Self {
            config,
            ca_key_pair: None,
        }
    }

    /// Create a provider with pre-loaded key pair.
    #[must_use]
    pub fn with_key_pair(config: InternalCaConfig, key_pair: KeyPair) -> Self {
        Self {
            config,
            ca_key_pair: Some(key_pair),
        }
    }

    /// Get the CA configuration.
    #[must_use]
    pub fn config(&self) -> &InternalCaConfig {
        &self.config
    }

    /// Load and cache the CA key pair.
    /// Prepared for caching optimization but not yet used.
    #[allow(dead_code)]
    fn load_ca_key_pair(&mut self) -> CaResult<&KeyPair> {
        if self.ca_key_pair.is_none() {
            let key_pem = self.config.ca_private_key_pem.as_ref().ok_or_else(|| {
                CaProviderError::PrivateKeyUnavailable("CA private key not available".to_string())
            })?;

            let key_pair = KeyPair::from_pem(key_pem).map_err(|e| {
                CaProviderError::InvalidConfiguration(format!("Failed to parse CA key: {e}"))
            })?;

            self.ca_key_pair = Some(key_pair);
        }

        Ok(self.ca_key_pair.as_ref().unwrap())
    }

    /// Generate a key pair for the requested algorithm.
    fn generate_key_pair(algorithm: KeyAlgorithm) -> CaResult<KeyPair> {
        let alg = match algorithm {
            KeyAlgorithm::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
            KeyAlgorithm::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => &PKCS_RSA_SHA256,
        };

        KeyPair::generate_for(alg)
            .map_err(|e| CaProviderError::Internal(format!("Failed to generate key pair: {e}")))
    }

    /// Calculate SHA-256 fingerprint of a certificate in DER format.
    fn calculate_fingerprint(cert_der: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let result = hasher.finalize();

        result
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Generate a unique serial number.
    fn generate_serial_number() -> String {
        // Use UUID as base for serial number (guaranteed unique)
        let uuid = Uuid::new_v4();
        let bytes = uuid.as_bytes();
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Parse a PEM certificate and extract DER bytes.
    fn parse_pem_to_der(pem_str: &str) -> CaResult<Vec<u8>> {
        let pem_data = ::pem::parse(pem_str)
            .map_err(|e| CaProviderError::InvalidFormat(format!("Failed to parse PEM: {e}")))?;

        Ok(pem_data.contents().to_vec())
    }

    /// Convert a String to `Ia5String` for SAN.
    fn to_ia5string(s: &str) -> CaResult<Ia5String> {
        Ia5String::try_from(s)
            .map_err(|e| CaProviderError::InvalidFormat(format!("Invalid IA5String '{s}': {e}")))
    }

    /// Build `CertificateParams` from an X509 certificate.
    ///
    /// This extracts the distinguished name from the certificate to create
    /// params that can be used as the issuer in `signed_by()`.
    fn build_ca_params_from_x509(cert: &X509Certificate) -> CaResult<CertificateParams> {
        let mut params = CertificateParams::default();

        // Extract DN components from the certificate's subject
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                let oid = attr.attr_type().to_string();
                let value = attr.as_str().unwrap_or("");

                // Map OID to DnType
                match oid.as_str() {
                    "2.5.4.3" => params.distinguished_name.push(DnType::CommonName, value),
                    "2.5.4.6" => params.distinguished_name.push(DnType::CountryName, value),
                    "2.5.4.7" => params.distinguished_name.push(DnType::LocalityName, value),
                    "2.5.4.8" => params
                        .distinguished_name
                        .push(DnType::StateOrProvinceName, value),
                    "2.5.4.10" => params
                        .distinguished_name
                        .push(DnType::OrganizationName, value),
                    "2.5.4.11" => params
                        .distinguished_name
                        .push(DnType::OrganizationalUnitName, value),
                    _ => {} // Skip unknown OIDs
                }
            }
        }

        // Mark as CA (needed for signing)
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Set key usages for CA
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        Ok(params)
    }
}

#[async_trait]
impl CaProvider for InternalCaProvider {
    fn provider_type(&self) -> &'static str {
        "internal"
    }

    async fn health_check(&self) -> CaResult<()> {
        // Verify we have access to the private key
        if self.config.ca_private_key_pem.is_none()
            && self.config.encrypted_private_key.is_none()
            && self.config.private_key_ref.is_none()
        {
            return Err(CaProviderError::PrivateKeyUnavailable(
                "No private key configured".to_string(),
            ));
        }

        // Verify CA certificate is parseable
        let _ = Self::parse_pem_to_der(&self.config.ca_certificate_pem).map_err(|e| {
            CaProviderError::InvalidConfiguration(format!("CA certificate invalid: {e}"))
        })?;

        Ok(())
    }

    async fn issue_certificate(
        &self,
        request: &CertificateIssueRequest,
    ) -> CaResult<IssuedCertificate> {
        // Validate requested validity
        if request.validity_days > self.config.max_validity_days {
            return Err(CaProviderError::ValidityExceedsMax {
                requested: request.validity_days,
                max: self.config.max_validity_days,
            });
        }

        // Load CA private key - required for signing
        let ca_key_pem = self.config.ca_private_key_pem.as_ref().ok_or_else(|| {
            CaProviderError::PrivateKeyUnavailable(
                "CA private key not available for signing".to_string(),
            )
        })?;
        let ca_key_pair = KeyPair::from_pem(ca_key_pem).map_err(|e| {
            CaProviderError::InvalidConfiguration(format!("Failed to parse CA private key: {e}"))
        })?;

        // Parse CA certificate to extract issuer DN for the CA params
        let ca_der = Self::parse_pem_to_der(&self.config.ca_certificate_pem)?;
        let (_, ca_x509) = X509Certificate::from_der(&ca_der).map_err(|e| {
            CaProviderError::InvalidConfiguration(format!("Failed to parse CA certificate: {e:?}"))
        })?;

        // Build CA params with the issuer DN (needed for signed_by)
        let ca_params = Self::build_ca_params_from_x509(&ca_x509)?;

        // Create a Certificate by self-signing the CA params with CA's key
        // rcgen 0.13's signed_by() requires a &Certificate (not CertificateParams)
        // This recreates the CA Certificate object with the correct issuer DN
        let ca_certificate = ca_params.self_signed(&ca_key_pair).map_err(|e| {
            CaProviderError::SigningFailed(format!(
                "Failed to recreate CA certificate for signing: {e}"
            ))
        })?;

        // Generate serial number
        let serial_number = Self::generate_serial_number();

        // Generate key pair for the agent
        let agent_key_pair = Self::generate_key_pair(request.key_algorithm)?;

        // Create certificate parameters for the agent
        let mut params = CertificateParams::default();

        // Set subject DN
        params
            .distinguished_name
            .push(DnType::CommonName, request.agent_name.clone());
        params.distinguished_name.push(
            DnType::OrganizationalUnitName,
            format!("Agent-{}", request.agent_id),
        );
        params.distinguished_name.push(
            DnType::OrganizationName,
            format!("Tenant-{}", request.tenant_id),
        );

        // Set validity period
        let not_before = Utc::now();
        let not_after = not_before + Duration::days(i64::from(request.validity_days));
        params.not_before = rcgen::date_time_ymd(
            not_before.date_naive().year(),
            not_before.date_naive().month() as u8,
            not_before.date_naive().day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.date_naive().year(),
            not_after.date_naive().month() as u8,
            not_after.date_naive().day() as u8,
        );

        // Set serial number
        let serial_bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&serial_number[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

        // Add Subject Alternative Names
        // URI SAN for agent identity: xavyo:tenant:{tenant_id}:agent:{agent_id}
        let agent_uri = format!(
            "xavyo:tenant:{}:agent:{}",
            request.tenant_id, request.agent_id
        );
        params
            .subject_alt_names
            .push(SanType::URI(Self::to_ia5string(&agent_uri)?));

        // Add DNS SAN for the agent name
        params
            .subject_alt_names
            .push(SanType::DnsName(Self::to_ia5string(&request.agent_name)?));

        // Add any additional SANs
        for san in &request.additional_sans {
            if let Some(dns_name) = san.strip_prefix("dns:") {
                params
                    .subject_alt_names
                    .push(SanType::DnsName(Self::to_ia5string(dns_name)?));
            } else if let Some(uri) = san.strip_prefix("uri:") {
                params
                    .subject_alt_names
                    .push(SanType::URI(Self::to_ia5string(uri)?));
            } else if let Some(email) = san.strip_prefix("email:") {
                params
                    .subject_alt_names
                    .push(SanType::Rfc822Name(Self::to_ia5string(email)?));
            } else {
                // Default to DNS SAN
                params
                    .subject_alt_names
                    .push(SanType::DnsName(Self::to_ia5string(san)?));
            }
        }

        // Set key usages for client certificate
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Set extended key usages for mTLS
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];

        // Not a CA certificate
        params.is_ca = IsCa::NoCa;

        // Sign the agent certificate with the CA's key (NOT self-signed!)
        let cert = params
            .signed_by(&agent_key_pair, &ca_certificate, &ca_key_pair)
            .map_err(|e| {
                CaProviderError::SigningFailed(format!("Failed to sign certificate with CA: {e}"))
            })?;

        // Get PEM-encoded certificate and private key
        let certificate_pem = cert.pem();
        let private_key_pem = agent_key_pair.serialize_pem();

        // Parse to get DER for fingerprint
        let cert_der = Self::parse_pem_to_der(&certificate_pem)?;
        let fingerprint_sha256 = Self::calculate_fingerprint(&cert_der);

        // Build subject DN string
        let subject_dn = format!(
            "CN={},OU=Agent-{},O=Tenant-{}",
            request.agent_name, request.agent_id, request.tenant_id
        );

        Ok(IssuedCertificate {
            certificate_id: Uuid::new_v4(),
            certificate_pem,
            private_key_pem,
            chain_pem: self.config.ca_certificate_pem.clone(),
            serial_number,
            fingerprint_sha256,
            subject_dn,
            issuer_dn: self.config.ca_subject_dn.clone(),
            not_before: not_before.timestamp(),
            not_after: not_after.timestamp(),
        })
    }

    async fn renew_certificate(
        &self,
        request: &CertificateRenewRequest,
    ) -> CaResult<IssuedCertificate> {
        // Validate requested validity
        if request.validity_days > self.config.max_validity_days {
            return Err(CaProviderError::ValidityExceedsMax {
                requested: request.validity_days,
                max: self.config.max_validity_days,
            });
        }

        // For renewal, we issue a new certificate with the same agent info
        // The actual certificate info (name, etc.) should be retrieved from the database
        // For now, we return an error indicating this needs database integration
        Err(CaProviderError::Internal(
            "Certificate renewal requires database integration - use CertificateService::renew_certificate".to_string(),
        ))
    }

    async fn revoke_certificate(
        &self,
        _request: &CertificateRevokeRequest,
    ) -> CaResult<RevocationResult> {
        // Revocation is handled at the service layer (database update)
        // The provider doesn't maintain revocation state
        Err(CaProviderError::Internal(
            "Certificate revocation handled by RevocationService".to_string(),
        ))
    }

    async fn validate_certificate(&self, certificate_pem: &str) -> CaResult<CertificateValidation> {
        // Parse the certificate
        let cert_der = match Self::parse_pem_to_der(certificate_pem) {
            Ok(der) => der,
            Err(e) => {
                return Ok(CertificateValidation::invalid(
                    CertificateStatus::Active, // Status unknown, use Active as placeholder
                    format!("Failed to parse certificate: {e}"),
                ));
            }
        };

        let (_, cert) = match X509Certificate::from_der(&cert_der) {
            Ok(result) => result,
            Err(e) => {
                return Ok(CertificateValidation::invalid(
                    CertificateStatus::Active,
                    format!("Failed to parse X.509: {e:?}"),
                ));
            }
        };

        // Parse CA certificate to verify signature
        let ca_der = match Self::parse_pem_to_der(&self.config.ca_certificate_pem) {
            Ok(der) => der,
            Err(e) => {
                return Ok(CertificateValidation::invalid(
                    CertificateStatus::Active,
                    format!("Failed to parse CA certificate: {e}"),
                ));
            }
        };

        let (_, ca_cert) = match X509Certificate::from_der(&ca_der) {
            Ok(result) => result,
            Err(e) => {
                return Ok(CertificateValidation::invalid(
                    CertificateStatus::Active,
                    format!("Failed to parse CA X.509: {e:?}"),
                ));
            }
        };

        // Verify the certificate's issuer DN matches the CA's subject DN
        if cert.issuer() != ca_cert.subject() {
            return Ok(CertificateValidation::invalid(
                CertificateStatus::Active,
                "Certificate issuer DN does not match CA subject DN",
            ));
        }

        // Verify certificate signature using CA public key
        let ca_public_key = ca_cert.public_key();
        if let Err(e) = cert.verify_signature(Some(ca_public_key)) {
            return Ok(CertificateValidation::invalid(
                CertificateStatus::Active,
                format!("Certificate signature verification failed: {e:?}"),
            ));
        }

        // Check expiration
        let now = Utc::now().timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        if now < not_before {
            return Ok(CertificateValidation::invalid(
                CertificateStatus::Active,
                "Certificate is not yet valid",
            ));
        }

        if now > not_after {
            return Ok(CertificateValidation::invalid(
                CertificateStatus::Expired,
                "Certificate has expired",
            ));
        }

        // Extract serial number
        let serial_number = cert
            .serial
            .to_bytes_be()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();

        // Try to extract agent_id and tenant_id from SAN URIs
        let mut agent_id: Option<Uuid> = None;
        let mut tenant_id: Option<Uuid> = None;

        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let GeneralName::URI(uri) = name {
                    // Parse URI: xavyo:tenant:{tenant_id}:agent:{agent_id}
                    if uri.starts_with("xavyo:tenant:") {
                        let parts: Vec<&str> = uri.split(':').collect();
                        if parts.len() >= 5 {
                            tenant_id = Uuid::parse_str(parts[2]).ok();
                            if parts[3] == "agent" {
                                agent_id = Uuid::parse_str(parts[4]).ok();
                            }
                        }
                    }
                }
            }
        }

        // Calculate fingerprint
        let _fingerprint = Self::calculate_fingerprint(&cert_der);

        Ok(CertificateValidation {
            valid: true,
            status: CertificateStatus::Active,
            agent_id,
            tenant_id,
            serial_number: Some(serial_number),
            expires_at: Some(not_after),
            error: None,
        })
    }

    async fn get_ca_chain(&self) -> CaResult<String> {
        Ok(self.config.ca_certificate_pem.clone())
    }

    async fn generate_crl(
        &self,
        revoked_certs: &[RevokedCertEntry],
        crl_number: i64,
    ) -> CaResult<Vec<u8>> {
        // Load CA private key - required for signing the CRL
        let ca_key_pem = self.config.ca_private_key_pem.as_ref().ok_or_else(|| {
            CaProviderError::PrivateKeyUnavailable(
                "CA private key not available for CRL signing".to_string(),
            )
        })?;
        let ca_key_pair = KeyPair::from_pem(ca_key_pem).map_err(|e| {
            CaProviderError::InvalidConfiguration(format!("Failed to parse CA private key: {e}"))
        })?;

        // Parse CA certificate to get issuer info
        let ca_der = Self::parse_pem_to_der(&self.config.ca_certificate_pem)?;
        let (_, ca_x509) = X509Certificate::from_der(&ca_der).map_err(|e| {
            CaProviderError::InvalidConfiguration(format!("Failed to parse CA certificate: {e:?}"))
        })?;

        // Build CA params for creating the issuer
        let ca_params = Self::build_ca_params_from_x509(&ca_x509)?;

        // Create the issuer certificate (needed for signing the CRL)
        let ca_certificate = ca_params.self_signed(&ca_key_pair).map_err(|e| {
            CaProviderError::SigningFailed(format!(
                "Failed to recreate CA certificate for CRL signing: {e}"
            ))
        })?;

        // Convert revoked cert entries to rcgen format
        let revoked_cert_params: Vec<RevokedCertParams> = revoked_certs
            .iter()
            .filter_map(|entry| {
                // Parse hex serial number to bytes
                let serial_bytes: Vec<u8> = (0..entry.serial_number.len() / 2)
                    .filter_map(|i| {
                        let start = i * 2;
                        let end = start + 2;
                        u8::from_str_radix(&entry.serial_number[start..end], 16).ok()
                    })
                    .collect();

                if serial_bytes.is_empty() {
                    return None;
                }

                // Convert revocation reason
                let reason_code = match entry.reason_code {
                    RevocationReason::Unspecified => Some(RcgenRevocationReason::Unspecified),
                    RevocationReason::KeyCompromise => Some(RcgenRevocationReason::KeyCompromise),
                    RevocationReason::CaCompromise => Some(RcgenRevocationReason::CaCompromise),
                    RevocationReason::AffiliationChanged => {
                        Some(RcgenRevocationReason::AffiliationChanged)
                    }
                    RevocationReason::Superseded => Some(RcgenRevocationReason::Superseded),
                    RevocationReason::CessationOfOperation => {
                        Some(RcgenRevocationReason::CessationOfOperation)
                    }
                    RevocationReason::CertificateHold => {
                        Some(RcgenRevocationReason::CertificateHold)
                    }
                    RevocationReason::PrivilegeWithdrawn => {
                        Some(RcgenRevocationReason::PrivilegeWithdrawn)
                    }
                    RevocationReason::AaCompromise => Some(RcgenRevocationReason::AaCompromise),
                    RevocationReason::RemoveFromCrl => None, // RemoveFromCrl means don't include
                };

                reason_code.map(|reason| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&serial_bytes),
                    revocation_time: rcgen::date_time_ymd(
                        chrono::DateTime::from_timestamp(entry.revocation_time, 0)
                            .map_or(2024, |dt| dt.date_naive().year()),
                        chrono::DateTime::from_timestamp(entry.revocation_time, 0)
                            .map_or(1, |dt| dt.date_naive().month() as u8),
                        chrono::DateTime::from_timestamp(entry.revocation_time, 0)
                            .map_or(1, |dt| dt.date_naive().day() as u8),
                    ),
                    reason_code: Some(reason),
                    invalidity_date: None,
                })
            })
            .collect();

        // Calculate this_update and next_update times
        let now = Utc::now();
        let next_update = now + Duration::hours(24); // CRL valid for 24 hours

        // Build CRL params (algorithm is determined by the signing key pair)
        let crl_params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(
                now.date_naive().year(),
                now.date_naive().month() as u8,
                now.date_naive().day() as u8,
            ),
            next_update: rcgen::date_time_ymd(
                next_update.date_naive().year(),
                next_update.date_naive().month() as u8,
                next_update.date_naive().day() as u8,
            ),
            crl_number: SerialNumber::from_slice(&crl_number.to_be_bytes()),
            issuing_distribution_point: None,
            revoked_certs: revoked_cert_params,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        // Create the CRL signed by the CA
        let crl = crl_params
            .signed_by(&ca_certificate, &ca_key_pair)
            .map_err(|e| CaProviderError::SigningFailed(format!("Failed to sign CRL: {e}")))?;

        Ok(crl.der().to_vec())
    }
}

/// Create a new internal CA (self-signed root CA).
///
/// # Arguments
/// * `name` - CA name for the subject DN
/// * `organization` - Organization name
/// * `validity_days` - Validity period in days
/// * `algorithm` - Key algorithm to use
///
/// # Returns
/// Tuple of (CA certificate PEM, CA private key PEM, subject DN)
pub fn create_internal_ca(
    name: &str,
    organization: &str,
    validity_days: i32,
    algorithm: KeyAlgorithm,
) -> CaResult<(String, String, String)> {
    // Generate CA key pair
    let key_pair = InternalCaProvider::generate_key_pair(algorithm)?;

    // Create CA certificate parameters
    let mut params = CertificateParams::default();

    // Set subject DN
    params.distinguished_name.push(DnType::CommonName, name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, organization);
    params.distinguished_name.push(DnType::CountryName, "FR"); // Default to France

    // Set validity period
    let not_before = Utc::now();
    let not_after = not_before + Duration::days(i64::from(validity_days));
    params.not_before = rcgen::date_time_ymd(
        not_before.date_naive().year(),
        not_before.date_naive().month() as u8,
        not_before.date_naive().day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        not_after.date_naive().year(),
        not_after.date_naive().month() as u8,
        not_after.date_naive().day() as u8,
    );

    // Mark as CA
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // No path length constraint

    // Set key usages for CA
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // Generate the CA certificate using rcgen 0.13 API
    let cert = params.self_signed(&key_pair).map_err(|e| {
        CaProviderError::SigningFailed(format!("Failed to generate CA certificate: {e}"))
    })?;

    let certificate_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();
    let subject_dn = format!("CN={name},O={organization},C=FR");

    Ok((certificate_pem, private_key_pem, subject_dn))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> InternalCaConfig {
        InternalCaConfig {
            ca_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            ca_certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            ca_private_key_pem: None,
            encrypted_private_key: Some(vec![1, 2, 3]),
            private_key_ref: None,
            ca_subject_dn: "CN=Test CA,O=Xavyo".to_string(),
            max_validity_days: 365,
            crl_url: Some("https://example.com/crl".to_string()),
            ocsp_url: Some("https://example.com/ocsp".to_string()),
        }
    }

    #[test]
    fn test_provider_type() {
        let provider = InternalCaProvider::new(test_config());
        assert_eq!(provider.provider_type(), "internal");
    }

    #[tokio::test]
    async fn test_health_check_with_key() {
        let provider = InternalCaProvider::new(test_config());
        // Health check will fail because the cert is not valid, but that's expected
        // The important thing is it doesn't panic
        let _ = provider.health_check().await;
    }

    #[tokio::test]
    async fn test_health_check_without_key() {
        let mut config = test_config();
        config.encrypted_private_key = None;
        config.private_key_ref = None;

        let provider = InternalCaProvider::new(config);
        let result = provider.health_check().await;
        assert!(matches!(
            result,
            Err(CaProviderError::PrivateKeyUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_get_ca_chain() {
        let config = test_config();
        let expected_chain = config.ca_certificate_pem.clone();
        let provider = InternalCaProvider::new(config);

        let chain = provider.get_ca_chain().await.unwrap();
        assert_eq!(chain, expected_chain);
    }

    #[tokio::test]
    async fn test_validity_exceeds_max() {
        let config = test_config();
        let provider = InternalCaProvider::new(config);

        let request = CertificateIssueRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            validity_days: 999, // Exceeds max of 365
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec![],
        };

        let result = provider.issue_certificate(&request).await;
        assert!(matches!(
            result,
            Err(CaProviderError::ValidityExceedsMax {
                requested: 999,
                max: 365
            })
        ));
    }

    #[test]
    fn test_generate_serial_number() {
        let serial = InternalCaProvider::generate_serial_number();
        assert_eq!(serial.len(), 32); // 16 bytes = 32 hex chars
        assert!(serial.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = InternalCaProvider::calculate_fingerprint(data);
        assert!(fingerprint.contains(':')); // Should be colon-separated
        assert!(fingerprint.len() > 60); // SHA-256 = 64 hex chars + colons
    }

    #[test]
    fn test_generate_key_pair_ecdsa_p256() {
        let key_pair = InternalCaProvider::generate_key_pair(KeyAlgorithm::EcdsaP256);
        assert!(key_pair.is_ok());
    }

    #[test]
    fn test_generate_key_pair_ecdsa_p384() {
        let key_pair = InternalCaProvider::generate_key_pair(KeyAlgorithm::EcdsaP384);
        assert!(key_pair.is_ok());
    }

    #[test]
    fn test_create_internal_ca() {
        let result = create_internal_ca("Test CA", "Xavyo Test", 365, KeyAlgorithm::EcdsaP256);

        assert!(result.is_ok());
        let (cert_pem, key_pem, subject_dn) = result.unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(subject_dn, "CN=Test CA,O=Xavyo Test,C=FR");
    }

    #[tokio::test]
    async fn test_issue_certificate_full() {
        // First create a real CA
        let (ca_cert, ca_key, ca_dn) =
            create_internal_ca("Test CA", "Xavyo Test", 3650, KeyAlgorithm::EcdsaP256).unwrap();

        let config = InternalCaConfig {
            ca_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            ca_certificate_pem: ca_cert,
            ca_private_key_pem: Some(ca_key),
            encrypted_private_key: None,
            private_key_ref: None,
            ca_subject_dn: ca_dn,
            max_validity_days: 365,
            crl_url: None,
            ocsp_url: None,
        };

        let provider = InternalCaProvider::new(config.clone());

        let request = CertificateIssueRequest {
            tenant_id: config.tenant_id,
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            validity_days: 90,
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec!["dns:test-agent.example.com".to_string()],
        };

        let result = provider.issue_certificate(&request).await;
        assert!(result.is_ok(), "Certificate issuance failed: {:?}", result);

        let issued = result.unwrap();
        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!issued.serial_number.is_empty());
        assert!(issued.fingerprint_sha256.contains(':'));
        assert!(issued.not_after > issued.not_before);
    }

    #[tokio::test]
    async fn test_validate_certificate() {
        // Create a CA and issue a certificate
        let (ca_cert, ca_key, ca_dn) =
            create_internal_ca("Test CA", "Xavyo", 3650, KeyAlgorithm::EcdsaP256).unwrap();

        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let config = InternalCaConfig {
            ca_id: Uuid::new_v4(),
            tenant_id,
            ca_certificate_pem: ca_cert,
            ca_private_key_pem: Some(ca_key),
            encrypted_private_key: None,
            private_key_ref: None,
            ca_subject_dn: ca_dn,
            max_validity_days: 365,
            crl_url: None,
            ocsp_url: None,
        };

        let provider = InternalCaProvider::new(config);

        let request = CertificateIssueRequest {
            tenant_id,
            agent_id,
            agent_name: "validation-test-agent".to_string(),
            validity_days: 90,
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec![],
        };

        let issued = provider.issue_certificate(&request).await.unwrap();

        // Now validate the certificate
        let validation = provider
            .validate_certificate(&issued.certificate_pem)
            .await
            .unwrap();

        assert!(validation.valid);
        assert_eq!(validation.status, CertificateStatus::Active);
        assert_eq!(validation.agent_id, Some(agent_id));
        assert_eq!(validation.tenant_id, Some(tenant_id));
        assert!(validation.serial_number.is_some());
        assert!(validation.expires_at.is_some());
    }

    #[tokio::test]
    async fn test_issued_certificate_is_ca_signed_not_self_signed() {
        // CRITICAL TEST: Verify that issued certificates are signed by the CA,
        // not self-signed. This validates the fix for the issue where
        // `self_signed()` was incorrectly used instead of `signed_by()`.

        // Create a CA
        let (ca_cert_pem, ca_key_pem, ca_dn) =
            create_internal_ca("Issuer Test CA", "Xavyo PKI", 3650, KeyAlgorithm::EcdsaP256)
                .unwrap();

        // Parse CA certificate to get its subject DN
        let ca_der = InternalCaProvider::parse_pem_to_der(&ca_cert_pem).unwrap();
        let (_, ca_x509) = X509Certificate::from_der(&ca_der).unwrap();
        let ca_subject = ca_x509.subject().to_string();

        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let config = InternalCaConfig {
            ca_id: Uuid::new_v4(),
            tenant_id,
            ca_certificate_pem: ca_cert_pem,
            ca_private_key_pem: Some(ca_key_pem),
            encrypted_private_key: None,
            private_key_ref: None,
            ca_subject_dn: ca_dn,
            max_validity_days: 365,
            crl_url: None,
            ocsp_url: None,
        };

        let provider = InternalCaProvider::new(config);

        let request = CertificateIssueRequest {
            tenant_id,
            agent_id,
            agent_name: "ca-sign-test-agent".to_string(),
            validity_days: 90,
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec![],
        };

        let issued = provider.issue_certificate(&request).await.unwrap();

        // Parse the issued certificate
        let agent_der = InternalCaProvider::parse_pem_to_der(&issued.certificate_pem).unwrap();
        let (_, agent_x509) = X509Certificate::from_der(&agent_der).unwrap();

        // Get the issuer DN from the agent certificate
        let agent_issuer = agent_x509.issuer().to_string();
        let agent_subject = agent_x509.subject().to_string();

        // CRITICAL ASSERTIONS:
        // 1. The agent certificate's ISSUER must match the CA's SUBJECT (proves CA signed it)
        assert_eq!(
            agent_issuer, ca_subject,
            "Certificate issuer DN must match CA subject DN. Got issuer='{}', expected CA subject='{}'",
            agent_issuer, ca_subject
        );

        // 2. The agent certificate's SUBJECT must NOT equal its ISSUER (proves not self-signed)
        assert_ne!(
            agent_subject, agent_issuer,
            "Certificate must NOT be self-signed. Subject='{}' should differ from Issuer='{}'",
            agent_subject, agent_issuer
        );

        // 3. The issued certificate's issuer_dn field must be set correctly
        assert!(
            issued.issuer_dn.contains("Issuer Test CA"),
            "issuer_dn should contain CA name, got: {}",
            issued.issuer_dn
        );
    }
}
