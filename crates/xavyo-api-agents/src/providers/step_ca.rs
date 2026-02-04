//! Step-CA Certificate Authority Provider (F127).
//!
//! This provider integrates with Smallstep's step-ca for certificate issuance.
//! It uses the step-ca API to request certificates signed by an external CA.
//!
//! ## Step-CA API Endpoints Used:
//! - `POST /sign` - Sign a CSR with the CA
//! - `POST /revoke` - Revoke a certificate
//! - `GET /health` - Health check
//! - `GET /root/{fingerprint}` - Get root CA certificate

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rcgen::{
    CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    PKCS_RSA_SHA256,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration as StdDuration;
use uuid::Uuid;
use x509_parser::prelude::*;

use super::{
    CaProvider, CaProviderError, CaResult, CertificateIssueRequest, CertificateRenewRequest,
    CertificateRevokeRequest, CertificateStatus, CertificateValidation, IssuedCertificate,
    KeyAlgorithm, RevocationResult,
};

/// Step-CA provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCaConfig {
    /// CA ID in the database.
    pub ca_id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Step-CA base URL.
    pub base_url: String,

    /// Provisioner name for signing requests.
    pub provisioner_name: String,

    /// Provisioner key ID.
    pub provisioner_key_id: String,

    /// Reference to provisioner password in xavyo-secrets.
    pub provisioner_password_ref: String,

    /// PEM-encoded CA certificate (root certificate).
    pub ca_certificate_pem: String,

    /// Maximum certificate validity in days.
    pub max_validity_days: i32,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30_000 // 30 seconds
}

/// Request body for step-ca /sign endpoint.
#[derive(Debug, Serialize)]
struct StepCaSignRequest {
    /// PEM-encoded CSR.
    csr: String,
    /// Provisioner name.
    ott: String,
    /// Requested validity duration (e.g., "720h" for 30 days).
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
}

/// Response from step-ca /sign endpoint.
#[derive(Debug, Deserialize)]
struct StepCaSignResponse {
    /// PEM-encoded certificate.
    crt: String,
    /// PEM-encoded CA certificate.
    ca: String,
}

/// Request body for step-ca /revoke endpoint.
#[derive(Debug, Serialize)]
struct StepCaRevokeRequest {
    /// Certificate serial number.
    serial: String,
    /// Revocation reason code.
    #[serde(rename = "reasonCode")]
    reason_code: i16,
    /// One-time token for authorization.
    ott: String,
    /// Whether this is a passive revocation (doesn't require possession of key).
    passive: bool,
}

/// Response from step-ca /revoke endpoint.
#[derive(Debug, Deserialize)]
struct StepCaRevokeResponse {
    /// Status message.
    #[allow(dead_code)]
    status: String,
}

/// Response from step-ca /health endpoint.
#[derive(Debug, Deserialize)]
struct StepCaHealthResponse {
    /// Health status.
    status: String,
}

/// Claims for step-ca One-Time Token (OTT) JWT.
/// See: <https://smallstep.com/docs/step-ca/provisioners/#jwk>
#[derive(Debug, Serialize)]
struct StepCaOttClaims {
    /// Audience - typically the step-ca URL.
    aud: String,
    /// Subject - the common name being requested.
    sub: String,
    /// Subject Alternative Names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sans: Vec<String>,
    /// Issued at timestamp.
    iat: i64,
    /// Not before timestamp.
    nbf: i64,
    /// Expiration timestamp.
    exp: i64,
    /// JWT ID (unique identifier).
    jti: String,
    /// Issuer - the provisioner key ID.
    iss: String,
}

/// Step-CA Certificate Authority provider.
pub struct StepCaProvider {
    config: StepCaConfig,
    http_client: Client,
    /// Cached provisioner password (loaded from xavyo-secrets).
    provisioner_password: Option<String>,
}

impl StepCaProvider {
    /// Create a new Step-CA provider.
    #[must_use] 
    pub fn new(config: StepCaConfig) -> Self {
        let http_client = Client::builder()
            .timeout(StdDuration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            provisioner_password: None,
        }
    }

    /// Create a provider with pre-loaded provisioner password.
    #[must_use] 
    pub fn with_password(config: StepCaConfig, password: String) -> Self {
        let http_client = Client::builder()
            .timeout(StdDuration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            provisioner_password: Some(password),
        }
    }

    /// Get the provider configuration.
    #[must_use] 
    pub fn config(&self) -> &StepCaConfig {
        &self.config
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

    /// Generate a CSR for the given request.
    fn generate_csr(request: &CertificateIssueRequest, key_pair: &KeyPair) -> CaResult<String> {
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

        // Add Subject Alternative Names
        let agent_uri = format!(
            "xavyo:tenant:{}:agent:{}",
            request.tenant_id, request.agent_id
        );

        // Create SAN entries
        let dns_san = rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from(request.agent_name.as_str())
                .map_err(|e| CaProviderError::InvalidCsr(format!("Invalid DNS name: {e}")))?,
        );
        let uri_san = rcgen::SanType::URI(
            rcgen::Ia5String::try_from(agent_uri.as_str())
                .map_err(|e| CaProviderError::InvalidCsr(format!("Invalid URI: {e}")))?,
        );

        params.subject_alt_names.push(dns_san);
        params.subject_alt_names.push(uri_san);

        // Add additional SANs
        for san in &request.additional_sans {
            if let Some(dns_name) = san.strip_prefix("dns:") {
                params.subject_alt_names.push(rcgen::SanType::DnsName(
                    rcgen::Ia5String::try_from(dns_name).map_err(|e| {
                        CaProviderError::InvalidCsr(format!("Invalid DNS SAN: {e}"))
                    })?,
                ));
            } else if let Some(uri) = san.strip_prefix("uri:") {
                params.subject_alt_names.push(rcgen::SanType::URI(
                    rcgen::Ia5String::try_from(uri).map_err(|e| {
                        CaProviderError::InvalidCsr(format!("Invalid URI SAN: {e}"))
                    })?,
                ));
            }
        }

        // Generate proper PKCS#10 CSR using rcgen's serialize_request
        let csr = params
            .serialize_request(key_pair)
            .map_err(|e| CaProviderError::InvalidCsr(format!("Failed to create CSR: {e}")))?;

        csr.pem().map_err(|e| {
            CaProviderError::InvalidCsr(format!("Failed to serialize CSR to PEM: {e}"))
        })
    }

    /// Generate a one-time token (OTT) for step-ca authentication.
    ///
    /// This generates a JWT signed with HS256 using the provisioner password.
    /// The JWT follows the step-ca OTT format for JWK provisioners.
    ///
    /// See: <https://smallstep.com/docs/step-ca/provisioners/#jwk>
    fn generate_ott(&self, subject: &str, sans: &[String]) -> CaResult<String> {
        let password = self.provisioner_password.as_ref().ok_or_else(|| {
            CaProviderError::NotAvailable("Provisioner password not configured".to_string())
        })?;

        let now = Utc::now().timestamp();
        let exp = now + 300; // 5 minutes validity for OTT

        // Build the OTT claims following step-ca specification
        let claims = StepCaOttClaims {
            aud: format!("{}/sign", self.config.base_url),
            sub: subject.to_string(),
            sans: sans.to_vec(),
            iat: now,
            nbf: now,
            exp,
            jti: Uuid::new_v4().to_string(),
            iss: self.config.provisioner_key_id.clone(),
        };

        // Sign with HS256 using the provisioner password
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(password.as_bytes());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| CaProviderError::Internal(format!("Failed to generate OTT JWT: {e}")))
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

    /// Parse a PEM certificate and extract DER bytes.
    fn parse_pem_to_der(pem_str: &str) -> CaResult<Vec<u8>> {
        let pem_data = ::pem::parse(pem_str)
            .map_err(|e| CaProviderError::InvalidFormat(format!("Failed to parse PEM: {e}")))?;

        Ok(pem_data.contents().to_vec())
    }

    /// Extract serial number from a PEM certificate.
    fn extract_serial_number(cert_pem: &str) -> CaResult<String> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        Ok(cert
            .serial
            .to_bytes_be()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect())
    }

    /// Extract subject DN from a PEM certificate.
    fn extract_subject_dn(cert_pem: &str) -> CaResult<String> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        Ok(cert.subject().to_string())
    }

    /// Extract issuer DN from a PEM certificate.
    fn extract_issuer_dn(cert_pem: &str) -> CaResult<String> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        Ok(cert.issuer().to_string())
    }

    /// Extract validity timestamps from a PEM certificate.
    fn extract_validity(cert_pem: &str) -> CaResult<(i64, i64)> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        Ok((not_before, not_after))
    }
}

#[async_trait]
impl CaProvider for StepCaProvider {
    fn provider_type(&self) -> &'static str {
        "step_ca"
    }

    async fn health_check(&self) -> CaResult<()> {
        let url = format!("{}/health", self.config.base_url);

        let response =
            self.http_client.get(&url).send().await.map_err(|e| {
                CaProviderError::NetworkError(format!("Health check failed: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(CaProviderError::NotAvailable(format!(
                "Step-CA health check returned status {}",
                response.status()
            )));
        }

        let health: StepCaHealthResponse = response.json().await.map_err(|e| {
            CaProviderError::ExternalCaError(format!("Invalid health response: {e}"))
        })?;

        if health.status != "ok" {
            return Err(CaProviderError::NotAvailable(format!(
                "Step-CA unhealthy: {}",
                health.status
            )));
        }

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

        // Generate key pair for the agent
        let key_pair = Self::generate_key_pair(request.key_algorithm)?;

        // Generate CSR
        let csr_pem = Self::generate_csr(request, &key_pair)?;

        // Build SANs for OTT
        let agent_uri = format!(
            "xavyo:tenant:{}:agent:{}",
            request.tenant_id, request.agent_id
        );
        let mut sans = vec![request.agent_name.clone(), agent_uri];
        for san in &request.additional_sans {
            if let Some(dns_name) = san.strip_prefix("dns:") {
                sans.push(dns_name.to_string());
            } else if let Some(uri) = san.strip_prefix("uri:") {
                sans.push(uri.to_string());
            }
        }

        // Generate one-time token for authentication
        let ott = self.generate_ott(&request.agent_name, &sans)?;

        // Calculate not_after duration
        let validity_hours = request.validity_days * 24;
        let not_after = format!("{validity_hours}h");

        // Build sign request
        let sign_request = StepCaSignRequest {
            csr: csr_pem,
            ott,
            not_after: Some(not_after),
        };

        // Call step-ca /sign endpoint
        let url = format!("{}/sign", self.config.base_url);
        let response = self
            .http_client
            .post(&url)
            .json(&sign_request)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("Sign request failed: {e}")))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CaProviderError::ExternalCaError(format!(
                "Step-CA sign failed: {error_text}"
            )));
        }

        let sign_response: StepCaSignResponse = response.json().await.map_err(|e| {
            CaProviderError::ExternalCaError(format!("Invalid sign response: {e}"))
        })?;

        // Parse the issued certificate
        let cert_der = Self::parse_pem_to_der(&sign_response.crt)?;
        let fingerprint_sha256 = Self::calculate_fingerprint(&cert_der);
        let serial_number = Self::extract_serial_number(&sign_response.crt)?;
        let subject_dn = Self::extract_subject_dn(&sign_response.crt)?;
        let issuer_dn = Self::extract_issuer_dn(&sign_response.crt)?;
        let (not_before, not_after) = Self::extract_validity(&sign_response.crt)?;

        // Build certificate chain (cert + CA)
        let chain_pem = format!("{}\n{}", sign_response.crt.trim(), sign_response.ca.trim());

        Ok(IssuedCertificate {
            certificate_id: Uuid::new_v4(),
            certificate_pem: sign_response.crt,
            private_key_pem: key_pair.serialize_pem(),
            chain_pem,
            serial_number,
            fingerprint_sha256,
            subject_dn,
            issuer_dn,
            not_before,
            not_after,
        })
    }

    async fn renew_certificate(
        &self,
        request: &CertificateRenewRequest,
    ) -> CaResult<IssuedCertificate> {
        if request.validity_days > self.config.max_validity_days {
            return Err(CaProviderError::ValidityExceedsMax {
                requested: request.validity_days,
                max: self.config.max_validity_days,
            });
        }

        // Step-CA renewal requires the original certificate for mTLS authentication.
        // For now, return an error indicating the service layer should handle this.
        Err(CaProviderError::Internal(
            "Certificate renewal requires database integration - use CertificateService::renew_certificate".to_string(),
        ))
    }

    async fn revoke_certificate(
        &self,
        request: &CertificateRevokeRequest,
    ) -> CaResult<RevocationResult> {
        // Generate one-time token for authentication
        // For revocation, we use the serial number as the subject
        let ott = self.generate_ott(&request.serial_number, &[])?;

        let revoke_request = StepCaRevokeRequest {
            serial: request.serial_number.clone(),
            reason_code: request.reason_code.as_i16(),
            ott,
            passive: true, // Passive revocation doesn't require key possession
        };

        let url = format!("{}/revoke", self.config.base_url);
        let response = self
            .http_client
            .post(&url)
            .json(&revoke_request)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("Revoke request failed: {e}")))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CaProviderError::ExternalCaError(format!(
                "Step-CA revoke failed: {error_text}"
            )));
        }

        let _revoke_response: StepCaRevokeResponse = response.json().await.map_err(|e| {
            CaProviderError::ExternalCaError(format!("Invalid revoke response: {e}"))
        })?;

        Ok(RevocationResult {
            certificate_id: Uuid::nil(), // We don't have the cert ID from step-ca
            serial_number: request.serial_number.clone(),
            revoked_at: Utc::now().timestamp(),
            reason: request.reason_code,
        })
    }

    async fn validate_certificate(&self, certificate_pem: &str) -> CaResult<CertificateValidation> {
        // Parse the certificate
        let cert_der = match Self::parse_pem_to_der(certificate_pem) {
            Ok(der) => der,
            Err(e) => {
                return Ok(CertificateValidation::invalid(
                    CertificateStatus::Active,
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

        // Extract agent_id and tenant_id from SAN URIs
        let mut agent_id: Option<Uuid> = None;
        let mut tenant_id: Option<Uuid> = None;

        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let GeneralName::URI(uri) = name {
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
        _revoked_certs: &[super::RevokedCertEntry],
        _crl_number: i64,
    ) -> CaResult<Vec<u8>> {
        // Step-CA manages its own CRL - we just fetch it from the /crl endpoint
        // The revoked_certs and crl_number parameters are ignored for external CAs
        let url = format!("{}/crl", self.config.base_url);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("CRL fetch failed: {e}")))?;

        if !response.status().is_success() {
            return Err(CaProviderError::ExternalCaError(format!(
                "Step-CA CRL fetch failed with status {}",
                response.status()
            )));
        }

        let crl_bytes = response
            .bytes()
            .await
            .map_err(|e| CaProviderError::ExternalCaError(format!("Failed to read CRL: {e}")))?;

        Ok(crl_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StepCaConfig {
        StepCaConfig {
            ca_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            base_url: "https://step-ca.example.com".to_string(),
            provisioner_name: "xavyo-agents".to_string(),
            provisioner_key_id: "test-key-id".to_string(),
            provisioner_password_ref: "secret://step-ca-password".to_string(),
            ca_certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            max_validity_days: 30,
            timeout_ms: 30_000,
        }
    }

    #[test]
    fn test_provider_type() {
        let provider = StepCaProvider::new(test_config());
        assert_eq!(provider.provider_type(), "step_ca");
    }

    #[tokio::test]
    async fn test_get_ca_chain() {
        let config = test_config();
        let expected_chain = config.ca_certificate_pem.clone();
        let provider = StepCaProvider::new(config);

        let chain = provider.get_ca_chain().await.unwrap();
        assert_eq!(chain, expected_chain);
    }

    #[tokio::test]
    async fn test_validity_exceeds_max() {
        let config = test_config();
        let provider = StepCaProvider::with_password(config, "test-password".to_string());

        let request = CertificateIssueRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            validity_days: 90, // Exceeds max of 30
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec![],
        };

        let result = provider.issue_certificate(&request).await;
        assert!(matches!(
            result,
            Err(CaProviderError::ValidityExceedsMax {
                requested: 90,
                max: 30
            })
        ));
    }

    #[test]
    fn test_generate_key_pair() {
        let key_pair = StepCaProvider::generate_key_pair(KeyAlgorithm::EcdsaP256);
        assert!(key_pair.is_ok());
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = StepCaProvider::calculate_fingerprint(data);
        assert!(fingerprint.contains(':'));
        assert!(fingerprint.len() > 60);
    }

    #[test]
    fn test_generate_ott_creates_valid_jwt() {
        let config = test_config();
        let provider = StepCaProvider::with_password(config, "test-password".to_string());

        let ott = provider.generate_ott(
            "test-agent",
            &[
                "test-agent".to_string(),
                "xavyo:tenant:xxx:agent:yyy".to_string(),
            ],
        );
        assert!(ott.is_ok());

        let token = ott.unwrap();
        // JWT has 3 parts separated by dots
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Verify we can decode the header (base64)
        let header_json =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0]);
        assert!(header_json.is_ok(), "Header should be valid base64");
    }

    #[test]
    fn test_generate_ott_fails_without_password() {
        let config = test_config();
        let provider = StepCaProvider::new(config);

        let ott = provider.generate_ott("test-agent", &[]);
        assert!(ott.is_err());
        assert!(matches!(ott.unwrap_err(), CaProviderError::NotAvailable(_)));
    }

    #[test]
    fn test_generate_csr_creates_valid_pkcs10() {
        let request = CertificateIssueRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            validity_days: 30,
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec!["dns:extra.example.com".to_string()],
        };

        let key_pair = StepCaProvider::generate_key_pair(KeyAlgorithm::EcdsaP256).unwrap();
        let csr_pem = StepCaProvider::generate_csr(&request, &key_pair);

        assert!(csr_pem.is_ok(), "CSR generation should succeed");
        let pem_str = csr_pem.unwrap();
        assert!(
            pem_str.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
            "CSR should be in PEM format"
        );
        assert!(
            pem_str.contains("-----END CERTIFICATE REQUEST-----"),
            "CSR should have proper ending"
        );
    }
}
