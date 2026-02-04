//! `HashiCorp` Vault PKI Certificate Authority Provider (F127).
//!
//! This provider integrates with `HashiCorp` Vault's PKI secrets engine
//! for certificate issuance.
//!
//! ## Vault PKI API Endpoints Used:
//! - `POST /v1/{mount}/issue/{role}` - Issue a certificate
//! - `POST /v1/{mount}/revoke` - Revoke a certificate
//! - `GET /v1/{mount}/crl` - Get CRL
//! - `GET /v1/{mount}/ca/pem` - Get CA certificate
//! - `GET /v1/sys/health` - Health check

use async_trait::async_trait;
use chrono::Utc;
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

/// Vault PKI provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPkiConfig {
    /// CA ID in the database.
    pub ca_id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Vault server URL.
    pub vault_url: String,

    /// PKI mount path (e.g., "pki" or "`pki_int`").
    pub mount_path: String,

    /// Role name for issuing certificates.
    pub role_name: String,

    /// Reference to Vault auth token in xavyo-secrets.
    pub auth_token_ref: String,

    /// PEM-encoded CA certificate.
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

/// Request body for Vault PKI /issue/{role} endpoint.
#[derive(Debug, Serialize)]
struct VaultIssueRequest {
    /// Common name for the certificate.
    common_name: String,

    /// Alternative names (DNS SANs).
    #[serde(skip_serializing_if = "Option::is_none")]
    alt_names: Option<String>,

    /// URI SANs.
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_sans: Option<String>,

    /// TTL for the certificate (e.g., "720h").
    ttl: String,

    /// Key type to use (rsa or ec).
    #[serde(skip_serializing_if = "Option::is_none")]
    key_type: Option<String>,

    /// Key bits for RSA keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_bits: Option<i32>,
}

/// Response from Vault PKI /issue endpoint.
#[derive(Debug, Deserialize)]
struct VaultIssueResponse {
    /// The response data.
    data: VaultIssueData,
}

/// Data portion of Vault PKI issue response.
#[derive(Debug, Deserialize)]
struct VaultIssueData {
    /// PEM-encoded certificate.
    certificate: String,

    /// PEM-encoded private key.
    private_key: String,

    /// PEM-encoded CA certificate chain.
    ca_chain: Vec<String>,

    /// Certificate serial number.
    serial_number: String,

    /// Certificate expiration (Unix timestamp).
    #[allow(dead_code)]
    expiration: i64,

    /// PEM-encoded issuing CA certificate.
    issuing_ca: String,
}

/// Request body for Vault PKI /revoke endpoint.
#[derive(Debug, Serialize)]
struct VaultRevokeRequest {
    /// Certificate serial number to revoke.
    serial_number: String,
}

/// Response from Vault PKI /revoke endpoint.
#[derive(Debug, Deserialize)]
struct VaultRevokeResponse {
    /// The response data.
    data: VaultRevokeData,
}

/// Data portion of Vault PKI revoke response.
#[derive(Debug, Deserialize)]
struct VaultRevokeData {
    /// Revocation time.
    revocation_time: i64,
}

/// Vault health check response.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct VaultHealthResponse {
    /// Whether Vault is initialized.
    initialized: bool,

    /// Whether Vault is sealed.
    sealed: bool,

    /// Vault version.
    version: String,
}

/// Vault PKI Certificate Authority provider.
pub struct VaultPkiProvider {
    config: VaultPkiConfig,
    http_client: Client,
    /// Cached Vault token (loaded from xavyo-secrets).
    vault_token: Option<String>,
}

impl VaultPkiProvider {
    /// Create a new Vault PKI provider.
    #[must_use] 
    pub fn new(config: VaultPkiConfig) -> Self {
        let http_client = Client::builder()
            .timeout(StdDuration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            vault_token: None,
        }
    }

    /// Create a provider with pre-loaded Vault token.
    #[must_use] 
    pub fn with_token(config: VaultPkiConfig, token: String) -> Self {
        let http_client = Client::builder()
            .timeout(StdDuration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            vault_token: Some(token),
        }
    }

    /// Get the provider configuration.
    #[must_use] 
    pub fn config(&self) -> &VaultPkiConfig {
        &self.config
    }

    /// Get the Vault token, returning an error if not configured.
    fn get_token(&self) -> CaResult<&str> {
        self.vault_token
            .as_deref()
            .ok_or_else(|| CaProviderError::NotAvailable("Vault token not configured".to_string()))
    }

    /// Map key algorithm to Vault `key_type` and `key_bits`.
    fn map_key_algorithm(algorithm: KeyAlgorithm) -> (String, Option<i32>) {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => ("ec".to_string(), Some(256)),
            KeyAlgorithm::EcdsaP384 => ("ec".to_string(), Some(384)),
            KeyAlgorithm::Rsa2048 => ("rsa".to_string(), Some(2048)),
            KeyAlgorithm::Rsa4096 => ("rsa".to_string(), Some(4096)),
        }
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

    /// Extract subject DN from a PEM certificate.
    fn extract_subject_dn(cert_pem: &str) -> CaResult<String> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        Ok(cert.subject().to_string())
    }

    /// Extract issuer DN from a PEM certificate.
    fn extract_issuer_dn(cert_pem: &str) -> CaResult<String> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        Ok(cert.issuer().to_string())
    }

    /// Extract validity timestamps from a PEM certificate.
    fn extract_validity(cert_pem: &str) -> CaResult<(i64, i64)> {
        let der = Self::parse_pem_to_der(cert_pem)?;
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).map_err(|e| {
            CaProviderError::InvalidFormat(format!("Failed to parse X.509: {e:?}"))
        })?;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        Ok((not_before, not_after))
    }

    /// Format serial number from Vault format to our format (colon-separated hex).
    fn format_serial_number(serial: &str) -> String {
        // Vault returns serial as "aa:bb:cc:dd..." format already
        // We store as uppercase hex without colons for consistency
        serial.replace(':', "").to_uppercase()
    }
}

#[async_trait]
impl CaProvider for VaultPkiProvider {
    fn provider_type(&self) -> &'static str {
        "vault_pki"
    }

    async fn health_check(&self) -> CaResult<()> {
        // First check Vault health
        let url = format!("{}/v1/sys/health", self.config.vault_url);

        let response =
            self.http_client.get(&url).send().await.map_err(|e| {
                CaProviderError::NetworkError(format!("Health check failed: {e}"))
            })?;

        // Vault health endpoint returns different status codes based on state
        // 200 = initialized, unsealed, active
        // 429 = unsealed, standby
        // 472 = disaster recovery mode replication secondary and active
        // 473 = performance standby
        // 501 = not initialized
        // 503 = sealed

        let status = response.status();
        if status.as_u16() == 501 {
            return Err(CaProviderError::NotAvailable(
                "Vault is not initialized".to_string(),
            ));
        }
        if status.as_u16() == 503 {
            return Err(CaProviderError::NotAvailable("Vault is sealed".to_string()));
        }

        // Check if PKI mount is accessible
        let token = self.get_token()?;
        let pki_url = format!(
            "{}/v1/{}/ca/pem",
            self.config.vault_url, self.config.mount_path
        );

        let response = self
            .http_client
            .get(&pki_url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("PKI mount check failed: {e}")))?;

        if !response.status().is_success() {
            return Err(CaProviderError::NotAvailable(format!(
                "PKI mount '{}' is not accessible (status {})",
                self.config.mount_path,
                response.status()
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

        let token = self.get_token()?;

        // Build common name with agent identity
        let common_name = request.agent_name.clone();

        // Build URI SANs (agent identity)
        let agent_uri = format!(
            "xavyo:tenant:{}:agent:{}",
            request.tenant_id, request.agent_id
        );

        // Build DNS SANs
        let mut dns_sans: Vec<String> = vec![request.agent_name.clone()];
        for san in &request.additional_sans {
            if let Some(dns_name) = san.strip_prefix("dns:") {
                dns_sans.push(dns_name.to_string());
            }
        }

        // Build URI SANs
        let mut uri_sans: Vec<String> = vec![agent_uri];
        for san in &request.additional_sans {
            if let Some(uri) = san.strip_prefix("uri:") {
                uri_sans.push(uri.to_string());
            }
        }

        // Map key algorithm
        let (key_type, key_bits) = Self::map_key_algorithm(request.key_algorithm);

        // Calculate TTL
        let ttl = format!("{}h", request.validity_days * 24);

        // Build issue request
        let issue_request = VaultIssueRequest {
            common_name,
            alt_names: if dns_sans.len() > 1 {
                Some(dns_sans[1..].join(","))
            } else {
                None
            },
            uri_sans: Some(uri_sans.join(",")),
            ttl,
            key_type: Some(key_type),
            key_bits,
        };

        // Call Vault PKI issue endpoint
        let url = format!(
            "{}/v1/{}/issue/{}",
            self.config.vault_url, self.config.mount_path, self.config.role_name
        );

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&issue_request)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("Issue request failed: {e}")))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CaProviderError::ExternalCaError(format!(
                "Vault PKI issue failed: {error_text}"
            )));
        }

        let issue_response: VaultIssueResponse = response.json().await.map_err(|e| {
            CaProviderError::ExternalCaError(format!("Invalid issue response: {e}"))
        })?;

        // Parse the issued certificate
        let cert_der = Self::parse_pem_to_der(&issue_response.data.certificate)?;
        let fingerprint_sha256 = Self::calculate_fingerprint(&cert_der);
        let serial_number = Self::format_serial_number(&issue_response.data.serial_number);
        let subject_dn = Self::extract_subject_dn(&issue_response.data.certificate)?;
        let issuer_dn = Self::extract_issuer_dn(&issue_response.data.certificate)?;
        let (not_before, not_after) = Self::extract_validity(&issue_response.data.certificate)?;

        // Build certificate chain
        let chain_pem = if issue_response.data.ca_chain.is_empty() {
            issue_response.data.issuing_ca.clone()
        } else {
            issue_response.data.ca_chain.join("\n")
        };

        Ok(IssuedCertificate {
            certificate_id: Uuid::new_v4(),
            certificate_pem: issue_response.data.certificate,
            private_key_pem: issue_response.data.private_key,
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

        // Vault PKI renewal requires re-issuing with the same parameters.
        // The actual certificate info should be retrieved from the database.
        Err(CaProviderError::Internal(
            "Certificate renewal requires database integration - use CertificateService::renew_certificate".to_string(),
        ))
    }

    async fn revoke_certificate(
        &self,
        request: &CertificateRevokeRequest,
    ) -> CaResult<RevocationResult> {
        let token = self.get_token()?;

        // Vault expects serial number in colon-separated format
        let serial_number = request
            .serial_number
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(":");

        let revoke_request = VaultRevokeRequest {
            serial_number: serial_number.to_lowercase(),
        };

        let url = format!(
            "{}/v1/{}/revoke",
            self.config.vault_url, self.config.mount_path
        );

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&revoke_request)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("Revoke request failed: {e}")))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CaProviderError::ExternalCaError(format!(
                "Vault PKI revoke failed: {error_text}"
            )));
        }

        let revoke_response: VaultRevokeResponse = response.json().await.map_err(|e| {
            CaProviderError::ExternalCaError(format!("Invalid revoke response: {e}"))
        })?;

        Ok(RevocationResult {
            certificate_id: Uuid::nil(), // We don't have the cert ID from Vault
            serial_number: request.serial_number.clone(),
            revoked_at: revoke_response.data.revocation_time,
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

        let (_, cert) = match x509_parser::prelude::X509Certificate::from_der(&cert_der) {
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
                if let x509_parser::prelude::GeneralName::URI(uri) = name {
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
        // Try to fetch from Vault if token is available
        if let Ok(token) = self.get_token() {
            let url = format!(
                "{}/v1/{}/ca_chain",
                self.config.vault_url, self.config.mount_path
            );

            if let Ok(response) = self
                .http_client
                .get(&url)
                .header("X-Vault-Token", token)
                .send()
                .await
            {
                if response.status().is_success() {
                    if let Ok(chain) = response.text().await {
                        return Ok(chain);
                    }
                }
            }
        }

        // Fall back to configured CA certificate
        Ok(self.config.ca_certificate_pem.clone())
    }

    async fn generate_crl(
        &self,
        _revoked_certs: &[super::RevokedCertEntry],
        _crl_number: i64,
    ) -> CaResult<Vec<u8>> {
        // Vault PKI manages its own CRL - we just fetch it from the /crl endpoint
        // The revoked_certs and crl_number parameters are ignored for external CAs
        let token = self.get_token()?;

        let url = format!(
            "{}/v1/{}/crl",
            self.config.vault_url, self.config.mount_path
        );

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| CaProviderError::NetworkError(format!("CRL fetch failed: {e}")))?;

        if !response.status().is_success() {
            return Err(CaProviderError::ExternalCaError(format!(
                "Vault PKI CRL fetch failed with status {}",
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

    fn test_config() -> VaultPkiConfig {
        VaultPkiConfig {
            ca_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            vault_url: "https://vault.example.com".to_string(),
            mount_path: "pki".to_string(),
            role_name: "agent-certs".to_string(),
            auth_token_ref: "secret://vault-token".to_string(),
            ca_certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            max_validity_days: 90,
            timeout_ms: 30_000,
        }
    }

    #[test]
    fn test_provider_type() {
        let provider = VaultPkiProvider::new(test_config());
        assert_eq!(provider.provider_type(), "vault_pki");
    }

    #[tokio::test]
    async fn test_get_ca_chain() {
        let config = test_config();
        let expected_chain = config.ca_certificate_pem.clone();
        let provider = VaultPkiProvider::new(config);

        let chain = provider.get_ca_chain().await.unwrap();
        assert_eq!(chain, expected_chain);
    }

    #[tokio::test]
    async fn test_validity_exceeds_max() {
        let config = test_config();
        let provider = VaultPkiProvider::with_token(config, "test-token".to_string());

        let request = CertificateIssueRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            validity_days: 365, // Exceeds max of 90
            key_algorithm: KeyAlgorithm::EcdsaP256,
            additional_sans: vec![],
        };

        let result = provider.issue_certificate(&request).await;
        assert!(matches!(
            result,
            Err(CaProviderError::ValidityExceedsMax {
                requested: 365,
                max: 90
            })
        ));
    }

    #[test]
    fn test_map_key_algorithm() {
        let (key_type, key_bits) = VaultPkiProvider::map_key_algorithm(KeyAlgorithm::EcdsaP256);
        assert_eq!(key_type, "ec");
        assert_eq!(key_bits, Some(256));

        let (key_type, key_bits) = VaultPkiProvider::map_key_algorithm(KeyAlgorithm::Rsa4096);
        assert_eq!(key_type, "rsa");
        assert_eq!(key_bits, Some(4096));
    }

    #[test]
    fn test_format_serial_number() {
        let serial = "aa:bb:cc:dd:ee:ff";
        let formatted = VaultPkiProvider::format_serial_number(serial);
        assert_eq!(formatted, "AABBCCDDEEFF");
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = VaultPkiProvider::calculate_fingerprint(data);
        assert!(fingerprint.contains(':'));
        assert!(fingerprint.len() > 60);
    }
}
