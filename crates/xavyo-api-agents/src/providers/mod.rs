//! Identity Providers for AI Agents.
//!
//! This module defines traits and implementations for:
//! - **Cloud Identity Providers** (F121): Workload identity federation for cloud credentials
//! - **Certificate Authority Providers** (F127): PKI certificate issuance for mTLS

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// F121: Cloud Identity Federation
pub mod aws_sts;
pub mod azure_federated;
pub mod gcp_workload;
pub mod kubernetes_oidc;

// F127: PKI Certificate Authority Providers
pub mod internal_ca;
pub mod step_ca;
pub mod vault_pki;

pub use aws_sts::AwsStsProvider;
pub use azure_federated::AzureFederatedProvider;
pub use gcp_workload::GcpWorkloadProvider;
pub use kubernetes_oidc::KubernetesOidcProvider;

// F127 exports
pub use internal_ca::InternalCaProvider;
pub use step_ca::StepCaProvider;
pub use vault_pki::VaultPkiProvider;

/// Result type for cloud identity provider operations.
pub type ProviderResult<T> = Result<T, CloudProviderError>;

/// Error type for cloud identity providers.
#[derive(Debug, thiserror::Error)]
pub enum CloudProviderError {
    /// Provider configuration is invalid.
    #[error("Invalid provider configuration: {0}")]
    InvalidConfiguration(String),

    /// Provider is not available/configured.
    #[error("Provider not available: {0}")]
    NotAvailable(String),

    /// Authentication with the cloud provider failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// The cloud provider returned an error.
    #[error("Provider error: {0}")]
    ProviderError(String),

    /// Operation timed out.
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// The requested role/identity is not allowed.
    #[error("Role not allowed: {0}")]
    RoleNotAllowed(String),

    /// Rate limit exceeded at the cloud provider.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Network error communicating with provider.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Cloud credential returned by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCredential {
    /// The type of credential (e.g., "aws-sts", "gcp-access-token", "azure-token").
    pub credential_type: String,

    /// Access key or token for the cloud provider.
    pub access_key: Option<String>,

    /// Secret key (for AWS-style credentials).
    pub secret_key: Option<String>,

    /// Session token (for temporary credentials).
    pub session_token: Option<String>,

    /// Access token (for OAuth-style credentials).
    pub access_token: Option<String>,

    /// When the credential expires (Unix timestamp in seconds).
    pub expires_at: i64,

    /// Additional provider-specific metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl CloudCredential {
    /// Create a new AWS STS credential.
    pub fn aws_sts(
        access_key: String,
        secret_key: String,
        session_token: String,
        expires_at: i64,
    ) -> Self {
        Self {
            credential_type: "aws-sts".to_string(),
            access_key: Some(access_key),
            secret_key: Some(secret_key),
            session_token: Some(session_token),
            access_token: None,
            expires_at,
            metadata: HashMap::new(),
        }
    }

    /// Create a new GCP access token credential.
    pub fn gcp_access_token(access_token: String, expires_at: i64) -> Self {
        Self {
            credential_type: "gcp-access-token".to_string(),
            access_key: None,
            secret_key: None,
            session_token: None,
            access_token: Some(access_token),
            expires_at,
            metadata: HashMap::new(),
        }
    }

    /// Create a new Azure token credential.
    pub fn azure_token(access_token: String, expires_at: i64) -> Self {
        Self {
            credential_type: "azure-token".to_string(),
            access_key: None,
            secret_key: None,
            session_token: None,
            access_token: Some(access_token),
            expires_at,
            metadata: HashMap::new(),
        }
    }

    /// Create a new Kubernetes service account token credential.
    pub fn kubernetes_token(token: String, expires_at: i64) -> Self {
        Self {
            credential_type: "kubernetes-token".to_string(),
            access_key: None,
            secret_key: None,
            session_token: None,
            access_token: Some(token),
            expires_at,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the credential.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if the credential has expired.
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.expires_at <= now
    }

    /// Get the time until expiration in seconds.
    pub fn ttl_seconds(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.expires_at - now).max(0)
    }
}

/// Request for cloud credentials.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// The tenant requesting credentials.
    pub tenant_id: Uuid,

    /// The agent requesting credentials.
    pub agent_id: Uuid,

    /// Agent type for role mapping.
    pub agent_type: String,

    /// JWT token from the agent (for OIDC-based federation).
    pub agent_jwt: String,

    /// Requested TTL in seconds.
    pub requested_ttl_seconds: i32,

    /// Role identifier to assume (from role mapping).
    pub role_identifier: String,

    /// Allowed scopes/permissions.
    pub allowed_scopes: Vec<String>,

    /// Additional constraints from the role mapping.
    pub constraints: serde_json::Value,
}

/// Configuration for a cloud identity provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// AWS STS configuration.
    Aws(AwsStsConfig),

    /// GCP Workload Identity configuration.
    Gcp(GcpWorkloadIdentityConfig),

    /// Azure AD Federated Credentials configuration.
    Azure(AzureFederatedConfig),

    /// Kubernetes OIDC configuration.
    Kubernetes(KubernetesOidcConfig),
}

/// AWS STS provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsStsConfig {
    /// AWS region for STS calls.
    pub region: String,

    /// The OIDC provider ARN configured in AWS IAM.
    pub oidc_provider_arn: String,

    /// Session name prefix for AssumeRoleWithWebIdentity.
    #[serde(default = "default_session_prefix")]
    pub session_name_prefix: String,

    /// External ID for additional security (optional).
    pub external_id: Option<String>,

    /// Maximum session duration in seconds.
    #[serde(default = "default_max_duration")]
    pub max_duration_seconds: i32,
}

fn default_session_prefix() -> String {
    "xavyo-agent".to_string()
}

fn default_max_duration() -> i32 {
    3600 // 1 hour
}

/// GCP Workload Identity provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpWorkloadIdentityConfig {
    /// GCP project ID.
    pub project_id: String,

    /// Workload Identity Pool ID.
    pub workload_identity_pool_id: String,

    /// Workload Identity Provider ID.
    pub workload_identity_provider_id: String,

    /// The audience for the OIDC token.
    pub audience: String,

    /// Service account email to impersonate.
    pub service_account_email: String,
}

/// Azure AD Federated Credentials configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureFederatedConfig {
    /// Azure tenant ID.
    pub tenant_id: String,

    /// Azure client ID (application ID).
    pub client_id: String,

    /// The audience for the federated token.
    pub audience: String,

    /// The issuer URL (must match Xavyo's OIDC issuer).
    pub issuer: String,

    /// Subject claim mapping (e.g., agent ID).
    pub subject_claim: String,
}

/// Kubernetes OIDC configuration for service account tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesOidcConfig {
    /// Kubernetes API server URL.
    pub api_server_url: String,

    /// OIDC issuer URL (usually the API server).
    pub issuer_url: String,

    /// JWKS URL for token verification.
    pub jwks_url: String,

    /// Expected audience in the token.
    pub audience: String,

    /// CA certificate for API server (PEM-encoded).
    pub ca_cert: Option<String>,
}

/// Trait for cloud identity providers.
///
/// Each cloud provider implements this trait to handle
/// credential federation using their specific APIs.
#[async_trait]
pub trait CloudIdentityProvider: Send + Sync {
    /// Get the provider type identifier.
    fn provider_type(&self) -> &'static str;

    /// Check if the provider is properly configured and available.
    async fn health_check(&self) -> ProviderResult<()>;

    /// Obtain credentials for the given request.
    ///
    /// # Arguments
    /// * `request` - The credential request with agent info and constraints.
    ///
    /// # Returns
    /// A cloud credential on success, or an error.
    async fn get_credentials(&self, request: &CredentialRequest)
        -> ProviderResult<CloudCredential>;

    /// Validate a JWT token from an agent.
    ///
    /// This is used for Kubernetes OIDC providers to verify
    /// service account tokens.
    async fn validate_token(&self, token: &str) -> ProviderResult<TokenValidation>;
}

/// Result of token validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidation {
    /// Whether the token is valid.
    pub valid: bool,

    /// Subject claim from the token.
    pub subject: Option<String>,

    /// Issuer claim from the token.
    pub issuer: Option<String>,

    /// Audience claim from the token.
    pub audience: Option<Vec<String>>,

    /// Expiration timestamp.
    pub expires_at: Option<i64>,

    /// Additional claims from the token.
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,

    /// Validation error message if not valid.
    pub error: Option<String>,
}

impl TokenValidation {
    /// Create a valid token validation result.
    pub fn valid(subject: String, issuer: String, expires_at: i64) -> Self {
        Self {
            valid: true,
            subject: Some(subject),
            issuer: Some(issuer),
            audience: None,
            expires_at: Some(expires_at),
            claims: HashMap::new(),
            error: None,
        }
    }

    /// Create an invalid token validation result.
    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            subject: None,
            issuer: None,
            audience: None,
            expires_at: None,
            claims: HashMap::new(),
            error: Some(error.into()),
        }
    }

    /// Add audience to the validation result.
    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Add a claim to the validation result.
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.claims.insert(key.into(), value);
        self
    }
}

// ============================================================================
// F127: Certificate Authority Provider Trait and Types
// ============================================================================

/// Result type for CA provider operations.
pub type CaResult<T> = Result<T, CaProviderError>;

/// Error type for Certificate Authority providers.
#[derive(Debug, thiserror::Error)]
pub enum CaProviderError {
    /// CA configuration is invalid.
    #[error("Invalid CA configuration: {0}")]
    InvalidConfiguration(String),

    /// CA is not available or not initialized.
    #[error("CA not available: {0}")]
    NotAvailable(String),

    /// CA private key is missing or inaccessible.
    #[error("CA private key unavailable: {0}")]
    PrivateKeyUnavailable(String),

    /// Certificate signing failed.
    #[error("Certificate signing failed: {0}")]
    SigningFailed(String),

    /// Certificate validation failed.
    #[error("Certificate validation failed: {0}")]
    ValidationFailed(String),

    /// Certificate has been revoked.
    #[error("Certificate revoked: {0}")]
    CertificateRevoked(String),

    /// Certificate has expired.
    #[error("Certificate expired")]
    CertificateExpired,

    /// Certificate not found.
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    /// Invalid certificate format.
    #[error("Invalid certificate format: {0}")]
    InvalidFormat(String),

    /// CSR (Certificate Signing Request) is invalid.
    #[error("Invalid CSR: {0}")]
    InvalidCsr(String),

    /// Requested validity exceeds CA maximum.
    #[error("Validity period exceeds maximum: requested {requested} days, max {max} days")]
    ValidityExceedsMax { requested: i32, max: i32 },

    /// External CA communication error.
    #[error("External CA error: {0}")]
    ExternalCaError(String),

    /// Network error communicating with CA.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Operation timed out.
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// Rate limit exceeded at the CA.
    #[error("CA rate limit exceeded")]
    RateLimitExceeded,

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Key algorithm for certificate generation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    /// RSA 2048-bit key.
    Rsa2048,
    /// RSA 4096-bit key.
    Rsa4096,
    /// ECDSA P-256 curve (recommended).
    #[default]
    EcdsaP256,
    /// ECDSA P-384 curve.
    EcdsaP384,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa2048 => write!(f, "rsa2048"),
            Self::Rsa4096 => write!(f, "rsa4096"),
            Self::EcdsaP256 => write!(f, "ecdsa_p256"),
            Self::EcdsaP384 => write!(f, "ecdsa_p384"),
        }
    }
}

impl std::str::FromStr for KeyAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "rsa2048" | "rsa_2048" => Ok(Self::Rsa2048),
            "rsa4096" | "rsa_4096" => Ok(Self::Rsa4096),
            "ecdsa_p256" | "ecdsap256" | "p256" => Ok(Self::EcdsaP256),
            "ecdsa_p384" | "ecdsap384" | "p384" => Ok(Self::EcdsaP384),
            _ => Err(format!("Invalid key algorithm: {}", s)),
        }
    }
}

/// Request to issue a certificate for an agent.
#[derive(Debug, Clone)]
pub struct CertificateIssueRequest {
    /// Tenant ID for the certificate.
    pub tenant_id: Uuid,

    /// Agent ID to issue certificate for.
    pub agent_id: Uuid,

    /// Agent name for the certificate subject.
    pub agent_name: String,

    /// Requested validity period in days.
    pub validity_days: i32,

    /// Key algorithm to use for the certificate.
    pub key_algorithm: KeyAlgorithm,

    /// Additional Subject Alternative Names (SANs).
    pub additional_sans: Vec<String>,
}

/// Result of certificate issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    /// Unique certificate ID.
    pub certificate_id: Uuid,

    /// PEM-encoded X.509 certificate.
    pub certificate_pem: String,

    /// PEM-encoded private key (only returned once at issuance).
    pub private_key_pem: String,

    /// PEM-encoded CA certificate chain.
    pub chain_pem: String,

    /// Certificate serial number (hex-encoded).
    pub serial_number: String,

    /// SHA-256 fingerprint of the certificate.
    pub fingerprint_sha256: String,

    /// Subject Distinguished Name.
    pub subject_dn: String,

    /// Issuer Distinguished Name.
    pub issuer_dn: String,

    /// Certificate validity start (Unix timestamp).
    pub not_before: i64,

    /// Certificate validity end (Unix timestamp).
    pub not_after: i64,
}

/// Request to renew an existing certificate.
#[derive(Debug, Clone)]
pub struct CertificateRenewRequest {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Agent ID.
    pub agent_id: Uuid,

    /// Certificate ID to renew.
    pub certificate_id: Uuid,

    /// New validity period in days.
    pub validity_days: i32,
}

/// Request to revoke a certificate.
#[derive(Debug, Clone)]
pub struct CertificateRevokeRequest {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Certificate serial number.
    pub serial_number: String,

    /// Revocation reason code (RFC 5280).
    pub reason_code: RevocationReason,

    /// User who is revoking the certificate.
    pub revoked_by: Uuid,

    /// Optional notes about the revocation.
    pub notes: Option<String>,
}

/// RFC 5280 certificate revocation reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i16)]
pub enum RevocationReason {
    /// Unspecified reason (0).
    Unspecified = 0,
    /// Key has been compromised (1).
    KeyCompromise = 1,
    /// CA has been compromised (2).
    CaCompromise = 2,
    /// Affiliation has changed (3).
    AffiliationChanged = 3,
    /// Certificate has been superseded (4).
    Superseded = 4,
    /// Certificate is no longer needed (5).
    CessationOfOperation = 5,
    /// Certificate is on hold (6).
    CertificateHold = 6,
    /// Remove from CRL (8).
    RemoveFromCrl = 8,
    /// Privilege withdrawn (9).
    PrivilegeWithdrawn = 9,
    /// AA compromise (10).
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert to i16 for database storage.
    pub fn as_i16(&self) -> i16 {
        *self as i16
    }

    /// Create from i16 value.
    pub fn from_i16(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::KeyCompromise => write!(f, "key_compromise"),
            Self::CaCompromise => write!(f, "ca_compromise"),
            Self::AffiliationChanged => write!(f, "affiliation_changed"),
            Self::Superseded => write!(f, "superseded"),
            Self::CessationOfOperation => write!(f, "cessation_of_operation"),
            Self::CertificateHold => write!(f, "certificate_hold"),
            Self::RemoveFromCrl => write!(f, "remove_from_crl"),
            Self::PrivilegeWithdrawn => write!(f, "privilege_withdrawn"),
            Self::AaCompromise => write!(f, "aa_compromise"),
        }
    }
}

impl std::str::FromStr for RevocationReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unspecified" => Ok(Self::Unspecified),
            "key_compromise" | "keycompromise" => Ok(Self::KeyCompromise),
            "ca_compromise" | "cacompromise" => Ok(Self::CaCompromise),
            "affiliation_changed" | "affiliationchanged" => Ok(Self::AffiliationChanged),
            "superseded" => Ok(Self::Superseded),
            "cessation_of_operation" | "cessationofoperation" => Ok(Self::CessationOfOperation),
            "certificate_hold" | "certificatehold" => Ok(Self::CertificateHold),
            "remove_from_crl" | "removefromcrl" => Ok(Self::RemoveFromCrl),
            "privilege_withdrawn" | "privilegewithdrawn" => Ok(Self::PrivilegeWithdrawn),
            "aa_compromise" | "aacompromise" => Ok(Self::AaCompromise),
            _ => Err(format!("Invalid revocation reason: {}", s)),
        }
    }
}

/// Result of certificate revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResult {
    /// Certificate ID that was revoked.
    pub certificate_id: Uuid,

    /// Certificate serial number.
    pub serial_number: String,

    /// When the certificate was revoked.
    pub revoked_at: i64,

    /// Revocation reason.
    pub reason: RevocationReason,
}

/// Entry for a revoked certificate in a CRL.
///
/// Used to pass revoked certificate information to the CA provider
/// for CRL generation.
#[derive(Debug, Clone)]
pub struct RevokedCertEntry {
    /// Certificate serial number (hex-encoded).
    pub serial_number: String,

    /// When the certificate was revoked (Unix timestamp).
    pub revocation_time: i64,

    /// Revocation reason code (RFC 5280).
    pub reason_code: RevocationReason,
}

/// Certificate status for validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    /// Certificate is valid and active.
    Active,
    /// Certificate has been revoked.
    Revoked,
    /// Certificate has expired.
    Expired,
}

/// Result of certificate validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidation {
    /// Whether the certificate is valid.
    pub valid: bool,

    /// Certificate status.
    pub status: CertificateStatus,

    /// Agent ID from the certificate.
    pub agent_id: Option<Uuid>,

    /// Tenant ID from the certificate.
    pub tenant_id: Option<Uuid>,

    /// Certificate serial number.
    pub serial_number: Option<String>,

    /// Certificate expiration timestamp.
    pub expires_at: Option<i64>,

    /// Validation error message if not valid.
    pub error: Option<String>,
}

impl CertificateValidation {
    /// Create a valid certificate validation result.
    pub fn valid(agent_id: Uuid, tenant_id: Uuid, serial_number: String, expires_at: i64) -> Self {
        Self {
            valid: true,
            status: CertificateStatus::Active,
            agent_id: Some(agent_id),
            tenant_id: Some(tenant_id),
            serial_number: Some(serial_number),
            expires_at: Some(expires_at),
            error: None,
        }
    }

    /// Create an invalid certificate validation result.
    pub fn invalid(status: CertificateStatus, error: impl Into<String>) -> Self {
        Self {
            valid: false,
            status,
            agent_id: None,
            tenant_id: None,
            serial_number: None,
            expires_at: None,
            error: Some(error.into()),
        }
    }
}

/// Trait for Certificate Authority providers.
///
/// Each CA provider (internal, step-ca, Vault PKI) implements this trait
/// to handle certificate operations.
#[async_trait]
pub trait CaProvider: Send + Sync {
    /// Get the provider type identifier.
    fn provider_type(&self) -> &'static str;

    /// Check if the CA is properly configured and available.
    async fn health_check(&self) -> CaResult<()>;

    /// Issue a new certificate for an agent.
    ///
    /// # Arguments
    /// * `request` - Certificate issuance request with agent info and validity.
    ///
    /// # Returns
    /// An issued certificate with private key on success.
    async fn issue_certificate(
        &self,
        request: &CertificateIssueRequest,
    ) -> CaResult<IssuedCertificate>;

    /// Renew an existing certificate.
    ///
    /// # Arguments
    /// * `request` - Certificate renewal request.
    ///
    /// # Returns
    /// A new issued certificate on success.
    async fn renew_certificate(
        &self,
        request: &CertificateRenewRequest,
    ) -> CaResult<IssuedCertificate>;

    /// Revoke a certificate.
    ///
    /// # Arguments
    /// * `request` - Certificate revocation request.
    ///
    /// # Returns
    /// Revocation result on success.
    async fn revoke_certificate(
        &self,
        request: &CertificateRevokeRequest,
    ) -> CaResult<RevocationResult>;

    /// Validate a certificate.
    ///
    /// # Arguments
    /// * `certificate_pem` - PEM-encoded certificate to validate.
    ///
    /// # Returns
    /// Validation result with certificate status.
    async fn validate_certificate(&self, certificate_pem: &str) -> CaResult<CertificateValidation>;

    /// Get the CA certificate chain (for trust configuration).
    async fn get_ca_chain(&self) -> CaResult<String>;

    /// Generate a Certificate Revocation List (CRL).
    ///
    /// # Arguments
    /// * `revoked_certs` - List of revoked certificates to include in the CRL.
    /// * `crl_number` - CRL number (should increment with each generation).
    ///
    /// # Returns
    /// DER-encoded CRL bytes on success.
    async fn generate_crl(
        &self,
        revoked_certs: &[RevokedCertEntry],
        crl_number: i64,
    ) -> CaResult<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_credential_creation() {
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        let cred = CloudCredential::aws_sts(
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            "FwoGZXIvYXdzEBY...".to_string(),
            expires_at,
        );

        assert_eq!(cred.credential_type, "aws-sts");
        assert!(cred.access_key.is_some());
        assert!(cred.secret_key.is_some());
        assert!(cred.session_token.is_some());
        assert!(!cred.is_expired());
    }

    #[test]
    fn test_gcp_credential_creation() {
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        let cred = CloudCredential::gcp_access_token("ya29.a0ARrdaM...".to_string(), expires_at);

        assert_eq!(cred.credential_type, "gcp-access-token");
        assert!(cred.access_token.is_some());
        assert!(cred.access_key.is_none());
        assert!(!cred.is_expired());
    }

    #[test]
    fn test_credential_expiration() {
        let past = chrono::Utc::now().timestamp() - 3600;
        let cred = CloudCredential::aws_sts(
            "key".to_string(),
            "secret".to_string(),
            "token".to_string(),
            past,
        );

        assert!(cred.is_expired());
        assert_eq!(cred.ttl_seconds(), 0);
    }

    #[test]
    fn test_token_validation() {
        let expires_at = chrono::Utc::now().timestamp() + 3600;
        let valid = TokenValidation::valid(
            "agent-123".to_string(),
            "https://xavyo.net".to_string(),
            expires_at,
        )
        .with_audience(vec!["sts.amazonaws.com".to_string()]);

        assert!(valid.valid);
        assert_eq!(valid.subject.as_deref(), Some("agent-123"));
        assert!(valid.audience.is_some());

        let invalid = TokenValidation::invalid("Token expired");
        assert!(!invalid.valid);
        assert!(invalid.error.is_some());
    }

    // F127: PKI tests
    #[test]
    fn test_key_algorithm_parsing() {
        assert_eq!(
            "ecdsa_p256".parse::<KeyAlgorithm>().unwrap(),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            "rsa2048".parse::<KeyAlgorithm>().unwrap(),
            KeyAlgorithm::Rsa2048
        );
        assert_eq!(
            "p384".parse::<KeyAlgorithm>().unwrap(),
            KeyAlgorithm::EcdsaP384
        );
        assert!("invalid".parse::<KeyAlgorithm>().is_err());
    }

    #[test]
    fn test_key_algorithm_display() {
        assert_eq!(KeyAlgorithm::EcdsaP256.to_string(), "ecdsa_p256");
        assert_eq!(KeyAlgorithm::Rsa4096.to_string(), "rsa4096");
    }

    #[test]
    fn test_revocation_reason_conversion() {
        assert_eq!(RevocationReason::KeyCompromise.as_i16(), 1);
        assert_eq!(
            RevocationReason::from_i16(5),
            Some(RevocationReason::CessationOfOperation)
        );
        assert_eq!(RevocationReason::from_i16(99), None);
    }

    #[test]
    fn test_revocation_reason_parsing() {
        assert_eq!(
            "key_compromise".parse::<RevocationReason>().unwrap(),
            RevocationReason::KeyCompromise
        );
        assert_eq!(
            "superseded".parse::<RevocationReason>().unwrap(),
            RevocationReason::Superseded
        );
        assert!("invalid_reason".parse::<RevocationReason>().is_err());
    }

    #[test]
    fn test_certificate_validation_valid() {
        let agent_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let expires_at = chrono::Utc::now().timestamp() + 86400;

        let validation =
            CertificateValidation::valid(agent_id, tenant_id, "01ABCDEF".to_string(), expires_at);

        assert!(validation.valid);
        assert_eq!(validation.status, CertificateStatus::Active);
        assert_eq!(validation.agent_id, Some(agent_id));
        assert!(validation.error.is_none());
    }

    #[test]
    fn test_certificate_validation_invalid() {
        let validation = CertificateValidation::invalid(
            CertificateStatus::Revoked,
            "Certificate was revoked due to key compromise",
        );

        assert!(!validation.valid);
        assert_eq!(validation.status, CertificateStatus::Revoked);
        assert!(validation.agent_id.is_none());
        assert!(validation.error.is_some());
    }
}
