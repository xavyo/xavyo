//! Certificate Authority Service for managing CA configurations (F127).
//!
//! This service handles CRUD operations for Certificate Authorities,
//! supporting both internal CAs (using rcgen) and external CAs (step-ca, Vault PKI).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use x509_parser::prelude::FromDer;
use xavyo_secrets::SecretProvider;

use xavyo_db::models::agent_certificate::AgentCertificate;
use xavyo_db::models::certificate_authority::{
    CaType, CertificateAuthority, CertificateAuthorityFilter, CreateExternalCa,
    UpdateCertificateAuthority,
};

use crate::error::ApiAgentsError;
use crate::providers::internal_ca::{create_internal_ca, InternalCaConfig, InternalCaProvider};
use crate::providers::step_ca::{StepCaConfig, StepCaProvider};
use crate::providers::vault_pki::{VaultPkiConfig, VaultPkiProvider};
use crate::providers::{CaProvider, KeyAlgorithm};
use crate::services::encryption::EncryptionService;

/// Service for managing Certificate Authorities.
pub struct CaService {
    pool: PgPool,
    encryption: Arc<EncryptionService>,
    secret_provider: Option<Arc<dyn SecretProvider>>,
}

impl CaService {
    /// Create a new CaService.
    pub fn new(pool: PgPool, encryption: Arc<EncryptionService>) -> Self {
        Self {
            pool,
            encryption,
            secret_provider: None,
        }
    }

    /// Create a new CaService with a secret provider for external CA credentials.
    pub fn with_secret_provider(
        pool: PgPool,
        encryption: Arc<EncryptionService>,
        secret_provider: Arc<dyn SecretProvider>,
    ) -> Self {
        Self {
            pool,
            encryption,
            secret_provider: Some(secret_provider),
        }
    }

    /// Load a secret from the configured secret provider.
    ///
    /// The secret reference can be in formats like:
    /// - `secret://my-secret-name` - Load from xavyo-secrets
    /// - Direct value (no prefix) - Return as-is (for testing/development)
    async fn load_secret(&self, secret_ref: &str) -> Result<String, ApiAgentsError> {
        if let Some(ref provider) = self.secret_provider {
            // Parse the secret reference
            let secret_name = if let Some(name) = secret_ref.strip_prefix("secret://") {
                name
            } else {
                // Return as-is for direct values (development/testing)
                return Ok(secret_ref.to_string());
            };

            // Load from secret provider
            let secret_value = provider
                .get_secret(secret_name)
                .await
                .map_err(|e| ApiAgentsError::CaCreationFailed(
                    format!("Failed to load secret '{}': {}", secret_name, e)
                ))?;

            secret_value
                .as_str()
                .map(|s| s.to_string())
                .map_err(|e| ApiAgentsError::CaCreationFailed(
                    format!("Invalid secret value: {}", e)
                ))
        } else {
            // No secret provider configured - return as-is (development mode)
            if secret_ref.starts_with("secret://") {
                Err(ApiAgentsError::CaCreationFailed(
                    "Secret provider not configured. Cannot load secrets.".to_string()
                ))
            } else {
                Ok(secret_ref.to_string())
            }
        }
    }

    /// Create a new internal CA with generated key pair.
    ///
    /// This generates a new CA certificate and private key, stores them encrypted,
    /// and registers the CA in the database.
    pub async fn create_internal_ca(
        &self,
        tenant_id: Uuid,
        request: CreateInternalCaRequest,
    ) -> Result<CaResponse, ApiAgentsError> {
        // Check if a CA with this name already exists
        if CertificateAuthority::find_by_name(&self.pool, tenant_id, &request.name)
            .await
            .map_err(ApiAgentsError::Database)?
            .is_some()
        {
            return Err(ApiAgentsError::CaAlreadyExists(request.name));
        }

        // Determine key algorithm
        let algorithm = match request.key_algorithm.as_deref() {
            Some("ecdsa-p384") | Some("ecdsa_p384") => KeyAlgorithm::EcdsaP384,
            Some("rsa-2048") | Some("rsa2048") => KeyAlgorithm::Rsa2048,
            Some("rsa-4096") | Some("rsa4096") => KeyAlgorithm::Rsa4096,
            _ => KeyAlgorithm::EcdsaP256, // Default
        };

        // Determine validity period (default 10 years for CA)
        let validity_days = request.validity_days.unwrap_or(3650);

        // Generate the CA certificate and private key
        let (ca_cert_pem, ca_key_pem, subject_dn) = create_internal_ca(
            &request.name,
            &request.organization,
            validity_days,
            algorithm,
        )
        .map_err(|e| ApiAgentsError::CaCreationFailed(e.to_string()))?;

        // Encrypt the private key - encrypt returns base64 String, convert to bytes for DB storage
        let encrypted_private_key_base64 = self.encryption.encrypt(&ca_key_pem)?;
        let encrypted_private_key = encrypted_private_key_base64.into_bytes();

        // Parse certificate to get not_before/not_after
        let cert_der = ::pem::parse(&ca_cert_pem)
            .map_err(|e| ApiAgentsError::CaCreationFailed(format!("Failed to parse CA cert: {}", e)))?;

        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.contents())
            .map_err(|e| ApiAgentsError::CaCreationFailed(format!("Failed to parse X.509: {:?}", e)))?;

        let not_before: DateTime<Utc> = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after: DateTime<Utc> = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::days(validity_days as i64));

        // Create DB record
        let ca = CertificateAuthority::create_internal(
            &self.pool,
            tenant_id,
            &request.name,
            &ca_cert_pem,
            encrypted_private_key,
            &subject_dn,
            not_before,
            not_after,
            request.max_cert_validity_days.unwrap_or(365),
            request.is_default.unwrap_or(false),
            request.crl_url.as_deref(),
            request.ocsp_url.as_deref(),
        )
        .await
        .map_err(ApiAgentsError::Database)?;

        Ok(CaResponse::from_ca(ca))
    }

    /// Register an external CA (step-ca or Vault PKI).
    pub async fn create_external_ca(
        &self,
        tenant_id: Uuid,
        request: CreateExternalCaRequest,
    ) -> Result<CaResponse, ApiAgentsError> {
        // Check if a CA with this name already exists
        if CertificateAuthority::find_by_name(&self.pool, tenant_id, &request.name)
            .await
            .map_err(ApiAgentsError::Database)?
            .is_some()
        {
            return Err(ApiAgentsError::CaAlreadyExists(request.name));
        }

        // Validate CA type
        let ca_type_str = match request.ca_type.as_str() {
            "step_ca" => "step_ca",
            "vault_pki" => "vault_pki",
            _ => return Err(ApiAgentsError::InvalidCaType(request.ca_type)),
        };

        // Parse the CA chain certificate
        let cert_der = ::pem::parse(&request.ca_chain_pem)
            .map_err(|e| ApiAgentsError::CaCreationFailed(format!("Failed to parse CA chain: {}", e)))?;

        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.contents())
            .map_err(|e| ApiAgentsError::CaCreationFailed(format!("Failed to parse X.509: {:?}", e)))?;

        let subject_dn = format_subject_dn(cert.subject());

        let not_before: DateTime<Utc> = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after: DateTime<Utc> = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::days(3650));

        let db_input = CreateExternalCa {
            name: request.name,
            ca_type: ca_type_str.to_string(),
            certificate_pem: request.ca_chain_pem,
            chain_pem: None,
            external_config: request.connection_settings,
            max_validity_days: request.max_cert_validity_days.unwrap_or(365),
            is_default: request.is_default.unwrap_or(false),
            crl_url: request.crl_url,
            ocsp_url: request.ocsp_url,
        };

        let ca = CertificateAuthority::create_external(
            &self.pool,
            tenant_id,
            db_input,
            &subject_dn,
            not_before,
            not_after,
        )
        .await
        .map_err(ApiAgentsError::Database)?;

        Ok(CaResponse::from_ca(ca))
    }

    /// Get a CA by ID.
    pub async fn get_ca(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<CaResponse, ApiAgentsError> {
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        Ok(CaResponse::from_ca(ca))
    }

    /// Get the default CA for a tenant.
    pub async fn get_default_ca(
        &self,
        tenant_id: Uuid,
    ) -> Result<CaResponse, ApiAgentsError> {
        let ca = CertificateAuthority::find_default(&self.pool, tenant_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::NoDefaultCa)?;

        Ok(CaResponse::from_ca(ca))
    }

    /// List CAs for a tenant with filtering.
    pub async fn list_cas(
        &self,
        tenant_id: Uuid,
        filter: CertificateAuthorityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<CaListResponse, ApiAgentsError> {
        let cas = CertificateAuthority::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(ApiAgentsError::Database)?;

        let total = CertificateAuthority::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(ApiAgentsError::Database)?;

        let items: Vec<CaResponse> = cas.into_iter().map(CaResponse::from_ca).collect();

        Ok(CaListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Update a CA.
    pub async fn update_ca(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
        request: UpdateCaRequest,
    ) -> Result<CaResponse, ApiAgentsError> {
        // Verify CA exists
        let existing = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        // Check name uniqueness if changing name
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name
                && CertificateAuthority::find_by_name(&self.pool, tenant_id, new_name)
                    .await
                    .map_err(ApiAgentsError::Database)?
                    .is_some()
            {
                return Err(ApiAgentsError::CaAlreadyExists(new_name.clone()));
            }
        }

        let db_update = UpdateCertificateAuthority {
            name: request.name,
            is_active: request.enabled,
            is_default: request.is_default,
            max_validity_days: request.max_cert_validity_days,
            crl_url: request.crl_url.map(Some),
            ocsp_url: request.ocsp_url.map(Some),
            external_config: None,
        };

        let ca = CertificateAuthority::update(&self.pool, tenant_id, ca_id, db_update)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        Ok(CaResponse::from_ca(ca))
    }

    /// Set a CA as the default for the tenant.
    pub async fn set_default_ca(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<CaResponse, ApiAgentsError> {
        // Verify CA exists and is active
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        if !ca.is_active {
            return Err(ApiAgentsError::CaDisabled(ca_id));
        }

        // Set as default
        let db_update = UpdateCertificateAuthority {
            is_default: Some(true),
            ..Default::default()
        };

        let ca = CertificateAuthority::update(&self.pool, tenant_id, ca_id, db_update)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        Ok(CaResponse::from_ca(ca))
    }

    /// Delete a CA.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The CA doesn't exist
    /// - The CA is set as the default
    /// - There are active certificates signed by this CA
    pub async fn delete_ca(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        // Check if CA exists
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        // Don't allow deleting the default CA
        if ca.is_default {
            return Err(ApiAgentsError::CannotDeleteDefaultCa);
        }

        // Check if there are any active certificates signed by this CA
        let active_cert_count = AgentCertificate::count_active_by_ca(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?;

        if active_cert_count > 0 {
            return Err(ApiAgentsError::CaHasActiveCertificates {
                ca_id,
                count: active_cert_count,
            });
        }

        CertificateAuthority::delete(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?;

        Ok(())
    }

    /// Get a CA provider instance for certificate operations.
    pub async fn get_ca_provider(
        &self,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<Box<dyn CaProvider + Send + Sync>, ApiAgentsError> {
        let ca = CertificateAuthority::find_by_id(&self.pool, tenant_id, ca_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

        self.create_provider_for_ca(&ca).await
    }

    /// Get the default CA provider for a tenant.
    pub async fn get_default_ca_provider(
        &self,
        tenant_id: Uuid,
    ) -> Result<Box<dyn CaProvider + Send + Sync>, ApiAgentsError> {
        let ca = CertificateAuthority::find_default(&self.pool, tenant_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::NoDefaultCa)?;

        self.create_provider_for_ca(&ca).await
    }

    /// Create a provider instance for a CA.
    async fn create_provider_for_ca(
        &self,
        ca: &CertificateAuthority,
    ) -> Result<Box<dyn CaProvider + Send + Sync>, ApiAgentsError> {
        let ca_type = ca.ca_type_enum()
            .map_err(ApiAgentsError::InvalidCaType)?;

        match ca_type {
            CaType::Internal => {
                // Decrypt the private key
                // The encrypted key is stored as Vec<u8> (base64-encoded bytes), convert to String for decrypt()
                let key_pem = if let Some(ref encrypted) = ca.private_key_encrypted {
                    let encrypted_str = String::from_utf8(encrypted.clone())
                        .map_err(|e| ApiAgentsError::CaCreationFailed(format!("Invalid encrypted key encoding: {}", e)))?;
                    self.encryption.decrypt(&encrypted_str)?
                } else {
                    return Err(ApiAgentsError::CaCreationFailed("No private key for internal CA".to_string()));
                };

                let config = InternalCaConfig {
                    ca_id: ca.id,
                    tenant_id: ca.tenant_id,
                    ca_certificate_pem: ca.certificate_pem.clone(),
                    ca_private_key_pem: Some(key_pem),
                    encrypted_private_key: None,
                    private_key_ref: ca.private_key_ref.clone(),
                    ca_subject_dn: ca.subject_dn.clone(),
                    max_validity_days: ca.max_validity_days,
                    crl_url: ca.crl_url.clone(),
                    ocsp_url: ca.ocsp_url.clone(),
                };

                Ok(Box::new(InternalCaProvider::new(config)))
            }
            CaType::StepCa => {
                // Parse external_config into StepCaConfig
                let external_config = ca.external_config.clone().ok_or_else(|| {
                    ApiAgentsError::CaCreationFailed("No external configuration for step-ca".to_string())
                })?;

                let base_config: serde_json::Value = external_config;
                let mut config: StepCaConfig = serde_json::from_value(base_config).map_err(|e| {
                    ApiAgentsError::CaCreationFailed(format!("Invalid step-ca config: {}", e))
                })?;

                // Fill in fields from the CA record
                config.ca_id = ca.id;
                config.tenant_id = ca.tenant_id;
                config.ca_certificate_pem = ca.certificate_pem.clone();
                config.max_validity_days = ca.max_validity_days;

                // Load provisioner password from secret provider
                let password = self.load_secret(&config.provisioner_password_ref).await?;

                Ok(Box::new(StepCaProvider::with_password(config, password)))
            }
            CaType::VaultPki => {
                // Parse external_config into VaultPkiConfig
                let external_config = ca.external_config.clone().ok_or_else(|| {
                    ApiAgentsError::CaCreationFailed("No external configuration for Vault PKI".to_string())
                })?;

                let base_config: serde_json::Value = external_config;
                let mut config: VaultPkiConfig = serde_json::from_value(base_config).map_err(|e| {
                    ApiAgentsError::CaCreationFailed(format!("Invalid Vault PKI config: {}", e))
                })?;

                // Fill in fields from the CA record
                config.ca_id = ca.id;
                config.tenant_id = ca.tenant_id;
                config.ca_certificate_pem = ca.certificate_pem.clone();
                config.max_validity_days = ca.max_validity_days;

                // Load Vault token from secret provider
                let token = self.load_secret(&config.auth_token_ref).await?;

                Ok(Box::new(VaultPkiProvider::with_token(config, token)))
            }
        }
    }
}

/// Format an X.500 Distinguished Name.
fn format_subject_dn(subject: &x509_parser::x509::X509Name) -> String {
    subject
        .iter()
        .flat_map(|rdn| rdn.iter())
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
            oid_str.map(|oid| {
                format!("{}={}", oid, attr.as_str().unwrap_or(""))
            })
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Request to create an internal CA.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateInternalCaRequest {
    /// Name of the CA.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Organization name for the CA certificate.
    pub organization: String,
    /// Key algorithm: "ecdsa_p256" (default), "ecdsa_p384", "rsa2048", "rsa4096".
    pub key_algorithm: Option<String>,
    /// Validity period in days (default: 3650 = 10 years).
    pub validity_days: Option<i32>,
    /// Maximum validity for issued certificates (default: 365 days).
    pub max_cert_validity_days: Option<i32>,
    /// CRL distribution point URL.
    pub crl_url: Option<String>,
    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
    /// Set as default CA for the tenant.
    pub is_default: Option<bool>,
}

/// Request to register an external CA.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateExternalCaRequest {
    /// CA type: "step_ca" or "vault_pki".
    pub ca_type: String,
    /// Name of the CA.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// CA chain certificate in PEM format.
    pub ca_chain_pem: String,
    /// API endpoint for the CA service.
    pub api_endpoint: Option<String>,
    /// Connection settings (provider-specific configuration).
    pub connection_settings: serde_json::Value,
    /// Maximum validity for issued certificates (default: 365 days).
    pub max_cert_validity_days: Option<i32>,
    /// CRL distribution point URL.
    pub crl_url: Option<String>,
    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
    /// Set as default CA for the tenant.
    pub is_default: Option<bool>,
}

/// Request to update a CA.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateCaRequest {
    /// New name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New max certificate validity.
    pub max_cert_validity_days: Option<i32>,
    /// New CRL URL.
    pub crl_url: Option<String>,
    /// New OCSP URL.
    pub ocsp_url: Option<String>,
    /// Enable or disable the CA.
    pub enabled: Option<bool>,
    /// Set as default.
    pub is_default: Option<bool>,
}

/// CA response.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CaResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub ca_type: String,
    pub name: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub max_validity_days: i32,
    pub crl_url: Option<String>,
    pub ocsp_url: Option<String>,
    pub is_active: bool,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CaResponse {
    fn from_ca(ca: CertificateAuthority) -> Self {
        Self {
            id: ca.id,
            tenant_id: ca.tenant_id,
            ca_type: ca.ca_type,
            name: ca.name,
            subject_dn: ca.subject_dn,
            not_before: ca.not_before,
            not_after: ca.not_after,
            max_validity_days: ca.max_validity_days,
            crl_url: ca.crl_url,
            ocsp_url: ca.ocsp_url,
            is_active: ca.is_active,
            is_default: ca.is_default,
            created_at: ca.created_at,
            updated_at: ca.updated_at,
        }
    }
}

/// CA list response.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CaListResponse {
    pub items: Vec<CaResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use xavyo_secrets::{SecretError, SecretValue};

    /// Mock secret provider for testing.
    struct MockSecretProvider {
        secrets: HashMap<String, String>,
    }

    impl MockSecretProvider {
        fn new() -> Self {
            Self {
                secrets: HashMap::new(),
            }
        }

        fn with_secret(mut self, name: &str, value: &str) -> Self {
            self.secrets.insert(name.to_string(), value.to_string());
            self
        }
    }

    #[async_trait]
    impl SecretProvider for MockSecretProvider {
        async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
            self.secrets
                .get(name)
                .map(|v| SecretValue::new(name, v.as_bytes().to_vec()))
                .ok_or_else(|| SecretError::NotFound { name: name.to_string() })
        }

        async fn health_check(&self) -> Result<bool, SecretError> {
            Ok(true)
        }

        fn provider_type(&self) -> &'static str {
            "mock"
        }
    }

    #[test]
    fn test_create_internal_ca_request_default_values() {
        let json = r#"{"name": "Test CA", "organization": "Test Org"}"#;
        let request: CreateInternalCaRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.name, "Test CA");
        assert_eq!(request.organization, "Test Org");
        assert!(request.key_algorithm.is_none());
        assert!(request.validity_days.is_none());
        assert!(request.is_default.is_none());
    }

    #[test]
    fn test_ca_response_from_ca() {
        let ca = CertificateAuthority {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            ca_type: "internal".to_string(),
            name: "Test CA".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            chain_pem: None,
            private_key_encrypted: Some(vec![1, 2, 3]),
            private_key_ref: None,
            external_config: None,
            subject_dn: "CN=Test CA,O=Test Org".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            max_validity_days: 90,
            crl_url: Some("https://example.com/crl".to_string()),
            ocsp_url: None,
            is_active: true,
            is_default: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = CaResponse::from_ca(ca);

        assert_eq!(response.ca_type, "internal");
        assert_eq!(response.name, "Test CA");
        assert_eq!(response.max_validity_days, 90);
        assert!(response.is_active);
        assert!(!response.is_default);
    }

    #[tokio::test]
    async fn test_mock_secret_provider() {
        let mock_provider = MockSecretProvider::new()
            .with_secret("step-ca-password", "my-secret-password")
            .with_secret("vault-token", "hvs.test-token");

        // Test that the mock provider works correctly
        let secret = mock_provider.get_secret("step-ca-password").await.unwrap();
        assert_eq!(secret.as_str().unwrap(), "my-secret-password");

        let secret = mock_provider.get_secret("vault-token").await.unwrap();
        assert_eq!(secret.as_str().unwrap(), "hvs.test-token");

        // Test that nonexistent secrets return an error
        assert!(mock_provider.get_secret("nonexistent").await.is_err());
    }

    #[test]
    fn test_secret_ref_parsing() {
        // Test that secret:// prefix is correctly recognized
        let secret_ref = "secret://my-secret";
        assert!(secret_ref.starts_with("secret://"));
        assert_eq!(&secret_ref[9..], "my-secret");

        // Test direct values (no prefix)
        let direct_value = "direct-password";
        assert!(!direct_value.starts_with("secret://"));
    }
}
