//! Provider Registry for dynamic secret providers (F120).
//!
//! Manages instances of `DynamicSecretProvider` and coordinates
//! between configured providers and credential generation.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use xavyo_secrets::dynamic::{DynamicCredential, DynamicCredentialRequest, DynamicSecretProvider};
use xavyo_secrets::provider::internal::InternalSecretProvider;
use xavyo_secrets::provider::openbao::{OpenBaoAuthMethod, OpenBaoConfig, OpenBaoSecretProvider};
use xavyo_secrets::SecretError;

use crate::error::ApiAgentsError;
use crate::services::encryption::EncryptionService;

use sqlx::PgPool;
use xavyo_db::models::secret_provider_config::SecretProviderConfig;

/// Configuration parsed from provider settings.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OpenBaoSettings {
    pub addr: String,
    pub token: Option<String>,
    pub role_id: Option<String>,
    pub secret_id: Option<String>,
    pub namespace: Option<String>,
    pub database_mount: Option<String>,
}

/// Registry for managing dynamic secret provider instances.
///
/// Providers are lazily instantiated and cached per tenant + provider ID.
pub struct ProviderRegistry {
    #[allow(dead_code)]
    pool: PgPool,
    encryption: Arc<EncryptionService>,
    /// Cache of provider instances: (`tenant_id`, `provider_id`) -> Provider
    providers: RwLock<HashMap<(Uuid, Uuid), Arc<dyn DynamicSecretProvider>>>,
    /// Internal provider instance (shared across all tenants)
    internal_provider: Arc<InternalSecretProvider>,
}

impl ProviderRegistry {
    /// Create a new `ProviderRegistry`.
    #[must_use]
    pub fn new(pool: PgPool, encryption: Arc<EncryptionService>) -> Self {
        Self {
            pool,
            encryption,
            providers: RwLock::new(HashMap::new()),
            internal_provider: Arc::new(InternalSecretProvider::new()),
        }
    }

    /// Get or create a provider instance for the given configuration.
    pub async fn get_provider(
        &self,
        tenant_id: Uuid,
        provider_type: &str,
        provider_config: Option<&SecretProviderConfig>,
    ) -> Result<Arc<dyn DynamicSecretProvider>, ApiAgentsError> {
        match provider_type {
            "internal" => Ok(self.internal_provider.clone()),
            "openbao" => {
                let config = provider_config.ok_or_else(|| {
                    ApiAgentsError::SecretProviderUnavailable(
                        "No OpenBao provider configured".to_string(),
                    )
                })?;
                self.get_or_create_openbao(tenant_id, config).await
            }
            "infisical" => {
                // TODO: Implement Infisical provider integration
                Err(ApiAgentsError::SecretProviderUnavailable(
                    "Infisical provider not yet implemented".to_string(),
                ))
            }
            "aws" => {
                // TODO: Implement AWS Secrets Manager provider integration
                Err(ApiAgentsError::SecretProviderUnavailable(
                    "AWS provider not yet implemented".to_string(),
                ))
            }
            other => Err(ApiAgentsError::BadRequest(format!(
                "Unknown provider type: {other}"
            ))),
        }
    }

    /// Get or create an `OpenBao` provider instance.
    async fn get_or_create_openbao(
        &self,
        tenant_id: Uuid,
        config: &SecretProviderConfig,
    ) -> Result<Arc<dyn DynamicSecretProvider>, ApiAgentsError> {
        let cache_key = (tenant_id, config.id);

        // Check cache first
        {
            let providers = self.providers.read().await;
            if let Some(provider) = providers.get(&cache_key) {
                return Ok(provider.clone());
            }
        }

        // Create new provider
        let settings_json = self.encryption.decrypt(&config.connection_settings)?;
        let settings: OpenBaoSettings = serde_json::from_str(&settings_json)
            .map_err(|e| ApiAgentsError::BadRequest(format!("Invalid OpenBao settings: {e}")))?;

        let auth_method =
            if let (Some(role_id), Some(secret_id)) = (&settings.role_id, &settings.secret_id) {
                OpenBaoAuthMethod::AppRole {
                    role_id: role_id.clone(),
                    secret_id: secret_id.clone(),
                }
            } else if let Some(token) = &settings.token {
                OpenBaoAuthMethod::Token {
                    token: token.clone(),
                }
            } else {
                return Err(ApiAgentsError::BadRequest(
                    "OpenBao settings must have either token or role_id/secret_id".to_string(),
                ));
            };

        let openbao_config = OpenBaoConfig {
            address: settings.addr,
            namespace: settings.namespace,
            auth_method,
            database_mount: settings
                .database_mount
                .unwrap_or_else(|| "database".to_string()),
        };

        let provider = OpenBaoSecretProvider::new(&openbao_config)
            .await
            .map_err(|e| {
                ApiAgentsError::SecretProviderUnavailable(format!(
                    "Failed to initialize OpenBao provider: {e}"
                ))
            })?;

        let provider: Arc<dyn DynamicSecretProvider> = Arc::new(provider);

        // Cache the provider
        {
            let mut providers = self.providers.write().await;
            providers.insert(cache_key, provider.clone());
        }

        Ok(provider)
    }

    /// Generate credentials using the appropriate provider.
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_credentials(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
        ttl_seconds: i32,
        provider_type: &str,
        provider_config: Option<&SecretProviderConfig>,
        role: Option<String>,
    ) -> Result<DynamicCredential, ApiAgentsError> {
        let provider = self
            .get_provider(tenant_id, provider_type, provider_config)
            .await?;

        let request = DynamicCredentialRequest {
            tenant_id,
            agent_id,
            secret_type: secret_type.to_string(),
            ttl_seconds,
            role,
            context: None,
        };

        provider
            .generate_credentials(&request)
            .await
            .map_err(|e| match e {
                SecretError::ProviderUnavailable { provider, detail } => {
                    ApiAgentsError::SecretProviderUnavailable(format!("{provider}: {detail}"))
                }
                SecretError::PermissionDenied { detail } => {
                    ApiAgentsError::ProviderAuthFailed(format!("Permission denied: {detail}"))
                }
                SecretError::ConfigError { detail } => {
                    ApiAgentsError::BadRequest(format!("Configuration error: {detail}"))
                }
                other => ApiAgentsError::Internal(other.to_string()),
            })
    }

    /// Revoke credentials by lease ID.
    pub async fn revoke_credentials(
        &self,
        tenant_id: Uuid,
        provider_type: &str,
        provider_config: Option<&SecretProviderConfig>,
        lease_id: &str,
    ) -> Result<(), ApiAgentsError> {
        let provider = self
            .get_provider(tenant_id, provider_type, provider_config)
            .await?;

        provider
            .revoke_credentials(lease_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(e.to_string()))
    }

    /// Clear cached providers (e.g., when settings change).
    pub async fn clear_cache(&self, tenant_id: Uuid, provider_id: Uuid) {
        let mut providers = self.providers.write().await;
        providers.remove(&(tenant_id, provider_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openbao_settings_deserialization() {
        let json = r#"{
            "addr": "https://openbao.example.com:8200",
            "token": "hvs.test-token",
            "namespace": "admin",
            "database_mount": "database"
        }"#;

        let settings: OpenBaoSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.addr, "https://openbao.example.com:8200");
        assert_eq!(settings.token.unwrap(), "hvs.test-token");
        assert_eq!(settings.namespace.unwrap(), "admin");
        assert_eq!(settings.database_mount.unwrap(), "database");
    }

    #[test]
    fn test_openbao_settings_approle() {
        let json = r#"{
            "addr": "https://openbao.example.com:8200",
            "role_id": "my-role",
            "secret_id": "my-secret"
        }"#;

        let settings: OpenBaoSettings = serde_json::from_str(json).unwrap();
        assert!(settings.token.is_none());
        assert_eq!(settings.role_id.unwrap(), "my-role");
        assert_eq!(settings.secret_id.unwrap(), "my-secret");
    }
}
