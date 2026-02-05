//! Secret Provider Service for managing external secret provider configurations (F120).
//!
//! This service handles CRUD operations for secret providers (`OpenBao`, Infisical, AWS)
//! with encrypted connection settings and health check management.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::secret_provider_config::{
    CreateSecretProviderConfig, InfisicalSettings, OpenBaoSettings, ProviderHealthResult,
    ProviderHealthStatus, SecretProviderConfig, SecretProviderConfigFilter,
    UpdateSecretProviderConfig,
};

use crate::error::ApiAgentsError;
use crate::services::encryption::EncryptionService;

/// Service for managing secret provider configurations.
pub struct SecretProviderService {
    pool: PgPool,
    encryption: Arc<EncryptionService>,
}

impl SecretProviderService {
    /// Create a new `SecretProviderService`.
    #[must_use]
    pub fn new(pool: PgPool, encryption: Arc<EncryptionService>) -> Self {
        Self { pool, encryption }
    }

    /// Create a new provider configuration with encrypted settings.
    pub async fn create_provider(
        &self,
        tenant_id: Uuid,
        input: CreateProviderRequest,
    ) -> Result<ProviderResponse, ApiAgentsError> {
        // Validate provider type
        Self::validate_provider_type(&input.provider_type)?;

        // Check for duplicate name
        if SecretProviderConfig::find_by_name(&self.pool, tenant_id, &input.name)
            .await
            .map_err(ApiAgentsError::Database)?
            .is_some()
        {
            return Err(ApiAgentsError::SecretTypeExists(input.name));
        }

        // Encrypt connection settings
        let encrypted_settings = self.encryption.encrypt(&input.connection_settings)?;

        let db_input = CreateSecretProviderConfig {
            provider_type: input.provider_type,
            name: input.name,
            connection_settings: encrypted_settings,
        };

        let config = SecretProviderConfig::create(&self.pool, tenant_id, db_input)
            .await
            .map_err(ApiAgentsError::Database)?;

        Ok(ProviderResponse::from_config(config, false))
    }

    /// Get a provider configuration by ID.
    pub async fn get_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderResponse, ApiAgentsError> {
        let config = SecretProviderConfig::find_by_id(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        Ok(ProviderResponse::from_config(config, false))
    }

    /// List provider configurations with filtering.
    pub async fn list_providers(
        &self,
        tenant_id: Uuid,
        filter: SecretProviderConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<ProviderListResponse, ApiAgentsError> {
        let configs =
            SecretProviderConfig::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(ApiAgentsError::Database)?;

        let total = SecretProviderConfig::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(ApiAgentsError::Database)?;

        let items: Vec<ProviderResponse> = configs
            .into_iter()
            .map(|c| ProviderResponse::from_config(c, false))
            .collect();

        Ok(ProviderListResponse { items, total })
    }

    /// Update a provider configuration.
    pub async fn update_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        input: UpdateProviderRequest,
    ) -> Result<ProviderResponse, ApiAgentsError> {
        // Check if provider exists
        let existing = SecretProviderConfig::find_by_id(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = input.name {
            if new_name != &existing.name
                && SecretProviderConfig::find_by_name(&self.pool, tenant_id, new_name)
                    .await
                    .map_err(ApiAgentsError::Database)?
                    .is_some()
            {
                return Err(ApiAgentsError::SecretTypeExists(new_name.clone()));
            }
        }

        // Encrypt connection settings if provided
        let encrypted_settings = if let Some(ref settings) = input.connection_settings {
            Some(self.encryption.encrypt(settings)?)
        } else {
            None
        };

        let db_input = UpdateSecretProviderConfig {
            name: input.name,
            connection_settings: encrypted_settings,
            status: input.status,
        };

        let config = SecretProviderConfig::update(&self.pool, tenant_id, provider_id, db_input)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        Ok(ProviderResponse::from_config(config, false))
    }

    /// Delete a provider configuration.
    pub async fn delete_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<bool, ApiAgentsError> {
        let deleted = SecretProviderConfig::delete(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?;

        if !deleted {
            return Err(ApiAgentsError::SecretProviderNotFound(
                provider_id.to_string(),
            ));
        }

        Ok(true)
    }

    /// Activate a provider.
    pub async fn activate_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderResponse, ApiAgentsError> {
        let config = SecretProviderConfig::activate(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        Ok(ProviderResponse::from_config(config, false))
    }

    /// Deactivate a provider.
    pub async fn deactivate_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderResponse, ApiAgentsError> {
        let config = SecretProviderConfig::deactivate(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        Ok(ProviderResponse::from_config(config, false))
    }

    /// Run a health check on a provider.
    pub async fn health_check(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderHealthResult, ApiAgentsError> {
        let config = SecretProviderConfig::find_by_id(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        // Decrypt connection settings
        let settings_json = self.encryption.decrypt(&config.connection_settings)?;

        let start = std::time::Instant::now();
        let health_result = match config.provider_type.as_str() {
            "openbao" => self.check_openbao_health(&settings_json).await,
            "infisical" => self.check_infisical_health(&settings_json).await,
            "internal" => Ok(true), // Internal provider is always healthy
            other => Err(ApiAgentsError::BadRequest(format!(
                "Unknown provider type: {other}"
            ))),
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (status, error) = match health_result {
            Ok(true) => (ProviderHealthStatus::Healthy, None),
            Ok(false) => (
                ProviderHealthStatus::Degraded,
                Some("Provider returned degraded status".to_string()),
            ),
            Err(e) => (ProviderHealthStatus::Unhealthy, Some(e.to_string())),
        };

        // Update health check timestamp in database
        let _ = SecretProviderConfig::update_health_check(
            &self.pool,
            tenant_id,
            provider_id,
            status == ProviderHealthStatus::Healthy,
        )
        .await;

        Ok(ProviderHealthResult {
            status,
            last_check: chrono::Utc::now(),
            latency_ms: Some(latency_ms),
            error,
        })
    }

    /// Get decrypted connection settings (for internal use).
    pub async fn get_decrypted_settings(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<String, ApiAgentsError> {
        let config = SecretProviderConfig::find_by_id(&self.pool, tenant_id, provider_id)
            .await
            .map_err(ApiAgentsError::Database)?
            .ok_or_else(|| ApiAgentsError::SecretProviderNotFound(provider_id.to_string()))?;

        if !config.is_active() {
            return Err(ApiAgentsError::SecretProviderUnavailable(format!(
                "Provider '{}' is not active (status: {})",
                config.name, config.status
            )));
        }

        self.encryption.decrypt(&config.connection_settings)
    }

    /// Find the first active provider of a given type.
    pub async fn find_active_provider(
        &self,
        tenant_id: Uuid,
        provider_type: &str,
    ) -> Result<Option<SecretProviderConfig>, ApiAgentsError> {
        let providers =
            SecretProviderConfig::find_active_by_type(&self.pool, tenant_id, provider_type)
                .await
                .map_err(ApiAgentsError::Database)?;

        Ok(providers.into_iter().next())
    }

    /// Check `OpenBao` health.
    async fn check_openbao_health(&self, settings_json: &str) -> Result<bool, ApiAgentsError> {
        let settings: OpenBaoSettings = serde_json::from_str(settings_json)
            .map_err(|e| ApiAgentsError::BadRequest(format!("Invalid OpenBao settings: {e}")))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to create HTTP client: {e}")))?;

        let url = format!("{}/v1/sys/health", settings.addr.trim_end_matches('/'));
        let resp = client.get(&url).send().await.map_err(|e| {
            ApiAgentsError::SecretProviderUnavailable(format!("OpenBao connection failed: {e}"))
        })?;

        let status = resp.status().as_u16();
        // 200 = active, 429 = standby, 472/473 = replication modes
        Ok(matches!(status, 200 | 429 | 472 | 473))
    }

    /// Check Infisical health.
    async fn check_infisical_health(&self, settings_json: &str) -> Result<bool, ApiAgentsError> {
        let settings: InfisicalSettings = serde_json::from_str(settings_json)
            .map_err(|e| ApiAgentsError::BadRequest(format!("Invalid Infisical settings: {e}")))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to create HTTP client: {e}")))?;

        // Try to get workspace info
        let url = format!(
            "{}/api/v1/workspace/{}/environments",
            settings.base_url.trim_end_matches('/'),
            settings.workspace_id
        );

        let resp = client
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", settings.service_token),
            )
            .send()
            .await
            .map_err(|e| {
                ApiAgentsError::SecretProviderUnavailable(format!(
                    "Infisical connection failed: {e}"
                ))
            })?;

        Ok(resp.status().is_success())
    }

    /// Validate provider type.
    fn validate_provider_type(provider_type: &str) -> Result<(), ApiAgentsError> {
        match provider_type {
            "openbao" | "infisical" | "internal" | "aws" => Ok(()),
            other => Err(ApiAgentsError::BadRequest(format!(
                "Invalid provider type: {other}. Supported types: openbao, infisical, internal, aws"
            ))),
        }
    }
}

/// Request to create a provider configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateProviderRequest {
    /// Provider type (openbao, infisical, internal, aws).
    pub provider_type: String,
    /// Human-readable name.
    pub name: String,
    /// Connection settings as JSON string.
    pub connection_settings: String,
}

/// Request to update a provider configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateProviderRequest {
    /// Updated name.
    pub name: Option<String>,
    /// Updated connection settings as JSON string.
    pub connection_settings: Option<String>,
    /// Updated status (active, inactive).
    pub status: Option<String>,
}

/// Provider configuration response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderResponse {
    pub id: Uuid,
    pub provider_type: String,
    pub name: String,
    pub status: String,
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Connection settings (only included if requested and authorized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_settings: Option<String>,
}

impl ProviderResponse {
    /// Create a response from a database config.
    fn from_config(config: SecretProviderConfig, include_settings: bool) -> Self {
        Self {
            id: config.id,
            provider_type: config.provider_type,
            name: config.name,
            status: config.status,
            last_health_check: config.last_health_check,
            created_at: config.created_at,
            updated_at: config.updated_at,
            connection_settings: if include_settings {
                Some(config.connection_settings)
            } else {
                None
            },
        }
    }
}

/// Response for listing providers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderListResponse {
    pub items: Vec<ProviderResponse>,
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_provider_type_valid() {
        assert!(SecretProviderService::validate_provider_type("openbao").is_ok());
        assert!(SecretProviderService::validate_provider_type("infisical").is_ok());
        assert!(SecretProviderService::validate_provider_type("internal").is_ok());
        assert!(SecretProviderService::validate_provider_type("aws").is_ok());
    }

    #[test]
    fn test_validate_provider_type_invalid() {
        let result = SecretProviderService::validate_provider_type("vault");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid provider type"));
    }

    #[test]
    fn test_create_provider_request_serialization() {
        let request = CreateProviderRequest {
            provider_type: "openbao".to_string(),
            name: "production-openbao".to_string(),
            connection_settings: r#"{"addr":"https://openbao.example.com:8200"}"#.to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("openbao"));
        assert!(json.contains("production-openbao"));
    }

    #[test]
    fn test_provider_response_excludes_settings_by_default() {
        let config = SecretProviderConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider_type: "openbao".to_string(),
            name: "test".to_string(),
            connection_settings: "encrypted".to_string(),
            status: "active".to_string(),
            last_health_check: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let response = ProviderResponse::from_config(config, false);
        assert!(response.connection_settings.is_none());
    }
}
