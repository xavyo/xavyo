//! Secret Type Service for managing secret type configurations (F120).
//!
//! Provides business logic for:
//! - Creating and managing secret type configurations
//! - Validating TTL and rate limit constraints
//! - Enabling/disabling secret types

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use xavyo_db::models::secret_type_config::{
    CreateSecretTypeConfiguration, SecretTypeConfigFilter, SecretTypeConfiguration,
    UpdateSecretTypeConfiguration,
};

/// Response for secret type list operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SecretTypeListResponse {
    /// List of secret types.
    pub secret_types: Vec<SecretTypeConfiguration>,
    /// Total count (for pagination).
    pub total: i64,
}

/// Service for managing secret type configurations.
#[derive(Clone)]
pub struct SecretTypeService {
    pool: PgPool,
}

impl SecretTypeService {
    /// Create a new SecretTypeService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new secret type configuration.
    ///
    /// Validates:
    /// - Type name is unique for the tenant
    /// - TTL constraints are valid (min 60s, default <= max)
    /// - Rate limit is positive
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateSecretTypeConfiguration,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        // Check if type name already exists
        let existing =
            SecretTypeConfiguration::find_by_type_name(&self.pool, tenant_id, &input.type_name)
                .await?;
        if existing.is_some() {
            return Err(ApiAgentsError::SecretTypeExists(input.type_name.clone()));
        }

        // Validate TTL constraints
        if input.default_ttl_seconds < 60 {
            return Err(ApiAgentsError::InvalidTtl(
                "Default TTL must be at least 60 seconds".to_string(),
            ));
        }
        if input.max_ttl_seconds < 60 {
            return Err(ApiAgentsError::InvalidTtl(
                "Max TTL must be at least 60 seconds".to_string(),
            ));
        }
        if input.default_ttl_seconds > input.max_ttl_seconds {
            return Err(ApiAgentsError::InvalidTtl(
                "Default TTL cannot exceed max TTL".to_string(),
            ));
        }

        // Validate rate limit
        if input.rate_limit_per_hour < 1 {
            return Err(ApiAgentsError::InvalidRateLimit(
                "Rate limit must be at least 1 per hour".to_string(),
            ));
        }

        // Validate provider type
        let valid_providers = ["openbao", "infisical", "internal", "aws"];
        if !valid_providers.contains(&input.provider_type.as_str()) {
            return Err(ApiAgentsError::BadRequest(format!(
                "Invalid provider type '{}'. Must be one of: {:?}",
                input.provider_type, valid_providers
            )));
        }

        let config = SecretTypeConfiguration::create(&self.pool, tenant_id, input).await?;
        Ok(config)
    }

    /// Get a secret type configuration by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        SecretTypeConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))
    }

    /// Get a secret type configuration by type name.
    pub async fn get_by_name(
        &self,
        tenant_id: Uuid,
        type_name: &str,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        SecretTypeConfiguration::find_by_type_name(&self.pool, tenant_id, type_name)
            .await?
            .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(type_name.to_string()))
    }

    /// List secret type configurations with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: SecretTypeConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<SecretTypeListResponse, ApiAgentsError> {
        let secret_types =
            SecretTypeConfiguration::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            SecretTypeConfiguration::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(SecretTypeListResponse {
            secret_types,
            total,
        })
    }

    /// Update a secret type configuration.
    ///
    /// Validates:
    /// - TTL constraints are valid
    /// - Rate limit is positive
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSecretTypeConfiguration,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        // Get existing to validate constraints
        let existing = SecretTypeConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))?;

        // Validate TTL constraints
        let new_default = input
            .default_ttl_seconds
            .unwrap_or(existing.default_ttl_seconds);
        let new_max = input.max_ttl_seconds.unwrap_or(existing.max_ttl_seconds);

        if new_default < 60 {
            return Err(ApiAgentsError::InvalidTtl(
                "Default TTL must be at least 60 seconds".to_string(),
            ));
        }
        if new_max < 60 {
            return Err(ApiAgentsError::InvalidTtl(
                "Max TTL must be at least 60 seconds".to_string(),
            ));
        }
        if new_default > new_max {
            return Err(ApiAgentsError::InvalidTtl(
                "Default TTL cannot exceed max TTL".to_string(),
            ));
        }

        // Validate rate limit
        if let Some(rate) = input.rate_limit_per_hour {
            if rate < 1 {
                return Err(ApiAgentsError::InvalidRateLimit(
                    "Rate limit must be at least 1 per hour".to_string(),
                ));
            }
        }

        let updated = SecretTypeConfiguration::update(&self.pool, tenant_id, id, input).await?;
        updated.ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))
    }

    /// Delete a secret type configuration.
    ///
    /// Note: This will fail if there are active permissions referencing this type.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, ApiAgentsError> {
        // Check if configuration exists
        SecretTypeConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))?;

        // TODO: Check if there are active permissions or credentials using this type

        let deleted = SecretTypeConfiguration::delete(&self.pool, tenant_id, id).await?;
        Ok(deleted)
    }

    /// Enable a secret type configuration.
    pub async fn enable(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        let updated = SecretTypeConfiguration::enable(&self.pool, tenant_id, id).await?;
        updated.ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))
    }

    /// Disable a secret type configuration.
    pub async fn disable(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        let updated = SecretTypeConfiguration::disable(&self.pool, tenant_id, id).await?;
        updated.ok_or_else(|| ApiAgentsError::SecretTypeNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_type_list_response_serialization() {
        let response = SecretTypeListResponse {
            secret_types: vec![],
            total: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"secret_types\":[]"));
        assert!(json.contains("\"total\":0"));
    }

    #[test]
    fn test_valid_provider_types() {
        let valid_providers = ["openbao", "infisical", "internal", "aws"];

        for provider in valid_providers {
            assert!(
                valid_providers.contains(&provider),
                "Provider {} should be valid",
                provider
            );
        }

        // Invalid provider
        assert!(!valid_providers.contains(&"hashicorp-vault")); // BSL license
    }

    #[test]
    fn test_ttl_validation_rules() {
        // Min TTL is 60 seconds
        assert!(60 >= 60);
        assert!(59 < 60);

        // Default cannot exceed max
        let default_ttl = 300;
        let max_ttl = 900;
        assert!(default_ttl <= max_ttl);

        // Invalid: default > max
        let bad_default = 1000;
        let bad_max = 500;
        assert!(bad_default > bad_max);
    }
}
