//! Ticketing Configuration Service for semi-manual resources (F064).
//!
//! Manages external ticketing system configurations (`ServiceNow`, Jira, webhooks).

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::{
    CreateTicketingConfiguration, GovTicketingConfiguration, TicketingConfigFilter,
    UpdateTicketingConfiguration,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateTicketingConfigurationRequest, ListTicketingConfigurationsQuery,
    TicketingConfigurationListResponse, TicketingConfigurationResponse,
    UpdateTicketingConfigurationRequest,
};
use crate::services::ticketing::{create_provider, decrypt_credentials, encrypt_credentials};

/// Service for managing ticketing configurations.
pub struct TicketingConfigService {
    pool: PgPool,
}

impl TicketingConfigService {
    /// Create a new ticketing configuration service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List ticketing configurations with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListTicketingConfigurationsQuery,
    ) -> Result<TicketingConfigurationListResponse> {
        let filter = TicketingConfigFilter {
            ticketing_type: query.ticketing_type,
            is_active: query.is_active,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let configs = GovTicketingConfiguration::list_by_tenant(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;

        let total =
            GovTicketingConfiguration::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(TicketingConfigurationListResponse {
            items: configs
                .into_iter()
                .map(TicketingConfigurationResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a ticketing configuration by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<TicketingConfigurationResponse> {
        let config = GovTicketingConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::TicketingConfigurationNotFound(id))?;

        Ok(TicketingConfigurationResponse::from(config))
    }

    /// Create a new ticketing configuration.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateTicketingConfigurationRequest,
    ) -> Result<TicketingConfigurationResponse> {
        // Parse and encrypt credentials
        let credentials_json: serde_json::Value = serde_json::from_str(&request.credentials)
            .map_err(|e| GovernanceError::Validation(format!("Invalid credentials JSON: {e}")))?;

        let encrypted_credentials = encrypt_credentials(&credentials_json).map_err(|e| {
            GovernanceError::Validation(format!("Failed to encrypt credentials: {e}"))
        })?;

        let input = CreateTicketingConfiguration {
            name: request.name,
            ticketing_type: request.ticketing_type,
            endpoint_url: request.endpoint_url,
            credentials: encrypted_credentials.into_bytes(),
            field_mappings: request.field_mappings,
            default_assignee: request.default_assignee,
            default_assignment_group: request.default_assignment_group,
            project_key: request.project_key,
            issue_type: request.issue_type,
            polling_interval_seconds: Some(request.polling_interval_seconds),
            webhook_callback_secret: None,
            status_field_mapping: None,
        };

        let config = GovTicketingConfiguration::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            config_id = %config.id,
            ticketing_type = %config.ticketing_type,
            "Ticketing configuration created"
        );

        Ok(TicketingConfigurationResponse::from(config))
    }

    /// Update a ticketing configuration.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: UpdateTicketingConfigurationRequest,
    ) -> Result<TicketingConfigurationResponse> {
        // Encrypt credentials if provided
        let encrypted_credentials = match request.credentials {
            Some(ref creds) => {
                let credentials_json: serde_json::Value =
                    serde_json::from_str(creds).map_err(|e| {
                        GovernanceError::Validation(format!("Invalid credentials JSON: {e}"))
                    })?;

                let encrypted = encrypt_credentials(&credentials_json).map_err(|e| {
                    GovernanceError::Validation(format!("Failed to encrypt credentials: {e}"))
                })?;

                Some(encrypted.into_bytes())
            }
            None => None,
        };

        let input = UpdateTicketingConfiguration {
            name: request.name,
            endpoint_url: request.endpoint_url,
            credentials: encrypted_credentials,
            field_mappings: request.field_mappings,
            default_assignee: request.default_assignee,
            default_assignment_group: request.default_assignment_group,
            project_key: request.project_key,
            issue_type: request.issue_type,
            polling_interval_seconds: request.polling_interval_seconds,
            webhook_callback_secret: None,
            status_field_mapping: None,
            is_active: request.is_active,
        };

        let config = GovTicketingConfiguration::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::TicketingConfigurationNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            config_id = %id,
            "Ticketing configuration updated"
        );

        Ok(TicketingConfigurationResponse::from(config))
    }

    /// Delete a ticketing configuration.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        // Check if configuration is in use
        let in_use = GovTicketingConfiguration::is_in_use(&self.pool, tenant_id, id).await?;

        if in_use {
            return Err(GovernanceError::TicketingConfigurationInUse(id));
        }

        let deleted = GovTicketingConfiguration::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(GovernanceError::TicketingConfigurationNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            config_id = %id,
            "Ticketing configuration deleted"
        );

        Ok(())
    }

    /// Test connectivity to a ticketing configuration.
    pub async fn test_connectivity(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<ConnectivityTestResult> {
        let config = GovTicketingConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::TicketingConfigurationNotFound(id))?;

        let start = std::time::Instant::now();

        // Decrypt credentials
        let credentials_encrypted = String::from_utf8(config.credentials.clone())
            .map_err(|_| GovernanceError::Validation("Invalid credentials encoding".to_string()))?;

        let credentials = decrypt_credentials(&credentials_encrypted).map_err(|e| {
            GovernanceError::Validation(format!("Failed to decrypt credentials: {e}"))
        })?;

        // Create provider and test connectivity
        let result = match create_provider(&config, &credentials) {
            Ok(provider) => match provider.test_connectivity().await {
                Ok(response) => {
                    let elapsed_ms = start.elapsed().as_millis() as i64;
                    if response.success {
                        ConnectivityTestResult {
                            success: true,
                            message: Some("Connection successful".to_string()),
                            response_time_ms: Some(elapsed_ms),
                            error: None,
                            details: response.details,
                        }
                    } else {
                        ConnectivityTestResult {
                            success: false,
                            message: None,
                            response_time_ms: Some(elapsed_ms),
                            error: response.error_message,
                            details: response.details,
                        }
                    }
                }
                Err(e) => ConnectivityTestResult {
                    success: false,
                    message: None,
                    response_time_ms: Some(start.elapsed().as_millis() as i64),
                    error: Some(e.to_string()),
                    details: None,
                },
            },
            Err(e) => ConnectivityTestResult {
                success: false,
                message: None,
                response_time_ms: None,
                error: Some(e.to_string()),
                details: None,
            },
        };

        Ok(result)
    }

    /// Get a provider for a ticketing configuration (for use by other services).
    pub async fn get_provider(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Box<dyn crate::services::ticketing::TicketingProvider>> {
        let config = GovTicketingConfiguration::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::TicketingConfigurationNotFound(id))?;

        if !config.is_active {
            return Err(GovernanceError::Validation(
                "Ticketing configuration is not active".to_string(),
            ));
        }

        // Decrypt credentials
        let credentials_encrypted = String::from_utf8(config.credentials.clone())
            .map_err(|_| GovernanceError::Validation("Invalid credentials encoding".to_string()))?;

        let credentials = decrypt_credentials(&credentials_encrypted).map_err(|e| {
            GovernanceError::Validation(format!("Failed to decrypt credentials: {e}"))
        })?;

        create_provider(&config, &credentials)
            .map_err(|e| GovernanceError::Validation(format!("Failed to create provider: {e}")))
    }
}

/// Result of a connectivity test.
#[derive(Debug, Clone)]
pub struct ConnectivityTestResult {
    pub success: bool,
    pub message: Option<String>,
    pub response_time_ms: Option<i64>,
    pub error: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connectivity_test_result() {
        let result = ConnectivityTestResult {
            success: true,
            message: Some("OK".to_string()),
            response_time_ms: Some(150),
            error: None,
            details: None,
        };

        assert!(result.success);
        assert_eq!(result.response_time_ms, Some(150));
    }
}
