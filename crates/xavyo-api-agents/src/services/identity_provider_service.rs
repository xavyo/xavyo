//! Identity Provider Service for Workload Identity Federation (F121).
//!
//! Manages cloud identity provider configurations for each tenant.

use sqlx::PgPool;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use xavyo_db::models::{
    CreateIdentityProviderConfig, IdentityProviderConfig, IdentityProviderConfigFilter,
    IdpHealthStatus, UpdateIdentityProviderConfig,
};

use crate::error::ApiAgentsError;
use crate::providers::ProviderConfig;
use crate::services::{IdentityAuditService, ProviderOperation};

/// Service for managing identity provider configurations.
#[derive(Clone)]
pub struct IdentityProviderService {
    pool: PgPool,
    audit_service: IdentityAuditService,
}

impl IdentityProviderService {
    /// Create a new identity provider service.
    #[must_use]
    pub fn new(pool: PgPool, audit_service: IdentityAuditService) -> Self {
        Self {
            pool,
            audit_service,
        }
    }

    /// Create a new identity provider configuration.
    #[instrument(skip(self, encrypted_config), fields(tenant_id = %tenant_id, user_id = %user_id))]
    pub async fn create_provider(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &CreateIdentityProviderConfig,
        encrypted_config: &str,
    ) -> Result<IdentityProviderConfig, ApiAgentsError> {
        // Validate unique name per tenant (T042)
        if IdentityProviderConfig::exists_by_name(&self.pool, tenant_id, &request.name, None)
            .await?
        {
            return Err(ApiAgentsError::DuplicateProviderName(request.name.clone()));
        }

        // Create the request with encrypted configuration
        let create_request = CreateIdentityProviderConfig {
            provider_type: request.provider_type,
            name: request.name.clone(),
            configuration: encrypted_config.to_string(),
            is_active: request.is_active,
        };

        let provider =
            IdentityProviderConfig::create(&self.pool, tenant_id, &create_request).await?;

        info!(
            provider_id = %provider.id,
            provider_type = %provider.provider_type,
            name = %provider.name,
            "Created identity provider"
        );

        // Audit log the creation
        self.audit_service
            .log_provider_change(
                tenant_id,
                user_id,
                provider.id,
                &provider.provider_type,
                ProviderOperation::Create,
                &provider.name,
            )
            .await?;

        Ok(provider)
    }

    /// Get an identity provider by ID.
    pub async fn get_provider(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<IdentityProviderConfig, ApiAgentsError> {
        IdentityProviderConfig::get_by_id(&self.pool, tenant_id, provider_id)
            .await?
            .ok_or(ApiAgentsError::IdentityProviderNotFound)
    }

    /// List identity providers for a tenant.
    pub async fn list_providers(
        &self,
        tenant_id: Uuid,
        filter: &IdentityProviderConfigFilter,
    ) -> Result<Vec<IdentityProviderConfig>, ApiAgentsError> {
        let providers = IdentityProviderConfig::list(&self.pool, tenant_id, filter).await?;
        Ok(providers)
    }

    /// Update an identity provider configuration.
    #[instrument(skip(self, encrypted_config), fields(tenant_id = %tenant_id, user_id = %user_id, provider_id = %provider_id))]
    pub async fn update_provider(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_id: Uuid,
        request: &UpdateIdentityProviderConfig,
        encrypted_config: Option<&str>,
    ) -> Result<IdentityProviderConfig, ApiAgentsError> {
        // Verify provider exists
        let existing = self.get_provider(tenant_id, provider_id).await?;

        // Validate unique name per tenant if name is being changed (T042)
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name
                && IdentityProviderConfig::exists_by_name(
                    &self.pool,
                    tenant_id,
                    new_name,
                    Some(provider_id),
                )
                .await?
            {
                return Err(ApiAgentsError::DuplicateProviderName(new_name.clone()));
            }
        }

        // Build update request
        let update_request = UpdateIdentityProviderConfig {
            name: request.name.clone(),
            configuration: encrypted_config.map(std::string::ToString::to_string),
            is_active: request.is_active,
        };

        let provider =
            IdentityProviderConfig::update(&self.pool, tenant_id, provider_id, &update_request)
                .await?
                .ok_or(ApiAgentsError::IdentityProviderNotFound)?;

        info!(
            provider_id = %provider.id,
            name = %provider.name,
            is_active = provider.is_active,
            "Updated identity provider"
        );

        // Audit log the update
        self.audit_service
            .log_provider_change(
                tenant_id,
                user_id,
                provider_id,
                &existing.provider_type,
                ProviderOperation::Update,
                &provider.name,
            )
            .await?;

        Ok(provider)
    }

    /// Delete an identity provider configuration.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, provider_id = %provider_id))]
    pub async fn delete_provider(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        // Get provider info for audit log
        let provider = self.get_provider(tenant_id, provider_id).await?;

        let deleted = IdentityProviderConfig::delete(&self.pool, tenant_id, provider_id).await?;

        if !deleted {
            return Err(ApiAgentsError::IdentityProviderNotFound);
        }

        info!(provider_id = %provider_id, "Deleted identity provider");

        // Audit log the deletion
        self.audit_service
            .log_provider_change(
                tenant_id,
                user_id,
                provider_id,
                &provider.provider_type,
                ProviderOperation::Delete,
                &provider.name,
            )
            .await?;

        Ok(())
    }

    /// Delete an identity provider with cascade to role mappings (T044).
    ///
    /// When cascade is true, deletes all associated role mappings first,
    /// then deletes the provider. When false, behaves like regular delete
    /// (fails if mappings exist).
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, provider_id = %provider_id, cascade = %cascade))]
    pub async fn delete_provider_with_cascade(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_id: Uuid,
        cascade: bool,
    ) -> Result<u64, ApiAgentsError> {
        use xavyo_db::models::IamRoleMapping;

        // Get provider info for audit log
        let provider = self.get_provider(tenant_id, provider_id).await?;

        // Check if there are mappings
        let mapping_count =
            IamRoleMapping::count_by_provider(&self.pool, tenant_id, provider_id).await?;

        if mapping_count > 0 {
            if !cascade {
                return Err(ApiAgentsError::IdentityProviderHasRoleMappings(provider_id));
            }

            // Delete all role mappings first
            let deleted_mappings =
                IamRoleMapping::delete_by_provider(&self.pool, tenant_id, provider_id).await?;

            info!(
                provider_id = %provider_id,
                deleted_mappings = deleted_mappings,
                "Cascade deleted role mappings"
            );

            // Audit log the cascade deletion of mappings
            self.audit_service
                .log_cascade_delete(
                    tenant_id,
                    user_id,
                    provider_id,
                    &provider.provider_type,
                    deleted_mappings,
                )
                .await?;
        }

        // Now delete the provider
        let deleted = IdentityProviderConfig::delete(&self.pool, tenant_id, provider_id).await?;

        if !deleted {
            return Err(ApiAgentsError::IdentityProviderNotFound);
        }

        info!(provider_id = %provider_id, "Deleted identity provider");

        // Audit log the deletion
        self.audit_service
            .log_provider_change(
                tenant_id,
                user_id,
                provider_id,
                &provider.provider_type,
                ProviderOperation::Delete,
                &provider.name,
            )
            .await?;

        Ok(mapping_count as u64)
    }

    /// Update provider health status after a health check.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, provider_id = %provider_id))]
    pub async fn update_health_status(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        status: IdpHealthStatus,
        latency_ms: Option<i32>,
        error_message: Option<&str>,
    ) -> Result<(), ApiAgentsError> {
        let provider = self.get_provider(tenant_id, provider_id).await?;

        IdentityProviderConfig::update_health(&self.pool, tenant_id, provider_id, status).await?;

        let outcome = match status {
            IdpHealthStatus::Healthy => xavyo_db::models::IdentityAuditOutcome::Success,
            _ => xavyo_db::models::IdentityAuditOutcome::Failure,
        };

        // Audit log the health check
        self.audit_service
            .log_health_check(
                tenant_id,
                provider_id,
                &provider.provider_type,
                outcome,
                latency_ms,
                error_message,
            )
            .await?;

        if status != IdpHealthStatus::Healthy {
            warn!(
                provider_id = %provider_id,
                status = ?status,
                error = ?error_message,
                "Provider health check failed"
            );
        }

        Ok(())
    }

    /// Get all active providers of a specific type.
    pub async fn get_active_by_type(
        &self,
        tenant_id: Uuid,
        provider_type: xavyo_db::models::CloudProviderType,
    ) -> Result<Vec<IdentityProviderConfig>, ApiAgentsError> {
        let providers =
            IdentityProviderConfig::get_active_by_type(&self.pool, tenant_id, provider_type)
                .await?;
        Ok(providers)
    }

    /// Parse and validate provider configuration JSON.
    pub fn parse_provider_config(&self, json: &str) -> Result<ProviderConfig, ApiAgentsError> {
        serde_json::from_str(json).map_err(|e| {
            ApiAgentsError::InvalidProviderConfig(format!("Invalid configuration JSON: {e}"))
        })
    }

    /// Validate that a provider configuration is well-formed.
    pub fn validate_provider_config(&self, config: &ProviderConfig) -> Result<(), ApiAgentsError> {
        match config {
            ProviderConfig::Aws(aws) => {
                if aws.region.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "AWS region is required".to_string(),
                    ));
                }
                if aws.oidc_provider_arn.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "AWS OIDC provider ARN is required".to_string(),
                    ));
                }
                if !aws.oidc_provider_arn.starts_with("arn:aws:iam::") {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Invalid AWS OIDC provider ARN format".to_string(),
                    ));
                }
            }
            ProviderConfig::Gcp(gcp) => {
                if gcp.project_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP project ID is required".to_string(),
                    ));
                }
                if gcp.workload_identity_pool_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP workload identity pool ID is required".to_string(),
                    ));
                }
                if gcp.service_account_email.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP service account email is required".to_string(),
                    ));
                }
            }
            ProviderConfig::Azure(azure) => {
                if azure.tenant_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Azure tenant ID is required".to_string(),
                    ));
                }
                if azure.client_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Azure client ID is required".to_string(),
                    ));
                }
            }
            ProviderConfig::Kubernetes(k8s) => {
                if k8s.api_server_url.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Kubernetes API server URL is required".to_string(),
                    ));
                }
                if k8s.jwks_url.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Kubernetes JWKS URL is required".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{AwsStsConfig, GcpWorkloadIdentityConfig};

    // Helper function to validate provider config without needing a service instance.
    // This mirrors the service method but is callable in pure unit tests.
    fn validate_provider_config(config: &ProviderConfig) -> Result<(), ApiAgentsError> {
        match config {
            ProviderConfig::Aws(aws) => {
                if aws.region.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "AWS region is required".to_string(),
                    ));
                }
                if aws.oidc_provider_arn.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "AWS OIDC provider ARN is required".to_string(),
                    ));
                }
                if !aws.oidc_provider_arn.starts_with("arn:aws:iam::") {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Invalid AWS OIDC provider ARN format".to_string(),
                    ));
                }
            }
            ProviderConfig::Gcp(gcp) => {
                if gcp.project_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP project ID is required".to_string(),
                    ));
                }
                if gcp.workload_identity_pool_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP workload identity pool ID is required".to_string(),
                    ));
                }
                if gcp.service_account_email.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "GCP service account email is required".to_string(),
                    ));
                }
            }
            ProviderConfig::Azure(azure) => {
                if azure.tenant_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Azure tenant ID is required".to_string(),
                    ));
                }
                if azure.client_id.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Azure client ID is required".to_string(),
                    ));
                }
            }
            ProviderConfig::Kubernetes(k8s) => {
                if k8s.api_server_url.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Kubernetes API server URL is required".to_string(),
                    ));
                }
                if k8s.jwks_url.is_empty() {
                    return Err(ApiAgentsError::InvalidProviderConfig(
                        "Kubernetes JWKS URL is required".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_validate_aws_config() {
        // Valid AWS config
        let valid_config = ProviderConfig::Aws(AwsStsConfig {
            region: "us-east-1".to_string(),
            oidc_provider_arn: "arn:aws:iam::123456789012:oidc-provider/xavyo.net".to_string(),
            session_name_prefix: "xavyo-agent".to_string(),
            external_id: None,
            max_duration_seconds: 3600,
        });
        assert!(validate_provider_config(&valid_config).is_ok());

        // Invalid - empty region
        let invalid_region = ProviderConfig::Aws(AwsStsConfig {
            region: "".to_string(),
            oidc_provider_arn: "arn:aws:iam::123456789012:oidc-provider/xavyo.net".to_string(),
            session_name_prefix: "xavyo-agent".to_string(),
            external_id: None,
            max_duration_seconds: 3600,
        });
        assert!(validate_provider_config(&invalid_region).is_err());

        // Invalid - bad ARN format
        let invalid_arn = ProviderConfig::Aws(AwsStsConfig {
            region: "us-east-1".to_string(),
            oidc_provider_arn: "not-an-arn".to_string(),
            session_name_prefix: "xavyo-agent".to_string(),
            external_id: None,
            max_duration_seconds: 3600,
        });
        assert!(validate_provider_config(&invalid_arn).is_err());
    }

    #[test]
    fn test_validate_gcp_config() {
        // Valid GCP config
        let valid_config = ProviderConfig::Gcp(GcpWorkloadIdentityConfig {
            project_id: "my-project".to_string(),
            workload_identity_pool_id: "my-pool".to_string(),
            workload_identity_provider_id: "my-provider".to_string(),
            audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider".to_string(),
            service_account_email: "sa@my-project.iam.gserviceaccount.com".to_string(),
        });
        assert!(validate_provider_config(&valid_config).is_ok());

        // Invalid - empty project ID
        let invalid_project = ProviderConfig::Gcp(GcpWorkloadIdentityConfig {
            project_id: "".to_string(),
            workload_identity_pool_id: "my-pool".to_string(),
            workload_identity_provider_id: "my-provider".to_string(),
            audience: "test".to_string(),
            service_account_email: "sa@my-project.iam.gserviceaccount.com".to_string(),
        });
        assert!(validate_provider_config(&invalid_project).is_err());
    }
}
