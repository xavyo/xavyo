//! Identity Federation Service for Workload Identity Federation (F121).
//!
//! Orchestrates cloud credential requests by:
//! 1. Looking up the appropriate provider configuration
//! 2. Finding the matching role mapping for the agent
//! 3. Checking rate limits
//! 4. Requesting credentials from the cloud provider
//! 5. Recording audit events and metrics

use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use xavyo_db::models::{
    CloudProviderType, CreateIdentityCredentialRequest, IamRoleMapping, IdentityAuditOutcome,
    IdentityCredentialOutcome, IdentityCredentialRequest, IdentityProviderConfig,
};

use crate::error::ApiAgentsError;
use crate::providers::{
    AwsStsProvider, AzureFederatedProvider, CloudCredential, CloudIdentityProvider,
    CloudProviderError, CredentialRequest, GcpWorkloadProvider, KubernetesOidcProvider,
    ProviderConfig, TokenValidation,
};
use crate::services::{IdentityAuditService, IdentityProviderService, RoleMappingService};

/// Maximum credential requests per agent per provider per hour.
const DEFAULT_RATE_LIMIT: i32 = 100;

/// Service for orchestrating cloud identity federation.
pub struct IdentityFederationService {
    pool: PgPool,
    provider_service: IdentityProviderService,
    mapping_service: RoleMappingService,
    audit_service: IdentityAuditService,
    /// Cached cloud identity providers.
    providers: Arc<RwLock<HashMap<Uuid, Arc<dyn CloudIdentityProvider>>>>,
}

impl IdentityFederationService {
    /// Create a new identity federation service.
    #[must_use] 
    pub fn new(
        pool: PgPool,
        provider_service: IdentityProviderService,
        mapping_service: RoleMappingService,
        audit_service: IdentityAuditService,
    ) -> Self {
        Self {
            pool,
            provider_service,
            mapping_service,
            audit_service,
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Request cloud credentials for an agent.
    ///
    /// This is the main entry point for credential federation.
    #[instrument(skip(self, agent_jwt), fields(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        agent_type = %agent_type,
        provider_type = %provider_type
    ))]
    pub async fn request_credentials(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        agent_type: &str,
        provider_type: CloudProviderType,
        agent_jwt: &str,
        requested_ttl_seconds: i32,
    ) -> Result<CloudCredentialResponse, ApiAgentsError> {
        let start = Instant::now();

        // 1. Find an active provider of the requested type
        let provider_config = self.find_active_provider(tenant_id, provider_type).await?;

        // 2. Find the role mapping for this agent type
        let mapping = self
            .mapping_service
            .find_mapping_for_agent(tenant_id, provider_config.id, agent_type)
            .await?;

        // 3. Check rate limits
        self.check_rate_limit(tenant_id, agent_id, provider_config.id, DEFAULT_RATE_LIMIT)
            .await?;

        // 4. Calculate effective TTL
        let effective_ttl = self
            .mapping_service
            .get_effective_ttl(&mapping, requested_ttl_seconds);

        // 5. Get the cloud provider
        let cloud_provider = self.get_or_create_provider(&provider_config).await?;

        // 6. Build and execute the credential request
        let cred_request = CredentialRequest {
            tenant_id,
            agent_id,
            agent_type: agent_type.to_string(),
            agent_jwt: agent_jwt.to_string(),
            requested_ttl_seconds: effective_ttl,
            role_identifier: mapping.role_identifier.clone(),
            allowed_scopes: mapping.allowed_scopes.clone(),
            constraints: mapping.constraints.clone(),
        };

        let result = cloud_provider.get_credentials(&cred_request).await;
        let duration_ms = start.elapsed().as_millis() as i32;

        // 7. Record the request and audit event
        match result {
            Ok(credential) => {
                self.record_success(
                    tenant_id,
                    agent_id,
                    &provider_config,
                    &mapping,
                    requested_ttl_seconds,
                    effective_ttl,
                    duration_ms,
                )
                .await?;

                info!(
                    provider_id = %provider_config.id,
                    role = %mapping.role_identifier,
                    ttl = effective_ttl,
                    duration_ms = duration_ms,
                    "Cloud credentials issued successfully"
                );

                Ok(CloudCredentialResponse {
                    credential,
                    provider_config_id: provider_config.id,
                    role_mapping_id: mapping.id,
                    granted_ttl_seconds: effective_ttl,
                })
            }
            Err(e) => {
                self.record_failure(
                    tenant_id,
                    agent_id,
                    &provider_config,
                    Some(&mapping),
                    requested_ttl_seconds,
                    duration_ms,
                    &e,
                )
                .await?;

                error!(
                    provider_id = %provider_config.id,
                    error = %e,
                    duration_ms = duration_ms,
                    "Cloud credential request failed"
                );

                Err(self.map_provider_error(e))
            }
        }
    }

    /// Find an active provider of the specified type.
    async fn find_active_provider(
        &self,
        tenant_id: Uuid,
        provider_type: CloudProviderType,
    ) -> Result<IdentityProviderConfig, ApiAgentsError> {
        let providers = self
            .provider_service
            .get_active_by_type(tenant_id, provider_type)
            .await?;

        providers
            .into_iter()
            .next()
            .ok_or(ApiAgentsError::IdentityProviderNotFound)
    }

    /// Check if the agent has exceeded the rate limit.
    async fn check_rate_limit(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        provider_config_id: Uuid,
        max_requests: i32,
    ) -> Result<(), ApiAgentsError> {
        let count = IdentityCredentialRequest::count_recent_for_agent(
            &self.pool,
            tenant_id,
            agent_id,
            provider_config_id,
        )
        .await?;

        if count >= i64::from(max_requests) {
            warn!(
                agent_id = %agent_id,
                count = count,
                limit = max_requests,
                "Cloud credential rate limit exceeded"
            );
            return Err(ApiAgentsError::CloudCredentialRateLimited(
                count as i32,
                max_requests,
            ));
        }

        Ok(())
    }

    /// Get or create a cloud provider instance for a configuration.
    async fn get_or_create_provider(
        &self,
        config: &IdentityProviderConfig,
    ) -> Result<Arc<dyn CloudIdentityProvider>, ApiAgentsError> {
        // Check cache first
        {
            let providers = self.providers.read().await;
            if let Some(provider) = providers.get(&config.id) {
                return Ok(provider.clone());
            }
        }

        // Parse the provider configuration
        let provider_config: ProviderConfig = serde_json::from_str(&config.configuration)
            .map_err(|e| ApiAgentsError::InvalidProviderConfig(e.to_string()))?;

        // Create the provider
        let provider: Arc<dyn CloudIdentityProvider> = match provider_config {
            ProviderConfig::Aws(aws_config) => {
                let provider = AwsStsProvider::new(aws_config)
                    .await
                    .map_err(|e| ApiAgentsError::CloudProviderError(e.to_string()))?;
                Arc::new(provider)
            }
            ProviderConfig::Gcp(gcp_config) => {
                let provider = GcpWorkloadProvider::new(gcp_config)
                    .map_err(|e| ApiAgentsError::CloudProviderError(e.to_string()))?;
                Arc::new(provider)
            }
            ProviderConfig::Azure(azure_config) => {
                let provider = AzureFederatedProvider::new(azure_config)
                    .map_err(|e| ApiAgentsError::CloudProviderError(e.to_string()))?;
                Arc::new(provider)
            }
            ProviderConfig::Kubernetes(k8s_config) => {
                let provider = KubernetesOidcProvider::new(k8s_config)
                    .map_err(|e| ApiAgentsError::CloudProviderError(e.to_string()))?;
                Arc::new(provider)
            }
        };

        // Cache the provider
        {
            let mut providers = self.providers.write().await;
            providers.insert(config.id, provider.clone());
        }

        Ok(provider)
    }

    /// Record a successful credential request.
    #[allow(clippy::too_many_arguments)]
    async fn record_success(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        provider_config: &IdentityProviderConfig,
        mapping: &IamRoleMapping,
        requested_ttl: i32,
        granted_ttl: i32,
        duration_ms: i32,
    ) -> Result<(), ApiAgentsError> {
        // Record the credential request
        let request = CreateIdentityCredentialRequest {
            agent_id,
            provider_config_id: provider_config.id,
            role_mapping_id: Some(mapping.id),
            requested_ttl_seconds: requested_ttl,
            granted_ttl_seconds: Some(granted_ttl),
            outcome: IdentityCredentialOutcome::Success,
            error_code: None,
            error_message: None,
            duration_ms,
            source_ip: None, // Could be added from request context
        };

        IdentityCredentialRequest::create(&self.pool, tenant_id, &request).await?;

        // Audit log
        self.audit_service
            .log_credential_request(
                tenant_id,
                agent_id,
                &provider_config.provider_type,
                &mapping.role_identifier,
                IdentityAuditOutcome::Success,
                None,
            )
            .await?;

        Ok(())
    }

    /// Record a failed credential request.
    #[allow(clippy::too_many_arguments)]
    async fn record_failure(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        provider_config: &IdentityProviderConfig,
        mapping: Option<&IamRoleMapping>,
        requested_ttl: i32,
        duration_ms: i32,
        error: &CloudProviderError,
    ) -> Result<(), ApiAgentsError> {
        let (outcome, error_code) = match error {
            CloudProviderError::AuthenticationFailed(_) => {
                (IdentityCredentialOutcome::Denied, "AUTH_FAILED")
            }
            CloudProviderError::RoleNotAllowed(_) => {
                (IdentityCredentialOutcome::Denied, "ROLE_NOT_ALLOWED")
            }
            CloudProviderError::RateLimitExceeded => {
                (IdentityCredentialOutcome::RateLimited, "RATE_LIMITED")
            }
            _ => (IdentityCredentialOutcome::Error, "PROVIDER_ERROR"),
        };

        let request = CreateIdentityCredentialRequest {
            agent_id,
            provider_config_id: provider_config.id,
            role_mapping_id: mapping.map(|m| m.id),
            requested_ttl_seconds: requested_ttl,
            granted_ttl_seconds: None,
            outcome,
            error_code: Some(error_code.to_string()),
            error_message: Some(error.to_string()),
            duration_ms,
            source_ip: None,
        };

        IdentityCredentialRequest::create(&self.pool, tenant_id, &request).await?;

        // Audit log
        let role_identifier = mapping
            .map_or("unknown", |m| m.role_identifier.as_str());

        self.audit_service
            .log_credential_request(
                tenant_id,
                agent_id,
                &provider_config.provider_type,
                role_identifier,
                IdentityAuditOutcome::Failure,
                Some(&error.to_string()),
            )
            .await?;

        Ok(())
    }

    /// Map a cloud provider error to an API error.
    fn map_provider_error(&self, error: CloudProviderError) -> ApiAgentsError {
        match error {
            CloudProviderError::AuthenticationFailed(msg) => {
                ApiAgentsError::CloudCredentialDenied(format!("Authentication failed: {msg}"))
            }
            CloudProviderError::RoleNotAllowed(role) => {
                ApiAgentsError::CloudCredentialDenied(format!("Role not allowed: {role}"))
            }
            CloudProviderError::RateLimitExceeded => {
                ApiAgentsError::CloudCredentialRateLimited(0, 0)
            }
            CloudProviderError::NotAvailable(msg) => ApiAgentsError::IdentityProviderUnhealthy(msg),
            _ => ApiAgentsError::CloudProviderError(error.to_string()),
        }
    }

    /// Verify a token (for Kubernetes OIDC).
    #[instrument(skip(self, token), fields(tenant_id = %tenant_id, provider_type = %provider_type))]
    pub async fn verify_token(
        &self,
        tenant_id: Uuid,
        provider_type: CloudProviderType,
        token: &str,
    ) -> Result<TokenValidation, ApiAgentsError> {
        let provider_config = self.find_active_provider(tenant_id, provider_type).await?;
        let cloud_provider = self.get_or_create_provider(&provider_config).await?;

        let result = cloud_provider.validate_token(token).await;

        match result {
            Ok(validation) => {
                let outcome = if validation.valid {
                    IdentityAuditOutcome::Success
                } else {
                    IdentityAuditOutcome::Failure
                };

                self.audit_service
                    .log_token_verification(
                        tenant_id,
                        None,
                        &provider_config.provider_type,
                        outcome,
                        validation.subject.as_deref(),
                        validation.issuer.as_deref(),
                        validation.error.as_deref(),
                    )
                    .await?;

                Ok(validation)
            }
            Err(e) => {
                self.audit_service
                    .log_token_verification(
                        tenant_id,
                        None,
                        &provider_config.provider_type,
                        IdentityAuditOutcome::Failure,
                        None,
                        None,
                        Some(&e.to_string()),
                    )
                    .await?;

                Err(ApiAgentsError::CloudProviderError(e.to_string()))
            }
        }
    }

    /// Invalidate cached provider (e.g., after configuration update).
    pub async fn invalidate_provider_cache(&self, provider_id: Uuid) {
        let mut providers = self.providers.write().await;
        providers.remove(&provider_id);
    }

    /// Clear all cached providers.
    pub async fn clear_provider_cache(&self) {
        let mut providers = self.providers.write().await;
        providers.clear();
    }

    /// Check the health of a specific provider.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, provider_id = %provider_id))]
    pub async fn check_provider_health(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        // Get the provider configuration
        let provider_config = self
            .provider_service
            .get_provider(tenant_id, provider_id)
            .await?;

        // Get or create the cloud provider
        let cloud_provider = self.get_or_create_provider(&provider_config).await?;

        // Perform health check
        cloud_provider
            .health_check()
            .await
            .map_err(|e| ApiAgentsError::IdentityProviderUnhealthy(e.to_string()))
    }
}

/// Response from a cloud credential request.
#[derive(Debug, Clone)]
pub struct CloudCredentialResponse {
    /// The issued credential.
    pub credential: CloudCredential,
    /// The provider configuration that was used.
    pub provider_config_id: Uuid,
    /// The role mapping that was applied.
    pub role_mapping_id: Uuid,
    /// The TTL that was granted.
    pub granted_ttl_seconds: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to map provider errors without needing a service instance.
    // This mirrors the service method but is callable in pure unit tests.
    fn map_provider_error(error: CloudProviderError) -> ApiAgentsError {
        match error {
            CloudProviderError::AuthenticationFailed(msg) => {
                ApiAgentsError::CloudCredentialDenied(format!("Authentication failed: {}", msg))
            }
            CloudProviderError::RoleNotAllowed(role) => {
                ApiAgentsError::CloudCredentialDenied(format!("Role not allowed: {}", role))
            }
            CloudProviderError::RateLimitExceeded => {
                ApiAgentsError::CloudCredentialRateLimited(0, 0)
            }
            CloudProviderError::NotAvailable(msg) => ApiAgentsError::IdentityProviderUnhealthy(msg),
            _ => ApiAgentsError::CloudProviderError(error.to_string()),
        }
    }

    #[test]
    fn test_map_provider_error() {
        // Auth failure
        let auth_err = CloudProviderError::AuthenticationFailed("Invalid token".to_string());
        let mapped = map_provider_error(auth_err);
        assert!(matches!(mapped, ApiAgentsError::CloudCredentialDenied(_)));

        // Role not allowed
        let role_err = CloudProviderError::RoleNotAllowed("admin-role".to_string());
        let mapped = map_provider_error(role_err);
        assert!(matches!(mapped, ApiAgentsError::CloudCredentialDenied(_)));

        // Rate limited
        let rate_err = CloudProviderError::RateLimitExceeded;
        let mapped = map_provider_error(rate_err);
        assert!(matches!(
            mapped,
            ApiAgentsError::CloudCredentialRateLimited(_, _)
        ));

        // Not available
        let unavail_err = CloudProviderError::NotAvailable("AWS STS down".to_string());
        let mapped = map_provider_error(unavail_err);
        assert!(matches!(
            mapped,
            ApiAgentsError::IdentityProviderUnhealthy(_)
        ));

        // Generic error
        let generic_err = CloudProviderError::ProviderError("Unknown error".to_string());
        let mapped = map_provider_error(generic_err);
        assert!(matches!(mapped, ApiAgentsError::CloudProviderError(_)));
    }
}
