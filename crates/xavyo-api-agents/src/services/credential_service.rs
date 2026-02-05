//! Dynamic Credential Service for `SecretlessAI` (F120).
//!
//! Provides just-in-time credential generation with:
//! - Permission checking against `agent_secret_permissions`
//! - Rate limiting using `DashMap` (same pattern as `authorization_service`)
//! - Audit logging for every request
//! - TTL validation against secret type configuration
//! - Kafka event emission for credential lifecycle events
//! - Real provider integration (`OpenBao`, Infisical, AWS, internal)

use chrono::{Duration, Timelike, Utc};
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{CredentialRequest, CredentialResponse, RateLimitInfo};
use crate::services::encryption::{encrypt_credential_value, EncryptionService};
use crate::services::provider_registry::ProviderRegistry;
use xavyo_db::models::{
    agent_secret_permission::AgentSecretPermission,
    ai_agent::AiAgent,
    credential_request_audit::{
        CreateCredentialRequestAudit, CredentialErrorCode, CredentialRequestAudit,
        CredentialRequestOutcome,
    },
    dynamic_credential::{CreateDynamicCredential, DynamicCredential, DynamicCredentialFilter},
    secret_provider_config::SecretProviderConfig,
    secret_type_config::SecretTypeConfiguration,
};

#[cfg(feature = "kafka")]
use xavyo_events::{
    events::credentials::{
        CredentialDenialReason, CredentialDenied, CredentialIssued, CredentialRateLimited,
        CredentialRequested, CredentialRevoked,
    },
    EventProducer,
};

/// Rate limit tracking entry for credential requests.
#[derive(Debug, Clone)]
struct CredentialRateLimitEntry {
    /// Number of requests in the current hour window.
    count: i32,
    /// Start of the current hour window.
    window_start: chrono::DateTime<Utc>,
}

/// Service for dynamic credential provisioning.
#[derive(Clone)]
pub struct DynamicCredentialService {
    pool: PgPool,
    /// Provider registry for real secret provider integration.
    provider_registry: Arc<ProviderRegistry>,
    /// In-memory rate limit tracking: (`tenant_id`, `agent_id`, `secret_type`) -> `RateLimitEntry`
    rate_limits: Arc<DashMap<(Uuid, Uuid, String), CredentialRateLimitEntry>>,
    /// Kafka event producer for credential lifecycle events.
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl DynamicCredentialService {
    /// Create a new `DynamicCredentialService` with provider registry.
    #[must_use]
    pub fn new(pool: PgPool, encryption_service: Arc<EncryptionService>) -> Self {
        let provider_registry = Arc::new(ProviderRegistry::new(pool.clone(), encryption_service));
        Self {
            pool,
            provider_registry,
            rate_limits: Arc::new(DashMap::new()),
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create with an existing provider registry (for testing or shared registry).
    pub fn with_registry(pool: PgPool, registry: Arc<ProviderRegistry>) -> Self {
        Self {
            pool,
            provider_registry: registry,
            rate_limits: Arc::new(DashMap::new()),
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Set the event producer for Kafka integration.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    /// Create a new credential service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(
        pool: PgPool,
        encryption_service: Arc<EncryptionService>,
        producer: Arc<EventProducer>,
    ) -> Self {
        let provider_registry = Arc::new(ProviderRegistry::new(pool.clone(), encryption_service));
        Self {
            pool,
            provider_registry,
            rate_limits: Arc::new(DashMap::new()),
            event_producer: Some(producer),
        }
    }

    /// Request ephemeral credentials for an agent.
    ///
    /// This is the main entry point for credential requests.
    /// It validates the agent, checks permissions, enforces rate limits,
    /// and generates credentials.
    pub async fn request_credential(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request: CredentialRequest,
        source_ip: Option<&str>,
    ) -> Result<(CredentialResponse, RateLimitInfo), ApiAgentsError> {
        let _request_id = Uuid::new_v4();
        let now = Utc::now();

        // 0. Emit Kafka event for credential request
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let requested_event = CredentialRequested {
                tenant_id,
                agent_id,
                secret_type: request.secret_type.clone(),
                requested_ttl_seconds: request.ttl_seconds,
                conversation_id: request.context.conversation_id.map(|id| id.to_string()),
                session_id: request.context.session_id.map(|id| id.to_string()),
                source_ip: source_ip.map(|s| s.to_string()),
                timestamp: now,
            };
            if let Err(e) = producer.publish(requested_event, tenant_id, None).await {
                tracing::warn!("Failed to emit CredentialRequested event: {}", e);
            }
        }

        // 1. Validate agent exists and is active
        let _agent = self.validate_agent(tenant_id, agent_id).await?;

        // 2. Get secret type configuration
        let secret_config = self
            .get_secret_type_config(tenant_id, &request.secret_type)
            .await?;

        // 3. Check agent has permission for this secret type
        let permission = self
            .check_permission(tenant_id, agent_id, &request.secret_type)
            .await?;

        // 4. Check rate limit
        let rate_limit = self.get_effective_rate_limit(&secret_config, &permission);
        let (remaining, reset_at) = self.check_and_update_rate_limit(
            tenant_id,
            agent_id,
            &request.secret_type,
            rate_limit,
        )?;

        // 5. Calculate effective TTL
        let effective_ttl =
            self.calculate_effective_ttl(request.ttl_seconds, &secret_config, &permission)?;

        // 5b. Load provider config (if not internal)
        let provider_config = self
            .get_provider_config(tenant_id, &secret_config.provider_type)
            .await?;

        // 6. Generate credentials using real provider
        let dynamic_cred = self
            .provider_registry
            .generate_credentials(
                tenant_id,
                agent_id,
                &secret_config.type_name,
                effective_ttl,
                &secret_config.provider_type,
                provider_config.as_ref(),
                secret_config.provider_path.clone(),
            )
            .await?;

        let credentials = dynamic_cred.credentials;
        let provider_lease_id = dynamic_cred.lease_id;

        // 7. Encrypt credential value for storage
        let encrypted_value =
            encrypt_credential_value(&serde_json::to_string(&credentials).map_err(|e| {
                ApiAgentsError::Internal(format!("JSON serialization failed: {e}"))
            })?)
            .map_err(|e| ApiAgentsError::EncryptionError(e.to_string()))?;

        // 8. Store the dynamic credential
        let expires_at = now + Duration::seconds(i64::from(effective_ttl));
        let create_input = CreateDynamicCredential {
            agent_id,
            secret_type: request.secret_type.clone(),
            credential_value: encrypted_value,
            ttl_seconds: effective_ttl,
            provider_type: secret_config.provider_type.clone(),
            provider_lease_id: provider_lease_id.clone(),
        };
        let credential = DynamicCredential::create(&self.pool, tenant_id, create_input).await?;

        // 9. Create audit log entry
        let audit_context = serde_json::json!({
            "conversation_id": request.context.conversation_id,
            "session_id": request.context.session_id,
            "user_instruction": request.context.user_instruction,
            "credential_id": credential.id,
            "requested_ttl": request.ttl_seconds,
        });
        let audit_entry = CreateCredentialRequestAudit {
            agent_id,
            secret_type: request.secret_type.clone(),
            outcome: CredentialRequestOutcome::Success,
            ttl_granted: Some(effective_ttl),
            error_code: None,
            source_ip: source_ip.map(std::string::ToString::to_string),
            user_agent: None,
            latency_ms: 0.0, // TODO: measure actual latency
            context: Some(audit_context),
        };
        let _ = CredentialRequestAudit::insert(&self.pool, tenant_id, audit_entry).await;

        // 9b. Emit Kafka event for credential issuance
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let issued_event = CredentialIssued {
                tenant_id,
                agent_id,
                credential_id: credential.id,
                secret_type: request.secret_type.clone(),
                provider_type: secret_config.provider_type.clone(),
                ttl_seconds: effective_ttl,
                expires_at,
                timestamp: now,
            };
            if let Err(e) = producer.publish(issued_event, tenant_id, None).await {
                tracing::warn!("Failed to emit CredentialIssued event: {}", e);
            }
        }

        // 10. Build response
        let response = CredentialResponse {
            credential_id: credential.id,
            credentials,
            issued_at: credential.issued_at,
            expires_at,
            ttl_seconds: effective_ttl,
            provider: secret_config.provider_type.clone(),
        };

        let rate_info = RateLimitInfo {
            remaining,
            reset_at,
        };

        Ok((response, rate_info))
    }

    /// Validate that the agent exists and is active.
    async fn validate_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AiAgent, ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if !agent.is_active() {
            if agent.status == "suspended" {
                return Err(ApiAgentsError::AgentNotActive);
            }
            if agent.status == "expired" {
                return Err(ApiAgentsError::AgentExpired);
            }
            return Err(ApiAgentsError::AgentNotActive);
        }

        Ok(agent)
    }

    /// Get and validate secret type configuration.
    async fn get_secret_type_config(
        &self,
        tenant_id: Uuid,
        secret_type: &str,
    ) -> Result<SecretTypeConfiguration, ApiAgentsError> {
        let config = SecretTypeConfiguration::find_by_type_name(&self.pool, tenant_id, secret_type)
            .await?
            .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(secret_type.to_string()))?;

        if !config.enabled {
            return Err(ApiAgentsError::SecretTypeDisabled(secret_type.to_string()));
        }

        Ok(config)
    }

    /// Check that the agent has permission for the secret type.
    async fn check_permission(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
    ) -> Result<AgentSecretPermission, ApiAgentsError> {
        let permission = AgentSecretPermission::find_by_agent_and_type(
            &self.pool,
            tenant_id,
            agent_id,
            secret_type,
        )
        .await?
        .ok_or_else(|| ApiAgentsError::SecretPermissionDenied(secret_type.to_string()))?;

        if !permission.is_valid() {
            return Err(ApiAgentsError::SecretPermissionExpired);
        }

        Ok(permission)
    }

    /// Get the effective rate limit considering permission overrides.
    fn get_effective_rate_limit(
        &self,
        config: &SecretTypeConfiguration,
        permission: &AgentSecretPermission,
    ) -> i32 {
        permission.effective_rate_limit(config.rate_limit_per_hour)
    }

    /// Check and update rate limit, returning remaining count and reset time.
    fn check_and_update_rate_limit(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
        max_requests: i32,
    ) -> Result<(i32, chrono::DateTime<Utc>), ApiAgentsError> {
        let key = (tenant_id, agent_id, secret_type.to_string());
        let now = Utc::now();
        let hour_start = now
            .date_naive()
            .and_hms_opt(now.time().hour(), 0, 0)
            .unwrap()
            .and_utc();
        let reset_at = hour_start + Duration::hours(1);

        let mut entry = self
            .rate_limits
            .entry(key)
            .or_insert(CredentialRateLimitEntry {
                count: 0,
                window_start: hour_start,
            });

        // Reset if we're in a new hour window
        if entry.window_start < hour_start {
            entry.count = 0;
            entry.window_start = hour_start;
        }

        // Check limit
        if entry.count >= max_requests {
            return Err(ApiAgentsError::CredentialRateLimitExceeded(
                entry.count,
                max_requests,
            ));
        }

        // Increment and return remaining
        entry.count += 1;
        let remaining = max_requests - entry.count;

        Ok((remaining, reset_at))
    }

    /// Calculate the effective TTL considering all constraints.
    fn calculate_effective_ttl(
        &self,
        requested_ttl: Option<i32>,
        config: &SecretTypeConfiguration,
        permission: &AgentSecretPermission,
    ) -> Result<i32, ApiAgentsError> {
        // Get the maximum allowed TTL (minimum of config max and permission override)
        let max_ttl = permission.effective_max_ttl(config.max_ttl_seconds);

        // Get effective TTL (use requested, capped at max, or default)
        let ttl = config.effective_ttl(requested_ttl);

        // Ensure TTL doesn't exceed the max
        let effective = ttl.min(max_ttl);

        // Validate minimum TTL (60 seconds)
        if effective < 60 {
            return Err(ApiAgentsError::InvalidTtl(
                "TTL must be at least 60 seconds".to_string(),
            ));
        }

        Ok(effective)
    }

    /// Get the provider configuration for a given provider type.
    ///
    /// Returns None for "internal" provider (no external config needed).
    /// Returns the first active provider config for other types.
    async fn get_provider_config(
        &self,
        tenant_id: Uuid,
        provider_type: &str,
    ) -> Result<Option<SecretProviderConfig>, ApiAgentsError> {
        if provider_type == "internal" {
            // Internal provider doesn't need external configuration
            return Ok(None);
        }

        // Find an active provider configuration for this type
        let configs =
            SecretProviderConfig::find_active_by_type(&self.pool, tenant_id, provider_type).await?;

        if configs.is_empty() {
            return Err(ApiAgentsError::SecretProviderNotFound(format!(
                "No active {provider_type} provider configured for tenant"
            )));
        }

        // Return the first active provider
        Ok(Some(configs.into_iter().next().unwrap()))
    }

    /// Revoke a credential by ID.
    pub async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        credential_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), ApiAgentsError> {
        let credential = DynamicCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await?
            .ok_or(ApiAgentsError::CredentialNotFound)?;

        if credential.status == "revoked" {
            return Ok(()); // Already revoked
        }

        // Revoke in the external provider if there's a lease_id
        if let Some(ref lease_id) = credential.provider_lease_id {
            let provider_config = self
                .get_provider_config(tenant_id, &credential.provider_type)
                .await?;

            if let Err(e) = self
                .provider_registry
                .revoke_credentials(
                    tenant_id,
                    &credential.provider_type,
                    provider_config.as_ref(),
                    lease_id,
                )
                .await
            {
                // Log the error but continue with local revocation
                tracing::warn!(
                    "Failed to revoke credential in provider {}: {}",
                    credential.provider_type,
                    e
                );
            }
        }

        DynamicCredential::revoke(&self.pool, tenant_id, credential_id).await?;

        // Log the revocation
        let audit_context = serde_json::json!({
            "action": "revocation",
            "credential_id": credential_id,
            "reason": reason,
        });
        let audit_entry = CreateCredentialRequestAudit {
            agent_id: credential.agent_id,
            secret_type: credential.secret_type.clone(),
            outcome: CredentialRequestOutcome::Success,
            ttl_granted: None,
            error_code: None,
            source_ip: None,
            user_agent: None,
            latency_ms: 0.0,
            context: Some(audit_context),
        };
        let _ = CredentialRequestAudit::insert(&self.pool, tenant_id, audit_entry).await;

        // Emit Kafka event for credential revocation
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let revoked_event = CredentialRevoked {
                tenant_id,
                agent_id: credential.agent_id,
                credential_id,
                secret_type: credential.secret_type.clone(),
                reason: reason.map(|s| s.to_string()),
                revoked_by: "system".to_string(), // TODO: Pass actual actor
                timestamp: Utc::now(),
            };
            if let Err(e) = producer.publish(revoked_event, tenant_id, None).await {
                tracing::warn!("Failed to emit CredentialRevoked event: {}", e);
            }
        }

        Ok(())
    }

    /// Get a credential by ID (for status checks).
    pub async fn get_credential(
        &self,
        tenant_id: Uuid,
        credential_id: Uuid,
    ) -> Result<DynamicCredential, ApiAgentsError> {
        DynamicCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await?
            .ok_or(ApiAgentsError::CredentialNotFound)
    }

    /// List credentials for an agent.
    pub async fn list_agent_credentials(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        status: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DynamicCredential>, ApiAgentsError> {
        let filter = DynamicCredentialFilter {
            agent_id: Some(agent_id),
            status,
            ..Default::default()
        };
        DynamicCredential::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(ApiAgentsError::from)
    }

    /// Log a denied credential request for audit purposes.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_denied_request(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
        outcome: CredentialRequestOutcome,
        error_code: CredentialErrorCode,
        error_message: &str,
        request: &CredentialRequest,
        source_ip: Option<&str>,
    ) -> Result<(), ApiAgentsError> {
        let audit_context = serde_json::json!({
            "conversation_id": request.context.conversation_id,
            "session_id": request.context.session_id,
            "user_instruction": request.context.user_instruction,
            "requested_ttl": request.ttl_seconds,
            "error_message": error_message,
        });
        let audit_entry = CreateCredentialRequestAudit {
            agent_id,
            secret_type: secret_type.to_string(),
            outcome,
            ttl_granted: None,
            error_code: Some(error_code),
            source_ip: source_ip.map(std::string::ToString::to_string),
            user_agent: None,
            latency_ms: 0.0,
            context: Some(audit_context),
        };

        CredentialRequestAudit::insert(&self.pool, tenant_id, audit_entry).await?;

        // Emit Kafka event for credential denial
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let denial_reason = match error_code {
                CredentialErrorCode::AgentNotFound => CredentialDenialReason::AgentNotFound,
                CredentialErrorCode::AgentSuspended => CredentialDenialReason::AgentSuspended,
                CredentialErrorCode::AgentExpired => CredentialDenialReason::AgentExpired,
                CredentialErrorCode::SecretTypeNotFound => {
                    CredentialDenialReason::SecretTypeNotFound
                }
                CredentialErrorCode::SecretTypeDisabled => {
                    CredentialDenialReason::SecretTypeDisabled
                }
                CredentialErrorCode::PermissionDenied => CredentialDenialReason::PermissionDenied,
                CredentialErrorCode::PermissionExpired => CredentialDenialReason::PermissionExpired,
                CredentialErrorCode::RateLimitExceeded => CredentialDenialReason::RateLimitExceeded,
                CredentialErrorCode::ProviderUnavailable => {
                    CredentialDenialReason::ProviderUnavailable
                }
                CredentialErrorCode::ProviderTimeout => CredentialDenialReason::ProviderTimeout,
                CredentialErrorCode::ProviderAuthFailed => {
                    CredentialDenialReason::ProviderAuthFailed
                }
                CredentialErrorCode::InvalidTtl => CredentialDenialReason::InvalidTtl,
                CredentialErrorCode::InternalError => CredentialDenialReason::InternalError,
            };
            let denied_event = CredentialDenied {
                tenant_id,
                agent_id,
                secret_type: secret_type.to_string(),
                reason: denial_reason,
                error_message: error_message.to_string(),
                timestamp: Utc::now(),
            };
            if let Err(e) = producer.publish(denied_event, tenant_id, None).await {
                tracing::warn!("Failed to emit CredentialDenied event: {}", e);
            }
        }

        Ok(())
    }

    /// Emit a rate limit event.
    #[cfg(feature = "kafka")]
    pub async fn emit_rate_limit_event(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
        current_count: i32,
        limit: i32,
        reset_at: chrono::DateTime<Utc>,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = CredentialRateLimited {
                tenant_id,
                agent_id,
                secret_type: secret_type.to_string(),
                current_count,
                limit,
                reset_at,
                timestamp: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!("Failed to emit CredentialRateLimited event: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_key_creation() {
        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let secret_type = "postgres-readonly".to_string();

        let key = (tenant_id, agent_id, secret_type.clone());
        assert_eq!(key.0, tenant_id);
        assert_eq!(key.1, agent_id);
        assert_eq!(key.2, secret_type);
    }

    #[test]
    fn test_credential_response_creation() {
        let response = CredentialResponse {
            credential_id: Uuid::new_v4(),
            credentials: serde_json::json!({"test": "value"}),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            ttl_seconds: 300,
            provider: "internal".to_string(),
        };

        assert_eq!(response.ttl_seconds, 300);
        assert_eq!(response.provider, "internal");
    }
}
