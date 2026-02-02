//! Secret Permission Service for managing agent access to secret types (F120).
//!
//! Provides business logic for:
//! - Granting permissions to agents for secret types
//! - Revoking permissions
//! - Validating permission constraints
//! - Listing permissions

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use xavyo_db::models::{
    agent_secret_permission::{
        AgentSecretPermission, AgentSecretPermissionFilter, GrantSecretPermission,
        UpdateSecretPermission,
    },
    ai_agent::AiAgent,
    secret_type_config::SecretTypeConfiguration,
};

/// Response for permission grant operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PermissionGrantResponse {
    /// The created or updated permission.
    pub permission: AgentSecretPermission,
    /// Whether this was a new grant or an update.
    pub created: bool,
}

/// Service for managing secret permissions.
#[derive(Clone)]
pub struct SecretPermissionService {
    pool: PgPool,
}

impl SecretPermissionService {
    /// Create a new SecretPermissionService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grant or update a permission for an agent to access a secret type.
    ///
    /// Validates:
    /// - Agent exists and is active
    /// - Secret type exists and is enabled
    /// - TTL/rate limit overrides are within type limits
    pub async fn grant_permission(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        granted_by: Uuid,
        input: GrantSecretPermission,
    ) -> Result<PermissionGrantResponse, ApiAgentsError> {
        // Validate agent exists
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if !agent.is_active() {
            return Err(ApiAgentsError::AgentNotActive);
        }

        // Validate secret type exists and is enabled
        let secret_config =
            SecretTypeConfiguration::find_by_type_name(&self.pool, tenant_id, &input.secret_type)
                .await?
                .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(input.secret_type.clone()))?;

        if !secret_config.enabled {
            return Err(ApiAgentsError::SecretTypeDisabled(
                input.secret_type.clone(),
            ));
        }

        // Validate TTL override is within limits
        if let Some(ttl) = input.max_ttl_seconds {
            if ttl > secret_config.max_ttl_seconds {
                return Err(ApiAgentsError::InvalidTtl(format!(
                    "Override TTL {} exceeds secret type max {}",
                    ttl, secret_config.max_ttl_seconds
                )));
            }
            if ttl < 60 {
                return Err(ApiAgentsError::InvalidTtl(
                    "TTL must be at least 60 seconds".to_string(),
                ));
            }
        }

        // Validate rate limit override is within limits
        if let Some(rate) = input.max_requests_per_hour {
            if rate > secret_config.rate_limit_per_hour {
                return Err(ApiAgentsError::InvalidRateLimit(format!(
                    "Override rate limit {} exceeds secret type max {}",
                    rate, secret_config.rate_limit_per_hour
                )));
            }
            if rate < 1 {
                return Err(ApiAgentsError::InvalidRateLimit(
                    "Rate limit must be at least 1 per hour".to_string(),
                ));
            }
        }

        // Check if permission already exists
        let existing = AgentSecretPermission::find_by_agent_and_type(
            &self.pool,
            tenant_id,
            agent_id,
            &input.secret_type,
        )
        .await?;

        let created = existing.is_none();

        // Grant (upsert) the permission
        let permission =
            AgentSecretPermission::grant(&self.pool, tenant_id, agent_id, granted_by, input)
                .await?;

        Ok(PermissionGrantResponse {
            permission,
            created,
        })
    }

    /// Revoke a permission for an agent to access a secret type.
    pub async fn revoke_permission(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
    ) -> Result<bool, ApiAgentsError> {
        // Validate agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let revoked =
            AgentSecretPermission::revoke(&self.pool, tenant_id, agent_id, secret_type).await?;

        if !revoked {
            return Err(ApiAgentsError::SecretPermissionNotFound);
        }

        Ok(true)
    }

    /// Revoke all permissions for an agent.
    pub async fn revoke_all_for_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, ApiAgentsError> {
        // Validate agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let count =
            AgentSecretPermission::revoke_all_for_agent(&self.pool, tenant_id, agent_id).await?;

        Ok(count)
    }

    /// Get a permission by ID.
    pub async fn get_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
    ) -> Result<AgentSecretPermission, ApiAgentsError> {
        AgentSecretPermission::find_by_id(&self.pool, tenant_id, permission_id)
            .await?
            .ok_or(ApiAgentsError::SecretPermissionNotFound)
    }

    /// List permissions for an agent.
    pub async fn list_agent_permissions(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AgentSecretPermission>, ApiAgentsError> {
        // Validate agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let permissions =
            AgentSecretPermission::list_by_agent(&self.pool, tenant_id, agent_id).await?;

        Ok(permissions)
    }

    /// List all permissions with filtering.
    pub async fn list_permissions(
        &self,
        tenant_id: Uuid,
        filter: AgentSecretPermissionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AgentSecretPermission>, ApiAgentsError> {
        let permissions =
            AgentSecretPermission::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        Ok(permissions)
    }

    /// Update a permission.
    pub async fn update_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
        input: UpdateSecretPermission,
    ) -> Result<AgentSecretPermission, ApiAgentsError> {
        // Get existing permission to validate updates
        let existing = AgentSecretPermission::find_by_id(&self.pool, tenant_id, permission_id)
            .await?
            .ok_or(ApiAgentsError::SecretPermissionNotFound)?;

        // Get secret type config for validation
        let secret_config = SecretTypeConfiguration::find_by_type_name(
            &self.pool,
            tenant_id,
            &existing.secret_type,
        )
        .await?
        .ok_or_else(|| ApiAgentsError::SecretTypeNotFound(existing.secret_type.clone()))?;

        // Validate TTL override if being updated
        if let Some(Some(ttl)) = input.max_ttl_seconds {
            if ttl > secret_config.max_ttl_seconds {
                return Err(ApiAgentsError::InvalidTtl(format!(
                    "Override TTL {} exceeds secret type max {}",
                    ttl, secret_config.max_ttl_seconds
                )));
            }
            if ttl < 60 {
                return Err(ApiAgentsError::InvalidTtl(
                    "TTL must be at least 60 seconds".to_string(),
                ));
            }
        }

        // Validate rate limit override if being updated
        if let Some(Some(rate)) = input.max_requests_per_hour {
            if rate > secret_config.rate_limit_per_hour {
                return Err(ApiAgentsError::InvalidRateLimit(format!(
                    "Override rate limit {} exceeds secret type max {}",
                    rate, secret_config.rate_limit_per_hour
                )));
            }
            if rate < 1 {
                return Err(ApiAgentsError::InvalidRateLimit(
                    "Rate limit must be at least 1 per hour".to_string(),
                ));
            }
        }

        let updated =
            AgentSecretPermission::update(&self.pool, tenant_id, permission_id, input).await?;

        updated.ok_or(ApiAgentsError::SecretPermissionNotFound)
    }

    /// Check if an agent has a valid permission for a secret type.
    pub async fn check_permission(
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

    /// Delete expired permissions.
    pub async fn delete_expired(&self, tenant_id: Uuid) -> Result<u64, ApiAgentsError> {
        let count = AgentSecretPermission::delete_expired(&self.pool, tenant_id).await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_grant_response_serialization() {
        let response = PermissionGrantResponse {
            permission: AgentSecretPermission {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                agent_id: Uuid::new_v4(),
                secret_type: "postgres-readonly".to_string(),
                max_ttl_seconds: Some(300),
                max_requests_per_hour: Some(10),
                expires_at: None,
                granted_by: Uuid::new_v4(),
                granted_at: chrono::Utc::now(),
            },
            created: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("postgres-readonly"));
        assert!(json.contains("\"created\":true"));
    }
}
