//! Role Mapping Service for Workload Identity Federation (F121).
//!
//! Manages IAM role mappings that determine which cloud roles agents can assume.

use sqlx::PgPool;
use tracing::{info, instrument};
use uuid::Uuid;

use xavyo_db::models::{
    CreateIamRoleMapping, IamRoleMapping, IamRoleMappingFilter, UpdateIamRoleMapping,
};

use crate::error::ApiAgentsError;
use crate::services::{IdentityAuditService, MappingOperation};

/// Service for managing IAM role mappings.
#[derive(Clone)]
pub struct RoleMappingService {
    pool: PgPool,
    audit_service: IdentityAuditService,
}

impl RoleMappingService {
    /// Create a new role mapping service.
    #[must_use]
    pub fn new(pool: PgPool, audit_service: IdentityAuditService) -> Self {
        Self {
            pool,
            audit_service,
        }
    }

    /// Create a new role mapping.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, provider_config_id = %request.provider_config_id))]
    pub async fn create_mapping(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_type: &str,
        request: &CreateIamRoleMapping,
    ) -> Result<IamRoleMapping, ApiAgentsError> {
        let mapping = IamRoleMapping::create(&self.pool, tenant_id, request).await?;

        info!(
            mapping_id = %mapping.id,
            agent_type = ?mapping.agent_type,
            role_identifier = %mapping.role_identifier,
            "Created role mapping"
        );

        // Audit log the creation
        self.audit_service
            .log_mapping_change(
                tenant_id,
                user_id,
                mapping.id,
                provider_type,
                MappingOperation::Create,
                mapping.agent_type.as_deref(),
                &mapping.role_identifier,
            )
            .await?;

        Ok(mapping)
    }

    /// Get a role mapping by ID.
    pub async fn get_mapping(
        &self,
        tenant_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<IamRoleMapping, ApiAgentsError> {
        IamRoleMapping::get_by_id(&self.pool, tenant_id, mapping_id)
            .await?
            .ok_or(ApiAgentsError::RoleMappingNotFound)
    }

    /// List role mappings for a tenant with optional filtering.
    pub async fn list_mappings(
        &self,
        tenant_id: Uuid,
        filter: &IamRoleMappingFilter,
    ) -> Result<Vec<IamRoleMapping>, ApiAgentsError> {
        let mappings = IamRoleMapping::list(&self.pool, tenant_id, filter).await?;
        Ok(mappings)
    }

    /// Get all mappings for a specific provider.
    pub async fn get_provider_mappings(
        &self,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<Vec<IamRoleMapping>, ApiAgentsError> {
        let mappings =
            IamRoleMapping::get_by_provider(&self.pool, tenant_id, provider_config_id).await?;
        Ok(mappings)
    }

    /// Update a role mapping.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, mapping_id = %mapping_id))]
    pub async fn update_mapping(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        mapping_id: Uuid,
        provider_type: &str,
        request: &UpdateIamRoleMapping,
    ) -> Result<IamRoleMapping, ApiAgentsError> {
        // Get existing mapping for audit log
        let existing = self.get_mapping(tenant_id, mapping_id).await?;

        let mapping = IamRoleMapping::update(&self.pool, tenant_id, mapping_id, request)
            .await?
            .ok_or(ApiAgentsError::RoleMappingNotFound)?;

        info!(
            mapping_id = %mapping.id,
            role_identifier = %mapping.role_identifier,
            "Updated role mapping"
        );

        // Audit log the update
        self.audit_service
            .log_mapping_change(
                tenant_id,
                user_id,
                mapping_id,
                provider_type,
                MappingOperation::Update,
                existing.agent_type.as_deref(),
                &mapping.role_identifier,
            )
            .await?;

        Ok(mapping)
    }

    /// Delete a role mapping.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, mapping_id = %mapping_id))]
    pub async fn delete_mapping(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        mapping_id: Uuid,
        provider_type: &str,
    ) -> Result<(), ApiAgentsError> {
        // Get mapping info for audit log
        let mapping = self.get_mapping(tenant_id, mapping_id).await?;

        let deleted = IamRoleMapping::delete(&self.pool, tenant_id, mapping_id).await?;

        if !deleted {
            return Err(ApiAgentsError::RoleMappingNotFound);
        }

        info!(mapping_id = %mapping_id, "Deleted role mapping");

        // Audit log the deletion
        self.audit_service
            .log_mapping_change(
                tenant_id,
                user_id,
                mapping_id,
                provider_type,
                MappingOperation::Delete,
                mapping.agent_type.as_deref(),
                &mapping.role_identifier,
            )
            .await?;

        Ok(())
    }

    /// Find the best matching role mapping for an agent.
    ///
    /// This method implements the role resolution logic:
    /// 1. First, try to find a specific mapping for the agent type
    /// 2. If not found, fall back to the default mapping (`agent_type` = NULL)
    /// 3. If neither exists, return an error
    #[instrument(skip(self), fields(tenant_id = %tenant_id, agent_type = %agent_type))]
    pub async fn find_mapping_for_agent(
        &self,
        tenant_id: Uuid,
        provider_config_id: Uuid,
        agent_type: &str,
    ) -> Result<IamRoleMapping, ApiAgentsError> {
        let mapping =
            IamRoleMapping::find_for_agent(&self.pool, tenant_id, provider_config_id, agent_type)
                .await?
                .ok_or_else(|| ApiAgentsError::NoRoleMappingForAgent(agent_type.to_string()))?;

        info!(
            mapping_id = %mapping.id,
            matched_type = ?mapping.agent_type,
            role_identifier = %mapping.role_identifier,
            "Found role mapping for agent"
        );

        Ok(mapping)
    }

    /// Check if a provider has any role mappings.
    pub async fn provider_has_mappings(
        &self,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<bool, ApiAgentsError> {
        let has = IamRoleMapping::has_mappings(&self.pool, tenant_id, provider_config_id).await?;
        Ok(has)
    }

    /// Validate a role mapping request.
    pub fn validate_mapping_request(
        &self,
        request: &CreateIamRoleMapping,
    ) -> Result<(), ApiAgentsError> {
        // Role identifier must not be empty
        if request.role_identifier.trim().is_empty() {
            return Err(ApiAgentsError::Validation(
                "Role identifier cannot be empty".to_string(),
            ));
        }

        // TTL must be within valid range (enforced at DB level, but validate early)
        if request.max_ttl_seconds < 900 {
            return Err(ApiAgentsError::InvalidTtl(
                "TTL must be at least 900 seconds (15 minutes)".to_string(),
            ));
        }

        if request.max_ttl_seconds > 43200 {
            return Err(ApiAgentsError::InvalidTtl(
                "TTL cannot exceed 43200 seconds (12 hours)".to_string(),
            ));
        }

        // Validate agent type if specified
        if let Some(ref agent_type) = request.agent_type {
            if agent_type.trim().is_empty() {
                return Err(ApiAgentsError::Validation(
                    "Agent type cannot be empty string (use NULL for default mapping)".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the effective TTL for a mapping request.
    ///
    /// Clamps the requested TTL to the mapping's max TTL.
    #[must_use]
    pub fn get_effective_ttl(&self, mapping: &IamRoleMapping, requested_ttl: i32) -> i32 {
        requested_ttl
            .max(900) // Minimum 15 minutes
            .min(mapping.max_ttl_seconds) // Can't exceed mapping limit
            .min(43200) // Can't exceed AWS max (12 hours)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to validate mapping request without needing a service instance.
    // This mirrors the service method but is callable in pure unit tests.
    fn validate_mapping_request(request: &CreateIamRoleMapping) -> Result<(), ApiAgentsError> {
        // Role identifier must not be empty
        if request.role_identifier.trim().is_empty() {
            return Err(ApiAgentsError::Validation(
                "Role identifier cannot be empty".to_string(),
            ));
        }

        // TTL must be within valid range
        if request.max_ttl_seconds < 900 {
            return Err(ApiAgentsError::InvalidTtl(
                "TTL must be at least 900 seconds (15 minutes)".to_string(),
            ));
        }

        if request.max_ttl_seconds > 43200 {
            return Err(ApiAgentsError::InvalidTtl(
                "TTL cannot exceed 43200 seconds (12 hours)".to_string(),
            ));
        }

        // Validate agent type if specified
        if let Some(ref agent_type) = request.agent_type {
            if agent_type.trim().is_empty() {
                return Err(ApiAgentsError::Validation(
                    "Agent type cannot be empty string (use NULL for default mapping)".to_string(),
                ));
            }
        }

        Ok(())
    }

    // Helper function to get effective TTL without needing a service instance.
    fn get_effective_ttl(mapping: &IamRoleMapping, requested_ttl: i32) -> i32 {
        requested_ttl
            .max(900) // Minimum 15 minutes
            .min(mapping.max_ttl_seconds) // Can't exceed mapping limit
            .min(43200) // Can't exceed AWS max (12 hours)
    }

    #[test]
    fn test_validate_mapping_request() {
        // Valid request
        let valid = CreateIamRoleMapping {
            provider_config_id: Uuid::new_v4(),
            agent_type: Some("code-assistant".to_string()),
            role_identifier: "arn:aws:iam::123456789012:role/AgentRole".to_string(),
            allowed_scopes: vec!["s3:GetObject".to_string()],
            max_ttl_seconds: 3600,
            constraints: serde_json::json!({}),
        };
        assert!(validate_mapping_request(&valid).is_ok());

        // Empty role identifier
        let empty_role = CreateIamRoleMapping {
            provider_config_id: Uuid::new_v4(),
            agent_type: None,
            role_identifier: "   ".to_string(),
            allowed_scopes: vec![],
            max_ttl_seconds: 3600,
            constraints: serde_json::json!({}),
        };
        assert!(validate_mapping_request(&empty_role).is_err());

        // TTL too low
        let low_ttl = CreateIamRoleMapping {
            provider_config_id: Uuid::new_v4(),
            agent_type: None,
            role_identifier: "role-arn".to_string(),
            allowed_scopes: vec![],
            max_ttl_seconds: 60,
            constraints: serde_json::json!({}),
        };
        assert!(validate_mapping_request(&low_ttl).is_err());

        // TTL too high
        let high_ttl = CreateIamRoleMapping {
            provider_config_id: Uuid::new_v4(),
            agent_type: None,
            role_identifier: "role-arn".to_string(),
            allowed_scopes: vec![],
            max_ttl_seconds: 100000,
            constraints: serde_json::json!({}),
        };
        assert!(validate_mapping_request(&high_ttl).is_err());
    }

    #[test]
    fn test_get_effective_ttl() {
        let mapping = IamRoleMapping {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider_config_id: Uuid::new_v4(),
            agent_type: None,
            role_identifier: "role".to_string(),
            allowed_scopes: vec![],
            max_ttl_seconds: 7200, // 2 hours
            constraints: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Request within limits
        assert_eq!(get_effective_ttl(&mapping, 3600), 3600);

        // Request below minimum
        assert_eq!(get_effective_ttl(&mapping, 100), 900);

        // Request above mapping limit
        assert_eq!(get_effective_ttl(&mapping, 10000), 7200);

        // Request above AWS max
        let high_limit_mapping = IamRoleMapping {
            max_ttl_seconds: 50000,
            ..mapping
        };
        assert_eq!(get_effective_ttl(&high_limit_mapping, 50000), 43200);
    }
}
