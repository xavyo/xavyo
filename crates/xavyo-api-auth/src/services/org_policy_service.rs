//! Organization security policy service (F-066).
//!
//! Handles policy CRUD operations, inheritance resolution, and conflict detection.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    models::org_security_policy::{
        CreateOrgSecurityPolicy, EffectiveOrgPolicy, OrgPolicyType, OrgSecurityPolicy, PolicySource,
    },
    models::Group,
    TenantMfaPolicy, TenantPasswordPolicy, TenantSessionPolicy,
};

use crate::models::{
    IpRestrictionPolicyConfig, MfaPolicyConfig, PasswordPolicyConfig, PolicyConflictWarning,
    PolicyValidationResult, SessionPolicyConfig,
};

/// Error type for organization policy operations.
#[derive(Debug, thiserror::Error)]
pub enum OrgPolicyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Organization not found: {0}")]
    OrgNotFound(Uuid),

    #[error("Policy not found")]
    PolicyNotFound,

    #[error("Invalid policy configuration: {0}")]
    InvalidConfig(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Service for managing organization-level security policies.
pub struct OrgPolicyService {
    pool: Arc<PgPool>,
}

impl OrgPolicyService {
    /// Create a new `OrgPolicyService`.
    #[must_use]
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // -------------------------------------------------------------------------
    // CRUD Operations
    // -------------------------------------------------------------------------

    /// List policies for an organization.
    pub async fn list_policies_for_org(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<OrgSecurityPolicy>, OrgPolicyError> {
        // Verify org exists
        self.verify_org_exists(tenant_id, group_id).await?;

        Ok(OrgSecurityPolicy::list_by_group(&self.pool, tenant_id, group_id).await?)
    }

    /// Get a specific policy for an organization.
    pub async fn get_policy(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<Option<OrgSecurityPolicy>, OrgPolicyError> {
        self.verify_org_exists(tenant_id, group_id).await?;
        Ok(
            OrgSecurityPolicy::find_by_group_and_type(&self.pool, tenant_id, group_id, policy_type)
                .await?,
        )
    }

    /// Create or update a policy (upsert).
    pub async fn upsert_policy(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
        config: serde_json::Value,
        is_active: bool,
        user_id: Option<Uuid>,
    ) -> Result<OrgSecurityPolicy, OrgPolicyError> {
        self.verify_org_exists(tenant_id, group_id).await?;

        // Validate config based on policy type
        self.validate_config(policy_type, &config)?;

        let create = CreateOrgSecurityPolicy {
            policy_type,
            config,
            is_active,
        };

        Ok(OrgSecurityPolicy::upsert(&self.pool, tenant_id, group_id, &create, user_id).await?)
    }

    /// Delete a policy.
    pub async fn delete_policy(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<bool, OrgPolicyError> {
        self.verify_org_exists(tenant_id, group_id).await?;
        Ok(OrgSecurityPolicy::delete_by_group_and_type(
            &self.pool,
            tenant_id,
            group_id,
            policy_type,
        )
        .await?)
    }

    // -------------------------------------------------------------------------
    // Effective Policy Resolution
    // -------------------------------------------------------------------------

    /// Get the effective policy for an organization (with inheritance).
    pub async fn get_effective_policy_for_org(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<EffectiveOrgPolicy, OrgPolicyError> {
        self.verify_org_exists(tenant_id, group_id).await?;

        // Try to find policy in hierarchy
        if let Some(row) =
            OrgSecurityPolicy::get_effective_policy(&self.pool, tenant_id, group_id, policy_type)
                .await?
        {
            let source = if row.depth == 0 {
                PolicySource::Local {
                    group_id: row.group_id.unwrap_or(group_id),
                    group_name: row.group_name.unwrap_or_default(),
                }
            } else {
                PolicySource::Inherited {
                    group_id: row.group_id.unwrap_or(group_id),
                    group_name: row.group_name.unwrap_or_default(),
                }
            };

            return Ok(EffectiveOrgPolicy {
                config: row.config.unwrap_or(serde_json::json!({})),
                source,
                policy_type,
            });
        }

        // Fall back to tenant-level policy
        let config = self
            .get_tenant_default_config(tenant_id, policy_type)
            .await?;

        Ok(EffectiveOrgPolicy {
            config,
            source: PolicySource::TenantDefault,
            policy_type,
        })
    }

    /// Get effective policy for a user (most restrictive across all memberships).
    pub async fn get_effective_policy_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<(serde_json::Value, Vec<PolicySource>), OrgPolicyError> {
        // Get all groups the user belongs to
        let groups = self.get_user_groups(tenant_id, user_id).await?;

        if groups.is_empty() {
            // User has no group memberships, use tenant default
            let config = self
                .get_tenant_default_config(tenant_id, policy_type)
                .await?;
            return Ok((config, vec![PolicySource::TenantDefault]));
        }

        // Resolve effective policy for each group
        let mut policies: Vec<(serde_json::Value, PolicySource)> = Vec::new();

        for group_id in groups {
            let effective = self
                .get_effective_policy_for_org(tenant_id, group_id, policy_type)
                .await?;
            policies.push((effective.config, effective.source));
        }

        // Combine using most restrictive logic
        let (config, sources) = self.combine_policies_most_restrictive(policy_type, policies)?;

        Ok((config, sources))
    }

    // -------------------------------------------------------------------------
    // Conflict Detection
    // -------------------------------------------------------------------------

    /// Validate a proposed policy for conflicts with parent/child organizations.
    pub async fn validate_policy(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
        config: &serde_json::Value,
    ) -> Result<PolicyValidationResult, OrgPolicyError> {
        self.verify_org_exists(tenant_id, group_id).await?;

        // Validate config format
        self.validate_config(policy_type, config)?;

        let mut warnings = Vec::new();

        // Check parent policies
        let parent_policies =
            OrgSecurityPolicy::get_hierarchy_policies(&self.pool, tenant_id, group_id, policy_type)
                .await?;

        for parent in parent_policies.iter().filter(|p| p.depth > 0) {
            if let Some(ref parent_config) = parent.config {
                if let Some(warning) = self.check_conflict(
                    policy_type,
                    config,
                    parent_config,
                    parent.group_id.unwrap_or(Uuid::nil()),
                    &parent.group_name.clone().unwrap_or_default(),
                    true, // is_parent
                ) {
                    warnings.push(warning);
                }
            }
        }

        // Check child policies
        let child_policies =
            OrgSecurityPolicy::get_child_policies(&self.pool, tenant_id, group_id, policy_type)
                .await?;

        for child in &child_policies {
            if let Some(warning) = self.check_conflict(
                policy_type,
                config,
                &child.config,
                child.group_id,
                "",    // We don't have group name in the child result
                false, // is_parent
            ) {
                warnings.push(warning);
            }
        }

        Ok(PolicyValidationResult {
            valid: true, // Warnings don't block creation
            warnings,
        })
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------

    /// Verify that an organization exists.
    async fn verify_org_exists(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<(), OrgPolicyError> {
        let group = Group::find_by_id(&self.pool, tenant_id, group_id).await?;
        if group.is_none() {
            return Err(OrgPolicyError::OrgNotFound(group_id));
        }
        Ok(())
    }

    /// Validate config JSON against policy type schema.
    fn validate_config(
        &self,
        policy_type: OrgPolicyType,
        config: &serde_json::Value,
    ) -> Result<(), OrgPolicyError> {
        match policy_type {
            OrgPolicyType::Password => {
                let parsed: PasswordPolicyConfig = serde_json::from_value(config.clone())
                    .map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;
                parsed
                    .validate()
                    .map_err(|errors| OrgPolicyError::InvalidConfig(errors.join(", ")))?;
            }
            OrgPolicyType::Mfa => {
                let parsed: MfaPolicyConfig = serde_json::from_value(config.clone())
                    .map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;
                parsed
                    .validate()
                    .map_err(|errors| OrgPolicyError::InvalidConfig(errors.join(", ")))?;
            }
            OrgPolicyType::Session => {
                let parsed: SessionPolicyConfig = serde_json::from_value(config.clone())
                    .map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;
                parsed
                    .validate()
                    .map_err(|errors| OrgPolicyError::InvalidConfig(errors.join(", ")))?;
            }
            OrgPolicyType::IpRestriction => {
                let parsed: IpRestrictionPolicyConfig = serde_json::from_value(config.clone())
                    .map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;
                parsed
                    .validate()
                    .map_err(|errors| OrgPolicyError::InvalidConfig(errors.join(", ")))?;
            }
        }
        Ok(())
    }

    /// Get tenant-level default policy configuration.
    async fn get_tenant_default_config(
        &self,
        tenant_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<serde_json::Value, OrgPolicyError> {
        match policy_type {
            OrgPolicyType::Password => {
                let policy = TenantPasswordPolicy::find_by_tenant(&*self.pool, tenant_id).await?;
                if let Some(p) = policy {
                    Ok(serde_json::json!({
                        "min_length": p.min_length,
                        "max_length": p.max_length,
                        "require_uppercase": p.require_uppercase,
                        "require_lowercase": p.require_lowercase,
                        "require_digit": p.require_digit,
                        "require_special": p.require_special,
                        "expiration_days": p.expiration_days,
                        "history_count": p.history_count,
                        "min_age_hours": p.min_age_hours
                    }))
                } else {
                    Ok(serde_json::to_value(PasswordPolicyConfig::default()).unwrap())
                }
            }
            OrgPolicyType::Mfa => {
                let policy = TenantMfaPolicy::get(&*self.pool, tenant_id).await.ok();
                let required = policy.is_some_and(|p| p.mfa_policy.to_string() == "required");
                Ok(serde_json::json!({
                    "required": required,
                    "allowed_methods": ["totp", "webauthn"],
                    "grace_period_hours": 0,
                    "remember_device_days": 0
                }))
            }
            OrgPolicyType::Session => {
                let policy = TenantSessionPolicy::find_by_tenant(&*self.pool, tenant_id).await?;
                if let Some(p) = policy {
                    Ok(serde_json::json!({
                        "max_duration_hours": p.absolute_timeout_hours,
                        "idle_timeout_minutes": p.idle_timeout_minutes,
                        "concurrent_session_limit": p.max_concurrent_sessions,
                        "require_reauth_sensitive": false
                    }))
                } else {
                    Ok(serde_json::to_value(SessionPolicyConfig::default()).unwrap())
                }
            }
            OrgPolicyType::IpRestriction => {
                // IP restrictions are typically empty at tenant level
                Ok(serde_json::to_value(IpRestrictionPolicyConfig::default()).unwrap())
            }
        }
    }

    /// Get all groups a user belongs to.
    async fn get_user_groups(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, OrgPolicyError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT group_id FROM group_memberships
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(self.pool())
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Combine multiple policies using most restrictive logic.
    fn combine_policies_most_restrictive(
        &self,
        policy_type: OrgPolicyType,
        policies: Vec<(serde_json::Value, PolicySource)>,
    ) -> Result<(serde_json::Value, Vec<PolicySource>), OrgPolicyError> {
        if policies.is_empty() {
            return Err(OrgPolicyError::PolicyNotFound);
        }

        if policies.len() == 1 {
            let (config, source) = policies.into_iter().next().unwrap();
            return Ok((config, vec![source]));
        }

        let sources: Vec<PolicySource> = policies.iter().map(|(_, s)| s.clone()).collect();

        match policy_type {
            OrgPolicyType::Password => {
                let configs: Result<Vec<PasswordPolicyConfig>, _> = policies
                    .iter()
                    .map(|(c, _)| serde_json::from_value(c.clone()))
                    .collect();
                let configs = configs.map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;

                let combined = configs
                    .into_iter()
                    .reduce(|a, b| a.most_restrictive(&b))
                    .unwrap();

                Ok((serde_json::to_value(combined).unwrap(), sources))
            }
            OrgPolicyType::Mfa => {
                let configs: Result<Vec<MfaPolicyConfig>, _> = policies
                    .iter()
                    .map(|(c, _)| serde_json::from_value(c.clone()))
                    .collect();
                let configs = configs.map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;

                let combined = configs
                    .into_iter()
                    .reduce(|a, b| a.most_restrictive(&b))
                    .unwrap();

                Ok((serde_json::to_value(combined).unwrap(), sources))
            }
            OrgPolicyType::Session => {
                let configs: Result<Vec<SessionPolicyConfig>, _> = policies
                    .iter()
                    .map(|(c, _)| serde_json::from_value(c.clone()))
                    .collect();
                let configs = configs.map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;

                let combined = configs
                    .into_iter()
                    .reduce(|a, b| a.most_restrictive(&b))
                    .unwrap();

                Ok((serde_json::to_value(combined).unwrap(), sources))
            }
            OrgPolicyType::IpRestriction => {
                let configs: Result<Vec<IpRestrictionPolicyConfig>, _> = policies
                    .iter()
                    .map(|(c, _)| serde_json::from_value(c.clone()))
                    .collect();
                let configs = configs.map_err(|e| OrgPolicyError::InvalidConfig(e.to_string()))?;

                let combined = configs
                    .into_iter()
                    .reduce(|a, b| a.most_restrictive(&b))
                    .unwrap();

                Ok((serde_json::to_value(combined).unwrap(), sources))
            }
        }
    }

    /// Check for conflict between two policy configs.
    fn check_conflict(
        &self,
        policy_type: OrgPolicyType,
        new_config: &serde_json::Value,
        existing_config: &serde_json::Value,
        related_org_id: Uuid,
        related_org_name: &str,
        is_parent: bool,
    ) -> Option<PolicyConflictWarning> {
        match policy_type {
            OrgPolicyType::Password => {
                let new: PasswordPolicyConfig = serde_json::from_value(new_config.clone()).ok()?;
                let existing: PasswordPolicyConfig =
                    serde_json::from_value(existing_config.clone()).ok()?;

                if is_parent && !new.is_more_restrictive_than(&existing) {
                    return Some(PolicyConflictWarning {
                        severity: "warning".to_string(),
                        message: format!(
                            "This policy is less restrictive than parent organization '{}'",
                            related_org_name
                        ),
                        related_org_id,
                        related_org_name: related_org_name.to_string(),
                        field: None,
                    });
                }
                None
            }
            OrgPolicyType::Mfa => {
                let new: MfaPolicyConfig = serde_json::from_value(new_config.clone()).ok()?;
                let existing: MfaPolicyConfig =
                    serde_json::from_value(existing_config.clone()).ok()?;

                if is_parent && existing.required && !new.required {
                    return Some(PolicyConflictWarning {
                        severity: "warning".to_string(),
                        message: format!(
                            "Parent organization '{}' requires MFA, but this policy does not",
                            related_org_name
                        ),
                        related_org_id,
                        related_org_name: related_org_name.to_string(),
                        field: Some("required".to_string()),
                    });
                }
                None
            }
            OrgPolicyType::Session => {
                let new: SessionPolicyConfig = serde_json::from_value(new_config.clone()).ok()?;
                let existing: SessionPolicyConfig =
                    serde_json::from_value(existing_config.clone()).ok()?;

                if is_parent && new.max_duration_hours > existing.max_duration_hours {
                    return Some(PolicyConflictWarning {
                        severity: "warning".to_string(),
                        message: format!(
                            "Session duration ({} hours) exceeds parent organization '{}' limit ({} hours)",
                            new.max_duration_hours, related_org_name, existing.max_duration_hours
                        ),
                        related_org_id,
                        related_org_name: related_org_name.to_string(),
                        field: Some("max_duration_hours".to_string()),
                    });
                }
                None
            }
            OrgPolicyType::IpRestriction => {
                // IP restrictions don't have simple less/more restrictive comparison
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_string_conversion() {
        assert_eq!(OrgPolicyType::Password.as_str(), "password");
        assert_eq!(OrgPolicyType::Mfa.as_str(), "mfa");
        assert_eq!(OrgPolicyType::Session.as_str(), "session");
        assert_eq!(OrgPolicyType::IpRestriction.as_str(), "ip_restriction");
    }
}
