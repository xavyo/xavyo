//! Escalation policy service for governance API (F054).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateEscalationLevel, CreateEscalationPolicy, EscalationPolicyFilter, GovEscalationLevel,
    GovEscalationPolicy, UpdateEscalationPolicy,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for escalation policy operations.
pub struct EscalationPolicyService {
    pool: PgPool,
}

impl EscalationPolicyService {
    /// Create a new escalation policy service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List escalation policies for a tenant with pagination and filtering.
    pub async fn list_policies(
        &self,
        tenant_id: Uuid,
        is_active: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovEscalationPolicy>, i64)> {
        let filter = EscalationPolicyFilter { is_active };

        let policies =
            GovEscalationPolicy::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovEscalationPolicy::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((policies, total))
    }

    /// Get an escalation policy by ID.
    pub async fn get_policy(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<GovEscalationPolicy> {
        GovEscalationPolicy::find_by_id(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::EscalationPolicyNotFound(policy_id))
    }

    /// Get the active default policy for a tenant.
    pub async fn get_active_default(&self, tenant_id: Uuid) -> Result<Option<GovEscalationPolicy>> {
        GovEscalationPolicy::find_active_default(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Create a new escalation policy.
    pub async fn create_policy(
        &self,
        tenant_id: Uuid,
        input: CreateEscalationPolicy,
    ) -> Result<GovEscalationPolicy> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Policy name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Policy name cannot exceed 255 characters".to_string(),
            ));
        }

        // Validate timeout
        if input.default_timeout_secs < 60 {
            return Err(GovernanceError::Validation(
                "Timeout must be at least 60 seconds".to_string(),
            ));
        }

        // Check for duplicate name
        if GovEscalationPolicy::find_by_name(&self.pool, tenant_id, &input.name)
            .await
            .map_err(GovernanceError::Database)?
            .is_some()
        {
            return Err(GovernanceError::EscalationPolicyNameExists(
                input.name.clone(),
            ));
        }

        GovEscalationPolicy::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update an escalation policy.
    pub async fn update_policy(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        input: UpdateEscalationPolicy,
    ) -> Result<GovEscalationPolicy> {
        // Validate name if provided
        if let Some(ref name) = input.name {
            if name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Policy name cannot be empty".to_string(),
                ));
            }

            // Check for duplicate name (excluding current)
            if let Some(existing) =
                GovEscalationPolicy::find_by_name(&self.pool, tenant_id, name).await?
            {
                if existing.id != policy_id {
                    return Err(GovernanceError::EscalationPolicyNameExists(name.clone()));
                }
            }
        }

        // Validate timeout if provided
        if let Some(timeout_secs) = input.default_timeout_secs {
            if timeout_secs < 60 {
                return Err(GovernanceError::Validation(
                    "Timeout must be at least 60 seconds".to_string(),
                ));
            }
        }

        GovEscalationPolicy::update(&self.pool, tenant_id, policy_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::EscalationPolicyNotFound(policy_id))
    }

    /// Delete an escalation policy.
    pub async fn delete_policy(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<bool> {
        // First delete all levels associated with this policy
        GovEscalationLevel::delete_by_policy(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)?;

        GovEscalationPolicy::delete(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Set a policy as the active default (deactivates others).
    pub async fn set_active_default(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<GovEscalationPolicy> {
        // First, verify the policy exists
        let _policy = self.get_policy(tenant_id, policy_id).await?;

        // Deactivate all other policies
        GovEscalationPolicy::deactivate_others(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Activate this policy
        let input = UpdateEscalationPolicy {
            name: None,
            description: None,
            default_timeout_secs: None,
            warning_threshold_secs: None,
            final_fallback: None,
            is_active: Some(true),
        };

        GovEscalationPolicy::update(&self.pool, tenant_id, policy_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::EscalationPolicyNotFound(policy_id))
    }

    /// Get policy with its escalation levels.
    pub async fn get_policy_with_levels(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<(GovEscalationPolicy, Vec<GovEscalationLevel>)> {
        let policy = self.get_policy(tenant_id, policy_id).await?;
        let levels = GovEscalationLevel::find_by_policy(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)?;
        Ok((policy, levels))
    }

    /// Add an escalation level to a policy.
    pub async fn add_level(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        input: CreateEscalationLevel,
    ) -> Result<GovEscalationLevel> {
        // Verify policy exists
        self.get_policy(tenant_id, policy_id).await?;

        // Validate timeout
        if input.timeout_secs < 60 {
            return Err(GovernanceError::Validation(
                "Level timeout must be at least 60 seconds".to_string(),
            ));
        }

        GovEscalationLevel::create_for_policy(&self.pool, tenant_id, policy_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Remove an escalation level.
    pub async fn remove_level(&self, tenant_id: Uuid, level_id: Uuid) -> Result<bool> {
        GovEscalationLevel::delete(&self.pool, tenant_id, level_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Replace all escalation levels for a policy.
    pub async fn replace_levels(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        levels: Vec<CreateEscalationLevel>,
    ) -> Result<Vec<GovEscalationLevel>> {
        // Verify policy exists
        self.get_policy(tenant_id, policy_id).await?;

        // Validate all levels
        for level in &levels {
            if level.timeout_secs < 60 {
                return Err(GovernanceError::Validation(
                    "Level timeout must be at least 60 seconds".to_string(),
                ));
            }
        }

        // Delete existing levels
        GovEscalationLevel::delete_by_policy(&self.pool, tenant_id, policy_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Create new levels
        GovEscalationLevel::create_batch_for_policy(&self.pool, tenant_id, policy_id, levels)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get reference to the database pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
