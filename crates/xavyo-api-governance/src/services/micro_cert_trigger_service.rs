//! Micro-certification trigger rule service for governance API (F055).
//!
//! Handles CRUD operations for micro-certification trigger rules,
//! including scope validation and default rule management.

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    CreateMicroCertTrigger, GovApplication, GovEntitlement, GovMicroCertTrigger,
    MicroCertReviewerType, MicroCertScopeType, MicroCertTriggerFilter, UpdateMicroCertTrigger,
    User,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for micro-certification trigger rule operations.
pub struct MicroCertTriggerService {
    pool: PgPool,
}

impl MicroCertTriggerService {
    /// Create a new trigger service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // T055: CRUD methods
    // =========================================================================

    /// Create a new trigger rule.
    ///
    /// Validates:
    /// - Name uniqueness within tenant and trigger type
    /// - Scope ID exists (if application or entitlement scope)
    /// - Specific reviewer exists (if `specific_user` type)
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateMicroCertTrigger,
    ) -> Result<GovMicroCertTrigger> {
        // Check name uniqueness
        let existing = GovMicroCertTrigger::find_by_name(
            &self.pool,
            tenant_id,
            input.trigger_type,
            &input.name,
        )
        .await?;
        if existing.is_some() {
            return Err(GovernanceError::MicroCertTriggerNameExists(input.name));
        }

        // Validate scope (T057)
        let scope_type = input.scope_type.unwrap_or(MicroCertScopeType::Tenant);
        self.validate_scope(tenant_id, scope_type, input.scope_id)
            .await?;

        // Validate specific reviewer
        let reviewer_type = input
            .reviewer_type
            .unwrap_or(MicroCertReviewerType::UserManager);
        self.validate_reviewer(tenant_id, reviewer_type, input.specific_reviewer_id)
            .await?;

        // Validate fallback reviewer if provided
        if let Some(fallback_id) = input.fallback_reviewer_id {
            self.validate_user_exists(tenant_id, fallback_id).await?;
        }

        // Create the rule
        let rule = GovMicroCertTrigger::create(&self.pool, tenant_id, input).await?;

        // If this is a default rule, deactivate other defaults (T056)
        if rule.is_default {
            GovMicroCertTrigger::deactivate_other_defaults(
                &self.pool,
                tenant_id,
                rule.trigger_type,
                rule.id,
            )
            .await?;
        }

        info!(
            rule_id = %rule.id,
            name = %rule.name,
            trigger_type = ?rule.trigger_type,
            "Micro-certification trigger rule created"
        );

        Ok(rule)
    }

    /// Get a trigger rule by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMicroCertTrigger> {
        GovMicroCertTrigger::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::MicroCertTriggerNotFound(id))
    }

    /// Update a trigger rule.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateMicroCertTrigger,
    ) -> Result<GovMicroCertTrigger> {
        // Get existing rule
        let existing = self.get(tenant_id, id).await?;

        // Validate name uniqueness if changed
        if let Some(ref name) = input.name {
            if name != &existing.name {
                let duplicate = GovMicroCertTrigger::find_by_name(
                    &self.pool,
                    tenant_id,
                    existing.trigger_type,
                    name,
                )
                .await?;
                if duplicate.is_some() {
                    return Err(GovernanceError::MicroCertTriggerNameExists(name.clone()));
                }
            }
        }

        // Validate scope if changed
        let new_scope_type = input.scope_type.unwrap_or(existing.scope_type);
        let new_scope_id = if input.scope_id.is_some() {
            input.scope_id
        } else {
            existing.scope_id
        };
        self.validate_scope(tenant_id, new_scope_type, new_scope_id)
            .await?;

        // Validate reviewer if changed
        let new_reviewer_type = input.reviewer_type.unwrap_or(existing.reviewer_type);
        let new_specific_id = if input.specific_reviewer_id.is_some() {
            input.specific_reviewer_id
        } else {
            existing.specific_reviewer_id
        };
        self.validate_reviewer(tenant_id, new_reviewer_type, new_specific_id)
            .await?;

        // Validate fallback reviewer if changed
        if let Some(fallback_id) = input.fallback_reviewer_id {
            self.validate_user_exists(tenant_id, fallback_id).await?;
        }

        // Update the rule
        let updated = GovMicroCertTrigger::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::MicroCertTriggerNotFound(id))?;

        // If this is now a default rule, deactivate other defaults
        if updated.is_default {
            GovMicroCertTrigger::deactivate_other_defaults(
                &self.pool,
                tenant_id,
                updated.trigger_type,
                updated.id,
            )
            .await?;
        }

        info!(
            rule_id = %updated.id,
            name = %updated.name,
            "Micro-certification trigger rule updated"
        );

        Ok(updated)
    }

    /// Delete a trigger rule.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        // Check rule exists
        let rule = self.get(tenant_id, id).await?;

        // Delete the rule
        let deleted = GovMicroCertTrigger::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(GovernanceError::MicroCertTriggerNotFound(id));
        }

        info!(
            rule_id = %id,
            name = %rule.name,
            "Micro-certification trigger rule deleted"
        );

        Ok(())
    }

    /// List trigger rules with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &MicroCertTriggerFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMicroCertTrigger>, i64)> {
        let items =
            GovMicroCertTrigger::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        let total = GovMicroCertTrigger::count_by_tenant(&self.pool, tenant_id, filter).await?;
        Ok((items, total))
    }

    // =========================================================================
    // T056: Set default rule management
    // =========================================================================

    /// Set a rule as the default for its trigger type.
    ///
    /// This deactivates any other default rules for the same trigger type.
    pub async fn set_default(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMicroCertTrigger> {
        // Get the rule
        let rule = self.get(tenant_id, id).await?;

        if !rule.is_active {
            return Err(GovernanceError::MicroCertTriggerNotActive(id));
        }

        // If already default, return as-is
        if rule.is_default {
            return Ok(rule);
        }

        // Update to be default
        let input = UpdateMicroCertTrigger {
            is_default: Some(true),
            ..Default::default()
        };

        let updated = GovMicroCertTrigger::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::MicroCertTriggerNotFound(id))?;

        // Deactivate other defaults
        GovMicroCertTrigger::deactivate_other_defaults(
            &self.pool,
            tenant_id,
            updated.trigger_type,
            updated.id,
        )
        .await?;

        info!(
            rule_id = %updated.id,
            trigger_type = ?updated.trigger_type,
            "Micro-certification trigger rule set as default"
        );

        Ok(updated)
    }

    /// Enable a trigger rule.
    pub async fn enable(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMicroCertTrigger> {
        let input = UpdateMicroCertTrigger {
            is_active: Some(true),
            ..Default::default()
        };

        let updated = GovMicroCertTrigger::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::MicroCertTriggerNotFound(id))?;

        info!(rule_id = %id, "Micro-certification trigger rule enabled");

        Ok(updated)
    }

    /// Disable a trigger rule.
    ///
    /// If this is a default rule, it will no longer match events.
    pub async fn disable(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMicroCertTrigger> {
        let input = UpdateMicroCertTrigger {
            is_active: Some(false),
            ..Default::default()
        };

        let updated = GovMicroCertTrigger::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::MicroCertTriggerNotFound(id))?;

        info!(rule_id = %id, "Micro-certification trigger rule disabled");

        Ok(updated)
    }

    // =========================================================================
    // T057: Scope validation
    // =========================================================================

    /// Validate that the scope is correctly configured.
    async fn validate_scope(
        &self,
        tenant_id: Uuid,
        scope_type: MicroCertScopeType,
        scope_id: Option<Uuid>,
    ) -> Result<()> {
        match scope_type {
            MicroCertScopeType::Tenant => {
                // Tenant scope must not have scope_id
                if scope_id.is_some() {
                    return Err(GovernanceError::Validation(
                        "scope_id must be null for tenant scope".to_string(),
                    ));
                }
            }
            MicroCertScopeType::Application => {
                // Application scope must have scope_id pointing to valid application
                let app_id = scope_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "scope_id is required for application scope".to_string(),
                    )
                })?;
                let app = GovApplication::find_by_id(&self.pool, tenant_id, app_id).await?;
                if app.is_none() {
                    return Err(GovernanceError::ApplicationNotFound(app_id));
                }
            }
            MicroCertScopeType::Entitlement => {
                // Entitlement scope must have scope_id pointing to valid entitlement
                let ent_id = scope_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "scope_id is required for entitlement scope".to_string(),
                    )
                })?;
                let ent = GovEntitlement::find_by_id(&self.pool, tenant_id, ent_id).await?;
                if ent.is_none() {
                    return Err(GovernanceError::EntitlementNotFound(ent_id));
                }
            }
        }
        Ok(())
    }

    /// Validate that the reviewer configuration is correct.
    async fn validate_reviewer(
        &self,
        tenant_id: Uuid,
        reviewer_type: MicroCertReviewerType,
        specific_reviewer_id: Option<Uuid>,
    ) -> Result<()> {
        if reviewer_type == MicroCertReviewerType::SpecificUser {
            let user_id = specific_reviewer_id.ok_or_else(|| {
                GovernanceError::Validation(
                    "specific_reviewer_id is required for specific_user reviewer type".to_string(),
                )
            })?;
            self.validate_user_exists(tenant_id, user_id).await?;
        }
        Ok(())
    }

    /// Validate that a user exists in the tenant.
    async fn validate_user_exists(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        // Use find_by_id_in_tenant for defense-in-depth
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id).await?;
        match user {
            Some(_) => Ok(()),
            None => Err(GovernanceError::UserNotFound(user_id)),
        }
    }

    /// Get reference to the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_micro_cert_trigger_default() {
        let update = UpdateMicroCertTrigger::default();
        assert!(update.name.is_none());
        assert!(update.is_active.is_none());
        assert!(update.is_default.is_none());
    }
}
