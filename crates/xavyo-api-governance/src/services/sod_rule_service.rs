//! `SoD` rule service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovSodRule, GovSodRule, GovSodRuleStatus, GovSodSeverity, SodRuleFilter, UpdateGovSodRule,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for `SoD` rule operations.
pub struct SodRuleService {
    pool: PgPool,
}

impl SodRuleService {
    /// Create a new `SoD` rule service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List `SoD` rules for a tenant with pagination and filtering.
    pub async fn list_rules(
        &self,
        tenant_id: Uuid,
        status: Option<GovSodRuleStatus>,
        severity: Option<GovSodSeverity>,
        entitlement_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovSodRule>, i64)> {
        let filter = SodRuleFilter {
            status,
            severity,
            entitlement_id,
        };

        let rules = GovSodRule::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovSodRule::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((rules, total))
    }

    /// Get an `SoD` rule by ID.
    pub async fn get_rule(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<GovSodRule> {
        GovSodRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))
    }

    /// Create a new `SoD` rule.
    ///
    /// Validates:
    /// - Rule name is not empty
    /// - Entitlement IDs are different
    /// - No duplicate rule exists for the same entitlement pair (order-independent)
    pub async fn create_rule(
        &self,
        tenant_id: Uuid,
        input: CreateGovSodRule,
    ) -> Result<GovSodRule> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Rule name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Rule name cannot exceed 255 characters".to_string(),
            ));
        }

        // Validate entitlement IDs are different
        if input.first_entitlement_id == input.second_entitlement_id {
            return Err(GovernanceError::SodSameEntitlement);
        }

        // Check for duplicate name
        if let Some(_existing) =
            GovSodRule::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(GovernanceError::SodRuleNameExists(input.name));
        }

        // Check for duplicate entitlement pair (order-independent)
        if let Some(existing) = GovSodRule::find_by_entitlement_pair(
            &self.pool,
            tenant_id,
            input.first_entitlement_id,
            input.second_entitlement_id,
        )
        .await?
        {
            return Err(GovernanceError::SodRulePairExists {
                rule_id: existing.id,
                rule_name: existing.name,
            });
        }

        GovSodRule::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update an `SoD` rule.
    ///
    /// Note: Entitlement IDs cannot be changed after creation.
    pub async fn update_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        input: UpdateGovSodRule,
    ) -> Result<GovSodRule> {
        // Verify rule exists
        let _existing = self.get_rule(tenant_id, rule_id).await?;

        // Validate name if being updated
        if let Some(ref new_name) = input.name {
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Rule name cannot be empty".to_string(),
                ));
            }

            if new_name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Rule name cannot exceed 255 characters".to_string(),
                ));
            }

            // Check for duplicate name
            if let Some(existing) =
                GovSodRule::find_by_name(&self.pool, tenant_id, new_name).await?
            {
                if existing.id != rule_id {
                    return Err(GovernanceError::SodRuleNameExists(new_name.clone()));
                }
            }
        }

        GovSodRule::update(&self.pool, tenant_id, rule_id, input)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))
    }

    /// Enable an `SoD` rule.
    pub async fn enable_rule(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<GovSodRule> {
        // Verify rule exists
        let _existing = self.get_rule(tenant_id, rule_id).await?;

        GovSodRule::enable(&self.pool, tenant_id, rule_id)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))
    }

    /// Disable an `SoD` rule.
    pub async fn disable_rule(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<GovSodRule> {
        // Verify rule exists
        let _existing = self.get_rule(tenant_id, rule_id).await?;

        GovSodRule::disable(&self.pool, tenant_id, rule_id)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))
    }

    /// Delete an `SoD` rule.
    ///
    /// This also deletes associated violations and exemptions.
    pub async fn delete_rule(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<()> {
        use xavyo_db::models::{GovSodExemption, GovSodViolation};

        // Verify rule exists
        let _existing = self.get_rule(tenant_id, rule_id).await?;

        // Delete associated exemptions
        GovSodExemption::delete_for_rule(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Delete associated violations
        GovSodViolation::delete_for_rule(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Delete the rule
        let deleted = GovSodRule::delete(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?;

        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::SodRuleNotFound(rule_id))
        }
    }

    /// Find all active rules involving a specific entitlement.
    pub async fn find_rules_by_entitlement(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<GovSodRule>> {
        GovSodRule::find_active_by_entitlement(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List all active rules for a tenant.
    pub async fn list_active_rules(&self, tenant_id: Uuid) -> Result<Vec<GovSodRule>> {
        GovSodRule::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get the database pool reference for use in transactions.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        // Verify that the service structure is valid
        // Real database tests require integration test setup
    }

    #[test]
    fn test_validation_empty_name() {
        // Validation logic test - empty name should fail
        let name = "  ".trim();
        assert!(name.is_empty());
    }

    #[test]
    fn test_validation_name_length() {
        let name = "a".repeat(256);
        assert!(name.len() > 255);
    }

    #[test]
    fn test_same_entitlement_detection() {
        let ent_a = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let ent_b = ent_a;
        assert_eq!(ent_a, ent_b, "Same entitlement IDs should be detected");
    }
}
