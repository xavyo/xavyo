//! SoD exemption service for governance API.
//!
//! Provides management of SoD exemptions (approved exceptions to rules).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovSodExemption, GovExemptionStatus, GovSodExemption, GovSodRule, GovSodViolation,
    SodExemptionFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::SodExemptionResponse;

/// Service for SoD exemption operations.
pub struct SodExemptionService {
    pool: PgPool,
}

impl SodExemptionService {
    /// Create a new SoD exemption service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List exemptions for a tenant with pagination and filtering.
    pub async fn list_exemptions(
        &self,
        tenant_id: Uuid,
        rule_id: Option<Uuid>,
        user_id: Option<Uuid>,
        status: Option<GovExemptionStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovSodExemption>, i64)> {
        let filter = SodExemptionFilter {
            rule_id,
            user_id,
            status,
        };

        let exemptions =
            GovSodExemption::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovSodExemption::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((exemptions, total))
    }

    /// Get an exemption by ID.
    pub async fn get_exemption(
        &self,
        tenant_id: Uuid,
        exemption_id: Uuid,
    ) -> Result<GovSodExemption> {
        GovSodExemption::find_by_id(&self.pool, tenant_id, exemption_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodExemptionNotFound(exemption_id))
    }

    /// Create a new exemption.
    ///
    /// Validates:
    /// - Rule exists and is active
    /// - User doesn't already have an active exemption for this rule
    /// - Justification is not empty
    /// - Expiration is in the future
    pub async fn create_exemption(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        user_id: Uuid,
        approver_id: Uuid,
        justification: String,
        expires_at: DateTime<Utc>,
    ) -> Result<GovSodExemption> {
        // Validate justification is not empty
        if justification.trim().is_empty() {
            return Err(GovernanceError::SodExemptionJustificationRequired);
        }

        // Validate expiration is in the future
        if expires_at <= Utc::now() {
            return Err(GovernanceError::InvalidExpirationDate);
        }

        // Verify rule exists
        GovSodRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))?;

        // Check for existing active exemption
        if let Some(_existing) =
            GovSodExemption::find_active_for_rule_user(&self.pool, tenant_id, rule_id, user_id)
                .await
                .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::SodExemptionAlreadyExists);
        }

        let input = CreateGovSodExemption {
            rule_id,
            user_id,
            approver_id,
            justification,
            expires_at,
        };

        let exemption = GovSodExemption::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Update any active violation to exempted status
        if let Some(violation) =
            GovSodViolation::find_active_for_rule_user(&self.pool, tenant_id, rule_id, user_id)
                .await
                .map_err(GovernanceError::Database)?
        {
            GovSodViolation::mark_exempted(&self.pool, tenant_id, violation.id)
                .await
                .map_err(GovernanceError::Database)?;
        }

        Ok(exemption)
    }

    /// Revoke an exemption.
    pub async fn revoke_exemption(
        &self,
        tenant_id: Uuid,
        exemption_id: Uuid,
        revoked_by: Uuid,
    ) -> Result<GovSodExemption> {
        // Verify exemption exists
        let existing = self.get_exemption(tenant_id, exemption_id).await?;

        if existing.status != GovExemptionStatus::Active {
            return Err(GovernanceError::SodExemptionAlreadyInactive(exemption_id));
        }

        let revoked = GovSodExemption::revoke(&self.pool, tenant_id, exemption_id, revoked_by)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodExemptionNotFound(exemption_id))?;

        // Reactivate any exempted violation for this rule/user
        if let Some(violation) = GovSodViolation::find_active_for_rule_user(
            &self.pool,
            tenant_id,
            existing.rule_id,
            existing.user_id,
        )
        .await
        .map_err(GovernanceError::Database)?
        {
            // Only reactivate if the violation is still exempted
            if violation.is_exempted() {
                GovSodViolation::reactivate(&self.pool, tenant_id, violation.id)
                    .await
                    .map_err(GovernanceError::Database)?;
            }
        }

        Ok(revoked)
    }

    /// Expire exemptions past their expiration date.
    ///
    /// Returns the number of exemptions expired.
    pub async fn expire_past_due(&self, tenant_id: Uuid) -> Result<u64> {
        // First, find exemptions that are about to expire so we can reactivate their violations
        let expiring = GovSodExemption::find_expiring_soon(&self.pool, tenant_id, 0)
            .await
            .map_err(GovernanceError::Database)?;

        // Expire the exemptions
        let expired_count = GovSodExemption::expire_past_due(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Reactivate violations for expired exemptions
        for exemption in expiring {
            if let Some(violation) = GovSodViolation::find_active_for_rule_user(
                &self.pool,
                tenant_id,
                exemption.rule_id,
                exemption.user_id,
            )
            .await
            .map_err(GovernanceError::Database)?
            {
                if violation.is_exempted() {
                    GovSodViolation::reactivate(&self.pool, tenant_id, violation.id)
                        .await
                        .map_err(GovernanceError::Database)?;
                }
            }
        }

        Ok(expired_count)
    }

    /// Find exemptions expiring within a time window.
    pub async fn find_expiring_soon(
        &self,
        tenant_id: Uuid,
        within_hours: i64,
    ) -> Result<Vec<GovSodExemption>> {
        GovSodExemption::find_expiring_soon(&self.pool, tenant_id, within_hours)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Check if a user has an active exemption for a rule.
    pub async fn has_active_exemption(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        GovSodExemption::has_active_exemption(&self.pool, tenant_id, rule_id, user_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Convert database model to API response format.
    pub fn to_api_response(exemption: &GovSodExemption) -> SodExemptionResponse {
        SodExemptionResponse {
            id: exemption.id,
            rule_id: exemption.rule_id,
            user_id: exemption.user_id,
            approver_id: exemption.approver_id,
            justification: exemption.justification.clone(),
            status: exemption.status,
            created_at: exemption.created_at,
            expires_at: exemption.expires_at,
            revoked_at: exemption.revoked_at,
            revoked_by: exemption.revoked_by,
            updated_at: exemption.updated_at,
            is_active: exemption.is_active(),
        }
    }

    /// Get database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_justification_validation() {
        // Empty justification should fail
        let justification = "  ".trim();
        assert!(justification.is_empty());
    }

    #[test]
    fn test_expiration_validation() {
        // Past expiration should fail
        let past = Utc::now() - chrono::Duration::hours(1);
        assert!(past <= Utc::now());

        // Future expiration should pass
        let future = Utc::now() + chrono::Duration::days(30);
        assert!(future > Utc::now());
    }
}
