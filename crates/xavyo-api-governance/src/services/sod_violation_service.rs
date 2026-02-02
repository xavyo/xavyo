//! SoD violation service for governance API.
//!
//! Provides detective enforcement by scanning for and managing SoD violations.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovSodViolation, GovSodRule, GovSodViolation, GovViolationStatus, SodViolationFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{ScanRuleResponse, SodViolationResponse};
use crate::services::EffectiveAccessService;

/// Result of scanning a rule for violations.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Total users checked.
    pub users_checked: usize,
    /// Violations found.
    pub violations_found: usize,
    /// Newly created violations.
    pub violations_created: usize,
    /// Existing violations (already tracked).
    pub existing_violations: usize,
}

/// Service for SoD violation operations.
pub struct SodViolationService {
    pool: PgPool,
    #[allow(dead_code)]
    effective_access_service: EffectiveAccessService,
}

impl SodViolationService {
    /// Create a new SoD violation service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            effective_access_service: EffectiveAccessService::new(pool.clone()),
            pool,
        }
    }

    /// List violations for a tenant with pagination and filtering.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_violations(
        &self,
        tenant_id: Uuid,
        rule_id: Option<Uuid>,
        user_id: Option<Uuid>,
        status: Option<GovViolationStatus>,
        detected_after: Option<chrono::DateTime<chrono::Utc>>,
        detected_before: Option<chrono::DateTime<chrono::Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovSodViolation>, i64)> {
        let filter = SodViolationFilter {
            rule_id,
            user_id,
            status,
            detected_after,
            detected_before,
        };

        let violations =
            GovSodViolation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovSodViolation::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((violations, total))
    }

    /// Get a violation by ID.
    pub async fn get_violation(
        &self,
        tenant_id: Uuid,
        violation_id: Uuid,
    ) -> Result<GovSodViolation> {
        GovSodViolation::find_by_id(&self.pool, tenant_id, violation_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodViolationNotFound(violation_id))
    }

    /// Scan for violations of a specific rule.
    ///
    /// Finds all users who have both conflicting entitlements and creates
    /// violation records for them.
    pub async fn scan_rule_violations(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<ScanResult> {
        // Get the rule to find conflicting entitlements
        let rule = GovSodRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodRuleNotFound(rule_id))?;

        // Find all users with both entitlements (direct assignments only for now)
        let violating_users = GovSodViolation::find_users_violating_rule(
            &self.pool,
            tenant_id,
            rule.first_entitlement_id,
            rule.second_entitlement_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let users_checked = violating_users.len();
        let mut violations_created = 0;
        let mut existing_violations = 0;

        // Create violations for each user
        for user_id in violating_users {
            let input = CreateGovSodViolation {
                rule_id,
                user_id,
                first_assignment_id: None, // Could be enhanced to track specific assignments
                second_assignment_id: None,
            };

            // Check if violation already exists
            if let Some(_existing) =
                GovSodViolation::find_active_for_rule_user(&self.pool, tenant_id, rule_id, user_id)
                    .await
                    .map_err(GovernanceError::Database)?
            {
                existing_violations += 1;
            } else {
                GovSodViolation::create(&self.pool, tenant_id, input)
                    .await
                    .map_err(GovernanceError::Database)?;
                violations_created += 1;
            }
        }

        Ok(ScanResult {
            users_checked,
            violations_found: users_checked,
            violations_created,
            existing_violations,
        })
    }

    /// Scan all active rules in a tenant for violations.
    pub async fn scan_all_rules(&self, tenant_id: Uuid) -> Result<Vec<(Uuid, ScanResult)>> {
        // Get all active rules
        let rules = GovSodRule::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        let mut results = Vec::with_capacity(rules.len());

        for rule in rules {
            let scan_result = self.scan_rule_violations(tenant_id, rule.id).await?;
            results.push((rule.id, scan_result));
        }

        Ok(results)
    }

    /// Remediate a violation (mark as resolved).
    pub async fn remediate_violation(
        &self,
        tenant_id: Uuid,
        violation_id: Uuid,
        remediated_by: Uuid,
        notes: Option<String>,
    ) -> Result<GovSodViolation> {
        // Check if violation exists and is not already remediated
        let existing = self.get_violation(tenant_id, violation_id).await?;

        if existing.is_remediated() {
            return Err(GovernanceError::SodViolationAlreadyRemediated(violation_id));
        }

        GovSodViolation::remediate(&self.pool, tenant_id, violation_id, remediated_by, notes)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodViolationNotFound(violation_id))
    }

    /// Mark violation as exempted (when an exemption is granted).
    pub async fn mark_violation_exempted(
        &self,
        tenant_id: Uuid,
        violation_id: Uuid,
    ) -> Result<GovSodViolation> {
        GovSodViolation::mark_exempted(&self.pool, tenant_id, violation_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodViolationNotFound(violation_id))
    }

    /// Reactivate violation (when exemption expires/revoked).
    pub async fn reactivate_violation(
        &self,
        tenant_id: Uuid,
        violation_id: Uuid,
    ) -> Result<GovSodViolation> {
        GovSodViolation::reactivate(&self.pool, tenant_id, violation_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::SodViolationNotFound(violation_id))
    }

    /// Check and auto-remediate violations when an assignment is revoked.
    ///
    /// If a user no longer has one of the conflicting entitlements,
    /// the violation is automatically remediated.
    pub async fn check_auto_remediation(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<GovSodViolation>> {
        // Find all active rules involving this entitlement
        let rules = GovSodRule::find_active_by_entitlement(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)?;

        let mut remediated = Vec::new();

        for rule in rules {
            // Check if there's an active violation for this rule and user
            if let Some(violation) =
                GovSodViolation::find_active_for_rule_user(&self.pool, tenant_id, rule.id, user_id)
                    .await
                    .map_err(GovernanceError::Database)?
            {
                // Remediate it (the user no longer has the entitlement)
                if let Some(remediated_violation) = GovSodViolation::remediate(
                    &self.pool,
                    tenant_id,
                    violation.id,
                    Uuid::nil(), // System remediation
                    Some("Auto-remediated: entitlement assignment revoked".to_string()),
                )
                .await
                .map_err(GovernanceError::Database)?
                {
                    remediated.push(remediated_violation);
                }
            }
        }

        Ok(remediated)
    }

    /// Count active violations for a rule.
    pub async fn count_active_violations(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<i64> {
        GovSodViolation::count_active_for_rule(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Convert internal scan result to API response format.
    pub async fn scan_to_api_response(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        result: &ScanResult,
    ) -> Result<ScanRuleResponse> {
        let total_active = self.count_active_violations(tenant_id, rule_id).await?;
        Ok(ScanRuleResponse {
            rule_id,
            violations_detected: result.violations_created as i64,
            total_active_violations: total_active,
        })
    }

    /// Convert database model to API response format.
    pub fn to_api_response(violation: &GovSodViolation) -> SodViolationResponse {
        SodViolationResponse {
            id: violation.id,
            rule_id: violation.rule_id,
            user_id: violation.user_id,
            first_assignment_id: violation.first_assignment_id,
            second_assignment_id: violation.second_assignment_id,
            status: violation.status,
            detected_at: violation.detected_at,
            remediated_at: violation.remediated_at,
            remediated_by: violation.remediated_by,
            remediation_notes: violation.remediation_notes.clone(),
            created_at: violation.created_at,
            updated_at: violation.updated_at,
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
    fn test_scan_result() {
        let result = ScanResult {
            users_checked: 100,
            violations_found: 5,
            violations_created: 3,
            existing_violations: 2,
        };

        assert_eq!(result.users_checked, 100);
        assert_eq!(result.violations_found, 5);
        assert_eq!(result.violations_created, 3);
        assert_eq!(result.existing_violations, 2);
    }

    #[test]
    fn test_scan_result_fields() {
        let result = ScanResult {
            users_checked: 50,
            violations_found: 3,
            violations_created: 2,
            existing_violations: 1,
        };

        // scan_to_api_response requires async DB access, so just test ScanResult fields
        assert_eq!(result.users_checked, 50);
        assert_eq!(result.violations_found, 3);
        assert_eq!(result.violations_created, 2);
        assert_eq!(result.existing_violations, 1);
    }
}
