//! SoD enforcement service for governance API.
//!
//! Provides preventive enforcement by checking assignments against SoD rules.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GovAssignmentTargetType, GovSodExemption, GovSodRule, GovSodSeverity};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{EntitlementSourceInfo, SodCheckResponse, SodCheckViolation};
use crate::services::effective_access_service::EntitlementSource;
use crate::services::EffectiveAccessService;

/// Result of an SoD check for a potential assignment.
#[derive(Debug, Clone)]
pub struct SodCheckResult {
    /// Whether the assignment is allowed.
    pub allowed: bool,
    /// List of violations that would be created.
    pub violations: Vec<SodViolationInfo>,
}

/// Information about a potential SoD violation.
#[derive(Debug, Clone)]
pub struct SodViolationInfo {
    /// Rule that would be violated.
    pub rule_id: Uuid,
    /// Rule name.
    pub rule_name: String,
    /// Severity level.
    pub severity: GovSodSeverity,
    /// Conflicting entitlement the user already has.
    pub conflicting_entitlement_id: Uuid,
    /// Whether an active exemption exists.
    pub has_exemption: bool,
    /// Source of the conflicting entitlement (F088: includes inheritance info).
    pub source: Option<EntitlementSourceInfo>,
}

/// Service for SoD enforcement operations.
pub struct SodEnforcementService {
    pool: PgPool,
    effective_access_service: EffectiveAccessService,
}

impl SodEnforcementService {
    /// Create a new SoD enforcement service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            effective_access_service: EffectiveAccessService::new(pool.clone()),
            pool,
        }
    }

    /// Check if an assignment would create SoD violations.
    ///
    /// Returns a result indicating whether the assignment is allowed and
    /// details of any violations found.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Tenant context
    /// * `user_id` - User receiving the entitlement
    /// * `entitlement_id` - Entitlement being assigned
    /// * `check_exemptions` - Whether to check for exemptions (true allows exempted violations)
    pub async fn check_assignment(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        check_exemptions: bool,
    ) -> Result<SodCheckResult> {
        // Find all active SoD rules involving this entitlement
        let rules = GovSodRule::find_active_by_entitlement(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)?;

        if rules.is_empty() {
            return Ok(SodCheckResult {
                allowed: true,
                violations: vec![],
            });
        }

        // Get user's effective entitlements (direct + inherited from groups + role hierarchy)
        let effective_access = self
            .effective_access_service
            .get_effective_access(tenant_id, user_id, None)
            .await?;

        // Build a map of entitlement_id -> sources for quick lookup
        let entitlement_sources: std::collections::HashMap<Uuid, Vec<&EntitlementSource>> =
            effective_access
                .entitlements
                .iter()
                .map(|e| (e.entitlement.id, e.sources.iter().collect()))
                .collect();

        let mut violations = Vec::new();

        for rule in rules {
            // Get the conflicting entitlement (the one the user might already have)
            let conflicting_id = rule
                .get_conflicting_entitlement(entitlement_id)
                .expect("Rule should contain the entitlement");

            // Check if user has the conflicting entitlement
            if let Some(sources) = entitlement_sources.get(&conflicting_id) {
                let has_exemption = if check_exemptions {
                    GovSodExemption::has_active_exemption(&self.pool, tenant_id, rule.id, user_id)
                        .await
                        .map_err(GovernanceError::Database)?
                } else {
                    false
                };

                // Convert the first source to API format (F088: include inheritance info)
                let source = sources.first().map(|s| Self::convert_source(s));

                violations.push(SodViolationInfo {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    conflicting_entitlement_id: conflicting_id,
                    has_exemption,
                    source,
                });
            }
        }

        // Assignment is allowed if there are no violations, or all violations are exempted
        let allowed = violations.is_empty() || violations.iter().all(|v| v.has_exemption);

        Ok(SodCheckResult {
            allowed,
            violations,
        })
    }

    /// Check assignment and return an error if not allowed.
    ///
    /// This is a convenience method for use in assignment creation.
    pub async fn enforce_assignment(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<()> {
        let result = self
            .check_assignment(tenant_id, user_id, entitlement_id, true)
            .await?;

        if !result.allowed {
            // Return the first non-exempted violation
            let violation = result
                .violations
                .iter()
                .find(|v| !v.has_exemption)
                .expect("Should have at least one non-exempted violation");

            return Err(GovernanceError::SodViolationBlocked {
                rule_id: violation.rule_id,
                rule_name: violation.rule_name.clone(),
                severity: format!("{:?}", violation.severity).to_lowercase(),
                conflicting_entitlement_id: violation.conflicting_entitlement_id,
            });
        }

        Ok(())
    }

    /// Check multiple assignments at once (for bulk operations).
    ///
    /// Returns a list of (user_id, entitlement_id) pairs that would violate SoD rules.
    pub async fn check_bulk_assignments(
        &self,
        tenant_id: Uuid,
        assignments: Vec<(Uuid, Uuid)>, // (user_id, entitlement_id)
    ) -> Result<Vec<(Uuid, Uuid, SodCheckResult)>> {
        let mut results = Vec::with_capacity(assignments.len());

        for (user_id, entitlement_id) in assignments {
            let check_result = self
                .check_assignment(tenant_id, user_id, entitlement_id, true)
                .await?;
            results.push((user_id, entitlement_id, check_result));
        }

        Ok(results)
    }

    /// Check if a specific target (user or group) would create violations.
    ///
    /// For groups, this checks all members of the group.
    pub async fn check_target_assignment(
        &self,
        tenant_id: Uuid,
        target_type: GovAssignmentTargetType,
        target_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<SodCheckResult> {
        match target_type {
            GovAssignmentTargetType::User => {
                self.check_assignment(tenant_id, target_id, entitlement_id, true)
                    .await
            }
            GovAssignmentTargetType::Group => {
                // For group assignments, we need to check all group members
                // Get group members
                let members = xavyo_db::models::GroupMembership::get_group_members(
                    &self.pool, tenant_id, target_id,
                )
                .await
                .map_err(GovernanceError::Database)?;

                let mut all_violations = Vec::new();
                let mut any_blocked = false;

                for member in members {
                    let result = self
                        .check_assignment(tenant_id, member.user_id, entitlement_id, true)
                        .await?;

                    if !result.allowed {
                        any_blocked = true;
                    }
                    all_violations.extend(result.violations);
                }

                Ok(SodCheckResult {
                    allowed: !any_blocked,
                    violations: all_violations,
                })
            }
        }
    }

    /// Convert internal check result to API response format.
    pub fn to_api_response(result: &SodCheckResult) -> SodCheckResponse {
        SodCheckResponse {
            allowed: result.allowed,
            violations: result
                .violations
                .iter()
                .map(|v| SodCheckViolation {
                    rule_id: v.rule_id,
                    rule_name: v.rule_name.clone(),
                    severity: v.severity,
                    conflicting_entitlement_id: v.conflicting_entitlement_id,
                    has_exemption: v.has_exemption,
                    source: v.source.clone(),
                })
                .collect(),
        }
    }

    /// Convert internal entitlement source to API format (F088).
    fn convert_source(source: &EntitlementSource) -> EntitlementSourceInfo {
        match source {
            EntitlementSource::Direct => EntitlementSourceInfo::Direct,
            EntitlementSource::Group {
                group_id,
                group_name,
            } => EntitlementSourceInfo::Group {
                group_id: *group_id,
                group_name: group_name.clone(),
            },
            EntitlementSource::Role { role_name } => EntitlementSourceInfo::Role {
                role_name: role_name.clone(),
            },
            EntitlementSource::GovRole {
                role_id,
                role_name,
                source_role_id,
                source_role_name,
                is_inherited,
            } => EntitlementSourceInfo::GovRole {
                role_id: *role_id,
                role_name: role_name.clone(),
                source_role_id: *source_role_id,
                source_role_name: source_role_name.clone(),
                is_inherited: *is_inherited,
            },
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
    fn test_sod_check_result_allowed() {
        let result = SodCheckResult {
            allowed: true,
            violations: vec![],
        };
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_sod_check_result_blocked() {
        let result = SodCheckResult {
            allowed: false,
            violations: vec![SodViolationInfo {
                rule_id: Uuid::new_v4(),
                rule_name: "Test Rule".to_string(),
                severity: GovSodSeverity::High,
                conflicting_entitlement_id: Uuid::new_v4(),
                has_exemption: false,
                source: None,
            }],
        };
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn test_sod_check_result_exempted() {
        let result = SodCheckResult {
            allowed: true,
            violations: vec![SodViolationInfo {
                rule_id: Uuid::new_v4(),
                rule_name: "Test Rule".to_string(),
                severity: GovSodSeverity::High,
                conflicting_entitlement_id: Uuid::new_v4(),
                has_exemption: true,
                source: None,
            }],
        };
        // Allowed because all violations are exempted
        assert!(result.allowed);
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_sod_check_result_with_gov_role_source() {
        let role_id = Uuid::new_v4();
        let source_role_id = Uuid::new_v4();
        let result = SodCheckResult {
            allowed: false,
            violations: vec![SodViolationInfo {
                rule_id: Uuid::new_v4(),
                rule_name: "Test Rule".to_string(),
                severity: GovSodSeverity::Critical,
                conflicting_entitlement_id: Uuid::new_v4(),
                has_exemption: false,
                source: Some(EntitlementSourceInfo::GovRole {
                    role_id,
                    role_name: "Junior Dev".to_string(),
                    source_role_id,
                    source_role_name: "Developer Base".to_string(),
                    is_inherited: true,
                }),
            }],
        };
        assert!(!result.allowed);
        let violation = &result.violations[0];
        if let Some(EntitlementSourceInfo::GovRole { is_inherited, .. }) = &violation.source {
            assert!(*is_inherited);
        } else {
            panic!("Expected GovRole source");
        }
    }
}
