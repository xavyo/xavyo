//! `SoD` validation service for preventive and detective validation.
//!
//! This module provides the `SodValidationService` for checking entitlement
//! assignments against `SoD` rules and detecting existing violations.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::Result;
use crate::services::sod::{SodRule, SodRuleStore};
use crate::services::sod_exemption::SodExemptionStore;
use crate::types::{SodConflictType, SodRuleId, SodSeverity, SodViolationId, SodViolationStatus};

// ============================================================================
// Domain Types
// ============================================================================

/// An `SoD` violation detected in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolation {
    /// Unique identifier.
    pub id: SodViolationId,
    /// Tenant this violation belongs to.
    pub tenant_id: Uuid,
    /// The rule that was violated.
    pub rule_id: SodRuleId,
    /// The user who has the violation.
    pub user_id: Uuid,
    /// The specific conflicting entitlements.
    pub entitlement_ids: Vec<Uuid>,
    /// When the violation was detected.
    pub detected_at: DateTime<Utc>,
    /// When the violation was resolved (if resolved).
    pub resolved_at: Option<DateTime<Utc>>,
    /// Violation status.
    pub status: SodViolationStatus,
}

/// Information about a single `SoD` violation for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolationInfo {
    /// The rule that was violated.
    pub rule_id: SodRuleId,
    /// Name of the violated rule.
    pub rule_name: String,
    /// The specific entitlements causing the conflict.
    pub conflicting_entitlements: Vec<Uuid>,
    /// Severity of the violation.
    pub severity: SodSeverity,
    /// Human-readable violation message.
    pub message: String,
}

/// Result of preventive validation.
#[derive(Debug, Clone, Default)]
pub struct PreventiveValidationResult {
    /// Whether the assignment is allowed.
    pub is_valid: bool,
    /// List of violations if not valid.
    pub violations: Vec<SodViolationInfo>,
}

impl PreventiveValidationResult {
    /// Create a successful validation result.
    #[must_use]
    pub fn success() -> Self {
        Self {
            is_valid: true,
            violations: vec![],
        }
    }

    /// Create a failed validation result.
    #[must_use]
    pub fn failure(violations: Vec<SodViolationInfo>) -> Self {
        Self {
            is_valid: violations.is_empty(),
            violations,
        }
    }
}

/// Result of detective scan for a single user.
#[derive(Debug, Clone, Default)]
pub struct UserViolationReport {
    /// The user with violations.
    pub user_id: Uuid,
    /// List of violations.
    pub violations: Vec<SodViolationInfo>,
}

/// Result of detective scan for a rule.
#[derive(Debug, Clone, Default)]
pub struct RuleScanResult {
    /// The rule that was scanned.
    pub rule_id: SodRuleId,
    /// Name of the rule.
    pub rule_name: String,
    /// Total violations found.
    pub total_violations: usize,
    /// Per-user violation details.
    pub user_violations: Vec<UserViolationReport>,
}

/// Result of full detective scan.
#[derive(Debug, Clone, Default)]
pub struct DetectiveScanResult {
    /// Number of rules scanned.
    pub total_rules_scanned: usize,
    /// Total violations found.
    pub total_violations_found: usize,
    /// Total violations auto-resolved.
    pub total_violations_resolved: usize,
    /// Per-rule results.
    pub rule_results: Vec<RuleScanResult>,
}

// ============================================================================
// Store Trait
// ============================================================================

/// Trait for `SoD` violation storage backends.
#[async_trait::async_trait]
pub trait SodViolationStore: Send + Sync {
    /// Get a violation by ID.
    async fn get(&self, tenant_id: Uuid, id: SodViolationId) -> Result<Option<SodViolation>>;

    /// Get active violation for a user+rule.
    async fn get_active(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<Option<SodViolation>>;

    /// List all active violations for a tenant.
    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodViolation>>;

    /// List all violations for a user.
    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodViolation>>;

    /// List all violations for a rule.
    async fn list_by_rule(&self, tenant_id: Uuid, rule_id: SodRuleId) -> Result<Vec<SodViolation>>;

    /// Create or update a violation.
    async fn upsert(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
        entitlement_ids: Vec<Uuid>,
    ) -> Result<SodViolation>;

    /// Resolve a violation.
    async fn resolve(&self, tenant_id: Uuid, id: SodViolationId) -> Result<bool>;

    /// Resolve all violations for a user+rule.
    async fn resolve_by_user_rule(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<bool>;
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory `SoD` violation store for testing.
#[derive(Debug, Default)]
pub struct InMemorySodViolationStore {
    violations: Arc<RwLock<HashMap<Uuid, SodViolation>>>,
}

impl InMemorySodViolationStore {
    /// Create a new in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            violations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.violations.write().await.clear();
    }

    /// Get violation count.
    pub async fn count(&self) -> usize {
        self.violations.read().await.len()
    }
}

#[async_trait::async_trait]
impl SodViolationStore for InMemorySodViolationStore {
    async fn get(&self, tenant_id: Uuid, id: SodViolationId) -> Result<Option<SodViolation>> {
        let violations = self.violations.read().await;
        Ok(violations
            .get(&id.into_inner())
            .filter(|v| v.tenant_id == tenant_id)
            .cloned())
    }

    async fn get_active(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<Option<SodViolation>> {
        let violations = self.violations.read().await;
        Ok(violations
            .values()
            .find(|v| {
                v.tenant_id == tenant_id
                    && v.rule_id == rule_id
                    && v.user_id == user_id
                    && v.status == SodViolationStatus::Active
            })
            .cloned())
    }

    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodViolation>> {
        let violations = self.violations.read().await;
        Ok(violations
            .values()
            .filter(|v| v.tenant_id == tenant_id && v.status == SodViolationStatus::Active)
            .cloned()
            .collect())
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodViolation>> {
        let violations = self.violations.read().await;
        Ok(violations
            .values()
            .filter(|v| {
                v.tenant_id == tenant_id
                    && v.user_id == user_id
                    && v.status == SodViolationStatus::Active
            })
            .cloned()
            .collect())
    }

    async fn list_by_rule(&self, tenant_id: Uuid, rule_id: SodRuleId) -> Result<Vec<SodViolation>> {
        let violations = self.violations.read().await;
        Ok(violations
            .values()
            .filter(|v| {
                v.tenant_id == tenant_id
                    && v.rule_id == rule_id
                    && v.status == SodViolationStatus::Active
            })
            .cloned()
            .collect())
    }

    async fn upsert(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
        entitlement_ids: Vec<Uuid>,
    ) -> Result<SodViolation> {
        let mut violations = self.violations.write().await;

        // Check for existing active violation
        if let Some(existing) = violations.values_mut().find(|v| {
            v.tenant_id == tenant_id
                && v.rule_id == rule_id
                && v.user_id == user_id
                && v.status == SodViolationStatus::Active
        }) {
            existing.entitlement_ids = entitlement_ids;
            return Ok(existing.clone());
        }

        // Create new violation
        let violation = SodViolation {
            id: SodViolationId::new(),
            tenant_id,
            rule_id,
            user_id,
            entitlement_ids,
            detected_at: Utc::now(),
            resolved_at: None,
            status: SodViolationStatus::Active,
        };

        violations.insert(violation.id.into_inner(), violation.clone());
        Ok(violation)
    }

    async fn resolve(&self, tenant_id: Uuid, id: SodViolationId) -> Result<bool> {
        let mut violations = self.violations.write().await;

        if let Some(violation) = violations.get_mut(&id.into_inner()) {
            if violation.tenant_id != tenant_id {
                return Ok(false);
            }
            violation.status = SodViolationStatus::Resolved;
            violation.resolved_at = Some(Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn resolve_by_user_rule(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<bool> {
        let mut violations = self.violations.write().await;

        let mut resolved = false;
        for violation in violations.values_mut() {
            if violation.tenant_id == tenant_id
                && violation.rule_id == rule_id
                && violation.user_id == user_id
                && violation.status == SodViolationStatus::Active
            {
                violation.status = SodViolationStatus::Resolved;
                violation.resolved_at = Some(Utc::now());
                resolved = true;
            }
        }

        Ok(resolved)
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service for validating entitlement assignments against `SoD` rules.
pub struct SodValidationService {
    rule_store: Arc<dyn SodRuleStore>,
    violation_store: Arc<dyn SodViolationStore>,
    exemption_store: Arc<dyn SodExemptionStore>,
}

impl SodValidationService {
    /// Create a new `SoD` validation service.
    pub fn new(
        rule_store: Arc<dyn SodRuleStore>,
        violation_store: Arc<dyn SodViolationStore>,
        exemption_store: Arc<dyn SodExemptionStore>,
    ) -> Self {
        Self {
            rule_store,
            violation_store,
            exemption_store,
        }
    }

    /// Check if an exclusive rule is violated.
    fn check_exclusive_violation(
        rule: &SodRule,
        user_entitlements: &[Uuid],
        proposed_entitlement: Uuid,
    ) -> Option<SodViolationInfo> {
        let mut user_set: Vec<Uuid> = user_entitlements.to_vec();
        user_set.push(proposed_entitlement);

        let matching: Vec<Uuid> = rule
            .entitlement_ids
            .iter()
            .filter(|e| user_set.contains(e))
            .copied()
            .collect();

        if matching.len() >= 2 {
            Some(SodViolationInfo {
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                conflicting_entitlements: matching,
                severity: rule.severity,
                message: format!(
                    "User cannot have both entitlements (exclusive rule '{}')",
                    rule.name
                ),
            })
        } else {
            None
        }
    }

    /// Check if a cardinality rule is violated.
    fn check_cardinality_violation(
        rule: &SodRule,
        user_entitlements: &[Uuid],
        proposed_entitlement: Uuid,
    ) -> Option<SodViolationInfo> {
        let max_count = rule.max_count.unwrap_or(1) as usize;
        let mut user_set: Vec<Uuid> = user_entitlements.to_vec();
        user_set.push(proposed_entitlement);

        let matching: Vec<Uuid> = rule
            .entitlement_ids
            .iter()
            .filter(|e| user_set.contains(e))
            .copied()
            .collect();

        if matching.len() > max_count {
            Some(SodViolationInfo {
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                conflicting_entitlements: matching.clone(),
                severity: rule.severity,
                message: format!(
                    "User can have at most {} of these entitlements, has {} (rule '{}')",
                    max_count,
                    matching.len(),
                    rule.name
                ),
            })
        } else {
            None
        }
    }

    /// Check if an inclusive rule is violated.
    fn check_inclusive_violation(
        rule: &SodRule,
        user_entitlements: &[Uuid],
        proposed_entitlement: Uuid,
    ) -> Option<SodViolationInfo> {
        let mut user_set: Vec<Uuid> = user_entitlements.to_vec();
        user_set.push(proposed_entitlement);

        let matching: Vec<Uuid> = rule
            .entitlement_ids
            .iter()
            .filter(|e| user_set.contains(e))
            .copied()
            .collect();

        // Inclusive: must have all or none
        if !matching.is_empty() && matching.len() < rule.entitlement_ids.len() {
            let missing: Vec<Uuid> = rule
                .entitlement_ids
                .iter()
                .filter(|e| !user_set.contains(e))
                .copied()
                .collect();

            Some(SodViolationInfo {
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                conflicting_entitlements: matching,
                severity: rule.severity,
                message: format!(
                    "User must have all {} entitlements together, missing {} (rule '{}')",
                    rule.entitlement_ids.len(),
                    missing.len(),
                    rule.name
                ),
            })
        } else {
            None
        }
    }

    /// Validate a proposed entitlement assignment.
    pub async fn validate_preventive(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        proposed_entitlement_id: Uuid,
        current_entitlements: &[Uuid],
    ) -> Result<PreventiveValidationResult> {
        // Get all rules that reference the proposed entitlement or any current entitlements
        let mut all_entitlements = current_entitlements.to_vec();
        all_entitlements.push(proposed_entitlement_id);

        let rules = self
            .rule_store
            .list_by_entitlements(tenant_id, &all_entitlements)
            .await?;

        let mut violations = Vec::new();

        for rule in rules {
            // Check if user has exemption for this rule
            if self
                .exemption_store
                .is_exempted(tenant_id, rule.id, user_id)
                .await?
            {
                continue;
            }

            let violation = match rule.conflict_type {
                SodConflictType::Exclusive => Self::check_exclusive_violation(
                    &rule,
                    current_entitlements,
                    proposed_entitlement_id,
                ),
                SodConflictType::Cardinality => Self::check_cardinality_violation(
                    &rule,
                    current_entitlements,
                    proposed_entitlement_id,
                ),
                SodConflictType::Inclusive => Self::check_inclusive_violation(
                    &rule,
                    current_entitlements,
                    proposed_entitlement_id,
                ),
            };

            if let Some(v) = violation {
                violations.push(v);
            }
        }

        if violations.is_empty() {
            Ok(PreventiveValidationResult::success())
        } else {
            Ok(PreventiveValidationResult {
                is_valid: false,
                violations,
            })
        }
    }

    /// Get all active violations for a user.
    pub async fn get_user_violations(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SodViolationInfo>> {
        let violations = self
            .violation_store
            .list_by_user(tenant_id, user_id)
            .await?;
        let mut result = Vec::new();

        for v in violations {
            if let Some(rule) = self.rule_store.get(tenant_id, v.rule_id).await? {
                result.push(SodViolationInfo {
                    rule_id: v.rule_id,
                    rule_name: rule.name.clone(),
                    conflicting_entitlements: v.entitlement_ids,
                    severity: rule.severity,
                    message: format!("Violation of rule '{}'", rule.name),
                });
            }
        }

        Ok(result)
    }

    /// Scan a specific rule for violations.
    pub async fn scan_rule(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_entitlements_fn: impl Fn(Uuid) -> Vec<Uuid>,
        all_user_ids: &[Uuid],
    ) -> Result<RuleScanResult> {
        let rule = match self.rule_store.get(tenant_id, rule_id).await? {
            Some(r) => r,
            None => {
                return Ok(RuleScanResult {
                    rule_id,
                    rule_name: "Unknown".to_string(),
                    total_violations: 0,
                    user_violations: vec![],
                });
            }
        };

        let mut user_violations = Vec::new();

        for &user_id in all_user_ids {
            let entitlements = user_entitlements_fn(user_id);

            // Check each entitlement as if it were being "proposed" to existing set
            // This is a simplified scan - just check if current state violates
            let user_set: Vec<Uuid> = entitlements.clone();
            let matching: Vec<Uuid> = rule
                .entitlement_ids
                .iter()
                .filter(|e| user_set.contains(e))
                .copied()
                .collect();

            let has_violation = match rule.conflict_type {
                SodConflictType::Exclusive => matching.len() >= 2,
                SodConflictType::Cardinality => {
                    let max = rule.max_count.unwrap_or(1) as usize;
                    matching.len() > max
                }
                SodConflictType::Inclusive => {
                    !matching.is_empty() && matching.len() < rule.entitlement_ids.len()
                }
            };

            if has_violation {
                // Record violation
                self.violation_store
                    .upsert(tenant_id, rule_id, user_id, matching.clone())
                    .await?;

                user_violations.push(UserViolationReport {
                    user_id,
                    violations: vec![SodViolationInfo {
                        rule_id,
                        rule_name: rule.name.clone(),
                        conflicting_entitlements: matching,
                        severity: rule.severity,
                        message: format!("Violation of rule '{}'", rule.name),
                    }],
                });
            } else {
                // Resolve if was previously in violation
                self.violation_store
                    .resolve_by_user_rule(tenant_id, rule_id, user_id)
                    .await?;
            }
        }

        Ok(RuleScanResult {
            rule_id,
            rule_name: rule.name.clone(),
            total_violations: user_violations.len(),
            user_violations,
        })
    }

    /// Scan all active rules for violations.
    pub async fn scan_all(
        &self,
        tenant_id: Uuid,
        user_entitlements_fn: impl Fn(Uuid) -> Vec<Uuid> + Clone,
        all_user_ids: &[Uuid],
    ) -> Result<DetectiveScanResult> {
        let rules = self.rule_store.list_active(tenant_id).await?;
        let mut rule_results = Vec::new();
        let mut total_violations = 0;

        for rule in &rules {
            let result = self
                .scan_rule(
                    tenant_id,
                    rule.id,
                    user_entitlements_fn.clone(),
                    all_user_ids,
                )
                .await?;
            total_violations += result.total_violations;
            rule_results.push(result);
        }

        Ok(DetectiveScanResult {
            total_rules_scanned: rules.len(),
            total_violations_found: total_violations,
            total_violations_resolved: 0, // Would need more tracking
            rule_results,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::sod::{CreateSodRuleInput, InMemorySodRuleStore};
    use crate::services::sod_exemption::InMemorySodExemptionStore;
    use crate::types::SodRuleStatus;

    fn create_test_service() -> (
        SodValidationService,
        Arc<InMemorySodRuleStore>,
        Arc<InMemorySodViolationStore>,
        Arc<InMemorySodExemptionStore>,
    ) {
        let rule_store = Arc::new(InMemorySodRuleStore::new());
        let violation_store = Arc::new(InMemorySodViolationStore::new());
        let exemption_store = Arc::new(InMemorySodExemptionStore::new());
        let service = SodValidationService::new(
            rule_store.clone(),
            violation_store.clone(),
            exemption_store.clone(),
        );
        (service, rule_store, violation_store, exemption_store)
    }

    #[tokio::test]
    async fn test_exclusive_violation_detected() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();

        // Create exclusive rule: A + B
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Exclusive AB".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Critical,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // User has A, try to assign B
        let result = service
            .validate_preventive(tenant_id, user_id, ent_b, &[ent_a])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].severity, SodSeverity::Critical);
    }

    #[tokio::test]
    async fn test_cardinality_violation_detected() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();
        let ent_c = Uuid::new_v4();

        // Create cardinality rule: max 2 of {A, B, C}
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Max 2".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Cardinality,
                    entitlement_ids: vec![ent_a, ent_b, ent_c],
                    max_count: Some(2),
                    severity: SodSeverity::High,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // User has A and B, try to assign C (would be 3)
        let result = service
            .validate_preventive(tenant_id, user_id, ent_c, &[ent_a, ent_b])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.violations.len(), 1);
    }

    #[tokio::test]
    async fn test_inclusive_violation_detected() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();
        let ent_c = Uuid::new_v4();

        // Create inclusive rule: must have all of {A, B, C} or none
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "All or None".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Inclusive,
                    entitlement_ids: vec![ent_a, ent_b, ent_c],
                    max_count: None,
                    severity: SodSeverity::Medium,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // User has none, try to assign A (would have 1 of 3)
        let result = service
            .validate_preventive(tenant_id, user_id, ent_a, &[])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.violations.len(), 1);
    }

    #[tokio::test]
    async fn test_no_violation_when_allowed() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();
        let ent_c = Uuid::new_v4();

        // Create exclusive rule: A + B
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Exclusive AB".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Critical,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // User has A, try to assign C (not in rule)
        let result = service
            .validate_preventive(tenant_id, user_id, ent_c, &[ent_a])
            .await
            .unwrap();

        assert!(result.is_valid);
        assert!(result.violations.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_violations_reported() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();

        // Create two exclusive rules that both involve A + B
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Rule 1".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Critical,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Rule 2".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::High,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // User has A, try to assign B - violates both rules
        let result = service
            .validate_preventive(tenant_id, user_id, ent_b, &[ent_a])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.violations.len(), 2);
    }

    #[tokio::test]
    async fn test_inactive_rules_ignored() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();

        // Create exclusive rule and deactivate it
        let rule = rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Inactive Rule".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Critical,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        rule_store
            .update(
                tenant_id,
                rule.id,
                crate::services::sod::UpdateSodRuleInput {
                    status: Some(SodRuleStatus::Inactive),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // User has A, try to assign B - should pass because rule is inactive
        let result = service
            .validate_preventive(tenant_id, user_id, ent_b, &[ent_a])
            .await
            .unwrap();

        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_violation_info_complete() {
        let (service, rule_store, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();

        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Test Rule".to_string(),
                    description: Some("Test description".to_string()),
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::High,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        let result = service
            .validate_preventive(tenant_id, user_id, ent_b, &[ent_a])
            .await
            .unwrap();

        assert!(!result.is_valid);
        let violation = &result.violations[0];
        assert_eq!(violation.rule_name, "Test Rule");
        assert_eq!(violation.severity, SodSeverity::High);
        assert_eq!(violation.conflicting_entitlements.len(), 2);
        assert!(violation.message.contains("Test Rule"));
    }
}
