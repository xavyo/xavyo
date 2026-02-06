//! Meta-role matching service for governance API (F056).
//!
//! Handles evaluation of which meta-roles apply to which roles,
//! based on criteria matching, and manages inheritance relationships.

#[cfg(feature = "kafka")]
use std::sync::Arc;

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::{
    CreateGovMetaRoleEvent, CreateGovMetaRoleInheritance, CriteriaLogic, CriteriaOperator,
    EntitlementFilter, GovEntitlement, GovMetaRole, GovMetaRoleCriteria, GovMetaRoleEvent,
    GovMetaRoleInheritance, InheritanceStatus, MetaRoleEventType, MetaRoleStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

/// Result of evaluating meta-role matches for a role.
#[derive(Debug, Clone)]
pub struct RoleMatchResult {
    /// The role being evaluated.
    pub role_id: Uuid,
    /// Meta-roles that match.
    pub matching_meta_roles: Vec<MatchingMetaRole>,
}

/// A meta-role that matches a role with the reason.
#[derive(Debug, Clone)]
pub struct MatchingMetaRole {
    /// Meta-role ID.
    pub meta_role_id: Uuid,
    /// Meta-role name.
    pub name: String,
    /// Priority for conflict resolution.
    pub priority: i32,
    /// Match reason (which criteria matched).
    pub match_reason: serde_json::Value,
    /// Whether already applied.
    pub already_applied: bool,
    /// Inheritance ID if applied.
    pub inheritance_id: Option<Uuid>,
}

/// Service for meta-role matching and inheritance operations.
pub struct MetaRoleMatchingService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl MetaRoleMatchingService {
    /// Create a new meta-role matching service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new meta-role matching service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    // =========================================================================
    // Matching operations
    // =========================================================================

    /// Evaluate which meta-roles match a given role (entitlement).
    pub async fn evaluate_role_matches(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<RoleMatchResult> {
        // Get the role to evaluate
        let role = GovEntitlement::find_by_id(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::EntitlementNotFound(role_id))?;

        // Get all active meta-roles
        let meta_roles = GovMetaRole::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Get existing inheritances for this role
        let existing_inheritances =
            GovMetaRoleInheritance::list_by_child_role(&self.pool, tenant_id, role_id, None)
                .await
                .map_err(GovernanceError::Database)?;

        let mut matching_meta_roles = Vec::new();

        for meta_role in meta_roles {
            // Get criteria for this meta-role
            let criteria =
                GovMetaRoleCriteria::list_by_meta_role(&self.pool, tenant_id, meta_role.id)
                    .await
                    .map_err(GovernanceError::Database)?;

            // Evaluate if role matches
            if let Some(match_reason) = self.evaluate_criteria(&role, &meta_role, &criteria)? {
                // Check if already applied
                let existing = existing_inheritances
                    .iter()
                    .find(|i| i.meta_role_id == meta_role.id);

                matching_meta_roles.push(MatchingMetaRole {
                    meta_role_id: meta_role.id,
                    name: meta_role.name.clone(),
                    priority: meta_role.priority,
                    match_reason,
                    already_applied: existing.is_some(),
                    inheritance_id: existing.map(|i| i.id),
                });
            }
        }

        // Sort by priority (lower = higher precedence)
        matching_meta_roles.sort_by_key(|m| m.priority);

        Ok(RoleMatchResult {
            role_id,
            matching_meta_roles,
        })
    }

    /// Evaluate criteria against a role and return match reason if matched.
    fn evaluate_criteria(
        &self,
        role: &GovEntitlement,
        meta_role: &GovMetaRole,
        criteria: &[GovMetaRoleCriteria],
    ) -> Result<Option<serde_json::Value>> {
        if criteria.is_empty() {
            return Ok(None);
        }

        let mut matched_criteria = Vec::new();
        let mut all_matched = true;
        let mut any_matched = false;

        for criterion in criteria {
            let matches = self.evaluate_single_criterion(role, criterion)?;

            if matches {
                any_matched = true;
                matched_criteria.push(serde_json::json!({
                    "field": criterion.field,
                    "operator": format!("{:?}", criterion.operator),
                    "expected": criterion.value,
                    "actual": self.get_role_field_value(role, &criterion.field),
                }));
            } else {
                all_matched = false;
            }
        }

        // Apply logic (AND vs OR)
        let is_match = match meta_role.criteria_logic {
            CriteriaLogic::And => all_matched,
            CriteriaLogic::Or => any_matched,
        };

        if is_match {
            Ok(Some(serde_json::json!({
                "logic": format!("{:?}", meta_role.criteria_logic),
                "matched_criteria": matched_criteria,
            })))
        } else {
            Ok(None)
        }
    }

    /// Evaluate a single criterion against a role.
    fn evaluate_single_criterion(
        &self,
        role: &GovEntitlement,
        criterion: &GovMetaRoleCriteria,
    ) -> Result<bool> {
        let actual_value = self.get_role_field_value(role, &criterion.field);

        match criterion.operator {
            CriteriaOperator::Eq => Ok(actual_value == criterion.value),
            CriteriaOperator::Neq => Ok(actual_value != criterion.value),
            CriteriaOperator::In => {
                if let Some(arr) = criterion.value.as_array() {
                    Ok(arr.contains(&actual_value))
                } else {
                    Ok(false)
                }
            }
            CriteriaOperator::NotIn => {
                if let Some(arr) = criterion.value.as_array() {
                    Ok(!arr.contains(&actual_value))
                } else {
                    Ok(true)
                }
            }
            CriteriaOperator::Gt => {
                self.compare_numeric(&actual_value, &criterion.value, |a, b| a > b)
            }
            CriteriaOperator::Gte => {
                self.compare_numeric(&actual_value, &criterion.value, |a, b| a >= b)
            }
            CriteriaOperator::Lt => {
                self.compare_numeric(&actual_value, &criterion.value, |a, b| a < b)
            }
            CriteriaOperator::Lte => {
                self.compare_numeric(&actual_value, &criterion.value, |a, b| a <= b)
            }
            CriteriaOperator::Contains => {
                if let (Some(actual_str), Some(expected_str)) =
                    (actual_value.as_str(), criterion.value.as_str())
                {
                    Ok(actual_str.contains(expected_str))
                } else {
                    Ok(false)
                }
            }
            CriteriaOperator::StartsWith => {
                if let (Some(actual_str), Some(expected_str)) =
                    (actual_value.as_str(), criterion.value.as_str())
                {
                    Ok(actual_str.starts_with(expected_str))
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Compare two numeric values with a comparison function.
    fn compare_numeric(
        &self,
        actual: &serde_json::Value,
        expected: &serde_json::Value,
        compare: fn(f64, f64) -> bool,
    ) -> Result<bool> {
        match (actual.as_f64(), expected.as_f64()) {
            (Some(a), Some(e)) => Ok(compare(a, e)),
            _ => Ok(false),
        }
    }

    /// Get a field value from a role as a JSON value.
    fn get_role_field_value(&self, role: &GovEntitlement, field: &str) -> serde_json::Value {
        match field {
            "risk_level" => serde_json::json!(format!("{:?}", role.risk_level)),
            "application_id" => serde_json::json!(role.application_id.to_string()),
            "owner_id" => role.owner_id.map_or(serde_json::Value::Null, |id| {
                serde_json::json!(id.to_string())
            }),
            "status" => serde_json::json!(format!("{:?}", role.status)),
            "name" => serde_json::json!(&role.name),
            "is_delegable" => serde_json::json!(role.is_delegable),
            "metadata" => role.metadata.clone().unwrap_or(serde_json::Value::Null),
            _ => serde_json::Value::Null,
        }
    }

    // =========================================================================
    // Public criteria matching for simulation
    // =========================================================================

    /// Evaluate if a role matches a set of criteria (used by simulation service).
    #[must_use]
    pub fn role_matches_criteria(
        &self,
        role: &GovEntitlement,
        criteria: &[crate::models::CreateMetaRoleCriteriaRequest],
        criteria_logic: &str,
    ) -> bool {
        if criteria.is_empty() {
            return false;
        }

        let mut all_matched = true;
        let mut any_matched = false;

        for criterion in criteria {
            let actual_value = self.get_role_field_value(role, &criterion.field);

            let matches = match criterion.operator {
                xavyo_db::CriteriaOperator::Eq => actual_value == criterion.value,
                xavyo_db::CriteriaOperator::Neq => actual_value != criterion.value,
                xavyo_db::CriteriaOperator::In => criterion
                    .value
                    .as_array()
                    .is_some_and(|arr| arr.contains(&actual_value)),
                xavyo_db::CriteriaOperator::NotIn => criterion
                    .value
                    .as_array()
                    .is_none_or(|arr| !arr.contains(&actual_value)),
                xavyo_db::CriteriaOperator::Gt => self
                    .compare_numeric(&actual_value, &criterion.value, |a, b| a > b)
                    .unwrap_or(false),
                xavyo_db::CriteriaOperator::Gte => self
                    .compare_numeric(&actual_value, &criterion.value, |a, b| a >= b)
                    .unwrap_or(false),
                xavyo_db::CriteriaOperator::Lt => self
                    .compare_numeric(&actual_value, &criterion.value, |a, b| a < b)
                    .unwrap_or(false),
                xavyo_db::CriteriaOperator::Lte => self
                    .compare_numeric(&actual_value, &criterion.value, |a, b| a <= b)
                    .unwrap_or(false),
                xavyo_db::CriteriaOperator::Contains => actual_value
                    .as_str()
                    .and_then(|a| criterion.value.as_str().map(|e| a.contains(e)))
                    .unwrap_or(false),
                xavyo_db::CriteriaOperator::StartsWith => actual_value
                    .as_str()
                    .and_then(|a| criterion.value.as_str().map(|e| a.starts_with(e)))
                    .unwrap_or(false),
            };

            if matches {
                any_matched = true;
            } else {
                all_matched = false;
            }
        }

        // Apply logic (AND vs OR)
        match criteria_logic.to_lowercase().as_str() {
            "and" => all_matched,
            "or" => any_matched,
            _ => all_matched, // Default to AND
        }
    }

    // =========================================================================
    // Inheritance operations
    // =========================================================================

    /// Apply a meta-role to a child role, creating an inheritance relationship.
    pub async fn apply_inheritance(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        child_role_id: Uuid,
        match_reason: serde_json::Value,
    ) -> Result<GovMetaRoleInheritance> {
        // Check if already exists
        if let Some(existing) = GovMetaRoleInheritance::find_by_meta_role_and_child(
            &self.pool,
            tenant_id,
            meta_role_id,
            child_role_id,
        )
        .await
        .map_err(GovernanceError::Database)?
        {
            // If removed, reactivate it
            if existing.status == InheritanceStatus::Removed {
                return GovMetaRoleInheritance::update_status(
                    &self.pool,
                    tenant_id,
                    existing.id,
                    InheritanceStatus::Active,
                )
                .await
                .map_err(GovernanceError::Database)?
                .ok_or_else(|| GovernanceError::MetaRoleInheritanceNotFound(existing.id));
            }
            return Ok(existing);
        }

        // Create new inheritance
        let inheritance = GovMetaRoleInheritance::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleInheritance {
                meta_role_id,
                child_role_id,
                match_reason: match_reason.clone(),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Record audit event
        GovMetaRoleEvent::record_inheritance_applied(
            &self.pool,
            tenant_id,
            meta_role_id,
            child_role_id,
            match_reason,
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            child_role_id = %child_role_id,
            "Meta-role inheritance applied"
        );

        Ok(inheritance)
    }

    /// Remove an inheritance relationship.
    pub async fn remove_inheritance(
        &self,
        tenant_id: Uuid,
        inheritance_id: Uuid,
    ) -> Result<GovMetaRoleInheritance> {
        let inheritance =
            GovMetaRoleInheritance::mark_removed(&self.pool, tenant_id, inheritance_id)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or_else(|| GovernanceError::MetaRoleInheritanceNotFound(inheritance_id))?;

        // Record audit event
        GovMetaRoleEvent::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(inheritance.meta_role_id),
                event_type: MetaRoleEventType::InheritanceRemoved,
                actor_id: None, // System action
                changes: None,
                affected_roles: Some(serde_json::json!([inheritance.child_role_id])),
                metadata: Some(serde_json::json!({
                    "inheritance_id": inheritance_id,
                })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            inheritance_id = %inheritance_id,
            meta_role_id = %inheritance.meta_role_id,
            child_role_id = %inheritance.child_role_id,
            "Meta-role inheritance removed"
        );

        Ok(inheritance)
    }

    /// List inheritances for a meta-role.
    pub async fn list_inheritances_by_meta_role(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        status: Option<InheritanceStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovMetaRoleInheritance>> {
        GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            status,
            limit,
            offset,
        )
        .await
        .map_err(GovernanceError::Database)
    }

    /// List inheritances for a child role.
    pub async fn list_inheritances_by_child_role(
        &self,
        tenant_id: Uuid,
        child_role_id: Uuid,
        status: Option<InheritanceStatus>,
    ) -> Result<Vec<GovMetaRoleInheritance>> {
        GovMetaRoleInheritance::list_by_child_role(&self.pool, tenant_id, child_role_id, status)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Bulk operations
    // =========================================================================

    /// Re-evaluate all roles against all active meta-roles.
    /// Returns number of inheritances added and removed.
    pub async fn reevaluate_all_roles(&self, tenant_id: Uuid) -> Result<(i64, i64)> {
        let mut added = 0i64;
        let mut removed = 0i64;

        // Get all entitlements (roles)
        let filter = EntitlementFilter::default();
        let roles = GovEntitlement::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        for role in &roles {
            let result = self.evaluate_role_matches(tenant_id, role.id).await?;

            for matching in &result.matching_meta_roles {
                if !matching.already_applied {
                    self.apply_inheritance(
                        tenant_id,
                        matching.meta_role_id,
                        role.id,
                        matching.match_reason.clone(),
                    )
                    .await?;
                    added += 1;
                }
            }

            // Remove inheritances for meta-roles that no longer match
            let existing = GovMetaRoleInheritance::list_by_child_role(
                &self.pool,
                tenant_id,
                role.id,
                Some(InheritanceStatus::Active),
            )
            .await
            .map_err(GovernanceError::Database)?;

            for inheritance in existing {
                let still_matches = result
                    .matching_meta_roles
                    .iter()
                    .any(|m| m.meta_role_id == inheritance.meta_role_id);

                if !still_matches {
                    self.remove_inheritance(tenant_id, inheritance.id).await?;
                    removed += 1;
                }
            }
        }

        info!(
            tenant_id = %tenant_id,
            added = added,
            removed = removed,
            "Re-evaluated all role matches"
        );

        Ok((added, removed))
    }

    /// Re-evaluate a specific meta-role against all roles.
    pub async fn reevaluate_meta_role(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<(i64, i64)> {
        let mut added = 0i64;
        let mut removed = 0i64;

        // Get the meta-role
        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        if meta_role.status != MetaRoleStatus::Active {
            warn!(
                tenant_id = %tenant_id,
                meta_role_id = %meta_role_id,
                "Skipping re-evaluation of disabled meta-role"
            );
            return Ok((0, 0));
        }

        // Get criteria
        let criteria = GovMetaRoleCriteria::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Get all roles
        let filter = EntitlementFilter::default();
        let roles = GovEntitlement::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        // Get existing inheritances for this meta-role
        let existing_inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            10000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let mut matched_role_ids: Vec<Uuid> = Vec::new();

        for role in &roles {
            if let Some(match_reason) = self.evaluate_criteria(role, &meta_role, &criteria)? {
                matched_role_ids.push(role.id);

                // Check if already inherited
                let already_inherited = existing_inheritances
                    .iter()
                    .any(|i| i.child_role_id == role.id);

                if !already_inherited {
                    self.apply_inheritance(tenant_id, meta_role_id, role.id, match_reason)
                        .await?;
                    added += 1;
                }
            }
        }

        // Remove inheritances for roles that no longer match
        for inheritance in existing_inheritances {
            if !matched_role_ids.contains(&inheritance.child_role_id) {
                self.remove_inheritance(tenant_id, inheritance.id).await?;
                removed += 1;
            }
        }

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            added = added,
            removed = removed,
            "Re-evaluated meta-role matches"
        );

        Ok((added, removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criteria_logic() {
        // Test that AND requires all to match
        assert_eq!(CriteriaLogic::default(), CriteriaLogic::And);
    }

    #[test]
    fn test_matching_meta_role_structure() {
        let matching = MatchingMetaRole {
            meta_role_id: Uuid::new_v4(),
            name: "High Risk Policy".to_string(),
            priority: 10,
            match_reason: serde_json::json!({"criteria": "risk_level = critical"}),
            already_applied: false,
            inheritance_id: None,
        };

        assert!(!matching.already_applied);
        assert!(matching.inheritance_id.is_none());
        assert_eq!(matching.priority, 10);
    }

    #[test]
    fn test_matching_meta_role_already_applied() {
        let inheritance_id = Uuid::new_v4();
        let matching = MatchingMetaRole {
            meta_role_id: Uuid::new_v4(),
            name: "Finance Policy".to_string(),
            priority: 5,
            match_reason: serde_json::json!({"criteria": "application_id = finance"}),
            already_applied: true,
            inheritance_id: Some(inheritance_id),
        };

        assert!(matching.already_applied);
        assert_eq!(matching.inheritance_id, Some(inheritance_id));
    }

    #[test]
    fn test_role_match_result_structure() {
        let role_id = Uuid::new_v4();
        let result = RoleMatchResult {
            role_id,
            matching_meta_roles: vec![
                MatchingMetaRole {
                    meta_role_id: Uuid::new_v4(),
                    name: "Policy A".to_string(),
                    priority: 1,
                    match_reason: serde_json::json!({}),
                    already_applied: false,
                    inheritance_id: None,
                },
                MatchingMetaRole {
                    meta_role_id: Uuid::new_v4(),
                    name: "Policy B".to_string(),
                    priority: 2,
                    match_reason: serde_json::json!({}),
                    already_applied: true,
                    inheritance_id: Some(Uuid::new_v4()),
                },
            ],
        };

        assert_eq!(result.role_id, role_id);
        assert_eq!(result.matching_meta_roles.len(), 2);
    }

    #[test]
    fn test_multiple_meta_roles_priority_ordering() {
        // Test that meta-roles with lower priority numbers should win conflicts
        let meta_roles = vec![
            MatchingMetaRole {
                meta_role_id: Uuid::new_v4(),
                name: "Low Priority".to_string(),
                priority: 100,
                match_reason: serde_json::json!({}),
                already_applied: false,
                inheritance_id: None,
            },
            MatchingMetaRole {
                meta_role_id: Uuid::new_v4(),
                name: "High Priority".to_string(),
                priority: 1,
                match_reason: serde_json::json!({}),
                already_applied: false,
                inheritance_id: None,
            },
            MatchingMetaRole {
                meta_role_id: Uuid::new_v4(),
                name: "Medium Priority".to_string(),
                priority: 50,
                match_reason: serde_json::json!({}),
                already_applied: false,
                inheritance_id: None,
            },
        ];

        // Sort by priority (lower wins)
        let mut sorted = meta_roles.clone();
        sorted.sort_by_key(|m| m.priority);

        assert_eq!(sorted[0].name, "High Priority");
        assert_eq!(sorted[1].name, "Medium Priority");
        assert_eq!(sorted[2].name, "Low Priority");
    }

    #[test]
    fn test_empty_matching_meta_roles() {
        let result = RoleMatchResult {
            role_id: Uuid::new_v4(),
            matching_meta_roles: vec![],
        };

        assert!(result.matching_meta_roles.is_empty());
    }

    #[test]
    fn test_criteria_operators() {
        // Verify all criteria operators exist
        let operators = [
            CriteriaOperator::Eq,
            CriteriaOperator::Neq,
            CriteriaOperator::In,
            CriteriaOperator::NotIn,
            CriteriaOperator::Gt,
            CriteriaOperator::Gte,
            CriteriaOperator::Lt,
            CriteriaOperator::Lte,
            CriteriaOperator::Contains,
            CriteriaOperator::StartsWith,
        ];

        assert_eq!(operators.len(), 10);
    }

    #[test]
    fn test_inheritance_status_values() {
        // Verify all inheritance statuses exist
        let statuses = [
            InheritanceStatus::Active,
            InheritanceStatus::Suspended,
            InheritanceStatus::Removed,
        ];

        assert_eq!(statuses.len(), 3);
    }

    #[test]
    fn test_match_reason_json_structure() {
        // Test that match_reason can contain detailed criteria information
        let match_reason = serde_json::json!({
            "matched_criteria": [
                {
                    "field": "risk_level",
                    "operator": "eq",
                    "value": "critical",
                    "matched": true
                },
                {
                    "field": "application_id",
                    "operator": "in",
                    "value": ["app1", "app2"],
                    "matched": true
                }
            ],
            "logic": "and",
            "all_matched": true
        });

        assert!(match_reason["matched_criteria"].is_array());
        assert_eq!(match_reason["logic"], "and");
        assert!(match_reason["all_matched"].as_bool().unwrap());
    }
}
