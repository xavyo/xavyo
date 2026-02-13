//! Birthright policy service for lifecycle workflow management.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    BirthrightPolicyFilter, BirthrightPolicyStatus, ConditionOperator, CreateBirthrightPolicy,
    EvaluationMode, GovBirthrightPolicy, GovEntitlement, PolicyCondition, UpdateBirthrightPolicy,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    AffectedUser, ConditionEvaluationResult, DepartmentImpact, EntitlementImpact,
    ImpactAnalysisRequest, ImpactAnalysisResponse, ImpactSummary, LocationImpact,
    MatchingPolicyResult, PolicyConditionRequest, SimulateAllPoliciesResponse,
    SimulatePolicyResponse, UserImpactType,
};

/// Service for birthright policy operations.
pub struct BirthrightPolicyService {
    pool: PgPool,
}

impl BirthrightPolicyService {
    /// Create a new birthright policy service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new birthright policy.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        priority: i32,
        conditions: Vec<PolicyConditionRequest>,
        entitlement_ids: Vec<Uuid>,
        evaluation_mode: Option<EvaluationMode>,
        grace_period_days: Option<i32>,
        created_by: Uuid,
    ) -> Result<GovBirthrightPolicy> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Policy name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Policy name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name
        if let Some(_existing) =
            GovBirthrightPolicy::find_by_name(&self.pool, tenant_id, &name).await?
        {
            return Err(GovernanceError::BirthrightPolicyNameExists(name));
        }

        // Validate conditions
        if conditions.is_empty() {
            return Err(GovernanceError::InvalidPolicyConditions(
                "At least one condition is required".to_string(),
            ));
        }

        for condition in &conditions {
            self.validate_condition(condition)?;
        }

        // Validate entitlements exist
        if entitlement_ids.is_empty() {
            return Err(GovernanceError::Validation(
                "At least one entitlement is required".to_string(),
            ));
        }

        let missing_entitlements = self
            .find_missing_entitlements(tenant_id, &entitlement_ids)
            .await?;
        if !missing_entitlements.is_empty() {
            return Err(GovernanceError::PolicyEntitlementsNotFound(
                missing_entitlements,
            ));
        }

        // Convert conditions to domain model
        let policy_conditions: Vec<PolicyCondition> = conditions
            .into_iter()
            .map(|c| PolicyCondition {
                attribute: c.attribute,
                operator: c.operator.as_str().to_string(),
                value: c.value,
            })
            .collect();

        let input = CreateBirthrightPolicy {
            name,
            description,
            priority: Some(priority),
            conditions: policy_conditions,
            entitlement_ids,
            evaluation_mode,
            grace_period_days,
            created_by,
        };

        GovBirthrightPolicy::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get a birthright policy by ID.
    pub async fn get(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<GovBirthrightPolicy> {
        GovBirthrightPolicy::find_by_id(&self.pool, tenant_id, policy_id)
            .await?
            .ok_or(GovernanceError::BirthrightPolicyNotFound(policy_id))
    }

    /// List birthright policies with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        status: Option<BirthrightPolicyStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovBirthrightPolicy>, i64)> {
        let filter = BirthrightPolicyFilter {
            status,
            created_by: None,
        };

        let policies =
            GovBirthrightPolicy::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovBirthrightPolicy::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((policies, total))
    }

    /// List all active birthright policies (for lifecycle event processing).
    pub async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<GovBirthrightPolicy>> {
        GovBirthrightPolicy::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a birthright policy.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        name: Option<String>,
        description: Option<String>,
        priority: Option<i32>,
        conditions: Option<Vec<PolicyConditionRequest>>,
        entitlement_ids: Option<Vec<Uuid>>,
        evaluation_mode: Option<EvaluationMode>,
        grace_period_days: Option<i32>,
    ) -> Result<GovBirthrightPolicy> {
        // Verify policy exists and is not archived
        let existing = self.get(tenant_id, policy_id).await?;

        if existing.status == BirthrightPolicyStatus::Archived {
            return Err(GovernanceError::Validation(
                "Cannot update an archived policy".to_string(),
            ));
        }

        // Validate name if provided
        if let Some(ref new_name) = name {
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Policy name cannot be empty".to_string(),
                ));
            }

            if new_name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Policy name cannot exceed 255 characters".to_string(),
                ));
            }

            // Check for duplicate name (if different from current)
            if new_name != &existing.name {
                if let Some(_existing) =
                    GovBirthrightPolicy::find_by_name(&self.pool, tenant_id, new_name).await?
                {
                    return Err(GovernanceError::BirthrightPolicyNameExists(
                        new_name.clone(),
                    ));
                }
            }
        }

        // Validate conditions if provided
        let policy_conditions = if let Some(conds) = conditions {
            if conds.is_empty() {
                return Err(GovernanceError::InvalidPolicyConditions(
                    "At least one condition is required".to_string(),
                ));
            }

            for condition in &conds {
                self.validate_condition(condition)?;
            }

            Some(
                conds
                    .into_iter()
                    .map(|c| PolicyCondition {
                        attribute: c.attribute,
                        operator: c.operator.as_str().to_string(),
                        value: c.value,
                    })
                    .collect(),
            )
        } else {
            None
        };

        // Validate entitlements if provided
        if let Some(ref ent_ids) = entitlement_ids {
            if ent_ids.is_empty() {
                return Err(GovernanceError::Validation(
                    "At least one entitlement is required".to_string(),
                ));
            }

            let missing_entitlements = self.find_missing_entitlements(tenant_id, ent_ids).await?;
            if !missing_entitlements.is_empty() {
                return Err(GovernanceError::PolicyEntitlementsNotFound(
                    missing_entitlements,
                ));
            }
        }

        let input = UpdateBirthrightPolicy {
            name,
            description,
            priority,
            conditions: policy_conditions,
            entitlement_ids,
            evaluation_mode,
            grace_period_days,
        };

        GovBirthrightPolicy::update(&self.pool, tenant_id, policy_id, input)
            .await?
            .ok_or(GovernanceError::BirthrightPolicyNotFound(policy_id))
    }

    /// Archive (soft-delete) a birthright policy.
    pub async fn archive(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<GovBirthrightPolicy> {
        // Verify policy exists
        let existing = self.get(tenant_id, policy_id).await?;

        if existing.status == BirthrightPolicyStatus::Archived {
            return Err(GovernanceError::Validation(
                "Policy is already archived".to_string(),
            ));
        }

        GovBirthrightPolicy::archive(&self.pool, tenant_id, policy_id)
            .await?
            .ok_or(GovernanceError::BirthrightPolicyNotFound(policy_id))
    }

    /// Enable a birthright policy.
    pub async fn enable(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<GovBirthrightPolicy> {
        let existing = self.get(tenant_id, policy_id).await?;

        if !existing.status.can_enable() {
            return Err(GovernanceError::Validation(format!(
                "Cannot enable policy with status '{:?}'",
                existing.status
            )));
        }

        GovBirthrightPolicy::enable(&self.pool, tenant_id, policy_id)
            .await?
            .ok_or(GovernanceError::BirthrightPolicyNotFound(policy_id))
    }

    /// Disable a birthright policy.
    pub async fn disable(&self, tenant_id: Uuid, policy_id: Uuid) -> Result<GovBirthrightPolicy> {
        let existing = self.get(tenant_id, policy_id).await?;

        if !existing.status.can_disable() {
            return Err(GovernanceError::Validation(format!(
                "Cannot disable policy with status '{:?}'",
                existing.status
            )));
        }

        GovBirthrightPolicy::disable(&self.pool, tenant_id, policy_id)
            .await?
            .ok_or(GovernanceError::BirthrightPolicyNotFound(policy_id))
    }

    /// Simulate a single policy against user attributes.
    pub async fn simulate_policy(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        attributes: &serde_json::Value,
    ) -> Result<SimulatePolicyResponse> {
        let policy = self.get(tenant_id, policy_id).await?;
        let conditions = policy.parse_conditions();

        let mut condition_results = Vec::new();
        let mut all_match = true;

        for condition in &conditions {
            let operator =
                ConditionOperator::parse(&condition.operator).unwrap_or(ConditionOperator::Equals);

            // Resolve attribute value (F081: support custom_attributes.* and metadata.* prefixes)
            let actual = if let Some(key) = condition.attribute.strip_prefix("custom_attributes.") {
                attributes
                    .get("custom_attributes")
                    .and_then(|ca| ca.get(key))
                    .cloned()
            } else if let Some(key) = condition.attribute.strip_prefix("metadata.") {
                attributes.get("metadata").and_then(|m| m.get(key)).cloned()
            } else {
                attributes.get(&condition.attribute).cloned()
            };
            let actual_str = actual.as_ref().and_then(|v| v.as_str());
            let matched = operator.evaluate(actual_str, &condition.value);

            if !matched {
                all_match = false;
            }

            condition_results.push(ConditionEvaluationResult {
                attribute: condition.attribute.clone(),
                operator,
                expected: condition.value.clone(),
                actual,
                matched,
            });
        }

        Ok(SimulatePolicyResponse {
            matches: all_match,
            condition_results,
        })
    }

    /// Simulate all active policies against user attributes.
    ///
    /// Respects evaluation modes:
    /// - `FirstMatch`: Stop at the first matching policy and only apply its entitlements
    /// - `AllMatch`: Apply entitlements from all matching policies
    pub async fn simulate_all_policies(
        &self,
        tenant_id: Uuid,
        attributes: &serde_json::Value,
    ) -> Result<SimulateAllPoliciesResponse> {
        let mut policies = self.list_active(tenant_id).await?;

        // Sort by priority (higher = first) to ensure consistent evaluation order
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut matching_policies = Vec::new();
        let mut total_entitlements = std::collections::HashSet::new();

        for policy in policies {
            if policy.evaluate(attributes) {
                for ent_id in &policy.entitlement_ids {
                    total_entitlements.insert(*ent_id);
                }

                matching_policies.push(MatchingPolicyResult {
                    policy_id: policy.id,
                    policy_name: policy.name.clone(),
                    priority: policy.priority,
                    entitlements: policy.entitlement_ids.clone(),
                });

                // If this policy is set to first-match mode, stop evaluating further policies
                if policy.evaluation_mode.is_first_match() {
                    break;
                }
            }
        }

        Ok(SimulateAllPoliciesResponse {
            attributes: attributes.clone(),
            matching_policies,
            total_entitlements: total_entitlements.into_iter().collect(),
        })
    }

    /// Find matching policies for a user's attributes.
    ///
    /// Respects evaluation modes:
    /// - `FirstMatch`: Stop at the first matching policy (highest priority)
    /// - `AllMatch`: Return all matching policies
    ///
    /// Policies are evaluated in priority order (highest first).
    pub async fn find_matching_policies(
        &self,
        tenant_id: Uuid,
        attributes: &serde_json::Value,
    ) -> Result<Vec<GovBirthrightPolicy>> {
        let mut policies = self.list_active(tenant_id).await?;

        // Sort by priority (higher = first) to ensure consistent evaluation order
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut matching = Vec::new();

        for policy in policies {
            if policy.evaluate(attributes) {
                let is_first_match = policy.evaluation_mode.is_first_match();
                matching.push(policy);

                // If this policy is set to first-match mode, stop evaluating further policies
                if is_first_match {
                    break;
                }
            }
        }

        Ok(matching)
    }

    /// Validate a condition request.
    fn validate_condition(&self, condition: &PolicyConditionRequest) -> Result<()> {
        // Validate attribute name
        if condition.attribute.trim().is_empty() {
            return Err(GovernanceError::InvalidConditionAttribute(
                "Attribute name cannot be empty".to_string(),
            ));
        }

        if condition.attribute.len() > 100 {
            return Err(GovernanceError::InvalidConditionAttribute(
                "Attribute name cannot exceed 100 characters".to_string(),
            ));
        }

        // Validate value based on operator
        match condition.operator {
            ConditionOperator::In | ConditionOperator::NotIn => {
                if !condition.value.is_array() {
                    return Err(GovernanceError::InvalidPolicyConditions(format!(
                        "Operator '{:?}' requires an array value",
                        condition.operator
                    )));
                }
            }
            _ => {
                if condition.value.is_null() {
                    return Err(GovernanceError::InvalidPolicyConditions(
                        "Condition value cannot be null".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Find entitlement IDs that don't exist.
    async fn find_missing_entitlements(
        &self,
        tenant_id: Uuid,
        entitlement_ids: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        let mut missing = Vec::new();

        for ent_id in entitlement_ids {
            let exists = GovEntitlement::find_by_id(&self.pool, tenant_id, *ent_id)
                .await?
                .is_some();
            if !exists {
                missing.push(*ent_id);
            }
        }

        Ok(missing)
    }

    /// Analyze the impact of a policy on users.
    ///
    /// This evaluates the policy (optionally with proposed changes) against all
    /// tenant users and returns impact statistics and affected user details.
    pub async fn analyze_impact(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        request: &ImpactAnalysisRequest,
    ) -> Result<ImpactAnalysisResponse> {
        // Get the policy
        let policy = self.get(tenant_id, policy_id).await?;

        // Determine conditions to use (proposed or current)
        let conditions: Vec<PolicyCondition> =
            if let Some(ref proposed) = request.proposed_conditions {
                proposed
                    .iter()
                    .map(|c| PolicyCondition {
                        attribute: c.attribute.clone(),
                        operator: c.operator.as_str().to_string(),
                        value: c.value.clone(),
                    })
                    .collect()
            } else {
                policy.parse_conditions()
            };

        // Determine entitlement IDs to use (proposed or current)
        let entitlement_ids: Vec<Uuid> = request
            .proposed_entitlement_ids
            .clone()
            .unwrap_or_else(|| policy.entitlement_ids.clone());

        // Get all users for the tenant
        let users = self.get_tenant_users(tenant_id).await?;

        // Get current assignments for comparison
        let current_assignments = self.get_tenant_assignments(tenant_id).await?;

        // Build maps for quick lookup
        let mut user_assignments: std::collections::HashMap<Uuid, std::collections::HashSet<Uuid>> =
            std::collections::HashMap::new();
        for (user_id, ent_id) in current_assignments {
            user_assignments.entry(user_id).or_default().insert(ent_id);
        }

        // Evaluate policy against each user
        let mut affected_users = Vec::new();
        let mut summary = ImpactSummary::default();
        let mut department_counts: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut location_counts: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut entitlement_gaining: std::collections::HashMap<Uuid, i64> =
            std::collections::HashMap::new();
        let mut entitlement_already_have: std::collections::HashMap<Uuid, i64> =
            std::collections::HashMap::new();

        for user in users {
            let user_attrs = &user.attributes;

            // Evaluate conditions against user
            let matches = conditions.iter().all(|c| c.evaluate(user_attrs));

            if matches {
                summary.total_users_affected += 1;

                // Get user's current entitlements
                let user_current_ents = user_assignments.get(&user.id).cloned().unwrap_or_default();

                // Calculate what would be gained/lost
                let mut gaining = Vec::new();
                let mut losing = Vec::new();

                for ent_id in &entitlement_ids {
                    if user_current_ents.contains(ent_id) {
                        *entitlement_already_have.entry(*ent_id).or_default() += 1;
                    } else {
                        gaining.push(*ent_id);
                        *entitlement_gaining.entry(*ent_id).or_default() += 1;
                    }
                }

                // For proposed changes, check what would be lost (current policy ents not in proposed)
                if request.proposed_entitlement_ids.is_some() {
                    for ent_id in &policy.entitlement_ids {
                        if !entitlement_ids.contains(ent_id) && user_current_ents.contains(ent_id) {
                            losing.push(*ent_id);
                        }
                    }
                }

                // Determine impact type
                let impact_type = match (gaining.is_empty(), losing.is_empty()) {
                    (false, false) => UserImpactType::Mixed,
                    (false, true) => UserImpactType::Gaining,
                    (true, false) => UserImpactType::Losing,
                    (true, true) => UserImpactType::Unchanged,
                };

                match impact_type {
                    UserImpactType::Gaining => summary.users_gaining_access += 1,
                    UserImpactType::Losing => summary.users_losing_access += 1,
                    UserImpactType::Unchanged => summary.users_unchanged += 1,
                    UserImpactType::Mixed => {
                        summary.users_gaining_access += 1;
                        summary.users_losing_access += 1;
                    }
                }

                // Track department/location counts
                if let Some(dept) = user_attrs.get("department").and_then(|v| v.as_str()) {
                    *department_counts.entry(dept.to_string()).or_default() += 1;
                }
                if let Some(loc) = user_attrs.get("location").and_then(|v| v.as_str()) {
                    *location_counts.entry(loc.to_string()).or_default() += 1;
                }

                // Add to affected users list (limited)
                if (affected_users.len() as i64) < request.max_affected_users {
                    affected_users.push(AffectedUser {
                        user_id: user.id,
                        email: user.email.clone(),
                        department: user_attrs
                            .get("department")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        location: user_attrs
                            .get("location")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        impact_type,
                        entitlements_gaining: gaining.clone(),
                        entitlements_losing: losing.clone(),
                    });
                }

                summary.total_entitlements_granted += gaining.len() as i64;
            }
        }

        // Build department breakdown
        let total_affected = summary.total_users_affected.max(1) as f64;
        let by_department: Vec<DepartmentImpact> = department_counts
            .into_iter()
            .map(|(dept, count)| DepartmentImpact {
                department: dept,
                user_count: count,
                percentage: (count as f64 / total_affected) * 100.0,
            })
            .collect();

        // Build location breakdown
        let by_location: Vec<LocationImpact> = location_counts
            .into_iter()
            .map(|(loc, count)| LocationImpact {
                location: loc,
                user_count: count,
                percentage: (count as f64 / total_affected) * 100.0,
            })
            .collect();

        // Build entitlement impacts
        let entitlement_impacts: Vec<EntitlementImpact> = entitlement_ids
            .iter()
            .map(|ent_id| EntitlementImpact {
                entitlement_id: *ent_id,
                entitlement_name: None, // Would need to fetch from entitlement table
                users_gaining: *entitlement_gaining.get(ent_id).unwrap_or(&0),
                users_already_have: *entitlement_already_have.get(ent_id).unwrap_or(&0),
            })
            .collect();

        let is_truncated = summary.total_users_affected > request.max_affected_users;

        Ok(ImpactAnalysisResponse {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            summary,
            by_department,
            by_location,
            entitlement_impacts,
            affected_users,
            is_truncated,
        })
    }

    /// Get all users for a tenant with their attributes.
    /// Returns a lightweight user representation for impact analysis.
    async fn get_tenant_users(&self, tenant_id: Uuid) -> Result<Vec<UserForImpact>> {
        // Query users with their profile data.
        // User attributes like department, job_title, location are stored in custom_attributes JSONB.
        let rows = sqlx::query_as::<_, UserForImpact>(
            r"
            SELECT
                id,
                email,
                jsonb_build_object(
                    'department', custom_attributes->>'department',
                    'job_title', custom_attributes->>'job_title',
                    'location', custom_attributes->>'location',
                    'custom_attributes', COALESCE(custom_attributes, '{}'::jsonb)
                ) as attributes
            FROM users
            WHERE tenant_id = $1 AND is_active = true
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows)
    }

    /// Get all entitlement assignments for a tenant.
    async fn get_tenant_assignments(&self, tenant_id: Uuid) -> Result<Vec<(Uuid, Uuid)>> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT target_id, entitlement_id
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1
              AND target_type = 'user'
              AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows)
    }
}

/// Lightweight user representation for impact analysis.
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserForImpact {
    pub id: Uuid,
    pub email: Option<String>,
    pub attributes: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function for testing validation logic without needing a service instance.
    fn validate_condition_test(condition: &PolicyConditionRequest) -> Result<()> {
        // Validate attribute name
        if condition.attribute.trim().is_empty() {
            return Err(GovernanceError::InvalidConditionAttribute(
                "Attribute name cannot be empty".to_string(),
            ));
        }

        if condition.attribute.len() > 100 {
            return Err(GovernanceError::InvalidConditionAttribute(
                "Attribute name cannot exceed 100 characters".to_string(),
            ));
        }

        // Validate value based on operator
        match condition.operator {
            ConditionOperator::In | ConditionOperator::NotIn => {
                if !condition.value.is_array() {
                    return Err(GovernanceError::InvalidPolicyConditions(format!(
                        "Operator '{}' requires an array value",
                        condition.operator.as_str()
                    )));
                }
            }
            _ => {}
        }

        Ok(())
    }

    #[test]
    fn test_condition_validation_empty_attribute() {
        // Test that empty attribute names are rejected
        let condition = PolicyConditionRequest {
            attribute: "".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("test"),
        };

        let result = validate_condition_test(&condition);
        assert!(result.is_err());
    }

    #[test]
    fn test_condition_validation_in_requires_array() {
        let condition = PolicyConditionRequest {
            attribute: "department".to_string(),
            operator: ConditionOperator::In,
            value: serde_json::json!("Engineering"), // Should be an array
        };

        let result = validate_condition_test(&condition);
        assert!(result.is_err());
    }

    #[test]
    fn test_condition_validation_valid() {
        let condition = PolicyConditionRequest {
            attribute: "department".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("Engineering"),
        };

        let result = validate_condition_test(&condition);
        assert!(result.is_ok());
    }

    #[test]
    fn test_condition_validation_in_with_array() {
        let condition = PolicyConditionRequest {
            attribute: "department".to_string(),
            operator: ConditionOperator::In,
            value: serde_json::json!(["Engineering", "Product"]),
        };

        let result = validate_condition_test(&condition);
        assert!(result.is_ok());
    }
}
