//! Governance Birthright Policy model.
//!
//! Represents attribute-based access rules for automatic entitlement provisioning.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for birthright policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "birthright_policy_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BirthrightPolicyStatus {
    /// Policy is active and evaluated.
    Active,
    /// Policy is disabled.
    Inactive,
    /// Policy is soft-deleted.
    Archived,
}

impl BirthrightPolicyStatus {
    /// Check if the policy is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the policy can be enabled.
    #[must_use] 
    pub fn can_enable(&self) -> bool {
        matches!(self, Self::Inactive)
    }

    /// Check if the policy can be disabled.
    #[must_use] 
    pub fn can_disable(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the policy can be archived.
    #[must_use] 
    pub fn can_archive(&self) -> bool {
        !matches!(self, Self::Archived)
    }
}

/// Evaluation mode for birthright policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "evaluation_mode", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum EvaluationMode {
    /// Stop at first matching policy and apply only its entitlements.
    FirstMatch,
    /// Apply entitlements from all matching policies.
    #[default]
    AllMatch,
}

impl EvaluationMode {
    /// Check if this is first-match mode.
    #[must_use] 
    pub fn is_first_match(&self) -> bool {
        matches!(self, Self::FirstMatch)
    }

    /// Check if this is all-match mode.
    #[must_use] 
    pub fn is_all_match(&self) -> bool {
        matches!(self, Self::AllMatch)
    }
}

/// Condition operator for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Exact match.
    Equals,
    /// Not equal.
    NotEquals,
    /// Value in list.
    In,
    /// Value not in list.
    NotIn,
    /// Prefix match.
    StartsWith,
    /// Substring match.
    Contains,
}

impl ConditionOperator {
    /// Parse operator from string.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "equals" => Some(Self::Equals),
            "not_equals" => Some(Self::NotEquals),
            "in" => Some(Self::In),
            "not_in" => Some(Self::NotIn),
            "starts_with" => Some(Self::StartsWith),
            "contains" => Some(Self::Contains),
            _ => None,
        }
    }

    /// Convert operator to string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::NotEquals => "not_equals",
            Self::In => "in",
            Self::NotIn => "not_in",
            Self::StartsWith => "starts_with",
            Self::Contains => "contains",
        }
    }

    /// Evaluate the condition against a user value.
    #[must_use] 
    pub fn evaluate(&self, user_value: Option<&str>, condition_value: &serde_json::Value) -> bool {
        let user_value = match user_value {
            Some(v) => v,
            None => return matches!(self, Self::NotEquals | Self::NotIn),
        };

        match self {
            Self::Equals => condition_value.as_str() == Some(user_value),
            Self::NotEquals => condition_value.as_str() != Some(user_value),
            Self::In => condition_value
                .as_array()
                .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(user_value))),
            Self::NotIn => condition_value
                .as_array()
                .is_none_or(|arr| !arr.iter().any(|v| v.as_str() == Some(user_value))),
            Self::StartsWith => condition_value
                .as_str()
                .is_some_and(|v| user_value.starts_with(v)),
            Self::Contains => condition_value
                .as_str()
                .is_some_and(|v| user_value.contains(v)),
        }
    }
}

/// A single condition in a birthright policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// User attribute to match (department, title, locale, metadata.*, or `custom_attributes`.*)
    pub attribute: String,
    /// Comparison operator.
    pub operator: String,
    /// Value to compare against.
    pub value: serde_json::Value,
}

impl PolicyCondition {
    /// Validate the condition structure.
    pub fn validate(&self) -> Result<(), String> {
        if self.attribute.is_empty() {
            return Err("Condition attribute cannot be empty".to_string());
        }

        if ConditionOperator::parse(&self.operator).is_none() {
            return Err(format!("Invalid operator: {}", self.operator));
        }

        // Validate value based on operator
        let op = ConditionOperator::parse(&self.operator).unwrap();
        match op {
            ConditionOperator::In | ConditionOperator::NotIn => {
                if !self.value.is_array() {
                    return Err("'in' and 'not_in' operators require array value".to_string());
                }
            }
            _ => {
                if !self.value.is_string() && !self.value.is_array() {
                    return Err("Condition value must be a string or array".to_string());
                }
            }
        }

        Ok(())
    }

    /// Evaluate this condition against user attributes.
    #[must_use] 
    pub fn evaluate(&self, user_attrs: &serde_json::Value) -> bool {
        let operator = match ConditionOperator::parse(&self.operator) {
            Some(op) => op,
            None => return false,
        };

        // Get user value for attribute
        let user_value = if self.attribute.starts_with("metadata.") {
            let key = &self.attribute["metadata.".len()..];
            user_attrs
                .get("metadata")
                .and_then(|m| m.get(key))
                .and_then(|v| v.as_str())
        } else if self.attribute.starts_with("custom_attributes.") {
            // F081: Resolve custom attribute values from user's custom_attributes JSONB
            let key = &self.attribute["custom_attributes.".len()..];
            user_attrs
                .get("custom_attributes")
                .and_then(|ca| ca.get(key))
                .and_then(|v| v.as_str())
        } else {
            user_attrs.get(&self.attribute).and_then(|v| v.as_str())
        };

        operator.evaluate(user_value, &self.value)
    }
}

/// A governance birthright policy.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovBirthrightPolicy {
    /// Unique identifier for the policy.
    pub id: Uuid,

    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Policy display name.
    pub name: String,

    /// Policy description.
    pub description: Option<String>,

    /// Conditions for policy evaluation (JSON array of `PolicyCondition`).
    pub conditions: serde_json::Value,

    /// Entitlement IDs to provision when conditions match.
    pub entitlement_ids: Vec<Uuid>,

    /// Evaluation priority (higher = first).
    pub priority: i32,

    /// Policy status.
    pub status: BirthrightPolicyStatus,

    /// Evaluation mode (`first_match` or `all_match`).
    pub evaluation_mode: EvaluationMode,

    /// Grace period in days for mover revocations.
    pub grace_period_days: i32,

    /// User who created the policy.
    pub created_by: Uuid,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new birthright policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBirthrightPolicy {
    pub name: String,
    pub description: Option<String>,
    pub conditions: Vec<PolicyCondition>,
    pub entitlement_ids: Vec<Uuid>,
    pub priority: Option<i32>,
    pub evaluation_mode: Option<EvaluationMode>,
    pub grace_period_days: Option<i32>,
    pub created_by: Uuid,
}

/// Request to update a birthright policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateBirthrightPolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub conditions: Option<Vec<PolicyCondition>>,
    pub entitlement_ids: Option<Vec<Uuid>>,
    pub priority: Option<i32>,
    pub evaluation_mode: Option<EvaluationMode>,
    pub grace_period_days: Option<i32>,
}

/// Filter options for listing birthright policies.
#[derive(Debug, Clone, Default)]
pub struct BirthrightPolicyFilter {
    pub status: Option<BirthrightPolicyStatus>,
    pub created_by: Option<Uuid>,
}

impl GovBirthrightPolicy {
    /// Find a policy by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_birthright_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a policy by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_birthright_policies
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List active policies for a tenant, ordered by priority (descending).
    pub async fn list_active(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_birthright_policies
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY priority DESC, name ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List policies for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BirthrightPolicyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_birthright_policies
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY priority DESC, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovBirthrightPolicy>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count policies in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BirthrightPolicyFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_birthright_policies
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new birthright policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateBirthrightPolicy,
    ) -> Result<Self, sqlx::Error> {
        let conditions =
            serde_json::to_value(&input.conditions).unwrap_or_else(|_| serde_json::json!([]));

        sqlx::query_as(
            r"
            INSERT INTO gov_birthright_policies (
                tenant_id, name, description, conditions, entitlement_ids,
                priority, evaluation_mode, grace_period_days, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&conditions)
        .bind(&input.entitlement_ids)
        .bind(input.priority.unwrap_or(0))
        .bind(input.evaluation_mode.unwrap_or_default())
        .bind(input.grace_period_days.unwrap_or(7))
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateBirthrightPolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.conditions.is_some() {
            updates.push(format!("conditions = ${param_idx}"));
            param_idx += 1;
        }
        if input.entitlement_ids.is_some() {
            updates.push(format!("entitlement_ids = ${param_idx}"));
            param_idx += 1;
        }
        if input.priority.is_some() {
            updates.push(format!("priority = ${param_idx}"));
            param_idx += 1;
        }
        if input.evaluation_mode.is_some() {
            updates.push(format!("evaluation_mode = ${param_idx}"));
            param_idx += 1;
        }
        if input.grace_period_days.is_some() {
            updates.push(format!("grace_period_days = ${param_idx}"));
            let _ = param_idx; // Suppress unused warning
        }

        let query = format!(
            "UPDATE gov_birthright_policies SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovBirthrightPolicy>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref conditions) = input.conditions {
            let conditions_json =
                serde_json::to_value(conditions).unwrap_or_else(|_| serde_json::json!([]));
            q = q.bind(conditions_json);
        }
        if let Some(ref entitlement_ids) = input.entitlement_ids {
            q = q.bind(entitlement_ids);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        if let Some(evaluation_mode) = input.evaluation_mode {
            q = q.bind(evaluation_mode);
        }
        if let Some(grace_period_days) = input.grace_period_days {
            q = q.bind(grace_period_days);
        }

        q.fetch_optional(pool).await
    }

    /// Archive a policy (soft delete).
    pub async fn archive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_birthright_policies
            SET status = 'archived', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status != 'archived'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Enable a policy.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_birthright_policies
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'inactive'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a policy.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_birthright_policies
            SET status = 'inactive', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Parse conditions from JSON.
    #[must_use] 
    pub fn parse_conditions(&self) -> Vec<PolicyCondition> {
        serde_json::from_value(self.conditions.clone()).unwrap_or_default()
    }

    /// Evaluate this policy against user attributes.
    /// Returns true if all conditions match (AND logic).
    #[must_use] 
    pub fn evaluate(&self, user_attrs: &serde_json::Value) -> bool {
        if !self.status.is_active() {
            return false;
        }

        let conditions = self.parse_conditions();
        if conditions.is_empty() {
            return false; // No conditions = no match
        }

        conditions.iter().all(|c| c.evaluate(user_attrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_status_methods() {
        assert!(BirthrightPolicyStatus::Active.is_active());
        assert!(!BirthrightPolicyStatus::Inactive.is_active());
        assert!(!BirthrightPolicyStatus::Archived.is_active());

        assert!(BirthrightPolicyStatus::Inactive.can_enable());
        assert!(!BirthrightPolicyStatus::Active.can_enable());

        assert!(BirthrightPolicyStatus::Active.can_disable());
        assert!(!BirthrightPolicyStatus::Inactive.can_disable());
    }

    #[test]
    fn test_condition_operator_equals() {
        let op = ConditionOperator::Equals;
        assert!(op.evaluate(Some("Engineering"), &serde_json::json!("Engineering")));
        assert!(!op.evaluate(Some("Sales"), &serde_json::json!("Engineering")));
        assert!(!op.evaluate(None, &serde_json::json!("Engineering")));
    }

    #[test]
    fn test_condition_operator_in() {
        let op = ConditionOperator::In;
        let values = serde_json::json!(["US", "UK", "DE"]);
        assert!(op.evaluate(Some("US"), &values));
        assert!(op.evaluate(Some("UK"), &values));
        assert!(!op.evaluate(Some("FR"), &values));
        assert!(!op.evaluate(None, &values));
    }

    #[test]
    fn test_condition_operator_starts_with() {
        let op = ConditionOperator::StartsWith;
        assert!(op.evaluate(
            Some("Engineering/Frontend"),
            &serde_json::json!("Engineering")
        ));
        assert!(!op.evaluate(Some("Sales/EMEA"), &serde_json::json!("Engineering")));
    }

    #[test]
    fn test_policy_condition_evaluate() {
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };

        let user_attrs = serde_json::json!({
            "department": "Engineering",
            "title": "Software Engineer"
        });

        assert!(condition.evaluate(&user_attrs));

        let user_attrs_sales = serde_json::json!({
            "department": "Sales",
            "title": "Account Executive"
        });

        assert!(!condition.evaluate(&user_attrs_sales));
    }

    #[test]
    fn test_policy_condition_metadata() {
        let condition = PolicyCondition {
            attribute: "metadata.cost_center".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("CC123"),
        };

        let user_attrs = serde_json::json!({
            "department": "Engineering",
            "metadata": {
                "cost_center": "CC123"
            }
        });

        assert!(condition.evaluate(&user_attrs));
    }

    #[test]
    fn test_status_serialization() {
        let active = BirthrightPolicyStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let inactive = BirthrightPolicyStatus::Inactive;
        let json = serde_json::to_string(&inactive).unwrap();
        assert_eq!(json, "\"inactive\"");
    }

    #[test]
    fn test_evaluation_mode_default() {
        let mode = EvaluationMode::default();
        assert_eq!(mode, EvaluationMode::AllMatch);
        assert!(mode.is_all_match());
        assert!(!mode.is_first_match());
    }

    #[test]
    fn test_evaluation_mode_first_match() {
        let mode = EvaluationMode::FirstMatch;
        assert!(mode.is_first_match());
        assert!(!mode.is_all_match());
    }

    #[test]
    fn test_evaluation_mode_serialization() {
        let first_match = EvaluationMode::FirstMatch;
        let json = serde_json::to_string(&first_match).unwrap();
        assert_eq!(json, "\"first_match\"");

        let all_match = EvaluationMode::AllMatch;
        let json = serde_json::to_string(&all_match).unwrap();
        assert_eq!(json, "\"all_match\"");
    }

    #[test]
    fn test_evaluation_mode_deserialization() {
        let first_match: EvaluationMode = serde_json::from_str("\"first_match\"").unwrap();
        assert_eq!(first_match, EvaluationMode::FirstMatch);

        let all_match: EvaluationMode = serde_json::from_str("\"all_match\"").unwrap();
        assert_eq!(all_match, EvaluationMode::AllMatch);
    }

    #[test]
    fn test_condition_operator_not_equals() {
        let op = ConditionOperator::NotEquals;
        assert!(!op.evaluate(Some("Engineering"), &serde_json::json!("Engineering")));
        assert!(op.evaluate(Some("Sales"), &serde_json::json!("Engineering")));
        assert!(op.evaluate(None, &serde_json::json!("Engineering")));
    }

    #[test]
    fn test_condition_operator_not_in() {
        let op = ConditionOperator::NotIn;
        let values = serde_json::json!(["US", "UK", "DE"]);
        assert!(!op.evaluate(Some("US"), &values));
        assert!(!op.evaluate(Some("UK"), &values));
        assert!(op.evaluate(Some("FR"), &values));
        assert!(op.evaluate(None, &values));
    }

    #[test]
    fn test_condition_operator_contains() {
        let op = ConditionOperator::Contains;
        assert!(op.evaluate(Some("Senior Engineer"), &serde_json::json!("Engineer")));
        assert!(op.evaluate(Some("Engineering Lead"), &serde_json::json!("Engineer")));
        assert!(!op.evaluate(Some("Sales Manager"), &serde_json::json!("Engineer")));
        assert!(!op.evaluate(None, &serde_json::json!("Engineer")));
    }

    #[test]
    fn test_policy_condition_validate_valid() {
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };
        assert!(condition.validate().is_ok());
    }

    #[test]
    fn test_policy_condition_validate_empty_attribute() {
        let condition = PolicyCondition {
            attribute: String::new(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };
        assert!(condition.validate().is_err());
    }

    #[test]
    fn test_policy_condition_validate_invalid_operator() {
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "invalid_op".to_string(),
            value: serde_json::json!("Engineering"),
        };
        assert!(condition.validate().is_err());
    }

    #[test]
    fn test_policy_condition_validate_in_requires_array() {
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "in".to_string(),
            value: serde_json::json!("Engineering"), // Should be an array
        };
        assert!(condition.validate().is_err());
    }

    #[test]
    fn test_policy_condition_validate_in_with_array() {
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "in".to_string(),
            value: serde_json::json!(["Engineering", "Product"]),
        };
        assert!(condition.validate().is_ok());
    }

    // F081: Custom attributes in policy conditions

    #[test]
    fn test_policy_condition_custom_attributes_equals() {
        let condition = PolicyCondition {
            attribute: "custom_attributes.department".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };

        let user_attrs = serde_json::json!({
            "department": "Sales",
            "custom_attributes": {
                "department": "Engineering"
            }
        });

        assert!(condition.evaluate(&user_attrs));
    }

    #[test]
    fn test_policy_condition_custom_attributes_in() {
        let condition = PolicyCondition {
            attribute: "custom_attributes.employee_type".to_string(),
            operator: "in".to_string(),
            value: serde_json::json!(["full_time", "contractor"]),
        };

        let user_attrs = serde_json::json!({
            "custom_attributes": {
                "employee_type": "full_time"
            }
        });

        assert!(condition.evaluate(&user_attrs));
    }

    #[test]
    fn test_policy_condition_custom_attributes_missing_key() {
        let condition = PolicyCondition {
            attribute: "custom_attributes.nonexistent".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("anything"),
        };

        let user_attrs = serde_json::json!({
            "custom_attributes": {
                "department": "Engineering"
            }
        });

        // Missing custom attribute should evaluate to false for equality
        assert!(!condition.evaluate(&user_attrs));
    }

    #[test]
    fn test_policy_condition_custom_attributes_no_custom_attrs() {
        let condition = PolicyCondition {
            attribute: "custom_attributes.department".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };

        let user_attrs = serde_json::json!({
            "department": "Engineering"
        });

        // No custom_attributes key at all should evaluate to false
        assert!(!condition.evaluate(&user_attrs));
    }

    #[test]
    fn test_policy_condition_bare_attribute_unchanged() {
        // Verify that non-prefixed attributes still work as before
        let condition = PolicyCondition {
            attribute: "department".to_string(),
            operator: "equals".to_string(),
            value: serde_json::json!("Engineering"),
        };

        let user_attrs = serde_json::json!({
            "department": "Engineering",
            "custom_attributes": {
                "department": "Sales"
            }
        });

        // Bare "department" should use the top-level value, not custom_attributes
        assert!(condition.evaluate(&user_attrs));
    }
}
