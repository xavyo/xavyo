//! Governance Template Rule model (F058).
//!
//! Represents individual rules within a template for defaults, computed values,
//! validation, and normalization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{TemplateRuleType, TemplateStrength, TemplateTimeReference};

/// A rule within an object template.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateRule {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// The template this rule belongs to.
    pub template_id: Uuid,

    /// Type of rule (default, computed, validation, normalization).
    pub rule_type: TemplateRuleType,

    /// Target attribute this rule affects.
    pub target_attribute: String,

    /// Expression or value for the rule.
    pub expression: String,

    /// Mapping strength (strong, normal, weak).
    pub strength: TemplateStrength,

    /// Whether values are removed when source changes (for computed).
    pub authoritative: bool,

    /// Priority for rule ordering within template (lower = first).
    pub priority: i32,

    /// Optional condition expression for when rule applies.
    pub condition: Option<String>,

    /// Custom error message for validation failures.
    pub error_message: Option<String>,

    /// If true, no other rule can target the same attribute (IGA pattern: exclusive mapping).
    pub exclusive: bool,

    /// Rule only applies after this timestamp.
    pub time_from: Option<DateTime<Utc>>,

    /// Rule only applies before this timestamp.
    pub time_to: Option<DateTime<Utc>>,

    /// How to interpret `time_from/time_to`.
    pub time_reference: Option<TemplateTimeReference>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new template rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateRule {
    pub rule_type: TemplateRuleType,
    pub target_attribute: String,
    pub expression: String,
    pub strength: Option<TemplateStrength>,
    pub authoritative: Option<bool>,
    pub priority: Option<i32>,
    pub condition: Option<String>,
    pub error_message: Option<String>,
    pub exclusive: Option<bool>,
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub time_reference: Option<TemplateTimeReference>,
}

/// Request to update a template rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovTemplateRule {
    pub expression: Option<String>,
    pub strength: Option<TemplateStrength>,
    pub authoritative: Option<bool>,
    pub priority: Option<i32>,
    pub condition: Option<String>,
    pub error_message: Option<String>,
    pub exclusive: Option<bool>,
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub time_reference: Option<TemplateTimeReference>,
}

/// Filter options for listing template rules.
#[derive(Debug, Clone, Default)]
pub struct TemplateRuleFilter {
    pub template_id: Option<Uuid>,
    pub rule_type: Option<TemplateRuleType>,
    pub target_attribute: Option<String>,
    pub strength: Option<TemplateStrength>,
}

/// Default rule priority.
pub const DEFAULT_RULE_PRIORITY: i32 = 100;

/// Minimum rule priority.
pub const MIN_RULE_PRIORITY: i32 = 1;

/// Maximum rule priority.
pub const MAX_RULE_PRIORITY: i32 = 1000;

impl GovTemplateRule {
    /// Find a rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all rules for a template ordered by priority.
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_rules
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY priority ASC, target_attribute ASC
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List rules by type for a template.
    pub async fn list_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_type: TemplateRuleType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_rules
            WHERE tenant_id = $1 AND template_id = $2 AND rule_type = $3
            ORDER BY priority ASC, target_attribute ASC
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(rule_type)
        .fetch_all(pool)
        .await
    }

    /// List rules targeting a specific attribute across all templates.
    pub async fn list_by_attribute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        target_attribute: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_rules
            WHERE tenant_id = $1 AND target_attribute = $2
            ORDER BY priority ASC
            ",
        )
        .bind(tenant_id)
        .bind(target_attribute)
        .fetch_all(pool)
        .await
    }

    /// List rules with filtering and pagination.
    pub async fn list_with_filter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TemplateRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_template_rules WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.rule_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND rule_type = ${param_count}"));
        }
        if filter.target_attribute.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_attribute = ${param_count}"));
        }
        if filter.strength.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND strength = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY priority ASC, target_attribute ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(rule_type) = filter.rule_type {
            q = q.bind(rule_type);
        }
        if let Some(ref target_attribute) = filter.target_attribute {
            q = q.bind(target_attribute);
        }
        if let Some(strength) = filter.strength {
            q = q.bind(strength);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new template rule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        input: CreateGovTemplateRule,
    ) -> Result<Self, sqlx::Error> {
        let strength = input.strength.unwrap_or_default();
        let authoritative = input.authoritative.unwrap_or(true);
        let priority = input.priority.unwrap_or(DEFAULT_RULE_PRIORITY);
        let exclusive = input.exclusive.unwrap_or(false);

        sqlx::query_as(
            r"
            INSERT INTO gov_template_rules (
                tenant_id, template_id, rule_type, target_attribute, expression,
                strength, authoritative, priority, condition, error_message,
                exclusive, time_from, time_to, time_reference
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(input.rule_type)
        .bind(&input.target_attribute)
        .bind(&input.expression)
        .bind(strength)
        .bind(authoritative)
        .bind(priority)
        .bind(&input.condition)
        .bind(&input.error_message)
        .bind(exclusive)
        .bind(input.time_from)
        .bind(input.time_to)
        .bind(input.time_reference)
        .fetch_one(pool)
        .await
    }

    /// Update a template rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovTemplateRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if input.expression.is_some() {
            param_count += 1;
            updates.push(format!("expression = ${param_count}"));
        }
        if input.strength.is_some() {
            param_count += 1;
            updates.push(format!("strength = ${param_count}"));
        }
        if input.authoritative.is_some() {
            param_count += 1;
            updates.push(format!("authoritative = ${param_count}"));
        }
        if input.priority.is_some() {
            param_count += 1;
            updates.push(format!("priority = ${param_count}"));
        }
        if input.condition.is_some() {
            param_count += 1;
            updates.push(format!("condition = ${param_count}"));
        }
        if input.error_message.is_some() {
            param_count += 1;
            updates.push(format!("error_message = ${param_count}"));
        }
        if input.exclusive.is_some() {
            param_count += 1;
            updates.push(format!("exclusive = ${param_count}"));
        }
        if input.time_from.is_some() {
            param_count += 1;
            updates.push(format!("time_from = ${param_count}"));
        }
        if input.time_to.is_some() {
            param_count += 1;
            updates.push(format!("time_to = ${param_count}"));
        }
        if input.time_reference.is_some() {
            param_count += 1;
            updates.push(format!("time_reference = ${param_count}"));
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        updates.push("updated_at = NOW()".to_string());
        let query = format!(
            "UPDATE gov_template_rules SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref expression) = input.expression {
            q = q.bind(expression);
        }
        if let Some(strength) = input.strength {
            q = q.bind(strength);
        }
        if let Some(authoritative) = input.authoritative {
            q = q.bind(authoritative);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        if let Some(ref condition) = input.condition {
            q = q.bind(condition);
        }
        if let Some(ref error_message) = input.error_message {
            q = q.bind(error_message);
        }
        if let Some(exclusive) = input.exclusive {
            q = q.bind(exclusive);
        }
        if let Some(time_from) = input.time_from {
            q = q.bind(time_from);
        }
        if let Some(time_to) = input.time_to {
            q = q.bind(time_to);
        }
        if let Some(time_reference) = input.time_reference {
            q = q.bind(time_reference);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a template rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_template_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all rules for a template.
    pub async fn delete_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_template_rules
            WHERE tenant_id = $1 AND template_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count rules for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_template_rules
            WHERE tenant_id = $1 AND template_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Check if rule is for validation.
    #[must_use] 
    pub fn is_validation(&self) -> bool {
        self.rule_type == TemplateRuleType::Validation
    }

    /// Check if rule is for computed values.
    #[must_use] 
    pub fn is_computed(&self) -> bool {
        self.rule_type == TemplateRuleType::Computed
    }

    /// Check if rule is for defaults.
    #[must_use] 
    pub fn is_default(&self) -> bool {
        self.rule_type == TemplateRuleType::Default
    }

    /// Check if rule is for normalization.
    #[must_use] 
    pub fn is_normalization(&self) -> bool {
        self.rule_type == TemplateRuleType::Normalization
    }

    /// Check if rule has strong strength.
    #[must_use] 
    pub fn is_strong(&self) -> bool {
        self.strength == TemplateStrength::Strong
    }

    /// Check if rule has weak strength.
    #[must_use] 
    pub fn is_weak(&self) -> bool {
        self.strength == TemplateStrength::Weak
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rule_defaults() {
        let input = CreateGovTemplateRule {
            rule_type: TemplateRuleType::Default,
            target_attribute: "department".to_string(),
            expression: "Unassigned".to_string(),
            strength: None,
            authoritative: None,
            priority: None,
            condition: None,
            error_message: None,
            exclusive: None,
            time_from: None,
            time_to: None,
            time_reference: None,
        };

        assert_eq!(input.rule_type, TemplateRuleType::Default);
        assert_eq!(input.target_attribute, "department");
        assert!(input.strength.is_none());
        assert!(input.exclusive.is_none());
        assert!(input.time_from.is_none());
    }

    #[test]
    fn test_rule_priority_constants() {
        assert_eq!(DEFAULT_RULE_PRIORITY, 100);
        assert_eq!(MIN_RULE_PRIORITY, 1);
        assert_eq!(MAX_RULE_PRIORITY, 1000);
    }

    #[test]
    fn test_filter_default() {
        let filter = TemplateRuleFilter::default();
        assert!(filter.template_id.is_none());
        assert!(filter.rule_type.is_none());
        assert!(filter.target_attribute.is_none());
        assert!(filter.strength.is_none());
    }
}
