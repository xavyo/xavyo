//! Governance Detection Rule model.
//!
//! Represents configurable rules for orphan account detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_detection_rule_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DetectionRuleType {
    /// Detect users without a manager assigned.
    NoManager,
    /// Detect users marked as terminated in HR.
    Terminated,
    /// Detect users inactive for configured period.
    Inactive,
    /// Custom detection rule with expression.
    Custom,
}

impl DetectionRuleType {
    /// Check if this rule type requires parameters.
    pub fn requires_parameters(&self) -> bool {
        matches!(self, Self::Inactive | Self::Custom)
    }

    /// Get default parameters for this rule type.
    pub fn default_parameters(&self) -> serde_json::Value {
        match self {
            Self::NoManager => serde_json::json!({}),
            Self::Terminated => serde_json::json!({}),
            Self::Inactive => serde_json::json!({ "days_threshold": 90 }),
            Self::Custom => serde_json::json!({ "expression": "" }),
        }
    }
}

/// A governance detection rule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovDetectionRule {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// Rule display name.
    pub name: String,

    /// Type of detection rule.
    pub rule_type: DetectionRuleType,

    /// Whether this rule is enabled.
    pub is_enabled: bool,

    /// Priority for rule execution (lower = higher priority).
    pub priority: i32,

    /// Rule-specific parameters (e.g., days_threshold for inactive).
    pub parameters: serde_json::Value,

    /// Human-readable description.
    pub description: Option<String>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovDetectionRule {
    pub name: String,
    pub rule_type: DetectionRuleType,
    pub is_enabled: Option<bool>,
    pub priority: Option<i32>,
    pub parameters: Option<serde_json::Value>,
    pub description: Option<String>,
}

/// Request to update a detection rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovDetectionRule {
    pub name: Option<String>,
    pub is_enabled: Option<bool>,
    pub priority: Option<i32>,
    pub parameters: Option<serde_json::Value>,
    pub description: Option<String>,
}

/// Filter options for listing detection rules.
#[derive(Debug, Clone, Default)]
pub struct DetectionRuleFilter {
    pub rule_type: Option<DetectionRuleType>,
    pub is_enabled: Option<bool>,
}

impl GovDetectionRule {
    /// Find a rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_detection_rules
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a rule by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_detection_rules
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List enabled rules for a tenant ordered by priority.
    pub async fn list_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_detection_rules
            WHERE tenant_id = $1 AND is_enabled = true
            ORDER BY priority ASC, name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List rules by type for a tenant.
    pub async fn list_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_type: DetectionRuleType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_detection_rules
            WHERE tenant_id = $1 AND rule_type = $2
            ORDER BY priority ASC
            "#,
        )
        .bind(tenant_id)
        .bind(rule_type)
        .fetch_all(pool)
        .await
    }

    /// List all rules for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DetectionRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_detection_rules
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.rule_type.is_some() {
            query.push_str(&format!(" AND rule_type = ${}", param_idx));
            param_idx += 1;
        }

        if filter.is_enabled.is_some() {
            query.push_str(&format!(" AND is_enabled = ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY priority ASC, name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(rule_type) = filter.rule_type {
            q = q.bind(rule_type);
        }

        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count rules for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DetectionRuleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_detection_rules
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.rule_type.is_some() {
            query.push_str(&format!(" AND rule_type = ${}", param_idx));
            param_idx += 1;
        }

        if filter.is_enabled.is_some() {
            query.push_str(&format!(" AND is_enabled = ${}", param_idx));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(rule_type) = filter.rule_type {
            q = q.bind(rule_type);
        }

        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }

        q.fetch_one(pool).await
    }

    /// Create a new detection rule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovDetectionRule,
    ) -> Result<Self, sqlx::Error> {
        let parameters = data
            .parameters
            .unwrap_or_else(|| data.rule_type.default_parameters());

        sqlx::query_as(
            r#"
            INSERT INTO gov_detection_rules (
                tenant_id, name, rule_type, is_enabled, priority, parameters, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&data.name)
        .bind(data.rule_type)
        .bind(data.is_enabled.unwrap_or(true))
        .bind(data.priority.unwrap_or(100))
        .bind(&parameters)
        .bind(&data.description)
        .fetch_one(pool)
        .await
    }

    /// Update a detection rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: UpdateGovDetectionRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_detection_rules
            SET
                name = COALESCE($3, name),
                is_enabled = COALESCE($4, is_enabled),
                priority = COALESCE($5, priority),
                parameters = COALESCE($6, parameters),
                description = COALESCE($7, description)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(data.name)
        .bind(data.is_enabled)
        .bind(data.priority)
        .bind(data.parameters)
        .bind(data.description)
        .fetch_optional(pool)
        .await
    }

    /// Enable a detection rule.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_detection_rules
            SET is_enabled = true
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a detection rule.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_detection_rules
            SET is_enabled = false
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a detection rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_detection_rules
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Seed default rules for a tenant.
    pub async fn seed_defaults(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let defaults = vec![
            CreateGovDetectionRule {
                name: "No Manager Rule".to_string(),
                rule_type: DetectionRuleType::NoManager,
                is_enabled: Some(true),
                priority: Some(10),
                parameters: None,
                description: Some("Detect users without a manager assigned".to_string()),
            },
            CreateGovDetectionRule {
                name: "Terminated Employee Rule".to_string(),
                rule_type: DetectionRuleType::Terminated,
                is_enabled: Some(true),
                priority: Some(20),
                parameters: None,
                description: Some("Detect users marked as terminated in HR system".to_string()),
            },
            CreateGovDetectionRule {
                name: "Inactive User Rule".to_string(),
                rule_type: DetectionRuleType::Inactive,
                is_enabled: Some(true),
                priority: Some(30),
                parameters: Some(serde_json::json!({ "days_threshold": 90 })),
                description: Some("Detect users inactive for 90+ days".to_string()),
            },
        ];

        let mut created = Vec::new();
        for rule in defaults {
            // Skip if rule already exists
            if Self::find_by_name(pool, tenant_id, &rule.name)
                .await?
                .is_none()
            {
                created.push(Self::create(pool, tenant_id, rule).await?);
            }
        }

        Ok(created)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_type_requires_parameters() {
        assert!(!DetectionRuleType::NoManager.requires_parameters());
        assert!(!DetectionRuleType::Terminated.requires_parameters());
        assert!(DetectionRuleType::Inactive.requires_parameters());
        assert!(DetectionRuleType::Custom.requires_parameters());
    }

    #[test]
    fn test_rule_type_default_parameters() {
        let inactive_params = DetectionRuleType::Inactive.default_parameters();
        assert_eq!(inactive_params["days_threshold"], 90);

        let no_manager_params = DetectionRuleType::NoManager.default_parameters();
        assert!(no_manager_params.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_rule_type_serialization() {
        let inactive = DetectionRuleType::Inactive;
        let json = serde_json::to_string(&inactive).unwrap();
        assert_eq!(json, "\"inactive\"");

        let no_manager = DetectionRuleType::NoManager;
        let json = serde_json::to_string(&no_manager).unwrap();
        assert_eq!(json, "\"no_manager\"");
    }
}
