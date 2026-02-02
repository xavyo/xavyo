//! Governance Template Merge Policy model (F058).
//!
//! Defines merge policies for handling multi-source data conflicts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{TemplateMergeStrategy, TemplateNullHandling};

/// A merge policy that defines how to resolve conflicts when data comes from multiple sources.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateMergePolicy {
    /// Unique identifier for the policy.
    pub id: Uuid,

    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// The template this policy belongs to.
    pub template_id: Uuid,

    /// Target attribute this policy applies to.
    pub attribute: String,

    /// Merge strategy to use.
    pub strategy: TemplateMergeStrategy,

    /// Ordered list of sources for source_precedence strategy.
    pub source_precedence: Option<serde_json::Value>,

    /// How to handle null values.
    pub null_handling: TemplateNullHandling,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new merge policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateMergePolicy {
    pub attribute: String,
    pub strategy: TemplateMergeStrategy,
    pub source_precedence: Option<Vec<String>>,
    pub null_handling: Option<TemplateNullHandling>,
}

/// Request to update a merge policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovTemplateMergePolicy {
    pub strategy: Option<TemplateMergeStrategy>,
    pub source_precedence: Option<Vec<String>>,
    pub null_handling: Option<TemplateNullHandling>,
}

impl GovTemplateMergePolicy {
    /// Find a policy by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_merge_policies
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a policy by attribute for a template.
    pub async fn find_by_attribute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        attribute: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_merge_policies
            WHERE tenant_id = $1 AND template_id = $2 AND attribute = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(attribute)
        .fetch_optional(pool)
        .await
    }

    /// List all merge policies for a template.
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_merge_policies
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY attribute ASC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List merge policies by strategy.
    pub async fn list_by_strategy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        strategy: TemplateMergeStrategy,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_merge_policies
            WHERE tenant_id = $1 AND template_id = $2 AND strategy = $3
            ORDER BY attribute ASC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(strategy)
        .fetch_all(pool)
        .await
    }

    /// Create a new merge policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        input: CreateGovTemplateMergePolicy,
    ) -> Result<Self, sqlx::Error> {
        let null_handling = input.null_handling.unwrap_or_default();
        let source_precedence = input
            .source_precedence
            .map(|sp| serde_json::to_value(sp).unwrap_or(serde_json::Value::Null));

        sqlx::query_as(
            r#"
            INSERT INTO gov_template_merge_policies (
                tenant_id, template_id, attribute, strategy,
                source_precedence, null_handling
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .bind(&input.attribute)
        .bind(input.strategy)
        .bind(&source_precedence)
        .bind(null_handling)
        .fetch_one(pool)
        .await
    }

    /// Update a merge policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovTemplateMergePolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if input.strategy.is_some() {
            param_count += 1;
            updates.push(format!("strategy = ${}", param_count));
        }
        if input.source_precedence.is_some() {
            param_count += 1;
            updates.push(format!("source_precedence = ${}", param_count));
        }
        if input.null_handling.is_some() {
            param_count += 1;
            updates.push(format!("null_handling = ${}", param_count));
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        updates.push("updated_at = NOW()".to_string());
        let query = format!(
            "UPDATE gov_template_merge_policies SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(strategy) = input.strategy {
            q = q.bind(strategy);
        }
        if let Some(ref source_precedence) = input.source_precedence {
            let json_value =
                serde_json::to_value(source_precedence).unwrap_or(serde_json::Value::Null);
            q = q.bind(json_value);
        }
        if let Some(null_handling) = input.null_handling {
            q = q.bind(null_handling);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a merge policy.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_merge_policies
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all merge policies for a template.
    pub async fn delete_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_template_merge_policies
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count merge policies for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_merge_policies
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Get the source precedence as a Vec<String>.
    pub fn get_source_precedence(&self) -> Option<Vec<String>> {
        self.source_precedence
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Check if this policy uses source precedence strategy.
    pub fn is_source_precedence(&self) -> bool {
        self.strategy == TemplateMergeStrategy::SourcePrecedence
    }

    /// Check if this policy uses timestamp wins strategy.
    pub fn is_timestamp_wins(&self) -> bool {
        self.strategy == TemplateMergeStrategy::TimestampWins
    }

    /// Check if this policy uses concatenate unique strategy.
    pub fn is_concatenate_unique(&self) -> bool {
        self.strategy == TemplateMergeStrategy::ConcatenateUnique
    }

    /// Check if this policy uses first wins strategy.
    pub fn is_first_wins(&self) -> bool {
        self.strategy == TemplateMergeStrategy::FirstWins
    }

    /// Check if this policy uses manual only strategy.
    pub fn is_manual_only(&self) -> bool {
        self.strategy == TemplateMergeStrategy::ManualOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_source_precedence_policy() {
        let input = CreateGovTemplateMergePolicy {
            attribute: "employeeNumber".to_string(),
            strategy: TemplateMergeStrategy::SourcePrecedence,
            source_precedence: Some(vec![
                "hr_system".to_string(),
                "active_directory".to_string(),
                "manual".to_string(),
            ]),
            null_handling: None,
        };

        assert_eq!(input.attribute, "employeeNumber");
        assert_eq!(input.strategy, TemplateMergeStrategy::SourcePrecedence);
        assert!(input.source_precedence.is_some());
    }

    #[test]
    fn test_create_timestamp_wins_policy() {
        let input = CreateGovTemplateMergePolicy {
            attribute: "title".to_string(),
            strategy: TemplateMergeStrategy::TimestampWins,
            source_precedence: None,
            null_handling: Some(TemplateNullHandling::PreserveEmpty),
        };

        assert_eq!(input.strategy, TemplateMergeStrategy::TimestampWins);
        assert_eq!(
            input.null_handling,
            Some(TemplateNullHandling::PreserveEmpty)
        );
    }

    #[test]
    fn test_null_handling_default() {
        assert_eq!(TemplateNullHandling::default(), TemplateNullHandling::Merge);
    }
}
