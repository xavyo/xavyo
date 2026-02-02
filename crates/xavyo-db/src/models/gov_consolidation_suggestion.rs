//! Governance Consolidation Suggestion model.
//!
//! Represents pairs of roles with high overlap that could be consolidated.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for a consolidation suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "consolidation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationStatus {
    /// Suggestion is awaiting review.
    Pending,
    /// Roles were merged.
    Merged,
    /// Suggestion was dismissed.
    Dismissed,
}

impl ConsolidationStatus {
    /// Check if suggestion can be updated.
    pub fn can_update(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// A consolidation suggestion for overlapping roles.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovConsolidationSuggestion {
    /// Unique identifier for the suggestion.
    pub id: Uuid,

    /// The tenant this suggestion belongs to.
    pub tenant_id: Uuid,

    /// The mining job that detected this.
    pub job_id: Uuid,

    /// First role in the pair.
    pub role_a_id: Uuid,

    /// Second role in the pair.
    pub role_b_id: Uuid,

    /// Percentage of overlap (Jaccard similarity * 100).
    pub overlap_percent: f64,

    /// Entitlements shared between both roles.
    pub shared_entitlements: Vec<Uuid>,

    /// Entitlements only in role A.
    pub unique_to_a: Vec<Uuid>,

    /// Entitlements only in role B.
    pub unique_to_b: Vec<Uuid>,

    /// Suggestion status.
    pub status: ConsolidationStatus,

    /// Reason for dismissal.
    pub dismissed_reason: Option<String>,

    /// When the suggestion was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a consolidation suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateConsolidationSuggestion {
    pub job_id: Uuid,
    pub role_a_id: Uuid,
    pub role_b_id: Uuid,
    pub overlap_percent: f64,
    pub shared_entitlements: Vec<Uuid>,
    pub unique_to_a: Vec<Uuid>,
    pub unique_to_b: Vec<Uuid>,
}

/// Filter options for listing suggestions.
#[derive(Debug, Clone, Default)]
pub struct ConsolidationSuggestionFilter {
    pub job_id: Option<Uuid>,
    pub status: Option<ConsolidationStatus>,
    pub min_overlap: Option<f64>,
    pub role_id: Option<Uuid>,
}

impl GovConsolidationSuggestion {
    /// Find a suggestion by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_consolidation_suggestions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List suggestions for a job with filtering and pagination.
    pub async fn list_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &ConsolidationSuggestionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_consolidation_suggestions
            WHERE tenant_id = $1 AND job_id = $2
            "#,
        );
        let mut param_count = 2;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.min_overlap.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overlap_percent >= ${}", param_count));
        }
        if filter.role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (role_a_id = ${} OR role_b_id = ${})",
                param_count, param_count
            ));
        }

        query.push_str(&format!(
            " ORDER BY overlap_percent DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovConsolidationSuggestion>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_overlap) = filter.min_overlap {
            q = q.bind(min_overlap);
        }
        if let Some(role_id) = filter.role_id {
            q = q.bind(role_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count suggestions for a job with filtering.
    pub async fn count_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &ConsolidationSuggestionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_consolidation_suggestions
            WHERE tenant_id = $1 AND job_id = $2
            "#,
        );
        let mut param_count = 2;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.min_overlap.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND overlap_percent >= ${}", param_count));
        }
        if filter.role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (role_a_id = ${} OR role_b_id = ${})",
                param_count, param_count
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_overlap) = filter.min_overlap {
            q = q.bind(min_overlap);
        }
        if let Some(role_id) = filter.role_id {
            q = q.bind(role_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new consolidation suggestion.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateConsolidationSuggestion,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_consolidation_suggestions (
                tenant_id, job_id, role_a_id, role_b_id,
                overlap_percent, shared_entitlements, unique_to_a, unique_to_b
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.job_id)
        .bind(input.role_a_id)
        .bind(input.role_b_id)
        .bind(input.overlap_percent)
        .bind(&input.shared_entitlements)
        .bind(&input.unique_to_a)
        .bind(&input.unique_to_b)
        .fetch_one(pool)
        .await
    }

    /// Create multiple suggestions in batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inputs: Vec<CreateConsolidationSuggestion>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let suggestion = Self::create(pool, tenant_id, input).await?;
            results.push(suggestion);
        }
        Ok(results)
    }

    /// Mark as merged.
    pub async fn mark_merged(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_consolidation_suggestions
            SET status = 'merged'
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Dismiss a suggestion.
    pub async fn dismiss(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_consolidation_suggestions
            SET status = 'dismissed', dismissed_reason = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consolidation_status_methods() {
        assert!(ConsolidationStatus::Pending.can_update());
        assert!(!ConsolidationStatus::Merged.can_update());
        assert!(!ConsolidationStatus::Dismissed.can_update());
    }

    #[test]
    fn test_consolidation_status_serialization() {
        let pending = ConsolidationStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let merged = ConsolidationStatus::Merged;
        let json = serde_json::to_string(&merged).unwrap();
        assert_eq!(json, "\"merged\"");

        let dismissed = ConsolidationStatus::Dismissed;
        let json = serde_json::to_string(&dismissed).unwrap();
        assert_eq!(json, "\"dismissed\"");
    }
}
