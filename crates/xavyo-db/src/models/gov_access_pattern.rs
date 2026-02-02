//! Governance Access Pattern model.
//!
//! Represents aggregated access pattern frequency data from mining analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An aggregated access pattern discovered during mining.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovAccessPattern {
    /// Unique identifier for the pattern.
    pub id: Uuid,

    /// The tenant this pattern belongs to.
    pub tenant_id: Uuid,

    /// The mining job that discovered this pattern.
    pub job_id: Uuid,

    /// Entitlements in this pattern combination.
    pub entitlement_ids: Vec<Uuid>,

    /// How often this pattern occurs.
    pub frequency: i32,

    /// Number of users with this exact pattern.
    pub user_count: i32,

    /// Sample user IDs (up to 10).
    pub sample_user_ids: Vec<Uuid>,

    /// When the pattern was discovered.
    pub created_at: DateTime<Utc>,
}

/// Request to create an access pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessPattern {
    pub job_id: Uuid,
    pub entitlement_ids: Vec<Uuid>,
    pub frequency: i32,
    pub user_count: i32,
    pub sample_user_ids: Vec<Uuid>,
}

/// Filter options for listing patterns.
#[derive(Debug, Clone, Default)]
pub struct AccessPatternFilter {
    pub min_frequency: Option<i32>,
    pub min_users: Option<i32>,
}

impl GovAccessPattern {
    /// Find a pattern by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_patterns
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List patterns for a job with filtering and pagination.
    pub async fn list_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &AccessPatternFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_access_patterns
            WHERE tenant_id = $1 AND job_id = $2
            "#,
        );
        let mut param_count = 2;

        if filter.min_frequency.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND frequency >= ${}", param_count));
        }
        if filter.min_users.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_count >= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY frequency DESC, user_count DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovAccessPattern>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(min_freq) = filter.min_frequency {
            q = q.bind(min_freq);
        }
        if let Some(min_users) = filter.min_users {
            q = q.bind(min_users);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count patterns for a job with filtering.
    pub async fn count_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &AccessPatternFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_access_patterns
            WHERE tenant_id = $1 AND job_id = $2
            "#,
        );
        let mut param_count = 2;

        if filter.min_frequency.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND frequency >= ${}", param_count));
        }
        if filter.min_users.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_count >= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(min_freq) = filter.min_frequency {
            q = q.bind(min_freq);
        }
        if let Some(min_users) = filter.min_users {
            q = q.bind(min_users);
        }

        q.fetch_one(pool).await
    }

    /// Create a new access pattern.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateAccessPattern,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_access_patterns (
                tenant_id, job_id, entitlement_ids, frequency,
                user_count, sample_user_ids
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.job_id)
        .bind(&input.entitlement_ids)
        .bind(input.frequency)
        .bind(input.user_count)
        .bind(&input.sample_user_ids)
        .fetch_one(pool)
        .await
    }

    /// Create multiple patterns in batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inputs: Vec<CreateAccessPattern>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let pattern = Self::create(pool, tenant_id, input).await?;
            results.push(pattern);
        }
        Ok(results)
    }

    /// Delete all patterns for a job.
    pub async fn delete_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_access_patterns
            WHERE tenant_id = $1 AND job_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(job_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_pattern_filter_defaults() {
        let filter = AccessPatternFilter::default();
        assert!(filter.min_frequency.is_none());
        assert!(filter.min_users.is_none());
    }

    #[test]
    fn test_create_access_pattern_serialization() {
        let input = CreateAccessPattern {
            job_id: Uuid::new_v4(),
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            frequency: 10,
            user_count: 5,
            sample_user_ids: vec![Uuid::new_v4()],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"frequency\":10"));
        assert!(json.contains("\"user_count\":5"));
    }
}
