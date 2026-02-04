//! Governance Excessive Privilege model.
//!
//! Represents users flagged for having more access than their peers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for an excessive privilege flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "privilege_flag_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeFlagStatus {
    /// Flag is awaiting review.
    Pending,
    /// Flag was reviewed and acknowledged.
    Reviewed,
    /// Excess access was remediated.
    Remediated,
    /// Excess access was accepted as justified.
    Accepted,
}

impl PrivilegeFlagStatus {
    /// Check if flag can be updated.
    #[must_use] 
    pub fn can_update(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// An excessive privilege flag for a user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovExcessivePrivilege {
    /// Unique identifier for the flag.
    pub id: Uuid,

    /// The tenant this flag belongs to.
    pub tenant_id: Uuid,

    /// The mining job that detected this.
    pub job_id: Uuid,

    /// The user with excessive access.
    pub user_id: Uuid,

    /// The peer group used for comparison.
    pub peer_group_id: Option<Uuid>,

    /// Percentage above peer average.
    pub deviation_percent: f64,

    /// Specific entitlements that are excessive.
    pub excess_entitlements: Vec<Uuid>,

    /// Peer group's average entitlement count.
    pub peer_average: f64,

    /// User's entitlement count.
    pub user_count: i32,

    /// Flag status.
    pub status: PrivilegeFlagStatus,

    /// When the flag was reviewed.
    pub reviewed_at: Option<DateTime<Utc>>,

    /// Who reviewed the flag.
    pub reviewed_by: Option<Uuid>,

    /// Review notes.
    pub notes: Option<String>,

    /// When the flag was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create an excessive privilege flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExcessivePrivilege {
    pub job_id: Uuid,
    pub user_id: Uuid,
    pub peer_group_id: Option<Uuid>,
    pub deviation_percent: f64,
    pub excess_entitlements: Vec<Uuid>,
    pub peer_average: f64,
    pub user_count: i32,
}

/// Request to update a flag's status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateExcessivePrivilegeStatus {
    pub status: PrivilegeFlagStatus,
    pub reviewed_by: Uuid,
    pub notes: Option<String>,
}

/// Filter options for listing flags.
#[derive(Debug, Clone, Default)]
pub struct ExcessivePrivilegeFilter {
    pub job_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<PrivilegeFlagStatus>,
    pub min_deviation: Option<f64>,
}

impl GovExcessivePrivilege {
    /// Find a flag by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_excessive_privileges
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List flags for a job with filtering and pagination.
    pub async fn list_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &ExcessivePrivilegeFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_excessive_privileges
            WHERE tenant_id = $1 AND job_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.min_deviation.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND deviation_percent >= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY deviation_percent DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovExcessivePrivilege>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_dev) = filter.min_deviation {
            q = q.bind(min_dev);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count flags for a job with filtering.
    pub async fn count_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &ExcessivePrivilegeFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_excessive_privileges
            WHERE tenant_id = $1 AND job_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.min_deviation.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND deviation_percent >= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_dev) = filter.min_deviation {
            q = q.bind(min_dev);
        }

        q.fetch_one(pool).await
    }

    /// List flags by user across all jobs.
    pub async fn list_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_excessive_privileges
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Create a new excessive privilege flag.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateExcessivePrivilege,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_excessive_privileges (
                tenant_id, job_id, user_id, peer_group_id,
                deviation_percent, excess_entitlements, peer_average, user_count
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.job_id)
        .bind(input.user_id)
        .bind(input.peer_group_id)
        .bind(input.deviation_percent)
        .bind(&input.excess_entitlements)
        .bind(input.peer_average)
        .bind(input.user_count)
        .fetch_one(pool)
        .await
    }

    /// Create multiple flags in batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inputs: Vec<CreateExcessivePrivilege>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let flag = Self::create(pool, tenant_id, input).await?;
            results.push(flag);
        }
        Ok(results)
    }

    /// Update a flag's status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateExcessivePrivilegeStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_excessive_privileges
            SET status = $3, reviewed_at = NOW(), reviewed_by = $4, notes = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.reviewed_by)
        .bind(&input.notes)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_flag_status_methods() {
        assert!(PrivilegeFlagStatus::Pending.can_update());
        assert!(!PrivilegeFlagStatus::Reviewed.can_update());
        assert!(!PrivilegeFlagStatus::Remediated.can_update());
        assert!(!PrivilegeFlagStatus::Accepted.can_update());
    }

    #[test]
    fn test_privilege_flag_status_serialization() {
        let pending = PrivilegeFlagStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let reviewed = PrivilegeFlagStatus::Reviewed;
        let json = serde_json::to_string(&reviewed).unwrap();
        assert_eq!(json, "\"reviewed\"");

        let remediated = PrivilegeFlagStatus::Remediated;
        let json = serde_json::to_string(&remediated).unwrap();
        assert_eq!(json, "\"remediated\"");

        let accepted = PrivilegeFlagStatus::Accepted;
        let json = serde_json::to_string(&accepted).unwrap();
        assert_eq!(json, "\"accepted\"");
    }
}
