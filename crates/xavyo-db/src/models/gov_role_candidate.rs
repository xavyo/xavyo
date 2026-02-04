//! Governance Role Candidate model.
//!
//! Represents discovered potential roles from mining analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Promotion status for a role candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "candidate_promotion_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CandidatePromotionStatus {
    /// Candidate is awaiting review.
    Pending,
    /// Candidate was promoted to an actual role.
    Promoted,
    /// Candidate was dismissed.
    Dismissed,
}

impl CandidatePromotionStatus {
    /// Check if candidate can be promoted.
    #[must_use] 
    pub fn can_promote(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if candidate can be dismissed.
    #[must_use] 
    pub fn can_dismiss(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// A discovered role candidate from mining.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleCandidate {
    /// Unique identifier for the candidate.
    pub id: Uuid,

    /// The tenant this candidate belongs to.
    pub tenant_id: Uuid,

    /// The mining job that discovered this candidate.
    pub job_id: Uuid,

    /// Proposed name for the role.
    pub proposed_name: String,

    /// Confidence score (0.0 - 1.0).
    pub confidence_score: f64,

    /// Number of users matching this pattern.
    pub member_count: i32,

    /// Entitlements in this candidate role.
    pub entitlement_ids: Vec<Uuid>,

    /// Users matching this pattern.
    pub user_ids: Vec<Uuid>,

    /// Promotion status.
    pub promotion_status: CandidatePromotionStatus,

    /// ID of the role if promoted.
    pub promoted_role_id: Option<Uuid>,

    /// Reason for dismissal.
    pub dismissed_reason: Option<String>,

    /// When the candidate was discovered.
    pub created_at: DateTime<Utc>,
}

/// Request to create a role candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleCandidate {
    pub job_id: Uuid,
    pub proposed_name: String,
    pub confidence_score: f64,
    pub member_count: i32,
    pub entitlement_ids: Vec<Uuid>,
    pub user_ids: Vec<Uuid>,
}

/// Filter options for listing candidates.
#[derive(Debug, Clone, Default)]
pub struct RoleCandidateFilter {
    pub job_id: Option<Uuid>,
    pub promotion_status: Option<CandidatePromotionStatus>,
    pub min_confidence: Option<f64>,
    pub min_members: Option<i32>,
}

impl GovRoleCandidate {
    /// Find a candidate by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_role_candidates
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List candidates for a job with filtering and pagination.
    pub async fn list_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &RoleCandidateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_role_candidates
            WHERE tenant_id = $1 AND job_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.promotion_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND promotion_status = ${param_count}"));
        }
        if filter.min_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score >= ${param_count}"));
        }
        if filter.min_members.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND member_count >= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY confidence_score DESC, member_count DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRoleCandidate>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(status) = filter.promotion_status {
            q = q.bind(status);
        }
        if let Some(min_conf) = filter.min_confidence {
            q = q.bind(min_conf);
        }
        if let Some(min_members) = filter.min_members {
            q = q.bind(min_members);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count candidates for a job with filtering.
    pub async fn count_by_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        filter: &RoleCandidateFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_role_candidates
            WHERE tenant_id = $1 AND job_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.promotion_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND promotion_status = ${param_count}"));
        }
        if filter.min_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score >= ${param_count}"));
        }
        if filter.min_members.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND member_count >= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(job_id);

        if let Some(status) = filter.promotion_status {
            q = q.bind(status);
        }
        if let Some(min_conf) = filter.min_confidence {
            q = q.bind(min_conf);
        }
        if let Some(min_members) = filter.min_members {
            q = q.bind(min_members);
        }

        q.fetch_one(pool).await
    }

    /// Create a new role candidate.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateRoleCandidate,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_role_candidates (
                tenant_id, job_id, proposed_name, confidence_score,
                member_count, entitlement_ids, user_ids
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.job_id)
        .bind(&input.proposed_name)
        .bind(input.confidence_score)
        .bind(input.member_count)
        .bind(&input.entitlement_ids)
        .bind(&input.user_ids)
        .fetch_one(pool)
        .await
    }

    /// Create multiple candidates in batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inputs: Vec<CreateRoleCandidate>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let candidate = Self::create(pool, tenant_id, input).await?;
            results.push(candidate);
        }
        Ok(results)
    }

    /// Promote a candidate to a role.
    pub async fn promote(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_role_candidates
            SET promotion_status = 'promoted', promoted_role_id = $3
            WHERE id = $1 AND tenant_id = $2 AND promotion_status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(role_id)
        .fetch_optional(pool)
        .await
    }

    /// Dismiss a candidate.
    pub async fn dismiss(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_role_candidates
            SET promotion_status = 'dismissed', dismissed_reason = $3
            WHERE id = $1 AND tenant_id = $2 AND promotion_status = 'pending'
            RETURNING *
            ",
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
    fn test_candidate_promotion_status_methods() {
        assert!(CandidatePromotionStatus::Pending.can_promote());
        assert!(!CandidatePromotionStatus::Promoted.can_promote());
        assert!(!CandidatePromotionStatus::Dismissed.can_promote());

        assert!(CandidatePromotionStatus::Pending.can_dismiss());
        assert!(!CandidatePromotionStatus::Promoted.can_dismiss());
        assert!(!CandidatePromotionStatus::Dismissed.can_dismiss());
    }

    #[test]
    fn test_candidate_status_serialization() {
        let pending = CandidatePromotionStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let promoted = CandidatePromotionStatus::Promoted;
        let json = serde_json::to_string(&promoted).unwrap();
        assert_eq!(json, "\"promoted\"");

        let dismissed = CandidatePromotionStatus::Dismissed;
        let json = serde_json::to_string(&dismissed).unwrap();
        assert_eq!(json, "\"dismissed\"");
    }
}
