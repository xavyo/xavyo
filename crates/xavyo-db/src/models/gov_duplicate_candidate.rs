//! Governance Duplicate Candidate model.
//!
//! Represents potential duplicate identity pairs detected by correlation rules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for duplicate candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_duplicate_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovDuplicateStatus {
    /// Awaiting review.
    Pending,
    /// Successfully merged.
    Merged,
    /// Dismissed as false positive.
    Dismissed,
}

/// Individual rule match details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub attribute: String,
    pub value_a: Option<String>,
    pub value_b: Option<String>,
    pub similarity: f64,
    pub weighted_score: f64,
}

/// Rule matches container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMatches {
    pub matches: Vec<RuleMatch>,
    pub total_confidence: f64,
}

/// A governance duplicate candidate pair.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovDuplicateCandidate {
    /// Unique identifier for the candidate.
    pub id: Uuid,

    /// The tenant this candidate belongs to.
    pub tenant_id: Uuid,

    /// First identity in the pair (canonical order: a < b).
    pub identity_a_id: Uuid,

    /// Second identity in the pair (canonical order: a < b).
    pub identity_b_id: Uuid,

    /// Overall match confidence (0.00-100.00).
    pub confidence_score: rust_decimal::Decimal,

    /// Current status.
    pub status: GovDuplicateStatus,

    /// JSONB details of which rules matched.
    pub rule_matches: serde_json::Value,

    /// When the duplicate was detected.
    pub detected_at: DateTime<Utc>,

    /// If dismissed, the reason.
    pub dismissed_reason: Option<String>,

    /// Who dismissed (if dismissed).
    pub dismissed_by: Option<Uuid>,

    /// When dismissed (if dismissed).
    pub dismissed_at: Option<DateTime<Utc>>,
}

/// Request to create a new duplicate candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovDuplicateCandidate {
    pub identity_a_id: Uuid,
    pub identity_b_id: Uuid,
    pub confidence_score: rust_decimal::Decimal,
    pub rule_matches: RuleMatches,
}

/// Request to dismiss a duplicate candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DismissGovDuplicateCandidate {
    pub reason: String,
    pub dismissed_by: Uuid,
}

/// Filter options for listing duplicate candidates.
#[derive(Debug, Clone, Default)]
pub struct DuplicateCandidateFilter {
    pub status: Option<GovDuplicateStatus>,
    pub min_confidence: Option<rust_decimal::Decimal>,
    pub max_confidence: Option<rust_decimal::Decimal>,
    pub identity_id: Option<Uuid>,
}

impl GovDuplicateCandidate {
    /// Ensure canonical ordering of identity IDs (a < b).
    fn canonical_order(id_a: Uuid, id_b: Uuid) -> (Uuid, Uuid) {
        if id_a < id_b {
            (id_a, id_b)
        } else {
            (id_b, id_a)
        }
    }

    /// Find a candidate by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_duplicate_candidates
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a candidate by identity pair.
    pub async fn find_by_pair(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_a: Uuid,
        identity_b: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let (id_a, id_b) = Self::canonical_order(identity_a, identity_b);

        sqlx::query_as(
            r#"
            SELECT * FROM gov_duplicate_candidates
            WHERE tenant_id = $1 AND identity_a_id = $2 AND identity_b_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(id_a)
        .bind(id_b)
        .fetch_optional(pool)
        .await
    }

    /// Alias for `find_by_pair` for compatibility.
    pub async fn find_by_identities(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_a: Uuid,
        identity_b: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::find_by_pair(pool, tenant_id, identity_a, identity_b).await
    }

    /// List candidates for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DuplicateCandidateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_duplicate_candidates
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.min_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score >= ${}", param_count));
        }
        if filter.max_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score <= ${}", param_count));
        }
        if filter.identity_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (identity_a_id = ${0} OR identity_b_id = ${0})",
                param_count
            ));
        }

        query.push_str(&format!(
            " ORDER BY confidence_score DESC, detected_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovDuplicateCandidate>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_confidence) = filter.min_confidence {
            q = q.bind(min_confidence);
        }
        if let Some(max_confidence) = filter.max_confidence {
            q = q.bind(max_confidence);
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count candidates in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DuplicateCandidateFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_duplicate_candidates
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.min_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score >= ${}", param_count));
        }
        if filter.max_confidence.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND confidence_score <= ${}", param_count));
        }
        if filter.identity_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (identity_a_id = ${0} OR identity_b_id = ${0})",
                param_count
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(min_confidence) = filter.min_confidence {
            q = q.bind(min_confidence);
        }
        if let Some(max_confidence) = filter.max_confidence {
            q = q.bind(max_confidence);
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new duplicate candidate (or update if exists).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovDuplicateCandidate,
    ) -> Result<Self, sqlx::Error> {
        let (id_a, id_b) = Self::canonical_order(input.identity_a_id, input.identity_b_id);
        let rule_matches_json =
            serde_json::to_value(&input.rule_matches).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r#"
            INSERT INTO gov_duplicate_candidates (
                tenant_id, identity_a_id, identity_b_id, confidence_score, rule_matches
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, identity_a_id, identity_b_id) DO UPDATE
            SET confidence_score = EXCLUDED.confidence_score,
                rule_matches = EXCLUDED.rule_matches,
                detected_at = NOW()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id_a)
        .bind(id_b)
        .bind(input.confidence_score)
        .bind(rule_matches_json)
        .fetch_one(pool)
        .await
    }

    /// Mark candidate as merged.
    pub async fn mark_merged(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_duplicate_candidates
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

    /// Mark candidate as merged (within a transaction).
    pub async fn mark_merged_with_tx<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            UPDATE gov_duplicate_candidates
            SET status = 'merged'
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Dismiss a candidate as false positive.
    pub async fn dismiss(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: DismissGovDuplicateCandidate,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_duplicate_candidates
            SET status = 'dismissed',
                dismissed_reason = $3,
                dismissed_by = $4,
                dismissed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.reason)
        .bind(input.dismissed_by)
        .fetch_optional(pool)
        .await
    }

    /// Get all pending candidates involving a specific identity.
    pub async fn find_pending_by_identity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_duplicate_candidates
            WHERE tenant_id = $1
              AND status = 'pending'
              AND (identity_a_id = $2 OR identity_b_id = $2)
            ORDER BY confidence_score DESC
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
    }

    /// Check if candidate is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self.status, GovDuplicateStatus::Pending)
    }

    /// Get the rule matches as structured data.
    pub fn get_rule_matches(&self) -> Result<RuleMatches, serde_json::Error> {
        serde_json::from_value(self.rule_matches.clone())
    }

    /// Get the other identity ID given one of the pair.
    pub fn get_other_identity(&self, identity_id: Uuid) -> Option<Uuid> {
        if self.identity_a_id == identity_id {
            Some(self.identity_b_id)
        } else if self.identity_b_id == identity_id {
            Some(self.identity_a_id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_order() {
        let id1 = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let id2 = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let (a, b) = GovDuplicateCandidate::canonical_order(id1, id2);
        assert_eq!(a, id1);
        assert_eq!(b, id2);

        let (a, b) = GovDuplicateCandidate::canonical_order(id2, id1);
        assert_eq!(a, id1);
        assert_eq!(b, id2);
    }

    #[test]
    fn test_status_serialization() {
        let pending = GovDuplicateStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");
    }

    #[test]
    fn test_rule_matches_serialization() {
        let matches = RuleMatches {
            matches: vec![RuleMatch {
                rule_id: Uuid::new_v4(),
                rule_name: "Email Match".to_string(),
                attribute: "email".to_string(),
                value_a: Some("test@example.com".to_string()),
                value_b: Some("test@example.com".to_string()),
                similarity: 1.0,
                weighted_score: 50.0,
            }],
            total_confidence: 50.0,
        };

        let json = serde_json::to_string(&matches).unwrap();
        assert!(json.contains("Email Match"));
        assert!(json.contains("50.0"));
    }
}
