//! Governance Correlation Case model.
//!
//! Represents correlation cases created when an unmatched account is detected
//! during reconciliation or live sync and requires identity correlation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for correlation cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_correlation_case_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovCorrelationCaseStatus {
    /// Awaiting review or automatic resolution.
    Pending,
    /// Confirmed match to an existing identity.
    Confirmed,
    /// Rejected as incorrect match.
    Rejected,
    /// No matching identity found.
    NoMatch,
    /// Account represents a new identity to be created.
    NewIdentity,
    /// Multiple high-confidence matches (collision).
    Collision,
}

/// Trigger type for how the correlation case was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_correlation_trigger", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovCorrelationTrigger {
    /// Created during a reconciliation run.
    Reconciliation,
    /// Created during live synchronization.
    LiveSync,
    /// Created manually by an administrator.
    Manual,
}

/// A governance correlation case for an unmatched account.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCorrelationCase {
    /// Unique identifier for the case.
    pub id: Uuid,

    /// The tenant this case belongs to.
    pub tenant_id: Uuid,

    /// The connector where the account was found.
    pub connector_id: Uuid,

    /// The account that needs correlation.
    pub account_id: Uuid,

    /// Human-readable account identifier (e.g. username, email).
    pub account_identifier: String,

    /// JSONB snapshot of the account attributes at detection time.
    pub account_attributes: serde_json::Value,

    /// Current case status.
    pub status: GovCorrelationCaseStatus,

    /// How this case was triggered.
    pub trigger_type: GovCorrelationTrigger,

    /// Highest confidence score among candidates (0.00-100.00).
    pub highest_confidence: rust_decimal::Decimal,

    /// Number of correlation candidates found.
    pub candidate_count: i32,

    /// Who resolved the case (if resolved).
    pub resolved_by: Option<Uuid>,

    /// When the case was resolved.
    pub resolved_at: Option<DateTime<Utc>>,

    /// Reason for the resolution decision.
    pub resolution_reason: Option<String>,

    /// The candidate that was selected during resolution.
    pub resolution_candidate_id: Option<Uuid>,

    /// Who the case is currently assigned to for review.
    pub assigned_to: Option<Uuid>,

    /// JSONB snapshot of the correlation rules at detection time.
    pub rules_snapshot: serde_json::Value,

    /// When the case was created.
    pub created_at: DateTime<Utc>,

    /// When the case was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new correlation case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovCorrelationCase {
    pub connector_id: Uuid,
    pub account_id: Uuid,
    pub account_identifier: String,
    pub account_attributes: serde_json::Value,
    pub trigger_type: GovCorrelationTrigger,
    pub highest_confidence: rust_decimal::Decimal,
    pub candidate_count: i32,
    pub rules_snapshot: serde_json::Value,
}

/// Filter options for listing correlation cases.
#[derive(Debug, Clone, Default)]
pub struct CorrelationCaseFilter {
    pub status: Option<GovCorrelationCaseStatus>,
    pub connector_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    pub trigger_type: Option<GovCorrelationTrigger>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

impl GovCorrelationCase {
    /// Find a correlation case by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_correlation_cases
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List correlation cases for a tenant with filtering, sorting, and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationCaseFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_correlation_cases
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${}", param_count));
        }
        if filter.assigned_to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assigned_to = ${}", param_count));
        }
        if filter.trigger_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_type = ${}", param_count));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        // Determine sort column (whitelist to prevent SQL injection)
        let sort_col = match filter.sort_by.as_deref() {
            Some("highest_confidence") => "highest_confidence",
            _ => "created_at",
        };
        let sort_dir = match filter.sort_order.as_deref() {
            Some("desc") | Some("DESC") => "DESC",
            _ => "ASC",
        };

        query.push_str(&format!(
            " ORDER BY {} {} LIMIT ${} OFFSET ${}",
            sort_col,
            sort_dir,
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovCorrelationCase>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(assigned_to) = filter.assigned_to {
            q = q.bind(assigned_to);
        }
        if let Some(trigger_type) = filter.trigger_type {
            q = q.bind(trigger_type);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count correlation cases in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationCaseFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_correlation_cases
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${}", param_count));
        }
        if filter.assigned_to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assigned_to = ${}", param_count));
        }
        if filter.trigger_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_type = ${}", param_count));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(assigned_to) = filter.assigned_to {
            q = q.bind(assigned_to);
        }
        if let Some(trigger_type) = filter.trigger_type {
            q = q.bind(trigger_type);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        q.fetch_one(pool).await
    }

    /// Create a new correlation case.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovCorrelationCase,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_correlation_cases (
                tenant_id, connector_id, account_id, account_identifier,
                account_attributes, trigger_type, highest_confidence,
                candidate_count, rules_snapshot
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.connector_id)
        .bind(input.account_id)
        .bind(&input.account_identifier)
        .bind(&input.account_attributes)
        .bind(input.trigger_type)
        .bind(input.highest_confidence)
        .bind(input.candidate_count)
        .bind(&input.rules_snapshot)
        .fetch_one(pool)
        .await
    }

    /// Resolve a pending correlation case.
    pub async fn resolve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: GovCorrelationCaseStatus,
        resolved_by: Uuid,
        reason: Option<&str>,
        candidate_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_correlation_cases
            SET status = $3,
                resolved_by = $4,
                resolved_at = NOW(),
                resolution_reason = $5,
                resolution_candidate_id = $6,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .bind(resolved_by)
        .bind(reason)
        .bind(candidate_id)
        .fetch_optional(pool)
        .await
    }

    /// Reassign a correlation case to a different reviewer.
    pub async fn reassign(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        assigned_to: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_correlation_cases
            SET assigned_to = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(assigned_to)
        .fetch_optional(pool)
        .await
    }

    /// Find a pending correlation case for a specific account.
    pub async fn find_pending_by_account(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_correlation_cases
            WHERE tenant_id = $1 AND account_id = $2 AND status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(account_id)
        .fetch_optional(pool)
        .await
    }

    /// Count pending correlation cases for a specific connector (queue depth).
    pub async fn count_pending_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_correlation_cases
            WHERE tenant_id = $1 AND connector_id = $2 AND status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_status_serialization() {
        let pending = GovCorrelationCaseStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let confirmed = GovCorrelationCaseStatus::Confirmed;
        let json = serde_json::to_string(&confirmed).unwrap();
        assert_eq!(json, "\"confirmed\"");

        let rejected = GovCorrelationCaseStatus::Rejected;
        let json = serde_json::to_string(&rejected).unwrap();
        assert_eq!(json, "\"rejected\"");

        let no_match = GovCorrelationCaseStatus::NoMatch;
        let json = serde_json::to_string(&no_match).unwrap();
        assert_eq!(json, "\"no_match\"");

        let new_identity = GovCorrelationCaseStatus::NewIdentity;
        let json = serde_json::to_string(&new_identity).unwrap();
        assert_eq!(json, "\"new_identity\"");

        let collision = GovCorrelationCaseStatus::Collision;
        let json = serde_json::to_string(&collision).unwrap();
        assert_eq!(json, "\"collision\"");

        // Roundtrip deserialization
        let deserialized: GovCorrelationCaseStatus = serde_json::from_str("\"no_match\"").unwrap();
        assert_eq!(deserialized, GovCorrelationCaseStatus::NoMatch);

        let deserialized: GovCorrelationCaseStatus =
            serde_json::from_str("\"new_identity\"").unwrap();
        assert_eq!(deserialized, GovCorrelationCaseStatus::NewIdentity);
    }

    #[test]
    fn test_trigger_type_serialization() {
        let reconciliation = GovCorrelationTrigger::Reconciliation;
        let json = serde_json::to_string(&reconciliation).unwrap();
        assert_eq!(json, "\"reconciliation\"");

        let live_sync = GovCorrelationTrigger::LiveSync;
        let json = serde_json::to_string(&live_sync).unwrap();
        assert_eq!(json, "\"live_sync\"");

        let manual = GovCorrelationTrigger::Manual;
        let json = serde_json::to_string(&manual).unwrap();
        assert_eq!(json, "\"manual\"");

        // Roundtrip deserialization
        let deserialized: GovCorrelationTrigger = serde_json::from_str("\"live_sync\"").unwrap();
        assert_eq!(deserialized, GovCorrelationTrigger::LiveSync);
    }

    #[test]
    fn test_default_filter() {
        let filter = CorrelationCaseFilter::default();
        assert!(filter.status.is_none());
        assert!(filter.connector_id.is_none());
        assert!(filter.assigned_to.is_none());
        assert!(filter.trigger_type.is_none());
        assert!(filter.start_date.is_none());
        assert!(filter.end_date.is_none());
        assert!(filter.sort_by.is_none());
        assert!(filter.sort_order.is_none());
    }
}
