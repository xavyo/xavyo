//! Correlation Audit Event model (F067).
//!
//! Immutable audit trail for correlation engine operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Event type for correlation audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_correlation_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovCorrelationEventType {
    /// Automatic evaluation of a correlation candidate.
    AutoEvaluated,
    /// Manual review of a correlation candidate.
    ManualReviewed,
    /// A correlation case was created.
    CaseCreated,
    /// A correlation case was reassigned.
    CaseReassigned,
    /// Correlation rules were changed.
    RulesChanged,
}

/// Outcome of a correlation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_correlation_outcome", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovCorrelationOutcome {
    /// Automatically confirmed as a match.
    AutoConfirmed,
    /// Manually confirmed as a match.
    ManualConfirmed,
    /// Manually rejected as not a match.
    ManualRejected,
    /// A new identity was created from the account.
    NewIdentityCreated,
    /// No matching identity found.
    NoMatch,
    /// A collision was detected (multiple high-confidence matches).
    CollisionDetected,
    /// Deferred to manual review.
    DeferredToReview,
}

/// An immutable audit event recording a correlation engine operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCorrelationAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The connector involved.
    pub connector_id: Uuid,

    /// The account involved (if applicable).
    pub account_id: Option<Uuid>,

    /// The correlation case involved (if applicable).
    pub case_id: Option<Uuid>,

    /// The identity involved (if applicable).
    pub identity_id: Option<Uuid>,

    /// Type of correlation event.
    pub event_type: GovCorrelationEventType,

    /// Outcome of the correlation evaluation.
    pub outcome: GovCorrelationOutcome,

    /// Confidence score of the best match (0.00-1.00).
    pub confidence_score: Option<rust_decimal::Decimal>,

    /// Number of candidates evaluated.
    pub candidate_count: i32,

    /// Summary of candidates evaluated.
    pub candidates_summary: serde_json::Value,

    /// Snapshot of the rules at the time of evaluation.
    pub rules_snapshot: serde_json::Value,

    /// Snapshot of the thresholds at the time of evaluation.
    pub thresholds_snapshot: serde_json::Value,

    /// Type of actor (e.g., "system", "user").
    pub actor_type: String,

    /// The actor who performed the action (if applicable).
    pub actor_id: Option<Uuid>,

    /// Reason for the outcome (e.g., manual review notes).
    pub reason: Option<String>,

    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new correlation audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovCorrelationAuditEvent {
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub account_id: Option<Uuid>,
    pub case_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    pub event_type: GovCorrelationEventType,
    pub outcome: GovCorrelationOutcome,
    pub confidence_score: Option<rust_decimal::Decimal>,
    pub candidate_count: i32,
    pub candidates_summary: serde_json::Value,
    pub rules_snapshot: serde_json::Value,
    pub thresholds_snapshot: serde_json::Value,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter options for listing correlation audit events.
#[derive(Debug, Clone, Default)]
pub struct CorrelationAuditFilter {
    pub connector_id: Option<Uuid>,
    pub event_type: Option<GovCorrelationEventType>,
    pub outcome: Option<GovCorrelationOutcome>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub actor_id: Option<Uuid>,
}

impl GovCorrelationAuditEvent {
    /// Create a new correlation audit event.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateGovCorrelationAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_correlation_audit_events (
                tenant_id, connector_id, account_id, case_id, identity_id,
                event_type, outcome, confidence_score, candidate_count,
                candidates_summary, rules_snapshot, thresholds_snapshot,
                actor_type, actor_id, reason, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(input.connector_id)
        .bind(input.account_id)
        .bind(input.case_id)
        .bind(input.identity_id)
        .bind(input.event_type)
        .bind(input.outcome)
        .bind(input.confidence_score)
        .bind(input.candidate_count)
        .bind(&input.candidates_summary)
        .bind(&input.rules_snapshot)
        .bind(&input.thresholds_snapshot)
        .bind(&input.actor_type)
        .bind(input.actor_id)
        .bind(&input.reason)
        .bind(&input.metadata)
        .fetch_one(pool)
        .await
    }

    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_correlation_audit_events
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List events for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_correlation_audit_events
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${param_count}"));
        }
        if filter.outcome.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND outcome = ${param_count}"));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(outcome) = filter.outcome {
            q = q.bind(outcome);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count events for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_correlation_audit_events
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${param_count}"));
        }
        if filter.outcome.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND outcome = ${param_count}"));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(outcome) = filter.outcome {
            q = q.bind(outcome);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }

        q.fetch_one(pool).await
    }

    /// Count events by outcome for statistics.
    pub async fn count_by_outcome(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        outcome: GovCorrelationOutcome,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_correlation_audit_events
            WHERE tenant_id = $1 AND connector_id = $2 AND outcome = $3
            ",
        );
        let mut param_count = 3;

        if start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        let _ = param_count; // suppress unused warning

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(connector_id)
            .bind(outcome);

        if let Some(start) = start_date {
            q = q.bind(start);
        }
        if let Some(end) = end_date {
            q = q.bind(end);
        }

        q.fetch_one(pool).await
    }

    /// Average confidence score for a connector (for statistics).
    pub async fn average_confidence(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<Option<rust_decimal::Decimal>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT AVG(confidence_score) FROM gov_correlation_audit_events
            WHERE tenant_id = $1 AND connector_id = $2 AND confidence_score IS NOT NULL
            ",
        );
        let mut param_count = 2;

        if start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        let _ = param_count; // suppress unused warning

        let mut q = sqlx::query_scalar::<_, Option<rust_decimal::Decimal>>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(start) = start_date {
            q = q.bind(start);
        }
        if let Some(end) = end_date {
            q = q.bind(end);
        }

        q.fetch_one(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_serialization() {
        let event_type = GovCorrelationEventType::AutoEvaluated;
        let json = serde_json::to_string(&event_type).unwrap();
        assert_eq!(json, "\"auto_evaluated\"");

        let deserialized: GovCorrelationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, GovCorrelationEventType::AutoEvaluated);

        // Test all variants
        let variants = vec![
            (GovCorrelationEventType::AutoEvaluated, "\"auto_evaluated\""),
            (
                GovCorrelationEventType::ManualReviewed,
                "\"manual_reviewed\"",
            ),
            (GovCorrelationEventType::CaseCreated, "\"case_created\""),
            (
                GovCorrelationEventType::CaseReassigned,
                "\"case_reassigned\"",
            ),
            (GovCorrelationEventType::RulesChanged, "\"rules_changed\""),
        ];

        for (variant, expected) in variants {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn test_outcome_serialization() {
        let outcome = GovCorrelationOutcome::AutoConfirmed;
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(json, "\"auto_confirmed\"");

        let deserialized: GovCorrelationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, GovCorrelationOutcome::AutoConfirmed);

        // Test all variants
        let variants = vec![
            (GovCorrelationOutcome::AutoConfirmed, "\"auto_confirmed\""),
            (
                GovCorrelationOutcome::ManualConfirmed,
                "\"manual_confirmed\"",
            ),
            (GovCorrelationOutcome::ManualRejected, "\"manual_rejected\""),
            (
                GovCorrelationOutcome::NewIdentityCreated,
                "\"new_identity_created\"",
            ),
            (GovCorrelationOutcome::NoMatch, "\"no_match\""),
            (
                GovCorrelationOutcome::CollisionDetected,
                "\"collision_detected\"",
            ),
            (
                GovCorrelationOutcome::DeferredToReview,
                "\"deferred_to_review\"",
            ),
        ];

        for (variant, expected) in variants {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn test_default_filter() {
        let filter = CorrelationAuditFilter::default();
        assert!(filter.connector_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.outcome.is_none());
        assert!(filter.start_date.is_none());
        assert!(filter.end_date.is_none());
        assert!(filter.actor_id.is_none());
    }
}
