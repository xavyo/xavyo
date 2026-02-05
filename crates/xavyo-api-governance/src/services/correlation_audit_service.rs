//! Correlation Audit Service for the Correlation Engine (F067).
//!
//! Records and retrieves immutable audit events for all correlation engine
//! operations, including automatic evaluations, case creation, manual decisions,
//! reassignments, and rule changes.

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CorrelationAuditFilter, CreateGovCorrelationAuditEvent, GovCorrelationAuditEvent,
    GovCorrelationEventType, GovCorrelationOutcome,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::correlation::{
    CorrelationAuditEventResponse, CorrelationAuditListResponse, ListCorrelationAuditQuery,
};

/// Service for recording and querying correlation audit events.
pub struct CorrelationAuditService {
    pool: PgPool,
}

impl CorrelationAuditService {
    /// Create a new correlation audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Recording methods
    // =========================================================================

    /// Record an automatic evaluation event.
    ///
    /// Called when the correlation engine automatically evaluates an account
    /// against identity candidates and produces a definitive outcome (e.g.,
    /// auto-confirmed, no-match, collision-detected).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_auto_evaluation(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        identity_id: Option<Uuid>,
        outcome: GovCorrelationOutcome,
        confidence_score: Option<f64>,
        candidate_count: i32,
        candidates_summary: serde_json::Value,
        rules_snapshot: serde_json::Value,
        thresholds_snapshot: serde_json::Value,
    ) -> Result<()> {
        let decimal_score = confidence_score
            .map(|s| {
                Decimal::try_from(s).map_err(|_| GovernanceError::InvalidCorrelationThreshold(s))
            })
            .transpose()?;

        let input = CreateGovCorrelationAuditEvent {
            tenant_id,
            connector_id,
            account_id: Some(account_id),
            case_id: None,
            identity_id,
            event_type: GovCorrelationEventType::AutoEvaluated,
            outcome,
            confidence_score: decimal_score,
            candidate_count,
            candidates_summary,
            rules_snapshot,
            thresholds_snapshot,
            actor_type: "system".to_string(),
            actor_id: None,
            reason: None,
            metadata: None,
        };

        GovCorrelationAuditEvent::create(&self.pool, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            account_id = %account_id,
            outcome = ?outcome,
            "Correlation auto-evaluation audit event recorded"
        );

        Ok(())
    }

    /// Record a case creation event.
    ///
    /// Called when the correlation engine creates a manual review case because
    /// the confidence score falls within the review threshold range.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_case_creation(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        case_id: Uuid,
        confidence_score: Option<f64>,
        candidate_count: i32,
        candidates_summary: serde_json::Value,
        rules_snapshot: serde_json::Value,
        thresholds_snapshot: serde_json::Value,
    ) -> Result<()> {
        let decimal_score = confidence_score
            .map(|s| {
                Decimal::try_from(s).map_err(|_| GovernanceError::InvalidCorrelationThreshold(s))
            })
            .transpose()?;

        let input = CreateGovCorrelationAuditEvent {
            tenant_id,
            connector_id,
            account_id: Some(account_id),
            case_id: Some(case_id),
            identity_id: None,
            event_type: GovCorrelationEventType::CaseCreated,
            outcome: GovCorrelationOutcome::DeferredToReview,
            confidence_score: decimal_score,
            candidate_count,
            candidates_summary,
            rules_snapshot,
            thresholds_snapshot,
            actor_type: "system".to_string(),
            actor_id: None,
            reason: None,
            metadata: None,
        };

        GovCorrelationAuditEvent::create(&self.pool, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            account_id = %account_id,
            case_id = %case_id,
            "Correlation case creation audit event recorded"
        );

        Ok(())
    }

    /// Record a manual review decision event.
    ///
    /// Called when a reviewer confirms, rejects, or creates a new identity
    /// for a correlation case.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_manual_decision(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        case_id: Uuid,
        identity_id: Option<Uuid>,
        outcome: GovCorrelationOutcome,
        actor_id: Uuid,
        reason: Option<String>,
        confidence_score: Option<f64>,
        candidate_count: i32,
    ) -> Result<()> {
        let decimal_score = confidence_score
            .map(|s| {
                Decimal::try_from(s).map_err(|_| GovernanceError::InvalidCorrelationThreshold(s))
            })
            .transpose()?;

        let input = CreateGovCorrelationAuditEvent {
            tenant_id,
            connector_id,
            account_id: Some(account_id),
            case_id: Some(case_id),
            identity_id,
            event_type: GovCorrelationEventType::ManualReviewed,
            outcome,
            confidence_score: decimal_score,
            candidate_count,
            candidates_summary: serde_json::json!([]),
            rules_snapshot: serde_json::json!({}),
            thresholds_snapshot: serde_json::json!({}),
            actor_type: "user".to_string(),
            actor_id: Some(actor_id),
            reason,
            metadata: None,
        };

        GovCorrelationAuditEvent::create(&self.pool, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            case_id = %case_id,
            actor_id = %actor_id,
            outcome = ?outcome,
            "Correlation manual decision audit event recorded"
        );

        Ok(())
    }

    /// Record a case reassignment event.
    ///
    /// Called when a correlation case is reassigned to a different reviewer.
    pub async fn record_reassignment(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        case_id: Uuid,
        actor_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        let input = CreateGovCorrelationAuditEvent {
            tenant_id,
            connector_id,
            account_id: None,
            case_id: Some(case_id),
            identity_id: None,
            event_type: GovCorrelationEventType::CaseReassigned,
            outcome: GovCorrelationOutcome::DeferredToReview,
            confidence_score: None,
            candidate_count: 0,
            candidates_summary: serde_json::json!([]),
            rules_snapshot: serde_json::json!({}),
            thresholds_snapshot: serde_json::json!({}),
            actor_type: "user".to_string(),
            actor_id: Some(actor_id),
            reason,
            metadata: None,
        };

        GovCorrelationAuditEvent::create(&self.pool, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            case_id = %case_id,
            actor_id = %actor_id,
            "Correlation case reassignment audit event recorded"
        );

        Ok(())
    }

    /// Record a rules change event.
    ///
    /// Called when correlation rules or thresholds are modified for a connector.
    pub async fn record_rules_change(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        actor_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        let input = CreateGovCorrelationAuditEvent {
            tenant_id,
            connector_id,
            account_id: None,
            case_id: None,
            identity_id: None,
            event_type: GovCorrelationEventType::RulesChanged,
            outcome: GovCorrelationOutcome::DeferredToReview,
            confidence_score: None,
            candidate_count: 0,
            candidates_summary: serde_json::json!([]),
            rules_snapshot: serde_json::json!({}),
            thresholds_snapshot: serde_json::json!({}),
            actor_type: "user".to_string(),
            actor_id: Some(actor_id),
            reason,
            metadata: None,
        };

        GovCorrelationAuditEvent::create(&self.pool, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            actor_id = %actor_id,
            "Correlation rules change audit event recorded"
        );

        Ok(())
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /// List audit events for a tenant with filtering and pagination.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        filter: &CorrelationAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<CorrelationAuditListResponse> {
        let events =
            GovCorrelationAuditEvent::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;

        let total =
            GovCorrelationAuditEvent::count_by_tenant(&self.pool, tenant_id, filter).await?;

        Ok(CorrelationAuditListResponse {
            items: events.into_iter().map(audit_event_to_response).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a single audit event by ID.
    pub async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<CorrelationAuditEventResponse> {
        let event = GovCorrelationAuditEvent::find_by_id(&self.pool, tenant_id, event_id)
            .await?
            .ok_or(GovernanceError::CorrelationAuditEventNotFound(event_id))?;

        Ok(audit_event_to_response(event))
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Convert a `GovCorrelationAuditEvent` database model into a
/// `CorrelationAuditEventResponse` DTO.
fn audit_event_to_response(e: GovCorrelationAuditEvent) -> CorrelationAuditEventResponse {
    CorrelationAuditEventResponse {
        id: e.id,
        connector_id: e.connector_id,
        account_id: e.account_id,
        case_id: e.case_id,
        identity_id: e.identity_id,
        event_type: format!("{:?}", e.event_type).to_lowercase(),
        outcome: format!("{:?}", e.outcome).to_lowercase(),
        confidence_score: e
            .confidence_score
            .map(|d| d.to_string().parse::<f64>().unwrap_or(0.0)),
        candidate_count: e.candidate_count,
        candidates_summary: e.candidates_summary,
        rules_snapshot: e.rules_snapshot,
        thresholds_snapshot: e.thresholds_snapshot,
        actor_type: e.actor_type,
        actor_id: e.actor_id,
        reason: e.reason,
        created_at: e.created_at,
    }
}

/// Parse an event type string into a `GovCorrelationEventType` enum value.
pub fn parse_event_type(s: &str) -> Result<GovCorrelationEventType> {
    match s.to_lowercase().as_str() {
        "auto_evaluated" | "autoevaluated" => Ok(GovCorrelationEventType::AutoEvaluated),
        "manual_reviewed" | "manualreviewed" => Ok(GovCorrelationEventType::ManualReviewed),
        "case_created" | "casecreated" => Ok(GovCorrelationEventType::CaseCreated),
        "case_reassigned" | "casereassigned" => Ok(GovCorrelationEventType::CaseReassigned),
        "rules_changed" | "ruleschanged" => Ok(GovCorrelationEventType::RulesChanged),
        other => Err(GovernanceError::Validation(format!(
            "Invalid event type '{other}'. Must be one of: auto_evaluated, manual_reviewed, case_created, case_reassigned, rules_changed"
        ))),
    }
}

/// Parse an outcome string into a `GovCorrelationOutcome` enum value.
pub fn parse_outcome(s: &str) -> Result<GovCorrelationOutcome> {
    match s.to_lowercase().as_str() {
        "auto_confirmed" | "autoconfirmed" => Ok(GovCorrelationOutcome::AutoConfirmed),
        "manual_confirmed" | "manualconfirmed" => Ok(GovCorrelationOutcome::ManualConfirmed),
        "manual_rejected" | "manualrejected" => Ok(GovCorrelationOutcome::ManualRejected),
        "new_identity_created" | "newidentitycreated" => {
            Ok(GovCorrelationOutcome::NewIdentityCreated)
        }
        "no_match" | "nomatch" => Ok(GovCorrelationOutcome::NoMatch),
        "collision_detected" | "collisiondetected" => {
            Ok(GovCorrelationOutcome::CollisionDetected)
        }
        "deferred_to_review" | "deferredtoreview" => {
            Ok(GovCorrelationOutcome::DeferredToReview)
        }
        other => Err(GovernanceError::Validation(format!(
            "Invalid outcome '{other}'. Must be one of: auto_confirmed, manual_confirmed, manual_rejected, new_identity_created, no_match, collision_detected, deferred_to_review"
        ))),
    }
}

/// Build a `CorrelationAuditFilter` from query parameters.
pub fn build_audit_filter(query: &ListCorrelationAuditQuery) -> Result<CorrelationAuditFilter> {
    let event_type = match &query.event_type {
        Some(et) => Some(parse_event_type(et)?),
        None => None,
    };

    let outcome = match &query.outcome {
        Some(o) => Some(parse_outcome(o)?),
        None => None,
    };

    Ok(CorrelationAuditFilter {
        connector_id: query.connector_id,
        event_type,
        outcome,
        start_date: query.start_date,
        end_date: query.end_date,
        actor_id: query.actor_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests would require a database connection.
    }

    #[test]
    fn test_audit_event_to_response_mapping() {
        let event = GovCorrelationAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            account_id: Some(Uuid::new_v4()),
            case_id: Some(Uuid::new_v4()),
            identity_id: Some(Uuid::new_v4()),
            event_type: GovCorrelationEventType::AutoEvaluated,
            outcome: GovCorrelationOutcome::AutoConfirmed,
            confidence_score: Some(Decimal::new(95, 2)), // 0.95
            candidate_count: 3,
            candidates_summary: serde_json::json!([
                {"identity_id": "abc", "score": 0.95},
                {"identity_id": "def", "score": 0.72},
                {"identity_id": "ghi", "score": 0.45}
            ]),
            rules_snapshot: serde_json::json!({"rules": []}),
            thresholds_snapshot: serde_json::json!({"auto_confirm": 0.90}),
            actor_type: "system".to_string(),
            actor_id: None,
            reason: None,
            metadata: None,
            created_at: chrono::Utc::now(),
        };

        let account_id = event.account_id;
        let case_id = event.case_id;
        let identity_id = event.identity_id;
        let event_id = event.id;

        let response = audit_event_to_response(event);

        assert_eq!(response.id, event_id);
        assert_eq!(response.account_id, account_id);
        assert_eq!(response.case_id, case_id);
        assert_eq!(response.identity_id, identity_id);
        assert_eq!(response.event_type, "autoevaluated");
        assert_eq!(response.outcome, "autoconfirmed");
        assert!((response.confidence_score.unwrap() - 0.95).abs() < f64::EPSILON);
        assert_eq!(response.candidate_count, 3);
        assert_eq!(response.actor_type, "system");
        assert!(response.actor_id.is_none());
        assert!(response.reason.is_none());
    }

    #[test]
    fn test_audit_event_to_response_manual_review() {
        let actor_id = Uuid::new_v4();
        let event = GovCorrelationAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            account_id: Some(Uuid::new_v4()),
            case_id: Some(Uuid::new_v4()),
            identity_id: Some(Uuid::new_v4()),
            event_type: GovCorrelationEventType::ManualReviewed,
            outcome: GovCorrelationOutcome::ManualConfirmed,
            confidence_score: Some(Decimal::new(78, 2)), // 0.78
            candidate_count: 2,
            candidates_summary: serde_json::json!([]),
            rules_snapshot: serde_json::json!({}),
            thresholds_snapshot: serde_json::json!({}),
            actor_type: "user".to_string(),
            actor_id: Some(actor_id),
            reason: Some("Verified via HR records".to_string()),
            metadata: None,
            created_at: chrono::Utc::now(),
        };

        let response = audit_event_to_response(event);

        assert_eq!(response.event_type, "manualreviewed");
        assert_eq!(response.outcome, "manualconfirmed");
        assert_eq!(response.actor_type, "user");
        assert_eq!(response.actor_id, Some(actor_id));
        assert_eq!(response.reason, Some("Verified via HR records".to_string()));
    }

    #[test]
    fn test_audit_event_to_response_no_confidence() {
        let event = GovCorrelationAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            account_id: None,
            case_id: Some(Uuid::new_v4()),
            identity_id: None,
            event_type: GovCorrelationEventType::CaseReassigned,
            outcome: GovCorrelationOutcome::DeferredToReview,
            confidence_score: None,
            candidate_count: 0,
            candidates_summary: serde_json::json!([]),
            rules_snapshot: serde_json::json!({}),
            thresholds_snapshot: serde_json::json!({}),
            actor_type: "user".to_string(),
            actor_id: Some(Uuid::new_v4()),
            reason: Some("Reassigning to senior reviewer".to_string()),
            metadata: None,
            created_at: chrono::Utc::now(),
        };

        let response = audit_event_to_response(event);

        assert_eq!(response.event_type, "casereassigned");
        assert_eq!(response.outcome, "deferredtoreview");
        assert!(response.confidence_score.is_none());
        assert!(response.account_id.is_none());
        assert!(response.identity_id.is_none());
    }

    #[test]
    fn test_parse_event_type_valid() {
        assert_eq!(
            parse_event_type("auto_evaluated").unwrap(),
            GovCorrelationEventType::AutoEvaluated
        );
        assert_eq!(
            parse_event_type("manual_reviewed").unwrap(),
            GovCorrelationEventType::ManualReviewed
        );
        assert_eq!(
            parse_event_type("case_created").unwrap(),
            GovCorrelationEventType::CaseCreated
        );
        assert_eq!(
            parse_event_type("case_reassigned").unwrap(),
            GovCorrelationEventType::CaseReassigned
        );
        assert_eq!(
            parse_event_type("rules_changed").unwrap(),
            GovCorrelationEventType::RulesChanged
        );
        // Case insensitive.
        assert_eq!(
            parse_event_type("AUTO_EVALUATED").unwrap(),
            GovCorrelationEventType::AutoEvaluated
        );
    }

    #[test]
    fn test_parse_event_type_invalid() {
        assert!(parse_event_type("invalid").is_err());
        assert!(parse_event_type("").is_err());
    }

    #[test]
    fn test_parse_outcome_valid() {
        assert_eq!(
            parse_outcome("auto_confirmed").unwrap(),
            GovCorrelationOutcome::AutoConfirmed
        );
        assert_eq!(
            parse_outcome("manual_confirmed").unwrap(),
            GovCorrelationOutcome::ManualConfirmed
        );
        assert_eq!(
            parse_outcome("manual_rejected").unwrap(),
            GovCorrelationOutcome::ManualRejected
        );
        assert_eq!(
            parse_outcome("new_identity_created").unwrap(),
            GovCorrelationOutcome::NewIdentityCreated
        );
        assert_eq!(
            parse_outcome("no_match").unwrap(),
            GovCorrelationOutcome::NoMatch
        );
        assert_eq!(
            parse_outcome("collision_detected").unwrap(),
            GovCorrelationOutcome::CollisionDetected
        );
        assert_eq!(
            parse_outcome("deferred_to_review").unwrap(),
            GovCorrelationOutcome::DeferredToReview
        );
    }

    #[test]
    fn test_parse_outcome_invalid() {
        assert!(parse_outcome("invalid").is_err());
        assert!(parse_outcome("").is_err());
    }

    #[test]
    fn test_build_audit_filter_empty() {
        let query = ListCorrelationAuditQuery {
            connector_id: None,
            event_type: None,
            outcome: None,
            start_date: None,
            end_date: None,
            actor_id: None,
            limit: None,
            offset: None,
        };

        let filter = build_audit_filter(&query).unwrap();
        assert!(filter.connector_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.outcome.is_none());
        assert!(filter.start_date.is_none());
        assert!(filter.end_date.is_none());
        assert!(filter.actor_id.is_none());
    }

    #[test]
    fn test_build_audit_filter_with_values() {
        let connector_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let query = ListCorrelationAuditQuery {
            connector_id: Some(connector_id),
            event_type: Some("auto_evaluated".to_string()),
            outcome: Some("auto_confirmed".to_string()),
            start_date: None,
            end_date: None,
            actor_id: Some(actor_id),
            limit: Some(25),
            offset: Some(10),
        };

        let filter = build_audit_filter(&query).unwrap();
        assert_eq!(filter.connector_id, Some(connector_id));
        assert_eq!(
            filter.event_type,
            Some(GovCorrelationEventType::AutoEvaluated)
        );
        assert_eq!(filter.outcome, Some(GovCorrelationOutcome::AutoConfirmed));
        assert_eq!(filter.actor_id, Some(actor_id));
    }

    #[test]
    fn test_build_audit_filter_invalid_event_type() {
        let query = ListCorrelationAuditQuery {
            connector_id: None,
            event_type: Some("bogus".to_string()),
            outcome: None,
            start_date: None,
            end_date: None,
            actor_id: None,
            limit: None,
            offset: None,
        };

        assert!(build_audit_filter(&query).is_err());
    }

    #[test]
    fn test_build_audit_filter_invalid_outcome() {
        let query = ListCorrelationAuditQuery {
            connector_id: None,
            event_type: None,
            outcome: Some("bogus".to_string()),
            start_date: None,
            end_date: None,
            actor_id: None,
            limit: None,
            offset: None,
        };

        assert!(build_audit_filter(&query).is_err());
    }
}
