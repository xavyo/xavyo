//! Correlation Case Service for the Correlation Engine (F067).
//!
//! Manages CRUD operations for correlation cases that require manual review
//! when an unmatched account is detected during reconciliation or live sync.
//! Provides idempotent case creation, candidate management, filtering, and
//! pagination for the review queue.

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CorrelationCaseFilter, CreateGovCorrelationCandidate, CreateGovCorrelationCase,
    GovCorrelationCandidate, GovCorrelationCase, GovCorrelationCaseStatus, GovCorrelationTrigger,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::correlation::{
    CorrelationCandidateDetailResponse, CorrelationCaseDetailResponse,
    CorrelationCaseSummaryResponse, ListCorrelationCasesQuery,
};

// ============================================================================
// Paginated list response (not defined in the shared models module)
// ============================================================================

/// Paginated list of correlation case summaries.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelationCaseListResponse {
    /// List of correlation case summaries.
    pub items: Vec<CorrelationCaseSummaryResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for the query.
    pub limit: i64,

    /// Offset used for the query.
    pub offset: i64,
}

// ============================================================================
// Service
// ============================================================================

/// Service for managing correlation cases.
pub struct CorrelationCaseService {
    pool: PgPool,
}

impl CorrelationCaseService {
    /// Create a new correlation case service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a new correlation case with its associated candidates.
    ///
    /// Inserts the case row first, then creates each candidate record linked
    /// to the new case. Returns a summary response for the created case.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_case(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        account_identifier: String,
        trigger: GovCorrelationTrigger,
        account_attributes: serde_json::Value,
        highest_confidence: Decimal,
        candidate_count: i32,
        candidates: Vec<CreateGovCorrelationCandidate>,
        rules_snapshot: serde_json::Value,
        assigned_to: Option<Uuid>,
    ) -> Result<CorrelationCaseSummaryResponse> {
        let input = CreateGovCorrelationCase {
            connector_id,
            account_id,
            account_identifier,
            account_attributes,
            trigger_type: trigger,
            highest_confidence,
            candidate_count,
            rules_snapshot,
        };

        let case = GovCorrelationCase::create(&self.pool, tenant_id, input).await?;

        // Optionally assign a reviewer immediately.
        let case = if let Some(reviewer) = assigned_to {
            GovCorrelationCase::reassign(&self.pool, tenant_id, case.id, reviewer)
                .await?
                .unwrap_or(case)
        } else {
            case
        };

        // Create all candidate records for the case.
        for candidate_input in candidates {
            GovCorrelationCandidate::create(&self.pool, candidate_input).await?;
        }

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            case_id = %case.id,
            account_id = %case.account_id,
            candidate_count = case.candidate_count,
            highest_confidence = %case.highest_confidence,
            trigger_type = ?case.trigger_type,
            "Correlation case created"
        );

        Ok(case_to_summary(case))
    }

    /// Get a single correlation case by ID, including all candidates.
    pub async fn get_case(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
    ) -> Result<CorrelationCaseDetailResponse> {
        let case = GovCorrelationCase::find_by_id(&self.pool, tenant_id, case_id)
            .await?
            .ok_or(GovernanceError::CorrelationCaseNotFound(case_id))?;

        let candidates = GovCorrelationCandidate::list_by_case(&self.pool, case.id).await?;

        Ok(case_to_detail(case, candidates))
    }

    /// List correlation cases for a tenant with filtering, sorting, and pagination.
    pub async fn list_cases(
        &self,
        tenant_id: Uuid,
        query: &ListCorrelationCasesQuery,
    ) -> Result<CorrelationCaseListResponse> {
        let filter = build_case_filter(query)?;

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let cases =
            GovCorrelationCase::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        let total = GovCorrelationCase::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(CorrelationCaseListResponse {
            items: cases.into_iter().map(case_to_summary).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Check whether a pending correlation case already exists for a specific account.
    ///
    /// Used as an idempotency check before creating a new case so that the same
    /// account is not queued for review multiple times.
    pub async fn is_account_already_queued(
        &self,
        tenant_id: Uuid,
        account_id: Uuid,
    ) -> Result<bool> {
        let existing =
            GovCorrelationCase::find_pending_by_account(&self.pool, tenant_id, account_id).await?;

        Ok(existing.is_some())
    }

    /// Confirm a correlation case by linking it to a specific identity candidate.
    ///
    /// Validates that the case is still pending, then resolves it with status
    /// `Confirmed`, recording the reviewer, timestamp, reason, and selected candidate.
    pub async fn confirm_case(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        candidate_id: Uuid,
        reviewer_id: Uuid,
        reason: Option<String>,
    ) -> Result<CorrelationCaseDetailResponse> {
        let case = GovCorrelationCase::find_by_id(&self.pool, tenant_id, case_id)
            .await?
            .ok_or(GovernanceError::CorrelationCaseNotFound(case_id))?;

        if case.status != GovCorrelationCaseStatus::Pending {
            return Err(GovernanceError::CorrelationCaseAlreadyResolved(case_id));
        }

        GovCorrelationCase::resolve(
            &self.pool,
            tenant_id,
            case_id,
            GovCorrelationCaseStatus::Confirmed,
            reviewer_id,
            reason.as_deref(),
            Some(candidate_id),
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            case_id = %case_id,
            candidate_id = %candidate_id,
            reviewer_id = %reviewer_id,
            "Correlation case confirmed"
        );

        self.get_case(tenant_id, case_id).await
    }

    /// Reject a correlation case, indicating no candidate should be linked.
    ///
    /// Validates that the case is still pending, then resolves it with status
    /// `Rejected`, recording the reviewer, timestamp, and reason.
    pub async fn reject_case(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        reviewer_id: Uuid,
        reason: Option<String>,
    ) -> Result<CorrelationCaseDetailResponse> {
        let case = GovCorrelationCase::find_by_id(&self.pool, tenant_id, case_id)
            .await?
            .ok_or(GovernanceError::CorrelationCaseNotFound(case_id))?;

        if case.status != GovCorrelationCaseStatus::Pending {
            return Err(GovernanceError::CorrelationCaseAlreadyResolved(case_id));
        }

        GovCorrelationCase::resolve(
            &self.pool,
            tenant_id,
            case_id,
            GovCorrelationCaseStatus::Rejected,
            reviewer_id,
            reason.as_deref(),
            None,
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            case_id = %case_id,
            reviewer_id = %reviewer_id,
            "Correlation case rejected"
        );

        self.get_case(tenant_id, case_id).await
    }

    /// Create a new identity from a correlation case.
    ///
    /// Validates that the case is still pending, then resolves it with status
    /// `NewIdentity`, indicating that a new identity should be created from the
    /// account attributes. No candidate is linked.
    pub async fn create_identity_from_case(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        reviewer_id: Uuid,
        reason: Option<String>,
    ) -> Result<CorrelationCaseDetailResponse> {
        let case = GovCorrelationCase::find_by_id(&self.pool, tenant_id, case_id)
            .await?
            .ok_or(GovernanceError::CorrelationCaseNotFound(case_id))?;

        if case.status != GovCorrelationCaseStatus::Pending {
            return Err(GovernanceError::CorrelationCaseAlreadyResolved(case_id));
        }

        GovCorrelationCase::resolve(
            &self.pool,
            tenant_id,
            case_id,
            GovCorrelationCaseStatus::NewIdentity,
            reviewer_id,
            reason.as_deref(),
            None,
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            case_id = %case_id,
            reviewer_id = %reviewer_id,
            "Correlation case resolved: new identity to be created"
        );

        self.get_case(tenant_id, case_id).await
    }

    /// Reassign a correlation case to a different reviewer.
    ///
    /// Updates the `assigned_to` field of the case and returns the updated
    /// case detail.
    pub async fn reassign_case(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        assigned_to: Uuid,
        reason: Option<String>,
    ) -> Result<CorrelationCaseDetailResponse> {
        GovCorrelationCase::reassign(&self.pool, tenant_id, case_id, assigned_to).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            case_id = %case_id,
            assigned_to = %assigned_to,
            reason = ?reason,
            "Correlation case reassigned"
        );

        self.get_case(tenant_id, case_id).await
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Build a `CorrelationCaseFilter` from query parameters.
fn build_case_filter(query: &ListCorrelationCasesQuery) -> Result<CorrelationCaseFilter> {
    let status = match &query.status {
        Some(s) => Some(parse_case_status(s)?),
        None => None,
    };

    let trigger_type = match &query.trigger_type {
        Some(t) => Some(parse_trigger_type(t)?),
        None => None,
    };

    Ok(CorrelationCaseFilter {
        status,
        connector_id: query.connector_id,
        assigned_to: query.assigned_to,
        trigger_type,
        start_date: query.start_date,
        end_date: query.end_date,
        sort_by: query.sort_by.clone(),
        sort_order: query.sort_order.clone(),
    })
}

/// Parse a case status string into a `GovCorrelationCaseStatus` enum value.
fn parse_case_status(s: &str) -> Result<GovCorrelationCaseStatus> {
    match s.to_lowercase().as_str() {
        "pending" => Ok(GovCorrelationCaseStatus::Pending),
        "confirmed" => Ok(GovCorrelationCaseStatus::Confirmed),
        "rejected" => Ok(GovCorrelationCaseStatus::Rejected),
        "no_match" => Ok(GovCorrelationCaseStatus::NoMatch),
        "new_identity" => Ok(GovCorrelationCaseStatus::NewIdentity),
        "collision" => Ok(GovCorrelationCaseStatus::Collision),
        other => Err(GovernanceError::Validation(format!(
            "Invalid case status '{other}'. Must be one of: pending, confirmed, rejected, no_match, new_identity, collision"
        ))),
    }
}

/// Parse a trigger type string into a `GovCorrelationTrigger` enum value.
fn parse_trigger_type(s: &str) -> Result<GovCorrelationTrigger> {
    match s.to_lowercase().as_str() {
        "reconciliation" => Ok(GovCorrelationTrigger::Reconciliation),
        "live_sync" => Ok(GovCorrelationTrigger::LiveSync),
        "manual" => Ok(GovCorrelationTrigger::Manual),
        other => Err(GovernanceError::Validation(format!(
            "Invalid trigger type '{other}'. Must be one of: reconciliation, live_sync, manual"
        ))),
    }
}

/// Convert a `GovCorrelationCase` database model into a `CorrelationCaseSummaryResponse`.
fn case_to_summary(case: GovCorrelationCase) -> CorrelationCaseSummaryResponse {
    CorrelationCaseSummaryResponse {
        id: case.id,
        connector_id: case.connector_id,
        connector_name: None, // Connector name requires a join; populated by caller if needed.
        account_identifier: case.account_identifier,
        status: format!("{:?}", case.status).to_lowercase(),
        trigger_type: format!("{:?}", case.trigger_type).to_lowercase(),
        highest_confidence: case
            .highest_confidence
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0),
        candidate_count: case.candidate_count,
        assigned_to: case.assigned_to,
        created_at: case.created_at,
    }
}

/// Convert a `GovCorrelationCase` and its candidates into a `CorrelationCaseDetailResponse`.
fn case_to_detail(
    case: GovCorrelationCase,
    candidates: Vec<GovCorrelationCandidate>,
) -> CorrelationCaseDetailResponse {
    CorrelationCaseDetailResponse {
        id: case.id,
        connector_id: case.connector_id,
        connector_name: None,
        account_identifier: case.account_identifier,
        account_id: Some(case.account_id),
        status: format!("{:?}", case.status).to_lowercase(),
        trigger_type: format!("{:?}", case.trigger_type).to_lowercase(),
        highest_confidence: case
            .highest_confidence
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0),
        candidate_count: case.candidate_count,
        assigned_to: case.assigned_to,
        account_attributes: case.account_attributes,
        candidates: candidates.into_iter().map(candidate_to_detail).collect(),
        resolved_by: case.resolved_by,
        resolved_at: case.resolved_at,
        resolution_reason: case.resolution_reason,
        rules_snapshot: case.rules_snapshot,
        created_at: case.created_at,
        updated_at: case.updated_at,
    }
}

/// Convert a `GovCorrelationCandidate` database model into a `CorrelationCandidateDetailResponse`.
fn candidate_to_detail(c: GovCorrelationCandidate) -> CorrelationCandidateDetailResponse {
    CorrelationCandidateDetailResponse {
        id: c.id,
        identity_id: c.identity_id,
        identity_display_name: c.identity_display_name,
        identity_attributes: c.identity_attributes,
        aggregate_confidence: c
            .aggregate_confidence
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0),
        per_attribute_scores: c.per_attribute_scores,
        is_deactivated: c.is_deactivated,
        is_definitive_match: c.is_definitive_match,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn test_case_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests would require a database connection.
    }

    #[test]
    fn test_case_to_summary_mapping() {
        let case = GovCorrelationCase {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            account_identifier: "jdoe@example.com".to_string(),
            account_attributes: serde_json::json!({"email": "jdoe@example.com"}),
            status: GovCorrelationCaseStatus::Pending,
            trigger_type: GovCorrelationTrigger::Reconciliation,
            highest_confidence: Decimal::new(8750, 2), // 87.50
            candidate_count: 3,
            resolved_by: None,
            resolved_at: None,
            resolution_reason: None,
            resolution_candidate_id: None,
            assigned_to: None,
            rules_snapshot: serde_json::json!([]),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let summary = case_to_summary(case.clone());

        assert_eq!(summary.id, case.id);
        assert_eq!(summary.connector_id, case.connector_id);
        assert!(summary.connector_name.is_none());
        assert_eq!(summary.account_identifier, "jdoe@example.com");
        assert_eq!(summary.status, "pending");
        assert_eq!(summary.trigger_type, "reconciliation");
        assert!((summary.highest_confidence - 87.50).abs() < f64::EPSILON);
        assert_eq!(summary.candidate_count, 3);
        assert!(summary.assigned_to.is_none());
    }

    #[test]
    fn test_case_to_detail_mapping() {
        let case_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();

        let case = GovCorrelationCase {
            id: case_id,
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            account_identifier: "alice".to_string(),
            account_attributes: serde_json::json!({"username": "alice"}),
            status: GovCorrelationCaseStatus::Pending,
            trigger_type: GovCorrelationTrigger::LiveSync,
            highest_confidence: Decimal::new(9200, 2), // 92.00
            candidate_count: 1,
            resolved_by: None,
            resolved_at: None,
            resolution_reason: None,
            resolution_candidate_id: None,
            assigned_to: Some(Uuid::new_v4()),
            rules_snapshot: serde_json::json!({"rules": []}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let candidates = vec![GovCorrelationCandidate {
            id: Uuid::new_v4(),
            case_id,
            identity_id,
            identity_display_name: Some("Alice Smith".to_string()),
            identity_attributes: serde_json::json!({"email": "alice@example.com"}),
            aggregate_confidence: Decimal::new(9200, 2),
            per_attribute_scores: serde_json::json!({"scores": []}),
            is_deactivated: false,
            is_definitive_match: false,
            created_at: chrono::Utc::now(),
        }];

        let detail = case_to_detail(case.clone(), candidates);

        assert_eq!(detail.id, case.id);
        assert_eq!(detail.connector_id, case.connector_id);
        assert_eq!(detail.account_identifier, "alice");
        assert_eq!(detail.status, "pending");
        assert_eq!(detail.trigger_type, "livesync");
        assert!((detail.highest_confidence - 92.00).abs() < f64::EPSILON);
        assert_eq!(detail.candidate_count, 1);
        assert!(detail.assigned_to.is_some());
        assert_eq!(detail.candidates.len(), 1);
        assert_eq!(detail.candidates[0].identity_id, identity_id);
        assert_eq!(
            detail.candidates[0].identity_display_name,
            Some("Alice Smith".to_string())
        );
        assert!((detail.candidates[0].aggregate_confidence - 92.00).abs() < f64::EPSILON);
        assert!(!detail.candidates[0].is_deactivated);
        assert!(!detail.candidates[0].is_definitive_match);
    }

    #[test]
    fn test_candidate_to_detail_mapping() {
        let candidate = GovCorrelationCandidate {
            id: Uuid::new_v4(),
            case_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            identity_display_name: Some("Bob Jones".to_string()),
            identity_attributes: serde_json::json!({"email": "bob@example.com", "name": "Bob Jones"}),
            aggregate_confidence: Decimal::new(7500, 2), // 75.00
            per_attribute_scores: serde_json::json!({
                "scores": [
                    {"rule_name": "Email Match", "weighted_score": 0.5},
                    {"rule_name": "Name Fuzzy", "weighted_score": 0.25}
                ],
                "aggregate_confidence": 75.0
            }),
            is_deactivated: false,
            is_definitive_match: true,
            created_at: chrono::Utc::now(),
        };

        let detail = candidate_to_detail(candidate.clone());

        assert_eq!(detail.id, candidate.id);
        assert_eq!(detail.identity_id, candidate.identity_id);
        assert_eq!(detail.identity_display_name, Some("Bob Jones".to_string()));
        assert!((detail.aggregate_confidence - 75.00).abs() < f64::EPSILON);
        assert!(!detail.is_deactivated);
        assert!(detail.is_definitive_match);
        assert!(detail.per_attribute_scores.is_object());
    }

    #[test]
    fn test_parse_case_status_valid() {
        assert_eq!(
            parse_case_status("pending").unwrap(),
            GovCorrelationCaseStatus::Pending
        );
        assert_eq!(
            parse_case_status("confirmed").unwrap(),
            GovCorrelationCaseStatus::Confirmed
        );
        assert_eq!(
            parse_case_status("rejected").unwrap(),
            GovCorrelationCaseStatus::Rejected
        );
        assert_eq!(
            parse_case_status("no_match").unwrap(),
            GovCorrelationCaseStatus::NoMatch
        );
        assert_eq!(
            parse_case_status("new_identity").unwrap(),
            GovCorrelationCaseStatus::NewIdentity
        );
        assert_eq!(
            parse_case_status("collision").unwrap(),
            GovCorrelationCaseStatus::Collision
        );
        // Case insensitive.
        assert_eq!(
            parse_case_status("Pending").unwrap(),
            GovCorrelationCaseStatus::Pending
        );
        assert_eq!(
            parse_case_status("CONFIRMED").unwrap(),
            GovCorrelationCaseStatus::Confirmed
        );
    }

    #[test]
    fn test_parse_case_status_invalid() {
        assert!(parse_case_status("invalid").is_err());
        assert!(parse_case_status("").is_err());
    }

    #[test]
    fn test_parse_trigger_type_valid() {
        assert_eq!(
            parse_trigger_type("reconciliation").unwrap(),
            GovCorrelationTrigger::Reconciliation
        );
        assert_eq!(
            parse_trigger_type("live_sync").unwrap(),
            GovCorrelationTrigger::LiveSync
        );
        assert_eq!(
            parse_trigger_type("manual").unwrap(),
            GovCorrelationTrigger::Manual
        );
        // Case insensitive.
        assert_eq!(
            parse_trigger_type("MANUAL").unwrap(),
            GovCorrelationTrigger::Manual
        );
    }

    #[test]
    fn test_parse_trigger_type_invalid() {
        assert!(parse_trigger_type("unknown").is_err());
        assert!(parse_trigger_type("").is_err());
    }

    #[test]
    fn test_case_list_response_serialization() {
        let response = CorrelationCaseListResponse {
            items: vec![],
            total: 0,
            limit: 50,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"limit\":50"));
        assert!(json.contains("\"offset\":0"));
        assert!(json.contains("\"items\":[]"));
    }
}
