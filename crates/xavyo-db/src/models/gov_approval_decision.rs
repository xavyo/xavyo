//! Governance Approval Decision model.
//!
//! Represents an approver's decision at each step of an approval workflow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Decision types for approvals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_approval_decision", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovDecisionType {
    /// Request approved at this step.
    Approved,
    /// Request rejected at this step.
    Rejected,
}

/// Record of an approver's decision.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApprovalDecision {
    /// Unique identifier for the decision.
    pub id: Uuid,

    /// The tenant this decision belongs to.
    pub tenant_id: Uuid,

    /// The request this decision is for.
    pub request_id: Uuid,

    /// Which step in the workflow this decision is for.
    pub step_order: i32,

    /// The user who made the decision.
    pub approver_id: Uuid,

    /// Original approver if this was made by a delegate.
    pub delegate_id: Option<Uuid>,

    /// The decision made.
    pub decision: GovDecisionType,

    /// Comments from the approver.
    pub comments: Option<String>,

    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
}

/// Request to create a new approval decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovApprovalDecision {
    pub tenant_id: Uuid,
    pub request_id: Uuid,
    pub step_order: i32,
    pub approver_id: Uuid,
    pub delegate_id: Option<Uuid>,
    pub decision: GovDecisionType,
    pub comments: Option<String>,
}

impl GovApprovalDecision {
    /// Find a decision by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_decisions
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find all decisions for a request, ordered by step.
    pub async fn find_by_request(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2
            ORDER BY step_order ASC, decided_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_all(pool)
        .await
    }

    /// Find decisions for a specific step.
    pub async fn find_by_request_and_step(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        request_id: Uuid,
        step_order: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2 AND step_order = $3
            ORDER BY decided_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(step_order)
        .fetch_optional(pool)
        .await
    }

    /// Find decisions made by a specific approver within a tenant.
    pub async fn find_by_approver(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        approver_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_decisions
            WHERE tenant_id = $1 AND approver_id = $2
            ORDER BY decided_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(approver_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Create a new decision.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateGovApprovalDecision,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_approval_decisions (
                tenant_id, request_id, step_order, approver_id, delegate_id, decision, comments
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(input.request_id)
        .bind(input.step_order)
        .bind(input.approver_id)
        .bind(input.delegate_id)
        .bind(input.decision)
        .bind(&input.comments)
        .fetch_one(pool)
        .await
    }

    /// Count decisions for a request within a tenant.
    pub async fn count_by_request(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_one(pool)
        .await
    }

    /// Check if decision is an approval.
    pub fn is_approved(&self) -> bool {
        matches!(self.decision, GovDecisionType::Approved)
    }

    /// Check if decision is a rejection.
    pub fn is_rejected(&self) -> bool {
        matches!(self.decision, GovDecisionType::Rejected)
    }

    /// Check if this decision was made by a delegate.
    pub fn is_delegated(&self) -> bool {
        self.delegate_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_type_serialization() {
        let approved = GovDecisionType::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");

        let rejected = GovDecisionType::Rejected;
        let json = serde_json::to_string(&rejected).unwrap();
        assert_eq!(json, "\"rejected\"");
    }

    #[test]
    fn test_decision_is_approved() {
        let decision = GovApprovalDecision {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            delegate_id: None,
            decision: GovDecisionType::Approved,
            comments: Some("Approved for Q4 reporting".to_string()),
            decided_at: Utc::now(),
        };

        assert!(decision.is_approved());
        assert!(!decision.is_rejected());
        assert!(!decision.is_delegated());
    }

    #[test]
    fn test_decision_is_delegated() {
        let decision = GovApprovalDecision {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            delegate_id: Some(Uuid::new_v4()),
            decision: GovDecisionType::Approved,
            comments: Some("Approved on behalf of manager".to_string()),
            decided_at: Utc::now(),
        };

        assert!(decision.is_delegated());
    }

    #[test]
    fn test_create_decision_request() {
        let request = CreateGovApprovalDecision {
            tenant_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            step_order: 1,
            approver_id: Uuid::new_v4(),
            delegate_id: None,
            decision: GovDecisionType::Rejected,
            comments: Some("Access not required for current role".to_string()),
        };

        assert!(matches!(request.decision, GovDecisionType::Rejected));
        assert!(request.comments.is_some());
    }
}
