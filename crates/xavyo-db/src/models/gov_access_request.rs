//! Governance Access Request model.
//!
//! Represents a user's request to gain access to a specific entitlement.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for access requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_request_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovRequestStatus {
    /// Awaiting first approval.
    Pending,
    /// In approval chain.
    PendingApproval,
    /// Fully approved, pending provisioning.
    Approved,
    /// Access granted.
    Provisioned,
    /// Rejected by approver.
    Rejected,
    /// Cancelled by requester.
    Cancelled,
    /// Auto-expired due to timeout.
    Expired,
    /// Provisioning failed.
    Failed,
}

impl GovRequestStatus {
    /// Check if the request is in a pending state (can be actioned).
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending | Self::PendingApproval)
    }

    /// Check if the request is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Provisioned | Self::Rejected | Self::Cancelled | Self::Expired | Self::Failed
        )
    }
}

/// A user's access request.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovAccessRequest {
    /// Unique identifier for the request.
    pub id: Uuid,

    /// The tenant this request belongs to.
    pub tenant_id: Uuid,

    /// The user submitting the request.
    pub requester_id: Uuid,

    /// The entitlement being requested.
    pub entitlement_id: Uuid,

    /// The workflow being used for approval.
    pub workflow_id: Option<Uuid>,

    /// Current step in the approval chain (0 = initial).
    pub current_step: i32,

    /// Request status.
    pub status: GovRequestStatus,

    /// Business justification for the request.
    pub justification: String,

    /// Optional requested access expiration.
    pub requested_expires_at: Option<DateTime<Utc>>,

    /// Whether SoD violations were detected.
    pub has_sod_warning: bool,

    /// SoD violation details for approver review.
    pub sod_violations: Option<serde_json::Value>,

    /// Assignment ID after provisioning.
    pub provisioned_assignment_id: Option<Uuid>,

    /// When the request was submitted.
    pub created_at: DateTime<Utc>,

    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the request expires (auto-timeout).
    pub expires_at: Option<DateTime<Utc>>,

    // Escalation tracking fields (F054)
    /// Current escalation level (0 = no escalation).
    pub current_escalation_level: i32,

    /// Deadline for current step/level action.
    pub current_deadline: Option<DateTime<Utc>>,

    /// Whether pre-escalation warning was sent.
    pub escalation_warning_sent: bool,
}

/// Request to create a new access request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovAccessRequest {
    pub requester_id: Uuid,
    pub entitlement_id: Uuid,
    pub workflow_id: Option<Uuid>,
    pub justification: String,
    pub requested_expires_at: Option<DateTime<Utc>>,
    pub has_sod_warning: bool,
    pub sod_violations: Option<serde_json::Value>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter options for listing access requests.
#[derive(Debug, Clone, Default)]
pub struct AccessRequestFilter {
    pub requester_id: Option<Uuid>,
    pub entitlement_id: Option<Uuid>,
    pub status: Option<GovRequestStatus>,
    pub statuses: Option<Vec<GovRequestStatus>>,
    pub has_sod_warning: Option<bool>,
}

impl GovAccessRequest {
    /// Find a request by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a request by ID within a tenant with row-level locking.
    ///
    /// Uses `FOR UPDATE` to prevent concurrent modifications.
    /// Used by approval operations to ensure only one deputy can act at a time (F053).
    pub async fn find_by_id_for_update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE id = $1 AND tenant_id = $2
            FOR UPDATE
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pending request for same user and entitlement.
    pub async fn find_pending_for_user_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE tenant_id = $1
              AND requester_id = $2
              AND entitlement_id = $3
              AND status IN ('pending', 'pending_approval')
            "#,
        )
        .bind(tenant_id)
        .bind(requester_id)
        .bind(entitlement_id)
        .fetch_optional(pool)
        .await
    }

    /// List requests for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AccessRequestFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_access_requests
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.requester_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND requester_id = ${}", param_count));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.has_sod_warning.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND has_sod_warning = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovAccessRequest>(&query).bind(tenant_id);

        if let Some(requester_id) = filter.requester_id {
            q = q.bind(requester_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(has_sod_warning) = filter.has_sod_warning {
            q = q.bind(has_sod_warning);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count requests in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AccessRequestFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_access_requests
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.requester_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND requester_id = ${}", param_count));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.has_sod_warning.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND has_sod_warning = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(requester_id) = filter.requester_id {
            q = q.bind(requester_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(has_sod_warning) = filter.has_sod_warning {
            q = q.bind(has_sod_warning);
        }

        q.fetch_one(pool).await
    }

    /// Create a new access request.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovAccessRequest,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_access_requests (
                tenant_id, requester_id, entitlement_id, workflow_id,
                justification, requested_expires_at, has_sod_warning,
                sod_violations, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.requester_id)
        .bind(input.entitlement_id)
        .bind(input.workflow_id)
        .bind(&input.justification)
        .bind(input.requested_expires_at)
        .bind(input.has_sod_warning)
        .bind(&input.sod_violations)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Update request status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: GovRequestStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Advance to next approval step.
    pub async fn advance_step(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET current_step = current_step + 1,
                status = 'pending_approval',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Set provisioned assignment ID.
    pub async fn set_provisioned(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET status = 'provisioned',
                provisioned_assignment_id = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_optional(pool)
        .await
    }

    /// Find expired requests that need to be auto-expired.
    pub async fn find_expired(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE status IN ('pending', 'pending_approval')
              AND expires_at IS NOT NULL
              AND expires_at <= $1
            "#,
        )
        .bind(now)
        .fetch_all(pool)
        .await
    }

    /// Expire stale requests.
    pub async fn expire_stale(pool: &sqlx::PgPool, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_access_requests
            SET status = 'expired', updated_at = NOW()
            WHERE status IN ('pending', 'pending_approval')
              AND expires_at IS NOT NULL
              AND expires_at <= $1
            "#,
        )
        .bind(now)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ==================== Escalation Methods (F054) ====================

    /// Find requests that need escalation (deadline passed).
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent race conditions when multiple
    /// workers process escalations concurrently. Locked rows (being approved or
    /// processed by another worker) are skipped.
    pub async fn find_pending_escalation(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE status IN ('pending', 'pending_approval')
              AND current_deadline IS NOT NULL
              AND current_deadline <= $1
            ORDER BY current_deadline ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find requests that need warning notification (approaching deadline).
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent race conditions.
    pub async fn find_pending_warning(
        pool: &sqlx::PgPool,
        warning_threshold: DateTime<Utc>,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_access_requests
            WHERE status IN ('pending', 'pending_approval')
              AND current_deadline IS NOT NULL
              AND current_deadline > $1
              AND current_deadline <= $2
              AND escalation_warning_sent = false
            ORDER BY current_deadline ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(now)
        .bind(warning_threshold)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Update escalation state after escalation occurs.
    pub async fn update_escalation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_level: i32,
        new_deadline: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET current_escalation_level = $3,
                current_deadline = $4,
                escalation_warning_sent = false,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_level)
        .bind(new_deadline)
        .fetch_optional(pool)
        .await
    }

    /// Mark warning as sent.
    pub async fn mark_warning_sent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET escalation_warning_sent = true,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Set deadline for current step (called when entering a new step).
    pub async fn set_deadline(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        deadline: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET current_deadline = $3,
                current_escalation_level = 0,
                escalation_warning_sent = false,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(deadline)
        .fetch_optional(pool)
        .await
    }

    /// Cancel pending escalation (stop timer, keep current assignee).
    pub async fn cancel_escalation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET current_deadline = NULL,
                escalation_warning_sent = false,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reset escalation (return to original, restart timer).
    pub async fn reset_escalation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_deadline: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_access_requests
            SET current_escalation_level = 0,
                current_deadline = $3,
                escalation_warning_sent = false,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_deadline)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_is_pending() {
        assert!(GovRequestStatus::Pending.is_pending());
        assert!(GovRequestStatus::PendingApproval.is_pending());
        assert!(!GovRequestStatus::Approved.is_pending());
        assert!(!GovRequestStatus::Provisioned.is_pending());
    }

    #[test]
    fn test_status_is_terminal() {
        assert!(GovRequestStatus::Provisioned.is_terminal());
        assert!(GovRequestStatus::Rejected.is_terminal());
        assert!(GovRequestStatus::Cancelled.is_terminal());
        assert!(GovRequestStatus::Expired.is_terminal());
        assert!(GovRequestStatus::Failed.is_terminal());
        assert!(!GovRequestStatus::Pending.is_terminal());
        assert!(!GovRequestStatus::PendingApproval.is_terminal());
    }

    #[test]
    fn test_status_serialization() {
        let pending = GovRequestStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let pending_approval = GovRequestStatus::PendingApproval;
        let json = serde_json::to_string(&pending_approval).unwrap();
        assert_eq!(json, "\"pending_approval\"");
    }

    #[test]
    fn test_create_request() {
        let request = CreateGovAccessRequest {
            requester_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            workflow_id: None,
            justification: "I need access for quarterly reporting".to_string(),
            requested_expires_at: None,
            has_sod_warning: false,
            sod_violations: None,
            expires_at: None,
        };

        assert_eq!(
            request.justification,
            "I need access for quarterly reporting"
        );
        assert!(!request.has_sod_warning);
    }
}
