//! NHI Request model.
//!
//! Self-service NHI provisioning requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of an NHI request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_nhi_request_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NhiRequestStatus {
    /// Request is pending approval.
    Pending,
    /// Request was approved (NHI created).
    Approved,
    /// Request was rejected.
    Rejected,
    /// Request was cancelled by requester.
    Cancelled,
}

/// An NHI request record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovNhiRequest {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this request belongs to.
    pub tenant_id: Uuid,

    /// Who submitted the request.
    pub requester_id: Uuid,

    /// Requested NHI name.
    pub requested_name: String,

    /// Purpose/justification for the NHI.
    pub purpose: String,

    /// Entitlement IDs to assign to the NHI.
    pub requested_permissions: Vec<Uuid>,

    /// Requested expiration date.
    pub requested_expiration: Option<DateTime<Utc>>,

    /// Requested rotation interval in days.
    pub requested_rotation_days: Option<i32>,

    /// Current status.
    pub status: NhiRequestStatus,

    /// Who approved/rejected the request.
    pub approver_id: Option<Uuid>,

    /// When the decision was made.
    pub decision_at: Option<DateTime<Utc>>,

    /// Approver comments.
    pub decision_comments: Option<String>,

    /// The created NHI ID (if approved).
    pub created_nhi_id: Option<Uuid>,

    /// When this request expires.
    pub expires_at: DateTime<Utc>,

    /// When the request was submitted.
    pub created_at: DateTime<Utc>,

    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new NHI request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovNhiRequest {
    pub requester_id: Uuid,
    pub requested_name: String,
    pub purpose: String,
    pub requested_permissions: Vec<Uuid>,
    pub requested_expiration: Option<DateTime<Utc>>,
    pub requested_rotation_days: Option<i32>,
    pub expires_at: DateTime<Utc>,
}

/// Request to approve an NHI request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveGovNhiRequest {
    pub approver_id: Uuid,
    pub comments: Option<String>,
    pub created_nhi_id: Uuid,
}

/// Request to reject an NHI request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectGovNhiRequest {
    pub approver_id: Uuid,
    pub reason: String,
}

/// Filter options for listing NHI requests.
#[derive(Debug, Clone, Default)]
pub struct NhiRequestFilter {
    pub requester_id: Option<Uuid>,
    pub status: Option<NhiRequestStatus>,
    pub pending_only: Option<bool>,
}

impl GovNhiRequest {
    /// Check if the request can still be actioned.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.status == NhiRequestStatus::Pending && self.expires_at > Utc::now()
    }

    /// Find request by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_requests
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List NHI requests with filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiRequestFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_nhi_requests
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.requester_id.is_some() {
            query.push_str(&format!(" AND requester_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if filter.pending_only == Some(true) {
            query.push_str(" AND status = 'pending' AND expires_at > NOW()");
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(requester_id) = filter.requester_id {
            q = q.bind(requester_id);
        }

        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count NHI requests with filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiRequestFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_nhi_requests
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.requester_id.is_some() {
            query.push_str(&format!(" AND requester_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
        }

        if filter.pending_only == Some(true) {
            query.push_str(" AND status = 'pending' AND expires_at > NOW()");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(requester_id) = filter.requester_id {
            q = q.bind(requester_id);
        }

        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.fetch_one(pool).await
    }

    /// Create a new NHI request.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovNhiRequest,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_nhi_requests (
                tenant_id, requester_id, requested_name, purpose,
                requested_permissions, requested_expiration,
                requested_rotation_days, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.requester_id)
        .bind(&data.requested_name)
        .bind(&data.purpose)
        .bind(&data.requested_permissions)
        .bind(data.requested_expiration)
        .bind(data.requested_rotation_days)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Approve a request.
    pub async fn approve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: ApproveGovNhiRequest,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_nhi_requests
            SET
                status = 'approved',
                approver_id = $3,
                decision_at = NOW(),
                decision_comments = $4,
                created_nhi_id = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(data.approver_id)
        .bind(&data.comments)
        .bind(data.created_nhi_id)
        .fetch_optional(pool)
        .await
    }

    /// Reject a request.
    pub async fn reject(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: RejectGovNhiRequest,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_nhi_requests
            SET
                status = 'rejected',
                approver_id = $3,
                decision_at = NOW(),
                decision_comments = $4
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(data.approver_id)
        .bind(&data.reason)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a request (requester only).
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        requester_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_nhi_requests
            SET status = 'cancelled'
            WHERE id = $1 AND tenant_id = $2 AND requester_id = $3 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(requester_id)
        .fetch_optional(pool)
        .await
    }

    /// Expire old pending requests.
    pub async fn expire_old_requests(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_nhi_requests
            SET status = 'cancelled'
            WHERE tenant_id = $1 AND status = 'pending' AND expires_at < NOW()
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check for duplicate pending request.
    pub async fn has_pending_request(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_nhi_requests
            WHERE tenant_id = $1
                AND requester_id = $2
                AND requested_name = $3
                AND status = 'pending'
                AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(requester_id)
        .bind(name)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_status_serialization() {
        let pending = NhiRequestStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let approved = NhiRequestStatus::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");

        let rejected = NhiRequestStatus::Rejected;
        let json = serde_json::to_string(&rejected).unwrap();
        assert_eq!(json, "\"rejected\"");

        let cancelled = NhiRequestStatus::Cancelled;
        let json = serde_json::to_string(&cancelled).unwrap();
        assert_eq!(json, "\"cancelled\"");
    }
}
