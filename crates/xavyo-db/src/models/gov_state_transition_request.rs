//! Governance State Transition Request model.
//!
//! Represents requests to transition objects between lifecycle states.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_lifecycle_config::LifecycleObjectType;

/// Status of a state transition request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_transition_request_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TransitionRequestStatus {
    /// Request is pending processing.
    Pending,
    /// Request is awaiting approval.
    PendingApproval,
    /// Request has been approved.
    Approved,
    /// Transition has been executed.
    Executed,
    /// Request was rejected.
    Rejected,
    /// Request was cancelled.
    Cancelled,
    /// Request expired without action.
    Expired,
    /// Transition was rolled back.
    RolledBack,
}

/// A governance state transition request.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovStateTransitionRequest {
    /// Unique identifier for the request.
    pub id: Uuid,

    /// The tenant this request belongs to.
    pub tenant_id: Uuid,

    /// The lifecycle configuration.
    pub config_id: Uuid,

    /// The transition being executed.
    pub transition_id: Uuid,

    /// ID of the object being transitioned.
    pub object_id: Uuid,

    /// Type of object being transitioned.
    pub object_type: LifecycleObjectType,

    /// Current state ID.
    pub from_state_id: Uuid,

    /// Target state ID.
    pub to_state_id: Uuid,

    /// User who requested the transition.
    pub requested_by: Uuid,

    /// Current status of the request.
    pub status: TransitionRequestStatus,

    /// Scheduled execution time (for future transitions).
    pub scheduled_for: Option<DateTime<Utc>>,

    /// Linked approval request ID (if approval required).
    pub approval_request_id: Option<Uuid>,

    /// When the transition was executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// When the grace period expires.
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Whether rollback is currently available.
    pub rollback_available: bool,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When the request was created.
    pub created_at: DateTime<Utc>,

    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,

    /// Version for optimistic locking.
    #[sqlx(default)]
    pub version: i32,

    /// Number of retry attempts for failed operations.
    #[sqlx(default)]
    pub retry_count: i32,

    /// When to next attempt retry.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Maximum number of retries allowed.
    #[sqlx(default)]
    pub max_retries: i32,
}

/// Request to create a new state transition request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovStateTransitionRequest {
    pub config_id: Uuid,
    pub transition_id: Uuid,
    pub object_id: Uuid,
    pub object_type: LifecycleObjectType,
    pub from_state_id: Uuid,
    pub to_state_id: Uuid,
    pub requested_by: Uuid,
    pub scheduled_for: Option<DateTime<Utc>>,
}

/// Request to update a state transition request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovStateTransitionRequest {
    pub status: Option<TransitionRequestStatus>,
    pub approval_request_id: Option<Uuid>,
    pub executed_at: Option<DateTime<Utc>>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub rollback_available: Option<bool>,
    pub error_message: Option<String>,
}

/// Filter options for listing transition requests.
#[derive(Debug, Clone, Default)]
pub struct TransitionRequestFilter {
    pub object_id: Option<Uuid>,
    pub object_type: Option<LifecycleObjectType>,
    pub status: Option<TransitionRequestStatus>,
    pub requested_by: Option<Uuid>,
    pub rollback_available: Option<bool>,
}

/// Transition request with state names for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovStateTransitionRequestWithStates {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub config_id: Uuid,
    pub transition_id: Uuid,
    pub transition_name: String,
    pub object_id: Uuid,
    pub object_type: LifecycleObjectType,
    pub from_state_id: Uuid,
    pub from_state_name: String,
    pub to_state_id: Uuid,
    pub to_state_name: String,
    pub requested_by: Uuid,
    pub status: TransitionRequestStatus,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub approval_request_id: Option<Uuid>,
    pub executed_at: Option<DateTime<Utc>>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub rollback_available: bool,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl GovStateTransitionRequest {
    /// Find a request by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a request by ID with state names.
    pub async fn find_by_id_with_states(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<GovStateTransitionRequestWithStates>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                r.id, r.tenant_id, r.config_id, r.transition_id, t.name as transition_name,
                r.object_id, r.object_type, r.from_state_id, fs.name as from_state_name,
                r.to_state_id, ts.name as to_state_name, r.requested_by, r.status,
                r.scheduled_for, r.approval_request_id, r.executed_at,
                r.grace_period_ends_at, r.rollback_available, r.error_message,
                r.created_at, r.updated_at
            FROM gov_state_transition_requests r
            JOIN gov_lifecycle_transitions t ON r.transition_id = t.id
            JOIN gov_lifecycle_states fs ON r.from_state_id = fs.id
            JOIN gov_lifecycle_states ts ON r.to_state_id = ts.id
            WHERE r.id = $1 AND r.tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the most recent request for an object.
    pub async fn find_latest_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE object_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(object_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find requests with active grace periods.
    pub async fn find_with_active_grace_period(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE object_id = $1 AND tenant_id = $2
            AND rollback_available = true
            AND grace_period_ends_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(object_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find requests pending approval.
    pub async fn find_pending_approval(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        approval_request_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE approval_request_id = $1 AND tenant_id = $2
            AND status = 'pending_approval'
            "#,
        )
        .bind(approval_request_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List requests for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TransitionRequestFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE tenant_id = $1
            "#,
        );

        let mut param_num = 2;

        if filter.object_id.is_some() {
            query.push_str(&format!(" AND object_id = ${}", param_num));
            param_num += 1;
        }

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${}", param_num));
            param_num += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_num));
            param_num += 1;
        }

        if filter.requested_by.is_some() {
            query.push_str(&format!(" AND requested_by = ${}", param_num));
            param_num += 1;
        }

        if filter.rollback_available.is_some() {
            query.push_str(&format!(" AND rollback_available = ${}", param_num));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(object_id) = filter.object_id {
            db_query = db_query.bind(object_id);
        }

        if let Some(object_type) = &filter.object_type {
            db_query = db_query.bind(object_type);
        }

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(requested_by) = filter.requested_by {
            db_query = db_query.bind(requested_by);
        }

        if let Some(rollback_available) = filter.rollback_available {
            db_query = db_query.bind(rollback_available);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List requests for an object.
    pub async fn list_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE object_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(object_id)
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count requests for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TransitionRequestFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_state_transition_requests
            WHERE tenant_id = $1
            "#,
        );

        let mut param_num = 2;

        if filter.object_id.is_some() {
            query.push_str(&format!(" AND object_id = ${}", param_num));
            param_num += 1;
        }

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${}", param_num));
            param_num += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_num));
            param_num += 1;
        }

        if filter.requested_by.is_some() {
            query.push_str(&format!(" AND requested_by = ${}", param_num));
            param_num += 1;
        }

        if filter.rollback_available.is_some() {
            query.push_str(&format!(" AND rollback_available = ${}", param_num));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(object_id) = filter.object_id {
            db_query = db_query.bind(object_id);
        }

        if let Some(object_type) = &filter.object_type {
            db_query = db_query.bind(object_type);
        }

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(requested_by) = filter.requested_by {
            db_query = db_query.bind(requested_by);
        }

        if let Some(rollback_available) = filter.rollback_available {
            db_query = db_query.bind(rollback_available);
        }

        db_query.fetch_one(pool).await
    }

    /// Find requests with expired grace periods that need to be finalized.
    pub async fn find_expired_grace_periods(pool: &sqlx::PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_state_transition_requests
            WHERE rollback_available = true
            AND grace_period_ends_at <= NOW()
            ORDER BY grace_period_ends_at ASC
            LIMIT 100
            "#,
        )
        .fetch_all(pool)
        .await
    }

    /// Create a new state transition request.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovStateTransitionRequest,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_state_transition_requests (
                tenant_id, config_id, transition_id, object_id, object_type,
                from_state_id, to_state_id, requested_by, scheduled_for
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.config_id)
        .bind(input.transition_id)
        .bind(input.object_id)
        .bind(input.object_type)
        .bind(input.from_state_id)
        .bind(input.to_state_id)
        .bind(input.requested_by)
        .bind(input.scheduled_for)
        .fetch_one(pool)
        .await
    }

    /// Update a state transition request.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovStateTransitionRequest,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_state_transition_requests
            SET
                status = COALESCE($3, status),
                approval_request_id = COALESCE($4, approval_request_id),
                executed_at = COALESCE($5, executed_at),
                grace_period_ends_at = COALESCE($6, grace_period_ends_at),
                rollback_available = COALESCE($7, rollback_available),
                error_message = COALESCE($8, error_message),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.approval_request_id)
        .bind(input.executed_at)
        .bind(input.grace_period_ends_at)
        .bind(input.rollback_available)
        .bind(&input.error_message)
        .fetch_optional(pool)
        .await
    }

    /// Mark grace period as expired (rollback no longer available).
    pub async fn expire_grace_period(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_state_transition_requests
            SET rollback_available = false, updated_at = NOW()
            WHERE id = $1 AND rollback_available = true
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a state transition request (only for pending/cancelled).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_state_transition_requests
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'cancelled')
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Expire grace periods for a tenant, marking rollback_available as false.
    ///
    /// Returns the number of records updated.
    pub async fn expire_grace_periods(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_state_transition_requests
            SET rollback_available = false, updated_at = NOW()
            WHERE tenant_id = $1
            AND rollback_available = true
            AND grace_period_ends_at <= NOW()
            AND id IN (
                SELECT id FROM gov_state_transition_requests
                WHERE tenant_id = $1
                AND rollback_available = true
                AND grace_period_ends_at <= NOW()
                LIMIT $2
            )
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Expire grace periods and return the affected request details.
    ///
    /// This is used when we need to emit events for each expired grace period.
    /// Returns a list of (request_id, object_id, object_type, to_state_id) tuples.
    pub async fn expire_grace_periods_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, Uuid, LifecycleObjectType, Uuid)>, sqlx::Error> {
        // First, get the IDs of requests to be expired
        let expired: Vec<(Uuid, Uuid, LifecycleObjectType, Uuid)> = sqlx::query_as(
            r#"
            UPDATE gov_state_transition_requests
            SET rollback_available = false, updated_at = NOW()
            WHERE tenant_id = $1
            AND rollback_available = true
            AND grace_period_ends_at <= NOW()
            AND id IN (
                SELECT id FROM gov_state_transition_requests
                WHERE tenant_id = $1
                AND rollback_available = true
                AND grace_period_ends_at <= NOW()
                LIMIT $2
            )
            RETURNING id, object_id, object_type, to_state_id
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(expired)
    }

    /// Get all tenant IDs that have expired grace periods.
    pub async fn get_tenants_with_expired_grace_periods(
        pool: &sqlx::PgPool,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT tenant_id FROM gov_state_transition_requests
            WHERE rollback_available = true
            AND grace_period_ends_at <= NOW()
            "#,
        )
        .fetch_all(pool)
        .await
    }
}
