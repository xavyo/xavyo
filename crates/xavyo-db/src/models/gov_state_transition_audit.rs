//! Governance State Transition Audit model.
//!
//! Immutable audit records for executed state transitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_lifecycle_config::LifecycleObjectType;

/// Type of audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_audit_action_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuditActionType {
    /// Transition execution.
    Execute,
    /// Transition rollback.
    Rollback,
}

/// A governance state transition audit record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovStateTransitionAudit {
    /// Unique identifier for the audit record.
    pub id: Uuid,

    /// The tenant this audit belongs to.
    pub tenant_id: Uuid,

    /// The original transition request ID.
    pub request_id: Uuid,

    /// ID of the object that was transitioned.
    pub object_id: Uuid,

    /// Type of object that was transitioned.
    pub object_type: LifecycleObjectType,

    /// Source state name (snapshot at time of transition).
    pub from_state: String,

    /// Target state name (snapshot at time of transition).
    pub to_state: String,

    /// Transition name (snapshot at time of transition).
    pub transition_name: String,

    /// User who performed the action.
    pub actor_id: Uuid,

    /// Type of action (execute or rollback).
    pub action_type: AuditActionType,

    /// Approval details if approval was required.
    pub approval_details: Option<JsonValue>,

    /// Snapshot of entitlements before the transition.
    pub entitlements_before: JsonValue,

    /// Snapshot of entitlements after the transition.
    pub entitlements_after: JsonValue,

    /// Additional metadata.
    pub metadata: Option<JsonValue>,

    /// When the audit record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovStateTransitionAudit {
    pub request_id: Uuid,
    pub object_id: Uuid,
    pub object_type: LifecycleObjectType,
    pub from_state: String,
    pub to_state: String,
    pub transition_name: String,
    pub actor_id: Uuid,
    pub action_type: AuditActionType,
    pub approval_details: Option<JsonValue>,
    pub entitlements_before: JsonValue,
    pub entitlements_after: JsonValue,
    pub metadata: Option<JsonValue>,
}

/// Filter options for listing audit records.
#[derive(Debug, Clone, Default)]
pub struct TransitionAuditFilter {
    pub object_id: Option<Uuid>,
    pub object_type: Option<LifecycleObjectType>,
    pub actor_id: Option<Uuid>,
    pub action_type: Option<AuditActionType>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Approval details stored in audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDetails {
    pub workflow_id: Uuid,
    pub request_id: Uuid,
    pub approver_id: Uuid,
    pub decision: String,
    pub comments: Option<String>,
    pub decided_at: DateTime<Utc>,
}

/// Entitlement snapshot for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    pub entitlement_id: Uuid,
    pub entitlement_name: String,
    pub application_id: Uuid,
    pub application_name: String,
    pub status: String,
}

/// Request to update entitlement snapshots in an audit record.
///
/// Only allows updating the entitlement snapshots, which may need to be
/// captured separately from the initial audit record creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovStateTransitionAudit {
    pub entitlements_before: Option<JsonValue>,
    pub entitlements_after: Option<JsonValue>,
}

impl GovStateTransitionAudit {
    /// Find an audit record by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_state_transition_audit
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find audit records by request ID.
    pub async fn find_by_request_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_state_transition_audit
            WHERE request_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(request_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List audit records for an object.
    pub async fn list_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_state_transition_audit
            WHERE object_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(object_id)
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List audit records for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TransitionAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_state_transition_audit
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.object_id.is_some() {
            query.push_str(&format!(" AND object_id = ${param_num}"));
            param_num += 1;
        }

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${param_num}"));
            param_num += 1;
        }

        if filter.actor_id.is_some() {
            query.push_str(&format!(" AND actor_id = ${param_num}"));
            param_num += 1;
        }

        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_num}"));
            param_num += 1;
        }

        if filter.from_date.is_some() {
            query.push_str(&format!(" AND created_at >= ${param_num}"));
            param_num += 1;
        }

        if filter.to_date.is_some() {
            query.push_str(&format!(" AND created_at <= ${param_num}"));
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

        if let Some(actor_id) = filter.actor_id {
            db_query = db_query.bind(actor_id);
        }

        if let Some(action_type) = &filter.action_type {
            db_query = db_query.bind(action_type);
        }

        if let Some(from_date) = filter.from_date {
            db_query = db_query.bind(from_date);
        }

        if let Some(to_date) = filter.to_date {
            db_query = db_query.bind(to_date);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count audit records for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TransitionAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_state_transition_audit
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.object_id.is_some() {
            query.push_str(&format!(" AND object_id = ${param_num}"));
            param_num += 1;
        }

        if filter.object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${param_num}"));
            param_num += 1;
        }

        if filter.actor_id.is_some() {
            query.push_str(&format!(" AND actor_id = ${param_num}"));
            param_num += 1;
        }

        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_num}"));
            param_num += 1;
        }

        if filter.from_date.is_some() {
            query.push_str(&format!(" AND created_at >= ${param_num}"));
            param_num += 1;
        }

        if filter.to_date.is_some() {
            query.push_str(&format!(" AND created_at <= ${param_num}"));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(object_id) = filter.object_id {
            db_query = db_query.bind(object_id);
        }

        if let Some(object_type) = &filter.object_type {
            db_query = db_query.bind(object_type);
        }

        if let Some(actor_id) = filter.actor_id {
            db_query = db_query.bind(actor_id);
        }

        if let Some(action_type) = &filter.action_type {
            db_query = db_query.bind(action_type);
        }

        if let Some(from_date) = filter.from_date {
            db_query = db_query.bind(from_date);
        }

        if let Some(to_date) = filter.to_date {
            db_query = db_query.bind(to_date);
        }

        db_query.fetch_one(pool).await
    }

    /// Count audit records for an object.
    pub async fn count_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_state_transition_audit
            WHERE object_id = $1 AND tenant_id = $2
            ",
        )
        .bind(object_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Get the most recent audit record for an object.
    pub async fn find_latest_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_state_transition_audit
            WHERE object_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(object_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Create a new audit record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovStateTransitionAudit,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_state_transition_audit (
                tenant_id, request_id, object_id, object_type,
                from_state, to_state, transition_name, actor_id,
                action_type, approval_details, entitlements_before,
                entitlements_after, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.request_id)
        .bind(input.object_id)
        .bind(input.object_type)
        .bind(&input.from_state)
        .bind(&input.to_state)
        .bind(&input.transition_name)
        .bind(input.actor_id)
        .bind(input.action_type)
        .bind(&input.approval_details)
        .bind(&input.entitlements_before)
        .bind(&input.entitlements_after)
        .bind(&input.metadata)
        .fetch_one(pool)
        .await
    }

    /// Update entitlement snapshots in an audit record.
    ///
    /// This is a limited update that only allows modifying the entitlement
    /// snapshots, which may need to be captured separately from the initial
    /// audit record creation.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovStateTransitionAudit,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_state_transition_audit
            SET
                entitlements_before = COALESCE($3, entitlements_before),
                entitlements_after = COALESCE($4, entitlements_after)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.entitlements_before)
        .bind(&input.entitlements_after)
        .fetch_optional(pool)
        .await
    }

    // Note: No delete method - audit records are immutable
}
