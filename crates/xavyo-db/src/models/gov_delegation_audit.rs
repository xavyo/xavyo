//! Governance Delegation Audit model.
//!
//! Tracks all actions taken by deputies on behalf of delegators.
//! Part of F053 Deputy & Power of Attorney feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Action types for delegation audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_delegation_action", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DelegationActionType {
    /// Approved access request.
    ApproveRequest,
    /// Rejected access request.
    RejectRequest,
    /// Certified item in campaign.
    CertifyAccess,
    /// Revoked access in certification.
    RevokeAccess,
    /// Approved state transition.
    ApproveTransition,
    /// Rejected state transition.
    RejectTransition,
}

impl std::fmt::Display for DelegationActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApproveRequest => write!(f, "approve_request"),
            Self::RejectRequest => write!(f, "reject_request"),
            Self::CertifyAccess => write!(f, "certify_access"),
            Self::RevokeAccess => write!(f, "revoke_access"),
            Self::ApproveTransition => write!(f, "approve_transition"),
            Self::RejectTransition => write!(f, "reject_transition"),
        }
    }
}

/// Work item types that can be delegated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_work_item_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum WorkItemType {
    /// Access request approval.
    AccessRequest,
    /// Certification campaign item.
    Certification,
    /// Lifecycle state transition.
    StateTransition,
}

impl std::fmt::Display for WorkItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessRequest => write!(f, "access_request"),
            Self::Certification => write!(f, "certification"),
            Self::StateTransition => write!(f, "state_transition"),
        }
    }
}

/// Audit record for a deputy action.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovDelegationAudit {
    /// Unique identifier for the audit record.
    pub id: Uuid,

    /// The tenant this record belongs to.
    pub tenant_id: Uuid,

    /// The delegation that authorized this action.
    pub delegation_id: Uuid,

    /// The user who performed the action (deputy).
    pub deputy_id: Uuid,

    /// The user on whose behalf the action was taken (delegator).
    pub delegator_id: Uuid,

    /// The type of action performed.
    pub action_type: DelegationActionType,

    /// The ID of the work item that was actioned.
    pub work_item_id: Uuid,

    /// The type of work item.
    pub work_item_type: WorkItemType,

    /// Additional metadata (comments, etc.).
    pub metadata: JsonValue,

    /// When the action was performed.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new delegation audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovDelegationAudit {
    pub delegation_id: Uuid,
    pub deputy_id: Uuid,
    pub delegator_id: Uuid,
    pub action_type: DelegationActionType,
    pub work_item_id: Uuid,
    pub work_item_type: WorkItemType,
    pub metadata: Option<JsonValue>,
}

/// Filter options for listing delegation audit records.
#[derive(Debug, Clone, Default)]
pub struct DelegationAuditFilter {
    pub delegation_id: Option<Uuid>,
    pub deputy_id: Option<Uuid>,
    pub delegator_id: Option<Uuid>,
    pub action_type: Option<DelegationActionType>,
    pub work_item_type: Option<WorkItemType>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovDelegationAudit {
    /// Find an audit record by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_delegation_audit
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List audit records for a delegation.
    pub async fn find_by_delegation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        delegation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_delegation_audit
            WHERE tenant_id = $1 AND delegation_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(delegation_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List audit records for a deputy.
    pub async fn find_by_deputy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        deputy_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_delegation_audit
            WHERE tenant_id = $1 AND deputy_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(deputy_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List audit records for a delegator.
    pub async fn find_by_delegator(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        delegator_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_delegation_audit
            WHERE tenant_id = $1 AND delegator_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(delegator_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List audit records with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DelegationAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_delegation_audit
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.delegation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegation_id = ${param_count}"));
        }
        if filter.deputy_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND deputy_id = ${param_count}"));
        }
        if filter.delegator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegator_id = ${param_count}"));
        }
        if filter.action_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action_type = ${param_count}"));
        }
        if filter.work_item_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND work_item_type = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovDelegationAudit>(&query).bind(tenant_id);

        if let Some(delegation_id) = filter.delegation_id {
            q = q.bind(delegation_id);
        }
        if let Some(deputy_id) = filter.deputy_id {
            q = q.bind(deputy_id);
        }
        if let Some(delegator_id) = filter.delegator_id {
            q = q.bind(delegator_id);
        }
        if let Some(action_type) = filter.action_type {
            q = q.bind(action_type);
        }
        if let Some(work_item_type) = filter.work_item_type {
            q = q.bind(work_item_type);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count audit records with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DelegationAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_delegation_audit
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.delegation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegation_id = ${param_count}"));
        }
        if filter.deputy_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND deputy_id = ${param_count}"));
        }
        if filter.delegator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegator_id = ${param_count}"));
        }
        if filter.action_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action_type = ${param_count}"));
        }
        if filter.work_item_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND work_item_type = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(delegation_id) = filter.delegation_id {
            q = q.bind(delegation_id);
        }
        if let Some(deputy_id) = filter.deputy_id {
            q = q.bind(deputy_id);
        }
        if let Some(delegator_id) = filter.delegator_id {
            q = q.bind(delegator_id);
        }
        if let Some(action_type) = filter.action_type {
            q = q.bind(action_type);
        }
        if let Some(work_item_type) = filter.work_item_type {
            q = q.bind(work_item_type);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.fetch_one(pool).await
    }

    /// Create a new audit record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovDelegationAudit,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_delegation_audit (
                tenant_id, delegation_id, deputy_id, delegator_id,
                action_type, work_item_id, work_item_type, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.delegation_id)
        .bind(input.deputy_id)
        .bind(input.delegator_id)
        .bind(input.action_type)
        .bind(input.work_item_id)
        .bind(input.work_item_type)
        .bind(input.metadata.unwrap_or_else(|| serde_json::json!({})))
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_action_type_display() {
        assert_eq!(
            DelegationActionType::ApproveRequest.to_string(),
            "approve_request"
        );
        assert_eq!(
            DelegationActionType::RejectRequest.to_string(),
            "reject_request"
        );
        assert_eq!(
            DelegationActionType::CertifyAccess.to_string(),
            "certify_access"
        );
    }

    #[test]
    fn test_work_item_type_display() {
        assert_eq!(WorkItemType::AccessRequest.to_string(), "access_request");
        assert_eq!(WorkItemType::Certification.to_string(), "certification");
        assert_eq!(
            WorkItemType::StateTransition.to_string(),
            "state_transition"
        );
    }

    #[test]
    fn test_create_audit_input() {
        let input = CreateGovDelegationAudit {
            delegation_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            action_type: DelegationActionType::ApproveRequest,
            work_item_id: Uuid::new_v4(),
            work_item_type: WorkItemType::AccessRequest,
            metadata: Some(serde_json::json!({"comments": "Approved during vacation"})),
        };

        assert_eq!(input.action_type, DelegationActionType::ApproveRequest);
        assert_eq!(input.work_item_type, WorkItemType::AccessRequest);
        assert!(input.metadata.is_some());
    }

    #[test]
    fn test_audit_filter_default() {
        let filter = DelegationAuditFilter::default();

        assert!(filter.delegation_id.is_none());
        assert!(filter.deputy_id.is_none());
        assert!(filter.delegator_id.is_none());
    }
}
