//! Governance Approval Delegation model.
//!
//! Represents temporary transfer of approval authority from one user to another.
//! Extended in F053 to support scoped delegations and lifecycle management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Delegation lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_delegation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    /// Scheduled but not yet active.
    #[default]
    Pending,
    /// Currently active.
    Active,
    /// Expired by end date.
    Expired,
    /// Manually revoked.
    Revoked,
}

impl DelegationStatus {
    /// Check if the delegation is in a state that can be acted upon.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the delegation is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Expired | Self::Revoked)
    }
}

/// A temporary delegation of approval authority.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApprovalDelegation {
    /// Unique identifier for the delegation.
    pub id: Uuid,

    /// The tenant this delegation belongs to.
    pub tenant_id: Uuid,

    /// The user delegating their approval authority.
    pub delegator_id: Uuid,

    /// The user receiving approval authority (deputy).
    pub delegate_id: Uuid,

    /// When the delegation becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,

    /// Whether the delegation is currently active (not revoked).
    /// Legacy field - use status for new code.
    pub is_active: bool,

    /// When the delegation was created.
    pub created_at: DateTime<Utc>,

    /// When the delegation was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Scope restrictions for this delegation. NULL = full authority.
    pub scope_id: Option<Uuid>,

    /// Lifecycle status of the delegation.
    pub status: DelegationStatus,

    /// Whether the 24-hour expiration warning has been sent.
    pub expiry_warning_sent: bool,
}

/// Request to create a new delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovApprovalDelegation {
    pub delegator_id: Uuid,
    pub delegate_id: Uuid,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    /// Optional scope ID for restricted delegation.
    pub scope_id: Option<Uuid>,
}

/// Filter options for listing delegations.
#[derive(Debug, Clone, Default)]
pub struct DelegationFilter {
    pub delegator_id: Option<Uuid>,
    pub delegate_id: Option<Uuid>,
    pub is_active: Option<bool>,
    pub active_now: Option<bool>,
    /// Filter by status.
    pub status: Option<DelegationStatus>,
    /// Filter by multiple statuses.
    pub statuses: Option<Vec<DelegationStatus>>,
}

impl GovApprovalDelegation {
    /// Find a delegation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find active delegation from a delegator at a specific time.
    pub async fn find_active_for_delegator(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        delegator_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND delegator_id = $2
              AND is_active = TRUE
              AND starts_at <= $3
              AND ends_at > $3
            ",
        )
        .bind(tenant_id)
        .bind(delegator_id)
        .bind(at_time)
        .fetch_optional(pool)
        .await
    }

    /// Find active delegations where a user is the delegate at a specific time.
    pub async fn find_active_for_delegate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        delegate_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND delegate_id = $2
              AND is_active = TRUE
              AND starts_at <= $3
              AND ends_at > $3
            ",
        )
        .bind(tenant_id)
        .bind(delegate_id)
        .bind(at_time)
        .fetch_all(pool)
        .await
    }

    /// Check if user A is currently delegating to user B.
    pub async fn is_delegating_to(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        delegator_id: Uuid,
        delegate_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND delegator_id = $2
              AND delegate_id = $3
              AND is_active = TRUE
              AND starts_at <= $4
              AND ends_at > $4
            ",
        )
        .bind(tenant_id)
        .bind(delegator_id)
        .bind(delegate_id)
        .bind(at_time)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List delegations for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DelegationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let now = Utc::now();
        let mut query = String::from(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.delegator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegator_id = ${param_count}"));
        }
        if filter.delegate_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegate_id = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.active_now == Some(true) {
            param_count += 1;
            query.push_str(&format!(
                " AND is_active = TRUE AND starts_at <= ${param_count} AND ends_at > ${param_count}"
            ));
        }

        query.push_str(&format!(
            " ORDER BY starts_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovApprovalDelegation>(&query).bind(tenant_id);

        if let Some(delegator_id) = filter.delegator_id {
            q = q.bind(delegator_id);
        }
        if let Some(delegate_id) = filter.delegate_id {
            q = q.bind(delegate_id);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if filter.active_now == Some(true) {
            q = q.bind(now);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count delegations in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DelegationFilter,
    ) -> Result<i64, sqlx::Error> {
        let now = Utc::now();
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_approval_delegations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.delegator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegator_id = ${param_count}"));
        }
        if filter.delegate_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delegate_id = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.active_now == Some(true) {
            param_count += 1;
            query.push_str(&format!(
                " AND is_active = TRUE AND starts_at <= ${param_count} AND ends_at > ${param_count}"
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(delegator_id) = filter.delegator_id {
            q = q.bind(delegator_id);
        }
        if let Some(delegate_id) = filter.delegate_id {
            q = q.bind(delegate_id);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if filter.active_now == Some(true) {
            q = q.bind(now);
        }

        q.fetch_one(pool).await
    }

    /// Create a new delegation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovApprovalDelegation,
    ) -> Result<Self, sqlx::Error> {
        // Determine initial status: active if starts_at is now or past, pending otherwise
        let now = Utc::now();
        let initial_status = if input.starts_at <= now {
            DelegationStatus::Active
        } else {
            DelegationStatus::Pending
        };

        sqlx::query_as(
            r"
            INSERT INTO gov_approval_delegations (
                tenant_id, delegator_id, delegate_id, starts_at, ends_at, scope_id, status, is_active
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.delegator_id)
        .bind(input.delegate_id)
        .bind(input.starts_at)
        .bind(input.ends_at)
        .bind(input.scope_id)
        .bind(initial_status)
        .bind(initial_status == DelegationStatus::Active)
        .fetch_one(pool)
        .await
    }

    /// Revoke a delegation.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_delegations
            SET is_active = FALSE, revoked_at = NOW(), status = 'revoked'
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Activate a pending delegation.
    pub async fn activate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_delegations
            SET is_active = TRUE, status = 'active'
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Expire a delegation (end date reached).
    pub async fn expire(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_delegations
            SET is_active = FALSE, status = 'expired'
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Extend the end date of an active delegation.
    pub async fn extend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_ends_at: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_delegations
            SET ends_at = $3, expiry_warning_sent = FALSE
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'active')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_ends_at)
        .fetch_optional(pool)
        .await
    }

    /// Mark expiry warning as sent.
    pub async fn mark_expiry_warning_sent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_delegations
            SET expiry_warning_sent = TRUE
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find delegations pending activation (`starts_at` <= now and status = pending).
    pub async fn find_pending_activation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND status = 'pending'
              AND starts_at <= NOW()
            ORDER BY starts_at ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find delegations due for expiration (`ends_at` <= now and status = active).
    pub async fn find_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND status = 'active'
              AND ends_at <= NOW()
            ORDER BY ends_at ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find delegations expiring soon (within warning period, not yet warned).
    pub async fn find_expiring_soon(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        warning_hours: i64,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND status = 'active'
              AND ends_at <= NOW() + ($2 || ' hours')::interval
              AND ends_at > NOW()
              AND expiry_warning_sent = FALSE
            ORDER BY ends_at ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(warning_hours.to_string())
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find all tenants with delegations needing lifecycle processing.
    pub async fn get_tenants_with_pending_lifecycle(
        pool: &sqlx::PgPool,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT DISTINCT tenant_id FROM gov_approval_delegations
            WHERE (status = 'pending' AND starts_at <= NOW())
               OR (status = 'active' AND ends_at <= NOW())
               OR (status = 'active' AND ends_at <= NOW() + interval '24 hours' AND expiry_warning_sent = FALSE)
            ",
        )
        .fetch_all(pool)
        .await
    }

    /// Check if this delegation is currently active.
    #[must_use]
    pub fn is_currently_active(&self, now: DateTime<Utc>) -> bool {
        self.is_active && self.starts_at <= now && self.ends_at > now
    }

    /// Find all active delegations for a delegate (deputy) that may apply to a work item.
    /// Returns delegations with their scopes for further matching.
    pub async fn find_active_delegations_for_deputy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        deputy_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND delegate_id = $2
              AND status = 'active'
              AND starts_at <= $3
              AND ends_at > $3
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(deputy_id)
        .bind(at_time)
        .fetch_all(pool)
        .await
    }

    /// Find a matching delegation for a work item.
    /// Uses the database function to check scope matching.
    /// Returns the first matching delegation (if any).
    #[allow(clippy::too_many_arguments)]
    pub async fn find_matching_delegation_for_work_item(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        deputy_id: Uuid,
        delegator_id: Option<Uuid>,
        application_id: Option<Uuid>,
        entitlement_id: Option<Uuid>,
        role_id: Option<Uuid>,
        workflow_type: Option<&str>,
        at_time: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build query with optional delegator filter
        let base_query = if delegator_id.is_some() {
            r"
            SELECT d.* FROM gov_approval_delegations d
            WHERE d.tenant_id = $1
              AND d.delegate_id = $2
              AND d.delegator_id = $3
              AND d.status = 'active'
              AND d.starts_at <= $4
              AND d.ends_at > $4
              AND work_item_matches_delegation_scope(d.id, $5, $6, $7, $8)
            ORDER BY d.created_at ASC
            LIMIT 1
            "
        } else {
            r"
            SELECT d.* FROM gov_approval_delegations d
            WHERE d.tenant_id = $1
              AND d.delegate_id = $2
              AND d.status = 'active'
              AND d.starts_at <= $3
              AND d.ends_at > $3
              AND work_item_matches_delegation_scope(d.id, $4, $5, $6, $7)
            ORDER BY d.created_at ASC
            LIMIT 1
            "
        };

        if let Some(del_id) = delegator_id {
            sqlx::query_as(base_query)
                .bind(tenant_id)
                .bind(deputy_id)
                .bind(del_id)
                .bind(at_time)
                .bind(application_id)
                .bind(entitlement_id)
                .bind(role_id)
                .bind(workflow_type)
                .fetch_optional(pool)
                .await
        } else {
            sqlx::query_as(base_query)
                .bind(tenant_id)
                .bind(deputy_id)
                .bind(at_time)
                .bind(application_id)
                .bind(entitlement_id)
                .bind(role_id)
                .bind(workflow_type)
                .fetch_optional(pool)
                .await
        }
    }

    /// Check if a delegation (by `scope_id`) matches a work item.
    /// If `scope_id` is None, returns true (full delegation).
    pub async fn delegation_matches_work_item(
        pool: &sqlx::PgPool,
        delegation_id: Uuid,
        application_id: Option<Uuid>,
        entitlement_id: Option<Uuid>,
        role_id: Option<Uuid>,
        workflow_type: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result: bool = sqlx::query_scalar(
            r"
            SELECT work_item_matches_delegation_scope($1, $2, $3, $4, $5)
            ",
        )
        .bind(delegation_id)
        .bind(application_id)
        .bind(entitlement_id)
        .bind(role_id)
        .bind(workflow_type)
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    /// Find all delegators whose work items a deputy can act on.
    pub async fn find_delegators_for_deputy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        deputy_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT DISTINCT delegator_id FROM gov_approval_delegations
            WHERE tenant_id = $1
              AND delegate_id = $2
              AND status = 'active'
              AND starts_at <= $3
              AND ends_at > $3
            ",
        )
        .bind(tenant_id)
        .bind(deputy_id)
        .bind(at_time)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_test_delegation(
        now: DateTime<Utc>,
        is_active: bool,
        status: DelegationStatus,
    ) -> GovApprovalDelegation {
        GovApprovalDelegation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            delegate_id: Uuid::new_v4(),
            starts_at: now - Duration::hours(1),
            ends_at: now + Duration::hours(1),
            is_active,
            created_at: now - Duration::hours(1),
            revoked_at: None,
            scope_id: None,
            status,
            expiry_warning_sent: false,
        }
    }

    #[test]
    fn test_create_delegation_request() {
        let now = Utc::now();
        let request = CreateGovApprovalDelegation {
            delegator_id: Uuid::new_v4(),
            delegate_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(7),
            scope_id: None,
        };

        assert!(request.ends_at > request.starts_at);
    }

    #[test]
    fn test_create_delegation_with_scope() {
        let now = Utc::now();
        let scope_id = Uuid::new_v4();
        let request = CreateGovApprovalDelegation {
            delegator_id: Uuid::new_v4(),
            delegate_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(7),
            scope_id: Some(scope_id),
        };

        assert_eq!(request.scope_id, Some(scope_id));
    }

    #[test]
    fn test_is_currently_active() {
        let now = Utc::now();
        let delegation = make_test_delegation(now, true, DelegationStatus::Active);

        assert!(delegation.is_currently_active(now));
    }

    #[test]
    fn test_is_not_active_when_revoked() {
        let now = Utc::now();
        let mut delegation = make_test_delegation(now, false, DelegationStatus::Revoked);
        delegation.revoked_at = Some(now);

        assert!(!delegation.is_currently_active(now));
    }

    #[test]
    fn test_is_not_active_when_expired() {
        let now = Utc::now();
        let mut delegation = make_test_delegation(now, true, DelegationStatus::Expired);
        delegation.starts_at = now - Duration::hours(2);
        delegation.ends_at = now - Duration::hours(1);

        assert!(!delegation.is_currently_active(now));
    }

    #[test]
    fn test_delegation_status_actionable() {
        assert!(DelegationStatus::Active.is_actionable());
        assert!(!DelegationStatus::Pending.is_actionable());
        assert!(!DelegationStatus::Expired.is_actionable());
        assert!(!DelegationStatus::Revoked.is_actionable());
    }

    #[test]
    fn test_delegation_status_terminal() {
        assert!(!DelegationStatus::Active.is_terminal());
        assert!(!DelegationStatus::Pending.is_terminal());
        assert!(DelegationStatus::Expired.is_terminal());
        assert!(DelegationStatus::Revoked.is_terminal());
    }

    #[test]
    fn test_delegation_filter_with_status() {
        let filter = DelegationFilter {
            status: Some(DelegationStatus::Active),
            ..Default::default()
        };

        assert_eq!(filter.status, Some(DelegationStatus::Active));
    }
}
