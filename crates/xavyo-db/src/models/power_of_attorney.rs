//! Power of Attorney model.
//!
//! Represents a grant of identity assumption authority from a donor to an attorney.
//! Part of F-061 Power of Attorney / Identity Assumption feature.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Power of Attorney lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "poa_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PoaStatus {
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

impl PoaStatus {
    /// Check if the PoA is in a state that can be used for identity assumption.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the PoA is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Expired | Self::Revoked)
    }
}

/// Maximum allowed duration for a Power of Attorney grant (90 days).
pub const POA_MAX_DURATION_DAYS: i64 = 90;

/// A Power of Attorney grant enabling identity assumption.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PowerOfAttorney {
    /// Unique identifier for the PoA grant.
    pub id: Uuid,

    /// The tenant this PoA belongs to.
    pub tenant_id: Uuid,

    /// The user granting PoA (the user being represented).
    pub donor_id: Uuid,

    /// The user receiving PoA (the user who can act on behalf).
    pub attorney_id: Uuid,

    /// Optional scope restrictions (reuses GovDelegationScope).
    pub scope_id: Option<Uuid>,

    /// When the PoA becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the PoA expires.
    pub ends_at: DateTime<Utc>,

    /// Lifecycle status.
    pub status: PoaStatus,

    /// When the PoA was created.
    pub created_at: DateTime<Utc>,

    /// When the PoA was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Who revoked the PoA (if applicable).
    pub revoked_by: Option<Uuid>,

    /// Optional reason for grant/revoke.
    pub reason: Option<String>,
}

/// Request to create a new Power of Attorney grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreatePowerOfAttorney {
    /// The user receiving PoA authority.
    pub attorney_id: Uuid,
    /// When the PoA becomes active.
    pub starts_at: DateTime<Utc>,
    /// When the PoA expires.
    pub ends_at: DateTime<Utc>,
    /// Optional scope ID for restricted PoA.
    pub scope_id: Option<Uuid>,
    /// Optional reason for granting.
    pub reason: Option<String>,
}

/// Filter options for listing Power of Attorney grants.
#[derive(Debug, Clone, Default)]
pub struct PoaFilter {
    /// Filter by donor (user who granted).
    pub donor_id: Option<Uuid>,
    /// Filter by attorney (user who received).
    pub attorney_id: Option<Uuid>,
    /// Filter by status.
    pub status: Option<PoaStatus>,
    /// Filter by multiple statuses.
    pub statuses: Option<Vec<PoaStatus>>,
    /// Filter to only include currently active (time-wise).
    pub active_now: Option<bool>,
}

impl PowerOfAttorney {
    /// Find a PoA by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM power_of_attorneys
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find active PoA from a donor at a specific time.
    pub async fn find_active_for_donor(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        donor_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM power_of_attorneys
            WHERE tenant_id = $1
              AND donor_id = $2
              AND status = 'active'
              AND starts_at <= $3
              AND ends_at > $3
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(donor_id)
        .bind(at_time)
        .fetch_all(pool)
        .await
    }

    /// Find active PoA grants where a user is the attorney at a specific time.
    pub async fn find_active_for_attorney(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        attorney_id: Uuid,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM power_of_attorneys
            WHERE tenant_id = $1
              AND attorney_id = $2
              AND status = 'active'
              AND starts_at <= $3
              AND ends_at > $3
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(attorney_id)
        .bind(at_time)
        .fetch_all(pool)
        .await
    }

    /// List PoA grants for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PoaFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let now = Utc::now();
        let mut query = String::from(
            r"
            SELECT * FROM power_of_attorneys
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.donor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND donor_id = ${param_count}"));
        }
        if filter.attorney_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attorney_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.active_now == Some(true) {
            param_count += 1;
            query.push_str(&format!(
                " AND status = 'active' AND starts_at <= ${param_count} AND ends_at > ${param_count}"
            ));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, PowerOfAttorney>(&query).bind(tenant_id);

        if let Some(donor_id) = filter.donor_id {
            q = q.bind(donor_id);
        }
        if let Some(attorney_id) = filter.attorney_id {
            q = q.bind(attorney_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if filter.active_now == Some(true) {
            q = q.bind(now);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count PoA grants in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PoaFilter,
    ) -> Result<i64, sqlx::Error> {
        let now = Utc::now();
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM power_of_attorneys
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.donor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND donor_id = ${param_count}"));
        }
        if filter.attorney_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attorney_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.active_now == Some(true) {
            param_count += 1;
            query.push_str(&format!(
                " AND status = 'active' AND starts_at <= ${param_count} AND ends_at > ${param_count}"
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(donor_id) = filter.donor_id {
            q = q.bind(donor_id);
        }
        if let Some(attorney_id) = filter.attorney_id {
            q = q.bind(attorney_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if filter.active_now == Some(true) {
            q = q.bind(now);
        }

        q.fetch_one(pool).await
    }

    /// Create a new Power of Attorney grant.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        donor_id: Uuid,
        input: CreatePowerOfAttorney,
    ) -> Result<Self, sqlx::Error> {
        // Determine initial status: active if starts_at is now or past, pending otherwise
        let now = Utc::now();
        let initial_status = if input.starts_at <= now {
            PoaStatus::Active
        } else {
            PoaStatus::Pending
        };

        sqlx::query_as(
            r"
            INSERT INTO power_of_attorneys (
                tenant_id, donor_id, attorney_id, scope_id, starts_at, ends_at, status, reason
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(donor_id)
        .bind(input.attorney_id)
        .bind(input.scope_id)
        .bind(input.starts_at)
        .bind(input.ends_at)
        .bind(initial_status)
        .bind(input.reason)
        .fetch_one(pool)
        .await
    }

    /// Revoke a PoA grant.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        revoked_by: Uuid,
        reason: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE power_of_attorneys
            SET status = 'revoked', revoked_at = NOW(), revoked_by = $3, reason = COALESCE($4, reason)
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'active')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(revoked_by)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Activate a pending PoA (when starts_at is reached).
    pub async fn activate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE power_of_attorneys
            SET status = 'active'
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Expire a PoA (when ends_at is reached).
    pub async fn expire(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE power_of_attorneys
            SET status = 'expired'
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Extend the end date of an active or pending PoA.
    pub async fn extend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_ends_at: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE power_of_attorneys
            SET ends_at = $3
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'active')
              AND $3 - starts_at <= INTERVAL '90 days'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_ends_at)
        .fetch_optional(pool)
        .await
    }

    /// Find PoA grants pending activation.
    pub async fn find_pending_activation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM power_of_attorneys
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

    /// Find PoA grants that have expired.
    pub async fn find_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM power_of_attorneys
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

    /// Check if this PoA is currently active (time-wise and status).
    #[must_use]
    pub fn is_currently_active(&self, now: DateTime<Utc>) -> bool {
        self.status == PoaStatus::Active && self.starts_at <= now && self.ends_at > now
    }

    /// Validate the duration is within limits.
    #[must_use]
    pub fn validate_duration(starts_at: DateTime<Utc>, ends_at: DateTime<Utc>) -> bool {
        let duration = ends_at - starts_at;
        duration > Duration::zero() && duration <= Duration::days(POA_MAX_DURATION_DAYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_poa(now: DateTime<Utc>, status: PoaStatus) -> PowerOfAttorney {
        PowerOfAttorney {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            donor_id: Uuid::new_v4(),
            attorney_id: Uuid::new_v4(),
            scope_id: None,
            starts_at: now - Duration::hours(1),
            ends_at: now + Duration::hours(1),
            status,
            created_at: now - Duration::hours(1),
            revoked_at: None,
            revoked_by: None,
            reason: None,
        }
    }

    #[test]
    fn test_poa_status_actionable() {
        assert!(PoaStatus::Active.is_actionable());
        assert!(!PoaStatus::Pending.is_actionable());
        assert!(!PoaStatus::Expired.is_actionable());
        assert!(!PoaStatus::Revoked.is_actionable());
    }

    #[test]
    fn test_poa_status_terminal() {
        assert!(!PoaStatus::Active.is_terminal());
        assert!(!PoaStatus::Pending.is_terminal());
        assert!(PoaStatus::Expired.is_terminal());
        assert!(PoaStatus::Revoked.is_terminal());
    }

    #[test]
    fn test_is_currently_active() {
        let now = Utc::now();
        let poa = make_test_poa(now, PoaStatus::Active);
        assert!(poa.is_currently_active(now));
    }

    #[test]
    fn test_is_not_active_when_revoked() {
        let now = Utc::now();
        let poa = make_test_poa(now, PoaStatus::Revoked);
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_is_not_active_when_expired_by_time() {
        let now = Utc::now();
        let mut poa = make_test_poa(now, PoaStatus::Active);
        poa.starts_at = now - Duration::hours(2);
        poa.ends_at = now - Duration::hours(1);
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_validate_duration_valid() {
        let now = Utc::now();
        assert!(PowerOfAttorney::validate_duration(
            now,
            now + Duration::days(30)
        ));
        assert!(PowerOfAttorney::validate_duration(
            now,
            now + Duration::days(90)
        ));
    }

    #[test]
    fn test_validate_duration_too_long() {
        let now = Utc::now();
        assert!(!PowerOfAttorney::validate_duration(
            now,
            now + Duration::days(91)
        ));
    }

    #[test]
    fn test_validate_duration_negative() {
        let now = Utc::now();
        assert!(!PowerOfAttorney::validate_duration(
            now,
            now - Duration::days(1)
        ));
    }

    #[test]
    fn test_create_poa_request() {
        let now = Utc::now();
        let request = CreatePowerOfAttorney {
            attorney_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(14),
            scope_id: None,
            reason: Some("Vacation coverage".to_string()),
        };

        assert!(PowerOfAttorney::validate_duration(
            request.starts_at,
            request.ends_at
        ));
    }

    #[test]
    fn test_poa_filter_default() {
        let filter = PoaFilter::default();
        assert!(filter.donor_id.is_none());
        assert!(filter.attorney_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.active_now.is_none());
    }
}
