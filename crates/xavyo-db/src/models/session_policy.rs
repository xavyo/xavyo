//! Tenant session policy model.
//!
//! Configures session behavior per tenant: timeouts, limits, and features.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Default values for session policy.
pub const DEFAULT_ACCESS_TOKEN_TTL_MINUTES: i32 = 15;
pub const DEFAULT_REFRESH_TOKEN_TTL_DAYS: i32 = 7;
pub const DEFAULT_IDLE_TIMEOUT_MINUTES: i32 = 30;
pub const DEFAULT_ABSOLUTE_TIMEOUT_HOURS: i32 = 24;
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: i32 = 0; // 0 = unlimited
pub const DEFAULT_REMEMBER_ME_TTL_DAYS: i32 = 30;

/// Tenant session policy configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantSessionPolicy {
    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Access token validity in minutes.
    pub access_token_ttl_minutes: i32,

    /// Refresh token validity in days.
    pub refresh_token_ttl_days: i32,

    /// Idle timeout in minutes (0 = disabled).
    pub idle_timeout_minutes: i32,

    /// Absolute session timeout in hours.
    pub absolute_timeout_hours: i32,

    /// Maximum concurrent sessions per user (0 = unlimited).
    pub max_concurrent_sessions: i32,

    /// Whether to track device information.
    pub track_device_info: bool,

    /// Extended session duration for "Remember Me" in days.
    pub remember_me_ttl_days: i32,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Default for TenantSessionPolicy {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            access_token_ttl_minutes: DEFAULT_ACCESS_TOKEN_TTL_MINUTES,
            refresh_token_ttl_days: DEFAULT_REFRESH_TOKEN_TTL_DAYS,
            idle_timeout_minutes: DEFAULT_IDLE_TIMEOUT_MINUTES,
            absolute_timeout_hours: DEFAULT_ABSOLUTE_TIMEOUT_HOURS,
            max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
            track_device_info: true,
            remember_me_ttl_days: DEFAULT_REMEMBER_ME_TTL_DAYS,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Data for creating or updating a session policy.
#[derive(Debug, Clone, Deserialize)]
pub struct UpsertSessionPolicy {
    pub access_token_ttl_minutes: Option<i32>,
    pub refresh_token_ttl_days: Option<i32>,
    pub idle_timeout_minutes: Option<i32>,
    pub absolute_timeout_hours: Option<i32>,
    pub max_concurrent_sessions: Option<i32>,
    pub track_device_info: Option<bool>,
    pub remember_me_ttl_days: Option<i32>,
}

impl TenantSessionPolicy {
    /// Get default policy for a tenant (doesn't persist).
    #[must_use] 
    pub fn default_for_tenant(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            ..Default::default()
        }
    }

    /// Find policy by tenant ID.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM tenant_session_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Get policy for tenant, returning defaults if none exists.
    pub async fn get_or_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        match Self::find_by_tenant(executor, tenant_id).await? {
            Some(policy) => Ok(policy),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create or update a session policy.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertSessionPolicy,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_session_policies (
                tenant_id,
                access_token_ttl_minutes,
                refresh_token_ttl_days,
                idle_timeout_minutes,
                absolute_timeout_hours,
                max_concurrent_sessions,
                track_device_info,
                remember_me_ttl_days
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id) DO UPDATE SET
                access_token_ttl_minutes = COALESCE($2, tenant_session_policies.access_token_ttl_minutes),
                refresh_token_ttl_days = COALESCE($3, tenant_session_policies.refresh_token_ttl_days),
                idle_timeout_minutes = COALESCE($4, tenant_session_policies.idle_timeout_minutes),
                absolute_timeout_hours = COALESCE($5, tenant_session_policies.absolute_timeout_hours),
                max_concurrent_sessions = COALESCE($6, tenant_session_policies.max_concurrent_sessions),
                track_device_info = COALESCE($7, tenant_session_policies.track_device_info),
                remember_me_ttl_days = COALESCE($8, tenant_session_policies.remember_me_ttl_days),
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.access_token_ttl_minutes.unwrap_or(DEFAULT_ACCESS_TOKEN_TTL_MINUTES))
        .bind(data.refresh_token_ttl_days.unwrap_or(DEFAULT_REFRESH_TOKEN_TTL_DAYS))
        .bind(data.idle_timeout_minutes.unwrap_or(DEFAULT_IDLE_TIMEOUT_MINUTES))
        .bind(data.absolute_timeout_hours.unwrap_or(DEFAULT_ABSOLUTE_TIMEOUT_HOURS))
        .bind(data.max_concurrent_sessions.unwrap_or(DEFAULT_MAX_CONCURRENT_SESSIONS))
        .bind(data.track_device_info.unwrap_or(true))
        .bind(data.remember_me_ttl_days.unwrap_or(DEFAULT_REMEMBER_ME_TTL_DAYS))
        .fetch_one(executor)
        .await
    }

    /// Delete a session policy.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM tenant_session_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Create default session policy for a newly provisioned tenant (F097).
    ///
    /// This is used during tenant provisioning to set up initial session policy.
    pub async fn create_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_session_policies (
                tenant_id,
                access_token_ttl_minutes,
                refresh_token_ttl_days,
                idle_timeout_minutes,
                absolute_timeout_hours,
                max_concurrent_sessions,
                track_device_info,
                remember_me_ttl_days
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(DEFAULT_ACCESS_TOKEN_TTL_MINUTES)
        .bind(DEFAULT_REFRESH_TOKEN_TTL_DAYS)
        .bind(DEFAULT_IDLE_TIMEOUT_MINUTES)
        .bind(DEFAULT_ABSOLUTE_TIMEOUT_HOURS)
        .bind(DEFAULT_MAX_CONCURRENT_SESSIONS)
        .bind(true)
        .bind(DEFAULT_REMEMBER_ME_TTL_DAYS)
        .fetch_one(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = TenantSessionPolicy::default();
        assert_eq!(policy.access_token_ttl_minutes, 15);
        assert_eq!(policy.refresh_token_ttl_days, 7);
        assert_eq!(policy.idle_timeout_minutes, 30);
        assert_eq!(policy.max_concurrent_sessions, 0);
        assert!(policy.track_device_info);
    }

    #[test]
    fn test_default_for_tenant() {
        let tenant_id = Uuid::new_v4();
        let policy = TenantSessionPolicy::default_for_tenant(tenant_id);
        assert_eq!(policy.tenant_id, tenant_id);
        assert_eq!(policy.access_token_ttl_minutes, 15);
    }
}
