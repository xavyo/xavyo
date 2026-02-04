//! Tenant usage tracking models.
//!
//! F-USAGE-TRACK: Track Monthly Active Users (MAU), API calls, and other usage metrics.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::DbError;

/// Usage metrics for a tenant per billing period.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantUsageMetrics {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this usage belongs to.
    pub tenant_id: Uuid,

    /// Start of the billing period (first day of month).
    pub period_start: NaiveDate,

    /// End of the billing period (last day of month).
    pub period_end: NaiveDate,

    /// Monthly Active Users count.
    pub mau_count: i32,

    /// Total API calls during the period.
    pub api_calls: i64,

    /// Authentication events (logins, token refreshes).
    pub auth_events: i64,

    /// AI agent API invocations.
    pub agent_invocations: i64,

    /// When this record was created.
    pub created_at: DateTime<Utc>,

    /// When this record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Active user tracking per billing period.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantActiveUser {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this record belongs to.
    pub tenant_id: Uuid,

    /// User who was active.
    pub user_id: Uuid,

    /// Start of the billing period.
    pub period_start: NaiveDate,

    /// Last activity timestamp.
    pub last_active_at: DateTime<Utc>,
}

impl TenantUsageMetrics {
    /// Calculate the period start for a given date (first day of month).
    #[must_use] 
    pub fn period_start_for(date: NaiveDate) -> NaiveDate {
        NaiveDate::from_ymd_opt(date.year(), date.month(), 1).unwrap()
    }

    /// Calculate the period end for a given date (last day of month).
    #[must_use] 
    pub fn period_end_for(date: NaiveDate) -> NaiveDate {
        let next_month = if date.month() == 12 {
            NaiveDate::from_ymd_opt(date.year() + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(date.year(), date.month() + 1, 1).unwrap()
        };
        next_month.pred_opt().unwrap()
    }

    /// Get or create the usage metrics for the current billing period.
    pub async fn get_or_create_current(pool: &PgPool, tenant_id: Uuid) -> Result<Self, DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);
        let period_end = Self::period_end_for(today);

        // Try to insert, on conflict return existing
        let result = sqlx::query_as::<_, Self>(
            r"
            INSERT INTO tenant_usage_metrics (tenant_id, period_start, period_end)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, period_start) DO UPDATE SET updated_at = NOW()
            RETURNING id, tenant_id, period_start, period_end, mau_count, api_calls, auth_events, agent_invocations, created_at, updated_at
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result)
    }

    /// Get usage metrics for the current billing period.
    pub async fn get_current(pool: &PgPool, tenant_id: Uuid) -> Result<Option<Self>, DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);

        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, period_start, period_end, mau_count, api_calls, auth_events, agent_invocations, created_at, updated_at
            FROM tenant_usage_metrics
            WHERE tenant_id = $1 AND period_start = $2
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Get historical usage metrics for a tenant.
    pub async fn get_history(
        pool: &PgPool,
        tenant_id: Uuid,
        periods: usize,
    ) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, period_start, period_end, mau_count, api_calls, auth_events, agent_invocations, created_at, updated_at
            FROM tenant_usage_metrics
            WHERE tenant_id = $1
            ORDER BY period_start DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(periods as i64)
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Increment API calls counter.
    pub async fn increment_api_calls(
        pool: &PgPool,
        tenant_id: Uuid,
        count: i64,
    ) -> Result<(), DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);
        let period_end = Self::period_end_for(today);

        sqlx::query(
            r"
            INSERT INTO tenant_usage_metrics (tenant_id, period_start, period_end, api_calls)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, period_start) DO UPDATE
            SET api_calls = tenant_usage_metrics.api_calls + $4,
                updated_at = NOW()
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .bind(count)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(())
    }

    /// Increment auth events counter.
    pub async fn increment_auth_events(
        pool: &PgPool,
        tenant_id: Uuid,
        count: i64,
    ) -> Result<(), DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);
        let period_end = Self::period_end_for(today);

        sqlx::query(
            r"
            INSERT INTO tenant_usage_metrics (tenant_id, period_start, period_end, auth_events)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, period_start) DO UPDATE
            SET auth_events = tenant_usage_metrics.auth_events + $4,
                updated_at = NOW()
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .bind(count)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(())
    }

    /// Increment agent invocations counter.
    pub async fn increment_agent_invocations(
        pool: &PgPool,
        tenant_id: Uuid,
        count: i64,
    ) -> Result<(), DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);
        let period_end = Self::period_end_for(today);

        sqlx::query(
            r"
            INSERT INTO tenant_usage_metrics (tenant_id, period_start, period_end, agent_invocations)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, period_start) DO UPDATE
            SET agent_invocations = tenant_usage_metrics.agent_invocations + $4,
                updated_at = NOW()
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .bind(count)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(())
    }

    /// Update MAU count based on active users.
    pub async fn update_mau_count(pool: &PgPool, tenant_id: Uuid) -> Result<i32, DbError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);
        let period_end = Self::period_end_for(today);

        // Count unique users and update the metrics
        let result = sqlx::query_scalar::<_, i64>(
            r"
            WITH mau AS (
                SELECT COUNT(DISTINCT user_id)::INTEGER as count
                FROM tenant_active_users
                WHERE tenant_id = $1 AND period_start = $2
            )
            INSERT INTO tenant_usage_metrics (tenant_id, period_start, period_end, mau_count)
            SELECT $1, $2, $3, COALESCE((SELECT count FROM mau), 0)
            ON CONFLICT (tenant_id, period_start) DO UPDATE
            SET mau_count = COALESCE((SELECT count FROM mau), 0),
                updated_at = NOW()
            RETURNING mau_count::BIGINT
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result as i32)
    }
}

impl TenantActiveUser {
    /// Record a user as active in the current billing period.
    pub async fn record_active(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), DbError> {
        let today = Utc::now().date_naive();
        let period_start = TenantUsageMetrics::period_start_for(today);

        sqlx::query(
            r"
            INSERT INTO tenant_active_users (tenant_id, user_id, period_start, last_active_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (tenant_id, user_id, period_start) DO UPDATE
            SET last_active_at = NOW()
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(period_start)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(())
    }

    /// Get active user count for current period.
    pub async fn count_current_period(pool: &PgPool, tenant_id: Uuid) -> Result<i64, DbError> {
        let today = Utc::now().date_naive();
        let period_start = TenantUsageMetrics::period_start_for(today);

        sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(DISTINCT user_id)
            FROM tenant_active_users
            WHERE tenant_id = $1 AND period_start = $2
            ",
        )
        .bind(tenant_id)
        .bind(period_start)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_period_start_calculation() {
        let date = NaiveDate::from_ymd_opt(2024, 3, 15).unwrap();
        let period_start = TenantUsageMetrics::period_start_for(date);
        assert_eq!(period_start, NaiveDate::from_ymd_opt(2024, 3, 1).unwrap());
    }

    #[test]
    fn test_period_end_calculation() {
        let date = NaiveDate::from_ymd_opt(2024, 3, 15).unwrap();
        let period_end = TenantUsageMetrics::period_end_for(date);
        assert_eq!(period_end, NaiveDate::from_ymd_opt(2024, 3, 31).unwrap());
    }

    #[test]
    fn test_period_end_february_leap_year() {
        let date = NaiveDate::from_ymd_opt(2024, 2, 10).unwrap();
        let period_end = TenantUsageMetrics::period_end_for(date);
        assert_eq!(period_end, NaiveDate::from_ymd_opt(2024, 2, 29).unwrap());
    }

    #[test]
    fn test_period_end_december() {
        let date = NaiveDate::from_ymd_opt(2024, 12, 15).unwrap();
        let period_end = TenantUsageMetrics::period_end_for(date);
        assert_eq!(period_end, NaiveDate::from_ymd_opt(2024, 12, 31).unwrap());
    }

    #[test]
    fn test_period_start_january() {
        let date = NaiveDate::from_ymd_opt(2024, 1, 31).unwrap();
        let period_start = TenantUsageMetrics::period_start_for(date);
        assert_eq!(period_start, NaiveDate::from_ymd_opt(2024, 1, 1).unwrap());
    }
}
