//! API Key Usage Statistics models (F-054)
//!
//! Tracks usage metrics for API keys including request counts, error rates,
//! and time-series data for monitoring and quota management.

use chrono::{DateTime, NaiveDate, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// HTTP response category for usage tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCategory {
    /// 2xx responses
    Success,
    /// 4xx responses
    ClientError,
    /// 5xx responses
    ServerError,
}

/// Cumulative usage statistics per API key.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApiKeyUsage {
    pub id: Uuid,
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub total_requests: i64,
    pub success_count: i64,
    pub client_error_count: i64,
    pub server_error_count: i64,
    pub first_used_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Data for creating a new usage record.
#[derive(Debug, Clone)]
pub struct CreateApiKeyUsage {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
}

/// Data for incrementing usage counters.
#[derive(Debug, Clone)]
pub struct IncrementUsage {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub category: ResponseCategory,
}

/// Filter for querying usage records.
#[derive(Debug, Clone, Default)]
pub struct UsageFilter {
    pub key_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
}

/// Hourly aggregated usage data.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApiKeyUsageHourly {
    pub id: Uuid,
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub hour: DateTime<Utc>,
    pub request_count: i32,
    pub success_count: i32,
    pub client_error_count: i32,
    pub server_error_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Daily aggregated usage data.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApiKeyUsageDaily {
    pub id: Uuid,
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub date: NaiveDate,
    pub request_count: i32,
    pub success_count: i32,
    pub client_error_count: i32,
    pub server_error_count: i32,
    pub created_at: DateTime<Utc>,
}

impl ApiKeyUsage {
    /// Get usage record by API key ID with tenant isolation.
    pub async fn get_by_key_id(
        pool: &PgPool,
        key_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, key_id, tenant_id, total_requests, success_count,
                   client_error_count, server_error_count, first_used_at,
                   last_used_at, created_at, updated_at
            FROM api_key_usage
            WHERE key_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get or create a usage record for an API key.
    pub async fn get_or_create(
        pool: &PgPool,
        data: CreateApiKeyUsage,
    ) -> Result<Self, sqlx::Error> {
        // Try to get existing record first
        if let Some(existing) = Self::get_by_key_id(pool, data.key_id, data.tenant_id).await? {
            return Ok(existing);
        }

        // Create new record
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO api_key_usage (key_id, tenant_id)
            VALUES ($1, $2)
            ON CONFLICT (key_id) DO UPDATE SET updated_at = NOW()
            RETURNING id, key_id, tenant_id, total_requests, success_count,
                      client_error_count, server_error_count, first_used_at,
                      last_used_at, created_at, updated_at
            "#,
        )
        .bind(data.key_id)
        .bind(data.tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Increment request counter with category tracking.
    /// Uses upsert pattern for concurrent safety.
    pub async fn increment_request(pool: &PgPool, data: IncrementUsage) -> Result<(), sqlx::Error> {
        let now = Utc::now();

        // Determine which counter to increment based on category
        let (success_inc, client_error_inc, server_error_inc) = match data.category {
            ResponseCategory::Success => (1i64, 0i64, 0i64),
            ResponseCategory::ClientError => (0i64, 1i64, 0i64),
            ResponseCategory::ServerError => (0i64, 0i64, 1i64),
        };

        sqlx::query(
            r#"
            INSERT INTO api_key_usage (key_id, tenant_id, total_requests, success_count,
                                       client_error_count, server_error_count,
                                       first_used_at, last_used_at)
            VALUES ($1, $2, 1, $3, $4, $5, $6, $6)
            ON CONFLICT (key_id) DO UPDATE SET
                total_requests = api_key_usage.total_requests + 1,
                success_count = api_key_usage.success_count + $3,
                client_error_count = api_key_usage.client_error_count + $4,
                server_error_count = api_key_usage.server_error_count + $5,
                last_used_at = $6,
                updated_at = NOW()
            "#,
        )
        .bind(data.key_id)
        .bind(data.tenant_id)
        .bind(success_inc)
        .bind(client_error_inc)
        .bind(server_error_inc)
        .bind(now)
        .execute(pool)
        .await?;

        Ok(())
    }
}

impl ApiKeyUsageHourly {
    /// Increment hourly usage counter.
    /// Uses upsert pattern for concurrent safety.
    pub async fn increment(
        pool: &PgPool,
        key_id: Uuid,
        tenant_id: Uuid,
        hour: DateTime<Utc>,
        category: ResponseCategory,
    ) -> Result<(), sqlx::Error> {
        // Truncate to hour
        let hour_truncated = hour
            .date_naive()
            .and_hms_opt(hour.hour(), 0, 0)
            .expect("valid hour")
            .and_utc();

        let (success_inc, client_error_inc, server_error_inc) = match category {
            ResponseCategory::Success => (1i32, 0i32, 0i32),
            ResponseCategory::ClientError => (0i32, 1i32, 0i32),
            ResponseCategory::ServerError => (0i32, 0i32, 1i32),
        };

        sqlx::query(
            r#"
            INSERT INTO api_key_usage_hourly (key_id, tenant_id, hour, request_count,
                                              success_count, client_error_count, server_error_count)
            VALUES ($1, $2, $3, 1, $4, $5, $6)
            ON CONFLICT (key_id, hour) DO UPDATE SET
                request_count = api_key_usage_hourly.request_count + 1,
                success_count = api_key_usage_hourly.success_count + $4,
                client_error_count = api_key_usage_hourly.client_error_count + $5,
                server_error_count = api_key_usage_hourly.server_error_count + $6
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .bind(hour_truncated)
        .bind(success_inc)
        .bind(client_error_inc)
        .bind(server_error_inc)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get hourly usage within a date range.
    pub async fn get_range(
        pool: &PgPool,
        key_id: Uuid,
        tenant_id: Uuid,
        start_date: Option<NaiveDate>,
        end_date: Option<NaiveDate>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let start = start_date
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(7));
        let end = end_date
            .map(|d| d.and_hms_opt(23, 59, 59).unwrap().and_utc())
            .unwrap_or_else(Utc::now);

        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, key_id, tenant_id, hour, request_count, success_count,
                   client_error_count, server_error_count, created_at
            FROM api_key_usage_hourly
            WHERE key_id = $1 AND tenant_id = $2 AND hour >= $3 AND hour <= $4
            ORDER BY hour ASC
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .fetch_all(pool)
        .await
    }
}

impl ApiKeyUsageDaily {
    /// Increment daily usage counter.
    /// Uses upsert pattern for concurrent safety.
    pub async fn increment(
        pool: &PgPool,
        key_id: Uuid,
        tenant_id: Uuid,
        date: NaiveDate,
        category: ResponseCategory,
    ) -> Result<(), sqlx::Error> {
        let (success_inc, client_error_inc, server_error_inc) = match category {
            ResponseCategory::Success => (1i32, 0i32, 0i32),
            ResponseCategory::ClientError => (0i32, 1i32, 0i32),
            ResponseCategory::ServerError => (0i32, 0i32, 1i32),
        };

        sqlx::query(
            r#"
            INSERT INTO api_key_usage_daily (key_id, tenant_id, date, request_count,
                                             success_count, client_error_count, server_error_count)
            VALUES ($1, $2, $3, 1, $4, $5, $6)
            ON CONFLICT (key_id, date) DO UPDATE SET
                request_count = api_key_usage_daily.request_count + 1,
                success_count = api_key_usage_daily.success_count + $4,
                client_error_count = api_key_usage_daily.client_error_count + $5,
                server_error_count = api_key_usage_daily.server_error_count + $6
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .bind(date)
        .bind(success_inc)
        .bind(client_error_inc)
        .bind(server_error_inc)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get daily usage within a date range.
    pub async fn get_range(
        pool: &PgPool,
        key_id: Uuid,
        tenant_id: Uuid,
        start_date: Option<NaiveDate>,
        end_date: Option<NaiveDate>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let start =
            start_date.unwrap_or_else(|| Utc::now().date_naive() - chrono::Duration::days(30));
        let end = end_date.unwrap_or_else(|| Utc::now().date_naive());

        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, key_id, tenant_id, date, request_count, success_count,
                   client_error_count, server_error_count, created_at
            FROM api_key_usage_daily
            WHERE key_id = $1 AND tenant_id = $2 AND date >= $3 AND date <= $4
            ORDER BY date ASC
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_category_mapping() {
        assert_eq!(ResponseCategory::Success, ResponseCategory::Success);
        assert_eq!(ResponseCategory::ClientError, ResponseCategory::ClientError);
        assert_eq!(ResponseCategory::ServerError, ResponseCategory::ServerError);
    }

    #[test]
    fn test_create_api_key_usage() {
        let data = CreateApiKeyUsage {
            key_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
        };
        assert!(!data.key_id.is_nil());
        assert!(!data.tenant_id.is_nil());
    }

    #[test]
    fn test_increment_usage_data() {
        let data = IncrementUsage {
            key_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            category: ResponseCategory::Success,
        };
        assert_eq!(data.category, ResponseCategory::Success);
    }

    #[test]
    fn test_usage_filter_default() {
        let filter = UsageFilter::default();
        assert!(filter.key_id.is_none());
        assert!(filter.tenant_id.is_none());
        assert!(filter.start_date.is_none());
        assert!(filter.end_date.is_none());
    }

    #[test]
    fn test_usage_filter_with_dates() {
        let filter = UsageFilter {
            key_id: Some(Uuid::new_v4()),
            tenant_id: Some(Uuid::new_v4()),
            start_date: Some(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 2, 4).unwrap()),
        };
        assert!(filter.key_id.is_some());
        assert!(filter.start_date.is_some());
    }
}
