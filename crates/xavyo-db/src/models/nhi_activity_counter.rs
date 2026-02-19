//! NHI activity counter model.
//!
//! Tracks call counts for NHI identities in hourly/daily windows.
//! Populated by the ext-authz `ActivityTracker` flush loop.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A single activity counter row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiActivityCounter {
    pub tenant_id: Uuid,
    pub nhi_id: Uuid,
    pub window_start: DateTime<Utc>,
    pub window_type: String,
    pub call_count: i32,
}

/// Summary of activity for an NHI identity.
#[derive(Debug, FromRow, Serialize)]
pub struct NhiActivitySummary {
    pub nhi_id: Uuid,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub total_calls_24h: i64,
    pub total_calls_7d: i64,
}

impl NhiActivityCounter {
    /// Increment the counter for a given NHI identity in the current hourly window.
    ///
    /// Uses INSERT ... ON CONFLICT to atomically upsert.
    pub async fn increment_hourly(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            INSERT INTO nhi_activity_counters (tenant_id, nhi_id, window_start, window_type, call_count)
            VALUES ($1, $2, date_trunc('hour', NOW()), 'hourly', 1)
            ON CONFLICT (tenant_id, nhi_id, window_start, window_type)
            DO UPDATE SET call_count = nhi_activity_counters.call_count + 1
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Get activity summary in a single query (last_activity_at + 24h + 7d counts).
    ///
    /// Returns `None` if the NHI identity does not exist.
    pub async fn get_summary(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<NhiActivitySummary>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT
                $2::uuid AS nhi_id,
                i.last_activity_at,
                COALESCE((
                    SELECT SUM(c.call_count::bigint)
                    FROM nhi_activity_counters c
                    WHERE c.tenant_id = $1 AND c.nhi_id = $2
                      AND c.window_start >= NOW() - INTERVAL '24 hours'
                ), 0) AS total_calls_24h,
                COALESCE((
                    SELECT SUM(c.call_count::bigint)
                    FROM nhi_activity_counters c
                    WHERE c.tenant_id = $1 AND c.nhi_id = $2
                      AND c.window_start >= NOW() - INTERVAL '7 days'
                ), 0) AS total_calls_7d
            FROM nhi_identities i
            WHERE i.tenant_id = $1 AND i.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete old counter rows (older than `retention_days`).
    ///
    /// Called by a background cleanup job. Operates across all tenants
    /// intentionally (background maintenance, not user-facing).
    pub async fn cleanup_old(pool: &PgPool, retention_days: i32) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_activity_counters
            WHERE window_start < NOW() - make_interval(days => $1)
            ",
        )
        .bind(retention_days)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}
