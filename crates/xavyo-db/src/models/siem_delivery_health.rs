//! SIEM Delivery Health model (F078).
//!
//! Aggregates delivery metrics per destination per time window.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A delivery health aggregation window for a destination.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiemDeliveryHealth {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub destination_id: Uuid,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub events_sent: i64,
    pub events_delivered: i64,
    pub events_failed: i64,
    pub events_dropped: i64,
    pub avg_latency_ms: Option<i32>,
    pub p95_latency_ms: Option<i32>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Aggregated health summary across all windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub destination_id: Uuid,
    pub total_events_sent: i64,
    pub total_events_delivered: i64,
    pub total_events_failed: i64,
    pub total_events_dropped: i64,
    pub avg_latency_ms: Option<i32>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub success_rate_percent: f64,
}

impl SiemDeliveryHealth {
    /// Upsert a delivery health window (insert or update existing window).
    /// Uses ON CONFLICT to atomically increment counters.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_window(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        sent: i64,
        delivered: i64,
        failed: i64,
        dropped: i64,
        latency_ms: Option<i32>,
        success_at: Option<DateTime<Utc>>,
        failure_at: Option<DateTime<Utc>>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO siem_delivery_health (
                tenant_id, destination_id, window_start, window_end,
                events_sent, events_delivered, events_failed, events_dropped,
                avg_latency_ms, last_success_at, last_failure_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (tenant_id, destination_id, window_start)
            DO UPDATE SET
                events_sent = siem_delivery_health.events_sent + EXCLUDED.events_sent,
                events_delivered = siem_delivery_health.events_delivered + EXCLUDED.events_delivered,
                events_failed = siem_delivery_health.events_failed + EXCLUDED.events_failed,
                events_dropped = siem_delivery_health.events_dropped + EXCLUDED.events_dropped,
                avg_latency_ms = COALESCE(EXCLUDED.avg_latency_ms, siem_delivery_health.avg_latency_ms),
                last_success_at = GREATEST(siem_delivery_health.last_success_at, EXCLUDED.last_success_at),
                last_failure_at = GREATEST(siem_delivery_health.last_failure_at, EXCLUDED.last_failure_at)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(window_start)
        .bind(window_end)
        .bind(sent)
        .bind(delivered)
        .bind(failed)
        .bind(dropped)
        .bind(latency_ms)
        .bind(success_at)
        .bind(failure_at)
        .fetch_one(pool)
        .await
    }

    /// Get aggregated health summary for a destination (last 24 hours).
    pub async fn get_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
    ) -> Result<Option<HealthSummary>, sqlx::Error> {
        let row = sqlx::query_as::<
            _,
            (
                i64,
                i64,
                i64,
                i64,
                Option<i32>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
            ),
        >(
            r#"
            SELECT
                COALESCE(SUM(events_sent), 0) as total_sent,
                COALESCE(SUM(events_delivered), 0) as total_delivered,
                COALESCE(SUM(events_failed), 0) as total_failed,
                COALESCE(SUM(events_dropped), 0) as total_dropped,
                AVG(avg_latency_ms)::INTEGER as avg_latency,
                MAX(last_success_at) as last_success,
                MAX(last_failure_at) as last_failure
            FROM siem_delivery_health
            WHERE tenant_id = $1 AND destination_id = $2
              AND window_start >= NOW() - INTERVAL '24 hours'
            "#,
        )
        .bind(tenant_id)
        .bind(destination_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(
            |(sent, delivered, failed, dropped, avg_latency, last_success, last_failure)| {
                let total = sent.max(1); // prevent division by zero
                let success_rate = (delivered as f64 / total as f64) * 100.0;
                HealthSummary {
                    destination_id,
                    total_events_sent: sent,
                    total_events_delivered: delivered,
                    total_events_failed: failed,
                    total_events_dropped: dropped,
                    avg_latency_ms: avg_latency,
                    last_success_at: last_success,
                    last_failure_at: last_failure,
                    success_rate_percent: success_rate,
                }
            },
        ))
    }

    /// List health windows for a destination over a time range.
    pub async fn list_history(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM siem_delivery_health
            WHERE tenant_id = $1 AND destination_id = $2
              AND window_start >= $3 AND window_end <= $4
            ORDER BY window_start DESC
            LIMIT $5 OFFSET $6
            "#,
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(from)
        .bind(to)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count health windows for a destination.
    pub async fn count_history(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM siem_delivery_health
            WHERE tenant_id = $1 AND destination_id = $2
              AND window_start >= $3 AND window_end <= $4
            "#,
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(from)
        .bind(to)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_summary_success_rate() {
        let summary = HealthSummary {
            destination_id: Uuid::new_v4(),
            total_events_sent: 100,
            total_events_delivered: 95,
            total_events_failed: 3,
            total_events_dropped: 2,
            avg_latency_ms: Some(45),
            last_success_at: Some(Utc::now()),
            last_failure_at: Some(Utc::now()),
            success_rate_percent: 95.0,
        };

        assert_eq!(summary.total_events_sent, 100);
        assert_eq!(summary.total_events_delivered, 95);
        assert!((summary.success_rate_percent - 95.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_health_summary_zero_events() {
        let summary = HealthSummary {
            destination_id: Uuid::new_v4(),
            total_events_sent: 0,
            total_events_delivered: 0,
            total_events_failed: 0,
            total_events_dropped: 0,
            avg_latency_ms: None,
            last_success_at: None,
            last_failure_at: None,
            success_rate_percent: 0.0,
        };

        assert_eq!(summary.total_events_sent, 0);
        assert!(summary.avg_latency_ms.is_none());
    }
}
