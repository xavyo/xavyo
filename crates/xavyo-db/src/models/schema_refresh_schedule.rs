//! Schema Refresh Schedule model.
//!
//! Represents automatic refresh configuration for schema discovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of schedule (interval-based or cron-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ScheduleType {
    /// Simple interval in hours.
    #[default]
    Interval,
    /// Cron expression.
    Cron,
}

impl ScheduleType {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ScheduleType::Interval => "interval",
            ScheduleType::Cron => "cron",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "interval" => Some(ScheduleType::Interval),
            "cron" => Some(ScheduleType::Cron),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScheduleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A schema refresh schedule configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SchemaRefreshSchedule {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this schedule belongs to.
    pub tenant_id: Uuid,

    /// Connector this schedule applies to.
    pub connector_id: Uuid,

    /// Whether the schedule is enabled.
    pub enabled: bool,

    /// Type of schedule (interval or cron).
    pub schedule_type: String,

    /// Hours between refreshes (if interval type).
    pub interval_hours: Option<i32>,

    /// Cron expression (if cron type).
    pub cron_expression: Option<String>,

    /// When the schedule last ran.
    pub last_run_at: Option<DateTime<Utc>>,

    /// When the next run is scheduled.
    pub next_run_at: Option<DateTime<Utc>>,

    /// Last error message if failed.
    pub last_error: Option<String>,

    /// Whether to notify on schema changes.
    pub notify_on_changes: bool,

    /// Email to notify on changes.
    pub notify_email: Option<String>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating/updating a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSchedule {
    /// Whether enabled.
    pub enabled: bool,
    /// Schedule type.
    pub schedule_type: ScheduleType,
    /// Interval hours (if interval type).
    pub interval_hours: Option<i32>,
    /// Cron expression (if cron type).
    pub cron_expression: Option<String>,
    /// Whether to notify on changes.
    pub notify_on_changes: bool,
    /// Notification email.
    pub notify_email: Option<String>,
}

impl SchemaRefreshSchedule {
    /// Find schedule for a connector.
    pub async fn find_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM schema_refresh_schedules
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find schedules that are due to run.
    pub async fn find_due_schedules(
        pool: &sqlx::PgPool,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM schema_refresh_schedules
            WHERE enabled = true
              AND next_run_at IS NOT NULL
              AND next_run_at <= NOW()
            ORDER BY next_run_at ASC
            LIMIT $1
            ",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Create or update a schedule.
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &UpsertSchedule,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO schema_refresh_schedules (
                tenant_id, connector_id, enabled, schedule_type,
                interval_hours, cron_expression, next_run_at,
                notify_on_changes, notify_email
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (connector_id)
            DO UPDATE SET
                enabled = EXCLUDED.enabled,
                schedule_type = EXCLUDED.schedule_type,
                interval_hours = EXCLUDED.interval_hours,
                cron_expression = EXCLUDED.cron_expression,
                next_run_at = EXCLUDED.next_run_at,
                notify_on_changes = EXCLUDED.notify_on_changes,
                notify_email = EXCLUDED.notify_email,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(input.enabled)
        .bind(input.schedule_type.as_str())
        .bind(input.interval_hours)
        .bind(&input.cron_expression)
        .bind(next_run_at)
        .bind(input.notify_on_changes)
        .bind(&input.notify_email)
        .fetch_one(pool)
        .await
    }

    /// Update after a run.
    pub async fn update_after_run(
        pool: &sqlx::PgPool,
        id: Uuid,
        next_run_at: Option<DateTime<Utc>>,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE schema_refresh_schedules
            SET last_run_at = NOW(),
                next_run_at = $2,
                last_error = $3,
                updated_at = NOW()
            WHERE id = $1
            ",
        )
        .bind(id)
        .bind(next_run_at)
        .bind(error)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Delete a schedule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM schema_refresh_schedules
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get schedule type as enum.
    #[must_use]
    pub fn get_schedule_type(&self) -> ScheduleType {
        ScheduleType::parse_str(&self.schedule_type).unwrap_or_default()
    }

    /// Check if this is an interval schedule.
    #[must_use]
    pub fn is_interval(&self) -> bool {
        self.get_schedule_type() == ScheduleType::Interval
    }

    /// Check if this is a cron schedule.
    #[must_use]
    pub fn is_cron(&self) -> bool {
        self.get_schedule_type() == ScheduleType::Cron
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_type_conversion() {
        assert_eq!(ScheduleType::Interval.as_str(), "interval");
        assert_eq!(ScheduleType::Cron.as_str(), "cron");

        assert_eq!(
            ScheduleType::parse_str("interval"),
            Some(ScheduleType::Interval)
        );
        assert_eq!(ScheduleType::parse_str("CRON"), Some(ScheduleType::Cron));
        assert_eq!(ScheduleType::parse_str("unknown"), None);
    }

    #[test]
    fn test_upsert_schedule_input() {
        let input = UpsertSchedule {
            enabled: true,
            schedule_type: ScheduleType::Interval,
            interval_hours: Some(24),
            cron_expression: None,
            notify_on_changes: true,
            notify_email: Some("admin@example.com".to_string()),
        };

        assert!(input.enabled);
        assert_eq!(input.interval_hours, Some(24));
        assert!(input.notify_on_changes);
    }

    #[test]
    fn test_upsert_cron_schedule() {
        let input = UpsertSchedule {
            enabled: true,
            schedule_type: ScheduleType::Cron,
            interval_hours: None,
            cron_expression: Some("0 2 * * 0".to_string()),
            notify_on_changes: false,
            notify_email: None,
        };

        assert_eq!(input.schedule_type, ScheduleType::Cron);
        assert_eq!(input.cron_expression, Some("0 2 * * 0".to_string()));
    }
}
