//! Schema Schedule Service for managing automatic schema refresh.
//!
//! Provides CRUD operations for schema refresh schedules and
//! `next_run_at` computation for both interval and cron-based schedules.

use chrono::{DateTime, Duration, Utc};
use cron::Schedule as CronSchedule;
use sqlx::PgPool;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use xavyo_db::models::{ScheduleType, SchemaRefreshSchedule, UpsertSchedule};

/// Errors that can occur during schedule operations.
#[derive(Error, Debug)]
pub enum ScheduleError {
    #[error("Invalid cron expression: {0}")]
    InvalidCronExpression(String),

    #[error("Invalid interval: interval_hours must be positive")]
    InvalidInterval,

    #[error("Schedule not found for connector {0}")]
    NotFound(Uuid),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Result type for schedule operations.
pub type ScheduleResult<T> = Result<T, ScheduleError>;

/// Validate schedule configuration.
///
/// Ensures that the required fields are present and valid for the given schedule type.
pub fn validate_schedule_config(
    schedule_type: &ScheduleType,
    interval_hours: Option<i32>,
    cron_expression: Option<&str>,
) -> ScheduleResult<()> {
    match schedule_type {
        ScheduleType::Interval => {
            let hours = interval_hours.ok_or(ScheduleError::ConfigurationError(
                "interval_hours required for interval schedule".to_string(),
            ))?;
            if hours <= 0 {
                return Err(ScheduleError::InvalidInterval);
            }
        }
        ScheduleType::Cron => {
            let expr = cron_expression.ok_or(ScheduleError::ConfigurationError(
                "cron_expression required for cron schedule".to_string(),
            ))?;
            // Validate cron expression
            CronSchedule::from_str(expr)
                .map_err(|e| ScheduleError::InvalidCronExpression(e.to_string()))?;
        }
    }
    Ok(())
}

/// Compute the next run time based on schedule configuration.
///
/// For interval schedules: adds `interval_hours` to the reference time.
/// For cron schedules: finds the next occurrence after the reference time.
pub fn compute_next_run_at(
    schedule_type: &ScheduleType,
    interval_hours: Option<i32>,
    cron_expression: Option<&str>,
    after: Option<DateTime<Utc>>,
) -> ScheduleResult<Option<DateTime<Utc>>> {
    let reference = after.unwrap_or_else(Utc::now);

    match schedule_type {
        ScheduleType::Interval => {
            let hours = interval_hours.ok_or(ScheduleError::InvalidInterval)?;
            if hours <= 0 {
                return Err(ScheduleError::InvalidInterval);
            }
            let next = reference + Duration::hours(i64::from(hours));
            Ok(Some(next))
        }
        ScheduleType::Cron => {
            let expr = cron_expression.ok_or(ScheduleError::ConfigurationError(
                "cron_expression required".to_string(),
            ))?;
            let schedule = CronSchedule::from_str(expr)
                .map_err(|e| ScheduleError::InvalidCronExpression(e.to_string()))?;

            // Find next occurrence after reference time
            let next = schedule.after(&reference).next();
            Ok(next)
        }
    }
}

/// Service for managing schema refresh schedules.
#[derive(Clone)]
pub struct ScheduleService {
    pool: PgPool,
}

impl ScheduleService {
    /// Create a new schedule service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the refresh schedule for a connector.
    #[instrument(skip(self))]
    pub async fn get_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ScheduleResult<Option<SchemaRefreshSchedule>> {
        let schedule =
            SchemaRefreshSchedule::find_by_connector(&self.pool, tenant_id, connector_id).await?;
        Ok(schedule)
    }

    /// Create or update a refresh schedule.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        enabled: bool,
        schedule_type: ScheduleType,
        interval_hours: Option<i32>,
        cron_expression: Option<String>,
        notify_on_changes: bool,
        notify_email: Option<String>,
    ) -> ScheduleResult<SchemaRefreshSchedule> {
        // Validate schedule configuration
        validate_schedule_config(&schedule_type, interval_hours, cron_expression.as_deref())?;

        // Compute next_run_at
        let next_run_at = if enabled {
            compute_next_run_at(
                &schedule_type,
                interval_hours,
                cron_expression.as_deref(),
                None,
            )?
        } else {
            None
        };

        let input = UpsertSchedule {
            enabled,
            schedule_type,
            interval_hours,
            cron_expression,
            notify_on_changes,
            notify_email,
        };

        let schedule =
            SchemaRefreshSchedule::upsert(&self.pool, tenant_id, connector_id, &input, next_run_at)
                .await?;

        info!(
            connector_id = %connector_id,
            enabled = enabled,
            schedule_type = ?schedule_type,
            next_run_at = ?next_run_at,
            "Schema refresh schedule updated"
        );

        Ok(schedule)
    }

    /// Delete a refresh schedule.
    #[instrument(skip(self))]
    pub async fn delete_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ScheduleResult<bool> {
        let deleted = SchemaRefreshSchedule::delete(&self.pool, tenant_id, connector_id).await?;

        if deleted {
            info!(connector_id = %connector_id, "Schema refresh schedule deleted");
        } else {
            debug!(connector_id = %connector_id, "No schedule to delete");
        }

        Ok(deleted)
    }

    /// Get all schedules due for execution.
    #[instrument(skip(self))]
    pub async fn get_due_schedules(
        &self,
        limit: i32,
    ) -> ScheduleResult<Vec<SchemaRefreshSchedule>> {
        let schedules = SchemaRefreshSchedule::find_due_schedules(&self.pool, limit).await?;
        debug!(count = schedules.len(), "Found due schedules");
        Ok(schedules)
    }

    /// Mark a schedule as executed and compute next run time.
    #[instrument(skip(self))]
    pub async fn mark_executed(
        &self,
        schedule: &SchemaRefreshSchedule,
        success: bool,
        error_message: Option<String>,
    ) -> ScheduleResult<()> {
        // Compute next run time
        let schedule_type = schedule.get_schedule_type();
        let next_run_at = if schedule.enabled {
            compute_next_run_at(
                &schedule_type,
                schedule.interval_hours,
                schedule.cron_expression.as_deref(),
                Some(Utc::now()),
            )?
        } else {
            None
        };

        SchemaRefreshSchedule::update_after_run(
            &self.pool,
            schedule.id,
            next_run_at,
            if success {
                None
            } else {
                error_message.as_deref()
            },
        )
        .await?;

        info!(
            schedule_id = %schedule.id,
            success = success,
            next_run_at = ?next_run_at,
            "Schedule execution recorded"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // T063 - Cron Expression Parsing Tests
    // =========================================================================
    // Note: cron crate 0.12 uses 7-field format: sec min hour day-of-month month day-of-week year

    #[test]
    fn test_cron_expression_valid_hourly() {
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            Some("0 0 * * * * *"), // Every hour at minute 0
            Some(Utc::now()),
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_cron_expression_valid_daily() {
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            Some("0 0 2 * * * *"), // Every day at 2:00 AM
            Some(Utc::now()),
        );
        assert!(result.is_ok());
        let next = result.unwrap().unwrap();
        // Next run should be in the future
        assert!(next > Utc::now());
    }

    #[test]
    fn test_cron_expression_valid_weekly() {
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            Some("0 0 0 * * SUN *"), // Every Sunday at midnight
            Some(Utc::now()),
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_cron_expression_invalid() {
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            Some("invalid cron"),
            Some(Utc::now()),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScheduleError::InvalidCronExpression(_)
        ));
    }

    #[test]
    fn test_cron_expression_missing() {
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            None, // Missing cron expression
            Some(Utc::now()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cron_next_run_is_after_reference() {
        let reference = Utc::now();
        let result = compute_next_run_at(
            &ScheduleType::Cron,
            None,
            Some("0 */5 * * * * *"), // Every 5 minutes
            Some(reference),
        );
        assert!(result.is_ok());
        let next = result.unwrap().unwrap();
        assert!(next > reference, "Next run should be after reference time");
    }

    // =========================================================================
    // T064 - Interval Schedule Tests
    // =========================================================================

    #[test]
    fn test_interval_hours_1() {
        let reference = Utc::now();
        let result = compute_next_run_at(&ScheduleType::Interval, Some(1), None, Some(reference));
        assert!(result.is_ok());
        let next = result.unwrap().unwrap();
        let expected = reference + Duration::hours(1);
        // Allow 1 second tolerance
        assert!((next - expected).num_seconds().abs() < 1);
    }

    #[test]
    fn test_interval_hours_24() {
        let reference = Utc::now();
        let result = compute_next_run_at(&ScheduleType::Interval, Some(24), None, Some(reference));
        assert!(result.is_ok());
        let next = result.unwrap().unwrap();
        let expected = reference + Duration::hours(24);
        assert!((next - expected).num_seconds().abs() < 1);
    }

    #[test]
    fn test_interval_hours_168() {
        // 168 hours = 1 week
        let reference = Utc::now();
        let result = compute_next_run_at(&ScheduleType::Interval, Some(168), None, Some(reference));
        assert!(result.is_ok());
        let next = result.unwrap().unwrap();
        let expected = reference + Duration::hours(168);
        assert!((next - expected).num_seconds().abs() < 1);
    }

    #[test]
    fn test_interval_zero_invalid() {
        let result = compute_next_run_at(&ScheduleType::Interval, Some(0), None, Some(Utc::now()));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScheduleError::InvalidInterval
        ));
    }

    #[test]
    fn test_interval_negative_invalid() {
        let result = compute_next_run_at(&ScheduleType::Interval, Some(-5), None, Some(Utc::now()));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScheduleError::InvalidInterval
        ));
    }

    #[test]
    fn test_interval_missing() {
        let result = compute_next_run_at(
            &ScheduleType::Interval,
            None, // Missing interval
            None,
            Some(Utc::now()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_interval_default_reference_is_now() {
        let before = Utc::now();
        let result = compute_next_run_at(
            &ScheduleType::Interval,
            Some(1),
            None,
            None, // Use default (now)
        );
        let after = Utc::now();

        assert!(result.is_ok());
        let next = result.unwrap().unwrap();

        // Next should be between before+1h and after+1h
        let min_expected = before + Duration::hours(1);
        let max_expected = after + Duration::hours(1);
        assert!(next >= min_expected && next <= max_expected);
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_interval_schedule_valid() {
        let result = validate_schedule_config(&ScheduleType::Interval, Some(6), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_interval_schedule_missing_hours() {
        let result = validate_schedule_config(&ScheduleType::Interval, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cron_schedule_valid() {
        let result = validate_schedule_config(
            &ScheduleType::Cron,
            None,
            Some("0 0 * * * * *"), // 7-field format required by cron 0.12
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_cron_schedule_missing_expression() {
        let result = validate_schedule_config(&ScheduleType::Cron, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cron_schedule_invalid_expression() {
        let result =
            validate_schedule_config(&ScheduleType::Cron, None, Some("not a cron expression"));
        assert!(result.is_err());
    }
}
