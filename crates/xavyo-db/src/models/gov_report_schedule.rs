//! Governance Report Schedule model.
//!
//! Represents recurring report generation schedules.

use chrono::{DateTime, Datelike, Duration, TimeZone, Utc, Weekday};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_generated_report::OutputFormat;

/// Schedule frequency for report generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_schedule_frequency", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScheduleFrequency {
    /// Run every day.
    Daily,
    /// Run once per week.
    Weekly,
    /// Run once per month.
    Monthly,
}

/// Schedule status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_schedule_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    /// Schedule is active.
    Active,
    /// Temporarily paused by user.
    Paused,
    /// Disabled due to failures or by admin.
    Disabled,
}

impl ScheduleStatus {
    /// Check if the schedule is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the schedule can be paused.
    #[must_use] 
    pub fn can_pause(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if the schedule can be resumed.
    #[must_use] 
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Paused | Self::Disabled)
    }
}

/// Maximum consecutive failures before auto-disable.
pub const MAX_CONSECUTIVE_FAILURES: i32 = 3;

/// A report generation schedule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovReportSchedule {
    /// Unique identifier for the schedule.
    pub id: Uuid,

    /// The tenant this schedule belongs to.
    pub tenant_id: Uuid,

    /// Reference to template.
    pub template_id: Uuid,

    /// Schedule display name.
    pub name: String,

    /// Run frequency.
    pub frequency: ScheduleFrequency,

    /// Hour of day to run (UTC, 0-23).
    pub schedule_hour: i32,

    /// Day of week for weekly (0=Sunday, 6=Saturday).
    pub schedule_day_of_week: Option<i32>,

    /// Day of month for monthly (1-31).
    pub schedule_day_of_month: Option<i32>,

    /// Default parameters for generation.
    pub parameters: serde_json::Value,

    /// Email recipients for notifications.
    pub recipients: serde_json::Value,

    /// Output format.
    pub output_format: OutputFormat,

    /// Schedule status.
    pub status: ScheduleStatus,

    /// Last successful run timestamp.
    pub last_run_at: Option<DateTime<Utc>>,

    /// Next scheduled run timestamp.
    pub next_run_at: DateTime<Utc>,

    /// Count of consecutive failures.
    pub consecutive_failures: i32,

    /// Last error message if any.
    pub last_error: Option<String>,

    /// User who created the schedule.
    pub created_by: Uuid,

    /// When the schedule was created.
    pub created_at: DateTime<Utc>,

    /// When the schedule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportSchedule {
    pub template_id: Uuid,
    pub name: String,
    pub frequency: ScheduleFrequency,
    pub schedule_hour: i32,
    pub schedule_day_of_week: Option<i32>,
    pub schedule_day_of_month: Option<i32>,
    pub parameters: Option<serde_json::Value>,
    pub recipients: Vec<String>,
    pub output_format: OutputFormat,
    pub created_by: Uuid,
}

/// Request to update a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReportSchedule {
    pub name: Option<String>,
    pub frequency: Option<ScheduleFrequency>,
    pub schedule_hour: Option<i32>,
    pub schedule_day_of_week: Option<i32>,
    pub schedule_day_of_month: Option<i32>,
    pub parameters: Option<serde_json::Value>,
    pub recipients: Option<Vec<String>>,
    pub output_format: Option<OutputFormat>,
}

/// Filter options for listing schedules.
#[derive(Debug, Clone, Default)]
pub struct ReportScheduleFilter {
    pub template_id: Option<Uuid>,
    pub status: Option<ScheduleStatus>,
    pub created_by: Option<Uuid>,
}

impl GovReportSchedule {
    /// Find a schedule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_report_schedules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a schedule by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_report_schedules
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List schedules for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReportScheduleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_report_schedules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovReportSchedule>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count schedules for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReportScheduleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_report_schedules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// List due schedules (active schedules past their `next_run_at`).
    pub async fn list_due(pool: &sqlx::PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_report_schedules
            WHERE status = 'active' AND next_run_at <= NOW()
            ORDER BY next_run_at ASC
            ",
        )
        .fetch_all(pool)
        .await
    }

    /// Create a new schedule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateReportSchedule,
    ) -> Result<Self, sqlx::Error> {
        let parameters = input.parameters.unwrap_or_else(|| serde_json::json!({}));
        let recipients =
            serde_json::to_value(&input.recipients).unwrap_or_else(|_| serde_json::json!([]));
        let next_run_at = calculate_next_run(
            input.frequency,
            input.schedule_hour,
            input.schedule_day_of_week,
            input.schedule_day_of_month,
            None,
        );

        sqlx::query_as(
            r"
            INSERT INTO gov_report_schedules (
                tenant_id, template_id, name, frequency, schedule_hour,
                schedule_day_of_week, schedule_day_of_month, parameters,
                recipients, output_format, created_by, next_run_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.template_id)
        .bind(&input.name)
        .bind(input.frequency)
        .bind(input.schedule_hour)
        .bind(input.schedule_day_of_week)
        .bind(input.schedule_day_of_month)
        .bind(&parameters)
        .bind(&recipients)
        .bind(input.output_format)
        .bind(input.created_by)
        .bind(next_run_at)
        .fetch_one(pool)
        .await
    }

    /// Update a schedule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateReportSchedule,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First fetch the current schedule to calculate new next_run_at if needed
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.frequency.is_some() {
            updates.push(format!("frequency = ${param_idx}"));
            param_idx += 1;
        }
        if input.schedule_hour.is_some() {
            updates.push(format!("schedule_hour = ${param_idx}"));
            param_idx += 1;
        }
        if input.schedule_day_of_week.is_some() {
            updates.push(format!("schedule_day_of_week = ${param_idx}"));
            param_idx += 1;
        }
        if input.schedule_day_of_month.is_some() {
            updates.push(format!("schedule_day_of_month = ${param_idx}"));
            param_idx += 1;
        }
        if input.parameters.is_some() {
            updates.push(format!("parameters = ${param_idx}"));
            param_idx += 1;
        }
        if input.recipients.is_some() {
            updates.push(format!("recipients = ${param_idx}"));
            param_idx += 1;
        }
        if input.output_format.is_some() {
            updates.push(format!("output_format = ${param_idx}"));
            param_idx += 1;
        }

        // Recalculate next_run_at if schedule changed
        let needs_recalc = input.frequency.is_some()
            || input.schedule_hour.is_some()
            || input.schedule_day_of_week.is_some()
            || input.schedule_day_of_month.is_some();

        if needs_recalc {
            updates.push(format!("next_run_at = ${param_idx}"));
            let _ = param_idx;
        }

        let query = format!(
            "UPDATE gov_report_schedules SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovReportSchedule>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(frequency) = input.frequency {
            q = q.bind(frequency);
        }
        if let Some(schedule_hour) = input.schedule_hour {
            q = q.bind(schedule_hour);
        }
        if let Some(day_of_week) = input.schedule_day_of_week {
            q = q.bind(day_of_week);
        }
        if let Some(day_of_month) = input.schedule_day_of_month {
            q = q.bind(day_of_month);
        }
        if let Some(ref parameters) = input.parameters {
            q = q.bind(parameters);
        }
        if let Some(ref recipients) = input.recipients {
            let recipients_json =
                serde_json::to_value(recipients).unwrap_or_else(|_| serde_json::json!([]));
            q = q.bind(recipients_json);
        }
        if let Some(output_format) = input.output_format {
            q = q.bind(output_format);
        }
        if needs_recalc {
            let new_next_run = calculate_next_run(
                input.frequency.unwrap_or(current.frequency),
                input.schedule_hour.unwrap_or(current.schedule_hour),
                input.schedule_day_of_week.or(current.schedule_day_of_week),
                input
                    .schedule_day_of_month
                    .or(current.schedule_day_of_month),
                None,
            );
            q = q.bind(new_next_run);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a schedule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_report_schedules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Pause a schedule.
    pub async fn pause(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_report_schedules
            SET status = 'paused', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Resume a schedule.
    pub async fn resume(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First get current schedule to recalculate next_run_at
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let current = match current {
            Some(c) if c.status.can_resume() => c,
            _ => return Ok(None),
        };

        let next_run_at = calculate_next_run(
            current.frequency,
            current.schedule_hour,
            current.schedule_day_of_week,
            current.schedule_day_of_month,
            None,
        );

        sqlx::query_as(
            r"
            UPDATE gov_report_schedules
            SET status = 'active', updated_at = NOW(), next_run_at = $3, consecutive_failures = 0
            WHERE id = $1 AND tenant_id = $2 AND status IN ('paused', 'disabled')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(next_run_at)
        .fetch_optional(pool)
        .await
    }

    /// Record a successful run.
    pub async fn record_success(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let next_run_at = calculate_next_run(
            current.frequency,
            current.schedule_hour,
            current.schedule_day_of_week,
            current.schedule_day_of_month,
            Some(Utc::now()),
        );

        sqlx::query_as(
            r"
            UPDATE gov_report_schedules
            SET last_run_at = NOW(), next_run_at = $3, consecutive_failures = 0,
                last_error = NULL, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(next_run_at)
        .fetch_optional(pool)
        .await
    }

    /// Record a failed run.
    pub async fn record_failure(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let new_failures = current.consecutive_failures + 1;
        let new_status = if new_failures >= MAX_CONSECUTIVE_FAILURES {
            ScheduleStatus::Disabled
        } else {
            current.status
        };

        let next_run_at = calculate_next_run(
            current.frequency,
            current.schedule_hour,
            current.schedule_day_of_week,
            current.schedule_day_of_month,
            Some(Utc::now()),
        );

        sqlx::query_as(
            r"
            UPDATE gov_report_schedules
            SET next_run_at = $3, consecutive_failures = $4, last_error = $5,
                status = $6, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(next_run_at)
        .bind(new_failures)
        .bind(error_message)
        .bind(new_status)
        .fetch_optional(pool)
        .await
    }

    /// Parse recipients from JSON.
    #[must_use] 
    pub fn parse_recipients(&self) -> Vec<String> {
        serde_json::from_value(self.recipients.clone()).unwrap_or_default()
    }

    /// Check if the schedule should run now.
    #[must_use] 
    pub fn is_due(&self) -> bool {
        self.status.is_active() && self.next_run_at <= Utc::now()
    }
}

/// Calculate the next run time for a schedule.
fn calculate_next_run(
    frequency: ScheduleFrequency,
    schedule_hour: i32,
    schedule_day_of_week: Option<i32>,
    schedule_day_of_month: Option<i32>,
    after: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    let now = after.unwrap_or_else(Utc::now);
    let today = now.date_naive();
    let schedule_hour = schedule_hour.clamp(0, 23) as u32;

    match frequency {
        ScheduleFrequency::Daily => {
            let mut next = Utc.from_utc_datetime(&today.and_hms_opt(schedule_hour, 0, 0).unwrap());
            if next <= now {
                next += Duration::days(1);
            }
            next
        }
        ScheduleFrequency::Weekly => {
            let target_day = schedule_day_of_week.unwrap_or(0).clamp(0, 6);
            let target_weekday = match target_day {
                0 => Weekday::Sun,
                1 => Weekday::Mon,
                2 => Weekday::Tue,
                3 => Weekday::Wed,
                4 => Weekday::Thu,
                5 => Weekday::Fri,
                _ => Weekday::Sat,
            };

            let current_weekday = today.weekday();
            let days_until = (i64::from(target_weekday.num_days_from_sunday())
                - i64::from(current_weekday.num_days_from_sunday())
                + 7)
                % 7;

            let target_date = today + Duration::days(days_until);
            let mut next =
                Utc.from_utc_datetime(&target_date.and_hms_opt(schedule_hour, 0, 0).unwrap());

            if next <= now {
                next += Duration::weeks(1);
            }
            next
        }
        ScheduleFrequency::Monthly => {
            let target_day = schedule_day_of_month.unwrap_or(1).clamp(1, 28) as u32;

            let mut year = today.year();
            let mut month = today.month();

            // Try current month first
            if let Some(date) = chrono::NaiveDate::from_ymd_opt(year, month, target_day) {
                let next = Utc.from_utc_datetime(&date.and_hms_opt(schedule_hour, 0, 0).unwrap());
                if next > now {
                    return next;
                }
            }

            // Move to next month
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }

            let date =
                chrono::NaiveDate::from_ymd_opt(year, month, target_day).unwrap_or_else(|| {
                    // If day doesn't exist in month, use last day
                    chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
                        .map(|d| d.pred_opt().unwrap())
                        .unwrap_or_else(|| {
                            chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
                                .unwrap()
                                .pred_opt()
                                .unwrap()
                        })
                });

            Utc.from_utc_datetime(&date.and_hms_opt(schedule_hour, 0, 0).unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_schedule_status_methods() {
        assert!(ScheduleStatus::Active.is_active());
        assert!(!ScheduleStatus::Paused.is_active());
        assert!(!ScheduleStatus::Disabled.is_active());

        assert!(ScheduleStatus::Active.can_pause());
        assert!(!ScheduleStatus::Paused.can_pause());

        assert!(ScheduleStatus::Paused.can_resume());
        assert!(ScheduleStatus::Disabled.can_resume());
        assert!(!ScheduleStatus::Active.can_resume());
    }

    #[test]
    fn test_schedule_frequency_serialization() {
        let daily = ScheduleFrequency::Daily;
        let json = serde_json::to_string(&daily).unwrap();
        assert_eq!(json, "\"daily\"");

        let weekly = ScheduleFrequency::Weekly;
        let json = serde_json::to_string(&weekly).unwrap();
        assert_eq!(json, "\"weekly\"");

        let monthly = ScheduleFrequency::Monthly;
        let json = serde_json::to_string(&monthly).unwrap();
        assert_eq!(json, "\"monthly\"");
    }

    #[test]
    fn test_calculate_next_run_daily() {
        let now = Utc.with_ymd_and_hms(2026, 1, 24, 10, 0, 0).unwrap();

        // Schedule for 14:00, should be today
        let next = calculate_next_run(ScheduleFrequency::Daily, 14, None, None, Some(now));
        assert_eq!(next.hour(), 14);
        assert_eq!(next.day(), 24);

        // Schedule for 8:00, should be tomorrow
        let next = calculate_next_run(ScheduleFrequency::Daily, 8, None, None, Some(now));
        assert_eq!(next.hour(), 8);
        assert_eq!(next.day(), 25);
    }

    #[test]
    fn test_calculate_next_run_weekly() {
        // Friday, January 24, 2026
        let now = Utc.with_ymd_and_hms(2026, 1, 24, 10, 0, 0).unwrap();

        // Schedule for Monday (day 1) at 8:00
        let next = calculate_next_run(ScheduleFrequency::Weekly, 8, Some(1), None, Some(now));
        assert_eq!(next.weekday(), Weekday::Mon);
        assert_eq!(next.hour(), 8);
    }

    #[test]
    fn test_calculate_next_run_monthly() {
        let now = Utc.with_ymd_and_hms(2026, 1, 24, 10, 0, 0).unwrap();

        // Schedule for day 15, should be next month
        let next = calculate_next_run(ScheduleFrequency::Monthly, 8, None, Some(15), Some(now));
        assert_eq!(next.day(), 15);
        assert_eq!(next.month(), 2);

        // Schedule for day 28, should be current month
        let next = calculate_next_run(ScheduleFrequency::Monthly, 8, None, Some(28), Some(now));
        assert_eq!(next.day(), 28);
        assert_eq!(next.month(), 1);
    }
}
