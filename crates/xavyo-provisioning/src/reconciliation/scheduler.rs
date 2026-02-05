//! Reconciliation scheduling for automatic runs.
//!
//! Manages scheduled reconciliation runs with configurable frequencies.

use chrono::{DateTime, Datelike, Duration, NaiveTime, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::ReconciliationMode;

/// Schedule frequency options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleFrequency {
    /// Every hour.
    Hourly,
    /// Every day.
    Daily,
    /// Every week.
    Weekly,
    /// Every month.
    Monthly,
    /// Custom cron expression.
    Cron(String),
}

impl std::fmt::Display for ScheduleFrequency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hourly => write!(f, "hourly"),
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
            Self::Cron(expr) => write!(f, "{expr}"),
        }
    }
}

impl std::str::FromStr for ScheduleFrequency {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hourly" => Ok(Self::Hourly),
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            _ if s.contains(' ') => Ok(Self::Cron(s.to_string())), // Likely a cron expression
            _ => Err(format!("Invalid schedule frequency: {s}")),
        }
    }
}

/// Configuration for a reconciliation schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Schedule ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Reconciliation mode.
    pub mode: ReconciliationMode,
    /// Schedule frequency.
    pub frequency: ScheduleFrequency,
    /// Day of week for weekly (0=Sunday, 6=Saturday).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_week: Option<u8>,
    /// Day of month for monthly (1-28).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<u8>,
    /// Hour of day (0-23 UTC).
    pub hour_of_day: u8,
    /// Whether the schedule is enabled.
    pub enabled: bool,
    /// Last run ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_id: Option<Uuid>,
    /// Next scheduled run time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<DateTime<Utc>>,
}

impl ScheduleConfig {
    /// Create a new schedule configuration.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        connector_id: Uuid,
        mode: ReconciliationMode,
        frequency: ScheduleFrequency,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            mode,
            frequency,
            day_of_week: None,
            day_of_month: None,
            hour_of_day: 2, // Default: 2 AM UTC
            enabled: true,
            last_run_id: None,
            next_run_at: None,
        }
    }

    /// Set day of week for weekly schedule.
    #[must_use]
    pub fn with_day_of_week(mut self, day: u8) -> Self {
        self.day_of_week = Some(day.min(6));
        self
    }

    /// Set day of month for monthly schedule.
    #[must_use]
    pub fn with_day_of_month(mut self, day: u8) -> Self {
        self.day_of_month = Some(day.clamp(1, 28));
        self
    }

    /// Set hour of day.
    #[must_use]
    pub fn with_hour(mut self, hour: u8) -> Self {
        self.hour_of_day = hour.min(23);
        self
    }

    /// Validate the schedule configuration.
    pub fn validate(&self) -> Result<(), String> {
        match &self.frequency {
            ScheduleFrequency::Weekly if self.day_of_week.is_none() => {
                Err("day_of_week is required for weekly schedule".to_string())
            }
            ScheduleFrequency::Monthly if self.day_of_month.is_none() => {
                Err("day_of_month is required for monthly schedule".to_string())
            }
            _ => Ok(()),
        }
    }
}

/// Scheduler for reconciliation runs.
pub struct ReconciliationScheduler;

impl ReconciliationScheduler {
    /// Calculate the next run time based on schedule configuration.
    #[must_use]
    pub fn calculate_next_run(
        config: &ScheduleConfig,
        from: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let target_time = NaiveTime::from_hms_opt(u32::from(config.hour_of_day), 0, 0)?;

        match &config.frequency {
            ScheduleFrequency::Hourly => {
                // Next hour
                let next = from + Duration::hours(1);
                Some(
                    next.date_naive()
                        .and_time(NaiveTime::from_hms_opt(next.hour(), 0, 0)?)
                        .and_utc(),
                )
            }
            ScheduleFrequency::Daily => Self::next_daily(from, target_time),
            ScheduleFrequency::Weekly => {
                let day = config.day_of_week.unwrap_or(0);
                Self::next_weekly(from, target_time, day)
            }
            ScheduleFrequency::Monthly => {
                let day = config.day_of_month.unwrap_or(1);
                Self::next_monthly(from, target_time, day)
            }
            ScheduleFrequency::Cron(_) => {
                // For cron, we'd need a cron parser
                // For now, fall back to daily
                Self::next_daily(from, target_time)
            }
        }
    }

    /// Calculate next daily run.
    fn next_daily(from: DateTime<Utc>, target_time: NaiveTime) -> Option<DateTime<Utc>> {
        let today_target = from.date_naive().and_time(target_time).and_utc();

        if from < today_target {
            Some(today_target)
        } else {
            let tomorrow = from.date_naive() + Duration::days(1);
            Some(tomorrow.and_time(target_time).and_utc())
        }
    }

    /// Calculate next weekly run.
    fn next_weekly(
        from: DateTime<Utc>,
        target_time: NaiveTime,
        day_of_week: u8,
    ) -> Option<DateTime<Utc>> {
        let target_weekday = match day_of_week {
            0 => Weekday::Sun,
            1 => Weekday::Mon,
            2 => Weekday::Tue,
            3 => Weekday::Wed,
            4 => Weekday::Thu,
            5 => Weekday::Fri,
            _ => Weekday::Sat,
        };

        let current_weekday = from.weekday();
        let days_until = (i64::from(target_weekday.num_days_from_sunday())
            - i64::from(current_weekday.num_days_from_sunday())
            + 7)
            % 7;

        let mut target_date = from.date_naive() + Duration::days(days_until);
        let target_datetime = target_date.and_time(target_time).and_utc();

        if days_until == 0 && from >= target_datetime {
            // Same day but past the time, move to next week
            target_date += Duration::days(7);
            return Some(target_date.and_time(target_time).and_utc());
        }

        Some(target_datetime)
    }

    /// Calculate next monthly run.
    fn next_monthly(
        from: DateTime<Utc>,
        target_time: NaiveTime,
        day_of_month: u8,
    ) -> Option<DateTime<Utc>> {
        let day = u32::from(day_of_month.min(28));

        // Try this month
        let this_month_date = from.date_naive().with_day(day)?;
        let this_month_datetime = this_month_date.and_time(target_time).and_utc();

        if from < this_month_datetime {
            return Some(this_month_datetime);
        }

        // Move to next month
        let (year, month) = if from.month() == 12 {
            (from.year() + 1, 1)
        } else {
            (from.year(), from.month() + 1)
        };

        let next_month_date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
        Some(next_month_date.and_time(target_time).and_utc())
    }

    /// Check if a schedule is due for execution.
    #[must_use]
    pub fn is_due(config: &ScheduleConfig, now: DateTime<Utc>, tolerance: Duration) -> bool {
        if !config.enabled {
            return false;
        }

        match config.next_run_at {
            Some(next_run) => {
                let window_start = next_run - tolerance;
                let window_end = next_run + tolerance;
                now >= window_start && now <= window_end
            }
            None => false,
        }
    }
}

/// Request to create or update a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRequest {
    /// Reconciliation mode.
    pub mode: ReconciliationMode,
    /// Frequency.
    pub frequency: String,
    /// Day of week (0-6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_week: Option<u8>,
    /// Day of month (1-28).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<u8>,
    /// Hour of day (0-23).
    #[serde(default = "default_hour")]
    pub hour_of_day: u8,
    /// Whether enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_hour() -> u8 {
    2
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_schedule_frequency_display() {
        assert_eq!(ScheduleFrequency::Hourly.to_string(), "hourly");
        assert_eq!(ScheduleFrequency::Daily.to_string(), "daily");
        assert_eq!(ScheduleFrequency::Weekly.to_string(), "weekly");
        assert_eq!(ScheduleFrequency::Monthly.to_string(), "monthly");
    }

    #[test]
    fn test_schedule_frequency_parse() {
        assert_eq!(
            "hourly".parse::<ScheduleFrequency>().unwrap(),
            ScheduleFrequency::Hourly
        );
        assert_eq!(
            "daily".parse::<ScheduleFrequency>().unwrap(),
            ScheduleFrequency::Daily
        );
        assert_eq!(
            "weekly".parse::<ScheduleFrequency>().unwrap(),
            ScheduleFrequency::Weekly
        );
        assert_eq!(
            "monthly".parse::<ScheduleFrequency>().unwrap(),
            ScheduleFrequency::Monthly
        );

        // Cron expression
        match "0 2 * * *".parse::<ScheduleFrequency>().unwrap() {
            ScheduleFrequency::Cron(expr) => assert_eq!(expr, "0 2 * * *"),
            _ => panic!("Expected Cron"),
        }
    }

    #[test]
    fn test_schedule_config_new() {
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Daily,
        );

        assert!(config.enabled);
        assert_eq!(config.hour_of_day, 2);
        assert!(config.next_run_at.is_none());
    }

    #[test]
    fn test_schedule_config_validation() {
        // Daily doesn't need extra params
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Daily,
        );
        assert!(config.validate().is_ok());

        // Weekly needs day_of_week
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Weekly,
        );
        assert!(config.validate().is_err());

        let config = config.with_day_of_week(0);
        assert!(config.validate().is_ok());

        // Monthly needs day_of_month
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Monthly,
        );
        assert!(config.validate().is_err());

        let config = config.with_day_of_month(15);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_calculate_next_run_hourly() {
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Hourly,
        );

        let now = Utc.with_ymd_and_hms(2026, 1, 25, 10, 30, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();

        assert_eq!(next.hour(), 11);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn test_calculate_next_run_daily() {
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Daily,
        )
        .with_hour(2);

        // Before target time
        let now = Utc.with_ymd_and_hms(2026, 1, 25, 1, 0, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();
        assert_eq!(next.day(), 25);
        assert_eq!(next.hour(), 2);

        // After target time
        let now = Utc.with_ymd_and_hms(2026, 1, 25, 10, 0, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();
        assert_eq!(next.day(), 26);
        assert_eq!(next.hour(), 2);
    }

    #[test]
    fn test_calculate_next_run_weekly() {
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Weekly,
        )
        .with_day_of_week(0) // Sunday
        .with_hour(3);

        // Sunday Jan 25, 2026, 10:00 - past target time of 03:00
        let now = Utc.with_ymd_and_hms(2026, 1, 25, 10, 0, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();

        // Should be next Sunday Feb 1
        assert_eq!(next.weekday(), Weekday::Sun);
        assert_eq!(next.day(), 1);
        assert_eq!(next.month(), 2);
        assert_eq!(next.hour(), 3);
    }

    #[test]
    fn test_calculate_next_run_monthly() {
        let config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Monthly,
        )
        .with_day_of_month(15)
        .with_hour(2);

        // Before the 15th
        let now = Utc.with_ymd_and_hms(2026, 1, 10, 10, 0, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();
        assert_eq!(next.month(), 1);
        assert_eq!(next.day(), 15);

        // After the 15th
        let now = Utc.with_ymd_and_hms(2026, 1, 20, 10, 0, 0).unwrap();
        let next = ReconciliationScheduler::calculate_next_run(&config, now).unwrap();
        assert_eq!(next.month(), 2);
        assert_eq!(next.day(), 15);
    }

    #[test]
    fn test_is_due() {
        let mut config = ScheduleConfig::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReconciliationMode::Full,
            ScheduleFrequency::Daily,
        );

        let now = Utc.with_ymd_and_hms(2026, 1, 25, 2, 0, 0).unwrap();
        config.next_run_at = Some(now);
        config.enabled = true;

        let tolerance = Duration::minutes(5);

        // Exactly at time
        assert!(ReconciliationScheduler::is_due(&config, now, tolerance));

        // Within tolerance
        let slightly_before = now - Duration::minutes(3);
        assert!(ReconciliationScheduler::is_due(
            &config,
            slightly_before,
            tolerance
        ));

        // Outside tolerance
        let too_early = now - Duration::minutes(10);
        assert!(!ReconciliationScheduler::is_due(
            &config, too_early, tolerance
        ));

        // Disabled
        config.enabled = false;
        assert!(!ReconciliationScheduler::is_due(&config, now, tolerance));
    }
}
