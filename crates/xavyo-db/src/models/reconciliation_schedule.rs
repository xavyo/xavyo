//! Reconciliation Schedule model for F049 Reconciliation Engine.
//!
//! Configuration for automatic recurring reconciliation runs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

use super::connector_reconciliation_run::ConnectorReconciliationMode;

/// Frequency for scheduled reconciliations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationScheduleFrequency {
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

impl fmt::Display for ReconciliationScheduleFrequency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hourly => write!(f, "hourly"),
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
            Self::Cron(expr) => write!(f, "{expr}"),
        }
    }
}

impl std::str::FromStr for ReconciliationScheduleFrequency {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hourly" => Ok(Self::Hourly),
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            _ if s.contains(' ') => Ok(Self::Cron(s.to_string())),
            _ => Err(format!("Unknown schedule frequency: {s}")),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for ReconciliationScheduleFrequency {
    fn default() -> Self {
        Self::Daily
    }
}

/// A reconciliation schedule record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReconciliationSchedule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub mode: String,
    pub frequency: String,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
    pub hour_of_day: i32,
    pub enabled: bool,
    pub last_run_id: Option<Uuid>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ReconciliationSchedule {
    /// Get mode enum.
    #[must_use] 
    pub fn mode(&self) -> ConnectorReconciliationMode {
        self.mode.parse().unwrap_or_default()
    }

    /// Get frequency enum.
    #[must_use] 
    pub fn frequency(&self) -> ReconciliationScheduleFrequency {
        self.frequency.parse().unwrap_or_default()
    }

    /// Create or update (upsert) a schedule.
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &UpsertReconciliationSchedule,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_reconciliation_schedules (
                tenant_id, connector_id, mode, frequency,
                day_of_week, day_of_month, hour_of_day, enabled, next_run_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (tenant_id, connector_id) DO UPDATE SET
                mode = EXCLUDED.mode,
                frequency = EXCLUDED.frequency,
                day_of_week = EXCLUDED.day_of_week,
                day_of_month = EXCLUDED.day_of_month,
                hour_of_day = EXCLUDED.hour_of_day,
                enabled = EXCLUDED.enabled,
                next_run_at = EXCLUDED.next_run_at,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(input.mode.to_string())
        .bind(input.frequency.to_string())
        .bind(input.day_of_week)
        .bind(input.day_of_month)
        .bind(input.hour_of_day)
        .bind(input.enabled)
        .bind(input.next_run_at)
        .fetch_one(pool)
        .await
    }

    /// Find schedule by connector.
    pub async fn find_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_schedules
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Find schedule by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_schedules
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all schedules for a tenant.
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_schedules
            WHERE tenant_id = $1
            ORDER BY created_at
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List enabled schedules due for execution.
    pub async fn list_due(pool: &PgPool, before: DateTime<Utc>) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_schedules
            WHERE enabled = true AND next_run_at <= $1
            ORDER BY next_run_at
            ",
        )
        .bind(before)
        .fetch_all(pool)
        .await
    }

    /// Enable schedule.
    pub async fn enable(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_schedules
            SET enabled = true, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable schedule.
    pub async fn disable(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_schedules
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Update after a run completes.
    pub async fn update_after_run(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        run_id: Uuid,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_schedules
            SET last_run_id = $3, next_run_at = $4, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(run_id)
        .bind(next_run_at)
        .fetch_optional(pool)
        .await
    }

    /// Delete schedule.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_reconciliation_schedules
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Validate schedule configuration.
    pub fn validate(&self) -> Result<(), String> {
        let freq = self.frequency();
        match freq {
            ReconciliationScheduleFrequency::Weekly if self.day_of_week.is_none() => {
                Err("day_of_week is required for weekly schedule".to_string())
            }
            ReconciliationScheduleFrequency::Monthly if self.day_of_month.is_none() => {
                Err("day_of_month is required for monthly schedule".to_string())
            }
            _ => Ok(()),
        }
    }
}

/// Input for creating/updating a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertReconciliationSchedule {
    pub mode: ConnectorReconciliationMode,
    pub frequency: ReconciliationScheduleFrequency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_week: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<i32>,
    #[serde(default = "default_hour")]
    pub hour_of_day: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<DateTime<Utc>>,
}

fn default_hour() -> i32 {
    2 // 2 AM UTC
}

fn default_enabled() -> bool {
    true
}

impl Default for UpsertReconciliationSchedule {
    fn default() -> Self {
        Self {
            mode: ConnectorReconciliationMode::Full,
            frequency: ReconciliationScheduleFrequency::Daily,
            day_of_week: None,
            day_of_month: None,
            hour_of_day: 2,
            enabled: true,
            next_run_at: None,
        }
    }
}

impl UpsertReconciliationSchedule {
    /// Validate the schedule configuration.
    pub fn validate(&self) -> Result<(), String> {
        match &self.frequency {
            ReconciliationScheduleFrequency::Weekly if self.day_of_week.is_none() => {
                Err("day_of_week is required for weekly schedule".to_string())
            }
            ReconciliationScheduleFrequency::Weekly
                if self
                    .day_of_week
                    .is_some_and(|d| !(0..=6).contains(&d)) =>
            {
                Err("day_of_week must be between 0 (Sunday) and 6 (Saturday)".to_string())
            }
            ReconciliationScheduleFrequency::Monthly if self.day_of_month.is_none() => {
                Err("day_of_month is required for monthly schedule".to_string())
            }
            ReconciliationScheduleFrequency::Monthly
                if self
                    .day_of_month
                    .is_some_and(|d| !(1..=28).contains(&d)) =>
            {
                Err("day_of_month must be between 1 and 28".to_string())
            }
            _ if !(0..=23).contains(&self.hour_of_day) => {
                Err("hour_of_day must be between 0 and 23".to_string())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_roundtrip() {
        for freq in [
            ReconciliationScheduleFrequency::Hourly,
            ReconciliationScheduleFrequency::Daily,
            ReconciliationScheduleFrequency::Weekly,
            ReconciliationScheduleFrequency::Monthly,
        ] {
            let s = freq.to_string();
            let parsed: ReconciliationScheduleFrequency = s.parse().unwrap();
            assert_eq!(freq, parsed);
        }
    }

    #[test]
    fn test_cron_frequency() {
        let cron = "0 2 * * *";
        let parsed: ReconciliationScheduleFrequency = cron.parse().unwrap();
        match parsed {
            ReconciliationScheduleFrequency::Cron(expr) => assert_eq!(expr, cron),
            _ => panic!("Expected Cron variant"),
        }
    }

    #[test]
    fn test_upsert_validation() {
        // Daily doesn't need extra params
        let input = UpsertReconciliationSchedule::default();
        assert!(input.validate().is_ok());

        // Weekly needs day_of_week
        let input = UpsertReconciliationSchedule {
            frequency: ReconciliationScheduleFrequency::Weekly,
            ..Default::default()
        };
        assert!(input.validate().is_err());

        // Weekly with valid day_of_week
        let input = UpsertReconciliationSchedule {
            frequency: ReconciliationScheduleFrequency::Weekly,
            day_of_week: Some(0),
            ..Default::default()
        };
        assert!(input.validate().is_ok());

        // Monthly needs day_of_month
        let input = UpsertReconciliationSchedule {
            frequency: ReconciliationScheduleFrequency::Monthly,
            ..Default::default()
        };
        assert!(input.validate().is_err());

        // Monthly with valid day_of_month
        let input = UpsertReconciliationSchedule {
            frequency: ReconciliationScheduleFrequency::Monthly,
            day_of_month: Some(15),
            ..Default::default()
        };
        assert!(input.validate().is_ok());

        // Invalid day_of_month
        let input = UpsertReconciliationSchedule {
            frequency: ReconciliationScheduleFrequency::Monthly,
            day_of_month: Some(31),
            ..Default::default()
        };
        assert!(input.validate().is_err());
    }
}
