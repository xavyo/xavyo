//! SLA Policy model for semi-manual resources (F064).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// SLA policy for manual provisioning tasks.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovSlaPolicy {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Display name for the policy.
    pub name: String,

    /// Policy description.
    pub description: Option<String>,

    /// Target completion time in seconds.
    pub target_duration_seconds: i32,

    /// Warning threshold as percentage of target time.
    pub warning_threshold_percent: i32,

    /// Contacts for escalation notifications.
    pub escalation_contacts: Option<serde_json::Value>,

    /// Whether to send notifications on breach.
    pub breach_notification_enabled: bool,

    /// Whether this policy is active.
    pub is_active: bool,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create an SLA policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSlaPolicy {
    pub name: String,
    pub description: Option<String>,
    pub target_duration_seconds: i32,
    pub warning_threshold_percent: Option<i32>,
    pub escalation_contacts: Option<serde_json::Value>,
    pub breach_notification_enabled: Option<bool>,
}

/// Request to update an SLA policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSlaPolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub target_duration_seconds: Option<i32>,
    pub warning_threshold_percent: Option<i32>,
    pub escalation_contacts: Option<serde_json::Value>,
    pub breach_notification_enabled: Option<bool>,
    pub is_active: Option<bool>,
}

/// Filter options for listing policies.
#[derive(Debug, Clone, Default)]
pub struct SlaPolicyFilter {
    pub is_active: Option<bool>,
}

impl GovSlaPolicy {
    /// Calculate warning time threshold.
    #[must_use] 
    pub fn warning_threshold_seconds(&self) -> i64 {
        (i64::from(self.target_duration_seconds) * i64::from(self.warning_threshold_percent)) / 100
    }

    /// Calculate deadline from a start time.
    #[must_use] 
    pub fn deadline_from(&self, start_time: DateTime<Utc>) -> DateTime<Utc> {
        start_time + chrono::Duration::seconds(i64::from(self.target_duration_seconds))
    }

    /// Calculate warning time from a start time.
    #[must_use] 
    pub fn warning_time_from(&self, start_time: DateTime<Utc>) -> DateTime<Utc> {
        start_time + chrono::Duration::seconds(self.warning_threshold_seconds())
    }

    /// Get human-readable duration string.
    #[must_use] 
    pub fn target_duration_human(&self) -> String {
        let seconds = self.target_duration_seconds;
        if seconds >= 86400 {
            let days = seconds / 86400;
            let hours = (seconds % 86400) / 3600;
            if hours > 0 {
                format!(
                    "{} day{}, {} hour{}",
                    days,
                    if days > 1 { "s" } else { "" },
                    hours,
                    if hours > 1 { "s" } else { "" }
                )
            } else {
                format!("{} day{}", days, if days > 1 { "s" } else { "" })
            }
        } else if seconds >= 3600 {
            let hours = seconds / 3600;
            let minutes = (seconds % 3600) / 60;
            if minutes > 0 {
                format!(
                    "{} hour{}, {} minute{}",
                    hours,
                    if hours > 1 { "s" } else { "" },
                    minutes,
                    if minutes > 1 { "s" } else { "" }
                )
            } else {
                format!("{} hour{}", hours, if hours > 1 { "s" } else { "" })
            }
        } else if seconds >= 60 {
            let minutes = seconds / 60;
            format!("{} minute{}", minutes, if minutes > 1 { "s" } else { "" })
        } else {
            format!("{} second{}", seconds, if seconds > 1 { "s" } else { "" })
        }
    }

    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sla_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List policies for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SlaPolicyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_sla_policies
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count policies for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SlaPolicyFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_sla_policies
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.fetch_one(pool).await
    }

    /// Create a new policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateSlaPolicy,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sla_policies (
                tenant_id, name, description, target_duration_seconds,
                warning_threshold_percent, escalation_contacts, breach_notification_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.target_duration_seconds)
        .bind(input.warning_threshold_percent.unwrap_or(75))
        .bind(&input.escalation_contacts)
        .bind(input.breach_notification_enabled.unwrap_or(true))
        .fetch_one(pool)
        .await
    }

    /// Update a policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSlaPolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sla_policies
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                target_duration_seconds = COALESCE($5, target_duration_seconds),
                warning_threshold_percent = COALESCE($6, warning_threshold_percent),
                escalation_contacts = COALESCE($7, escalation_contacts),
                breach_notification_enabled = COALESCE($8, breach_notification_enabled),
                is_active = COALESCE($9, is_active),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.target_duration_seconds)
        .bind(input.warning_threshold_percent)
        .bind(&input.escalation_contacts)
        .bind(input.breach_notification_enabled)
        .bind(input.is_active)
        .fetch_optional(pool)
        .await
    }

    /// Delete a policy.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sla_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if policy is in use by any application.
    pub async fn is_in_use(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_applications
            WHERE tenant_id = $1 AND sla_policy_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warning_threshold_seconds() {
        let policy = GovSlaPolicy {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            target_duration_seconds: 14400, // 4 hours
            warning_threshold_percent: 75,
            escalation_contacts: None,
            breach_notification_enabled: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // 75% of 4 hours = 3 hours = 10800 seconds
        assert_eq!(policy.warning_threshold_seconds(), 10800);
    }

    #[test]
    fn test_target_duration_human() {
        let mut policy = GovSlaPolicy {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            target_duration_seconds: 14400,
            warning_threshold_percent: 75,
            escalation_contacts: None,
            breach_notification_enabled: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(policy.target_duration_human(), "4 hours");

        policy.target_duration_seconds = 86400; // 1 day
        assert_eq!(policy.target_duration_human(), "1 day");

        policy.target_duration_seconds = 90000; // 1 day 1 hour
        assert_eq!(policy.target_duration_human(), "1 day, 1 hour");

        policy.target_duration_seconds = 3660; // 1 hour 1 minute
        assert_eq!(policy.target_duration_human(), "1 hour, 1 minute");

        policy.target_duration_seconds = 120; // 2 minutes
        assert_eq!(policy.target_duration_human(), "2 minutes");

        policy.target_duration_seconds = 45; // 45 seconds
        assert_eq!(policy.target_duration_human(), "45 seconds");
    }

    #[test]
    fn test_deadline_and_warning_from() {
        let policy = GovSlaPolicy {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            target_duration_seconds: 3600, // 1 hour
            warning_threshold_percent: 75,
            escalation_contacts: None,
            breach_notification_enabled: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let start = Utc::now();
        let deadline = policy.deadline_from(start);
        let warning = policy.warning_time_from(start);

        assert_eq!(deadline - start, chrono::Duration::seconds(3600));
        assert_eq!(warning - start, chrono::Duration::seconds(2700)); // 75% of 1 hour
    }

    #[test]
    fn test_create_input() {
        let input = CreateSlaPolicy {
            name: "Standard SLA".to_string(),
            description: Some("4 hour response time".to_string()),
            target_duration_seconds: 14400,
            warning_threshold_percent: Some(75),
            escalation_contacts: None,
            breach_notification_enabled: Some(true),
        };

        assert_eq!(input.target_duration_seconds, 14400);
    }
}
