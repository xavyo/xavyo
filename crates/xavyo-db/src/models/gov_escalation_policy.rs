//! Governance Escalation Policy model (F054).
//!
//! Represents tenant-wide default escalation configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{FinalFallbackAction, GovEscalationLevel};

/// Tenant-wide default escalation configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEscalationPolicy {
    /// Unique identifier for the policy.
    pub id: Uuid,

    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Policy name (unique within tenant).
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Default step timeout (e.g., '48 hours').
    /// Note: PgInterval doesn't implement Serialize/Deserialize, use timeout_secs() accessor.
    #[serde(skip)]
    pub default_timeout: sqlx::postgres::types::PgInterval,

    /// Time before timeout to send warning (e.g., '4 hours').
    /// Note: PgInterval doesn't implement Serialize/Deserialize, use warning_threshold_secs() accessor.
    #[serde(skip)]
    pub warning_threshold: Option<sqlx::postgres::types::PgInterval>,

    /// Action when all escalation levels are exhausted.
    pub final_fallback: FinalFallbackAction,

    /// Whether the policy is active (only one active default per tenant).
    pub is_active: bool,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new escalation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEscalationPolicy {
    pub name: String,
    pub description: Option<String>,
    /// Default timeout in seconds.
    pub default_timeout_secs: i64,
    /// Warning threshold in seconds (before timeout).
    pub warning_threshold_secs: Option<i64>,
    pub final_fallback: FinalFallbackAction,
}

/// Request to update an escalation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEscalationPolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    /// Default timeout in seconds.
    pub default_timeout_secs: Option<i64>,
    /// Warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,
    pub final_fallback: Option<FinalFallbackAction>,
    pub is_active: Option<bool>,
}

/// Filter options for listing escalation policies.
#[derive(Debug, Clone, Default)]
pub struct EscalationPolicyFilter {
    pub is_active: Option<bool>,
}

/// Escalation policy with its levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicyWithLevels {
    #[serde(flatten)]
    pub policy: GovEscalationPolicy,
    pub levels: Vec<GovEscalationLevel>,
}

impl GovEscalationPolicy {
    /// Find a policy by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_escalation_policies
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the active default policy for a tenant.
    pub async fn find_active_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_escalation_policies
            WHERE tenant_id = $1 AND is_active = true
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a policy by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_escalation_policies
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List policies for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EscalationPolicyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_escalation_policies WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
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

    /// Count policies in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EscalationPolicyFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_escalation_policies WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.fetch_one(pool).await
    }

    /// Create a new escalation policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateEscalationPolicy,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_escalation_policies (
                tenant_id, name, description, default_timeout,
                warning_threshold, final_fallback
            )
            VALUES (
                $1, $2, $3,
                make_interval(secs => $4),
                CASE WHEN $5::bigint IS NOT NULL THEN make_interval(secs => $5) ELSE NULL END,
                $6
            )
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.default_timeout_secs as f64)
        .bind(input.warning_threshold_secs.map(|s| s as f64))
        .bind(input.final_fallback)
        .fetch_one(pool)
        .await
    }

    /// Update an escalation policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEscalationPolicy,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.default_timeout_secs.is_some() {
            updates.push(format!(
                "default_timeout = make_interval(secs => ${})",
                param_idx
            ));
            param_idx += 1;
        }
        if input.warning_threshold_secs.is_some() {
            updates.push(format!(
                "warning_threshold = make_interval(secs => ${})",
                param_idx
            ));
            param_idx += 1;
        }
        if input.final_fallback.is_some() {
            updates.push(format!("final_fallback = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${}", param_idx));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_escalation_policies SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(timeout_secs) = input.default_timeout_secs {
            q = q.bind(timeout_secs as f64);
        }
        if let Some(threshold_secs) = input.warning_threshold_secs {
            q = q.bind(threshold_secs as f64);
        }
        if let Some(fallback) = input.final_fallback {
            q = q.bind(fallback);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an escalation policy.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_escalation_policies
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Deactivate all policies for a tenant except the specified one.
    pub async fn deactivate_others(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        except_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_escalation_policies
            SET is_active = false, updated_at = NOW()
            WHERE tenant_id = $1 AND id != $2 AND is_active = true
            "#,
        )
        .bind(tenant_id)
        .bind(except_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get timeout as Duration.
    pub fn timeout_duration(&self) -> chrono::Duration {
        interval_to_duration(&self.default_timeout)
    }

    /// Get timeout in seconds (for serialization).
    pub fn timeout_secs(&self) -> i64 {
        interval_to_secs(&self.default_timeout)
    }

    /// Get warning threshold as Duration.
    pub fn warning_duration(&self) -> Option<chrono::Duration> {
        self.warning_threshold.as_ref().map(interval_to_duration)
    }

    /// Get warning threshold in seconds (for serialization).
    pub fn warning_threshold_secs(&self) -> Option<i64> {
        self.warning_threshold.as_ref().map(interval_to_secs)
    }
}

/// Convert PgInterval to chrono::Duration.
fn interval_to_duration(interval: &sqlx::postgres::types::PgInterval) -> chrono::Duration {
    let microseconds = interval.microseconds;
    let days = interval.days as i64;
    let months = interval.months as i64;

    // Approximate: 1 month = 30 days
    let total_days = days + (months * 30);
    let total_microseconds = microseconds + (total_days * 24 * 60 * 60 * 1_000_000);

    chrono::Duration::microseconds(total_microseconds)
}

/// Convert PgInterval to seconds.
fn interval_to_secs(interval: &sqlx::postgres::types::PgInterval) -> i64 {
    let microseconds = interval.microseconds;
    let days = interval.days as i64;
    let months = interval.months as i64;

    // Approximate: 1 month = 30 days
    let total_days = days + (months * 30);
    (microseconds / 1_000_000) + (total_days * 24 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_escalation_policy() {
        let input = CreateEscalationPolicy {
            name: "Default Policy".to_string(),
            description: Some("Tenant-wide default".to_string()),
            default_timeout_secs: 172800,        // 48 hours
            warning_threshold_secs: Some(14400), // 4 hours
            final_fallback: FinalFallbackAction::RemainPending,
        };

        assert_eq!(input.name, "Default Policy");
        assert_eq!(input.default_timeout_secs, 172800);
    }
}
