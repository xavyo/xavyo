//! Governance Escalation Rule model (F054).
//!
//! Represents step-specific escalation configuration that overrides tenant defaults.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{FinalFallbackAction, GovEscalationLevel};

/// Step-specific escalation configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEscalationRule {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// The approval step this rule applies to.
    pub step_id: Uuid,

    /// Timeout for this step.
    /// Note: `PgInterval` doesn't implement Serialize/Deserialize, use `timeout_secs()` accessor.
    #[serde(skip)]
    pub timeout: sqlx::postgres::types::PgInterval,

    /// Time before timeout to send warning.
    /// Note: `PgInterval` doesn't implement Serialize/Deserialize, use `warning_threshold_secs()` accessor.
    #[serde(skip)]
    pub warning_threshold: Option<sqlx::postgres::types::PgInterval>,

    /// Override fallback action (uses policy default if None).
    pub final_fallback: Option<FinalFallbackAction>,

    /// Whether escalation is enabled for this step.
    pub is_enabled: bool,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update an escalation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEscalationRule {
    /// Timeout in seconds.
    pub timeout_secs: i64,
    /// Warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,
    pub final_fallback: Option<FinalFallbackAction>,
}

/// Request to update an escalation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEscalationRule {
    /// Timeout in seconds.
    pub timeout_secs: Option<i64>,
    /// Warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,
    pub final_fallback: Option<FinalFallbackAction>,
    pub is_enabled: Option<bool>,
}

/// Escalation rule with its levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRuleWithLevels {
    #[serde(flatten)]
    pub rule: GovEscalationRule,
    pub levels: Vec<GovEscalationLevel>,
}

impl GovEscalationRule {
    /// Find a rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_escalation_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a rule by step ID.
    pub async fn find_by_step(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        step_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_escalation_rules
            WHERE tenant_id = $1 AND step_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(step_id)
        .fetch_optional(pool)
        .await
    }

    /// List rules for steps in a workflow.
    pub async fn find_by_workflow(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT r.* FROM gov_escalation_rules r
            JOIN gov_approval_steps s ON s.id = r.step_id
            WHERE r.tenant_id = $1 AND s.workflow_id = $2
            ORDER BY s.step_order
            ",
        )
        .bind(tenant_id)
        .bind(workflow_id)
        .fetch_all(pool)
        .await
    }

    /// Create or update a rule for a step (upsert).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        step_id: Uuid,
        input: CreateEscalationRule,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_escalation_rules (
                tenant_id, step_id, timeout, warning_threshold, final_fallback
            )
            VALUES (
                $1, $2,
                make_interval(secs => $3),
                CASE WHEN $4::bigint IS NOT NULL THEN make_interval(secs => $4) ELSE NULL END,
                $5
            )
            ON CONFLICT (step_id) DO UPDATE SET
                timeout = EXCLUDED.timeout,
                warning_threshold = EXCLUDED.warning_threshold,
                final_fallback = EXCLUDED.final_fallback,
                is_enabled = true,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(step_id)
        .bind(input.timeout_secs as f64)
        .bind(input.warning_threshold_secs.map(|s| s as f64))
        .bind(input.final_fallback)
        .fetch_one(pool)
        .await
    }

    /// Update a rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEscalationRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.timeout_secs.is_some() {
            updates.push(format!("timeout = make_interval(secs => ${param_idx})"));
            param_idx += 1;
        }
        if input.warning_threshold_secs.is_some() {
            updates.push(format!(
                "warning_threshold = make_interval(secs => ${param_idx})"
            ));
            param_idx += 1;
        }
        if input.final_fallback.is_some() {
            updates.push(format!("final_fallback = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_enabled.is_some() {
            updates.push(format!("is_enabled = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_escalation_rules SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(timeout_secs) = input.timeout_secs {
            q = q.bind(timeout_secs as f64);
        }
        if let Some(threshold_secs) = input.warning_threshold_secs {
            q = q.bind(threshold_secs as f64);
        }
        if let Some(fallback) = input.final_fallback {
            q = q.bind(fallback);
        }
        if let Some(is_enabled) = input.is_enabled {
            q = q.bind(is_enabled);
        }

        q.fetch_optional(pool).await
    }

    /// Enable escalation for a step.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        step_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_escalation_rules
            SET is_enabled = true, updated_at = NOW()
            WHERE tenant_id = $1 AND step_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(step_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable escalation for a step.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        step_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_escalation_rules
            SET is_enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND step_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(step_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_escalation_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a rule by step ID.
    pub async fn delete_by_step(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        step_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_escalation_rules
            WHERE tenant_id = $1 AND step_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(step_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get timeout as Duration.
    #[must_use] 
    pub fn timeout_duration(&self) -> chrono::Duration {
        let microseconds = self.timeout.microseconds;
        let days = i64::from(self.timeout.days);
        let months = i64::from(self.timeout.months);
        let total_days = days + (months * 30);
        let total_microseconds = microseconds + (total_days * 24 * 60 * 60 * 1_000_000);
        chrono::Duration::microseconds(total_microseconds)
    }

    /// Get timeout in seconds (for serialization).
    #[must_use] 
    pub fn timeout_secs(&self) -> i64 {
        let microseconds = self.timeout.microseconds;
        let days = i64::from(self.timeout.days);
        let months = i64::from(self.timeout.months);
        let total_days = days + (months * 30);
        (microseconds / 1_000_000) + (total_days * 24 * 60 * 60)
    }

    /// Get warning threshold as Duration.
    #[must_use] 
    pub fn warning_duration(&self) -> Option<chrono::Duration> {
        self.warning_threshold.as_ref().map(|interval| {
            let microseconds = interval.microseconds;
            let days = i64::from(interval.days);
            let months = i64::from(interval.months);
            let total_days = days + (months * 30);
            let total_microseconds = microseconds + (total_days * 24 * 60 * 60 * 1_000_000);
            chrono::Duration::microseconds(total_microseconds)
        })
    }

    /// Get warning threshold in seconds (for serialization).
    #[must_use] 
    pub fn warning_threshold_secs(&self) -> Option<i64> {
        self.warning_threshold.as_ref().map(|interval| {
            let microseconds = interval.microseconds;
            let days = i64::from(interval.days);
            let months = i64::from(interval.months);
            let total_days = days + (months * 30);
            (microseconds / 1_000_000) + (total_days * 24 * 60 * 60)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_escalation_rule() {
        let input = CreateEscalationRule {
            timeout_secs: 86400,                 // 24 hours
            warning_threshold_secs: Some(14400), // 4 hours
            final_fallback: Some(FinalFallbackAction::AutoReject),
        };

        assert_eq!(input.timeout_secs, 86400);
    }
}
