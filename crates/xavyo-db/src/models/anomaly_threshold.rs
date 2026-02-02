//! Anomaly Threshold model for F094 Behavioral Anomaly Detection.
//!
//! Configurable thresholds at tenant or agent level.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

/// An anomaly threshold configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AnomalyThreshold {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this threshold belongs to.
    pub tenant_id: Uuid,

    /// The agent this threshold is for (NULL for tenant defaults).
    pub agent_id: Option<Uuid>,

    /// Type of anomaly this threshold applies to.
    pub anomaly_type: String,

    /// Threshold value (z-score for volume, percentage for others).
    pub threshold_value: Decimal,

    /// Whether this anomaly type check is enabled.
    pub enabled: bool,

    /// Whether to send alerts for this anomaly type.
    pub alert_enabled: bool,

    /// Aggregation window in seconds for alert deduplication.
    pub aggregation_window_secs: i32,

    /// When this threshold was created.
    pub created_at: DateTime<Utc>,

    /// When this threshold was last updated.
    pub updated_at: DateTime<Utc>,

    /// Who created this threshold.
    pub created_by: Option<Uuid>,
}

/// Data for creating or updating a threshold.
#[derive(Debug, Clone)]
pub struct UpsertAnomalyThreshold {
    pub tenant_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub anomaly_type: String,
    pub threshold_value: Decimal,
    pub enabled: bool,
    pub alert_enabled: bool,
    pub aggregation_window_secs: i32,
    pub created_by: Option<Uuid>,
}

impl AnomalyThreshold {
    /// Get threshold for a specific agent and anomaly type.
    /// Falls back to tenant default if agent-specific not found.
    pub async fn get_effective(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        anomaly_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First try agent-specific
        let agent_threshold = sqlx::query_as::<_, AnomalyThreshold>(
            r#"
            SELECT
                id, tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs,
                created_at, updated_at, created_by
            FROM anomaly_thresholds
            WHERE tenant_id = $1 AND agent_id = $2 AND anomaly_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(anomaly_type)
        .fetch_optional(pool)
        .await?;

        if agent_threshold.is_some() {
            return Ok(agent_threshold);
        }

        // Fall back to tenant default
        sqlx::query_as::<_, AnomalyThreshold>(
            r#"
            SELECT
                id, tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs,
                created_at, updated_at, created_by
            FROM anomaly_thresholds
            WHERE tenant_id = $1 AND agent_id IS NULL AND anomaly_type = $2
            "#,
        )
        .bind(tenant_id)
        .bind(anomaly_type)
        .fetch_optional(pool)
        .await
    }

    /// Get all thresholds for an agent (including tenant defaults for missing types).
    pub async fn get_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, AnomalyThreshold>(
            r#"
            SELECT DISTINCT ON (anomaly_type)
                id, tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs,
                created_at, updated_at, created_by
            FROM anomaly_thresholds
            WHERE tenant_id = $1 AND (agent_id = $2 OR agent_id IS NULL)
            ORDER BY anomaly_type, agent_id NULLS LAST
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// Get tenant default thresholds.
    pub async fn get_tenant_defaults(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, AnomalyThreshold>(
            r#"
            SELECT
                id, tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs,
                created_at, updated_at, created_by
            FROM anomaly_thresholds
            WHERE tenant_id = $1 AND agent_id IS NULL
            ORDER BY anomaly_type
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create or update a threshold (upsert).
    pub async fn upsert(pool: &PgPool, data: UpsertAnomalyThreshold) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, AnomalyThreshold>(
            r#"
            INSERT INTO anomaly_thresholds (
                tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, agent_id, anomaly_type)
            DO UPDATE SET
                threshold_value = EXCLUDED.threshold_value,
                enabled = EXCLUDED.enabled,
                alert_enabled = EXCLUDED.alert_enabled,
                aggregation_window_secs = EXCLUDED.aggregation_window_secs,
                updated_at = NOW()
            RETURNING
                id, tenant_id, agent_id, anomaly_type, threshold_value,
                enabled, alert_enabled, aggregation_window_secs,
                created_at, updated_at, created_by
            "#,
        )
        .bind(data.tenant_id)
        .bind(data.agent_id)
        .bind(data.anomaly_type)
        .bind(data.threshold_value)
        .bind(data.enabled)
        .bind(data.alert_enabled)
        .bind(data.aggregation_window_secs)
        .bind(data.created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete agent-specific thresholds (reset to tenant defaults).
    pub async fn delete_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM anomaly_thresholds
            WHERE tenant_id = $1 AND agent_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if agent has any agent-specific thresholds.
    pub async fn has_agent_thresholds(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM anomaly_thresholds
                WHERE tenant_id = $1 AND agent_id = $2
            ) as exists
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await?;

        Ok(row.get::<bool, _>("exists"))
    }
}
