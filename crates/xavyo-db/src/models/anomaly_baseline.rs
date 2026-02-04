//! Anomaly Baseline model for F094 Behavioral Anomaly Detection.
//!
//! Stores pre-computed statistical baselines for agent activity patterns.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Baseline type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbBaselineType {
    /// Requests per hour statistics.
    HourlyVolume,
    /// Frequency distribution of tools used.
    ToolDistribution,
    /// Activity distribution by hour of day.
    HourDistribution,
}

impl std::fmt::Display for DbBaselineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbBaselineType::HourlyVolume => write!(f, "hourly_volume"),
            DbBaselineType::ToolDistribution => write!(f, "tool_distribution"),
            DbBaselineType::HourDistribution => write!(f, "hour_distribution"),
        }
    }
}

impl std::str::FromStr for DbBaselineType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hourly_volume" => Ok(DbBaselineType::HourlyVolume),
            "tool_distribution" => Ok(DbBaselineType::ToolDistribution),
            "hour_distribution" => Ok(DbBaselineType::HourDistribution),
            _ => Err(format!("Invalid baseline type: {s}")),
        }
    }
}

/// An anomaly baseline record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AnomalyBaseline {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this baseline belongs to.
    pub tenant_id: Uuid,

    /// The agent this baseline is for.
    pub agent_id: Uuid,

    /// Type of baseline (`hourly_volume`, `tool_distribution`, `hour_distribution`).
    pub baseline_type: String,

    /// Mean value of the baseline metric.
    pub mean_value: Decimal,

    /// Standard deviation.
    pub std_deviation: Decimal,

    /// Number of samples used to compute this baseline.
    pub sample_count: i32,

    /// Percentile values (p5, p25, p50, p75, p95).
    pub percentiles: Option<serde_json::Value>,

    /// Tool frequency distribution (for `tool_distribution` type).
    pub tool_frequencies: Option<serde_json::Value>,

    /// Hour frequency distribution (for `hour_distribution` type).
    pub hour_frequencies: Option<serde_json::Value>,

    /// Start of the data window used to compute this baseline.
    pub window_start: DateTime<Utc>,

    /// End of the data window used to compute this baseline.
    pub window_end: DateTime<Utc>,

    /// When this baseline was computed.
    pub computed_at: DateTime<Utc>,

    /// Whether this baseline is currently valid.
    pub is_valid: bool,
}

/// Data for creating a new baseline.
#[derive(Debug, Clone)]
pub struct CreateAnomalyBaseline {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub baseline_type: String,
    pub mean_value: Decimal,
    pub std_deviation: Decimal,
    pub sample_count: i32,
    pub percentiles: Option<serde_json::Value>,
    pub tool_frequencies: Option<serde_json::Value>,
    pub hour_frequencies: Option<serde_json::Value>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
}

impl AnomalyBaseline {
    /// Get the current baseline for an agent and type.
    pub async fn get_by_agent_and_type(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        baseline_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, AnomalyBaseline>(
            r"
            SELECT
                id, tenant_id, agent_id, baseline_type, mean_value,
                std_deviation, sample_count, percentiles, tool_frequencies,
                hour_frequencies, window_start, window_end, computed_at, is_valid
            FROM anomaly_baselines
            WHERE tenant_id = $1 AND agent_id = $2 AND baseline_type = $3 AND is_valid = true
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(baseline_type)
        .fetch_optional(pool)
        .await
    }

    /// Get all baselines for an agent.
    pub async fn get_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, AnomalyBaseline>(
            r"
            SELECT
                id, tenant_id, agent_id, baseline_type, mean_value,
                std_deviation, sample_count, percentiles, tool_frequencies,
                hour_frequencies, window_start, window_end, computed_at, is_valid
            FROM anomaly_baselines
            WHERE tenant_id = $1 AND agent_id = $2 AND is_valid = true
            ORDER BY baseline_type
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// Create or update a baseline (upsert).
    pub async fn upsert(pool: &PgPool, data: CreateAnomalyBaseline) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, AnomalyBaseline>(
            r"
            INSERT INTO anomaly_baselines (
                tenant_id, agent_id, baseline_type, mean_value, std_deviation,
                sample_count, percentiles, tool_frequencies, hour_frequencies,
                window_start, window_end, computed_at, is_valid
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), true)
            ON CONFLICT (tenant_id, agent_id, baseline_type)
            DO UPDATE SET
                mean_value = EXCLUDED.mean_value,
                std_deviation = EXCLUDED.std_deviation,
                sample_count = EXCLUDED.sample_count,
                percentiles = EXCLUDED.percentiles,
                tool_frequencies = EXCLUDED.tool_frequencies,
                hour_frequencies = EXCLUDED.hour_frequencies,
                window_start = EXCLUDED.window_start,
                window_end = EXCLUDED.window_end,
                computed_at = NOW(),
                is_valid = true
            RETURNING
                id, tenant_id, agent_id, baseline_type, mean_value,
                std_deviation, sample_count, percentiles, tool_frequencies,
                hour_frequencies, window_start, window_end, computed_at, is_valid
            ",
        )
        .bind(data.tenant_id)
        .bind(data.agent_id)
        .bind(data.baseline_type)
        .bind(data.mean_value)
        .bind(data.std_deviation)
        .bind(data.sample_count)
        .bind(data.percentiles)
        .bind(data.tool_frequencies)
        .bind(data.hour_frequencies)
        .bind(data.window_start)
        .bind(data.window_end)
        .fetch_one(pool)
        .await
    }

    /// Invalidate baselines for an agent.
    pub async fn invalidate_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE anomaly_baselines
            SET is_valid = false
            WHERE tenant_id = $1 AND agent_id = $2 AND is_valid = true
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
