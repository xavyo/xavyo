//! Detected Anomaly model for F094 Behavioral Anomaly Detection.
//!
//! Records all detected anomalies for audit and analysis.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

/// Anomaly type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbAnomalyType {
    /// Request volume significantly above baseline.
    HighVolume,
    /// Request volume significantly below baseline (sudden drop).
    LowVolume,
    /// Tool usage outside historical pattern.
    UnusualTool,
    /// Activity outside normal time distribution.
    OffHours,
    /// Short-term spike in request rate.
    RapidBurst,
}

impl std::fmt::Display for DbAnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbAnomalyType::HighVolume => write!(f, "high_volume"),
            DbAnomalyType::LowVolume => write!(f, "low_volume"),
            DbAnomalyType::UnusualTool => write!(f, "unusual_tool"),
            DbAnomalyType::OffHours => write!(f, "off_hours"),
            DbAnomalyType::RapidBurst => write!(f, "rapid_burst"),
        }
    }
}

impl std::str::FromStr for DbAnomalyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "high_volume" => Ok(DbAnomalyType::HighVolume),
            "low_volume" => Ok(DbAnomalyType::LowVolume),
            "unusual_tool" => Ok(DbAnomalyType::UnusualTool),
            "off_hours" => Ok(DbAnomalyType::OffHours),
            "rapid_burst" => Ok(DbAnomalyType::RapidBurst),
            _ => Err(format!("Invalid anomaly type: {s}")),
        }
    }
}

/// Anomaly severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbAnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for DbAnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbAnomalySeverity::Low => write!(f, "low"),
            DbAnomalySeverity::Medium => write!(f, "medium"),
            DbAnomalySeverity::High => write!(f, "high"),
            DbAnomalySeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for DbAnomalySeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(DbAnomalySeverity::Low),
            "medium" => Ok(DbAnomalySeverity::Medium),
            "high" => Ok(DbAnomalySeverity::High),
            "critical" => Ok(DbAnomalySeverity::Critical),
            _ => Err(format!("Invalid severity: {s}")),
        }
    }
}

/// A detected anomaly record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DetectedAnomaly {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this anomaly belongs to.
    pub tenant_id: Uuid,

    /// The agent that triggered this anomaly.
    pub agent_id: Uuid,

    /// Type of anomaly.
    pub anomaly_type: String,

    /// Severity level.
    pub severity: String,

    /// Anomaly score (0-100).
    pub score: i32,

    /// The calculated z-score.
    pub z_score: Decimal,

    /// The baseline value (mean) at the time of detection.
    pub baseline_value: Decimal,

    /// The observed value that triggered the anomaly.
    pub observed_value: Decimal,

    /// Human-readable description of the anomaly.
    pub description: String,

    /// Additional context (`conversation_id`, `tool_name`, etc.).
    pub context: Option<serde_json::Value>,

    /// When the anomaly was detected.
    pub detected_at: DateTime<Utc>,

    /// Whether an alert was sent for this anomaly.
    pub alert_sent: bool,

    /// When the alert was sent.
    pub alert_sent_at: Option<DateTime<Utc>>,
}

/// Data for creating a new detected anomaly.
#[derive(Debug, Clone)]
pub struct CreateDetectedAnomaly {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub anomaly_type: String,
    pub severity: String,
    pub score: i32,
    pub z_score: Decimal,
    pub baseline_value: Decimal,
    pub observed_value: Decimal,
    pub description: String,
    pub context: Option<serde_json::Value>,
}

/// Filter for listing anomalies.
#[derive(Debug, Clone, Default)]
pub struct DetectedAnomalyFilter {
    pub since: Option<DateTime<Utc>>,
    pub anomaly_type: Option<String>,
    pub severity: Option<String>,
}

impl DetectedAnomaly {
    /// Create a new detected anomaly.
    pub async fn create(pool: &PgPool, data: CreateDetectedAnomaly) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, DetectedAnomaly>(
            r"
            INSERT INTO detected_anomalies (
                tenant_id, agent_id, anomaly_type, severity, score,
                z_score, baseline_value, observed_value, description,
                context, detected_at, alert_sent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), false)
            RETURNING
                id, tenant_id, agent_id, anomaly_type, severity, score,
                z_score, baseline_value, observed_value, description,
                context, detected_at, alert_sent, alert_sent_at
            ",
        )
        .bind(data.tenant_id)
        .bind(data.agent_id)
        .bind(data.anomaly_type)
        .bind(data.severity)
        .bind(data.score)
        .bind(data.z_score)
        .bind(data.baseline_value)
        .bind(data.observed_value)
        .bind(data.description)
        .bind(data.context)
        .fetch_one(pool)
        .await
    }

    /// List anomalies for an agent with filters.
    pub async fn list_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        filter: &DetectedAnomalyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, DetectedAnomaly>(
            r"
            SELECT
                id, tenant_id, agent_id, anomaly_type, severity, score,
                z_score, baseline_value, observed_value, description,
                context, detected_at, alert_sent, alert_sent_at
            FROM detected_anomalies
            WHERE tenant_id = $1
                AND agent_id = $2
                AND ($3::timestamptz IS NULL OR detected_at >= $3)
                AND ($4::text IS NULL OR anomaly_type = $4)
                AND ($5::text IS NULL OR severity = $5)
            ORDER BY detected_at DESC
            LIMIT $6 OFFSET $7
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(filter.since)
        .bind(&filter.anomaly_type)
        .bind(&filter.severity)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count anomalies for an agent matching filters.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        filter: &DetectedAnomalyFilter,
    ) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            r"
            SELECT COUNT(*) as count
            FROM detected_anomalies
            WHERE tenant_id = $1
                AND agent_id = $2
                AND ($3::timestamptz IS NULL OR detected_at >= $3)
                AND ($4::text IS NULL OR anomaly_type = $4)
                AND ($5::text IS NULL OR severity = $5)
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(filter.since)
        .bind(&filter.anomaly_type)
        .bind(&filter.severity)
        .fetch_one(pool)
        .await?;

        Ok(row.get::<i64, _>("count"))
    }

    /// Mark an anomaly as alert sent.
    pub async fn mark_alert_sent(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE detected_anomalies
            SET alert_sent = true, alert_sent_at = NOW()
            WHERE id = $1
            ",
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Check if an alert was recently sent for this agent/type combination.
    pub async fn has_recent_alert(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        anomaly_type: &str,
        since: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            r"
            SELECT EXISTS(
                SELECT 1 FROM detected_anomalies
                WHERE tenant_id = $1
                    AND agent_id = $2
                    AND anomaly_type = $3
                    AND alert_sent = true
                    AND alert_sent_at > $4
            ) as exists
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(anomaly_type)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(row.get::<bool, _>("exists"))
    }
}
