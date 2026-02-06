//! Behavioral Anomaly Detection models for the AI Agent Security API (F094).
//!
//! Defines types for anomaly baselines, detected anomalies, thresholds,
//! and API request/response structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
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

impl AnomalyType {
    /// Get the string representation for database storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyType::HighVolume => "high_volume",
            AnomalyType::LowVolume => "low_volume",
            AnomalyType::UnusualTool => "unusual_tool",
            AnomalyType::OffHours => "off_hours",
            AnomalyType::RapidBurst => "rapid_burst",
        }
    }

    /// Get default threshold for this anomaly type.
    #[must_use]
    pub fn default_threshold(&self) -> f64 {
        match self {
            AnomalyType::HighVolume => 3.0,  // 3 sigma
            AnomalyType::LowVolume => 3.0,   // 3 sigma (absolute)
            AnomalyType::UnusualTool => 0.0, // Binary check
            AnomalyType::OffHours => 0.05,   // 5% activity threshold
            AnomalyType::RapidBurst => 5.0,  // 5 sigma
        }
    }
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AnomalyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "high_volume" => Ok(AnomalyType::HighVolume),
            "low_volume" => Ok(AnomalyType::LowVolume),
            "unusual_tool" => Ok(AnomalyType::UnusualTool),
            "off_hours" => Ok(AnomalyType::OffHours),
            "rapid_burst" => Ok(AnomalyType::RapidBurst),
            _ => Err(format!("Unknown anomaly type: {s}")),
        }
    }
}

/// Types of baselines computed for anomaly detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BaselineType {
    /// Requests per hour statistics.
    HourlyVolume,
    /// Frequency distribution of tools used.
    ToolDistribution,
    /// Activity distribution by hour of day.
    HourDistribution,
}

impl BaselineType {
    /// Get the string representation for database storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            BaselineType::HourlyVolume => "hourly_volume",
            BaselineType::ToolDistribution => "tool_distribution",
            BaselineType::HourDistribution => "hour_distribution",
        }
    }
}

/// Status of a baseline computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    /// Baseline is valid and ready for use.
    Active,
    /// Insufficient data to compute baseline (< 24 hours).
    InsufficientData,
    /// Baseline is currently being computed.
    Computing,
}

/// Severity level for detected anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// API Response Models
// ============================================================================

/// Response for listing detected anomalies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AnomalyListResponse {
    pub items: Vec<DetectedAnomaly>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// A detected anomaly record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DetectedAnomaly {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub score: i32,
    pub z_score: f64,
    pub baseline_value: f64,
    pub observed_value: f64,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    pub detected_at: DateTime<Utc>,
}

/// Response for getting an agent's baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BaselineResponse {
    pub agent_id: Uuid,
    pub status: BaselineStatus,
    pub baselines: Vec<Baseline>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_since: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<DateTime<Utc>>,
}

/// A single baseline entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Baseline {
    pub baseline_type: BaselineType,
    pub mean: f64,
    pub std_deviation: f64,
    pub sample_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentiles: Option<serde_json::Value>,
}

/// Response for getting thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ThresholdsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Uuid>,
    pub source: ThresholdSource,
    pub thresholds: Vec<Threshold>,
}

/// Source of threshold configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThresholdSource {
    /// Agent-specific override.
    Agent,
    /// Tenant-wide default.
    Tenant,
    /// System default (no custom config).
    Default,
}

/// A threshold configuration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Threshold {
    pub anomaly_type: AnomalyType,
    pub threshold_value: f64,
    pub enabled: bool,
    pub alert_enabled: bool,
    #[serde(default = "default_aggregation_window")]
    pub aggregation_window_secs: i32,
}

fn default_aggregation_window() -> i32 {
    300
}

// ============================================================================
// API Request Models
// ============================================================================

/// Request to set thresholds.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SetThresholdsRequest {
    pub thresholds: Vec<AnomalyThresholdInput>,
}

/// Input for a single threshold configuration.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AnomalyThresholdInput {
    pub anomaly_type: AnomalyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_window_secs: Option<i32>,
}

/// Query parameters for listing anomalies.
#[derive(Debug, Clone, Deserialize)]
pub struct ListAnomaliesQuery {
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub anomaly_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_type_serialization() {
        let high_volume = AnomalyType::HighVolume;
        let json = serde_json::to_string(&high_volume).unwrap();
        assert_eq!(json, "\"high_volume\"");

        let parsed: AnomalyType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, AnomalyType::HighVolume);
    }

    #[test]
    fn test_anomaly_type_as_str() {
        assert_eq!(AnomalyType::HighVolume.as_str(), "high_volume");
        assert_eq!(AnomalyType::LowVolume.as_str(), "low_volume");
        assert_eq!(AnomalyType::UnusualTool.as_str(), "unusual_tool");
        assert_eq!(AnomalyType::OffHours.as_str(), "off_hours");
        assert_eq!(AnomalyType::RapidBurst.as_str(), "rapid_burst");
    }

    #[test]
    fn test_anomaly_type_from_str() {
        assert_eq!(
            "high_volume".parse::<AnomalyType>().unwrap(),
            AnomalyType::HighVolume
        );
        assert!("invalid".parse::<AnomalyType>().is_err());
    }

    #[test]
    fn test_baseline_type_serialization() {
        let hourly = BaselineType::HourlyVolume;
        let json = serde_json::to_string(&hourly).unwrap();
        assert_eq!(json, "\"hourly_volume\"");
    }

    #[test]
    fn test_baseline_status_serialization() {
        let active = BaselineStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let insufficient = BaselineStatus::InsufficientData;
        let json = serde_json::to_string(&insufficient).unwrap();
        assert_eq!(json, "\"insufficient_data\"");
    }

    #[test]
    fn test_default_thresholds() {
        assert_eq!(AnomalyType::HighVolume.default_threshold(), 3.0);
        assert_eq!(AnomalyType::LowVolume.default_threshold(), 3.0);
        assert_eq!(AnomalyType::RapidBurst.default_threshold(), 5.0);
    }

    #[test]
    fn test_detected_anomaly_serialization() {
        let anomaly = DetectedAnomaly {
            id: Uuid::nil(),
            agent_id: Uuid::nil(),
            anomaly_type: AnomalyType::HighVolume,
            severity: Severity::High,
            score: 85,
            z_score: 11.67,
            baseline_value: 100.0,
            observed_value: 450.0,
            description: "Test anomaly".to_string(),
            context: None,
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&anomaly).unwrap();
        assert!(json.contains("\"high_volume\""));
        assert!(json.contains("\"high\""));
        assert!(json.contains("85"));
    }

    #[test]
    fn test_threshold_source_serialization() {
        let agent = ThresholdSource::Agent;
        let json = serde_json::to_string(&agent).unwrap();
        assert_eq!(json, "\"agent\"");

        let tenant = ThresholdSource::Tenant;
        let json = serde_json::to_string(&tenant).unwrap();
        assert_eq!(json, "\"tenant\"");
    }

    #[test]
    fn test_set_thresholds_request_deserialization() {
        let json = r#"{
            "thresholds": [
                {
                    "anomaly_type": "high_volume",
                    "threshold_value": 5.0,
                    "enabled": true
                }
            ]
        }"#;

        let request: SetThresholdsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.thresholds.len(), 1);
        assert_eq!(request.thresholds[0].anomaly_type, AnomalyType::HighVolume);
        assert_eq!(request.thresholds[0].threshold_value, Some(5.0));
    }

    #[test]
    fn test_baseline_response_serialization() {
        let response = BaselineResponse {
            agent_id: Uuid::nil(),
            status: BaselineStatus::Active,
            baselines: vec![Baseline {
                baseline_type: BaselineType::HourlyVolume,
                mean: 100.5,
                std_deviation: 28.3,
                sample_count: 168,
                percentiles: Some(serde_json::json!({
                    "p5": 45.0,
                    "p25": 78.0,
                    "p50": 98.0,
                    "p75": 122.0,
                    "p95": 155.0
                })),
            }],
            data_since: Some(Utc::now()),
            computed_at: Some(Utc::now()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"active\""));
        assert!(json.contains("\"hourly_volume\""));
        assert!(json.contains("100.5"));
    }
}
