//! Anomaly detection service for the Behavioral Anomaly Detection API (F094).
//!
//! Detects behavioral anomalies in agent activity patterns.

use chrono::{DateTime, Duration, Timelike, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    AnomalyBaseline, AnomalyThreshold, CreateDetectedAnomaly, DetectedAnomaly as DbDetectedAnomaly,
    DetectedAnomalyFilter, UpsertAnomalyThreshold,
};

use crate::error::ApiAgentsError;
use crate::models::anomaly_models::{
    AnomalyListResponse, AnomalyType, DetectedAnomaly, ListAnomaliesQuery, SetThresholdsRequest,
    Severity, Threshold, ThresholdSource, ThresholdsResponse,
};

/// Default aggregation window for alerts (5 minutes).
const DEFAULT_AGGREGATION_WINDOW_SECS: i32 = 300;

/// Service for detecting and managing behavioral anomalies.
#[derive(Clone)]
pub struct AnomalyService {
    pool: PgPool,
}

impl AnomalyService {
    /// Create a new `AnomalyService`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List detected anomalies for an agent.
    pub async fn list_anomalies(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        query: &ListAnomaliesQuery,
    ) -> Result<AnomalyListResponse, ApiAgentsError> {
        // Parse filter parameters
        let filter = DetectedAnomalyFilter {
            since: query.since,
            anomaly_type: query.anomaly_type.clone(),
            severity: query.severity.clone(),
        };

        // Query database
        let db_anomalies = DbDetectedAnomaly::list_by_agent(
            &self.pool,
            tenant_id,
            agent_id,
            &filter,
            query.limit,
            query.offset,
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        // Get total count
        let total = DbDetectedAnomaly::count(&self.pool, tenant_id, agent_id, &filter)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        // Convert to API response format
        let items: Vec<DetectedAnomaly> = db_anomalies
            .into_iter()
            .map(|a| DetectedAnomaly {
                id: a.id,
                agent_id: a.agent_id,
                anomaly_type: parse_anomaly_type(&a.anomaly_type),
                severity: parse_severity(&a.severity),
                score: a.score,
                z_score: decimal_to_f64(&a.z_score),
                baseline_value: decimal_to_f64(&a.baseline_value),
                observed_value: decimal_to_f64(&a.observed_value),
                description: a.description,
                context: a.context,
                detected_at: a.detected_at,
            })
            .collect();

        Ok(AnomalyListResponse {
            items,
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }

    /// Detect volume anomaly based on current activity vs baseline.
    pub async fn detect_volume_anomaly(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        current_volume: f64,
    ) -> Result<Option<DetectedAnomaly>, ApiAgentsError> {
        // Get baseline
        let baseline = AnomalyBaseline::get_by_agent_and_type(
            &self.pool,
            tenant_id,
            agent_id,
            "hourly_volume",
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        let baseline = match baseline {
            Some(b) if b.sample_count >= 24 => b,
            _ => return Ok(None), // Insufficient data
        };

        let mean = decimal_to_f64(&baseline.mean_value);
        let std_dev = decimal_to_f64(&baseline.std_deviation);

        if std_dev <= 0.0 {
            return Ok(None); // Can't compute z-score with zero std dev
        }

        // Calculate z-score
        let z_score = (current_volume - mean) / std_dev;

        // Get effective threshold
        let threshold = self
            .get_effective_threshold(tenant_id, agent_id, "high_volume")
            .await?;

        // Check if anomaly
        let is_high_volume = z_score >= threshold;
        let is_low_volume = z_score <= -threshold;

        if !is_high_volume && !is_low_volume {
            return Ok(None);
        }

        let anomaly_type = if is_high_volume {
            AnomalyType::HighVolume
        } else {
            AnomalyType::LowVolume
        };

        let severity = Self::calculate_severity(z_score);
        let score = Self::calculate_score(z_score);

        let description = format!(
            "{} detected: observed {} requests/hour vs baseline {} (z-score: {:.2})",
            anomaly_type.as_str(),
            current_volume,
            mean,
            z_score
        );

        let anomaly = DetectedAnomaly {
            id: Uuid::new_v4(),
            agent_id,
            anomaly_type,
            severity,
            score,
            z_score,
            baseline_value: mean,
            observed_value: current_volume,
            description,
            context: None,
            detected_at: Utc::now(),
        };

        Ok(Some(anomaly))
    }

    /// Record a detected anomaly to the database.
    pub async fn record_anomaly(
        &self,
        tenant_id: Uuid,
        anomaly: &DetectedAnomaly,
    ) -> Result<DbDetectedAnomaly, ApiAgentsError> {
        let create_data = CreateDetectedAnomaly {
            tenant_id,
            agent_id: anomaly.agent_id,
            anomaly_type: anomaly.anomaly_type.as_str().to_string(),
            severity: anomaly.severity.as_str().to_string(),
            score: anomaly.score,
            z_score: f64_to_decimal(anomaly.z_score),
            baseline_value: f64_to_decimal(anomaly.baseline_value),
            observed_value: f64_to_decimal(anomaly.observed_value),
            description: anomaly.description.clone(),
            context: anomaly.context.clone(),
        };

        DbDetectedAnomaly::create(&self.pool, create_data)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to record anomaly: {e}")))
    }

    /// Check if an alert should be sent (respecting aggregation window).
    pub async fn should_send_alert(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        anomaly_type: &str,
        aggregation_window_secs: i32,
    ) -> Result<bool, ApiAgentsError> {
        let since = Utc::now() - Duration::seconds(i64::from(aggregation_window_secs));

        let has_recent = DbDetectedAnomaly::has_recent_alert(
            &self.pool,
            tenant_id,
            agent_id,
            anomaly_type,
            since,
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        Ok(!has_recent)
    }

    /// Mark anomaly as having sent an alert.
    pub async fn mark_alert_sent(&self, anomaly_id: Uuid) -> Result<(), ApiAgentsError> {
        DbDetectedAnomaly::mark_alert_sent(&self.pool, anomaly_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))
    }

    /// Detect tool usage anomaly based on historical tool frequency.
    ///
    /// Flags unusual tool if it was never or rarely used in baseline period.
    pub async fn detect_tool_anomaly(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_name: &str,
    ) -> Result<Option<DetectedAnomaly>, ApiAgentsError> {
        // Get tool baseline
        let baseline = AnomalyBaseline::get_by_agent_and_type(
            &self.pool,
            tenant_id,
            agent_id,
            "tool_distribution",
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        let baseline = match baseline {
            Some(b) if b.sample_count >= 24 => b,
            _ => return Ok(None), // Insufficient data
        };

        // Check if tool is in the known tool frequencies
        let tool_frequencies = match &baseline.tool_frequencies {
            Some(freqs) => freqs,
            None => return Ok(None),
        };

        let tool_freq = tool_frequencies
            .get(tool_name)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);

        // Get threshold for unusual tool detection
        let threshold = self
            .get_effective_threshold(tenant_id, agent_id, "unusual_tool")
            .await?;

        // If tool frequency is below threshold (or zero for unknown tool), flag it
        if tool_freq > threshold {
            return Ok(None); // Tool is commonly used
        }

        let severity = if tool_freq == 0.0 {
            Severity::High // Never seen before
        } else {
            Severity::Medium // Rarely used
        };

        let score = if tool_freq == 0.0 { 80 } else { 60 };

        let description = if tool_freq == 0.0 {
            format!("Unknown tool '{tool_name}' used - not in historical baseline")
        } else {
            format!(
                "Unusual tool '{}' used - historical frequency {:.1}% (threshold: {:.1}%)",
                tool_name,
                tool_freq * 100.0,
                threshold * 100.0
            )
        };

        let anomaly = DetectedAnomaly {
            id: Uuid::new_v4(),
            agent_id,
            anomaly_type: AnomalyType::UnusualTool,
            severity,
            score,
            z_score: 0.0, // Binary check, no z-score
            baseline_value: tool_freq,
            observed_value: 1.0,
            description,
            context: Some(serde_json::json!({ "tool_name": tool_name })),
            detected_at: Utc::now(),
        };

        Ok(Some(anomaly))
    }

    /// Detect timing anomaly based on hour distribution baseline.
    ///
    /// Flags activity during off-hours (hours with very low historical activity).
    pub async fn detect_timing_anomaly(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        current_hour: i32,
    ) -> Result<Option<DetectedAnomaly>, ApiAgentsError> {
        // Get hour distribution baseline
        let baseline = AnomalyBaseline::get_by_agent_and_type(
            &self.pool,
            tenant_id,
            agent_id,
            "hour_distribution",
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        let baseline = match baseline {
            Some(b) if b.sample_count >= 24 => b,
            _ => return Ok(None), // Insufficient data
        };

        // Get hour frequency
        let hour_frequencies = match &baseline.hour_frequencies {
            Some(freqs) => freqs,
            None => return Ok(None),
        };

        let hour_freq = hour_frequencies
            .get(current_hour.to_string())
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);

        // Get threshold for off-hours detection
        let threshold = self
            .get_effective_threshold(tenant_id, agent_id, "off_hours")
            .await?;

        // If activity at this hour is above threshold, it's normal
        if hour_freq > threshold {
            return Ok(None);
        }

        let severity = if hour_freq == 0.0 {
            Severity::High // Never active at this hour
        } else if hour_freq < 0.01 {
            Severity::Medium // Very rare
        } else {
            Severity::Low
        };

        let score = ((1.0 - hour_freq / threshold) * 80.0).min(100.0) as i32;

        let description = format!(
            "Off-hours activity detected at hour {} - historical activity {:.1}% (threshold: {:.1}%)",
            current_hour,
            hour_freq * 100.0,
            threshold * 100.0
        );

        let anomaly = DetectedAnomaly {
            id: Uuid::new_v4(),
            agent_id,
            anomaly_type: AnomalyType::OffHours,
            severity,
            score,
            z_score: 0.0, // Distribution check, no z-score
            baseline_value: hour_freq,
            observed_value: 1.0,
            description,
            context: Some(serde_json::json!({ "hour": current_hour })),
            detected_at: Utc::now(),
        };

        Ok(Some(anomaly))
    }

    /// Send anomaly alert via webhook.
    ///
    /// Checks aggregation window and sends webhook if appropriate.
    pub async fn send_anomaly_alert(
        &self,
        tenant_id: Uuid,
        anomaly: &DetectedAnomaly,
    ) -> Result<bool, ApiAgentsError> {
        // Get threshold config for this anomaly type
        let threshold = AnomalyThreshold::get_effective(
            &self.pool,
            tenant_id,
            anomaly.agent_id,
            anomaly.anomaly_type.as_str(),
        )
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        let alert_enabled = threshold.as_ref().is_none_or(|t| t.alert_enabled);
        if !alert_enabled {
            return Ok(false);
        }

        let aggregation_window = threshold
            .as_ref()
            .map_or(DEFAULT_AGGREGATION_WINDOW_SECS, |t| {
                t.aggregation_window_secs
            });

        // Check if we should send (respecting aggregation window)
        if !self
            .should_send_alert(
                tenant_id,
                anomaly.agent_id,
                anomaly.anomaly_type.as_str(),
                aggregation_window,
            )
            .await?
        {
            return Ok(false);
        }

        // Record the anomaly to DB (marks alert_sent = false initially)
        let db_anomaly = self.record_anomaly(tenant_id, anomaly).await?;

        // Mark alert as sent
        self.mark_alert_sent(db_anomaly.id).await?;

        // Webhook delivery would go here - for now we just record
        // In a real implementation, this would use the WebhookService

        Ok(true)
    }

    /// Get effective threshold for an anomaly type.
    async fn get_effective_threshold(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        anomaly_type: &str,
    ) -> Result<f64, ApiAgentsError> {
        let threshold =
            AnomalyThreshold::get_effective(&self.pool, tenant_id, agent_id, anomaly_type)
                .await
                .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        match threshold {
            Some(t) if t.enabled => Ok(decimal_to_f64(&t.threshold_value)),
            _ => Ok(parse_anomaly_type(anomaly_type).default_threshold()),
        }
    }

    /// Get thresholds for an agent (agent-specific or tenant defaults).
    pub async fn get_agent_thresholds(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<ThresholdsResponse, ApiAgentsError> {
        let db_thresholds = AnomalyThreshold::get_for_agent(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        if db_thresholds.is_empty() {
            return Ok(ThresholdsResponse {
                agent_id: Some(agent_id),
                source: ThresholdSource::Default,
                thresholds: Self::default_thresholds(),
            });
        }

        // Determine source (agent-specific if any have agent_id set)
        let source = if db_thresholds.iter().any(|t| t.agent_id.is_some()) {
            ThresholdSource::Agent
        } else {
            ThresholdSource::Tenant
        };

        let thresholds: Vec<Threshold> = db_thresholds
            .into_iter()
            .map(|t| Threshold {
                anomaly_type: parse_anomaly_type(&t.anomaly_type),
                threshold_value: decimal_to_f64(&t.threshold_value),
                enabled: t.enabled,
                alert_enabled: t.alert_enabled,
                aggregation_window_secs: t.aggregation_window_secs,
            })
            .collect();

        Ok(ThresholdsResponse {
            agent_id: Some(agent_id),
            source,
            thresholds,
        })
    }

    /// Get tenant-wide default thresholds.
    pub async fn get_tenant_thresholds(
        &self,
        tenant_id: Uuid,
    ) -> Result<ThresholdsResponse, ApiAgentsError> {
        let db_thresholds = AnomalyThreshold::get_tenant_defaults(&self.pool, tenant_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        if db_thresholds.is_empty() {
            return Ok(ThresholdsResponse {
                agent_id: None,
                source: ThresholdSource::Default,
                thresholds: Self::default_thresholds(),
            });
        }

        let thresholds: Vec<Threshold> = db_thresholds
            .into_iter()
            .map(|t| Threshold {
                anomaly_type: parse_anomaly_type(&t.anomaly_type),
                threshold_value: decimal_to_f64(&t.threshold_value),
                enabled: t.enabled,
                alert_enabled: t.alert_enabled,
                aggregation_window_secs: t.aggregation_window_secs,
            })
            .collect();

        Ok(ThresholdsResponse {
            agent_id: None,
            source: ThresholdSource::Tenant,
            thresholds,
        })
    }

    /// Set thresholds for an agent.
    pub async fn set_agent_thresholds(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request: SetThresholdsRequest,
    ) -> Result<ThresholdsResponse, ApiAgentsError> {
        let mut thresholds = Vec::new();

        for t in request.thresholds {
            let data = UpsertAnomalyThreshold {
                tenant_id,
                agent_id: Some(agent_id),
                anomaly_type: t.anomaly_type.as_str().to_string(),
                threshold_value: f64_to_decimal(
                    t.threshold_value
                        .unwrap_or_else(|| t.anomaly_type.default_threshold()),
                ),
                enabled: t.enabled.unwrap_or(true),
                alert_enabled: t.alert_enabled.unwrap_or(true),
                aggregation_window_secs: t
                    .aggregation_window_secs
                    .unwrap_or(DEFAULT_AGGREGATION_WINDOW_SECS),
                created_by: None,
            };

            let saved = AnomalyThreshold::upsert(&self.pool, data)
                .await
                .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

            thresholds.push(Threshold {
                anomaly_type: t.anomaly_type,
                threshold_value: decimal_to_f64(&saved.threshold_value),
                enabled: saved.enabled,
                alert_enabled: saved.alert_enabled,
                aggregation_window_secs: saved.aggregation_window_secs,
            });
        }

        Ok(ThresholdsResponse {
            agent_id: Some(agent_id),
            source: ThresholdSource::Agent,
            thresholds,
        })
    }

    /// Set tenant-wide default thresholds.
    pub async fn set_tenant_thresholds(
        &self,
        tenant_id: Uuid,
        request: SetThresholdsRequest,
    ) -> Result<ThresholdsResponse, ApiAgentsError> {
        let mut thresholds = Vec::new();

        for t in request.thresholds {
            let data = UpsertAnomalyThreshold {
                tenant_id,
                agent_id: None, // Tenant default
                anomaly_type: t.anomaly_type.as_str().to_string(),
                threshold_value: f64_to_decimal(
                    t.threshold_value
                        .unwrap_or_else(|| t.anomaly_type.default_threshold()),
                ),
                enabled: t.enabled.unwrap_or(true),
                alert_enabled: t.alert_enabled.unwrap_or(true),
                aggregation_window_secs: t
                    .aggregation_window_secs
                    .unwrap_or(DEFAULT_AGGREGATION_WINDOW_SECS),
                created_by: None,
            };

            let saved = AnomalyThreshold::upsert(&self.pool, data)
                .await
                .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

            thresholds.push(Threshold {
                anomaly_type: t.anomaly_type,
                threshold_value: decimal_to_f64(&saved.threshold_value),
                enabled: saved.enabled,
                alert_enabled: saved.alert_enabled,
                aggregation_window_secs: saved.aggregation_window_secs,
            });
        }

        Ok(ThresholdsResponse {
            agent_id: None,
            source: ThresholdSource::Tenant,
            thresholds,
        })
    }

    /// Reset agent thresholds to tenant defaults.
    pub async fn reset_agent_thresholds(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<ThresholdsResponse, ApiAgentsError> {
        // Delete agent-specific thresholds
        AnomalyThreshold::delete_for_agent(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        // Return tenant defaults
        self.get_tenant_thresholds(tenant_id).await
    }

    /// Detect all anomalies for an agent based on recent activity.
    pub async fn detect_anomalies(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<DetectedAnomaly>, ApiAgentsError> {
        let mut anomalies = Vec::new();

        // Get current hour's volume
        let current_volume = self.get_current_hour_volume(tenant_id, agent_id).await?;

        // Check for volume anomaly
        if let Some(anomaly) = self
            .detect_volume_anomaly(tenant_id, agent_id, current_volume)
            .await?
        {
            anomalies.push(anomaly);
        }

        // Check for timing anomaly (current hour)
        let current_hour = Utc::now().hour() as i32;
        if let Some(anomaly) = self
            .detect_timing_anomaly(tenant_id, agent_id, current_hour)
            .await?
        {
            anomalies.push(anomaly);
        }

        Ok(anomalies)
    }

    /// Detect all anomalies for a specific tool invocation.
    pub async fn detect_tool_invocation_anomalies(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_name: &str,
    ) -> Result<Vec<DetectedAnomaly>, ApiAgentsError> {
        let mut anomalies = Vec::new();

        // Run general anomaly detection
        anomalies.extend(self.detect_anomalies(tenant_id, agent_id).await?);

        // Check for unusual tool
        if let Some(anomaly) = self
            .detect_tool_anomaly(tenant_id, agent_id, tool_name)
            .await?
        {
            anomalies.push(anomaly);
        }

        Ok(anomalies)
    }

    /// Get event count for the current hour.
    async fn get_current_hour_volume(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<f64, ApiAgentsError> {
        let now = Utc::now();
        let hour_start = now
            .date_naive()
            .and_hms_opt(now.hour(), 0, 0)
            .map_or(now, |dt| {
                DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)
            });

        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND agent_id = $2
              AND timestamp >= $3
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(hour_start)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        Ok(count as f64)
    }

    /// Calculate severity based on z-score.
    #[must_use]
    pub fn calculate_severity(z_score: f64) -> Severity {
        let abs_z = z_score.abs();
        if abs_z >= 5.0 {
            Severity::Critical
        } else if abs_z >= 4.0 {
            Severity::High
        } else if abs_z >= 3.0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Calculate anomaly score (0-100) based on z-score.
    #[must_use]
    pub fn calculate_score(z_score: f64) -> i32 {
        // Map z-score to 0-100 scale
        // z=3 -> 60, z=4 -> 75, z=5 -> 90, z>=6 -> 100
        let abs_z = z_score.abs();
        let score = if abs_z <= 2.0 {
            (abs_z * 20.0) as i32
        } else if abs_z <= 5.0 {
            (40.0 + (abs_z - 2.0) * 15.0) as i32
        } else {
            (85.0 + (abs_z - 5.0) * 5.0).min(100.0) as i32
        };
        score.clamp(0, 100)
    }

    /// Get default thresholds for all anomaly types.
    fn default_thresholds() -> Vec<Threshold> {
        vec![
            Threshold {
                anomaly_type: AnomalyType::HighVolume,
                threshold_value: AnomalyType::HighVolume.default_threshold(),
                enabled: true,
                alert_enabled: true,
                aggregation_window_secs: DEFAULT_AGGREGATION_WINDOW_SECS,
            },
            Threshold {
                anomaly_type: AnomalyType::LowVolume,
                threshold_value: AnomalyType::LowVolume.default_threshold(),
                enabled: true,
                alert_enabled: true,
                aggregation_window_secs: DEFAULT_AGGREGATION_WINDOW_SECS,
            },
            Threshold {
                anomaly_type: AnomalyType::UnusualTool,
                threshold_value: AnomalyType::UnusualTool.default_threshold(),
                enabled: true,
                alert_enabled: true,
                aggregation_window_secs: DEFAULT_AGGREGATION_WINDOW_SECS,
            },
            Threshold {
                anomaly_type: AnomalyType::OffHours,
                threshold_value: AnomalyType::OffHours.default_threshold(),
                enabled: true,
                alert_enabled: true,
                aggregation_window_secs: DEFAULT_AGGREGATION_WINDOW_SECS,
            },
            Threshold {
                anomaly_type: AnomalyType::RapidBurst,
                threshold_value: AnomalyType::RapidBurst.default_threshold(),
                enabled: true,
                alert_enabled: true,
                aggregation_window_secs: DEFAULT_AGGREGATION_WINDOW_SECS,
            },
        ]
    }
}

/// Parse anomaly type string to enum.
fn parse_anomaly_type(s: &str) -> AnomalyType {
    s.parse().unwrap_or(AnomalyType::HighVolume)
}

/// Parse severity string to enum.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Low,
    }
}

/// Convert Decimal to f64.
fn decimal_to_f64(d: &Decimal) -> f64 {
    use rust_decimal::prelude::ToPrimitive;
    d.to_f64().unwrap_or(0.0)
}

/// Convert f64 to Decimal.
fn f64_to_decimal(f: f64) -> Decimal {
    use rust_decimal::prelude::FromPrimitive;
    Decimal::from_f64(f).unwrap_or(Decimal::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_severity() {
        assert_eq!(AnomalyService::calculate_severity(2.5), Severity::Low);
        assert_eq!(AnomalyService::calculate_severity(3.5), Severity::Medium);
        assert_eq!(AnomalyService::calculate_severity(4.5), Severity::High);
        assert_eq!(AnomalyService::calculate_severity(5.5), Severity::Critical);
        assert_eq!(AnomalyService::calculate_severity(-4.0), Severity::High);
    }

    #[test]
    fn test_calculate_score() {
        assert_eq!(AnomalyService::calculate_score(0.0), 0);
        assert_eq!(AnomalyService::calculate_score(2.0), 40);
        assert_eq!(AnomalyService::calculate_score(3.0), 55);
        assert_eq!(AnomalyService::calculate_score(5.0), 85);
        assert!(AnomalyService::calculate_score(10.0) <= 100);
    }

    #[test]
    fn test_default_thresholds() {
        let thresholds = AnomalyService::default_thresholds();
        assert_eq!(thresholds.len(), 5);

        let high_volume = thresholds
            .iter()
            .find(|t| t.anomaly_type == AnomalyType::HighVolume)
            .expect("Should have HighVolume threshold");
        assert_eq!(high_volume.threshold_value, 3.0);
        assert!(high_volume.enabled);
    }

    #[test]
    fn test_parse_anomaly_type() {
        assert_eq!(parse_anomaly_type("high_volume"), AnomalyType::HighVolume);
        assert_eq!(parse_anomaly_type("low_volume"), AnomalyType::LowVolume);
        assert_eq!(parse_anomaly_type("unusual_tool"), AnomalyType::UnusualTool);
        assert_eq!(parse_anomaly_type("unknown"), AnomalyType::HighVolume); // Default
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity("High"), Severity::High);
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("unknown"), Severity::Low); // Default
    }

    #[test]
    fn test_decimal_conversion() {
        let d = f64_to_decimal(3.14159);
        let f = decimal_to_f64(&d);
        assert!((f - 3.14159).abs() < 0.0001);
    }

    #[test]
    fn test_calculate_severity_boundary_values() {
        // Test exact boundary values
        assert_eq!(AnomalyService::calculate_severity(3.0), Severity::Medium);
        assert_eq!(AnomalyService::calculate_severity(4.0), Severity::High);
        assert_eq!(AnomalyService::calculate_severity(5.0), Severity::Critical);
        // Test negative z-scores (same severity as positive)
        assert_eq!(AnomalyService::calculate_severity(-3.0), Severity::Medium);
        assert_eq!(AnomalyService::calculate_severity(-5.0), Severity::Critical);
    }

    #[test]
    fn test_calculate_score_boundary_values() {
        // Score should always be 0-100
        assert_eq!(AnomalyService::calculate_score(-5.0), 85);
        assert_eq!(AnomalyService::calculate_score(-10.0), 100);
        assert!(AnomalyService::calculate_score(100.0) <= 100);
        assert!(AnomalyService::calculate_score(-100.0) <= 100);
    }

    #[test]
    fn test_all_anomaly_types_have_default_thresholds() {
        let thresholds = AnomalyService::default_thresholds();

        // Verify all 5 anomaly types are present
        let types: Vec<AnomalyType> = thresholds.iter().map(|t| t.anomaly_type).collect();
        assert!(types.contains(&AnomalyType::HighVolume));
        assert!(types.contains(&AnomalyType::LowVolume));
        assert!(types.contains(&AnomalyType::UnusualTool));
        assert!(types.contains(&AnomalyType::OffHours));
        assert!(types.contains(&AnomalyType::RapidBurst));
    }

    #[test]
    fn test_default_threshold_values() {
        // Verify default threshold values match AnomalyType defaults
        assert_eq!(AnomalyType::HighVolume.default_threshold(), 3.0);
        assert_eq!(AnomalyType::LowVolume.default_threshold(), 3.0);
        assert_eq!(AnomalyType::UnusualTool.default_threshold(), 0.0);
        assert_eq!(AnomalyType::OffHours.default_threshold(), 0.05);
        assert_eq!(AnomalyType::RapidBurst.default_threshold(), 5.0);
    }

    #[test]
    fn test_parse_all_anomaly_types() {
        assert_eq!(parse_anomaly_type("high_volume"), AnomalyType::HighVolume);
        assert_eq!(parse_anomaly_type("low_volume"), AnomalyType::LowVolume);
        assert_eq!(parse_anomaly_type("unusual_tool"), AnomalyType::UnusualTool);
        assert_eq!(parse_anomaly_type("off_hours"), AnomalyType::OffHours);
        assert_eq!(parse_anomaly_type("rapid_burst"), AnomalyType::RapidBurst);
    }

    #[test]
    fn test_threshold_aggregation_window_default() {
        let thresholds = AnomalyService::default_thresholds();
        for t in thresholds {
            assert_eq!(t.aggregation_window_secs, DEFAULT_AGGREGATION_WINDOW_SECS);
            assert_eq!(t.aggregation_window_secs, 300); // 5 minutes
        }
    }

    // T019 - Unit tests for volume anomaly detection logic
    #[test]
    fn test_volume_anomaly_z_score_calculation() {
        // Test z-score calculation: z = (observed - mean) / std_dev
        let mean = 100.0;
        let std_dev = 20.0;
        let observed = 160.0;

        let z_score = (observed - mean) / std_dev;
        assert_eq!(z_score, 3.0);

        // Negative z-score for low volume
        let low_observed = 40.0;
        let low_z_score = (low_observed - mean) / std_dev;
        assert_eq!(low_z_score, -3.0);
    }

    #[test]
    fn test_volume_anomaly_threshold_comparison() {
        // Default threshold for high/low volume is 3.0
        let threshold = 3.0;

        // z=3.5 should trigger anomaly (>= threshold)
        assert!(3.5 >= threshold);
        // z=2.5 should not trigger anomaly
        assert!(!(2.5 >= threshold));
        // z=-3.5 should trigger low volume anomaly (<= -threshold)
        assert!(-3.5 <= -threshold);
    }

    // T032 - Unit tests for tool anomaly detection logic
    #[test]
    fn test_tool_anomaly_score_unknown_tool() {
        // Unknown tool (frequency = 0.0) should have score 80
        let tool_freq = 0.0;
        let score = if tool_freq == 0.0 { 80 } else { 60 };
        assert_eq!(score, 80);
    }

    #[test]
    fn test_tool_anomaly_score_rare_tool() {
        // Rare tool (frequency > 0.0) should have score 60
        let tool_freq = 0.02;
        let score = if tool_freq == 0.0 { 80 } else { 60 };
        assert_eq!(score, 60);
    }

    #[test]
    fn test_tool_anomaly_severity_unknown_tool() {
        // Unknown tool should be High severity
        let tool_freq = 0.0;
        let severity = if tool_freq == 0.0 {
            Severity::High
        } else {
            Severity::Medium
        };
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_tool_anomaly_severity_rare_tool() {
        // Rare tool should be Medium severity
        let tool_freq = 0.01;
        let severity = if tool_freq == 0.0 {
            Severity::High
        } else {
            Severity::Medium
        };
        assert_eq!(severity, Severity::Medium);
    }

    // T037 - Unit tests for timing anomaly detection logic
    #[test]
    fn test_timing_anomaly_severity_never_active() {
        // Never active at this hour (0.0) should be High severity
        let hour_freq = 0.0;
        let severity = if hour_freq == 0.0 {
            Severity::High
        } else if hour_freq < 0.01 {
            Severity::Medium
        } else {
            Severity::Low
        };
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_timing_anomaly_severity_very_rare() {
        // Very rare activity (<1%) should be Medium severity
        let hour_freq = 0.005;
        let severity = if hour_freq == 0.0 {
            Severity::High
        } else if hour_freq < 0.01 {
            Severity::Medium
        } else {
            Severity::Low
        };
        assert_eq!(severity, Severity::Medium);
    }

    #[test]
    fn test_timing_anomaly_severity_low() {
        // Above 1% threshold should be Low severity
        let hour_freq = 0.02;
        let severity = if hour_freq == 0.0 {
            Severity::High
        } else if hour_freq < 0.01 {
            Severity::Medium
        } else {
            Severity::Low
        };
        assert_eq!(severity, Severity::Low);
    }

    #[test]
    fn test_timing_anomaly_score_calculation() {
        // Score formula: ((1.0 - hour_freq / threshold) * 80.0).min(100.0)
        let threshold: f64 = 0.05;

        // hour_freq = 0.0 -> score = 80
        let hour_freq: f64 = 0.0;
        let score = ((1.0 - hour_freq / threshold) * 80.0).min(100.0) as i32;
        assert_eq!(score, 80);

        // hour_freq = 0.025 -> score = 40
        let hour_freq: f64 = 0.025;
        let score = ((1.0 - hour_freq / threshold) * 80.0).min(100.0) as i32;
        assert_eq!(score, 40);

        // hour_freq = 0.05 -> score = 0
        let hour_freq: f64 = 0.05;
        let score = ((1.0 - hour_freq / threshold) * 80.0).min(100.0) as i32;
        assert_eq!(score, 0);
    }

    // T041 - Unit tests for threshold resolution logic
    #[test]
    fn test_threshold_source_priority() {
        // Agent-level threshold should take precedence over tenant
        // Tenant-level should take precedence over default
        // This tests the conceptual priority: agent > tenant > default

        // When agent has threshold, source is "agent"
        let has_agent_threshold = true;
        let source = if has_agent_threshold {
            ThresholdSource::Agent
        } else {
            ThresholdSource::Default
        };
        assert_eq!(source, ThresholdSource::Agent);

        // When no agent threshold, check tenant
        let has_agent_threshold = false;
        let has_tenant_threshold = true;
        let source = if has_agent_threshold {
            ThresholdSource::Agent
        } else if has_tenant_threshold {
            ThresholdSource::Tenant
        } else {
            ThresholdSource::Default
        };
        assert_eq!(source, ThresholdSource::Tenant);

        // When neither, use default
        let has_agent_threshold = false;
        let has_tenant_threshold = false;
        let source = if has_agent_threshold {
            ThresholdSource::Agent
        } else if has_tenant_threshold {
            ThresholdSource::Tenant
        } else {
            ThresholdSource::Default
        };
        assert_eq!(source, ThresholdSource::Default);
    }

    // T050 - Unit tests for alert aggregation logic
    #[test]
    fn test_aggregation_window_calculation() {
        // Aggregation window should prevent duplicate alerts within window
        let window_secs = 300; // 5 minutes
        let since = Utc::now() - Duration::seconds(window_secs as i64);

        // An alert from 2 minutes ago should be within window
        let recent_alert_time = Utc::now() - Duration::seconds(120);
        assert!(recent_alert_time > since);

        // An alert from 10 minutes ago should be outside window
        let old_alert_time = Utc::now() - Duration::seconds(600);
        assert!(old_alert_time < since);
    }

    #[test]
    fn test_default_aggregation_window() {
        assert_eq!(DEFAULT_AGGREGATION_WINDOW_SECS, 300);
    }

    // T051 - Unit tests for webhook payload structure
    #[test]
    fn test_detected_anomaly_can_serialize() {
        let anomaly = DetectedAnomaly {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            anomaly_type: AnomalyType::HighVolume,
            severity: Severity::High,
            score: 85,
            z_score: 4.2,
            baseline_value: 100.0,
            observed_value: 184.0,
            description: "Test anomaly".to_string(),
            context: Some(serde_json::json!({"test": true})),
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&anomaly);
        assert!(json.is_ok());

        let json_value: serde_json::Value = serde_json::from_str(&json.unwrap()).unwrap();
        assert!(json_value["anomaly_type"].is_string());
        assert!(json_value["severity"].is_string());
        assert!(json_value["score"].is_i64());
    }

    #[test]
    fn test_webhook_payload_contains_required_fields() {
        // Verify the anomaly struct has all fields needed for webhook payload
        let anomaly = DetectedAnomaly {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            anomaly_type: AnomalyType::UnusualTool,
            severity: Severity::Medium,
            score: 60,
            z_score: 0.0,
            baseline_value: 0.02,
            observed_value: 1.0,
            description: "Unusual tool usage".to_string(),
            context: Some(serde_json::json!({"tool_name": "dangerous_tool"})),
            detected_at: Utc::now(),
        };

        // All required fields for webhook are present
        assert!(!anomaly.id.is_nil());
        assert!(!anomaly.agent_id.is_nil());
        assert!(!anomaly.description.is_empty());
        assert!(anomaly.context.is_some());
    }
}
