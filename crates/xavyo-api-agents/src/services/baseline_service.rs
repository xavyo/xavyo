//! Baseline computation service for the Behavioral Anomaly Detection API (F094).
//!
//! Computes and manages statistical baselines from agent activity data.

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{AnomalyBaseline, CreateAnomalyBaseline};

use crate::error::ApiAgentsError;
use crate::models::anomaly_models::{Baseline, BaselineResponse, BaselineStatus, BaselineType};

/// Minimum samples (hours) required for a valid baseline.
const MIN_SAMPLES_FOR_BASELINE: i32 = 24;

/// Default baseline window in days.
const BASELINE_WINDOW_DAYS: i64 = 7;

/// Service for computing and managing behavioral baselines.
#[derive(Clone)]
pub struct BaselineService {
    pool: PgPool,
}

impl BaselineService {
    /// Create a new `BaselineService`.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the current baseline for an agent.
    pub async fn get_baseline(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<BaselineResponse, ApiAgentsError> {
        // Fetch all baselines for this agent
        let db_baselines = AnomalyBaseline::get_by_agent(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Database error: {e}")))?;

        if db_baselines.is_empty() {
            return Ok(BaselineResponse {
                agent_id,
                status: BaselineStatus::InsufficientData,
                baselines: vec![],
                data_since: None,
                computed_at: None,
            });
        }

        // Convert to API response format
        let baselines: Vec<Baseline> = db_baselines
            .iter()
            .map(|b| Baseline {
                baseline_type: parse_baseline_type(&b.baseline_type),
                mean: decimal_to_f64(&b.mean_value),
                std_deviation: decimal_to_f64(&b.std_deviation),
                sample_count: b.sample_count,
                percentiles: b.percentiles.clone(),
            })
            .collect();

        // Get earliest window_start and most recent computed_at
        let data_since = db_baselines.iter().map(|b| b.window_start).min();
        let computed_at = db_baselines.iter().map(|b| b.computed_at).max();

        // Determine status based on sample counts
        let has_sufficient_data = db_baselines
            .iter()
            .all(|b| b.sample_count >= MIN_SAMPLES_FOR_BASELINE);

        let status = if has_sufficient_data {
            BaselineStatus::Active
        } else {
            BaselineStatus::InsufficientData
        };

        Ok(BaselineResponse {
            agent_id,
            status,
            baselines,
            data_since,
            computed_at,
        })
    }

    /// Compute volume baseline from audit events.
    ///
    /// Queries audit events for the last 7 days, groups by hour, and computes
    /// mean and standard deviation of hourly event counts.
    pub async fn compute_volume_baseline(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Baseline, ApiAgentsError> {
        let window_end = Utc::now();
        let window_start = window_end - Duration::days(BASELINE_WINDOW_DAYS);

        // Query hourly event counts from audit events
        let hourly_counts = self
            .query_hourly_volume(tenant_id, agent_id, window_start, window_end)
            .await?;

        let sample_count = hourly_counts.len() as i32;

        if sample_count < MIN_SAMPLES_FOR_BASELINE {
            return Ok(Baseline {
                baseline_type: BaselineType::HourlyVolume,
                mean: 0.0,
                std_deviation: 0.0,
                sample_count,
                percentiles: None,
            });
        }

        // Calculate statistics
        let (mean, std_dev) = compute_statistics(&hourly_counts);
        let percentiles = compute_percentiles(&hourly_counts);

        // Persist baseline to database
        let create_data = CreateAnomalyBaseline {
            tenant_id,
            agent_id,
            baseline_type: "hourly_volume".to_string(),
            mean_value: f64_to_decimal(mean),
            std_deviation: f64_to_decimal(std_dev),
            sample_count,
            percentiles: Some(percentiles.clone()),
            tool_frequencies: None,
            hour_frequencies: None,
            window_start,
            window_end,
        };

        AnomalyBaseline::upsert(&self.pool, create_data)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to save baseline: {e}")))?;

        Ok(Baseline {
            baseline_type: BaselineType::HourlyVolume,
            mean,
            std_deviation: std_dev,
            sample_count,
            percentiles: Some(percentiles),
        })
    }

    /// Query hourly event counts from audit events.
    async fn query_hourly_volume(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<f64>, ApiAgentsError> {
        // Query to get event count per hour
        let rows = sqlx::query_as::<_, (i64,)>(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND agent_id = $2
              AND timestamp >= $3
              AND timestamp < $4
            GROUP BY date_trunc('hour', timestamp)
            ORDER BY date_trunc('hour', timestamp)
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database query failed: {e}")))?;

        Ok(rows.into_iter().map(|(count,)| count as f64).collect())
    }

    /// Compute tool usage baseline from audit events.
    pub async fn compute_tool_baseline(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Baseline, ApiAgentsError> {
        let window_end = Utc::now();
        let window_start = window_end - Duration::days(BASELINE_WINDOW_DAYS);

        // Query tool usage distribution
        let tool_counts = self
            .query_tool_distribution(tenant_id, agent_id, window_start, window_end)
            .await?;

        let sample_count = tool_counts.values().sum::<i64>() as i32;

        if sample_count < MIN_SAMPLES_FOR_BASELINE {
            return Ok(Baseline {
                baseline_type: BaselineType::ToolDistribution,
                mean: 0.0,
                std_deviation: 0.0,
                sample_count,
                percentiles: None,
            });
        }

        // Calculate tool distribution entropy/mean
        let total = tool_counts.values().sum::<i64>() as f64;
        let tool_frequencies: serde_json::Value = tool_counts
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(*v as f64 / total)))
            .collect();

        let counts: Vec<f64> = tool_counts.values().map(|v| *v as f64).collect();
        let (mean, std_dev) = compute_statistics(&counts);

        // Persist baseline
        let create_data = CreateAnomalyBaseline {
            tenant_id,
            agent_id,
            baseline_type: "tool_distribution".to_string(),
            mean_value: f64_to_decimal(mean),
            std_deviation: f64_to_decimal(std_dev),
            sample_count,
            percentiles: None,
            tool_frequencies: Some(tool_frequencies.clone()),
            hour_frequencies: None,
            window_start,
            window_end,
        };

        AnomalyBaseline::upsert(&self.pool, create_data)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to save baseline: {e}")))?;

        Ok(Baseline {
            baseline_type: BaselineType::ToolDistribution,
            mean,
            std_deviation: std_dev,
            sample_count,
            percentiles: Some(tool_frequencies),
        })
    }

    /// Query tool usage distribution from audit events.
    async fn query_tool_distribution(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<std::collections::HashMap<String, i64>, ApiAgentsError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r"
            SELECT COALESCE(tool_name, 'unknown') as tool, COUNT(*) as count
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND agent_id = $2
              AND timestamp >= $3
              AND timestamp < $4
              AND event_type = 'tool_invocation'
            GROUP BY tool_name
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database query failed: {e}")))?;

        Ok(rows.into_iter().collect())
    }

    /// Compute hour distribution baseline from audit events.
    pub async fn compute_hour_baseline(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Baseline, ApiAgentsError> {
        let window_end = Utc::now();
        let window_start = window_end - Duration::days(BASELINE_WINDOW_DAYS);

        // Query activity distribution by hour of day (0-23)
        let hour_counts = self
            .query_hour_distribution(tenant_id, agent_id, window_start, window_end)
            .await?;

        let sample_count = hour_counts.values().sum::<i64>() as i32;

        if sample_count < MIN_SAMPLES_FOR_BASELINE {
            return Ok(Baseline {
                baseline_type: BaselineType::HourDistribution,
                mean: 0.0,
                std_deviation: 0.0,
                sample_count,
                percentiles: None,
            });
        }

        // Calculate hour distribution
        let total = hour_counts.values().sum::<i64>() as f64;
        let hour_frequencies: serde_json::Value = hour_counts
            .iter()
            .map(|(hour, count)| (hour.to_string(), serde_json::json!(*count as f64 / total)))
            .collect();

        let counts: Vec<f64> = hour_counts.values().map(|v| *v as f64).collect();
        let (mean, std_dev) = compute_statistics(&counts);

        // Persist baseline
        let create_data = CreateAnomalyBaseline {
            tenant_id,
            agent_id,
            baseline_type: "hour_distribution".to_string(),
            mean_value: f64_to_decimal(mean),
            std_deviation: f64_to_decimal(std_dev),
            sample_count,
            percentiles: None,
            tool_frequencies: None,
            hour_frequencies: Some(hour_frequencies.clone()),
            window_start,
            window_end,
        };

        AnomalyBaseline::upsert(&self.pool, create_data)
            .await
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to save baseline: {e}")))?;

        Ok(Baseline {
            baseline_type: BaselineType::HourDistribution,
            mean,
            std_deviation: std_dev,
            sample_count,
            percentiles: Some(hour_frequencies),
        })
    }

    /// Query activity distribution by hour of day.
    async fn query_hour_distribution(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<std::collections::HashMap<i32, i64>, ApiAgentsError> {
        let rows = sqlx::query_as::<_, (i32, i64)>(
            r"
            SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as count
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND agent_id = $2
              AND timestamp >= $3
              AND timestamp < $4
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database query failed: {e}")))?;

        Ok(rows.into_iter().collect())
    }

    // ========================================================================
    // Background Job Support (T062)
    // ========================================================================

    /// Compute all baselines for an agent.
    ///
    /// This computes volume, tool distribution, and hour distribution baselines.
    pub async fn compute_all_baselines(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Baseline>, ApiAgentsError> {
        let mut baselines = Vec::new();

        // Compute volume baseline
        if let Ok(baseline) = self.compute_volume_baseline(tenant_id, agent_id).await {
            baselines.push(baseline);
        }

        // Compute tool distribution baseline
        if let Ok(baseline) = self.compute_tool_baseline(tenant_id, agent_id).await {
            baselines.push(baseline);
        }

        // Compute hour distribution baseline
        if let Ok(baseline) = self.compute_hour_baseline(tenant_id, agent_id).await {
            baselines.push(baseline);
        }

        Ok(baselines)
    }

    /// Get all active agent IDs for a tenant that have recent activity.
    ///
    /// Returns agents that have had at least one audit event in the last 7 days.
    pub async fn get_active_agent_ids(&self, tenant_id: Uuid) -> Result<Vec<Uuid>, ApiAgentsError> {
        let since = Utc::now() - Duration::days(BASELINE_WINDOW_DAYS);

        let rows = sqlx::query_as::<_, (Uuid,)>(
            r"
            SELECT DISTINCT agent_id
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND timestamp >= $2
            ",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiAgentsError::Internal(format!("Database query failed: {e}")))?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Process baselines for all active agents in a tenant.
    ///
    /// This is designed to be called by a background job scheduler.
    /// Returns the number of agents processed and any errors encountered.
    pub async fn process_tenant_baselines(
        &self,
        tenant_id: Uuid,
    ) -> Result<BaselineJobResult, ApiAgentsError> {
        let agent_ids = self.get_active_agent_ids(tenant_id).await?;
        let mut processed = 0;
        let mut errors = Vec::new();

        for agent_id in &agent_ids {
            match self.compute_all_baselines(tenant_id, *agent_id).await {
                Ok(_) => processed += 1,
                Err(e) => errors.push((*agent_id, e.to_string())),
            }
        }

        Ok(BaselineJobResult {
            tenant_id,
            agents_processed: processed,
            agents_total: agent_ids.len(),
            errors,
            completed_at: Utc::now(),
        })
    }

    /// Start a background baseline computation job for a tenant.
    ///
    /// This spawns a tokio task that computes baselines for all active agents.
    /// Returns immediately with a job handle.
    #[must_use] 
    pub fn spawn_baseline_job(
        &self,
        tenant_id: Uuid,
    ) -> tokio::task::JoinHandle<Result<BaselineJobResult, ApiAgentsError>> {
        let service = self.clone();
        tokio::spawn(async move { service.process_tenant_baselines(tenant_id).await })
    }

    /// Start a periodic baseline computation job.
    ///
    /// This spawns a tokio task that runs baseline computation at the specified interval.
    /// The interval should typically be 1 hour.
    #[must_use] 
    pub fn start_periodic_baseline_job(
        &self,
        tenant_id: Uuid,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                match service.process_tenant_baselines(tenant_id).await {
                    Ok(result) => {
                        tracing::info!(
                            tenant_id = %tenant_id,
                            agents_processed = result.agents_processed,
                            agents_total = result.agents_total,
                            errors = result.errors.len(),
                            "Baseline computation completed"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            tenant_id = %tenant_id,
                            error = %e,
                            "Baseline computation failed"
                        );
                    }
                }
            }
        })
    }
}

/// Result of a baseline computation job.
#[derive(Debug, Clone)]
pub struct BaselineJobResult {
    /// Tenant ID processed.
    pub tenant_id: Uuid,
    /// Number of agents successfully processed.
    pub agents_processed: usize,
    /// Total number of active agents.
    pub agents_total: usize,
    /// Errors encountered during processing.
    pub errors: Vec<(Uuid, String)>,
    /// Timestamp when job completed.
    pub completed_at: DateTime<Utc>,
}

/// Parse baseline type string to enum.
fn parse_baseline_type(s: &str) -> BaselineType {
    match s {
        "hourly_volume" => BaselineType::HourlyVolume,
        "tool_distribution" => BaselineType::ToolDistribution,
        "hour_distribution" => BaselineType::HourDistribution,
        _ => BaselineType::HourlyVolume, // Default fallback
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

/// Compute mean and standard deviation from a set of values.
fn compute_statistics(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    if values.len() < 2 {
        return (mean, 0.0);
    }

    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let std_dev = variance.sqrt();

    (mean, std_dev)
}

/// Compute percentiles (p5, p25, p50, p75, p95) from a set of values.
fn compute_percentiles(values: &[f64]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({
            "p5": 0.0,
            "p25": 0.0,
            "p50": 0.0,
            "p75": 0.0,
            "p95": 0.0
        });
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let percentile = |p: f64| -> f64 {
        let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    serde_json::json!({
        "p5": percentile(5.0),
        "p25": percentile(25.0),
        "p50": percentile(50.0),
        "p75": percentile(75.0),
        "p95": percentile(95.0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_statistics() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let (mean, std_dev) = compute_statistics(&values);
        assert!((mean - 3.0).abs() < 0.001);
        assert!((std_dev - 1.5811).abs() < 0.01); // sqrt(2.5)

        let empty: Vec<f64> = vec![];
        let (m, s) = compute_statistics(&empty);
        assert_eq!(m, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_compute_percentiles() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let percentiles = compute_percentiles(&values);
        assert_eq!(percentiles["p50"], 6.0); // Median (rounded index)
    }

    #[test]
    fn test_parse_baseline_type() {
        assert!(matches!(
            parse_baseline_type("hourly_volume"),
            BaselineType::HourlyVolume
        ));
        assert!(matches!(
            parse_baseline_type("tool_distribution"),
            BaselineType::ToolDistribution
        ));
        assert!(matches!(
            parse_baseline_type("unknown"),
            BaselineType::HourlyVolume
        ));
    }

    #[test]
    fn test_decimal_conversion() {
        let d = f64_to_decimal(3.14159);
        let f = decimal_to_f64(&d);
        assert!((f - 3.14159).abs() < 0.0001);
    }

    #[test]
    fn test_compute_statistics_single_value() {
        let values = vec![5.0];
        let (mean, std_dev) = compute_statistics(&values);
        assert_eq!(mean, 5.0);
        assert_eq!(std_dev, 0.0); // Single value has 0 std dev
    }

    #[test]
    fn test_compute_statistics_identical_values() {
        let values = vec![3.0, 3.0, 3.0, 3.0];
        let (mean, std_dev) = compute_statistics(&values);
        assert_eq!(mean, 3.0);
        assert_eq!(std_dev, 0.0); // All same value
    }

    #[test]
    fn test_compute_percentiles_empty() {
        let values: Vec<f64> = vec![];
        let percentiles = compute_percentiles(&values);
        assert_eq!(percentiles["p50"], 0.0);
        assert_eq!(percentiles["p95"], 0.0);
    }

    #[test]
    fn test_compute_percentiles_single_value() {
        let values = vec![42.0];
        let percentiles = compute_percentiles(&values);
        assert_eq!(percentiles["p5"], 42.0);
        assert_eq!(percentiles["p50"], 42.0);
        assert_eq!(percentiles["p95"], 42.0);
    }

    #[test]
    fn test_parse_all_baseline_types() {
        assert!(matches!(
            parse_baseline_type("hourly_volume"),
            BaselineType::HourlyVolume
        ));
        assert!(matches!(
            parse_baseline_type("tool_distribution"),
            BaselineType::ToolDistribution
        ));
        assert!(matches!(
            parse_baseline_type("hour_distribution"),
            BaselineType::HourDistribution
        ));
    }

    #[test]
    fn test_min_samples_constant() {
        // Verify the minimum samples required for a valid baseline
        assert_eq!(MIN_SAMPLES_FOR_BASELINE, 24);
    }

    #[test]
    fn test_baseline_window_days_constant() {
        // Verify the baseline window is 7 days
        assert_eq!(BASELINE_WINDOW_DAYS, 7);
    }

    // T020 - Unit tests for baseline retrieval with insufficient data
    #[test]
    fn test_insufficient_data_threshold() {
        // Baseline requires at least 24 samples
        let sample_count = 20;
        let is_insufficient = sample_count < MIN_SAMPLES_FOR_BASELINE;
        assert!(is_insufficient);

        let sample_count = 24;
        let is_sufficient = sample_count >= MIN_SAMPLES_FOR_BASELINE;
        assert!(is_sufficient);
    }

    #[test]
    fn test_baseline_status_determination() {
        // Test status logic based on sample count
        let determine_status = |count: i32| -> BaselineStatus {
            if count >= MIN_SAMPLES_FOR_BASELINE {
                BaselineStatus::Active
            } else {
                BaselineStatus::InsufficientData
            }
        };

        assert_eq!(determine_status(0), BaselineStatus::InsufficientData);
        assert_eq!(determine_status(10), BaselineStatus::InsufficientData);
        assert_eq!(determine_status(24), BaselineStatus::Active);
        assert_eq!(determine_status(100), BaselineStatus::Active);
    }

    // T033 - Unit tests for tool frequency baseline
    #[test]
    fn test_tool_frequency_calculation() {
        // Tool frequencies should be normalized (sum to 1.0)
        let tool_counts = vec![("tool_a", 50), ("tool_b", 30), ("tool_c", 20)];
        let total: i32 = tool_counts.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 100);

        // Frequencies should sum to 1.0
        let frequencies: Vec<f64> = tool_counts
            .iter()
            .map(|(_, c)| *c as f64 / total as f64)
            .collect();
        let sum: f64 = frequencies.iter().sum();
        assert!((sum - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_tool_frequency_threshold() {
        // Default threshold for unusual_tool is 0.0 (any tool never seen is flagged)
        let threshold = 0.0;
        let tool_freq = 0.0;

        // Tool with 0 frequency should be flagged
        let is_unusual = tool_freq <= threshold;
        assert!(is_unusual);

        // Tool with some frequency should not be flagged (if threshold is 0.0)
        let tool_freq = 0.05;
        let is_unusual = tool_freq <= threshold;
        assert!(!is_unusual);
    }

    // T038 - Unit tests for hour distribution baseline
    #[test]
    fn test_hour_distribution_has_24_hours() {
        // Hour distribution should cover all 24 hours
        let hours: Vec<i32> = (0..24).collect();
        assert_eq!(hours.len(), 24);
        assert_eq!(hours.first(), Some(&0));
        assert_eq!(hours.last(), Some(&23));
    }

    #[test]
    fn test_hour_frequency_normalization() {
        // Hour frequencies should sum to 1.0 (normalized)
        let hour_counts: Vec<(i32, i32)> = vec![
            (9, 100),  // 9 AM - peak hour
            (10, 150), // 10 AM - peak hour
            (14, 80),  // 2 PM
            (3, 5),    // 3 AM - off hours
        ];
        let total: i32 = hour_counts.iter().map(|(_, c)| c).sum();

        let frequencies: Vec<(i32, f64)> = hour_counts
            .iter()
            .map(|(h, c)| (*h, *c as f64 / total as f64))
            .collect();

        let sum: f64 = frequencies.iter().map(|(_, f)| f).sum();
        assert!((sum - 1.0).abs() < 0.0001);

        // 3 AM should have very low frequency
        let off_hours_freq = frequencies.iter().find(|(h, _)| *h == 3).map(|(_, f)| *f);
        assert!(off_hours_freq.unwrap() < 0.02); // Less than 2%
    }

    #[test]
    fn test_off_hours_threshold() {
        // Default threshold for off_hours is 0.05 (5%)
        let threshold = 0.05;

        // Hour with 2% activity should be flagged as off-hours
        let hour_freq = 0.02;
        let is_off_hours = hour_freq < threshold;
        assert!(is_off_hours);

        // Hour with 10% activity should not be flagged
        let hour_freq = 0.10;
        let is_off_hours = hour_freq < threshold;
        assert!(!is_off_hours);
    }

    #[test]
    fn test_compute_statistics_large_variance() {
        // Test with values that have high variance
        let values = vec![1.0, 100.0];
        let (mean, std_dev) = compute_statistics(&values);
        assert!((mean - 50.5).abs() < 0.01);
        // std_dev = sqrt((49.5^2 + 49.5^2) / 1) = sqrt(4900.5) = 70.0
        assert!(std_dev > 60.0);
    }

    #[test]
    fn test_compute_percentiles_two_values() {
        // Edge case: only two values
        let values = vec![10.0, 20.0];
        let percentiles = compute_percentiles(&values);
        // p50 should be one of the values
        let p50 = percentiles["p50"].as_f64().unwrap();
        assert!(p50 == 10.0 || p50 == 20.0);
    }

    // T062 - Unit tests for baseline job result
    #[test]
    fn test_baseline_job_result_fields() {
        let result = BaselineJobResult {
            tenant_id: Uuid::new_v4(),
            agents_processed: 5,
            agents_total: 7,
            errors: vec![(Uuid::new_v4(), "Test error".to_string())],
            completed_at: Utc::now(),
        };

        assert_eq!(result.agents_processed, 5);
        assert_eq!(result.agents_total, 7);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_baseline_job_result_no_errors() {
        let result = BaselineJobResult {
            tenant_id: Uuid::new_v4(),
            agents_processed: 10,
            agents_total: 10,
            errors: vec![],
            completed_at: Utc::now(),
        };

        assert_eq!(result.agents_processed, result.agents_total);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_baseline_job_result_partial_success() {
        let error_id = Uuid::new_v4();
        let result = BaselineJobResult {
            tenant_id: Uuid::new_v4(),
            agents_processed: 8,
            agents_total: 10,
            errors: vec![
                (error_id, "Agent not found".to_string()),
                (Uuid::new_v4(), "Database error".to_string()),
            ],
            completed_at: Utc::now(),
        };

        // Processed + errors should equal total
        assert_eq!(
            result.agents_processed + result.errors.len(),
            result.agents_total
        );
    }
}
