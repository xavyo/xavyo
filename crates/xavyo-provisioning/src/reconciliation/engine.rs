//! Reconciliation engine orchestrator.
//!
//! Main entry point for reconciliation operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::checkpoint::{Checkpoint, CheckpointManager};
use super::statistics::RunStatistics;
use super::types::{ReconciliationMode, RunStatus};

/// Configuration for reconciliation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationConfig {
    /// Batch size for processing accounts.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Maximum retries for transient failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Checkpoint interval (save every N batches).
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: usize,
    /// Attributes to compare (empty = all).
    #[serde(default)]
    pub comparison_attributes: Vec<String>,
    /// Whether to ignore case in comparisons.
    #[serde(default = "default_ignore_case")]
    pub ignore_case: bool,
}

fn default_batch_size() -> usize {
    1000
}

fn default_max_retries() -> usize {
    3
}

fn default_checkpoint_interval() -> usize {
    5
}

fn default_ignore_case() -> bool {
    true
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            max_retries: default_max_retries(),
            checkpoint_interval: default_checkpoint_interval(),
            comparison_attributes: vec![],
            ignore_case: default_ignore_case(),
        }
    }
}

/// Information about a reconciliation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationRunInfo {
    /// Run ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    /// Reconciliation mode.
    pub mode: ReconciliationMode,
    /// Run status.
    pub status: RunStatus,
    /// User who triggered the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<Uuid>,
    /// Name of user who triggered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by_name: Option<String>,
    /// Checkpoint for resumption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
    /// Run statistics.
    pub statistics: RunStatistics,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// When the run started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When the run completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Record creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
    /// Progress percentage (calculated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percentage: Option<f64>,
}

impl ReconciliationRunInfo {
    /// Calculate progress percentage.
    #[must_use]
    pub fn calculate_progress(&self) -> f64 {
        self.statistics.progress_percentage()
    }
}

/// Reconciliation engine for orchestrating reconciliation runs.
pub struct ReconciliationEngine {
    pool: PgPool,
    config: ReconciliationConfig,
    checkpoint_manager: CheckpointManager,
}

impl ReconciliationEngine {
    /// Create a new reconciliation engine.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            checkpoint_manager: CheckpointManager::new(pool.clone()),
            pool,
            config: ReconciliationConfig::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(pool: PgPool, config: ReconciliationConfig) -> Self {
        Self {
            checkpoint_manager: CheckpointManager::new(pool.clone()),
            pool,
            config,
        }
    }

    /// Start a new reconciliation run.
    pub async fn start_reconciliation(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        mode: ReconciliationMode,
        triggered_by: Option<Uuid>,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        // Check for existing running reconciliation
        if let Some(existing) = self.find_running_run(tenant_id, connector_id).await? {
            return Err(ReconciliationError::AlreadyRunning {
                run_id: existing.id,
                connector_id,
            });
        }

        // Create new run record
        let run = self
            .create_run(tenant_id, connector_id, mode, triggered_by)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            run_id = %run.id,
            mode = %mode,
            "Started reconciliation run"
        );

        Ok(run)
    }

    /// Cancel a running reconciliation.
    pub async fn cancel_reconciliation(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        let run = self
            .get_run(tenant_id, run_id)
            .await?
            .ok_or(ReconciliationError::RunNotFound { run_id })?;

        if !run.status.can_cancel() {
            return Err(ReconciliationError::InvalidState {
                run_id,
                expected: "pending or running".to_string(),
                actual: run.status.to_string(),
            });
        }

        let updated = self
            .update_run_status(tenant_id, run_id, RunStatus::Cancelled, None)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            run_id = %run_id,
            "Cancelled reconciliation run"
        );

        Ok(updated)
    }

    /// Resume a failed reconciliation from checkpoint.
    pub async fn resume_reconciliation(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        let run = self
            .get_run(tenant_id, run_id)
            .await?
            .ok_or(ReconciliationError::RunNotFound { run_id })?;

        if !run.status.can_resume() {
            return Err(ReconciliationError::InvalidState {
                run_id,
                expected: "failed".to_string(),
                actual: run.status.to_string(),
            });
        }

        if run.checkpoint.is_none() {
            return Err(ReconciliationError::NoCheckpoint { run_id });
        }

        // Reset status to running
        let updated = self
            .update_run_status(tenant_id, run_id, RunStatus::Running, None)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            run_id = %run_id,
            checkpoint = ?run.checkpoint,
            "Resumed reconciliation run"
        );

        Ok(updated)
    }

    /// Get a reconciliation run by ID.
    pub async fn get_run(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationResult<Option<ReconciliationRunInfo>> {
        let row: Option<ReconciliationRunRow> = sqlx::query_as(
            r"
            SELECT
                r.id, r.tenant_id, r.connector_id, r.mode, r.status,
                r.triggered_by, r.checkpoint, r.statistics, r.error_message,
                r.started_at, r.completed_at, r.created_at, r.updated_at,
                c.name as connector_name,
                u.email as triggered_by_name
            FROM gov_connector_reconciliation_runs r
            LEFT JOIN connector_configurations c ON c.id = r.connector_id
            LEFT JOIN users u ON u.id = r.triggered_by
            WHERE r.id = $1 AND r.tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReconciliationError::Database(e.to_string()))?;

        Ok(row.map(ReconciliationRunRow::into_info))
    }

    /// Find a running reconciliation for a connector.
    async fn find_running_run(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ReconciliationResult<Option<ReconciliationRunInfo>> {
        let row: Option<ReconciliationRunRow> = sqlx::query_as(
            r"
            SELECT
                r.id, r.tenant_id, r.connector_id, r.mode, r.status,
                r.triggered_by, r.checkpoint, r.statistics, r.error_message,
                r.started_at, r.completed_at, r.created_at, r.updated_at,
                NULL as connector_name,
                NULL as triggered_by_name
            FROM gov_connector_reconciliation_runs r
            WHERE r.tenant_id = $1 AND r.connector_id = $2 AND r.status = 'running'
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReconciliationError::Database(e.to_string()))?;

        Ok(row.map(ReconciliationRunRow::into_info))
    }

    /// Create a new run record.
    async fn create_run(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        mode: ReconciliationMode,
        triggered_by: Option<Uuid>,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        let row: ReconciliationRunRow = sqlx::query_as(
            r"
            INSERT INTO gov_connector_reconciliation_runs
                (tenant_id, connector_id, mode, status, triggered_by, started_at)
            VALUES ($1, $2, $3, 'running', $4, NOW())
            RETURNING
                id, tenant_id, connector_id, mode, status,
                triggered_by, checkpoint, statistics, error_message,
                started_at, completed_at, created_at, updated_at,
                NULL as connector_name,
                NULL as triggered_by_name
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(mode.to_string())
        .bind(triggered_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ReconciliationError::Database(e.to_string()))?;

        Ok(row.into_info())
    }

    /// Update run status.
    async fn update_run_status(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        status: RunStatus,
        error_message: Option<String>,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        let completed_at = if status.is_terminal() {
            Some(Utc::now())
        } else {
            None
        };

        let row: ReconciliationRunRow = sqlx::query_as(
            r"
            UPDATE gov_connector_reconciliation_runs
            SET
                status = $3,
                completed_at = COALESCE($4, completed_at),
                error_message = COALESCE($5, error_message),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING
                id, tenant_id, connector_id, mode, status,
                triggered_by, checkpoint, statistics, error_message,
                started_at, completed_at, created_at, updated_at,
                NULL as connector_name,
                NULL as triggered_by_name
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(status.to_string())
        .bind(completed_at)
        .bind(error_message)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ReconciliationError::Database(e.to_string()))?;

        Ok(row.into_info())
    }

    /// Update run statistics.
    pub async fn update_run_statistics(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        statistics: &RunStatistics,
    ) -> ReconciliationResult<()> {
        let stats_json = serde_json::to_value(statistics)
            .map_err(|e| ReconciliationError::Serialization(e.to_string()))?;

        sqlx::query(
            r"
            UPDATE gov_connector_reconciliation_runs
            SET statistics = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(&stats_json)
        .execute(&self.pool)
        .await
        .map_err(|e| ReconciliationError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark run as completed.
    pub async fn complete_run(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        statistics: &RunStatistics,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        // Clear checkpoint
        self.checkpoint_manager
            .clear(tenant_id, run_id)
            .await
            .map_err(|e| ReconciliationError::Checkpoint(e.to_string()))?;

        // Update stats and status
        self.update_run_statistics(tenant_id, run_id, statistics)
            .await?;
        self.update_run_status(tenant_id, run_id, RunStatus::Completed, None)
            .await
    }

    /// Mark run as failed.
    pub async fn fail_run(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        error: &str,
        statistics: &RunStatistics,
    ) -> ReconciliationResult<ReconciliationRunInfo> {
        self.update_run_statistics(tenant_id, run_id, statistics)
            .await?;
        self.update_run_status(
            tenant_id,
            run_id,
            RunStatus::Failed,
            Some(error.to_string()),
        )
        .await
    }

    /// Save checkpoint.
    pub async fn save_checkpoint(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        checkpoint: &Checkpoint,
    ) -> ReconciliationResult<()> {
        self.checkpoint_manager
            .save(tenant_id, run_id, checkpoint)
            .await
            .map_err(|e| ReconciliationError::Checkpoint(e.to_string()))
    }

    /// Get configuration.
    #[must_use]
    pub fn config(&self) -> &ReconciliationConfig {
        &self.config
    }
}

/// Row from database query.
#[derive(Debug, sqlx::FromRow)]
struct ReconciliationRunRow {
    id: Uuid,
    tenant_id: Uuid,
    connector_id: Uuid,
    mode: String,
    status: String,
    triggered_by: Option<Uuid>,
    checkpoint: Option<serde_json::Value>,
    statistics: serde_json::Value,
    error_message: Option<String>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    connector_name: Option<String>,
    triggered_by_name: Option<String>,
}

impl ReconciliationRunRow {
    fn into_info(self) -> ReconciliationRunInfo {
        let mode = self.mode.parse().unwrap_or(ReconciliationMode::Full);
        let status = self.status.parse().unwrap_or(RunStatus::Pending);
        let checkpoint = self.checkpoint.and_then(|v| serde_json::from_value(v).ok());
        let statistics: RunStatistics = serde_json::from_value(self.statistics).unwrap_or_default();

        let mut info = ReconciliationRunInfo {
            id: self.id,
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            connector_name: self.connector_name,
            mode,
            status,
            triggered_by: self.triggered_by,
            triggered_by_name: self.triggered_by_name,
            checkpoint,
            statistics,
            error_message: self.error_message,
            started_at: self.started_at,
            completed_at: self.completed_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            progress_percentage: None,
        };

        info.progress_percentage = Some(info.calculate_progress());
        info
    }
}

/// Result type for reconciliation operations.
pub type ReconciliationResult<T> = Result<T, ReconciliationError>;

/// Errors that can occur during reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Run not found.
    #[error("Reconciliation run not found: {run_id}")]
    RunNotFound { run_id: Uuid },

    /// Run already in progress.
    #[error("Reconciliation already running for connector {connector_id}: run {run_id}")]
    AlreadyRunning { run_id: Uuid, connector_id: Uuid },

    /// Invalid state transition.
    #[error("Invalid state for run {run_id}: expected {expected}, got {actual}")]
    InvalidState {
        run_id: Uuid,
        expected: String,
        actual: String,
    },

    /// No checkpoint available for resume.
    #[error("No checkpoint available for run {run_id}")]
    NoCheckpoint { run_id: Uuid },

    /// Checkpoint error.
    #[error("Checkpoint error: {0}")]
    Checkpoint(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Connector error.
    #[error("Connector error: {0}")]
    Connector(String),

    /// Correlation error.
    #[error("Correlation error: {0}")]
    Correlation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_config_default() {
        let config = ReconciliationConfig::default();
        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.checkpoint_interval, 5);
        assert!(config.ignore_case);
    }

    #[test]
    fn test_run_status_transitions() {
        assert!(RunStatus::Pending.can_cancel());
        assert!(RunStatus::Running.can_cancel());
        assert!(!RunStatus::Completed.can_cancel());
        assert!(!RunStatus::Failed.can_cancel());

        assert!(!RunStatus::Pending.can_resume());
        assert!(!RunStatus::Running.can_resume());
        assert!(!RunStatus::Completed.can_resume());
        assert!(RunStatus::Failed.can_resume());
    }

    #[test]
    fn test_run_status_terminal() {
        assert!(!RunStatus::Pending.is_terminal());
        assert!(!RunStatus::Running.is_terminal());
        assert!(RunStatus::Completed.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
        assert!(RunStatus::Cancelled.is_terminal());
    }
}
