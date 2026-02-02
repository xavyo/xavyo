//! Connector Reconciliation Run model for F049 Reconciliation Engine.
//!
//! Represents a reconciliation execution against a connector.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Mode of reconciliation run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReconciliationMode {
    /// Full reconciliation - compare all accounts.
    #[default]
    Full,
    /// Delta reconciliation - only changes since last sync.
    Delta,
}

impl fmt::Display for ConnectorReconciliationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Delta => write!(f, "delta"),
        }
    }
}

impl std::str::FromStr for ConnectorReconciliationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "delta" => Ok(Self::Delta),
            _ => Err(format!("Unknown reconciliation mode: {}", s)),
        }
    }
}

/// Status of a reconciliation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReconciliationStatus {
    /// Run is pending to start.
    Pending,
    /// Run is currently executing.
    Running,
    /// Run completed successfully.
    Completed,
    /// Run failed with error.
    Failed,
    /// Run was cancelled.
    Cancelled,
}

impl ConnectorReconciliationStatus {
    /// Check if this status is terminal (run has ended).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Check if run can be cancelled.
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Pending | Self::Running)
    }

    /// Check if run can be resumed.
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }
}

impl fmt::Display for ConnectorReconciliationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for ConnectorReconciliationStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("Unknown reconciliation status: {}", s)),
        }
    }
}

/// A connector reconciliation run record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConnectorReconciliationRun {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub mode: String,
    pub status: String,
    pub triggered_by: Option<Uuid>,
    pub checkpoint: Option<JsonValue>,
    pub statistics: JsonValue,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ConnectorReconciliationRun {
    /// Get the mode enum.
    pub fn mode(&self) -> ConnectorReconciliationMode {
        self.mode.parse().unwrap_or_default()
    }

    /// Get the status enum.
    pub fn status(&self) -> ConnectorReconciliationStatus {
        self.status
            .parse()
            .unwrap_or(ConnectorReconciliationStatus::Pending)
    }

    /// Create a new reconciliation run.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &CreateConnectorReconciliationRun,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_connector_reconciliation_runs (
                tenant_id, connector_id, mode, triggered_by, status, started_at
            )
            VALUES ($1, $2, $3, $4, 'running', NOW())
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.connector_id)
        .bind(input.mode.to_string())
        .bind(input.triggered_by)
        .fetch_one(pool)
        .await
    }

    /// Find run by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_connector_reconciliation_runs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find running reconciliation for a connector.
    pub async fn find_running(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_connector_reconciliation_runs
            WHERE tenant_id = $1 AND connector_id = $2 AND status = 'running'
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// List runs for a connector with filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ConnectorReconciliationRunFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from(r#"SELECT * FROM gov_connector_reconciliation_runs WHERE tenant_id = $1"#);
        let mut param_idx = 2;

        if filter.connector_id.is_some() {
            query.push_str(&format!(" AND connector_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.mode.is_some() {
            query.push_str(&format!(" AND mode = ${}", param_idx));
            param_idx += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_idx));
            param_idx += 1;
        }

        if filter.triggered_by.is_some() {
            query.push_str(&format!(" AND triggered_by = ${}", param_idx));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND created_at >= ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(ref mode) = filter.mode {
            q = q.bind(mode.to_string());
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }
        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q = q.bind(limit).bind(offset);
        q.fetch_all(pool).await
    }

    /// Count runs for a tenant with filtering.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ConnectorReconciliationRunFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"SELECT COUNT(*) FROM gov_connector_reconciliation_runs WHERE tenant_id = $1"#,
        );
        let mut param_idx = 2;

        if filter.connector_id.is_some() {
            query.push_str(&format!(" AND connector_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.mode.is_some() {
            query.push_str(&format!(" AND mode = ${}", param_idx));
            param_idx += 1;
        }
        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_idx));
            param_idx += 1;
        }
        if filter.triggered_by.is_some() {
            query.push_str(&format!(" AND triggered_by = ${}", param_idx));
            param_idx += 1;
        }
        if filter.since.is_some() {
            query.push_str(&format!(" AND created_at >= ${}", param_idx));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(ref mode) = filter.mode {
            q = q.bind(mode.to_string());
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }
        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q.fetch_one(pool).await
    }

    /// Update checkpoint and statistics.
    pub async fn update_progress(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        checkpoint: Option<JsonValue>,
        statistics: JsonValue,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_connector_reconciliation_runs
            SET checkpoint = $3, statistics = $4
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(checkpoint)
        .bind(statistics)
        .fetch_optional(pool)
        .await
    }

    /// Mark run as completed.
    pub async fn mark_completed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        statistics: JsonValue,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_connector_reconciliation_runs
            SET status = 'completed', completed_at = NOW(), statistics = $3, checkpoint = NULL
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(statistics)
        .fetch_optional(pool)
        .await
    }

    /// Mark run as failed.
    pub async fn mark_failed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
        statistics: JsonValue,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_connector_reconciliation_runs
            SET status = 'failed', completed_at = NOW(), error_message = $3, statistics = $4
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .bind(statistics)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a running reconciliation.
    pub async fn cancel(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_connector_reconciliation_runs
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'running')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Resume a failed or cancelled run.
    pub async fn resume(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_connector_reconciliation_runs
            SET status = 'running', started_at = NOW(), completed_at = NULL, error_message = NULL
            WHERE id = $1 AND tenant_id = $2 AND status IN ('failed', 'cancelled')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a run.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_connector_reconciliation_runs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get the most recent completed run for a connector.
    pub async fn find_last_completed(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_connector_reconciliation_runs
            WHERE tenant_id = $1 AND connector_id = $2 AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }
}

/// Input for creating a reconciliation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateConnectorReconciliationRun {
    pub connector_id: Uuid,
    pub mode: ConnectorReconciliationMode,
    pub triggered_by: Option<Uuid>,
}

/// Filter for listing reconciliation runs.
#[derive(Debug, Clone, Default)]
pub struct ConnectorReconciliationRunFilter {
    pub connector_id: Option<Uuid>,
    pub mode: Option<ConnectorReconciliationMode>,
    pub status: Option<ConnectorReconciliationStatus>,
    pub triggered_by: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
}

impl ConnectorReconciliationRunFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_connector(mut self, connector_id: Uuid) -> Self {
        self.connector_id = Some(connector_id);
        self
    }

    pub fn with_mode(mut self, mode: ConnectorReconciliationMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn with_status(mut self, status: ConnectorReconciliationStatus) -> Self {
        self.status = Some(status);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_roundtrip() {
        for mode in [
            ConnectorReconciliationMode::Full,
            ConnectorReconciliationMode::Delta,
        ] {
            let s = mode.to_string();
            let parsed: ConnectorReconciliationMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_status_roundtrip() {
        for status in [
            ConnectorReconciliationStatus::Pending,
            ConnectorReconciliationStatus::Running,
            ConnectorReconciliationStatus::Completed,
            ConnectorReconciliationStatus::Failed,
            ConnectorReconciliationStatus::Cancelled,
        ] {
            let s = status.to_string();
            let parsed: ConnectorReconciliationStatus = s.parse().unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_status_terminal() {
        assert!(!ConnectorReconciliationStatus::Pending.is_terminal());
        assert!(!ConnectorReconciliationStatus::Running.is_terminal());
        assert!(ConnectorReconciliationStatus::Completed.is_terminal());
        assert!(ConnectorReconciliationStatus::Failed.is_terminal());
        assert!(ConnectorReconciliationStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_status_can_cancel() {
        assert!(ConnectorReconciliationStatus::Pending.can_cancel());
        assert!(ConnectorReconciliationStatus::Running.can_cancel());
        assert!(!ConnectorReconciliationStatus::Completed.can_cancel());
        assert!(!ConnectorReconciliationStatus::Failed.can_cancel());
        assert!(!ConnectorReconciliationStatus::Cancelled.can_cancel());
    }

    #[test]
    fn test_status_can_resume() {
        assert!(!ConnectorReconciliationStatus::Pending.can_resume());
        assert!(!ConnectorReconciliationStatus::Running.can_resume());
        assert!(!ConnectorReconciliationStatus::Completed.can_resume());
        assert!(ConnectorReconciliationStatus::Failed.can_resume());
        assert!(ConnectorReconciliationStatus::Cancelled.can_resume());
    }
}
