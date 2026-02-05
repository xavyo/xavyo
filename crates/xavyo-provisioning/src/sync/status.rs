//! Sync status tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use super::error::SyncResult;
use super::types::SyncState;

/// Real-time sync status for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Connector ID (primary key).
    pub connector_id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Current sync state.
    pub current_state: SyncState,
    /// When the last sync started.
    pub last_sync_started_at: Option<DateTime<Utc>>,
    /// When the last sync completed.
    pub last_sync_completed_at: Option<DateTime<Utc>>,
    /// Last sync error (if any).
    pub last_sync_error: Option<String>,
    /// Total changes processed.
    pub changes_processed: i64,
    /// Changes pending processing.
    pub changes_pending: i32,
    /// Conflicts pending resolution.
    pub conflicts_pending: i32,
    /// Current processing rate (changes/minute).
    pub current_rate: f64,
    /// Whether throttling is active.
    pub is_throttled: bool,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

impl SyncStatus {
    /// Create a new sync status for a connector.
    #[must_use]
    pub fn new(tenant_id: Uuid, connector_id: Uuid) -> Self {
        Self {
            connector_id,
            tenant_id,
            current_state: SyncState::Idle,
            last_sync_started_at: None,
            last_sync_completed_at: None,
            last_sync_error: None,
            changes_processed: 0,
            changes_pending: 0,
            conflicts_pending: 0,
            current_rate: 0.0,
            is_throttled: false,
            updated_at: Utc::now(),
        }
    }

    /// Check if sync is active.
    #[must_use]
    pub fn is_syncing(&self) -> bool {
        self.current_state.is_active()
    }

    /// Check if there was an error.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.current_state == SyncState::Error
    }
}

/// Manager for sync status.
#[derive(Debug, Clone)]
pub struct SyncStatusManager {
    pool: PgPool,
}

impl SyncStatusManager {
    /// Create a new sync status manager.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get status for a connector.
    #[instrument(skip(self))]
    pub async fn get(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            SELECT connector_id, tenant_id, current_state, last_sync_started_at,
                   last_sync_completed_at, last_sync_error, changes_processed,
                   changes_pending, conflicts_pending, current_rate, is_throttled,
                   updated_at
            FROM gov_sync_status
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Initialize status for a new connector.
    #[instrument(skip(self))]
    pub async fn initialize(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<SyncStatus> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            INSERT INTO gov_sync_status (connector_id, tenant_id)
            VALUES ($1, $2)
            ON CONFLICT (connector_id) DO UPDATE SET updated_at = NOW()
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.into_status())
    }

    /// Mark sync as started.
    #[instrument(skip(self))]
    pub async fn start_sync(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET current_state = 'syncing',
                last_sync_started_at = NOW(),
                last_sync_error = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Mark sync as completed.
    #[instrument(skip(self))]
    pub async fn complete_sync(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        changes_processed: i64,
    ) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET current_state = 'idle',
                last_sync_completed_at = NOW(),
                changes_processed = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(changes_processed)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Set error state.
    #[instrument(skip(self))]
    pub async fn set_error(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        error: &str,
    ) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET current_state = 'error',
                last_sync_error = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(error)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Update throttling status.
    #[instrument(skip(self))]
    pub async fn set_throttled(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        is_throttled: bool,
    ) -> SyncResult<Option<SyncStatus>> {
        let state = if is_throttled { "throttled" } else { "syncing" };
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET current_state = $3,
                is_throttled = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(state)
        .bind(is_throttled)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Update pending counts.
    #[instrument(skip(self))]
    pub async fn update_pending_counts(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        changes_pending: i32,
        conflicts_pending: i32,
    ) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET changes_pending = $3,
                conflicts_pending = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(changes_pending)
        .bind(conflicts_pending)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// Update current processing rate.
    #[instrument(skip(self))]
    pub async fn update_rate(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        rate: f64,
    ) -> SyncResult<Option<SyncStatus>> {
        let result = sqlx::query_as::<_, SyncStatusRow>(
            r"
            UPDATE gov_sync_status
            SET current_rate = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING connector_id, tenant_id, current_state, last_sync_started_at,
                      last_sync_completed_at, last_sync_error, changes_processed,
                      changes_pending, conflicts_pending, current_rate, is_throttled,
                      updated_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(rate)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncStatusRow::into_status))
    }

    /// List all statuses for a tenant.
    #[instrument(skip(self))]
    pub async fn list_by_tenant(&self, tenant_id: Uuid) -> SyncResult<Vec<SyncStatus>> {
        let rows = sqlx::query_as::<_, SyncStatusRow>(
            r"
            SELECT connector_id, tenant_id, current_state, last_sync_started_at,
                   last_sync_completed_at, last_sync_error, changes_processed,
                   changes_pending, conflicts_pending, current_rate, is_throttled,
                   updated_at
            FROM gov_sync_status
            WHERE tenant_id = $1
            ORDER BY updated_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(SyncStatusRow::into_status).collect())
    }
}

/// Database row for sync status.
#[derive(Debug, sqlx::FromRow)]
struct SyncStatusRow {
    connector_id: Uuid,
    tenant_id: Uuid,
    current_state: String,
    last_sync_started_at: Option<DateTime<Utc>>,
    last_sync_completed_at: Option<DateTime<Utc>>,
    last_sync_error: Option<String>,
    changes_processed: i64,
    changes_pending: i32,
    conflicts_pending: i32,
    current_rate: f64,
    is_throttled: bool,
    updated_at: DateTime<Utc>,
}

impl SyncStatusRow {
    fn into_status(self) -> SyncStatus {
        SyncStatus {
            connector_id: self.connector_id,
            tenant_id: self.tenant_id,
            current_state: self.current_state.parse().unwrap_or(SyncState::Idle),
            last_sync_started_at: self.last_sync_started_at,
            last_sync_completed_at: self.last_sync_completed_at,
            last_sync_error: self.last_sync_error,
            changes_processed: self.changes_processed,
            changes_pending: self.changes_pending,
            conflicts_pending: self.conflicts_pending,
            current_rate: self.current_rate,
            is_throttled: self.is_throttled,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_status_new() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let status = SyncStatus::new(tenant_id, connector_id);

        assert_eq!(status.tenant_id, tenant_id);
        assert_eq!(status.connector_id, connector_id);
        assert_eq!(status.current_state, SyncState::Idle);
        assert!(!status.is_syncing());
        assert!(!status.has_error());
    }
}
