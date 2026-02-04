//! Sync Status model for tracking real-time synchronization state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Current state of synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    /// Not currently syncing.
    Idle,
    /// Actively syncing.
    Syncing,
    /// Sync paused.
    Paused,
    /// Sync error occurred.
    Error,
    /// Rate limited.
    Throttled,
}

impl fmt::Display for SyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncState::Idle => write!(f, "idle"),
            SyncState::Syncing => write!(f, "syncing"),
            SyncState::Paused => write!(f, "paused"),
            SyncState::Error => write!(f, "error"),
            SyncState::Throttled => write!(f, "throttled"),
        }
    }
}

impl std::str::FromStr for SyncState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "idle" => Ok(SyncState::Idle),
            "syncing" => Ok(SyncState::Syncing),
            "paused" => Ok(SyncState::Paused),
            "error" => Ok(SyncState::Error),
            "throttled" => Ok(SyncState::Throttled),
            _ => Err(format!("Unknown sync state: {s}")),
        }
    }
}

/// Sync status for a connector.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SyncStatus {
    pub connector_id: Uuid,
    pub tenant_id: Uuid,
    pub current_state: String,
    pub last_sync_started_at: Option<DateTime<Utc>>,
    pub last_sync_completed_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub changes_processed: i64,
    pub changes_pending: i32,
    pub conflicts_pending: i32,
    pub current_rate: f64,
    pub is_throttled: bool,
    pub updated_at: DateTime<Utc>,
}

impl SyncStatus {
    /// Get the current state enum.
    #[must_use] 
    pub fn current_state(&self) -> SyncState {
        self.current_state.parse().unwrap_or(SyncState::Idle)
    }

    /// Get current rate as f64.
    #[must_use] 
    pub fn current_rate_f64(&self) -> f64 {
        self.current_rate
    }

    /// Create or update sync status.
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &UpsertSyncStatus,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sync_status (
                connector_id, tenant_id, current_state, last_sync_started_at,
                last_sync_completed_at, last_sync_error, changes_processed,
                changes_pending, conflicts_pending, current_rate, is_throttled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (connector_id) DO UPDATE SET
                current_state = EXCLUDED.current_state,
                last_sync_started_at = COALESCE(EXCLUDED.last_sync_started_at, gov_sync_status.last_sync_started_at),
                last_sync_completed_at = COALESCE(EXCLUDED.last_sync_completed_at, gov_sync_status.last_sync_completed_at),
                last_sync_error = EXCLUDED.last_sync_error,
                changes_processed = EXCLUDED.changes_processed,
                changes_pending = EXCLUDED.changes_pending,
                conflicts_pending = EXCLUDED.conflicts_pending,
                current_rate = EXCLUDED.current_rate,
                is_throttled = EXCLUDED.is_throttled,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(input.current_state.to_string())
        .bind(input.last_sync_started_at)
        .bind(input.last_sync_completed_at)
        .bind(&input.last_sync_error)
        .bind(input.changes_processed)
        .bind(input.changes_pending)
        .bind(input.conflicts_pending)
        .bind(input.current_rate)
        .bind(input.is_throttled)
        .fetch_one(pool)
        .await
    }

    /// Find by connector ID.
    pub async fn find_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_status
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// List all sync statuses for a tenant.
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_status
            WHERE tenant_id = $1
            ORDER BY updated_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update state to syncing and record start time.
    pub async fn start_sync(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET current_state = 'syncing',
                last_sync_started_at = NOW(),
                last_sync_error = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Update state to idle and record completion time.
    pub async fn complete_sync(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        changes_processed: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET current_state = 'idle',
                last_sync_completed_at = NOW(),
                changes_processed = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(changes_processed)
        .fetch_optional(pool)
        .await
    }

    /// Update state to error.
    pub async fn set_error(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        error: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET current_state = 'error',
                last_sync_error = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(error)
        .fetch_optional(pool)
        .await
    }

    /// Update throttling status.
    pub async fn set_throttled(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        is_throttled: bool,
    ) -> Result<Option<Self>, sqlx::Error> {
        let state = if is_throttled { "throttled" } else { "syncing" };
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET current_state = $3,
                is_throttled = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(state)
        .bind(is_throttled)
        .fetch_optional(pool)
        .await
    }

    /// Update pending counts.
    pub async fn update_pending_counts(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        changes_pending: i32,
        conflicts_pending: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET changes_pending = $3,
                conflicts_pending = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(changes_pending)
        .bind(conflicts_pending)
        .fetch_optional(pool)
        .await
    }

    /// Update current processing rate.
    pub async fn update_rate(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        rate: f64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_status
            SET current_rate = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(rate)
        .fetch_optional(pool)
        .await
    }

    /// Initialize status for a new connector.
    pub async fn initialize(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let input = UpsertSyncStatus::default();
        Self::upsert(pool, tenant_id, connector_id, &input).await
    }

    /// Delete sync status.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sync_status
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Input for upserting sync status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSyncStatus {
    pub current_state: SyncState,
    pub last_sync_started_at: Option<DateTime<Utc>>,
    pub last_sync_completed_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub changes_processed: i64,
    pub changes_pending: i32,
    pub conflicts_pending: i32,
    pub current_rate: f64,
    pub is_throttled: bool,
}

impl Default for UpsertSyncStatus {
    fn default() -> Self {
        Self {
            current_state: SyncState::Idle,
            last_sync_started_at: None,
            last_sync_completed_at: None,
            last_sync_error: None,
            changes_processed: 0,
            changes_pending: 0,
            conflicts_pending: 0,
            current_rate: 0.0,
            is_throttled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state_roundtrip() {
        for state in [
            SyncState::Idle,
            SyncState::Syncing,
            SyncState::Paused,
            SyncState::Error,
            SyncState::Throttled,
        ] {
            let s = state.to_string();
            let parsed: SyncState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn test_upsert_sync_status_defaults() {
        let status = UpsertSyncStatus::default();
        assert_eq!(status.current_state, SyncState::Idle);
        assert_eq!(status.changes_processed, 0);
        assert_eq!(status.changes_pending, 0);
        assert_eq!(status.conflicts_pending, 0);
        assert!(!status.is_throttled);
    }
}
