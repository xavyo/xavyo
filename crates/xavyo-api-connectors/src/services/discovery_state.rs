//! Discovery State Manager for schema discovery tracking.
//!
//! Provides in-memory state tracking and PostgreSQL advisory locks
//! to prevent concurrent schema discoveries for the same connector.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use chrono::Utc;
use sqlx::PgPool;
use tracing::{debug, info, warn};
use uuid::Uuid;

use xavyo_connector::schema::{DiscoveryState, DiscoveryStatus};

use crate::error::{ConnectorApiError, Result};

/// Advisory lock namespace for schema discovery.
/// This prevents concurrent discoveries on the same connector.
const DISCOVERY_LOCK_NAMESPACE: i32 = 46001; // F046 feature number + 001

/// Default discovery timeout in seconds (30 seconds).
pub const DEFAULT_DISCOVERY_TIMEOUT_SECS: u64 = 30;

/// Maximum discovery timeout in seconds (5 minutes).
pub const MAX_DISCOVERY_TIMEOUT_SECS: u64 = 300;

/// Manager for tracking schema discovery state.
///
/// Uses in-memory state for quick lookups and PostgreSQL advisory locks
/// to prevent concurrent discoveries across multiple API instances.
pub struct DiscoveryStateManager {
    pool: PgPool,
    /// In-memory cache of discovery states by connector_id.
    states: Arc<RwLock<HashMap<Uuid, DiscoveryStatus>>>,
    /// Discovery timeout duration.
    timeout: Duration,
}

impl DiscoveryStateManager {
    /// Create a new discovery state manager with default timeout.
    pub fn new(pool: PgPool) -> Self {
        Self::with_timeout(pool, Duration::from_secs(DEFAULT_DISCOVERY_TIMEOUT_SECS))
    }

    /// Create a new discovery state manager with a custom timeout.
    pub fn with_timeout(pool: PgPool, timeout: Duration) -> Self {
        // Clamp timeout to maximum
        let timeout = if timeout.as_secs() > MAX_DISCOVERY_TIMEOUT_SECS {
            warn!(
                requested = timeout.as_secs(),
                max = MAX_DISCOVERY_TIMEOUT_SECS,
                "Discovery timeout clamped to maximum"
            );
            Duration::from_secs(MAX_DISCOVERY_TIMEOUT_SECS)
        } else {
            timeout
        };

        Self {
            pool,
            states: Arc::new(RwLock::new(HashMap::new())),
            timeout,
        }
    }

    /// Get the configured timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Try to acquire a discovery lock for a connector.
    ///
    /// Returns `Ok(true)` if lock acquired, `Ok(false)` if already locked.
    /// Uses PostgreSQL advisory locks to coordinate across instances.
    pub async fn try_acquire_lock(&self, connector_id: Uuid) -> Result<bool> {
        // Convert UUID to i64 for advisory lock (use first 8 bytes)
        let lock_key = uuid_to_lock_key(connector_id);

        // Try to acquire advisory lock (non-blocking)
        let result: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1, $2)")
            .bind(DISCOVERY_LOCK_NAMESPACE)
            .bind(lock_key)
            .fetch_one(&self.pool)
            .await?;

        if result.0 {
            debug!(
                connector_id = %connector_id,
                lock_key = lock_key,
                "Acquired discovery lock"
            );
        } else {
            debug!(
                connector_id = %connector_id,
                lock_key = lock_key,
                "Discovery lock already held by another process"
            );
        }

        Ok(result.0)
    }

    /// Release a discovery lock for a connector.
    pub async fn release_lock(&self, connector_id: Uuid) -> Result<()> {
        let lock_key = uuid_to_lock_key(connector_id);

        let _: (bool,) = sqlx::query_as("SELECT pg_advisory_unlock($1, $2)")
            .bind(DISCOVERY_LOCK_NAMESPACE)
            .bind(lock_key)
            .fetch_one(&self.pool)
            .await?;

        debug!(
            connector_id = %connector_id,
            lock_key = lock_key,
            "Released discovery lock"
        );

        Ok(())
    }

    /// Start a discovery operation.
    ///
    /// Acquires the lock and updates in-memory state.
    /// Returns error if lock cannot be acquired.
    pub async fn start_discovery(&self, connector_id: Uuid) -> Result<DiscoveryStatus> {
        // Try to acquire the lock
        if !self.try_acquire_lock(connector_id).await? {
            // Check if we already have a status
            let states = self.states.read().await;
            if let Some(status) = states.get(&connector_id) {
                if status.state == DiscoveryState::InProgress {
                    return Err(ConnectorApiError::Conflict(format!(
                        "Schema discovery already in progress for connector {}",
                        connector_id
                    )));
                }
            }
            return Err(ConnectorApiError::Conflict(format!(
                "Could not acquire discovery lock for connector {}",
                connector_id
            )));
        }

        // Create initial status
        let status = DiscoveryStatus {
            connector_id,
            state: DiscoveryState::InProgress,
            started_at: Some(Utc::now()),
            completed_at: None,
            progress_percent: Some(0),
            current_object_class: None,
            error: None,
            version: None,
        };

        // Update in-memory state
        {
            let mut states = self.states.write().await;
            states.insert(connector_id, status.clone());
        }

        info!(
            connector_id = %connector_id,
            "Started schema discovery"
        );

        Ok(status)
    }

    /// Update discovery progress.
    pub async fn update_progress(
        &self,
        connector_id: Uuid,
        progress_percent: i32,
        current_object_class: Option<String>,
    ) -> Result<()> {
        let mut states = self.states.write().await;

        if let Some(status) = states.get_mut(&connector_id) {
            status.progress_percent = Some(progress_percent);
            status.current_object_class = current_object_class.clone();

            debug!(
                connector_id = %connector_id,
                progress = progress_percent,
                current = ?current_object_class,
                "Updated discovery progress"
            );
        }

        Ok(())
    }

    /// Complete a discovery operation successfully.
    pub async fn complete_discovery(
        &self,
        connector_id: Uuid,
        version: i32,
    ) -> Result<DiscoveryStatus> {
        // Update in-memory state
        let status = {
            let mut states = self.states.write().await;

            let status = states
                .entry(connector_id)
                .or_insert_with(|| DiscoveryStatus {
                    connector_id,
                    state: DiscoveryState::Idle,
                    started_at: None,
                    completed_at: None,
                    progress_percent: None,
                    current_object_class: None,
                    error: None,
                    version: None,
                });

            status.state = DiscoveryState::Completed;
            status.completed_at = Some(Utc::now());
            status.progress_percent = Some(100);
            status.current_object_class = None;
            status.version = Some(version);
            status.error = None;

            status.clone()
        };

        // Release the lock
        if let Err(e) = self.release_lock(connector_id).await {
            warn!(
                connector_id = %connector_id,
                error = %e,
                "Failed to release discovery lock"
            );
        }

        info!(
            connector_id = %connector_id,
            version = version,
            "Completed schema discovery"
        );

        Ok(status)
    }

    /// Mark a discovery operation as failed.
    pub async fn fail_discovery(
        &self,
        connector_id: Uuid,
        error: String,
    ) -> Result<DiscoveryStatus> {
        // Update in-memory state
        let status = {
            let mut states = self.states.write().await;

            let status = states
                .entry(connector_id)
                .or_insert_with(|| DiscoveryStatus {
                    connector_id,
                    state: DiscoveryState::Idle,
                    started_at: None,
                    completed_at: None,
                    progress_percent: None,
                    current_object_class: None,
                    error: None,
                    version: None,
                });

            status.state = DiscoveryState::Failed;
            status.completed_at = Some(Utc::now());
            status.current_object_class = None;
            status.error = Some(error.clone());

            status.clone()
        };

        // Release the lock
        if let Err(e) = self.release_lock(connector_id).await {
            warn!(
                connector_id = %connector_id,
                error = %e,
                "Failed to release discovery lock after failure"
            );
        }

        warn!(
            connector_id = %connector_id,
            error = %error,
            "Schema discovery failed"
        );

        Ok(status)
    }

    /// Get the current discovery status for a connector.
    pub async fn get_status(&self, connector_id: Uuid) -> Option<DiscoveryStatus> {
        let states = self.states.read().await;
        states.get(&connector_id).cloned()
    }

    /// Get discovery statuses for multiple connectors.
    pub async fn get_statuses(&self, connector_ids: &[Uuid]) -> HashMap<Uuid, DiscoveryStatus> {
        let states = self.states.read().await;
        connector_ids
            .iter()
            .filter_map(|id| states.get(id).map(|s| (*id, s.clone())))
            .collect()
    }

    /// Clear old completed/failed statuses from memory.
    ///
    /// Statuses older than the specified duration are removed.
    pub async fn cleanup_old_statuses(&self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        let mut states = self.states.write().await;

        let to_remove: Vec<Uuid> = states
            .iter()
            .filter(|(_, status)| {
                // Remove completed/failed statuses that are old
                matches!(
                    status.state,
                    DiscoveryState::Completed | DiscoveryState::Failed
                ) && status.completed_at.map(|t| t < cutoff).unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            states.remove(&id);
        }
    }

    /// Check if a discovery is currently in progress for a connector.
    pub async fn is_discovery_in_progress(&self, connector_id: Uuid) -> bool {
        let states = self.states.read().await;
        states
            .get(&connector_id)
            .map(|s| s.state == DiscoveryState::InProgress)
            .unwrap_or(false)
    }

    /// Reset a stuck discovery (for recovery scenarios).
    ///
    /// This should only be used when a discovery appears stuck and
    /// needs to be manually reset.
    pub async fn reset_stuck_discovery(&self, connector_id: Uuid) -> Result<()> {
        // Release any held lock
        if let Err(e) = self.release_lock(connector_id).await {
            debug!(
                connector_id = %connector_id,
                error = %e,
                "No lock to release during reset"
            );
        }

        // Clear in-memory state
        {
            let mut states = self.states.write().await;
            states.remove(&connector_id);
        }

        info!(
            connector_id = %connector_id,
            "Reset stuck discovery state"
        );

        Ok(())
    }

    /// Check if a discovery has timed out.
    ///
    /// Returns true if the discovery has been running longer than the configured timeout.
    pub async fn is_discovery_timed_out(&self, connector_id: Uuid) -> bool {
        let states = self.states.read().await;
        if let Some(status) = states.get(&connector_id) {
            if status.state == DiscoveryState::InProgress {
                if let Some(started_at) = status.started_at {
                    let elapsed = Utc::now().signed_duration_since(started_at);
                    return elapsed.num_seconds() as u64 > self.timeout.as_secs();
                }
            }
        }
        false
    }

    /// Auto-fail timed-out discoveries.
    ///
    /// Checks all in-progress discoveries and marks those that have exceeded
    /// the timeout as failed. Returns the number of discoveries that were timed out.
    pub async fn cleanup_timed_out_discoveries(&self) -> u32 {
        let mut timed_out: Vec<Uuid> = Vec::new();

        // Identify timed-out discoveries
        {
            let states = self.states.read().await;
            for (connector_id, status) in states.iter() {
                if status.state == DiscoveryState::InProgress {
                    if let Some(started_at) = status.started_at {
                        let elapsed = Utc::now().signed_duration_since(started_at);
                        if elapsed.num_seconds() as u64 > self.timeout.as_secs() {
                            timed_out.push(*connector_id);
                        }
                    }
                }
            }
        }

        // Fail each timed-out discovery
        let count = timed_out.len() as u32;
        for connector_id in timed_out {
            let error = format!(
                "Schema discovery timed out after {} seconds",
                self.timeout.as_secs()
            );
            warn!(
                connector_id = %connector_id,
                timeout_secs = self.timeout.as_secs(),
                "Discovery timed out, marking as failed"
            );
            if let Err(e) = self.fail_discovery(connector_id, error).await {
                warn!(
                    connector_id = %connector_id,
                    error = %e,
                    "Failed to mark timed-out discovery as failed"
                );
            }
        }

        count
    }

    /// Get remaining time before timeout for an in-progress discovery.
    ///
    /// Returns None if no discovery is in progress or if already timed out.
    pub async fn get_remaining_timeout(&self, connector_id: Uuid) -> Option<Duration> {
        let states = self.states.read().await;
        if let Some(status) = states.get(&connector_id) {
            if status.state == DiscoveryState::InProgress {
                if let Some(started_at) = status.started_at {
                    let elapsed = Utc::now().signed_duration_since(started_at);
                    let elapsed_secs = elapsed.num_seconds() as u64;
                    if elapsed_secs < self.timeout.as_secs() {
                        return Some(Duration::from_secs(self.timeout.as_secs() - elapsed_secs));
                    }
                }
            }
        }
        None
    }
}

/// Convert UUID to i64 for advisory lock key.
///
/// Uses the first 8 bytes of the UUID, which provides sufficient
/// uniqueness for our purposes.
fn uuid_to_lock_key(id: Uuid) -> i64 {
    let bytes = id.as_bytes();
    i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_to_lock_key() {
        let id1 = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let id2 = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        let id3 = Uuid::parse_str("87654321-1234-5678-1234-567812345678").unwrap();

        let key1 = uuid_to_lock_key(id1);
        let key2 = uuid_to_lock_key(id2);
        let key3 = uuid_to_lock_key(id3);

        // Same first 8 bytes should produce same key
        assert_eq!(key1, key2);
        // Different first 8 bytes should produce different key
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_discovery_status_default() {
        let status = DiscoveryStatus {
            connector_id: Uuid::new_v4(),
            state: DiscoveryState::Idle,
            started_at: None,
            completed_at: None,
            progress_percent: None,
            current_object_class: None,
            error: None,
            version: None,
        };

        assert_eq!(status.state, DiscoveryState::Idle);
        assert!(status.started_at.is_none());
    }

    #[test]
    fn test_discovery_state_transitions() {
        // Idle -> InProgress
        let state = DiscoveryState::Idle;
        assert_ne!(state, DiscoveryState::InProgress);

        // InProgress -> Completed
        let state = DiscoveryState::InProgress;
        assert_ne!(state, DiscoveryState::Completed);

        // InProgress -> Failed
        let state = DiscoveryState::InProgress;
        assert_ne!(state, DiscoveryState::Failed);
    }

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_DISCOVERY_TIMEOUT_SECS, 30);
        assert_eq!(MAX_DISCOVERY_TIMEOUT_SECS, 300);
    }

    #[test]
    fn test_timeout_duration_constant() {
        let timeout = Duration::from_secs(DEFAULT_DISCOVERY_TIMEOUT_SECS);
        assert_eq!(timeout.as_secs(), 30);

        let max_timeout = Duration::from_secs(MAX_DISCOVERY_TIMEOUT_SECS);
        assert_eq!(max_timeout.as_secs(), 300);
    }
}
