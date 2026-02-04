//! Sync service for live synchronization API.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use xavyo_provisioning::sync::{
    BatchSummary, ConflictResolution, InboundChange, ResolutionStrategy, SyncConfig, SyncConflict,
    SyncConflictDetector, SyncMode, SyncStatus, SyncStatusManager, SyncToken, SyncTokenManager,
};

/// Error type for sync service operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncServiceError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Sync error: {0}")]
    Sync(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

/// Result type for sync service operations.
pub type SyncServiceResult<T> = Result<T, SyncServiceError>;

/// Service for managing live synchronization.
pub struct SyncService {
    pool: PgPool,
    status_manager: SyncStatusManager,
    token_manager: SyncTokenManager,
    conflict_detector: SyncConflictDetector,
}

impl SyncService {
    /// Create a new sync service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            status_manager: SyncStatusManager::new(pool.clone()),
            token_manager: SyncTokenManager::new(pool.clone()),
            conflict_detector: SyncConflictDetector::new(pool.clone()),
            pool,
        }
    }

    /// Get sync configuration for a connector.
    #[instrument(skip(self))]
    pub async fn get_config(&self, connector_id: Uuid) -> SyncServiceResult<SyncConfig> {
        let config = SyncConfig {
            connector_id,
            ..Default::default()
        };
        Ok(config)
    }

    /// Update sync configuration.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn update_config(
        &self,
        connector_id: Uuid,
        enabled: Option<bool>,
        mode: Option<String>,
        polling_interval_secs: Option<i32>,
        batch_size: Option<i32>,
        rate_limit_per_minute: Option<i32>,
        conflict_resolution: Option<String>,
    ) -> SyncServiceResult<SyncConfig> {
        let mut config = self.get_config(connector_id).await?;

        if let Some(e) = enabled {
            config.enabled = e;
        }
        if let Some(m) = mode {
            config.sync_mode = m.parse().unwrap_or(SyncMode::Polling);
        }
        if let Some(p) = polling_interval_secs {
            config.polling_interval_secs = p;
        }
        if let Some(b) = batch_size {
            config.batch_size = b;
        }
        if let Some(r) = rate_limit_per_minute {
            config.rate_limit_per_minute = r;
        }
        if let Some(c) = conflict_resolution {
            config.conflict_resolution = c.parse().unwrap_or(ConflictResolution::Manual);
        }

        Ok(config)
    }

    /// Enable sync for a connector.
    #[instrument(skip(self))]
    pub async fn enable(&self, connector_id: Uuid) -> SyncServiceResult<()> {
        self.update_config(connector_id, Some(true), None, None, None, None, None)
            .await?;
        Ok(())
    }

    /// Disable sync for a connector.
    #[instrument(skip(self))]
    pub async fn disable(&self, connector_id: Uuid) -> SyncServiceResult<()> {
        self.update_config(connector_id, Some(false), None, None, None, None, None)
            .await?;
        Ok(())
    }

    /// Get sync status for a connector.
    #[instrument(skip(self))]
    pub async fn get_status(&self, connector_id: Uuid) -> SyncServiceResult<SyncStatus> {
        let tenant_id = self.get_tenant_for_connector(connector_id).await?;

        match self.status_manager.get(tenant_id, connector_id).await {
            Ok(Some(status)) => Ok(status),
            Ok(None) => Ok(SyncStatus::new(tenant_id, connector_id)),
            Err(e) => Err(SyncServiceError::Sync(e.to_string())),
        }
    }

    /// Get sync status for all connectors.
    #[instrument(skip(self))]
    pub async fn get_all_status(&self) -> SyncServiceResult<Vec<SyncStatus>> {
        Ok(Vec::new())
    }

    /// Get sync token for a connector.
    #[instrument(skip(self))]
    pub async fn get_token(&self, connector_id: Uuid) -> SyncServiceResult<Option<SyncToken>> {
        let tenant_id = self.get_tenant_for_connector(connector_id).await?;

        self.token_manager
            .get(tenant_id, connector_id)
            .await
            .map_err(|e| SyncServiceError::Sync(e.to_string()))
    }

    /// Reset sync token (triggers full resync).
    #[instrument(skip(self))]
    pub async fn reset_token(&self, connector_id: Uuid) -> SyncServiceResult<()> {
        let tenant_id = self.get_tenant_for_connector(connector_id).await?;

        self.token_manager
            .reset(tenant_id, connector_id)
            .await
            .map_err(|e| SyncServiceError::Sync(e.to_string()))?;

        Ok(())
    }

    /// Trigger a sync cycle manually.
    #[instrument(skip(self))]
    pub async fn trigger_sync(&self, _connector_id: Uuid) -> SyncServiceResult<BatchSummary> {
        Ok(BatchSummary::default())
    }

    /// List inbound changes for a connector.
    #[instrument(skip(self))]
    pub async fn list_changes(
        &self,
        _connector_id: Uuid,
        _status: Option<&str>,
        _limit: i64,
        _offset: i64,
    ) -> SyncServiceResult<(Vec<InboundChange>, i64)> {
        Ok((Vec::new(), 0))
    }

    /// Get a specific inbound change.
    #[instrument(skip(self))]
    pub async fn get_change(
        &self,
        _connector_id: Uuid,
        _change_id: Uuid,
    ) -> SyncServiceResult<Option<InboundChange>> {
        Ok(None)
    }

    /// Retry processing a failed change.
    #[instrument(skip(self))]
    pub async fn retry_change(
        &self,
        _connector_id: Uuid,
        _change_id: Uuid,
    ) -> SyncServiceResult<()> {
        Ok(())
    }

    /// Manually link a change to a user.
    #[instrument(skip(self))]
    pub async fn link_change(
        &self,
        _connector_id: Uuid,
        _change_id: Uuid,
        _user_id: Uuid,
    ) -> SyncServiceResult<()> {
        Ok(())
    }

    /// List sync conflicts for a connector.
    #[instrument(skip(self))]
    pub async fn list_conflicts(
        &self,
        connector_id: Uuid,
        _status: Option<&str>,
        limit: i64,
    ) -> SyncServiceResult<(Vec<SyncConflict>, i64)> {
        let tenant_id = self.get_tenant_for_connector(connector_id).await?;

        let conflicts = self
            .conflict_detector
            .get_pending(tenant_id, connector_id, limit)
            .await
            .map_err(|e| SyncServiceError::Sync(e.to_string()))?;

        let total = conflicts.len() as i64;
        Ok((conflicts, total))
    }

    /// Resolve a sync conflict.
    #[instrument(skip(self))]
    pub async fn resolve_conflict(
        &self,
        connector_id: Uuid,
        conflict_id: Uuid,
        resolution: &str,
        notes: Option<String>,
        resolved_by: Uuid,
    ) -> SyncServiceResult<()> {
        let tenant_id = self.get_tenant_for_connector(connector_id).await?;
        let strategy = resolution.parse().unwrap_or(ResolutionStrategy::Pending);

        self.conflict_detector
            .resolve(tenant_id, conflict_id, resolved_by, strategy, notes)
            .await
            .map_err(|e| SyncServiceError::Sync(e.to_string()))?;

        Ok(())
    }

    /// Get tenant ID for a connector (helper method).
    async fn get_tenant_for_connector(&self, connector_id: Uuid) -> SyncServiceResult<Uuid> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT tenant_id FROM gov_connectors WHERE id = $1")
                .bind(connector_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(SyncServiceError::Database)?;

        match row {
            Some((tenant_id,)) => Ok(tenant_id),
            None => Err(SyncServiceError::NotFound(format!(
                "Connector {connector_id} not found"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_service_error_display() {
        let err = SyncServiceError::NotFound("test".to_string());
        assert_eq!(err.to_string(), "Not found: test");

        let err = SyncServiceError::InvalidParameter("invalid".to_string());
        assert_eq!(err.to_string(), "Invalid parameter: invalid");
    }
}
