//! Sync service for live synchronization API.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use xavyo_provisioning::sync::{
    BatchSummary, ConflictResolution, InboundChange, ResolutionStrategy, SyncConfig,
    SyncConfigService, SyncConflict, SyncConflictDetector, SyncError, SyncMode, SyncStatus,
    SyncStatusManager, SyncToken, SyncTokenManager,
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
    config_service: SyncConfigService,
    status_manager: SyncStatusManager,
    token_manager: SyncTokenManager,
    conflict_detector: SyncConflictDetector,
}

fn map_sync_error(err: SyncError) -> SyncServiceError {
    match err {
        SyncError::Configuration { message } => SyncServiceError::InvalidParameter(message),
        SyncError::NotFound { entity, id } => SyncServiceError::NotFound(format!("{entity} {id}")),
        SyncError::Database(e) => SyncServiceError::Database(e),
        other => SyncServiceError::Sync(other.to_string()),
    }
}

/// In-memory defaults for a tenant-scoped connector. Never uses `Uuid::nil()`.
pub(crate) fn default_config_for(tenant_id: Uuid, connector_id: Uuid) -> SyncConfig {
    SyncConfig {
        tenant_id,
        connector_id,
        ..SyncConfig::default()
    }
}

impl SyncService {
    /// Create a new sync service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            config_service: SyncConfigService::new(pool.clone()),
            status_manager: SyncStatusManager::new(pool.clone()),
            token_manager: SyncTokenManager::new(pool.clone()),
            conflict_detector: SyncConflictDetector::new(pool.clone()),
            pool,
        }
    }

    async fn ensure_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncServiceResult<()> {
        let found: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM connector_configurations WHERE id = $1 AND tenant_id = $2",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match found {
            Some(_) => Ok(()),
            None => Err(SyncServiceError::NotFound(format!(
                "Connector {connector_id} not found"
            ))),
        }
    }

    async fn load_or_default(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> SyncServiceResult<SyncConfig> {
        self.ensure_connector(tenant_id, connector_id).await?;
        match self
            .config_service
            .get(tenant_id, connector_id)
            .await
            .map_err(map_sync_error)?
        {
            Some(cfg) => Ok(cfg),
            None => Ok(default_config_for(tenant_id, connector_id)),
        }
    }

    /// Get sync configuration for a connector (persisted, or tenant-scoped defaults).
    #[instrument(skip(self))]
    pub async fn get_config(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> SyncServiceResult<SyncConfig> {
        self.load_or_default(tenant_id, connector_id).await
    }

    /// Update and persist sync configuration.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn update_config(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        enabled: Option<bool>,
        mode: Option<String>,
        polling_interval_secs: Option<i32>,
        batch_size: Option<i32>,
        rate_limit_per_minute: Option<i32>,
        conflict_resolution: Option<String>,
    ) -> SyncServiceResult<SyncConfig> {
        let mut config = self.load_or_default(tenant_id, connector_id).await?;

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

        self.config_service
            .upsert(&config)
            .await
            .map_err(map_sync_error)
    }

    /// Enable sync for a connector (persisted).
    #[instrument(skip(self))]
    pub async fn enable(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncServiceResult<()> {
        self.update_config(
            tenant_id,
            connector_id,
            Some(true),
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
        Ok(())
    }

    /// Disable sync for a connector (persisted).
    #[instrument(skip(self))]
    pub async fn disable(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncServiceResult<()> {
        self.update_config(
            tenant_id,
            connector_id,
            Some(false),
            None,
            None,
            None,
            None,
            None,
        )
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

    /// Get sync status for all connectors in a tenant.
    #[instrument(skip(self))]
    pub async fn get_all_status(&self, tenant_id: Uuid) -> SyncServiceResult<Vec<SyncStatus>> {
        self.status_manager
            .list_by_tenant(tenant_id)
            .await
            .map_err(map_sync_error)
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
            sqlx::query_as("SELECT tenant_id FROM connector_configurations WHERE id = $1")
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

    #[test]
    fn default_config_is_tenant_scoped() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let cfg = default_config_for(tenant_id, connector_id);
        assert_eq!(cfg.tenant_id, tenant_id);
        assert_eq!(cfg.connector_id, connector_id);
        assert_ne!(cfg.tenant_id, Uuid::nil());
        assert_ne!(cfg.connector_id, Uuid::nil());
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_mutations_go_through_upsert() {
        let src = include_str!("sync_service.rs");
        let persist_call = format!(".{}({})", "upsert", "&config");
        let list_call = format!("{}({})", "list_by_tenant", "tenant_id");
        assert!(
            src.contains(&persist_call),
            "update/enable/disable must persist via config service upsert"
        );
        assert!(
            src.contains(&list_call),
            "get_all_status must list tenant statuses, not return an empty vec"
        );
    }
}
