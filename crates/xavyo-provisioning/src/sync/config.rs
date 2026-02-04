//! Sync configuration management.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use tracing::instrument;
use uuid::Uuid;

use super::error::{SyncError, SyncResult};
use super::types::ResolutionStrategy;

/// Sync mode for live synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Periodic polling at configured interval.
    Polling,
    /// Event-driven (requires connector support).
    Event,
    /// Combination of polling and events.
    Hybrid,
}

impl SyncMode {
    /// Convert to string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncMode::Polling => "polling",
            SyncMode::Event => "event",
            SyncMode::Hybrid => "hybrid",
        }
    }
}

impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SyncMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "polling" => Ok(SyncMode::Polling),
            "event" => Ok(SyncMode::Event),
            "hybrid" => Ok(SyncMode::Hybrid),
            _ => Err(format!("Unknown sync mode: {s}")),
        }
    }
}

/// Conflict resolution strategy for inbound changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// External system changes always win.
    InboundWins,
    /// Pending local changes always win.
    OutboundWins,
    /// Non-overlapping attributes merged.
    Merge,
    /// All conflicts require administrator review.
    Manual,
}

impl ConflictResolution {
    /// Convert to resolution strategy.
    #[must_use] 
    pub fn to_strategy(&self) -> ResolutionStrategy {
        match self {
            ConflictResolution::InboundWins => ResolutionStrategy::InboundWins,
            ConflictResolution::OutboundWins => ResolutionStrategy::OutboundWins,
            ConflictResolution::Merge => ResolutionStrategy::Merge,
            ConflictResolution::Manual => ResolutionStrategy::Manual,
        }
    }

    /// Convert to string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            ConflictResolution::InboundWins => "inbound_wins",
            ConflictResolution::OutboundWins => "outbound_wins",
            ConflictResolution::Merge => "merge",
            ConflictResolution::Manual => "manual",
        }
    }
}

impl std::fmt::Display for ConflictResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ConflictResolution {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound_wins" => Ok(ConflictResolution::InboundWins),
            "outbound_wins" => Ok(ConflictResolution::OutboundWins),
            "merge" => Ok(ConflictResolution::Merge),
            "manual" => Ok(ConflictResolution::Manual),
            _ => Err(format!("Unknown conflict resolution: {s}")),
        }
    }
}

/// Sync configuration for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Configuration ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Whether sync is enabled.
    pub enabled: bool,
    /// Sync mode.
    pub sync_mode: SyncMode,
    /// Polling interval in seconds.
    pub polling_interval_secs: i32,
    /// Rate limit per minute.
    pub rate_limit_per_minute: i32,
    /// Batch size for processing.
    pub batch_size: i32,
    /// Conflict resolution strategy.
    pub conflict_resolution: ConflictResolution,
    /// Whether to auto-create identities for unmatched accounts.
    pub auto_create_identity: bool,
}

impl SyncConfig {
    /// Get polling interval as Duration.
    #[must_use] 
    pub fn polling_interval(&self) -> Duration {
        Duration::from_secs(self.polling_interval_secs as u64)
    }

    /// Check if this configuration is valid.
    pub fn validate(&self) -> SyncResult<()> {
        if self.polling_interval_secs < 1 {
            return Err(SyncError::configuration(
                "Polling interval must be at least 1 second",
            ));
        }
        if self.polling_interval_secs > 3600 {
            return Err(SyncError::configuration(
                "Polling interval cannot exceed 1 hour",
            ));
        }
        if self.rate_limit_per_minute < 1 {
            return Err(SyncError::configuration(
                "Rate limit must be at least 1 per minute",
            ));
        }
        if self.batch_size < 1 || self.batch_size > 10000 {
            return Err(SyncError::configuration(
                "Batch size must be between 1 and 10000",
            ));
        }
        Ok(())
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            connector_id: Uuid::nil(),
            enabled: false,
            sync_mode: SyncMode::Polling,
            polling_interval_secs: 60,
            rate_limit_per_minute: 1000,
            batch_size: 100,
            conflict_resolution: ConflictResolution::InboundWins,
            auto_create_identity: false,
        }
    }
}

/// Service for managing sync configurations.
#[derive(Debug, Clone)]
pub struct SyncConfigService {
    pool: PgPool,
}

impl SyncConfigService {
    /// Create a new sync config service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get sync configuration for a connector.
    #[instrument(skip(self))]
    pub async fn get(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<Option<SyncConfig>> {
        let result = sqlx::query_as::<_, SyncConfigRow>(
            r"
            SELECT id, tenant_id, connector_id, enabled, sync_mode,
                   polling_interval_secs, rate_limit_per_minute, batch_size,
                   conflict_resolution, auto_create_identity
            FROM gov_sync_configurations
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(SyncConfigRow::into_config))
    }

    /// Create or update sync configuration.
    #[instrument(skip(self, config))]
    pub async fn upsert(&self, config: &SyncConfig) -> SyncResult<SyncConfig> {
        config.validate()?;

        let result = sqlx::query_as::<_, SyncConfigRow>(
            r"
            INSERT INTO gov_sync_configurations (
                tenant_id, connector_id, enabled, sync_mode,
                polling_interval_secs, rate_limit_per_minute, batch_size,
                conflict_resolution, auto_create_identity
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (tenant_id, connector_id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                sync_mode = EXCLUDED.sync_mode,
                polling_interval_secs = EXCLUDED.polling_interval_secs,
                rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
                batch_size = EXCLUDED.batch_size,
                conflict_resolution = EXCLUDED.conflict_resolution,
                auto_create_identity = EXCLUDED.auto_create_identity,
                updated_at = NOW()
            RETURNING id, tenant_id, connector_id, enabled, sync_mode,
                      polling_interval_secs, rate_limit_per_minute, batch_size,
                      conflict_resolution, auto_create_identity
            ",
        )
        .bind(config.tenant_id)
        .bind(config.connector_id)
        .bind(config.enabled)
        .bind(config.sync_mode.as_str())
        .bind(config.polling_interval_secs)
        .bind(config.rate_limit_per_minute)
        .bind(config.batch_size)
        .bind(config.conflict_resolution.as_str())
        .bind(config.auto_create_identity)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.into_config())
    }

    /// Enable sync for a connector.
    #[instrument(skip(self))]
    pub async fn enable(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<bool> {
        let result = sqlx::query(
            r"
            UPDATE gov_sync_configurations
            SET enabled = true, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Disable sync for a connector.
    #[instrument(skip(self))]
    pub async fn disable(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<bool> {
        let result = sqlx::query(
            r"
            UPDATE gov_sync_configurations
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List all enabled sync configurations for a tenant.
    #[instrument(skip(self))]
    pub async fn list_enabled(&self, tenant_id: Uuid) -> SyncResult<Vec<SyncConfig>> {
        let rows = sqlx::query_as::<_, SyncConfigRow>(
            r"
            SELECT id, tenant_id, connector_id, enabled, sync_mode,
                   polling_interval_secs, rate_limit_per_minute, batch_size,
                   conflict_resolution, auto_create_identity
            FROM gov_sync_configurations
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY connector_id
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(SyncConfigRow::into_config).collect())
    }

    /// Delete sync configuration.
    #[instrument(skip(self))]
    pub async fn delete(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sync_configurations
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Database row for sync configuration.
#[derive(Debug, sqlx::FromRow)]
struct SyncConfigRow {
    id: Uuid,
    tenant_id: Uuid,
    connector_id: Uuid,
    enabled: bool,
    sync_mode: String,
    polling_interval_secs: i32,
    rate_limit_per_minute: i32,
    batch_size: i32,
    conflict_resolution: String,
    auto_create_identity: bool,
}

impl SyncConfigRow {
    fn into_config(self) -> SyncConfig {
        SyncConfig {
            id: self.id,
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            enabled: self.enabled,
            sync_mode: self.sync_mode.parse().unwrap_or(SyncMode::Polling),
            polling_interval_secs: self.polling_interval_secs,
            rate_limit_per_minute: self.rate_limit_per_minute,
            batch_size: self.batch_size,
            conflict_resolution: self
                .conflict_resolution
                .parse()
                .unwrap_or(ConflictResolution::InboundWins),
            auto_create_identity: self.auto_create_identity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_mode_roundtrip() {
        for mode in [SyncMode::Polling, SyncMode::Event, SyncMode::Hybrid] {
            let s = mode.as_str();
            let parsed: SyncMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_conflict_resolution_roundtrip() {
        for resolution in [
            ConflictResolution::InboundWins,
            ConflictResolution::OutboundWins,
            ConflictResolution::Merge,
            ConflictResolution::Manual,
        ] {
            let s = resolution.as_str();
            let parsed: ConflictResolution = s.parse().unwrap();
            assert_eq!(resolution, parsed);
        }
    }

    #[test]
    fn test_sync_config_validation() {
        let mut config = SyncConfig::default();
        config.tenant_id = Uuid::new_v4();
        config.connector_id = Uuid::new_v4();

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid polling interval
        config.polling_interval_secs = 0;
        assert!(config.validate().is_err());
        config.polling_interval_secs = 60;

        // Invalid batch size
        config.batch_size = 0;
        assert!(config.validate().is_err());
        config.batch_size = 100;

        // Invalid rate limit
        config.rate_limit_per_minute = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_polling_interval_duration() {
        let mut config = SyncConfig::default();
        config.polling_interval_secs = 120;
        assert_eq!(config.polling_interval(), Duration::from_secs(120));
    }
}
