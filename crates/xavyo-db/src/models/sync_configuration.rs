//! Sync Configuration model for live synchronization settings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Sync mode for live synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Periodic polling at configured interval.
    Polling,
    /// Event-driven (requires connector support).
    Event,
    /// Combination of polling and events.
    Hybrid,
}

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncMode::Polling => write!(f, "polling"),
            SyncMode::Event => write!(f, "event"),
            SyncMode::Hybrid => write!(f, "hybrid"),
        }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictResolution {
    /// External system changes always win.
    InboundWins,
    /// Pending local changes always win.
    OutboundWins,
    /// Non-overlapping attributes merged.
    Merge,
    /// All conflicts require administrator review.
    Manual,
}

impl fmt::Display for SyncConflictResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncConflictResolution::InboundWins => write!(f, "inbound_wins"),
            SyncConflictResolution::OutboundWins => write!(f, "outbound_wins"),
            SyncConflictResolution::Merge => write!(f, "merge"),
            SyncConflictResolution::Manual => write!(f, "manual"),
        }
    }
}

impl std::str::FromStr for SyncConflictResolution {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound_wins" => Ok(SyncConflictResolution::InboundWins),
            "outbound_wins" => Ok(SyncConflictResolution::OutboundWins),
            "merge" => Ok(SyncConflictResolution::Merge),
            "manual" => Ok(SyncConflictResolution::Manual),
            _ => Err(format!("Unknown conflict resolution: {s}")),
        }
    }
}

/// Sync configuration for a connector.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SyncConfiguration {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub enabled: bool,
    pub sync_mode: String,
    pub polling_interval_secs: i32,
    pub rate_limit_per_minute: i32,
    pub batch_size: i32,
    pub conflict_resolution: String,
    pub auto_create_identity: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SyncConfiguration {
    /// Get the sync mode enum.
    #[must_use]
    pub fn sync_mode(&self) -> SyncMode {
        self.sync_mode.parse().unwrap_or(SyncMode::Polling)
    }

    /// Get the conflict resolution enum.
    #[must_use]
    pub fn conflict_resolution(&self) -> SyncConflictResolution {
        self.conflict_resolution
            .parse()
            .unwrap_or(SyncConflictResolution::InboundWins)
    }

    /// Create a new sync configuration.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateSyncConfiguration,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sync_configurations (
                tenant_id, connector_id, enabled, sync_mode,
                polling_interval_secs, rate_limit_per_minute, batch_size,
                conflict_resolution, auto_create_identity
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(input.enabled)
        .bind(input.sync_mode.to_string())
        .bind(input.polling_interval_secs)
        .bind(input.rate_limit_per_minute)
        .bind(input.batch_size)
        .bind(input.conflict_resolution.to_string())
        .bind(input.auto_create_identity)
        .fetch_one(pool)
        .await
    }

    /// Find configuration by connector ID.
    pub async fn find_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_configurations
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Find configuration by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_configurations
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all enabled sync configurations for a tenant.
    pub async fn list_enabled(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_configurations
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY created_at
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List all sync configurations for a tenant.
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sync_configurations
            WHERE tenant_id = $1
            ORDER BY created_at
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update sync configuration.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &UpdateSyncConfiguration,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut query = String::from("UPDATE gov_sync_configurations SET updated_at = NOW()");
        let mut param_count = 2;

        if input.enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(", enabled = ${param_count}"));
        }
        if input.sync_mode.is_some() {
            param_count += 1;
            query.push_str(&format!(", sync_mode = ${param_count}"));
        }
        if input.polling_interval_secs.is_some() {
            param_count += 1;
            query.push_str(&format!(", polling_interval_secs = ${param_count}"));
        }
        if input.rate_limit_per_minute.is_some() {
            param_count += 1;
            query.push_str(&format!(", rate_limit_per_minute = ${param_count}"));
        }
        if input.batch_size.is_some() {
            param_count += 1;
            query.push_str(&format!(", batch_size = ${param_count}"));
        }
        if input.conflict_resolution.is_some() {
            param_count += 1;
            query.push_str(&format!(", conflict_resolution = ${param_count}"));
        }
        if input.auto_create_identity.is_some() {
            param_count += 1;
            query.push_str(&format!(", auto_create_identity = ${param_count}"));
        }

        query.push_str(" WHERE tenant_id = $1 AND connector_id = $2 RETURNING *");

        let mut q = sqlx::query_as::<_, SyncConfiguration>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(enabled) = input.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref mode) = input.sync_mode {
            q = q.bind(mode.to_string());
        }
        if let Some(interval) = input.polling_interval_secs {
            q = q.bind(interval);
        }
        if let Some(rate) = input.rate_limit_per_minute {
            q = q.bind(rate);
        }
        if let Some(batch) = input.batch_size {
            q = q.bind(batch);
        }
        if let Some(ref resolution) = input.conflict_resolution {
            q = q.bind(resolution.to_string());
        }
        if let Some(auto_create) = input.auto_create_identity {
            q = q.bind(auto_create);
        }

        q.fetch_optional(pool).await
    }

    /// Enable sync for a connector.
    pub async fn enable(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_configurations
            SET enabled = true, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable sync for a connector.
    pub async fn disable(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sync_configurations
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete sync configuration.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sync_configurations
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Upsert sync configuration (create or update).
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateSyncConfiguration,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
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
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(input.enabled)
        .bind(input.sync_mode.to_string())
        .bind(input.polling_interval_secs)
        .bind(input.rate_limit_per_minute)
        .bind(input.batch_size)
        .bind(input.conflict_resolution.to_string())
        .bind(input.auto_create_identity)
        .fetch_one(pool)
        .await
    }
}

/// Input for creating a sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSyncConfiguration {
    pub enabled: bool,
    pub sync_mode: SyncMode,
    pub polling_interval_secs: i32,
    pub rate_limit_per_minute: i32,
    pub batch_size: i32,
    pub conflict_resolution: SyncConflictResolution,
    pub auto_create_identity: bool,
}

impl Default for CreateSyncConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            sync_mode: SyncMode::Polling,
            polling_interval_secs: 60,
            rate_limit_per_minute: 1000,
            batch_size: 100,
            conflict_resolution: SyncConflictResolution::InboundWins,
            auto_create_identity: false,
        }
    }
}

/// Input for updating a sync configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSyncConfiguration {
    pub enabled: Option<bool>,
    pub sync_mode: Option<SyncMode>,
    pub polling_interval_secs: Option<i32>,
    pub rate_limit_per_minute: Option<i32>,
    pub batch_size: Option<i32>,
    pub conflict_resolution: Option<SyncConflictResolution>,
    pub auto_create_identity: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_mode_roundtrip() {
        for mode in [SyncMode::Polling, SyncMode::Event, SyncMode::Hybrid] {
            let s = mode.to_string();
            let parsed: SyncMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_conflict_resolution_roundtrip() {
        for resolution in [
            SyncConflictResolution::InboundWins,
            SyncConflictResolution::OutboundWins,
            SyncConflictResolution::Merge,
            SyncConflictResolution::Manual,
        ] {
            let s = resolution.to_string();
            let parsed: SyncConflictResolution = s.parse().unwrap();
            assert_eq!(resolution, parsed);
        }
    }

    #[test]
    fn test_create_sync_configuration_defaults() {
        let config = CreateSyncConfiguration::default();
        assert!(!config.enabled);
        assert_eq!(config.sync_mode, SyncMode::Polling);
        assert_eq!(config.polling_interval_secs, 60);
        assert_eq!(config.rate_limit_per_minute, 1000);
        assert_eq!(config.batch_size, 100);
        assert_eq!(
            config.conflict_resolution,
            SyncConflictResolution::InboundWins
        );
        assert!(!config.auto_create_identity);
    }
}
