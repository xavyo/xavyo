//! Sync Conflict model for tracking conflicts between inbound and outbound changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Type of sync conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictType {
    /// Both inbound and outbound changing same attribute.
    ConcurrentUpdate,
    /// Inbound data is older than current state.
    StaleData,
    /// Conflicting values for specific attributes.
    AttributeConflict,
    /// Correlation mismatch between systems.
    IdentityMismatch,
}

impl fmt::Display for SyncConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncConflictType::ConcurrentUpdate => write!(f, "concurrent_update"),
            SyncConflictType::StaleData => write!(f, "stale_data"),
            SyncConflictType::AttributeConflict => write!(f, "attribute_conflict"),
            SyncConflictType::IdentityMismatch => write!(f, "identity_mismatch"),
        }
    }
}

impl std::str::FromStr for SyncConflictType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "concurrent_update" => Ok(SyncConflictType::ConcurrentUpdate),
            "stale_data" => Ok(SyncConflictType::StaleData),
            "attribute_conflict" => Ok(SyncConflictType::AttributeConflict),
            "identity_mismatch" => Ok(SyncConflictType::IdentityMismatch),
            _ => Err(format!("Unknown conflict type: {}", s)),
        }
    }
}

/// Resolution strategy for sync conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncResolutionStrategy {
    /// Inbound change wins.
    InboundWins,
    /// Outbound change wins.
    OutboundWins,
    /// Merge non-conflicting attributes.
    Merge,
    /// Require manual resolution.
    Manual,
    /// Awaiting resolution.
    Pending,
}

impl fmt::Display for SyncResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncResolutionStrategy::InboundWins => write!(f, "inbound_wins"),
            SyncResolutionStrategy::OutboundWins => write!(f, "outbound_wins"),
            SyncResolutionStrategy::Merge => write!(f, "merge"),
            SyncResolutionStrategy::Manual => write!(f, "manual"),
            SyncResolutionStrategy::Pending => write!(f, "pending"),
        }
    }
}

impl std::str::FromStr for SyncResolutionStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound_wins" => Ok(SyncResolutionStrategy::InboundWins),
            "outbound_wins" => Ok(SyncResolutionStrategy::OutboundWins),
            "merge" => Ok(SyncResolutionStrategy::Merge),
            "manual" => Ok(SyncResolutionStrategy::Manual),
            "pending" => Ok(SyncResolutionStrategy::Pending),
            _ => Err(format!("Unknown resolution strategy: {}", s)),
        }
    }
}

/// A sync conflict between inbound and outbound changes.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SyncConflict {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub inbound_change_id: Uuid,
    pub outbound_operation_id: Option<Uuid>,
    pub conflict_type: String,
    pub affected_attributes: Vec<String>,
    pub inbound_value: serde_json::Value,
    pub outbound_value: Option<serde_json::Value>,
    pub resolution_strategy: String,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl SyncConflict {
    /// Get the conflict type enum.
    pub fn conflict_type(&self) -> SyncConflictType {
        self.conflict_type
            .parse()
            .unwrap_or(SyncConflictType::ConcurrentUpdate)
    }

    /// Get the resolution strategy enum.
    pub fn resolution_strategy(&self) -> SyncResolutionStrategy {
        self.resolution_strategy
            .parse()
            .unwrap_or(SyncResolutionStrategy::Pending)
    }

    /// Check if conflict is resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolved_at.is_some()
    }

    /// Create a new sync conflict.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &CreateSyncConflict,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_sync_conflicts (
                tenant_id, inbound_change_id, outbound_operation_id,
                conflict_type, affected_attributes, inbound_value,
                outbound_value, resolution_strategy
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.inbound_change_id)
        .bind(input.outbound_operation_id)
        .bind(input.conflict_type.to_string())
        .bind(&input.affected_attributes)
        .bind(&input.inbound_value)
        .bind(&input.outbound_value)
        .bind(SyncResolutionStrategy::Pending.to_string())
        .fetch_one(pool)
        .await
    }

    /// Find by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_sync_conflicts
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find by inbound change ID.
    pub async fn find_by_inbound_change(
        pool: &PgPool,
        tenant_id: Uuid,
        inbound_change_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_sync_conflicts
            WHERE tenant_id = $1 AND inbound_change_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(inbound_change_id)
        .fetch_optional(pool)
        .await
    }

    /// List pending conflicts for a connector.
    pub async fn list_pending_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT sc.* FROM gov_sync_conflicts sc
            JOIN gov_inbound_changes ic ON sc.inbound_change_id = ic.id
            WHERE sc.tenant_id = $1
                AND ic.connector_id = $2
                AND sc.resolution_strategy = 'pending'
            ORDER BY sc.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count pending conflicts for a connector.
    pub async fn count_pending_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_sync_conflicts sc
            JOIN gov_inbound_changes ic ON sc.inbound_change_id = ic.id
            WHERE sc.tenant_id = $1
                AND ic.connector_id = $2
                AND sc.resolution_strategy = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(pool)
        .await
    }

    /// List conflicts with filtering.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &SyncConflictFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_sync_conflicts WHERE tenant_id = $1");

        if filter.pending_only {
            query.push_str(" AND resolution_strategy = 'pending'");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $2 OFFSET $3");

        sqlx::query_as::<_, SyncConflict>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
    }

    /// Resolve a conflict.
    pub async fn resolve(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        resolved_by: Uuid,
        input: &ResolveSyncConflict,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_sync_conflicts
            SET resolution_strategy = $3,
                resolved_by = $4,
                resolved_at = NOW(),
                resolution_notes = $5
            WHERE tenant_id = $1 AND id = $2 AND resolution_strategy = 'pending'
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(input.resolution_strategy.to_string())
        .bind(resolved_by)
        .bind(&input.notes)
        .fetch_optional(pool)
        .await
    }
}

/// Input for creating a sync conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSyncConflict {
    pub inbound_change_id: Uuid,
    pub outbound_operation_id: Option<Uuid>,
    pub conflict_type: SyncConflictType,
    pub affected_attributes: Vec<String>,
    pub inbound_value: serde_json::Value,
    pub outbound_value: Option<serde_json::Value>,
}

/// Filter for listing sync conflicts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConflictFilter {
    pub pending_only: bool,
}

/// Input for resolving a sync conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveSyncConflict {
    pub resolution_strategy: SyncResolutionStrategy,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_type_roundtrip() {
        for conflict_type in [
            SyncConflictType::ConcurrentUpdate,
            SyncConflictType::StaleData,
            SyncConflictType::AttributeConflict,
            SyncConflictType::IdentityMismatch,
        ] {
            let s = conflict_type.to_string();
            let parsed: SyncConflictType = s.parse().unwrap();
            assert_eq!(conflict_type, parsed);
        }
    }

    #[test]
    fn test_resolution_strategy_roundtrip() {
        for strategy in [
            SyncResolutionStrategy::InboundWins,
            SyncResolutionStrategy::OutboundWins,
            SyncResolutionStrategy::Merge,
            SyncResolutionStrategy::Manual,
            SyncResolutionStrategy::Pending,
        ] {
            let s = strategy.to_string();
            let parsed: SyncResolutionStrategy = s.parse().unwrap();
            assert_eq!(strategy, parsed);
        }
    }
}
