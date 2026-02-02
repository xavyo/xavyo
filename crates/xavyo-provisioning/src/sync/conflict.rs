//! Sync conflict detection and management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use super::change::InboundChange;
use super::error::SyncResult;
use super::types::{ConflictType, ResolutionStrategy};

/// A sync conflict between inbound and outbound changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    /// Conflict ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Inbound change that caused the conflict.
    pub inbound_change_id: Uuid,
    /// Outbound operation that conflicts (if any).
    pub outbound_operation_id: Option<Uuid>,
    /// Type of conflict.
    pub conflict_type: ConflictType,
    /// Attributes that are in conflict.
    pub affected_attributes: Vec<String>,
    /// Inbound value.
    pub inbound_value: serde_json::Value,
    /// Outbound value (if applicable).
    pub outbound_value: Option<serde_json::Value>,
    /// Resolution strategy.
    pub resolution_strategy: ResolutionStrategy,
    /// Who resolved the conflict.
    pub resolved_by: Option<Uuid>,
    /// When the conflict was resolved.
    pub resolved_at: Option<DateTime<Utc>>,
    /// Notes about the resolution.
    pub resolution_notes: Option<String>,
    /// When the conflict was created.
    pub created_at: DateTime<Utc>,
}

impl SyncConflict {
    /// Check if this conflict is resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolved_at.is_some()
    }

    /// Check if this conflict needs manual resolution.
    pub fn needs_manual_resolution(&self) -> bool {
        self.resolution_strategy == ResolutionStrategy::Manual && !self.is_resolved()
    }
}

/// Detector for sync conflicts.
pub struct SyncConflictDetector {
    pool: PgPool,
}

impl SyncConflictDetector {
    /// Create a new conflict detector.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if an inbound change conflicts with pending outbound operations.
    #[instrument(skip(self, change))]
    pub async fn detect_conflict(
        &self,
        change: &InboundChange,
    ) -> SyncResult<Option<DetectedConflict>> {
        // Find pending outbound operations for the same external UID
        let pending_ops = self.find_pending_operations(change).await?;

        if pending_ops.is_empty() {
            return Ok(None);
        }

        // Check for conflicting attributes
        let empty_map = serde_json::Map::new();
        let inbound_attrs = change.attributes.as_object().unwrap_or(&empty_map);

        for op in &pending_ops {
            let outbound_attrs = op.attributes.as_object();
            if let Some(out_attrs) = outbound_attrs {
                let conflicts: Vec<String> = inbound_attrs
                    .keys()
                    .filter(|k| out_attrs.contains_key(*k))
                    .cloned()
                    .collect();

                if !conflicts.is_empty() {
                    return Ok(Some(DetectedConflict {
                        inbound_change_id: change.id,
                        outbound_operation_id: Some(op.id),
                        conflict_type: ConflictType::ConcurrentUpdate,
                        affected_attributes: conflicts,
                        inbound_value: change.attributes.clone(),
                        outbound_value: Some(op.attributes.clone()),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Create a conflict record.
    #[instrument(skip(self, conflict))]
    pub async fn create_conflict(
        &self,
        tenant_id: Uuid,
        conflict: &DetectedConflict,
        initial_strategy: ResolutionStrategy,
    ) -> SyncResult<SyncConflict> {
        let result = sqlx::query_as::<_, SyncConflictRow>(
            r#"
            INSERT INTO gov_sync_conflicts (
                tenant_id, inbound_change_id, outbound_operation_id,
                conflict_type, affected_attributes, inbound_value,
                outbound_value, resolution_strategy
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, tenant_id, inbound_change_id, outbound_operation_id,
                      conflict_type, affected_attributes, inbound_value,
                      outbound_value, resolution_strategy, resolved_by,
                      resolved_at, resolution_notes, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(conflict.inbound_change_id)
        .bind(conflict.outbound_operation_id)
        .bind(conflict.conflict_type.as_str())
        .bind(&conflict.affected_attributes)
        .bind(&conflict.inbound_value)
        .bind(&conflict.outbound_value)
        .bind(initial_strategy.as_str())
        .fetch_one(&self.pool)
        .await?;

        Ok(result.into_conflict())
    }

    /// Resolve a conflict.
    #[instrument(skip(self))]
    pub async fn resolve(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        resolved_by: Uuid,
        strategy: ResolutionStrategy,
        notes: Option<String>,
    ) -> SyncResult<Option<SyncConflict>> {
        let result = sqlx::query_as::<_, SyncConflictRow>(
            r#"
            UPDATE gov_sync_conflicts
            SET resolution_strategy = $3,
                resolved_by = $4,
                resolved_at = NOW(),
                resolution_notes = $5
            WHERE tenant_id = $1 AND id = $2 AND resolution_strategy = 'pending'
            RETURNING id, tenant_id, inbound_change_id, outbound_operation_id,
                      conflict_type, affected_attributes, inbound_value,
                      outbound_value, resolution_strategy, resolved_by,
                      resolved_at, resolution_notes, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(conflict_id)
        .bind(strategy.as_str())
        .bind(resolved_by)
        .bind(notes)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|r| r.into_conflict()))
    }

    /// Get pending conflicts for a connector.
    #[instrument(skip(self))]
    pub async fn get_pending(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        limit: i64,
    ) -> SyncResult<Vec<SyncConflict>> {
        let rows = sqlx::query_as::<_, SyncConflictRow>(
            r#"
            SELECT c.id, c.tenant_id, c.inbound_change_id, c.outbound_operation_id,
                   c.conflict_type, c.affected_attributes, c.inbound_value,
                   c.outbound_value, c.resolution_strategy, c.resolved_by,
                   c.resolved_at, c.resolution_notes, c.created_at
            FROM gov_sync_conflicts c
            JOIN gov_inbound_changes ic ON c.inbound_change_id = ic.id
            WHERE c.tenant_id = $1
                AND ic.connector_id = $2
                AND c.resolution_strategy = 'pending'
            ORDER BY c.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_conflict()).collect())
    }

    /// Count pending conflicts for a connector.
    #[instrument(skip(self))]
    pub async fn count_pending(&self, tenant_id: Uuid, connector_id: Uuid) -> SyncResult<i64> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_sync_conflicts c
            JOIN gov_inbound_changes ic ON c.inbound_change_id = ic.id
            WHERE c.tenant_id = $1
                AND ic.connector_id = $2
                AND c.resolution_strategy = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Find pending operations that might conflict with an inbound change.
    async fn find_pending_operations(&self, change: &InboundChange) -> SyncResult<Vec<PendingOp>> {
        let rows = sqlx::query_as::<_, PendingOp>(
            r#"
            SELECT id, attributes FROM provisioning_operations
            WHERE tenant_id = $1
                AND connector_id = $2
                AND target_uid = $3
                AND status IN ('pending', 'in_progress')
            ORDER BY created_at DESC
            "#,
        )
        .bind(change.tenant_id)
        .bind(change.connector_id)
        .bind(&change.external_uid)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}

/// A detected conflict before it's persisted.
#[derive(Debug, Clone)]
pub struct DetectedConflict {
    /// Inbound change ID.
    pub inbound_change_id: Uuid,
    /// Outbound operation ID.
    pub outbound_operation_id: Option<Uuid>,
    /// Conflict type.
    pub conflict_type: ConflictType,
    /// Affected attributes.
    pub affected_attributes: Vec<String>,
    /// Inbound value.
    pub inbound_value: serde_json::Value,
    /// Outbound value.
    pub outbound_value: Option<serde_json::Value>,
}

/// Pending operation row.
#[derive(Debug, sqlx::FromRow)]
struct PendingOp {
    id: Uuid,
    attributes: serde_json::Value,
}

/// Database row for sync conflict.
#[derive(Debug, sqlx::FromRow)]
struct SyncConflictRow {
    id: Uuid,
    tenant_id: Uuid,
    inbound_change_id: Uuid,
    outbound_operation_id: Option<Uuid>,
    conflict_type: String,
    affected_attributes: Vec<String>,
    inbound_value: serde_json::Value,
    outbound_value: Option<serde_json::Value>,
    resolution_strategy: String,
    resolved_by: Option<Uuid>,
    resolved_at: Option<DateTime<Utc>>,
    resolution_notes: Option<String>,
    created_at: DateTime<Utc>,
}

impl SyncConflictRow {
    fn into_conflict(self) -> SyncConflict {
        SyncConflict {
            id: self.id,
            tenant_id: self.tenant_id,
            inbound_change_id: self.inbound_change_id,
            outbound_operation_id: self.outbound_operation_id,
            conflict_type: self
                .conflict_type
                .parse()
                .unwrap_or(ConflictType::ConcurrentUpdate),
            affected_attributes: self.affected_attributes,
            inbound_value: self.inbound_value,
            outbound_value: self.outbound_value,
            resolution_strategy: self
                .resolution_strategy
                .parse()
                .unwrap_or(ResolutionStrategy::Pending),
            resolved_by: self.resolved_by,
            resolved_at: self.resolved_at,
            resolution_notes: self.resolution_notes,
            created_at: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_is_resolved() {
        let mut conflict = SyncConflict {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            inbound_change_id: Uuid::new_v4(),
            outbound_operation_id: None,
            conflict_type: ConflictType::ConcurrentUpdate,
            affected_attributes: vec!["email".to_string()],
            inbound_value: serde_json::json!({}),
            outbound_value: None,
            resolution_strategy: ResolutionStrategy::Pending,
            resolved_by: None,
            resolved_at: None,
            resolution_notes: None,
            created_at: Utc::now(),
        };

        assert!(!conflict.is_resolved());
        assert!(!conflict.needs_manual_resolution());

        conflict.resolution_strategy = ResolutionStrategy::Manual;
        assert!(conflict.needs_manual_resolution());

        conflict.resolved_at = Some(Utc::now());
        assert!(conflict.is_resolved());
        assert!(!conflict.needs_manual_resolution());
    }
}
