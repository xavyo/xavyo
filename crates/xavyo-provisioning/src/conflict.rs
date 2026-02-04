//! Conflict detection and resolution service.
//!
//! Detects concurrent modification conflicts between provisioning operations
//! and applies resolution strategies.

use chrono::{DateTime, Utc};
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

use xavyo_db::models::{
    ConflictFilter, ConflictRecord, ConflictType, CreateConflictRecord, ResolutionOutcome,
    ResolutionStrategy, ResolveConflict,
};

/// Errors that can occur during conflict operations.
#[derive(Debug, Error)]
pub enum ConflictError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Conflict not found.
    #[error("Conflict not found: {id}")]
    NotFound { id: Uuid },

    /// Conflict already resolved.
    #[error("Conflict already resolved: {id}")]
    AlreadyResolved { id: Uuid },

    /// Invalid resolution strategy.
    #[error("Invalid resolution strategy for conflict type: {0}")]
    InvalidStrategy(String),
}

/// Result type for conflict operations.
pub type ConflictResult<T> = Result<T, ConflictError>;

/// Detected conflict between operations.
#[derive(Debug, Clone)]
pub struct DetectedConflict {
    /// Primary operation ID.
    pub operation_id: Uuid,

    /// Conflicting operation ID (if known).
    pub conflicting_operation_id: Option<Uuid>,

    /// Type of conflict.
    pub conflict_type: ConflictType,

    /// Affected attributes.
    pub affected_attributes: Vec<String>,

    /// Recommended resolution strategy.
    pub recommended_strategy: ResolutionStrategy,
}

/// Result of applying a resolution strategy.
#[derive(Debug, Clone)]
pub enum ResolutionResult {
    /// Primary operation should be applied.
    ApplyPrimary,

    /// Primary operation should be skipped (superseded).
    SkipPrimary,

    /// Attributes should be merged.
    Merge { merged_payload: serde_json::Value },

    /// Requires manual intervention.
    RequiresManual,
}

/// Service for detecting and resolving conflicts.
pub struct ConflictService {
    pool: sqlx::PgPool,
}

impl ConflictService {
    /// Create a new conflict service.
    #[must_use] 
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Detect if there's a conflict with an existing operation.
    ///
    /// Checks for concurrent operations affecting the same target entity.
    pub async fn detect_conflict(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        target_uid: &str,
        operation_id: Uuid,
        payload: &serde_json::Value,
    ) -> ConflictResult<Option<DetectedConflict>> {
        // Find any in-progress or pending operations for the same target
        let conflicting: Option<ConflictingOperationRow> = sqlx::query_as(
            r"
            SELECT id, payload, created_at, status
            FROM provisioning_operations
            WHERE tenant_id = $1
                AND connector_id = $2
                AND target_uid = $3
                AND id != $4
                AND status IN ('pending', 'in_progress')
            ORDER BY created_at ASC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(target_uid)
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(conflicting_op) = conflicting {
            // Determine conflict type and affected attributes
            let (conflict_type, affected_attrs) =
                self.analyze_conflict(payload, &conflicting_op.payload);

            let conflict = DetectedConflict {
                operation_id,
                conflicting_operation_id: Some(conflicting_op.id),
                conflict_type,
                affected_attributes: affected_attrs,
                recommended_strategy: self.recommend_strategy(&conflict_type),
            };

            debug!(
                operation_id = %operation_id,
                conflicting_id = %conflicting_op.id,
                conflict_type = ?conflict_type,
                "Conflict detected"
            );

            return Ok(Some(conflict));
        }

        Ok(None)
    }

    /// Analyze the conflict and determine type and affected attributes.
    fn analyze_conflict(
        &self,
        primary_payload: &serde_json::Value,
        conflicting_payload: &serde_json::Value,
    ) -> (ConflictType, Vec<String>) {
        let mut affected = Vec::new();

        // Compare object keys to find overlapping changes
        if let (Some(primary_obj), Some(conflicting_obj)) =
            (primary_payload.as_object(), conflicting_payload.as_object())
        {
            for (key, primary_value) in primary_obj {
                if let Some(conflicting_value) = conflicting_obj.get(key) {
                    if primary_value != conflicting_value {
                        affected.push(key.clone());
                    }
                }
            }
        }

        let conflict_type = if affected.is_empty() {
            // No overlapping attribute changes - concurrent but non-conflicting
            ConflictType::ConcurrentUpdate
        } else {
            // Overlapping attribute changes - true conflict
            ConflictType::ConcurrentUpdate
        };

        (conflict_type, affected)
    }

    /// Recommend a resolution strategy based on conflict type.
    fn recommend_strategy(&self, conflict_type: &ConflictType) -> ResolutionStrategy {
        match conflict_type {
            ConflictType::ConcurrentUpdate => ResolutionStrategy::LastWriteWins,
            ConflictType::StaleData => ResolutionStrategy::FirstWriteWins,
            ConflictType::MissingTarget => ResolutionStrategy::Manual,
            ConflictType::ExternalChange => ResolutionStrategy::Merge,
        }
    }

    /// Apply a resolution strategy to resolve the conflict.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_resolution_strategy(
        &self,
        _tenant_id: Uuid,
        conflict: &DetectedConflict,
        strategy: ResolutionStrategy,
        primary_payload: &serde_json::Value,
        conflicting_payload: Option<&serde_json::Value>,
        primary_created_at: DateTime<Utc>,
        conflicting_created_at: Option<DateTime<Utc>>,
    ) -> ConflictResult<ResolutionResult> {
        match strategy {
            ResolutionStrategy::LastWriteWins => {
                // Most recent operation wins
                if let Some(conflicting_time) = conflicting_created_at {
                    if primary_created_at >= conflicting_time {
                        Ok(ResolutionResult::ApplyPrimary)
                    } else {
                        Ok(ResolutionResult::SkipPrimary)
                    }
                } else {
                    Ok(ResolutionResult::ApplyPrimary)
                }
            }

            ResolutionStrategy::FirstWriteWins => {
                // First operation wins
                if let Some(conflicting_time) = conflicting_created_at {
                    if primary_created_at <= conflicting_time {
                        Ok(ResolutionResult::ApplyPrimary)
                    } else {
                        Ok(ResolutionResult::SkipPrimary)
                    }
                } else {
                    Ok(ResolutionResult::ApplyPrimary)
                }
            }

            ResolutionStrategy::Merge => {
                // Merge non-conflicting attributes
                if let Some(conflicting) = conflicting_payload {
                    let merged = self.merge_payloads(
                        primary_payload,
                        conflicting,
                        &conflict.affected_attributes,
                    );
                    Ok(ResolutionResult::Merge {
                        merged_payload: merged,
                    })
                } else {
                    Ok(ResolutionResult::ApplyPrimary)
                }
            }

            ResolutionStrategy::Manual => Ok(ResolutionResult::RequiresManual),
        }
    }

    /// Merge two payloads, preferring primary for conflicting attributes.
    fn merge_payloads(
        &self,
        primary: &serde_json::Value,
        conflicting: &serde_json::Value,
        _conflicting_attrs: &[String],
    ) -> serde_json::Value {
        let mut merged = conflicting.clone();

        // Overlay primary attributes on top of conflicting
        if let (Some(merged_obj), Some(primary_obj)) = (merged.as_object_mut(), primary.as_object())
        {
            for (key, value) in primary_obj {
                merged_obj.insert(key.clone(), value.clone());
            }
        }

        merged
    }

    /// Record a conflict in the database.
    pub async fn record_conflict(
        &self,
        tenant_id: Uuid,
        conflict: &DetectedConflict,
    ) -> ConflictResult<ConflictRecord> {
        let input = CreateConflictRecord {
            operation_id: conflict.operation_id,
            conflicting_operation_id: conflict.conflicting_operation_id,
            conflict_type: conflict.conflict_type,
            affected_attributes: conflict.affected_attributes.clone(),
            resolution_strategy: conflict.recommended_strategy,
        };

        let record = ConflictRecord::create(&self.pool, tenant_id, &input).await?;

        info!(
            conflict_id = %record.id,
            operation_id = %conflict.operation_id,
            conflict_type = ?conflict.conflict_type,
            "Conflict recorded"
        );

        Ok(record)
    }

    /// Resolve a conflict manually.
    pub async fn resolve_conflict(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        resolved_by: Uuid,
        outcome: ResolutionOutcome,
        notes: Option<&str>,
    ) -> ConflictResult<ConflictRecord> {
        let input = ResolveConflict {
            outcome,
            notes: notes.map(std::string::ToString::to_string),
        };

        let record =
            ConflictRecord::resolve(&self.pool, tenant_id, conflict_id, resolved_by, &input)
                .await?
                .ok_or(ConflictError::NotFound { id: conflict_id })?;

        info!(
            conflict_id = %conflict_id,
            resolved_by = %resolved_by,
            outcome = ?outcome,
            "Conflict resolved"
        );

        Ok(record)
    }

    /// List pending conflicts.
    pub async fn list_pending_conflicts(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> ConflictResult<Vec<ConflictRecord>> {
        let conflicts = ConflictRecord::list_pending(&self.pool, tenant_id, limit, offset).await?;
        Ok(conflicts)
    }

    /// List conflicts with filter.
    pub async fn list_conflicts(
        &self,
        tenant_id: Uuid,
        filter: &ConflictFilter,
        limit: i64,
        offset: i64,
    ) -> ConflictResult<Vec<ConflictRecord>> {
        let conflicts =
            ConflictRecord::list_by_tenant(&self.pool, tenant_id, filter, limit, offset).await?;
        Ok(conflicts)
    }

    /// Get a conflict by ID.
    pub async fn get_conflict(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
    ) -> ConflictResult<Option<ConflictRecord>> {
        let conflict = ConflictRecord::find_by_id(&self.pool, tenant_id, conflict_id).await?;
        Ok(conflict)
    }

    /// Count pending conflicts.
    pub async fn count_pending_conflicts(&self, tenant_id: Uuid) -> ConflictResult<i64> {
        let count = ConflictRecord::count_pending(&self.pool, tenant_id).await?;
        Ok(count)
    }
}

/// Internal row type for conflicting operation queries.
#[derive(Debug, sqlx::FromRow)]
struct ConflictingOperationRow {
    id: Uuid,
    payload: serde_json::Value,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detected_conflict() {
        let conflict = DetectedConflict {
            operation_id: Uuid::new_v4(),
            conflicting_operation_id: Some(Uuid::new_v4()),
            conflict_type: ConflictType::ConcurrentUpdate,
            affected_attributes: vec!["email".to_string(), "department".to_string()],
            recommended_strategy: ResolutionStrategy::LastWriteWins,
        };

        assert_eq!(conflict.conflict_type, ConflictType::ConcurrentUpdate);
        assert_eq!(conflict.affected_attributes.len(), 2);
    }

    #[test]
    fn test_resolution_result() {
        let result = ResolutionResult::ApplyPrimary;
        assert!(matches!(result, ResolutionResult::ApplyPrimary));

        let merged = ResolutionResult::Merge {
            merged_payload: serde_json::json!({"name": "test"}),
        };
        assert!(matches!(merged, ResolutionResult::Merge { .. }));
    }

    #[test]
    fn test_recommend_strategy() {
        // Create a dummy pool-less service for testing strategy logic
        // We can't test actual service without DB, but we can verify strategy mapping
        assert_eq!(
            format!("{:?}", ResolutionStrategy::LastWriteWins),
            "LastWriteWins"
        );
        assert_eq!(format!("{:?}", ResolutionStrategy::Manual), "Manual");
    }
}
