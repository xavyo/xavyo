//! Checkpoint management for reconciliation resumption.
//!
//! Provides persistent checkpointing to allow reconciliation runs to be
//! resumed after failures or interruptions.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Phase of reconciliation processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPhase {
    /// Initial setup and validation.
    Initialization,
    /// Processing accounts from target system.
    ResourceProcessing,
    /// Processing remaining shadows (for deleted detection).
    ShadowProcessing,
    /// Final cleanup and statistics.
    Finalization,
}

impl std::fmt::Display for CheckpointPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initialization => write!(f, "initialization"),
            Self::ResourceProcessing => write!(f, "resource_processing"),
            Self::ShadowProcessing => write!(f, "shadow_processing"),
            Self::Finalization => write!(f, "finalization"),
        }
    }
}

/// Checkpoint state for resumable reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Current processing phase.
    pub phase: CheckpointPhase,
    /// Last processed key (for pagination).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_key: Option<String>,
    /// Number of accounts processed so far.
    pub accounts_processed: u32,
    /// Current batch number.
    pub batch_number: u32,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self {
            phase: CheckpointPhase::Initialization,
            last_key: None,
            accounts_processed: 0,
            batch_number: 0,
        }
    }
}

impl Checkpoint {
    /// Create a new checkpoint at initialization phase.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create checkpoint at resource processing phase.
    #[must_use] 
    pub fn at_resource_processing(
        last_key: Option<String>,
        accounts_processed: u32,
        batch: u32,
    ) -> Self {
        Self {
            phase: CheckpointPhase::ResourceProcessing,
            last_key,
            accounts_processed,
            batch_number: batch,
        }
    }

    /// Create checkpoint at shadow processing phase.
    #[must_use] 
    pub fn at_shadow_processing(
        last_key: Option<String>,
        accounts_processed: u32,
        batch: u32,
    ) -> Self {
        Self {
            phase: CheckpointPhase::ShadowProcessing,
            last_key,
            accounts_processed,
            batch_number: batch,
        }
    }

    /// Create checkpoint at finalization phase.
    #[must_use] 
    pub fn at_finalization(accounts_processed: u32) -> Self {
        Self {
            phase: CheckpointPhase::Finalization,
            last_key: None,
            accounts_processed,
            batch_number: 0,
        }
    }

    /// Advance to next batch.
    pub fn advance(&mut self, last_key: String, processed_in_batch: u32) {
        self.last_key = Some(last_key);
        self.accounts_processed += processed_in_batch;
        self.batch_number += 1;
    }

    /// Transition to shadow processing phase.
    pub fn transition_to_shadow_processing(&mut self) {
        self.phase = CheckpointPhase::ShadowProcessing;
        self.last_key = None;
        self.batch_number = 0;
    }

    /// Transition to finalization phase.
    pub fn transition_to_finalization(&mut self) {
        self.phase = CheckpointPhase::Finalization;
        self.last_key = None;
        self.batch_number = 0;
    }
}

/// Service for persisting and retrieving checkpoints.
pub struct CheckpointManager {
    pool: PgPool,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Save checkpoint for a run.
    pub async fn save(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        checkpoint: &Checkpoint,
    ) -> Result<(), CheckpointError> {
        let checkpoint_json = serde_json::to_value(checkpoint)
            .map_err(|e| CheckpointError::Serialization(e.to_string()))?;

        sqlx::query(
            r"
            UPDATE gov_connector_reconciliation_runs
            SET checkpoint = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(&checkpoint_json)
        .execute(&self.pool)
        .await
        .map_err(|e| CheckpointError::Database(e.to_string()))?;

        Ok(())
    }

    /// Load checkpoint for a run.
    pub async fn load(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as(
            r"
            SELECT checkpoint
            FROM gov_connector_reconciliation_runs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CheckpointError::Database(e.to_string()))?;

        match row {
            Some((Some(json),)) => {
                let checkpoint = serde_json::from_value(json)
                    .map_err(|e| CheckpointError::Deserialization(e.to_string()))?;
                Ok(Some(checkpoint))
            }
            _ => Ok(None),
        }
    }

    /// Clear checkpoint for a run (on completion).
    pub async fn clear(&self, tenant_id: Uuid, run_id: Uuid) -> Result<(), CheckpointError> {
        sqlx::query(
            r"
            UPDATE gov_connector_reconciliation_runs
            SET checkpoint = NULL, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| CheckpointError::Database(e.to_string()))?;

        Ok(())
    }
}

/// Errors that can occur during checkpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_default() {
        let checkpoint = Checkpoint::default();
        assert_eq!(checkpoint.phase, CheckpointPhase::Initialization);
        assert!(checkpoint.last_key.is_none());
        assert_eq!(checkpoint.accounts_processed, 0);
        assert_eq!(checkpoint.batch_number, 0);
    }

    #[test]
    fn test_checkpoint_advance() {
        let mut checkpoint = Checkpoint::at_resource_processing(None, 0, 0);

        checkpoint.advance("key1".to_string(), 100);
        assert_eq!(checkpoint.last_key, Some("key1".to_string()));
        assert_eq!(checkpoint.accounts_processed, 100);
        assert_eq!(checkpoint.batch_number, 1);

        checkpoint.advance("key2".to_string(), 100);
        assert_eq!(checkpoint.last_key, Some("key2".to_string()));
        assert_eq!(checkpoint.accounts_processed, 200);
        assert_eq!(checkpoint.batch_number, 2);
    }

    #[test]
    fn test_checkpoint_phase_transitions() {
        let mut checkpoint = Checkpoint::new();
        assert_eq!(checkpoint.phase, CheckpointPhase::Initialization);

        checkpoint.phase = CheckpointPhase::ResourceProcessing;
        checkpoint.advance("key1".to_string(), 500);
        assert_eq!(checkpoint.batch_number, 1);

        checkpoint.transition_to_shadow_processing();
        assert_eq!(checkpoint.phase, CheckpointPhase::ShadowProcessing);
        assert!(checkpoint.last_key.is_none());
        assert_eq!(checkpoint.batch_number, 0);
        assert_eq!(checkpoint.accounts_processed, 500); // Preserved

        checkpoint.transition_to_finalization();
        assert_eq!(checkpoint.phase, CheckpointPhase::Finalization);
    }

    #[test]
    fn test_checkpoint_serialization() {
        let checkpoint =
            Checkpoint::at_resource_processing(Some("uid=test,ou=users".to_string()), 1500, 3);

        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.phase, CheckpointPhase::ResourceProcessing);
        assert_eq!(deserialized.last_key, Some("uid=test,ou=users".to_string()));
        assert_eq!(deserialized.accounts_processed, 1500);
        assert_eq!(deserialized.batch_number, 3);
    }

    #[test]
    fn test_checkpoint_phase_display() {
        assert_eq!(
            CheckpointPhase::Initialization.to_string(),
            "initialization"
        );
        assert_eq!(
            CheckpointPhase::ResourceProcessing.to_string(),
            "resource_processing"
        );
        assert_eq!(
            CheckpointPhase::ShadowProcessing.to_string(),
            "shadow_processing"
        );
        assert_eq!(CheckpointPhase::Finalization.to_string(), "finalization");
    }
}
