//! Transaction support for multi-step remediations.
//!
//! Provides compensating transaction support for operations that span multiple
//! systems (connector operations + shadow link management). Since external
//! connector operations cannot participate in database transactions, we use
//! a compensating transaction pattern where executed steps are tracked and
//! can be rolled back by executing inverse operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::types::ActionType;

/// Status of a remediation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    /// Transaction is in progress.
    InProgress,
    /// All steps completed successfully.
    Committed,
    /// Transaction was rolled back after a failure.
    RolledBack,
    /// Transaction failed and rollback also failed.
    Failed,
}

impl TransactionStatus {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionStatus::InProgress => "in_progress",
            TransactionStatus::Committed => "committed",
            TransactionStatus::RolledBack => "rolled_back",
            TransactionStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A completed step in a remediation transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedStep {
    /// The action that was executed.
    pub action: ActionType,
    /// Identifier of the affected entity (e.g., external UID or identity ID).
    pub target_id: String,
    /// Connector ID if this was a connector operation.
    pub connector_id: Option<Uuid>,
    /// State before this step was executed.
    pub before_state: Option<JsonValue>,
    /// The inverse action to execute for rollback.
    pub rollback_action: Option<ActionType>,
    /// Additional context needed for rollback.
    pub rollback_context: Option<JsonValue>,
    /// When this step was executed.
    pub executed_at: DateTime<Utc>,
}

impl CompletedStep {
    /// Create a new completed step.
    pub fn new(action: ActionType, target_id: impl Into<String>) -> Self {
        Self {
            action,
            target_id: target_id.into(),
            connector_id: None,
            before_state: None,
            rollback_action: None,
            rollback_context: None,
            executed_at: Utc::now(),
        }
    }

    /// Set the connector ID.
    pub fn with_connector(mut self, connector_id: Uuid) -> Self {
        self.connector_id = Some(connector_id);
        self
    }

    /// Set the before state for rollback.
    pub fn with_before_state(mut self, state: JsonValue) -> Self {
        self.before_state = Some(state);
        self
    }

    /// Set the rollback action.
    pub fn with_rollback(mut self, action: ActionType) -> Self {
        self.rollback_action = Some(action);
        self
    }

    /// Set additional rollback context.
    pub fn with_rollback_context(mut self, context: JsonValue) -> Self {
        self.rollback_context = Some(context);
        self
    }
}

/// Error that occurred during rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackError {
    /// The step that failed to rollback.
    pub step_index: usize,
    /// The action that was being rolled back.
    pub action: ActionType,
    /// Error message.
    pub error: String,
}

/// A remediation transaction that tracks multi-step operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationTransaction {
    /// Transaction ID.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// When the transaction started.
    pub started_at: DateTime<Utc>,
    /// When the transaction completed (if finished).
    pub completed_at: Option<DateTime<Utc>>,
    /// Current transaction status.
    pub status: TransactionStatus,
    /// Completed steps (in execution order).
    pub steps: Vec<CompletedStep>,
    /// Errors encountered during rollback (if any).
    pub rollback_errors: Vec<RollbackError>,
}

impl RemediationTransaction {
    /// Create a new transaction.
    pub fn new(tenant_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            started_at: Utc::now(),
            completed_at: None,
            status: TransactionStatus::InProgress,
            steps: Vec::new(),
            rollback_errors: Vec::new(),
        }
    }

    /// Add a completed step to the transaction.
    pub fn add_step(&mut self, step: CompletedStep) {
        self.steps.push(step);
    }

    /// Get the number of completed steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Check if the transaction is still in progress.
    pub fn is_in_progress(&self) -> bool {
        self.status == TransactionStatus::InProgress
    }

    /// Check if the transaction completed successfully.
    pub fn is_committed(&self) -> bool {
        self.status == TransactionStatus::Committed
    }

    /// Check if the transaction was rolled back.
    pub fn is_rolled_back(&self) -> bool {
        self.status == TransactionStatus::RolledBack
    }

    /// Check if the transaction failed (including rollback failure).
    pub fn is_failed(&self) -> bool {
        self.status == TransactionStatus::Failed
    }

    /// Mark the transaction as committed.
    pub fn commit(&mut self) {
        self.status = TransactionStatus::Committed;
        self.completed_at = Some(Utc::now());
        tracing::info!(
            transaction_id = %self.id,
            tenant_id = %self.tenant_id,
            step_count = self.steps.len(),
            "Transaction committed successfully"
        );
    }

    /// Get the inverse action for rollback.
    pub fn get_inverse_action(action: ActionType) -> Option<ActionType> {
        match action {
            ActionType::Create => Some(ActionType::Delete),
            ActionType::Delete => None, // Cannot undo delete without state
            ActionType::Update => Some(ActionType::Update), // Restore previous state
            ActionType::Link => Some(ActionType::Unlink),
            ActionType::Unlink => Some(ActionType::Link),
            ActionType::InactivateIdentity => None, // Typically no auto-restore
        }
    }

    /// Mark the transaction as needing rollback and return steps to rollback.
    /// Steps are returned in reverse order (LIFO).
    pub fn prepare_rollback(&mut self) -> Vec<&CompletedStep> {
        self.steps.iter().rev().collect()
    }

    /// Record a rollback error.
    pub fn record_rollback_error(&mut self, step_index: usize, action: ActionType, error: String) {
        self.rollback_errors.push(RollbackError {
            step_index,
            action,
            error,
        });
    }

    /// Mark the transaction as rolled back.
    pub fn mark_rolled_back(&mut self) {
        if self.rollback_errors.is_empty() {
            self.status = TransactionStatus::RolledBack;
            tracing::info!(
                transaction_id = %self.id,
                tenant_id = %self.tenant_id,
                step_count = self.steps.len(),
                "Transaction rolled back successfully"
            );
        } else {
            self.status = TransactionStatus::Failed;
            tracing::error!(
                transaction_id = %self.id,
                tenant_id = %self.tenant_id,
                step_count = self.steps.len(),
                error_count = self.rollback_errors.len(),
                "Transaction rollback partially failed"
            );
        }
        self.completed_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_new() {
        let tenant_id = Uuid::new_v4();
        let tx = RemediationTransaction::new(tenant_id);

        assert_eq!(tx.tenant_id, tenant_id);
        assert!(tx.is_in_progress());
        assert_eq!(tx.step_count(), 0);
        assert!(tx.completed_at.is_none());
    }

    #[test]
    fn test_transaction_add_step() {
        let tenant_id = Uuid::new_v4();
        let mut tx = RemediationTransaction::new(tenant_id);

        let step = CompletedStep::new(ActionType::Create, "user-001")
            .with_connector(Uuid::new_v4())
            .with_rollback(ActionType::Delete);

        tx.add_step(step);
        assert_eq!(tx.step_count(), 1);
    }

    #[test]
    fn test_transaction_commit() {
        let tenant_id = Uuid::new_v4();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        tx.commit();

        assert!(tx.is_committed());
        assert!(tx.completed_at.is_some());
    }

    #[test]
    fn test_transaction_rollback() {
        let tenant_id = Uuid::new_v4();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        tx.add_step(CompletedStep::new(ActionType::Link, "user-001"));

        let steps_to_rollback = tx.prepare_rollback();
        assert_eq!(steps_to_rollback.len(), 2);
        // Should be in reverse order
        assert_eq!(steps_to_rollback[0].action, ActionType::Link);
        assert_eq!(steps_to_rollback[1].action, ActionType::Create);

        tx.mark_rolled_back();
        assert!(tx.is_rolled_back());
    }

    #[test]
    fn test_transaction_rollback_with_errors() {
        let tenant_id = Uuid::new_v4();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        tx.record_rollback_error(0, ActionType::Delete, "Connection refused".to_string());
        tx.mark_rolled_back();

        assert!(tx.is_failed());
        assert_eq!(tx.rollback_errors.len(), 1);
    }

    #[test]
    fn test_inverse_action_mapping() {
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Create),
            Some(ActionType::Delete)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Link),
            Some(ActionType::Unlink)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Unlink),
            Some(ActionType::Link)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Delete),
            None
        );
    }

    #[test]
    fn test_completed_step_builder() {
        let connector_id = Uuid::new_v4();
        let before_state = serde_json::json!({"name": "old"});

        let step = CompletedStep::new(ActionType::Update, "user-001")
            .with_connector(connector_id)
            .with_before_state(before_state.clone())
            .with_rollback(ActionType::Update)
            .with_rollback_context(serde_json::json!({"restore": true}));

        assert_eq!(step.action, ActionType::Update);
        assert_eq!(step.target_id, "user-001");
        assert_eq!(step.connector_id, Some(connector_id));
        assert_eq!(step.before_state, Some(before_state));
        assert_eq!(step.rollback_action, Some(ActionType::Update));
    }

    #[test]
    fn test_transaction_status_display() {
        assert_eq!(TransactionStatus::InProgress.as_str(), "in_progress");
        assert_eq!(TransactionStatus::Committed.as_str(), "committed");
        assert_eq!(TransactionStatus::RolledBack.as_str(), "rolled_back");
        assert_eq!(TransactionStatus::Failed.as_str(), "failed");
    }
}
