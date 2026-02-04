//! Batch operation result types
//!
//! Types for tracking batch operation outcomes with per-item status.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a single batch item
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchItemStatus {
    /// Operation completed successfully
    Success,
    /// Operation failed (API error)
    Failed,
    /// Item skipped (validation error, duplicate)
    Skipped,
    /// Not yet processed
    Pending,
}

/// Result for a single item in a batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemResult {
    /// Position in batch file (0-based)
    pub index: usize,
    /// Resource name
    pub name: String,
    /// Resource ID (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Result status
    pub status: BatchItemStatus,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BatchItemResult {
    /// Create a successful result
    pub fn success(index: usize, name: String, id: Uuid) -> Self {
        Self {
            index,
            name,
            id: Some(id),
            status: BatchItemStatus::Success,
            error: None,
        }
    }

    /// Create a failed result
    pub fn failed(index: usize, name: String, error: String) -> Self {
        Self {
            index,
            name,
            id: None,
            status: BatchItemStatus::Failed,
            error: Some(error),
        }
    }

    /// Create a skipped result
    pub fn skipped(index: usize, name: String, reason: String) -> Self {
        Self {
            index,
            name,
            id: None,
            status: BatchItemStatus::Skipped,
            error: Some(reason),
        }
    }
}

/// Summary of a completed batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// Type of operation performed
    pub operation: String,
    /// Total items attempted
    pub total: usize,
    /// Number of successful operations
    pub success_count: usize,
    /// Number of failed operations
    pub failure_count: usize,
    /// Number of skipped items (validation failures)
    pub skipped_count: usize,
    /// Per-item results
    pub items: Vec<BatchItemResult>,
    /// Total operation duration in milliseconds
    pub duration_ms: u64,
    /// Whether operation was interrupted (Ctrl+C)
    pub interrupted: bool,
}

impl BatchResult {
    /// Create a new empty batch result
    pub fn new(operation: &str, total: usize) -> Self {
        Self {
            operation: operation.to_string(),
            total,
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            items: Vec::with_capacity(total),
            duration_ms: 0,
            interrupted: false,
        }
    }

    /// Add a successful item
    pub fn add_success(&mut self, index: usize, name: String, id: Uuid) {
        self.success_count += 1;
        self.items.push(BatchItemResult::success(index, name, id));
    }

    /// Add a failed item
    pub fn add_failure(&mut self, index: usize, name: String, error: String) {
        self.failure_count += 1;
        self.items.push(BatchItemResult::failed(index, name, error));
    }

    /// Add a skipped item
    pub fn add_skipped(&mut self, index: usize, name: String, reason: String) {
        self.skipped_count += 1;
        self.items
            .push(BatchItemResult::skipped(index, name, reason));
    }

    /// Mark the batch as interrupted
    pub fn set_interrupted(&mut self) {
        self.interrupted = true;
    }

    /// Set the duration
    pub fn set_duration(&mut self, duration_ms: u64) {
        self.duration_ms = duration_ms;
    }

    /// Check if all items succeeded
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0 && self.skipped_count == 0 && !self.interrupted
    }

    /// Check if any items failed
    pub fn has_failures(&self) -> bool {
        self.failure_count > 0
    }

    /// Get only the successful items
    pub fn successful_items(&self) -> impl Iterator<Item = &BatchItemResult> {
        self.items
            .iter()
            .filter(|i| i.status == BatchItemStatus::Success)
    }

    /// Get only the failed items
    pub fn failed_items(&self) -> impl Iterator<Item = &BatchItemResult> {
        self.items
            .iter()
            .filter(|i| i.status == BatchItemStatus::Failed || i.status == BatchItemStatus::Skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_item_result_success() {
        let id = Uuid::new_v4();
        let result = BatchItemResult::success(0, "test-agent".to_string(), id);

        assert_eq!(result.index, 0);
        assert_eq!(result.name, "test-agent");
        assert_eq!(result.id, Some(id));
        assert_eq!(result.status, BatchItemStatus::Success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_batch_item_result_failed() {
        let result =
            BatchItemResult::failed(1, "bad-agent".to_string(), "Invalid name".to_string());

        assert_eq!(result.index, 1);
        assert_eq!(result.name, "bad-agent");
        assert!(result.id.is_none());
        assert_eq!(result.status, BatchItemStatus::Failed);
        assert_eq!(result.error, Some("Invalid name".to_string()));
    }

    #[test]
    fn test_batch_item_result_skipped() {
        let result =
            BatchItemResult::skipped(2, "dup-agent".to_string(), "Duplicate name".to_string());

        assert_eq!(result.index, 2);
        assert_eq!(result.status, BatchItemStatus::Skipped);
        assert_eq!(result.error, Some("Duplicate name".to_string()));
    }

    #[test]
    fn test_batch_result_new() {
        let result = BatchResult::new("create", 5);

        assert_eq!(result.operation, "create");
        assert_eq!(result.total, 5);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.skipped_count, 0);
        assert!(result.items.is_empty());
        assert!(!result.interrupted);
    }

    #[test]
    fn test_batch_result_add_items() {
        let mut result = BatchResult::new("create", 3);
        let id = Uuid::new_v4();

        result.add_success(0, "agent-1".to_string(), id);
        result.add_failure(1, "agent-2".to_string(), "Error".to_string());
        result.add_skipped(2, "agent-3".to_string(), "Skipped".to_string());

        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.items.len(), 3);
    }

    #[test]
    fn test_batch_result_all_succeeded() {
        let mut result = BatchResult::new("create", 2);
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        result.add_success(0, "agent-1".to_string(), id1);
        result.add_success(1, "agent-2".to_string(), id2);

        assert!(result.all_succeeded());
        assert!(!result.has_failures());
    }

    #[test]
    fn test_batch_result_has_failures() {
        let mut result = BatchResult::new("create", 2);
        let id = Uuid::new_v4();

        result.add_success(0, "agent-1".to_string(), id);
        result.add_failure(1, "agent-2".to_string(), "Error".to_string());

        assert!(!result.all_succeeded());
        assert!(result.has_failures());
    }

    #[test]
    fn test_batch_result_interrupted() {
        let mut result = BatchResult::new("delete", 5);
        let id = Uuid::new_v4();

        result.add_success(0, "agent-1".to_string(), id);
        result.set_interrupted();

        assert!(!result.all_succeeded());
        assert!(result.interrupted);
    }

    #[test]
    fn test_batch_result_iterators() {
        let mut result = BatchResult::new("create", 3);
        let id = Uuid::new_v4();

        result.add_success(0, "agent-1".to_string(), id);
        result.add_failure(1, "agent-2".to_string(), "Error".to_string());
        result.add_skipped(2, "agent-3".to_string(), "Skipped".to_string());

        assert_eq!(result.successful_items().count(), 1);
        assert_eq!(result.failed_items().count(), 2);
    }
}
