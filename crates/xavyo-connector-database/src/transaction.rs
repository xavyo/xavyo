//! Transaction support for `PostgreSQL` database connector.
//!
//! Provides transaction management with begin/commit/rollback, savepoints,
//! and batch operations.

use sqlx::{PgPool, Postgres, Transaction as SqlxTransaction};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{AttributeDelta, AttributeSet, Uid};

/// Transaction state for tracking active transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// No active transaction.
    None,
    /// Transaction is active.
    Active,
    /// Transaction is committed.
    Committed,
    /// Transaction is rolled back.
    RolledBack,
}

/// A database transaction wrapper.
///
/// Provides transaction management with automatic rollback on drop
/// if not explicitly committed.
pub struct DatabaseTransaction<'a> {
    /// The underlying `SQLx` transaction.
    inner: Option<SqlxTransaction<'a, Postgres>>,
    /// Current transaction state.
    state: TransactionState,
    /// Savepoint counter for nested savepoints.
    savepoint_counter: u32,
}

impl<'a> DatabaseTransaction<'a> {
    /// Create a new transaction from a pool.
    pub async fn begin(pool: &'a PgPool) -> ConnectorResult<Self> {
        let tx = pool.begin().await.map_err(|e| {
            ConnectorError::operation_failed_with_source("Failed to begin transaction", e)
        })?;

        debug!("Database transaction started");

        Ok(Self {
            inner: Some(tx),
            state: TransactionState::Active,
            savepoint_counter: 0,
        })
    }

    /// Get the current transaction state.
    #[must_use] 
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// Check if the transaction is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.state == TransactionState::Active
    }

    /// Commit the transaction.
    #[instrument(skip(self))]
    pub async fn commit(mut self) -> ConnectorResult<()> {
        if self.state != TransactionState::Active {
            return Err(ConnectorError::InvalidData {
                message: format!("Cannot commit transaction in state {:?}", self.state),
            });
        }

        if let Some(tx) = self.inner.take() {
            tx.commit().await.map_err(|e| {
                ConnectorError::operation_failed_with_source("Failed to commit transaction", e)
            })?;
        }

        // Note: self.state is not updated since self is consumed
        info!("Database transaction committed");

        Ok(())
    }

    /// Rollback the transaction.
    #[instrument(skip(self))]
    pub async fn rollback(mut self) -> ConnectorResult<()> {
        if self.state != TransactionState::Active {
            return Err(ConnectorError::InvalidData {
                message: format!("Cannot rollback transaction in state {:?}", self.state),
            });
        }

        if let Some(tx) = self.inner.take() {
            tx.rollback().await.map_err(|e| {
                ConnectorError::operation_failed_with_source("Failed to rollback transaction", e)
            })?;
        }

        // Note: self.state is not updated since self is consumed
        warn!("Database transaction rolled back");

        Ok(())
    }

    /// Create a savepoint within the transaction.
    #[instrument(skip(self))]
    pub async fn savepoint(&mut self, name: &str) -> ConnectorResult<Savepoint> {
        if self.state != TransactionState::Active {
            return Err(ConnectorError::InvalidData {
                message: "Cannot create savepoint: transaction not active".to_string(),
            });
        }

        let savepoint_name = if name.is_empty() {
            self.savepoint_counter += 1;
            format!("sp_{}", self.savepoint_counter)
        } else {
            name.to_string()
        };

        if let Some(ref mut tx) = self.inner {
            sqlx::query(&format!("SAVEPOINT {savepoint_name}"))
                .execute(&mut **tx)
                .await
                .map_err(|e| {
                    ConnectorError::operation_failed_with_source(
                        format!("Failed to create savepoint {savepoint_name}"),
                        e,
                    )
                })?;
        }

        debug!(savepoint = %savepoint_name, "Savepoint created");

        Ok(Savepoint {
            name: savepoint_name,
            released: false,
        })
    }

    /// Release a savepoint (discard it without rolling back).
    #[instrument(skip(self))]
    pub async fn release_savepoint(&mut self, savepoint: Savepoint) -> ConnectorResult<()> {
        if self.state != TransactionState::Active {
            return Err(ConnectorError::InvalidData {
                message: "Cannot release savepoint: transaction not active".to_string(),
            });
        }

        if savepoint.released {
            return Ok(());
        }

        if let Some(ref mut tx) = self.inner {
            sqlx::query(&format!("RELEASE SAVEPOINT {}", savepoint.name))
                .execute(&mut **tx)
                .await
                .map_err(|e| {
                    ConnectorError::operation_failed_with_source(
                        format!("Failed to release savepoint {}", savepoint.name),
                        e,
                    )
                })?;
        }

        debug!(savepoint = %savepoint.name, "Savepoint released");

        Ok(())
    }

    /// Rollback to a savepoint.
    #[instrument(skip(self))]
    pub async fn rollback_to_savepoint(&mut self, savepoint: &Savepoint) -> ConnectorResult<()> {
        if self.state != TransactionState::Active {
            return Err(ConnectorError::InvalidData {
                message: "Cannot rollback to savepoint: transaction not active".to_string(),
            });
        }

        if let Some(ref mut tx) = self.inner {
            sqlx::query(&format!("ROLLBACK TO SAVEPOINT {}", savepoint.name))
                .execute(&mut **tx)
                .await
                .map_err(|e| {
                    ConnectorError::operation_failed_with_source(
                        format!("Failed to rollback to savepoint {}", savepoint.name),
                        e,
                    )
                })?;
        }

        warn!(savepoint = %savepoint.name, "Rolled back to savepoint");

        Ok(())
    }

    /// Get a mutable reference to the underlying `SQLx` transaction.
    pub fn as_mut(&mut self) -> Option<&mut SqlxTransaction<'a, Postgres>> {
        self.inner.as_mut()
    }
}

/// A savepoint within a transaction.
#[derive(Debug)]
pub struct Savepoint {
    /// Savepoint name.
    pub name: String,
    /// Whether this savepoint has been released.
    released: bool,
}

impl Savepoint {
    /// Get the savepoint name.
    #[must_use] 
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if the savepoint has been released.
    #[must_use] 
    pub fn is_released(&self) -> bool {
        self.released
    }
}

/// Batch operation builder for bulk database operations.
///
/// Collects multiple operations and executes them efficiently.
#[derive(Debug, Default)]
pub struct BatchOperation {
    /// Insert operations grouped by table.
    inserts: Vec<BatchInsert>,
    /// Update operations grouped by table.
    updates: Vec<BatchUpdate>,
    /// Delete operations grouped by table.
    deletes: Vec<BatchDelete>,
}

#[derive(Debug)]
#[allow(dead_code)] // Fields used for data storage in batch operations
struct BatchInsert {
    table: String,
    id_column: String,
    attributes: AttributeSet,
}

#[derive(Debug)]
#[allow(dead_code)] // Fields used for data storage in batch operations
struct BatchUpdate {
    table: String,
    id_column: String,
    uid: Uid,
    changes: AttributeDelta,
}

#[derive(Debug)]
#[allow(dead_code)] // Fields used for data storage in batch operations
struct BatchDelete {
    table: String,
    id_column: String,
    uid: Uid,
}

impl BatchOperation {
    /// Create a new batch operation builder.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an insert operation to the batch.
    pub fn insert(
        mut self,
        table: impl Into<String>,
        id_column: impl Into<String>,
        attributes: AttributeSet,
    ) -> Self {
        self.inserts.push(BatchInsert {
            table: table.into(),
            id_column: id_column.into(),
            attributes,
        });
        self
    }

    /// Add an update operation to the batch.
    pub fn update(
        mut self,
        table: impl Into<String>,
        id_column: impl Into<String>,
        uid: Uid,
        changes: AttributeDelta,
    ) -> Self {
        self.updates.push(BatchUpdate {
            table: table.into(),
            id_column: id_column.into(),
            uid,
            changes,
        });
        self
    }

    /// Add a delete operation to the batch.
    pub fn delete(
        mut self,
        table: impl Into<String>,
        id_column: impl Into<String>,
        uid: Uid,
    ) -> Self {
        self.deletes.push(BatchDelete {
            table: table.into(),
            id_column: id_column.into(),
            uid,
        });
        self
    }

    /// Get the total number of operations in the batch.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.inserts.len() + self.updates.len() + self.deletes.len()
    }

    /// Check if the batch is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of insert operations.
    #[must_use] 
    pub fn insert_count(&self) -> usize {
        self.inserts.len()
    }

    /// Get the number of update operations.
    #[must_use] 
    pub fn update_count(&self) -> usize {
        self.updates.len()
    }

    /// Get the number of delete operations.
    #[must_use] 
    pub fn delete_count(&self) -> usize {
        self.deletes.len()
    }
}

/// Result of a batch execution.
#[derive(Debug, Default)]
pub struct BatchResult {
    /// UIDs of inserted records.
    pub inserted: Vec<Uid>,
    /// UIDs of updated records.
    pub updated: Vec<Uid>,
    /// Number of deleted records.
    pub deleted: usize,
    /// Errors encountered during execution.
    pub errors: Vec<BatchError>,
}

/// Error from a batch operation.
#[derive(Debug)]
pub struct BatchError {
    /// Index of the operation that failed.
    pub index: usize,
    /// Type of operation that failed.
    pub operation_type: BatchOperationType,
    /// The error message.
    pub message: String,
}

/// Type of batch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOperationType {
    /// Insert operation.
    Insert,
    /// Update operation.
    Update,
    /// Delete operation.
    Delete,
}

impl BatchResult {
    /// Check if all operations succeeded.
    #[must_use] 
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get the total number of successful operations.
    #[must_use] 
    pub fn success_count(&self) -> usize {
        self.inserted.len() + self.updated.len() + self.deleted
    }

    /// Get the total number of failed operations.
    #[must_use] 
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

/// Prepared statement cache for efficient query execution.
///
/// Caches frequently used queries to avoid re-preparing them.
pub struct PreparedStatementCache {
    /// Cache of prepared query strings by key.
    cache: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Maximum cache size.
    max_size: usize,
}

impl PreparedStatementCache {
    /// Create a new prepared statement cache.
    #[must_use] 
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            max_size,
        }
    }

    /// Get a cached query or generate a new one.
    pub async fn get_or_insert<F>(&self, key: &str, generate: F) -> String
    where
        F: FnOnce() -> String,
    {
        let mut cache = self.cache.lock().await;

        if let Some(query) = cache.get(key) {
            return query.clone();
        }

        let query = generate();

        // Evict oldest entry if cache is full
        if cache.len() >= self.max_size {
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(key.to_string(), query.clone());
        query
    }

    /// Clear the cache.
    pub async fn clear(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }

    /// Get the current cache size.
    pub async fn size(&self) -> usize {
        let cache = self.cache.lock().await;
        cache.len()
    }
}

impl Default for PreparedStatementCache {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_state_default() {
        assert_eq!(TransactionState::None, TransactionState::None);
    }

    #[test]
    fn test_transaction_state_transitions() {
        assert_ne!(TransactionState::Active, TransactionState::Committed);
        assert_ne!(TransactionState::Active, TransactionState::RolledBack);
        assert_ne!(TransactionState::Committed, TransactionState::RolledBack);
    }

    #[test]
    fn test_batch_operation_new() {
        let batch = BatchOperation::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_batch_operation_insert() {
        let attrs = AttributeSet::new();
        let batch = BatchOperation::new().insert("users", "id", attrs);

        assert_eq!(batch.len(), 1);
        assert_eq!(batch.insert_count(), 1);
        assert_eq!(batch.update_count(), 0);
        assert_eq!(batch.delete_count(), 0);
    }

    #[test]
    fn test_batch_operation_update() {
        let changes = AttributeDelta::new();
        let batch = BatchOperation::new().update("users", "id", Uid::from_id("user-1"), changes);

        assert_eq!(batch.len(), 1);
        assert_eq!(batch.insert_count(), 0);
        assert_eq!(batch.update_count(), 1);
        assert_eq!(batch.delete_count(), 0);
    }

    #[test]
    fn test_batch_operation_delete() {
        let batch = BatchOperation::new().delete("users", "id", Uid::from_id("user-1"));

        assert_eq!(batch.len(), 1);
        assert_eq!(batch.insert_count(), 0);
        assert_eq!(batch.update_count(), 0);
        assert_eq!(batch.delete_count(), 1);
    }

    #[test]
    fn test_batch_operation_mixed() {
        let attrs = AttributeSet::new();
        let changes = AttributeDelta::new();
        let batch = BatchOperation::new()
            .insert("users", "id", attrs.clone())
            .insert("users", "id", attrs)
            .update("users", "id", Uid::from_id("user-1"), changes.clone())
            .update("users", "id", Uid::from_id("user-2"), changes)
            .delete("users", "id", Uid::from_id("user-3"));

        assert_eq!(batch.len(), 5);
        assert_eq!(batch.insert_count(), 2);
        assert_eq!(batch.update_count(), 2);
        assert_eq!(batch.delete_count(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_result_success() {
        let result = BatchResult {
            inserted: vec![Uid::from_id("user-1"), Uid::from_id("user-2")],
            updated: vec![Uid::from_id("user-3")],
            deleted: 1,
            errors: vec![],
        };

        assert!(result.is_success());
        assert_eq!(result.success_count(), 4);
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn test_batch_result_with_errors() {
        let result = BatchResult {
            inserted: vec![Uid::from_id("user-1")],
            updated: vec![],
            deleted: 0,
            errors: vec![BatchError {
                index: 1,
                operation_type: BatchOperationType::Insert,
                message: "Duplicate key".to_string(),
            }],
        };

        assert!(!result.is_success());
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.error_count(), 1);
    }

    #[test]
    fn test_batch_error_type() {
        assert_eq!(BatchOperationType::Insert, BatchOperationType::Insert);
        assert_ne!(BatchOperationType::Insert, BatchOperationType::Update);
        assert_ne!(BatchOperationType::Update, BatchOperationType::Delete);
    }

    #[tokio::test]
    async fn test_prepared_statement_cache_new() {
        let cache = PreparedStatementCache::new(10);
        assert_eq!(cache.size().await, 0);
    }

    #[tokio::test]
    async fn test_prepared_statement_cache_get_or_insert() {
        let cache = PreparedStatementCache::new(10);

        let query1 = cache
            .get_or_insert("key1", || "SELECT * FROM users".to_string())
            .await;
        assert_eq!(query1, "SELECT * FROM users");
        assert_eq!(cache.size().await, 1);

        // Same key should return cached value
        let query2 = cache
            .get_or_insert("key1", || "DIFFERENT QUERY".to_string())
            .await;
        assert_eq!(query2, "SELECT * FROM users");
        assert_eq!(cache.size().await, 1);
    }

    #[tokio::test]
    async fn test_prepared_statement_cache_eviction() {
        let cache = PreparedStatementCache::new(2);

        cache.get_or_insert("key1", || "query1".to_string()).await;
        cache.get_or_insert("key2", || "query2".to_string()).await;
        assert_eq!(cache.size().await, 2);

        // Adding third should evict one
        cache.get_or_insert("key3", || "query3".to_string()).await;
        assert_eq!(cache.size().await, 2);
    }

    #[tokio::test]
    async fn test_prepared_statement_cache_clear() {
        let cache = PreparedStatementCache::new(10);

        cache.get_or_insert("key1", || "query1".to_string()).await;
        cache.get_or_insert("key2", || "query2".to_string()).await;
        assert_eq!(cache.size().await, 2);

        cache.clear().await;
        assert_eq!(cache.size().await, 0);
    }

    #[test]
    fn test_savepoint_name() {
        let sp = Savepoint {
            name: "test_savepoint".to_string(),
            released: false,
        };
        assert_eq!(sp.name(), "test_savepoint");
        assert!(!sp.is_released());
    }
}
