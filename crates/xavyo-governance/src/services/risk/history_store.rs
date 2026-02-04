//! Risk history storage trait and in-memory implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::error::GovernanceError;
use crate::types::RiskHistory;

/// Trait for storing and retrieving risk history records.
#[async_trait]
pub trait RiskHistoryStore: Send + Sync {
    /// Record a new risk history entry.
    async fn record(&self, history: RiskHistory) -> Result<(), GovernanceError>;

    /// Get risk trend for a user since a given date.
    ///
    /// Returns entries ordered by `recorded_at` ascending.
    async fn get_trend(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<RiskHistory>, GovernanceError>;

    /// Get the most recent risk history entry for a user.
    async fn get_latest(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<RiskHistory>, GovernanceError>;
}

/// In-memory implementation of `RiskHistoryStore` for testing.
#[derive(Debug, Default)]
pub struct InMemoryRiskHistoryStore {
    // Key: (tenant_id, user_id), Value: list of history entries
    history: RwLock<HashMap<(Uuid, Uuid), Vec<RiskHistory>>>,
}

impl InMemoryRiskHistoryStore {
    /// Create a new in-memory history store.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            history: RwLock::new(HashMap::new()),
        }
    }

    /// Get all history entries (for testing).
    pub fn get_all(&self) -> Vec<RiskHistory> {
        self.history
            .read()
            .expect("lock poisoned")
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    /// Clear all history entries (for testing).
    pub fn clear(&self) {
        self.history.write().expect("lock poisoned").clear();
    }

    /// Get count of all history entries (for testing).
    pub fn count(&self) -> usize {
        self.history
            .read()
            .expect("lock poisoned")
            .values()
            .map(std::vec::Vec::len)
            .sum()
    }
}

#[async_trait]
impl RiskHistoryStore for InMemoryRiskHistoryStore {
    async fn record(&self, history: RiskHistory) -> Result<(), GovernanceError> {
        let key = (history.tenant_id, history.user_id);
        self.history
            .write()
            .expect("lock poisoned")
            .entry(key)
            .or_default()
            .push(history);
        Ok(())
    }

    async fn get_trend(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<RiskHistory>, GovernanceError> {
        let key = (tenant_id, user_id);
        let history = self.history.read().expect("lock poisoned");

        let mut entries: Vec<RiskHistory> = history
            .get(&key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|h| h.recorded_at >= since)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Sort by recorded_at ascending
        entries.sort_by_key(|h| h.recorded_at);

        Ok(entries)
    }

    async fn get_latest(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<RiskHistory>, GovernanceError> {
        let key = (tenant_id, user_id);
        let history = self.history.read().expect("lock poisoned");

        Ok(history
            .get(&key)
            .and_then(|entries| entries.iter().max_by_key(|h| h.recorded_at).cloned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RiskLevel;
    use chrono::Duration;

    #[tokio::test]
    async fn test_history_store_record_and_get_trend() {
        let store = InMemoryRiskHistoryStore::new();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Record multiple entries
        let history1 = RiskHistory::new(tenant_id, user_id, 25, RiskLevel::Low);
        store.record(history1).await.unwrap();

        let history2 = RiskHistory::new(tenant_id, user_id, 50, RiskLevel::Medium);
        store.record(history2).await.unwrap();

        let history3 = RiskHistory::new(tenant_id, user_id, 75, RiskLevel::High);
        store.record(history3).await.unwrap();

        // Get trend since an hour ago
        let since = Utc::now() - Duration::hours(1);
        let trend = store.get_trend(tenant_id, user_id, since).await.unwrap();

        assert_eq!(trend.len(), 3);
    }

    #[tokio::test]
    async fn test_history_store_get_trend_empty() {
        let store = InMemoryRiskHistoryStore::new();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let since = Utc::now() - Duration::hours(1);
        let trend = store.get_trend(tenant_id, user_id, since).await.unwrap();

        assert!(trend.is_empty());
    }

    #[tokio::test]
    async fn test_history_store_get_latest() {
        let store = InMemoryRiskHistoryStore::new();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Record multiple entries
        store
            .record(RiskHistory::new(tenant_id, user_id, 25, RiskLevel::Low))
            .await
            .unwrap();
        store
            .record(RiskHistory::new(tenant_id, user_id, 50, RiskLevel::Medium))
            .await
            .unwrap();
        store
            .record(RiskHistory::new(tenant_id, user_id, 75, RiskLevel::High))
            .await
            .unwrap();

        let latest = store.get_latest(tenant_id, user_id).await.unwrap();
        assert!(latest.is_some());
        // Last recorded should be High
        assert_eq!(latest.unwrap().level, RiskLevel::High);
    }

    #[tokio::test]
    async fn test_history_store_tenant_isolation() {
        let store = InMemoryRiskHistoryStore::new();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Record in tenant1
        store
            .record(RiskHistory::new(tenant1, user_id, 25, RiskLevel::Low))
            .await
            .unwrap();

        // Record in tenant2
        store
            .record(RiskHistory::new(tenant2, user_id, 75, RiskLevel::High))
            .await
            .unwrap();

        // Get trend for tenant1 - should only see Low
        let since = Utc::now() - Duration::hours(1);
        let trend1 = store.get_trend(tenant1, user_id, since).await.unwrap();
        assert_eq!(trend1.len(), 1);
        assert_eq!(trend1[0].level, RiskLevel::Low);

        // Get trend for tenant2 - should only see High
        let trend2 = store.get_trend(tenant2, user_id, since).await.unwrap();
        assert_eq!(trend2.len(), 1);
        assert_eq!(trend2[0].level, RiskLevel::High);
    }
}
