//! Risk threshold storage trait and in-memory implementation.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::error::GovernanceError;
use crate::types::RiskThresholds;

/// Trait for storing and retrieving risk thresholds.
#[async_trait]
pub trait RiskThresholdStore: Send + Sync {
    /// Get thresholds for a tenant.
    ///
    /// Returns `None` if no custom thresholds are configured.
    async fn get(&self, tenant_id: Uuid) -> Result<Option<RiskThresholds>, GovernanceError>;

    /// Set thresholds for a tenant.
    async fn set(&self, thresholds: RiskThresholds) -> Result<(), GovernanceError>;

    /// Delete thresholds for a tenant (revert to defaults).
    async fn delete(&self, tenant_id: Uuid) -> Result<(), GovernanceError>;
}

/// In-memory implementation of `RiskThresholdStore` for testing.
#[derive(Debug, Default)]
pub struct InMemoryRiskThresholdStore {
    thresholds: RwLock<HashMap<Uuid, RiskThresholds>>,
}

impl InMemoryRiskThresholdStore {
    /// Create a new in-memory threshold store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            thresholds: RwLock::new(HashMap::new()),
        }
    }

    /// Get all thresholds (for testing).
    pub fn get_all(&self) -> Vec<RiskThresholds> {
        self.thresholds
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Clear all thresholds (for testing).
    pub fn clear(&self) {
        self.thresholds
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[async_trait]
impl RiskThresholdStore for InMemoryRiskThresholdStore {
    async fn get(&self, tenant_id: Uuid) -> Result<Option<RiskThresholds>, GovernanceError> {
        Ok(self
            .thresholds
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&tenant_id)
            .cloned())
    }

    async fn set(&self, thresholds: RiskThresholds) -> Result<(), GovernanceError> {
        self.thresholds
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(thresholds.tenant_id, thresholds);
        Ok(())
    }

    async fn delete(&self, tenant_id: Uuid) -> Result<(), GovernanceError> {
        self.thresholds
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&tenant_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threshold_store_get_empty() {
        let store = InMemoryRiskThresholdStore::new();
        let tenant_id = Uuid::new_v4();

        let result = store.get(tenant_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_threshold_store_set_and_get() {
        let store = InMemoryRiskThresholdStore::new();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let thresholds = RiskThresholds::new(tenant_id, 20, 40, 60, actor_id);
        store.set(thresholds.clone()).await.unwrap();

        let result = store.get(tenant_id).await.unwrap();
        assert!(result.is_some());
        let stored = result.unwrap();
        assert_eq!(stored.tenant_id, tenant_id);
        assert_eq!(stored.low_max, 20);
        assert_eq!(stored.medium_max, 40);
        assert_eq!(stored.high_max, 60);
    }

    #[tokio::test]
    async fn test_threshold_store_delete() {
        let store = InMemoryRiskThresholdStore::new();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let thresholds = RiskThresholds::new(tenant_id, 20, 40, 60, actor_id);
        store.set(thresholds).await.unwrap();

        store.delete(tenant_id).await.unwrap();

        let result = store.get(tenant_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_threshold_store_overwrite() {
        let store = InMemoryRiskThresholdStore::new();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let thresholds1 = RiskThresholds::new(tenant_id, 20, 40, 60, actor_id);
        store.set(thresholds1).await.unwrap();

        let thresholds2 = RiskThresholds::new(tenant_id, 30, 50, 70, actor_id);
        store.set(thresholds2).await.unwrap();

        let result = store.get(tenant_id).await.unwrap().unwrap();
        assert_eq!(result.low_max, 30);
        assert_eq!(result.medium_max, 50);
        assert_eq!(result.high_max, 70);
    }
}
