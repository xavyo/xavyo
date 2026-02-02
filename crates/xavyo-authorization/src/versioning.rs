//! Policy versioning for history tracking and rollback.
//!
//! This module provides version management for authorization policies.
//! Each policy modification creates a new version, enabling history
//! tracking and rollback capabilities.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::AuthorizationError;

/// A snapshot of a policy at a specific version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub tenant_id: Uuid,
    pub version: i32,
    pub policy_snapshot: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub change_summary: Option<String>,
}

/// Summary of a policy version (without full snapshot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersionSummary {
    pub id: Uuid,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub change_summary: Option<String>,
}

/// Difference between two policy versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    pub version_a: i32,
    pub version_b: i32,
    pub snapshot_a: serde_json::Value,
    pub snapshot_b: serde_json::Value,
}

/// Trait for version storage backends.
#[async_trait::async_trait]
pub trait VersionStore: Send + Sync {
    async fn create_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        policy_snapshot: &serde_json::Value,
        created_by: Uuid,
        change_summary: Option<String>,
    ) -> Result<PolicyVersion, AuthorizationError>;

    async fn get_version_history(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyVersionSummary>, AuthorizationError>;

    async fn get_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        version: i32,
    ) -> Result<Option<PolicyVersion>, AuthorizationError>;

    async fn get_latest_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<PolicyVersion>, AuthorizationError>;

    async fn get_version_count(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<usize, AuthorizationError>;
}

/// In-memory version store for testing.
pub struct InMemoryVersionStore {
    versions: RwLock<HashMap<(Uuid, Uuid), Vec<PolicyVersion>>>,
}

impl Default for InMemoryVersionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryVersionStore {
    pub fn new() -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl VersionStore for InMemoryVersionStore {
    async fn create_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        policy_snapshot: &serde_json::Value,
        created_by: Uuid,
        change_summary: Option<String>,
    ) -> Result<PolicyVersion, AuthorizationError> {
        let mut versions = self.versions.write().await;
        let key = (tenant_id, policy_id);
        let policy_versions = versions.entry(key).or_insert_with(Vec::new);

        let next_version = policy_versions.len() as i32 + 1;
        let version = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id,
            tenant_id,
            version: next_version,
            policy_snapshot: policy_snapshot.clone(),
            created_at: Utc::now(),
            created_by,
            change_summary,
        };

        policy_versions.push(version.clone());
        Ok(version)
    }

    async fn get_version_history(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyVersionSummary>, AuthorizationError> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        let summaries = versions
            .get(&key)
            .map(|v| {
                v.iter()
                    .rev()
                    .map(|pv| PolicyVersionSummary {
                        id: pv.id,
                        version: pv.version,
                        created_at: pv.created_at,
                        created_by: pv.created_by,
                        change_summary: pv.change_summary.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(summaries)
    }

    async fn get_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        version: i32,
    ) -> Result<Option<PolicyVersion>, AuthorizationError> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        Ok(versions
            .get(&key)
            .and_then(|v| v.iter().find(|pv| pv.version == version).cloned()))
    }

    async fn get_latest_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<PolicyVersion>, AuthorizationError> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        Ok(versions.get(&key).and_then(|v| v.last().cloned()))
    }

    async fn get_version_count(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<usize, AuthorizationError> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        Ok(versions.get(&key).map(|v| v.len()).unwrap_or(0))
    }
}

/// Service for managing policy versions.
pub struct PolicyVersionService {
    store: Arc<dyn VersionStore>,
}

impl PolicyVersionService {
    pub fn new(store: Arc<dyn VersionStore>) -> Self {
        Self { store }
    }

    pub fn in_memory() -> Self {
        Self::new(Arc::new(InMemoryVersionStore::new()))
    }

    pub async fn create_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        policy_snapshot: &serde_json::Value,
        created_by: Uuid,
        change_summary: Option<String>,
    ) -> Result<PolicyVersion, AuthorizationError> {
        self.store
            .create_version(
                tenant_id,
                policy_id,
                policy_snapshot,
                created_by,
                change_summary,
            )
            .await
    }

    pub async fn get_version_history(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyVersionSummary>, AuthorizationError> {
        self.store.get_version_history(tenant_id, policy_id).await
    }

    pub async fn get_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        version: i32,
    ) -> Result<Option<PolicyVersion>, AuthorizationError> {
        self.store.get_version(tenant_id, policy_id, version).await
    }

    pub async fn get_latest_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<PolicyVersion>, AuthorizationError> {
        self.store.get_latest_version(tenant_id, policy_id).await
    }

    pub async fn rollback_to_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        target_version: i32,
        actor_id: Uuid,
    ) -> Result<PolicyVersion, AuthorizationError> {
        let target = self
            .get_version(tenant_id, policy_id, target_version)
            .await?
            .ok_or_else(|| {
                AuthorizationError::NotFound(format!(
                    "Version {} not found for policy {}",
                    target_version, policy_id
                ))
            })?;

        let change_summary = Some(format!("Rollback to version {}", target_version));

        self.create_version(
            tenant_id,
            policy_id,
            &target.policy_snapshot,
            actor_id,
            change_summary,
        )
        .await
    }

    pub fn compare_versions(v1: &PolicyVersion, v2: &PolicyVersion) -> VersionDiff {
        VersionDiff {
            version_a: v1.version,
            version_b: v2.version,
            snapshot_a: v1.policy_snapshot.clone(),
            snapshot_b: v2.policy_snapshot.clone(),
        }
    }

    pub async fn get_version_count(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<usize, AuthorizationError> {
        self.store.get_version_count(tenant_id, policy_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_version_serialization() {
        let version = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            version: 1,
            policy_snapshot: serde_json::json!({"name": "test", "effect": "allow"}),
            created_at: Utc::now(),
            created_by: Uuid::new_v4(),
            change_summary: Some("Initial version".to_string()),
        };

        let json = serde_json::to_string(&version).unwrap();
        let deserialized: PolicyVersion = serde_json::from_str(&json).unwrap();

        assert_eq!(version.id, deserialized.id);
        assert_eq!(version.version, deserialized.version);
    }

    #[tokio::test]
    async fn test_version_creation_on_policy_update() {
        let service = PolicyVersionService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let snapshot = serde_json::json!({"name": "test", "effect": "allow"});
        let version = service
            .create_version(
                tenant_id,
                policy_id,
                &snapshot,
                actor_id,
                Some("Initial".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(version.version, 1);
        assert_eq!(version.policy_snapshot, snapshot);
    }

    #[tokio::test]
    async fn test_version_history_query() {
        let service = PolicyVersionService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Create multiple versions
        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"v": 1}),
                actor_id,
                None,
            )
            .await
            .unwrap();
        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"v": 2}),
                actor_id,
                None,
            )
            .await
            .unwrap();
        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"v": 3}),
                actor_id,
                None,
            )
            .await
            .unwrap();

        let history = service
            .get_version_history(tenant_id, policy_id)
            .await
            .unwrap();

        assert_eq!(history.len(), 3);
        // Should be in descending order
        assert_eq!(history[0].version, 3);
        assert_eq!(history[1].version, 2);
        assert_eq!(history[2].version, 1);
    }

    #[test]
    fn test_version_comparison() {
        let v1 = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            version: 1,
            policy_snapshot: serde_json::json!({"name": "old", "effect": "allow"}),
            created_at: Utc::now(),
            created_by: Uuid::new_v4(),
            change_summary: None,
        };

        let v2 = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id: v1.policy_id,
            tenant_id: v1.tenant_id,
            version: 2,
            policy_snapshot: serde_json::json!({"name": "new", "effect": "deny"}),
            created_at: Utc::now(),
            created_by: Uuid::new_v4(),
            change_summary: Some("Changed effect".to_string()),
        };

        let diff = PolicyVersionService::compare_versions(&v1, &v2);

        assert_eq!(diff.version_a, 1);
        assert_eq!(diff.version_b, 2);
        assert_ne!(diff.snapshot_a, diff.snapshot_b);
    }

    #[tokio::test]
    async fn test_policy_rollback_creates_new_version() {
        let service = PolicyVersionService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Create initial version
        let v1_snapshot = serde_json::json!({"name": "original"});
        service
            .create_version(tenant_id, policy_id, &v1_snapshot, actor_id, None)
            .await
            .unwrap();

        // Create second version
        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"name": "modified"}),
                actor_id,
                None,
            )
            .await
            .unwrap();

        // Rollback to version 1
        let rollback = service
            .rollback_to_version(tenant_id, policy_id, 1, actor_id)
            .await
            .unwrap();

        // Should create version 3 with snapshot from version 1
        assert_eq!(rollback.version, 3);
        assert_eq!(rollback.policy_snapshot, v1_snapshot);
        assert!(rollback.change_summary.unwrap().contains("Rollback"));
    }

    #[tokio::test]
    async fn test_version_numbers_auto_increment() {
        let service = PolicyVersionService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        for i in 1..=5 {
            let v = service
                .create_version(
                    tenant_id,
                    policy_id,
                    &serde_json::json!({"i": i}),
                    actor_id,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(v.version, i);
        }

        let count = service
            .get_version_count(tenant_id, policy_id)
            .await
            .unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_version_tenant_isolation() {
        let service = PolicyVersionService::in_memory();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        service
            .create_version(tenant_a, policy_id, &serde_json::json!({}), actor_id, None)
            .await
            .unwrap();

        let history_a = service
            .get_version_history(tenant_a, policy_id)
            .await
            .unwrap();
        let history_b = service
            .get_version_history(tenant_b, policy_id)
            .await
            .unwrap();

        assert_eq!(history_a.len(), 1);
        assert_eq!(history_b.len(), 0);
    }

    #[tokio::test]
    async fn test_get_specific_version() {
        let service = PolicyVersionService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"v": 1}),
                actor_id,
                None,
            )
            .await
            .unwrap();
        service
            .create_version(
                tenant_id,
                policy_id,
                &serde_json::json!({"v": 2}),
                actor_id,
                None,
            )
            .await
            .unwrap();

        let v1 = service.get_version(tenant_id, policy_id, 1).await.unwrap();
        let v2 = service.get_version(tenant_id, policy_id, 2).await.unwrap();
        let v3 = service.get_version(tenant_id, policy_id, 3).await.unwrap();

        assert!(v1.is_some());
        assert!(v2.is_some());
        assert!(v3.is_none());

        assert_eq!(v1.unwrap().policy_snapshot["v"], 1);
        assert_eq!(v2.unwrap().policy_snapshot["v"], 2);
    }
}
