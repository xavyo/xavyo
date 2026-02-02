//! Policy audit logging for compliance.
//!
//! This module provides audit logging for all policy administration actions.
//! Events can be logged to different backends (database, Kafka, in-memory for testing).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use crate::error::AuthorizationError;

/// Action performed on a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Created,
    Updated,
    Deleted,
    Enabled,
    Disabled,
    RolledBack,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::Created => write!(f, "created"),
            PolicyAction::Updated => write!(f, "updated"),
            PolicyAction::Deleted => write!(f, "deleted"),
            PolicyAction::Enabled => write!(f, "enabled"),
            PolicyAction::Disabled => write!(f, "disabled"),
            PolicyAction::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// A policy audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub policy_id: Option<Uuid>,
    pub action: PolicyAction,
    pub actor_id: Uuid,
    pub actor_ip: Option<IpAddr>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

/// Input for creating an audit event.
#[derive(Debug, Clone, Default)]
pub struct PolicyAuditEventInput {
    pub tenant_id: Uuid,
    pub policy_id: Option<Uuid>,
    pub action: PolicyAction,
    pub actor_id: Uuid,
    pub actor_ip: Option<IpAddr>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub policy_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub action: Option<PolicyAction>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Trait for audit event storage backends.
#[async_trait::async_trait]
pub trait AuditStore: Send + Sync {
    async fn log_event(
        &self,
        input: PolicyAuditEventInput,
    ) -> Result<PolicyAuditEvent, AuthorizationError>;
    async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<Vec<PolicyAuditEvent>, AuthorizationError>;
    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<PolicyAuditEvent>, AuthorizationError>;
    async fn count_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<usize, AuthorizationError>;
}

/// In-memory audit store for testing.
pub struct InMemoryAuditStore {
    events: RwLock<HashMap<Uuid, PolicyAuditEvent>>,
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn log_event(
        &self,
        input: PolicyAuditEventInput,
    ) -> Result<PolicyAuditEvent, AuthorizationError> {
        let event = PolicyAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            policy_id: input.policy_id,
            action: input.action,
            actor_id: input.actor_id,
            actor_ip: input.actor_ip,
            before_state: input.before_state,
            after_state: input.after_state,
            timestamp: Utc::now(),
            metadata: input.metadata,
        };

        info!(
            event_id = %event.id,
            tenant_id = %event.tenant_id,
            policy_id = ?event.policy_id,
            action = %event.action,
            actor_id = %event.actor_id,
            "Policy audit event logged"
        );

        let mut events = self.events.write().await;
        events.insert(event.id, event.clone());
        Ok(event)
    }

    async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<Vec<PolicyAuditEvent>, AuthorizationError> {
        let events = self.events.read().await;
        let mut results: Vec<_> = events
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| filter.policy_id.is_none_or(|id| e.policy_id == Some(id)))
            .filter(|e| filter.actor_id.is_none_or(|id| e.actor_id == id))
            .filter(|e| filter.action.is_none_or(|a| e.action == a))
            .filter(|e| filter.from_date.is_none_or(|d| e.timestamp >= d))
            .filter(|e| filter.to_date.is_none_or(|d| e.timestamp <= d))
            .cloned()
            .collect();

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(100);

        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<PolicyAuditEvent>, AuthorizationError> {
        let events = self.events.read().await;
        Ok(events
            .get(&event_id)
            .filter(|e| e.tenant_id == tenant_id)
            .cloned())
    }

    async fn count_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<usize, AuthorizationError> {
        let events = self.events.read().await;
        let count = events
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| filter.policy_id.is_none_or(|id| e.policy_id == Some(id)))
            .filter(|e| filter.actor_id.is_none_or(|id| e.actor_id == id))
            .filter(|e| filter.action.is_none_or(|a| e.action == a))
            .filter(|e| filter.from_date.is_none_or(|d| e.timestamp >= d))
            .filter(|e| filter.to_date.is_none_or(|d| e.timestamp <= d))
            .count();
        Ok(count)
    }
}

/// Service for policy audit logging.
pub struct PolicyAuditService {
    store: Arc<dyn AuditStore>,
}

impl PolicyAuditService {
    pub fn new(store: Arc<dyn AuditStore>) -> Self {
        Self { store }
    }

    pub fn in_memory() -> Self {
        Self::new(Arc::new(InMemoryAuditStore::new()))
    }

    pub async fn log_event(
        &self,
        input: PolicyAuditEventInput,
    ) -> Result<PolicyAuditEvent, AuthorizationError> {
        self.store.log_event(input).await
    }

    pub async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<Vec<PolicyAuditEvent>, AuthorizationError> {
        self.store.query_events(tenant_id, filter).await
    }

    pub async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<PolicyAuditEvent>, AuthorizationError> {
        self.store.get_event(tenant_id, event_id).await
    }

    pub async fn count_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<usize, AuthorizationError> {
        self.store.count_events(tenant_id, filter).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_action_display() {
        assert_eq!(PolicyAction::Created.to_string(), "created");
        assert_eq!(PolicyAction::Updated.to_string(), "updated");
        assert_eq!(PolicyAction::Deleted.to_string(), "deleted");
        assert_eq!(PolicyAction::Enabled.to_string(), "enabled");
        assert_eq!(PolicyAction::Disabled.to_string(), "disabled");
        assert_eq!(PolicyAction::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn test_policy_action_serialization() {
        let action = PolicyAction::Updated;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"updated\"");

        let deserialized: PolicyAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }

    #[tokio::test]
    async fn test_audit_log_on_policy_create() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let event = service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(policy_id),
                action: PolicyAction::Created,
                actor_id,
                after_state: Some(serde_json::json!({"name": "test"})),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.policy_id, Some(policy_id));
        assert_eq!(event.action, PolicyAction::Created);
    }

    #[tokio::test]
    async fn test_audit_log_on_policy_update() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();

        let event = service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(policy_id),
                action: PolicyAction::Updated,
                actor_id: Uuid::new_v4(),
                before_state: Some(serde_json::json!({"name": "old"})),
                after_state: Some(serde_json::json!({"name": "new"})),
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(event.before_state.is_some());
        assert!(event.after_state.is_some());
    }

    #[tokio::test]
    async fn test_audit_log_on_policy_delete() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();

        let event = service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Deleted,
                actor_id: Uuid::new_v4(),
                before_state: Some(serde_json::json!({"deleted": true})),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(event.action, PolicyAction::Deleted);
        assert!(event.before_state.is_some());
        assert!(event.after_state.is_none());
    }

    #[tokio::test]
    async fn test_audit_log_filtering_by_policy() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();

        // Log events for different policies
        service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(policy_id),
                action: PolicyAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let filter = AuditEventFilter {
            policy_id: Some(policy_id),
            ..Default::default()
        };
        let events = service.query_events(tenant_id, filter).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].policy_id, Some(policy_id));
    }

    #[tokio::test]
    async fn test_audit_log_filtering_by_actor() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Created,
                actor_id,
                ..Default::default()
            })
            .await
            .unwrap();

        service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let filter = AuditEventFilter {
            actor_id: Some(actor_id),
            ..Default::default()
        };
        let events = service.query_events(tenant_id, filter).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor_id, actor_id);
    }

    #[tokio::test]
    async fn test_audit_log_filtering_by_date_range() {
        let service = PolicyAuditService::in_memory();
        let tenant_id = Uuid::new_v4();

        service
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let now = Utc::now();
        let filter = AuditEventFilter {
            from_date: Some(now - chrono::Duration::hours(1)),
            to_date: Some(now + chrono::Duration::hours(1)),
            ..Default::default()
        };
        let events = service.query_events(tenant_id, filter).await.unwrap();

        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_tenant_isolation() {
        let service = PolicyAuditService::in_memory();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        service
            .log_event(PolicyAuditEventInput {
                tenant_id: tenant_a,
                policy_id: Some(Uuid::new_v4()),
                action: PolicyAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let events_a = service
            .query_events(tenant_a, AuditEventFilter::default())
            .await
            .unwrap();
        let events_b = service
            .query_events(tenant_b, AuditEventFilter::default())
            .await
            .unwrap();

        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 0);
    }
}
