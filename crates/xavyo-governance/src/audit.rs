//! Audit logging for governance operations.
//!
//! This module provides audit logging for all governance changes following
//! the F-003 pattern from xavyo-authorization.
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_governance::audit::{AuditStore, InMemoryAuditStore, EntitlementAuditEventInput, EntitlementAuditAction};
//! use std::sync::Arc;
//! use uuid::Uuid;
//!
//! let store = Arc::new(InMemoryAuditStore::new());
//! let input = EntitlementAuditEventInput {
//!     tenant_id: Uuid::new_v4(),
//!     entitlement_id: Some(Uuid::new_v4()),
//!     action: EntitlementAuditAction::Created,
//!     actor_id: Uuid::new_v4(),
//!     ..Default::default()
//! };
//! let event = store.log_event(input).await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::Result;

/// Action performed on an entitlement or assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementAuditAction {
    /// Entitlement was created.
    #[default]
    Created,
    /// Entitlement was updated.
    Updated,
    /// Entitlement was deleted.
    Deleted,
    /// Entitlement status was changed.
    StatusChanged,
    /// Entitlement was assigned to a user.
    Assigned,
    /// Entitlement assignment was revoked.
    Revoked,
}

impl std::fmt::Display for EntitlementAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Updated => write!(f, "updated"),
            Self::Deleted => write!(f, "deleted"),
            Self::StatusChanged => write!(f, "status_changed"),
            Self::Assigned => write!(f, "assigned"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// Action performed on `SoD` rules, violations, or exemptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SodAuditAction {
    /// `SoD` rule was created.
    #[default]
    RuleCreated,
    /// `SoD` rule was updated.
    RuleUpdated,
    /// `SoD` rule was deleted.
    RuleDeleted,
    /// `SoD` exemption was granted.
    ExemptionGranted,
    /// `SoD` exemption was revoked.
    ExemptionRevoked,
    /// `SoD` violation was detected.
    ViolationDetected,
    /// `SoD` violation was resolved.
    ViolationResolved,
}

impl std::fmt::Display for SodAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuleCreated => write!(f, "rule_created"),
            Self::RuleUpdated => write!(f, "rule_updated"),
            Self::RuleDeleted => write!(f, "rule_deleted"),
            Self::ExemptionGranted => write!(f, "exemption_granted"),
            Self::ExemptionRevoked => write!(f, "exemption_revoked"),
            Self::ViolationDetected => write!(f, "violation_detected"),
            Self::ViolationResolved => write!(f, "violation_resolved"),
        }
    }
}

/// An audit event for entitlement operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,
    /// Tenant this event belongs to.
    pub tenant_id: Uuid,
    /// The entitlement involved (if any).
    pub entitlement_id: Option<Uuid>,
    /// The assignment involved (if any).
    pub assignment_id: Option<Uuid>,
    /// The user involved (for assignment events).
    pub user_id: Option<Uuid>,
    /// Action performed.
    pub action: EntitlementAuditAction,
    /// User who performed the action.
    pub actor_id: Uuid,
    /// State before the change (JSON).
    pub before_state: Option<serde_json::Value>,
    /// State after the change (JSON).
    pub after_state: Option<serde_json::Value>,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Input for creating an audit event.
#[derive(Debug, Clone, Default)]
pub struct EntitlementAuditEventInput {
    /// Tenant this event belongs to.
    pub tenant_id: Uuid,
    /// The entitlement involved (if any).
    pub entitlement_id: Option<Uuid>,
    /// The assignment involved (if any).
    pub assignment_id: Option<Uuid>,
    /// The user involved (for assignment events).
    pub user_id: Option<Uuid>,
    /// Action performed.
    pub action: EntitlementAuditAction,
    /// User who performed the action.
    pub actor_id: Uuid,
    /// State before the change (JSON).
    pub before_state: Option<serde_json::Value>,
    /// State after the change (JSON).
    pub after_state: Option<serde_json::Value>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Filter for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,
    /// Filter by assignment ID.
    pub assignment_id: Option<Uuid>,
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,
    /// Filter by action type.
    pub action: Option<EntitlementAuditAction>,
    /// Filter by events after this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter by events before this date.
    pub to_date: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Number of results to skip.
    pub offset: Option<usize>,
}

/// Trait for audit event storage backends.
#[async_trait::async_trait]
pub trait AuditStore: Send + Sync {
    /// Log an audit event.
    async fn log_event(&self, input: EntitlementAuditEventInput) -> Result<EntitlementAuditEvent>;

    /// Query audit events.
    async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<Vec<EntitlementAuditEvent>>;

    /// Get a specific audit event by ID.
    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<EntitlementAuditEvent>>;
}

/// In-memory audit store for testing.
#[derive(Debug, Default)]
pub struct InMemoryAuditStore {
    events: Arc<RwLock<HashMap<Uuid, EntitlementAuditEvent>>>,
}

impl InMemoryAuditStore {
    /// Create a new in-memory audit store.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the count of events in the store.
    pub async fn count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Clear all events (for testing).
    pub async fn clear(&self) {
        self.events.write().await.clear();
    }

    /// Get all events (for testing).
    #[must_use] 
    pub fn get_all(&self) -> Vec<EntitlementAuditEvent> {
        // Use try_read to avoid blocking
        self.events
            .try_read()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn log_event(&self, input: EntitlementAuditEventInput) -> Result<EntitlementAuditEvent> {
        let event = EntitlementAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            entitlement_id: input.entitlement_id,
            assignment_id: input.assignment_id,
            user_id: input.user_id,
            action: input.action,
            actor_id: input.actor_id,
            before_state: input.before_state,
            after_state: input.after_state,
            timestamp: Utc::now(),
            metadata: input.metadata,
        };

        self.events.write().await.insert(event.id, event.clone());
        Ok(event)
    }

    async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: AuditEventFilter,
    ) -> Result<Vec<EntitlementAuditEvent>> {
        let events = self.events.read().await;
        let mut results: Vec<_> = events
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| {
                filter
                    .entitlement_id
                    .is_none_or(|id| e.entitlement_id == Some(id))
            })
            .filter(|e| {
                filter
                    .assignment_id
                    .is_none_or(|id| e.assignment_id == Some(id))
            })
            .filter(|e| filter.user_id.is_none_or(|id| e.user_id == Some(id)))
            .filter(|e| filter.actor_id.is_none_or(|id| e.actor_id == id))
            .filter(|e| filter.action.is_none_or(|a| e.action == a))
            .filter(|e| filter.from_date.is_none_or(|d| e.timestamp >= d))
            .filter(|e| filter.to_date.is_none_or(|d| e.timestamp <= d))
            .cloned()
            .collect();

        // Sort by timestamp descending (most recent first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply offset and limit
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);

        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<EntitlementAuditEvent>> {
        let events = self.events.read().await;
        Ok(events
            .get(&event_id)
            .filter(|e| e.tenant_id == tenant_id)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_event() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();

        let input = EntitlementAuditEventInput {
            tenant_id,
            entitlement_id: Some(entitlement_id),
            action: EntitlementAuditAction::Created,
            actor_id,
            ..Default::default()
        };

        let event = store.log_event(input).await.unwrap();
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.entitlement_id, Some(entitlement_id));
        assert_eq!(event.action, EntitlementAuditAction::Created);
        assert_eq!(event.actor_id, actor_id);
    }

    #[tokio::test]
    async fn test_query_events_by_entitlement() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();

        // Log two events for the same entitlement
        for action in [
            EntitlementAuditAction::Created,
            EntitlementAuditAction::Updated,
        ] {
            store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    entitlement_id: Some(entitlement_id),
                    action,
                    actor_id: Uuid::new_v4(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // Log one event for a different entitlement
        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                entitlement_id: Some(Uuid::new_v4()),
                action: EntitlementAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let filter = AuditEventFilter {
            entitlement_id: Some(entitlement_id),
            ..Default::default()
        };

        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_query_events_by_action() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();

        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Assigned,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let filter = AuditEventFilter {
            action: Some(EntitlementAuditAction::Created),
            ..Default::default()
        };

        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, EntitlementAuditAction::Created);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = InMemoryAuditStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        store
            .log_event(EntitlementAuditEventInput {
                tenant_id: tenant_a,
                action: EntitlementAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let events_a = store
            .query_events(tenant_a, AuditEventFilter::default())
            .await
            .unwrap();
        let events_b = store
            .query_events(tenant_b, AuditEventFilter::default())
            .await
            .unwrap();

        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 0);
    }

    #[tokio::test]
    async fn test_get_event() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();

        let event = store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let retrieved = store.get_event(tenant_id, event.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, event.id);

        // Should not find in different tenant
        let not_found = store.get_event(Uuid::new_v4(), event.id).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_pagination() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();

        // Create 5 events
        for _ in 0..5 {
            store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    action: EntitlementAuditAction::Created,
                    actor_id: Uuid::new_v4(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // Get first 2
        let filter = AuditEventFilter {
            limit: Some(2),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 2);

        // Get next 2
        let filter = AuditEventFilter {
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 2);

        // Get last 1
        let filter = AuditEventFilter {
            limit: Some(2),
            offset: Some(4),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_action_display() {
        assert_eq!(EntitlementAuditAction::Created.to_string(), "created");
        assert_eq!(EntitlementAuditAction::Assigned.to_string(), "assigned");
        assert_eq!(EntitlementAuditAction::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_sod_audit_action_display() {
        assert_eq!(SodAuditAction::RuleCreated.to_string(), "rule_created");
        assert_eq!(SodAuditAction::RuleUpdated.to_string(), "rule_updated");
        assert_eq!(SodAuditAction::RuleDeleted.to_string(), "rule_deleted");
        assert_eq!(
            SodAuditAction::ExemptionGranted.to_string(),
            "exemption_granted"
        );
        assert_eq!(
            SodAuditAction::ExemptionRevoked.to_string(),
            "exemption_revoked"
        );
        assert_eq!(
            SodAuditAction::ViolationDetected.to_string(),
            "violation_detected"
        );
        assert_eq!(
            SodAuditAction::ViolationResolved.to_string(),
            "violation_resolved"
        );
    }

    #[test]
    fn test_sod_audit_action_default() {
        let action = SodAuditAction::default();
        assert_eq!(action, SodAuditAction::RuleCreated);
    }

    #[tokio::test]
    async fn test_query_by_date_range() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();

        // Log an event
        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Query with from_date in the past - should find it
        let filter = AuditEventFilter {
            from_date: Some(Utc::now() - chrono::Duration::hours(1)),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 1);

        // Query with from_date in the future - should not find it
        let filter = AuditEventFilter {
            from_date: Some(Utc::now() + chrono::Duration::hours(1)),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn test_query_by_actor() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let actor1 = Uuid::new_v4();
        let actor2 = Uuid::new_v4();

        // Log event by actor1
        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: actor1,
                ..Default::default()
            })
            .await
            .unwrap();

        // Log event by actor2
        store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: actor2,
                ..Default::default()
            })
            .await
            .unwrap();

        // Filter by actor1
        let filter = AuditEventFilter {
            actor_id: Some(actor1),
            ..Default::default()
        };
        let events = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor_id, actor1);
    }

    #[tokio::test]
    async fn test_events_ordered_by_timestamp_descending() {
        let store = InMemoryAuditStore::new();
        let tenant_id = Uuid::new_v4();

        // Log multiple events rapidly
        for _ in 0..5 {
            store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    action: EntitlementAuditAction::Created,
                    actor_id: Uuid::new_v4(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        let events = store
            .query_events(tenant_id, AuditEventFilter::default())
            .await
            .unwrap();

        // Verify descending order (most recent first)
        for i in 1..events.len() {
            assert!(events[i - 1].timestamp >= events[i].timestamp);
        }
    }
}
