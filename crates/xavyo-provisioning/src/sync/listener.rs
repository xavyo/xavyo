//! Change listeners for detecting changes from external systems.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use super::change::InboundChange;
use super::error::{SyncError, SyncResult};
use super::token::SyncToken;
use super::types::ChangeType;

/// Result of fetching changes from an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Changes detected.
    pub changes: Vec<DetectedChange>,
    /// New token for next fetch (if changed).
    pub new_token: Option<String>,
    /// Whether there are more changes to fetch.
    pub has_more: bool,
}

impl ChangeSet {
    /// Create an empty changeset.
    pub fn empty() -> Self {
        Self {
            changes: vec![],
            new_token: None,
            has_more: false,
        }
    }

    /// Create a changeset with changes.
    pub fn with_changes(changes: Vec<DetectedChange>) -> Self {
        Self {
            changes,
            new_token: None,
            has_more: false,
        }
    }
}

/// A change detected in an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedChange {
    /// External system's unique identifier.
    pub external_uid: String,
    /// Object class in the external system.
    pub object_class: String,
    /// Type of change.
    pub change_type: ChangeType,
    /// Attributes from the external system.
    pub attributes: serde_json::Value,
}

impl DetectedChange {
    /// Create a new detected change.
    pub fn new(
        external_uid: String,
        object_class: String,
        change_type: ChangeType,
        attributes: serde_json::Value,
    ) -> Self {
        Self {
            external_uid,
            object_class,
            change_type,
            attributes,
        }
    }

    /// Convert to an inbound change.
    pub fn into_inbound(self, tenant_id: Uuid, connector_id: Uuid) -> InboundChange {
        InboundChange::new(
            tenant_id,
            connector_id,
            self.change_type,
            self.external_uid,
            self.object_class,
            self.attributes,
        )
    }
}

/// Trait for detecting changes from external systems.
#[async_trait]
pub trait ChangeListener: Send + Sync {
    /// Fetch changes since the given token.
    ///
    /// If token is None, this should perform a full sync (fetch all objects).
    async fn fetch_changes(
        &self,
        token: Option<&SyncToken>,
        batch_size: i32,
    ) -> SyncResult<ChangeSet>;

    /// Check if the connector supports change detection.
    fn supports_change_detection(&self) -> bool;

    /// Get the name of this listener for logging.
    fn name(&self) -> &str;
}

/// Polling-based change listener that periodically fetches all objects
/// and compares with known state.
pub struct PollingChangeListener {
    /// Listener name.
    name: String,
    /// Polling interval.
    _interval: Duration,
}

impl PollingChangeListener {
    /// Create a new polling change listener.
    pub fn new(name: impl Into<String>, interval: Duration) -> Self {
        Self {
            name: name.into(),
            _interval: interval,
        }
    }
}

#[async_trait]
impl ChangeListener for PollingChangeListener {
    async fn fetch_changes(
        &self,
        _token: Option<&SyncToken>,
        _batch_size: i32,
    ) -> SyncResult<ChangeSet> {
        // Polling listeners typically need to compare current state
        // with previous state. This is a stub that should be implemented
        // by specific connector implementations.
        Err(SyncError::connector(
            "Polling change listener not implemented for this connector",
        ))
    }

    fn supports_change_detection(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Event-based change listener for connectors that support push notifications.
pub struct EventChangeListener {
    /// Listener name.
    name: String,
}

impl EventChangeListener {
    /// Create a new event-based change listener.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl ChangeListener for EventChangeListener {
    async fn fetch_changes(
        &self,
        _token: Option<&SyncToken>,
        _batch_size: i32,
    ) -> SyncResult<ChangeSet> {
        // Event listeners receive changes through callbacks, not polling.
        // This method is used to process accumulated events.
        Err(SyncError::connector(
            "Event change listener not implemented for this connector",
        ))
    }

    fn supports_change_detection(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_changeset_empty() {
        let cs = ChangeSet::empty();
        assert!(cs.changes.is_empty());
        assert!(cs.new_token.is_none());
        assert!(!cs.has_more);
    }

    #[test]
    fn test_detected_change_into_inbound() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let change = DetectedChange::new(
            "uid=john".to_string(),
            "inetOrgPerson".to_string(),
            ChangeType::Create,
            serde_json::json!({"cn": "John Doe"}),
        );

        let inbound = change.into_inbound(tenant_id, connector_id);
        assert_eq!(inbound.tenant_id, tenant_id);
        assert_eq!(inbound.connector_id, connector_id);
        assert_eq!(inbound.change_type, ChangeType::Create);
        assert_eq!(inbound.external_uid, "uid=john");
    }

    #[test]
    fn test_polling_listener_name() {
        let listener = PollingChangeListener::new("test-listener", Duration::from_secs(60));
        assert_eq!(listener.name(), "test-listener");
        assert!(listener.supports_change_detection());
    }
}
