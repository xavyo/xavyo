//! Connector Framework traits
//!
//! Capability-based trait definitions for connectors, inspired by `ConnId`.

use async_trait::async_trait;

use crate::error::ConnectorResult;
use crate::operation::{AttributeDelta, AttributeSet, Filter, PageRequest, SearchResult, Uid};
use crate::schema::Schema;
use crate::types::ConnectorType;

/// Base trait for all connectors.
///
/// This trait provides common functionality that all connectors must implement,
/// regardless of their specific capabilities.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Get the type of this connector.
    fn connector_type(&self) -> ConnectorType;

    /// Get the display name for this connector instance.
    fn display_name(&self) -> &str;

    /// Test the connection to the target system.
    ///
    /// Returns `Ok(())` if the connection is successful, or an error describing
    /// what went wrong.
    async fn test_connection(&self) -> ConnectorResult<()>;

    /// Dispose of connector resources.
    ///
    /// Called when the connector is being removed from the registry.
    /// Implementations should close connections, release pools, etc.
    async fn dispose(&self) -> ConnectorResult<()>;

    /// Check if the connector is currently healthy.
    ///
    /// This is a lightweight health check, different from `test_connection`
    /// which may perform a more thorough validation.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Capability for discovering the schema of a target system.
///
/// Connectors implementing this trait can automatically discover
/// the object classes and attributes available in the target system.
#[async_trait]
pub trait SchemaDiscovery: Connector {
    /// Discover the schema from the target system.
    ///
    /// Returns a `Schema` containing all discovered object classes
    /// and their attributes.
    async fn discover_schema(&self) -> ConnectorResult<Schema>;

    /// Check if a specific object class exists in the target system.
    async fn has_object_class(&self, object_class: &str) -> ConnectorResult<bool> {
        let schema = self.discover_schema().await?;
        Ok(schema
            .object_classes
            .iter()
            .any(|oc| oc.name == object_class))
    }
}

/// Capability for creating objects in the target system.
#[async_trait]
pub trait CreateOp: Connector {
    /// Create a new object in the target system.
    ///
    /// # Arguments
    /// * `object_class` - The type of object to create (e.g., "user", "group")
    /// * `attributes` - The attributes for the new object
    ///
    /// # Returns
    /// The unique identifier (UID) of the created object in the target system.
    async fn create(&self, object_class: &str, attributes: AttributeSet) -> ConnectorResult<Uid>;
}

/// Capability for updating objects in the target system.
#[async_trait]
pub trait UpdateOp: Connector {
    /// Update an existing object in the target system.
    ///
    /// # Arguments
    /// * `object_class` - The type of object to update
    /// * `uid` - The unique identifier of the object in the target system
    /// * `changes` - The attribute changes to apply
    ///
    /// # Returns
    /// The UID of the updated object (may change for some systems).
    async fn update(
        &self,
        object_class: &str,
        uid: &Uid,
        changes: AttributeDelta,
    ) -> ConnectorResult<Uid>;
}

/// Capability for deleting objects from the target system.
#[async_trait]
pub trait DeleteOp: Connector {
    /// Delete an object from the target system.
    ///
    /// # Arguments
    /// * `object_class` - The type of object to delete
    /// * `uid` - The unique identifier of the object to delete
    async fn delete(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()>;
}

/// Capability for searching objects in the target system.
#[async_trait]
pub trait SearchOp: Connector {
    /// Search for objects in the target system.
    ///
    /// # Arguments
    /// * `object_class` - The type of objects to search for
    /// * `filter` - The search filter to apply
    /// * `attributes_to_get` - Optional list of attributes to retrieve
    /// * `page_request` - Optional pagination parameters
    ///
    /// # Returns
    /// Search results with matching objects and pagination info.
    async fn search(
        &self,
        object_class: &str,
        filter: Option<Filter>,
        attributes_to_get: Option<Vec<String>>,
        page_request: Option<PageRequest>,
    ) -> ConnectorResult<SearchResult>;

    /// Get a single object by its UID.
    ///
    /// This is a convenience method that searches for a specific object.
    async fn get(
        &self,
        object_class: &str,
        uid: &Uid,
        attributes_to_get: Option<Vec<String>>,
    ) -> ConnectorResult<Option<AttributeSet>> {
        let filter = Filter::Equals {
            attribute: uid.attribute_name().to_string(),
            value: uid.value().to_string(),
        };

        let result = self
            .search(object_class, Some(filter), attributes_to_get, None)
            .await?;

        Ok(result.objects.into_iter().next())
    }
}

/// Capability for disabling objects in the target system.
///
/// This is used for deprovisioning when the policy is to disable
/// rather than delete accounts.
#[async_trait]
pub trait DisableOp: Connector {
    /// Disable an object in the target system.
    ///
    /// # Arguments
    /// * `object_class` - The type of object to disable
    /// * `uid` - The unique identifier of the object to disable
    async fn disable(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()>;

    /// Enable a previously disabled object.
    ///
    /// # Arguments
    /// * `object_class` - The type of object to enable
    /// * `uid` - The unique identifier of the object to enable
    async fn enable(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()>;

    /// Check if an object is disabled.
    async fn is_disabled(&self, object_class: &str, uid: &Uid) -> ConnectorResult<bool>;
}

/// Capability for password operations.
#[async_trait]
pub trait PasswordOp: Connector {
    /// Set the password for an object.
    ///
    /// # Arguments
    /// * `object_class` - The type of object
    /// * `uid` - The unique identifier of the object
    /// * `password` - The new password to set
    async fn set_password(
        &self,
        object_class: &str,
        uid: &Uid,
        password: &str,
    ) -> ConnectorResult<()>;

    /// Check if the current password is valid.
    ///
    /// Returns `Ok(true)` if the password is valid.
    async fn validate_password(
        &self,
        object_class: &str,
        uid: &Uid,
        password: &str,
    ) -> ConnectorResult<bool>;
}

/// Capability for group membership operations.
#[async_trait]
pub trait GroupOp: Connector {
    /// Add a member to a group.
    ///
    /// # Arguments
    /// * `group_uid` - The UID of the group
    /// * `member_uid` - The UID of the member to add
    async fn add_member(&self, group_uid: &Uid, member_uid: &Uid) -> ConnectorResult<()>;

    /// Remove a member from a group.
    ///
    /// # Arguments
    /// * `group_uid` - The UID of the group
    /// * `member_uid` - The UID of the member to remove
    async fn remove_member(&self, group_uid: &Uid, member_uid: &Uid) -> ConnectorResult<()>;

    /// Get all members of a group.
    ///
    /// # Arguments
    /// * `group_uid` - The UID of the group
    ///
    /// # Returns
    /// List of member UIDs.
    async fn get_members(&self, group_uid: &Uid) -> ConnectorResult<Vec<Uid>>;

    /// Get all groups that a user is a member of.
    ///
    /// # Arguments
    /// * `member_uid` - The UID of the member
    ///
    /// # Returns
    /// List of group UIDs.
    async fn get_groups_for_member(&self, member_uid: &Uid) -> ConnectorResult<Vec<Uid>>;
}

/// Marker trait for connectors that support all CRUD operations.
pub trait FullCrud: CreateOp + UpdateOp + DeleteOp + SearchOp {}

// Blanket implementation for any connector that implements all CRUD ops
impl<T> FullCrud for T where T: CreateOp + UpdateOp + DeleteOp + SearchOp {}

/// A detected change from a target system during live synchronization.
#[derive(Debug, Clone)]
pub struct SyncChange {
    /// The unique identifier of the changed object.
    pub uid: Uid,
    /// The type of change.
    pub change_type: SyncChangeType,
    /// The object class (e.g., "user", "group").
    pub object_class: String,
    /// The current attributes of the object (for create/update).
    pub attributes: Option<AttributeSet>,
    /// Timestamp of the change (if provided by the source system).
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl SyncChange {
    /// Create a new sync change for a created object.
    pub fn created(uid: Uid, object_class: impl Into<String>, attributes: AttributeSet) -> Self {
        Self {
            uid,
            change_type: SyncChangeType::Create,
            object_class: object_class.into(),
            attributes: Some(attributes),
            timestamp: None,
        }
    }

    /// Create a new sync change for an updated object.
    pub fn updated(uid: Uid, object_class: impl Into<String>, attributes: AttributeSet) -> Self {
        Self {
            uid,
            change_type: SyncChangeType::Update,
            object_class: object_class.into(),
            attributes: Some(attributes),
            timestamp: None,
        }
    }

    /// Create a new sync change for a deleted object.
    pub fn deleted(uid: Uid, object_class: impl Into<String>) -> Self {
        Self {
            uid,
            change_type: SyncChangeType::Delete,
            object_class: object_class.into(),
            attributes: None,
            timestamp: None,
        }
    }

    /// Set the timestamp of the change.
    #[must_use] 
    pub fn with_timestamp(mut self, timestamp: chrono::DateTime<chrono::Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

/// Type of change detected during synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncChangeType {
    /// A new object was created.
    Create,
    /// An existing object was updated.
    Update,
    /// An object was deleted.
    Delete,
}

impl std::fmt::Display for SyncChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncChangeType::Create => write!(f, "create"),
            SyncChangeType::Update => write!(f, "update"),
            SyncChangeType::Delete => write!(f, "delete"),
        }
    }
}

/// Result of fetching changes during synchronization.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// The changes detected.
    pub changes: Vec<SyncChange>,
    /// The new sync token to use for the next sync.
    /// None if no changes were found and token remains the same.
    pub new_token: Option<String>,
    /// Whether there are more changes to fetch.
    pub has_more: bool,
}

impl SyncResult {
    /// Create a new sync result with no changes.
    #[must_use] 
    pub fn empty() -> Self {
        Self {
            changes: Vec::new(),
            new_token: None,
            has_more: false,
        }
    }

    /// Create a new sync result with changes.
    #[must_use] 
    pub fn with_changes(changes: Vec<SyncChange>) -> Self {
        Self {
            changes,
            new_token: None,
            has_more: false,
        }
    }

    /// Set the new sync token.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.new_token = Some(token.into());
        self
    }

    /// Indicate that there are more changes to fetch.
    #[must_use] 
    pub fn with_more(mut self) -> Self {
        self.has_more = true;
        self
    }
}

/// Capability for live synchronization from target systems.
///
/// Connectors implementing this trait can detect changes made in the target
/// system and report them for synchronization back to xavyo.
///
/// This supports various synchronization mechanisms:
/// - **LDAP Sync Cookie**: Persistent searches with sync control (RFC 4533)
/// - **AD `DirSync`**: Active Directory's `DirSync` control
/// - **Database Triggers**: Polling change tables populated by triggers
/// - **Polling**: Periodic full or incremental scans with timestamp tracking
///
/// # Sync Token
///
/// The sync token is an opaque string that represents the synchronization state.
/// Different systems use different token formats:
/// - LDAP: sync cookie (binary, base64 encoded)
/// - AD: `DirSync` cookie
/// - Database: Last processed sequence number or timestamp
/// - REST: Page cursor or version number
///
/// # Example
///
/// ```ignore
/// use xavyo_connector::traits::{Connector, SyncCapable, SyncResult};
///
/// async fn sync_from_ldap(connector: &impl SyncCapable, token: Option<&str>) -> SyncResult {
///     // Fetch changes since last sync
///     let result = connector.fetch_changes("user", token, 100).await?;
///
///     // Process changes
///     for change in &result.changes {
///         println!("Change: {} {} {}", change.change_type, change.object_class, change.uid);
///     }
///
///     // Store new token for next sync
///     if let Some(new_token) = &result.new_token {
///         save_token(connector.connector_id(), new_token);
///     }
///
///     Ok(result)
/// }
/// ```
#[async_trait]
pub trait SyncCapable: Connector {
    /// Fetch changes from the target system since the last sync.
    ///
    /// # Arguments
    /// * `object_class` - The type of objects to sync (e.g., "user", "group")
    /// * `sync_token` - The token from the last sync (None for initial sync)
    /// * `batch_size` - Maximum number of changes to return in one batch
    ///
    /// # Returns
    /// A `SyncResult` containing the detected changes and the new sync token.
    ///
    /// # Initial Sync
    /// When `sync_token` is None, the connector should perform an initial sync,
    /// returning all current objects as "create" changes.
    async fn fetch_changes(
        &self,
        object_class: &str,
        sync_token: Option<&str>,
        batch_size: u32,
    ) -> ConnectorResult<SyncResult>;

    /// Check if the given sync token is still valid.
    ///
    /// Some systems expire sync tokens after a period of inactivity.
    /// If the token is invalid, a full resync is required.
    ///
    /// # Arguments
    /// * `object_class` - The type of objects the token is for
    /// * `sync_token` - The token to validate
    ///
    /// # Returns
    /// `Ok(true)` if the token is valid, `Ok(false)` if expired or invalid.
    async fn validate_sync_token(
        &self,
        object_class: &str,
        sync_token: &str,
    ) -> ConnectorResult<bool> {
        // Default implementation: assume token is valid
        // Connectors should override if they can validate tokens
        let _ = (object_class, sync_token);
        Ok(true)
    }

    /// Get the synchronization mode supported by this connector.
    ///
    /// This helps the sync engine understand how the connector detects changes.
    fn sync_mode(&self) -> SyncMode {
        SyncMode::Polling
    }

    /// Get the recommended polling interval for this connector.
    ///
    /// Only applicable when `sync_mode()` returns `SyncMode::Polling`.
    /// Returns the recommended interval in seconds.
    fn recommended_poll_interval(&self) -> u64 {
        60 // Default: 1 minute
    }

    /// Check if the connector supports live/push-based synchronization.
    ///
    /// If true, the connector can register a callback to receive changes
    /// in real-time instead of polling.
    fn supports_live_sync(&self) -> bool {
        false
    }
}

/// Synchronization mode supported by a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncMode {
    /// Polling-based synchronization.
    /// The connector is periodically queried for changes.
    Polling,

    /// Event-driven synchronization.
    /// Changes are pushed to the connector (e.g., LDAP persistent search).
    EventDriven,

    /// Hybrid mode supporting both polling and events.
    /// Can switch between modes based on configuration.
    Hybrid,
}

impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncMode::Polling => write!(f, "polling"),
            SyncMode::EventDriven => write!(f, "event_driven"),
            SyncMode::Hybrid => write!(f, "hybrid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Mock connector for testing
    struct MockConnector {
        name: String,
        healthy: Arc<AtomicBool>,
    }

    impl MockConnector {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                healthy: Arc::new(AtomicBool::new(true)),
            }
        }
    }

    #[async_trait]
    impl Connector for MockConnector {
        fn connector_type(&self) -> ConnectorType {
            ConnectorType::Rest
        }

        fn display_name(&self) -> &str {
            &self.name
        }

        async fn test_connection(&self) -> ConnectorResult<()> {
            if self.healthy.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(crate::error::ConnectorError::connection_failed(
                    "not healthy",
                ))
            }
        }

        async fn dispose(&self) -> ConnectorResult<()> {
            Ok(())
        }

        fn is_healthy(&self) -> bool {
            self.healthy.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn test_mock_connector() {
        let connector = MockConnector::new("test");
        assert_eq!(connector.connector_type(), ConnectorType::Rest);
        assert_eq!(connector.display_name(), "test");
        assert!(connector.is_healthy());
        assert!(connector.test_connection().await.is_ok());
    }

    #[tokio::test]
    async fn test_unhealthy_connector() {
        let connector = MockConnector::new("test");
        connector.healthy.store(false, Ordering::SeqCst);
        assert!(!connector.is_healthy());
        assert!(connector.test_connection().await.is_err());
    }
}
