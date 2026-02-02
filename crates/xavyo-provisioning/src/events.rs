//! Event handlers for provisioning.
//!
//! Defines handlers for user lifecycle events that trigger provisioning operations.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use xavyo_connector::types::OperationType;

use crate::queue::{OperationQueue, QueueError, QueuedOperation};

/// Event handler errors.
#[derive(Debug, Error)]
pub enum EventError {
    /// Queue error.
    #[error("Queue error: {0}")]
    Queue(#[from] QueueError),

    /// Invalid event payload.
    #[error("Invalid event payload: {0}")]
    InvalidPayload(String),

    /// No connectors configured for tenant.
    #[error("No connectors configured for tenant {0}")]
    NoConnectors(Uuid),
}

/// Result type for event handlers.
pub type EventResult<T> = Result<T, EventError>;

/// User created event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreatedEvent {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// User attributes as key-value pairs.
    pub attributes: serde_json::Value,

    /// Optional correlation ID for tracing.
    #[serde(default)]
    pub correlation_id: Option<String>,
}

/// User updated event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdatedEvent {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// Changed attributes (only the fields that changed).
    pub changed_attributes: serde_json::Value,

    /// Optional correlation ID for tracing.
    #[serde(default)]
    pub correlation_id: Option<String>,
}

/// User deactivated event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeactivatedEvent {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// Whether to delete (true) or disable (false).
    #[serde(default)]
    pub delete: bool,

    /// Optional correlation ID for tracing.
    #[serde(default)]
    pub correlation_id: Option<String>,
}

/// Connector assignment for provisioning.
#[derive(Debug, Clone)]
pub struct ConnectorAssignment {
    /// Connector ID.
    pub connector_id: Uuid,

    /// Target object class (e.g., "inetOrgPerson", "user").
    pub object_class: String,

    /// Priority (higher = more urgent).
    pub priority: i32,
}

/// Trait for resolving which connectors apply to a user.
#[async_trait::async_trait]
pub trait ConnectorResolver: Send + Sync {
    /// Get connectors that should provision for this user.
    async fn get_connectors_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> EventResult<Vec<ConnectorAssignment>>;
}

/// Event handler for provisioning operations.
pub struct ProvisioningEventHandler<R: ConnectorResolver> {
    queue: Arc<OperationQueue>,
    resolver: Arc<R>,
}

impl<R: ConnectorResolver> ProvisioningEventHandler<R> {
    /// Create a new event handler.
    pub fn new(queue: Arc<OperationQueue>, resolver: Arc<R>) -> Self {
        Self { queue, resolver }
    }

    /// Handle user created event.
    #[instrument(skip(self, event), fields(tenant_id = %event.tenant_id, user_id = %event.user_id))]
    pub async fn handle_user_created(&self, event: UserCreatedEvent) -> EventResult<Vec<Uuid>> {
        info!("Handling UserCreated event");

        // Get connectors for this user
        let assignments = self
            .resolver
            .get_connectors_for_user(event.tenant_id, event.user_id)
            .await?;

        if assignments.is_empty() {
            debug!("No connectors configured for user, skipping provisioning");
            return Ok(vec![]);
        }

        let mut operation_ids = Vec::with_capacity(assignments.len());

        // Create a provisioning operation for each connector
        for assignment in assignments {
            let mut operation = QueuedOperation::new(
                event.tenant_id,
                assignment.connector_id,
                event.user_id,
                OperationType::Create,
                assignment.object_class,
                event.attributes.clone(),
            );
            operation.priority = assignment.priority;

            let id = self.queue.enqueue(operation).await?;
            info!(
                operation_id = %id,
                connector_id = %assignment.connector_id,
                "Enqueued create operation"
            );
            operation_ids.push(id);
        }

        Ok(operation_ids)
    }

    /// Handle user updated event.
    #[instrument(skip(self, event), fields(tenant_id = %event.tenant_id, user_id = %event.user_id))]
    pub async fn handle_user_updated(&self, event: UserUpdatedEvent) -> EventResult<Vec<Uuid>> {
        info!("Handling UserUpdated event");

        // Get connectors for this user
        let assignments = self
            .resolver
            .get_connectors_for_user(event.tenant_id, event.user_id)
            .await?;

        if assignments.is_empty() {
            debug!("No connectors configured for user, skipping update");
            return Ok(vec![]);
        }

        let mut operation_ids = Vec::with_capacity(assignments.len());

        // Create an update operation for each connector
        for assignment in assignments {
            let mut operation = QueuedOperation::new(
                event.tenant_id,
                assignment.connector_id,
                event.user_id,
                OperationType::Update,
                assignment.object_class,
                event.changed_attributes.clone(),
            );
            operation.priority = assignment.priority;

            let id = self.queue.enqueue(operation).await?;
            info!(
                operation_id = %id,
                connector_id = %assignment.connector_id,
                "Enqueued update operation"
            );
            operation_ids.push(id);
        }

        Ok(operation_ids)
    }

    /// Handle user deactivated event.
    #[instrument(skip(self, event), fields(tenant_id = %event.tenant_id, user_id = %event.user_id))]
    pub async fn handle_user_deactivated(
        &self,
        event: UserDeactivatedEvent,
    ) -> EventResult<Vec<Uuid>> {
        info!(delete = event.delete, "Handling UserDeactivated event");

        // Get connectors for this user
        let assignments = self
            .resolver
            .get_connectors_for_user(event.tenant_id, event.user_id)
            .await?;

        if assignments.is_empty() {
            debug!("No connectors configured for user, skipping deprovisioning");
            return Ok(vec![]);
        }

        let mut operation_ids = Vec::with_capacity(assignments.len());

        // Create a delete operation for each connector
        for assignment in assignments {
            let operation_type = if event.delete {
                OperationType::Delete
            } else {
                // For disable, we use Update with a special payload
                OperationType::Update
            };

            let payload = if event.delete {
                serde_json::json!({})
            } else {
                // Payload for disable operation
                serde_json::json!({
                    "_action": "disable"
                })
            };

            let mut operation = QueuedOperation::new(
                event.tenant_id,
                assignment.connector_id,
                event.user_id,
                operation_type,
                assignment.object_class,
                payload,
            );
            operation.priority = assignment.priority;

            let id = self.queue.enqueue(operation).await?;
            info!(
                operation_id = %id,
                connector_id = %assignment.connector_id,
                delete = event.delete,
                "Enqueued deprovisioning operation"
            );
            operation_ids.push(id);
        }

        Ok(operation_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_created_event_deserialize() {
        let json = r#"{
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "user_id": "660e8400-e29b-41d4-a716-446655440000",
            "attributes": {"firstName": "John", "lastName": "Doe"}
        }"#;

        let event: UserCreatedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(
            event.user_id.to_string(),
            "660e8400-e29b-41d4-a716-446655440000"
        );
        assert!(event.correlation_id.is_none());
    }

    #[test]
    fn test_user_updated_event_deserialize() {
        let json = r#"{
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "user_id": "660e8400-e29b-41d4-a716-446655440000",
            "changed_attributes": {"lastName": "Smith"},
            "correlation_id": "trace-123"
        }"#;

        let event: UserUpdatedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.correlation_id, Some("trace-123".to_string()));
    }

    #[test]
    fn test_user_deactivated_event_default() {
        let json = r#"{
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "user_id": "660e8400-e29b-41d4-a716-446655440000"
        }"#;

        let event: UserDeactivatedEvent = serde_json::from_str(json).unwrap();
        assert!(!event.delete); // Default is disable, not delete
    }

    #[test]
    fn test_connector_assignment() {
        let assignment = ConnectorAssignment {
            connector_id: Uuid::new_v4(),
            object_class: "inetOrgPerson".to_string(),
            priority: 10,
        };
        assert_eq!(assignment.priority, 10);
    }
}
