//! Entitlement service for managing entitlements.
//!
//! This module provides the `EntitlementService` for CRUD operations on entitlements
//! with business logic validation and audit logging.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEventInput};
use crate::error::{GovernanceError, Result};
use crate::types::{EntitlementId, EntitlementStatus, RiskLevel};

// ============================================================================
// Domain Types
// ============================================================================

/// An entitlement representing an access right or permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    /// Unique identifier.
    pub id: EntitlementId,
    /// Tenant this entitlement belongs to.
    pub tenant_id: Uuid,
    /// The application this entitlement belongs to.
    pub application_id: Uuid,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Risk level classification.
    pub risk_level: RiskLevel,
    /// Current status.
    pub status: EntitlementStatus,
    /// Owner user ID.
    pub owner_id: Option<Uuid>,
    /// External system reference ID.
    pub external_id: Option<String>,
    /// Extensible metadata.
    pub metadata: Option<serde_json::Value>,
    /// Whether this entitlement can be delegated.
    pub is_delegable: bool,
    /// When created.
    pub created_at: DateTime<Utc>,
    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEntitlementInput {
    /// The application this entitlement belongs to.
    pub application_id: Uuid,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Risk level classification.
    pub risk_level: RiskLevel,
    /// Owner user ID.
    pub owner_id: Option<Uuid>,
    /// External system reference ID.
    pub external_id: Option<String>,
    /// Extensible metadata.
    pub metadata: Option<serde_json::Value>,
    /// Whether this entitlement can be delegated.
    #[serde(default = "default_delegable")]
    pub is_delegable: bool,
}

fn default_delegable() -> bool {
    true
}

/// Input for updating an entitlement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateEntitlementInput {
    /// New name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New risk level.
    pub risk_level: Option<RiskLevel>,
    /// New status.
    pub status: Option<EntitlementStatus>,
    /// New owner ID.
    pub owner_id: Option<Uuid>,
    /// New external ID.
    pub external_id: Option<String>,
    /// New metadata.
    pub metadata: Option<serde_json::Value>,
    /// Whether this entitlement can be delegated.
    pub is_delegable: Option<bool>,
}

/// Filter options for listing entitlements.
#[derive(Debug, Clone, Default)]
pub struct EntitlementFilter {
    /// Filter by application ID.
    pub application_id: Option<Uuid>,
    /// Filter by status.
    pub status: Option<EntitlementStatus>,
    /// Filter by risk level.
    pub risk_level: Option<RiskLevel>,
    /// Filter by owner ID.
    pub owner_id: Option<Uuid>,
    /// Filter by name containing string.
    pub name_contains: Option<String>,
}

/// Options for list operations.
#[derive(Debug, Clone)]
pub struct ListOptions {
    /// Maximum number of results.
    pub limit: i64,
    /// Number of results to skip.
    pub offset: i64,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: 0,
        }
    }
}

// ============================================================================
// Store Trait
// ============================================================================

/// Trait for entitlement storage backends.
#[async_trait::async_trait]
pub trait EntitlementStore: Send + Sync {
    /// Get an entitlement by ID.
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Entitlement>>;

    /// Get an entitlement by name within an application.
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
        name: &str,
    ) -> Result<Option<Entitlement>>;

    /// Create a new entitlement.
    async fn create(&self, tenant_id: Uuid, input: CreateEntitlementInput) -> Result<Entitlement>;

    /// Update an entitlement.
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEntitlementInput,
    ) -> Result<Option<Entitlement>>;

    /// Delete an entitlement.
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool>;

    /// List entitlements with filtering and pagination.
    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &EntitlementFilter,
        options: &ListOptions,
    ) -> Result<Vec<Entitlement>>;

    /// Count entitlements with filtering.
    async fn count(&self, tenant_id: Uuid, filter: &EntitlementFilter) -> Result<i64>;

    /// Count active assignments for an entitlement.
    async fn count_assignments(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<i64>;
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory entitlement store for testing.
#[derive(Debug, Default)]
pub struct InMemoryEntitlementStore {
    entitlements: Arc<RwLock<HashMap<Uuid, Entitlement>>>,
    assignments: Arc<RwLock<HashMap<Uuid, Vec<Uuid>>>>, // entitlement_id -> assignment_ids
}

impl InMemoryEntitlementStore {
    /// Create a new in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entitlements: Arc::new(RwLock::new(HashMap::new())),
            assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a mock assignment for testing.
    pub async fn add_mock_assignment(&self, entitlement_id: Uuid, assignment_id: Uuid) {
        let mut assignments = self.assignments.write().await;
        assignments
            .entry(entitlement_id)
            .or_default()
            .push(assignment_id);
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.entitlements.write().await.clear();
        self.assignments.write().await.clear();
    }
}

#[async_trait::async_trait]
impl EntitlementStore for InMemoryEntitlementStore {
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Entitlement>> {
        let entitlements = self.entitlements.read().await;
        Ok(entitlements
            .get(&id)
            .filter(|e| e.tenant_id == tenant_id)
            .cloned())
    }

    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
        name: &str,
    ) -> Result<Option<Entitlement>> {
        let entitlements = self.entitlements.read().await;
        Ok(entitlements
            .values()
            .find(|e| {
                e.tenant_id == tenant_id && e.application_id == application_id && e.name == name
            })
            .cloned())
    }

    async fn create(&self, tenant_id: Uuid, input: CreateEntitlementInput) -> Result<Entitlement> {
        let now = Utc::now();
        let entitlement = Entitlement {
            id: EntitlementId::new(),
            tenant_id,
            application_id: input.application_id,
            name: input.name,
            description: input.description,
            risk_level: input.risk_level,
            status: EntitlementStatus::Active,
            owner_id: input.owner_id,
            external_id: input.external_id,
            metadata: input.metadata,
            is_delegable: input.is_delegable,
            created_at: now,
            updated_at: now,
        };

        let mut entitlements = self.entitlements.write().await;
        entitlements.insert(entitlement.id.into_inner(), entitlement.clone());
        Ok(entitlement)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEntitlementInput,
    ) -> Result<Option<Entitlement>> {
        let mut entitlements = self.entitlements.write().await;

        if let Some(entitlement) = entitlements.get_mut(&id) {
            if entitlement.tenant_id != tenant_id {
                return Ok(None);
            }

            if let Some(name) = input.name {
                entitlement.name = name;
            }
            if let Some(description) = input.description {
                entitlement.description = Some(description);
            }
            if let Some(risk_level) = input.risk_level {
                entitlement.risk_level = risk_level;
            }
            if let Some(status) = input.status {
                entitlement.status = status;
            }
            if let Some(owner_id) = input.owner_id {
                entitlement.owner_id = Some(owner_id);
            }
            if let Some(external_id) = input.external_id {
                entitlement.external_id = Some(external_id);
            }
            if let Some(metadata) = input.metadata {
                entitlement.metadata = Some(metadata);
            }
            if let Some(is_delegable) = input.is_delegable {
                entitlement.is_delegable = is_delegable;
            }
            entitlement.updated_at = Utc::now();

            Ok(Some(entitlement.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        let mut entitlements = self.entitlements.write().await;

        if let Some(entitlement) = entitlements.get(&id) {
            if entitlement.tenant_id != tenant_id {
                return Ok(false);
            }
            entitlements.remove(&id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &EntitlementFilter,
        options: &ListOptions,
    ) -> Result<Vec<Entitlement>> {
        let entitlements = self.entitlements.read().await;

        let mut results: Vec<_> = entitlements
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| {
                filter
                    .application_id
                    .is_none_or(|id| e.application_id == id)
            })
            .filter(|e| filter.status.is_none_or(|s| e.status == s))
            .filter(|e| filter.risk_level.is_none_or(|r| e.risk_level == r))
            .filter(|e| filter.owner_id.is_none_or(|id| e.owner_id == Some(id)))
            .filter(|e| {
                filter
                    .name_contains
                    .as_ref()
                    .is_none_or(|s| e.name.to_lowercase().contains(&s.to_lowercase()))
            })
            .cloned()
            .collect();

        // Sort by name
        results.sort_by(|a, b| a.name.cmp(&b.name));

        // Apply pagination
        Ok(results
            .into_iter()
            .skip(options.offset as usize)
            .take(options.limit as usize)
            .collect())
    }

    async fn count(&self, tenant_id: Uuid, filter: &EntitlementFilter) -> Result<i64> {
        let entitlements = self.entitlements.read().await;

        let count = entitlements
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| {
                filter
                    .application_id
                    .is_none_or(|id| e.application_id == id)
            })
            .filter(|e| filter.status.is_none_or(|s| e.status == s))
            .filter(|e| filter.risk_level.is_none_or(|r| e.risk_level == r))
            .filter(|e| filter.owner_id.is_none_or(|id| e.owner_id == Some(id)))
            .filter(|e| {
                filter
                    .name_contains
                    .as_ref()
                    .is_none_or(|s| e.name.to_lowercase().contains(&s.to_lowercase()))
            })
            .count();

        Ok(count as i64)
    }

    async fn count_assignments(&self, _tenant_id: Uuid, entitlement_id: Uuid) -> Result<i64> {
        let assignments = self.assignments.read().await;
        Ok(assignments
            .get(&entitlement_id)
            .map_or(0, |a| a.len() as i64))
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service for managing entitlements.
pub struct EntitlementService {
    store: Arc<dyn EntitlementStore>,
    audit_store: Arc<dyn AuditStore>,
}

impl EntitlementService {
    /// Create a new entitlement service.
    pub fn new(store: Arc<dyn EntitlementStore>, audit_store: Arc<dyn AuditStore>) -> Self {
        Self { store, audit_store }
    }

    /// Create a new entitlement.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateEntitlementInput,
        actor_id: Uuid,
    ) -> Result<Entitlement> {
        // Check for duplicate name
        if let Some(_existing) = self
            .store
            .get_by_name(tenant_id, input.application_id, &input.name)
            .await?
        {
            return Err(GovernanceError::EntitlementNameExists(input.name));
        }

        let entitlement = self.store.create(tenant_id, input).await?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                entitlement_id: Some(entitlement.id.into_inner()),
                action: EntitlementAuditAction::Created,
                actor_id,
                after_state: Some(serde_json::to_value(&entitlement).unwrap_or_default()),
                ..Default::default()
            })
            .await?;

        Ok(entitlement)
    }

    /// Get an entitlement by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Entitlement>> {
        self.store.get(tenant_id, id).await
    }

    /// Update an entitlement.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEntitlementInput,
        actor_id: Uuid,
    ) -> Result<Entitlement> {
        // Get current state for audit
        let before: Entitlement = self
            .store
            .get(tenant_id, id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(id))?;

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = input.name {
            if new_name != &before.name {
                if let Some(_existing) = self
                    .store
                    .get_by_name(tenant_id, before.application_id, new_name)
                    .await?
                {
                    return Err(GovernanceError::EntitlementNameExists(new_name.clone()));
                }
            }
        }

        let updated: Entitlement = self
            .store
            .update(tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(id))?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                entitlement_id: Some(id),
                action: EntitlementAuditAction::Updated,
                actor_id,
                before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                after_state: Some(serde_json::to_value(&updated).unwrap_or_default()),
                ..Default::default()
            })
            .await?;

        Ok(updated)
    }

    /// Delete an entitlement.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<bool> {
        // Get current state for audit
        let before: Entitlement = self
            .store
            .get(tenant_id, id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(id))?;

        // Check for active assignments
        let assignment_count = self.store.count_assignments(tenant_id, id).await?;
        if assignment_count > 0 {
            return Err(GovernanceError::EntitlementHasAssignments(assignment_count));
        }

        let deleted = self.store.delete(tenant_id, id).await?;

        if deleted {
            // Log audit event
            self.audit_store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    entitlement_id: Some(id),
                    action: EntitlementAuditAction::Deleted,
                    actor_id,
                    before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                    ..Default::default()
                })
                .await?;
        }

        Ok(deleted)
    }

    /// List entitlements with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &EntitlementFilter,
        options: &ListOptions,
    ) -> Result<Vec<Entitlement>> {
        self.store.list(tenant_id, filter, options).await
    }

    /// Count entitlements with filtering.
    pub async fn count(&self, tenant_id: Uuid, filter: &EntitlementFilter) -> Result<i64> {
        self.store.count(tenant_id, filter).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAuditStore;

    fn create_test_service() -> (
        EntitlementService,
        Arc<InMemoryEntitlementStore>,
        Arc<InMemoryAuditStore>,
    ) {
        let entitlement_store = Arc::new(InMemoryEntitlementStore::new());
        let audit_store = Arc::new(InMemoryAuditStore::new());
        let service = EntitlementService::new(entitlement_store.clone(), audit_store.clone());
        (service, entitlement_store, audit_store)
    }

    fn create_input() -> CreateEntitlementInput {
        CreateEntitlementInput {
            application_id: Uuid::new_v4(),
            name: "Admin Access".to_string(),
            description: Some("Full administrative privileges".to_string()),
            risk_level: RiskLevel::Critical,
            owner_id: Some(Uuid::new_v4()),
            external_id: None,
            metadata: None,
            is_delegable: true,
        }
    }

    #[tokio::test]
    async fn test_create_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let entitlement = service
            .create(tenant_id, input.clone(), actor_id)
            .await
            .unwrap();

        assert_eq!(entitlement.name, "Admin Access");
        assert_eq!(entitlement.tenant_id, tenant_id);
        assert_eq!(entitlement.risk_level, RiskLevel::Critical);
        assert_eq!(entitlement.status, EntitlementStatus::Active);
    }

    #[tokio::test]
    async fn test_get_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_id, input, actor_id).await.unwrap();

        let retrieved = service
            .get(tenant_id, created.id.into_inner())
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, created.id);
        assert_eq!(retrieved.name, created.name);
    }

    #[tokio::test]
    async fn test_update_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_id, input, actor_id).await.unwrap();

        let update = UpdateEntitlementInput {
            description: Some("Updated description".to_string()),
            risk_level: Some(RiskLevel::High),
            ..Default::default()
        };

        let updated = service
            .update(tenant_id, created.id.into_inner(), update, actor_id)
            .await
            .unwrap();

        assert_eq!(updated.description, Some("Updated description".to_string()));
        assert_eq!(updated.risk_level, RiskLevel::High);
        assert_eq!(updated.name, created.name); // Unchanged
    }

    #[tokio::test]
    async fn test_delete_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_id, input, actor_id).await.unwrap();

        let deleted = service
            .delete(tenant_id, created.id.into_inner(), actor_id)
            .await
            .unwrap();
        assert!(deleted);

        let retrieved = service
            .get(tenant_id, created.id.into_inner())
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_delete_with_assignments_fails() {
        let (service, store, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_id, input, actor_id).await.unwrap();

        // Add a mock assignment
        store
            .add_mock_assignment(created.id.into_inner(), Uuid::new_v4())
            .await;

        let result = service
            .delete(tenant_id, created.id.into_inner(), actor_id)
            .await;

        assert!(matches!(
            result,
            Err(GovernanceError::EntitlementHasAssignments(1))
        ));
    }

    #[tokio::test]
    async fn test_duplicate_name_rejected() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        let input1 = CreateEntitlementInput {
            application_id: app_id,
            name: "Unique Name".to_string(),
            description: None,
            risk_level: RiskLevel::Low,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        };

        service
            .create(tenant_id, input1.clone(), actor_id)
            .await
            .unwrap();

        // Try to create with same name
        let result = service.create(tenant_id, input1, actor_id).await;
        assert!(matches!(
            result,
            Err(GovernanceError::EntitlementNameExists(_))
        ));
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let (service, _, _) = create_test_service();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_a, input, actor_id).await.unwrap();

        // Cannot access from tenant B
        let retrieved = service
            .get(tenant_b, created.id.into_inner())
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_audit_events_created() {
        let (service, _, audit_store) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = create_input();
        let created = service.create(tenant_id, input, actor_id).await.unwrap();

        // Update
        service
            .update(
                tenant_id,
                created.id.into_inner(),
                UpdateEntitlementInput {
                    description: Some("Updated".to_string()),
                    ..Default::default()
                },
                actor_id,
            )
            .await
            .unwrap();

        // Delete
        service
            .delete(tenant_id, created.id.into_inner(), actor_id)
            .await
            .unwrap();

        // Should have 3 audit events: create, update, delete
        assert_eq!(audit_store.count().await, 3);
    }

    #[tokio::test]
    async fn test_list_entitlements_paginated() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        // Create 5 entitlements
        for i in 1..=5 {
            let input = CreateEntitlementInput {
                application_id: app_id,
                name: format!("Entitlement {}", i),
                description: None,
                risk_level: RiskLevel::Low,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            };
            service.create(tenant_id, input, actor_id).await.unwrap();
        }

        // Get first 2
        let options = ListOptions {
            limit: 2,
            offset: 0,
        };
        let results = service
            .list(tenant_id, &EntitlementFilter::default(), &options)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        // Get next 2
        let options = ListOptions {
            limit: 2,
            offset: 2,
        };
        let results = service
            .list(tenant_id, &EntitlementFilter::default(), &options)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        // Get last 1
        let options = ListOptions {
            limit: 2,
            offset: 4,
        };
        let results = service
            .list(tenant_id, &EntitlementFilter::default(), &options)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_filter_by_application() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_a = Uuid::new_v4();
        let app_b = Uuid::new_v4();

        // Create 2 for app A
        for i in 1..=2 {
            service
                .create(
                    tenant_id,
                    CreateEntitlementInput {
                        application_id: app_a,
                        name: format!("App A - {}", i),
                        description: None,
                        risk_level: RiskLevel::Low,
                        owner_id: None,
                        external_id: None,
                        metadata: None,
                        is_delegable: true,
                    },
                    actor_id,
                )
                .await
                .unwrap();
        }

        // Create 1 for app B
        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_b,
                    name: "App B".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            application_id: Some(app_a),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_filter_by_status() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        // Create and deactivate one
        let e1 = service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Active".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let e2 = service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Inactive".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        service
            .update(
                tenant_id,
                e2.id.into_inner(),
                UpdateEntitlementInput {
                    status: Some(EntitlementStatus::Inactive),
                    ..Default::default()
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            status: Some(EntitlementStatus::Active),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, e1.id);
    }

    #[tokio::test]
    async fn test_filter_by_risk_level() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Low Risk".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Critical Risk".to_string(),
                    description: None,
                    risk_level: RiskLevel::Critical,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            risk_level: Some(RiskLevel::Critical),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Critical Risk");
    }

    #[tokio::test]
    async fn test_search_by_name() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Admin Access".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "User Access".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            name_contains: Some("admin".to_string()),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Admin Access");
    }

    #[tokio::test]
    async fn test_combined_filters() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Admin Critical".to_string(),
                    description: None,
                    risk_level: RiskLevel::Critical,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Admin Low".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            name_contains: Some("admin".to_string()),
            risk_level: Some(RiskLevel::Critical),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Admin Critical");
    }

    #[tokio::test]
    async fn test_empty_results() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let results = service
            .list(
                tenant_id,
                &EntitlementFilter::default(),
                &ListOptions::default(),
            )
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_large_result_set() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        // Create 100 entitlements
        for i in 1..=100 {
            service
                .create(
                    tenant_id,
                    CreateEntitlementInput {
                        application_id: app_id,
                        name: format!("Entitlement {:03}", i),
                        description: None,
                        risk_level: RiskLevel::Low,
                        owner_id: None,
                        external_id: None,
                        metadata: None,
                        is_delegable: true,
                    },
                    actor_id,
                )
                .await
                .unwrap();
        }

        // Count should be 100
        let count = service
            .count(tenant_id, &EntitlementFilter::default())
            .await
            .unwrap();
        assert_eq!(count, 100);

        // List with default limit
        let results = service
            .list(
                tenant_id,
                &EntitlementFilter::default(),
                &ListOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 100); // Default limit is 100
    }

    #[tokio::test]
    async fn test_update_nonexistent_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let nonexistent_id = Uuid::new_v4();

        let result = service
            .update(
                tenant_id,
                nonexistent_id,
                UpdateEntitlementInput {
                    name: Some("New Name".to_string()),
                    ..Default::default()
                },
                actor_id,
            )
            .await;

        assert!(result.is_err());
        if let Err(GovernanceError::EntitlementNotFound(id)) = result {
            assert_eq!(id, nonexistent_id);
        } else {
            panic!("Expected EntitlementNotFound error");
        }
    }

    #[tokio::test]
    async fn test_delete_nonexistent_entitlement() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let nonexistent_id = Uuid::new_v4();

        let result = service.delete(tenant_id, nonexistent_id, actor_id).await;

        assert!(result.is_err());
        if let Err(GovernanceError::EntitlementNotFound(id)) = result {
            assert_eq!(id, nonexistent_id);
        } else {
            panic!("Expected EntitlementNotFound error");
        }
    }

    #[tokio::test]
    async fn test_update_name_to_existing_name_fails() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        // Create first entitlement
        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Existing Name".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        // Create second entitlement
        let e2 = service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Different Name".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        // Try to update second entitlement to have first's name
        let result = service
            .update(
                tenant_id,
                e2.id.into_inner(),
                UpdateEntitlementInput {
                    name: Some("Existing Name".to_string()),
                    ..Default::default()
                },
                actor_id,
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GovernanceError::EntitlementNameExists(_))
        ));
    }

    #[tokio::test]
    async fn test_filter_by_owner() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let owner1 = Uuid::new_v4();
        let owner2 = Uuid::new_v4();

        // Create entitlement owned by owner1
        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Owner1 Entitlement".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: Some(owner1),
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        // Create entitlement owned by owner2
        service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Owner2 Entitlement".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: Some(owner2),
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        let filter = EntitlementFilter {
            owner_id: Some(owner1),
            ..Default::default()
        };

        let results = service
            .list(tenant_id, &filter, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].owner_id, Some(owner1));
    }

    #[tokio::test]
    async fn test_count_with_filter() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        // Create 3 high-risk and 2 low-risk entitlements
        for i in 0..5 {
            let risk = if i < 3 {
                RiskLevel::High
            } else {
                RiskLevel::Low
            };
            service
                .create(
                    tenant_id,
                    CreateEntitlementInput {
                        application_id: app_id,
                        name: format!("Entitlement {}", i),
                        description: None,
                        risk_level: risk,
                        owner_id: None,
                        external_id: None,
                        metadata: None,
                        is_delegable: true,
                    },
                    actor_id,
                )
                .await
                .unwrap();
        }

        // Count high-risk only
        let filter = EntitlementFilter {
            risk_level: Some(RiskLevel::High),
            ..Default::default()
        };
        let count = service.count(tenant_id, &filter).await.unwrap();
        assert_eq!(count, 3);

        // Count all
        let count = service
            .count(tenant_id, &EntitlementFilter::default())
            .await
            .unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_update_keeps_same_name() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        let entitlement = service
            .create(
                tenant_id,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: "Keep This Name".to_string(),
                    description: None,
                    risk_level: RiskLevel::Low,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                actor_id,
            )
            .await
            .unwrap();

        // Update with same name should succeed
        let updated = service
            .update(
                tenant_id,
                entitlement.id.into_inner(),
                UpdateEntitlementInput {
                    name: Some("Keep This Name".to_string()), // Same name
                    description: Some("Updated description".to_string()),
                    ..Default::default()
                },
                actor_id,
            )
            .await
            .unwrap();

        assert_eq!(updated.name, "Keep This Name");
        assert_eq!(updated.description, Some("Updated description".to_string()));
    }
}
