//! Assignment service for managing entitlement assignments.
//!
//! This module provides the `AssignmentService` for assigning and revoking
//! entitlements for users with validation and audit logging.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEventInput};
use crate::error::{GovernanceError, Result};
use crate::services::entitlement::EntitlementStore;
use crate::services::validation::ValidationService;
use crate::types::{AssignmentId, AssignmentStatus, AssignmentTargetType};

// ============================================================================
// Domain Types
// ============================================================================

/// An entitlement assignment to a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementAssignment {
    /// Unique identifier.
    pub id: AssignmentId,
    /// Tenant this assignment belongs to.
    pub tenant_id: Uuid,
    /// The entitlement being assigned.
    pub entitlement_id: Uuid,
    /// The type of target (user or group).
    pub target_type: AssignmentTargetType,
    /// The target ID (user_id or group_id).
    pub target_id: Uuid,
    /// Who made the assignment.
    pub assigned_by: Uuid,
    /// When the assignment was made.
    pub assigned_at: DateTime<Utc>,
    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
    /// Assignment status.
    pub status: AssignmentStatus,
    /// Business justification.
    pub justification: Option<String>,
    /// When created.
    pub created_at: DateTime<Utc>,
    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for assigning an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignEntitlementInput {
    /// The entitlement to assign.
    pub entitlement_id: Uuid,
    /// The user to assign to.
    pub user_id: Uuid,
    /// Who is making the assignment.
    pub assigned_by: Uuid,
    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
    /// Business justification.
    pub justification: Option<String>,
}

/// Filter options for listing assignments.
#[derive(Debug, Clone, Default)]
pub struct AssignmentFilter {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
    /// Filter by status.
    pub status: Option<AssignmentStatus>,
}

// ============================================================================
// Store Trait
// ============================================================================

/// Trait for assignment storage backends.
#[async_trait::async_trait]
pub trait AssignmentStore: Send + Sync {
    /// Get an assignment by ID.
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<EntitlementAssignment>>;

    /// Get an existing assignment for a user/entitlement pair.
    async fn get_by_user_entitlement(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<EntitlementAssignment>>;

    /// Create a new assignment.
    async fn create(
        &self,
        tenant_id: Uuid,
        input: AssignEntitlementInput,
    ) -> Result<EntitlementAssignment>;

    /// Delete (revoke) an assignment.
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool>;

    /// List assignments for a user.
    async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<EntitlementAssignment>>;

    /// List user entitlement IDs (for validation).
    async fn list_user_entitlement_ids(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>>;
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory assignment store for testing.
#[derive(Debug, Default)]
pub struct InMemoryAssignmentStore {
    assignments: Arc<RwLock<HashMap<Uuid, EntitlementAssignment>>>,
}

impl InMemoryAssignmentStore {
    /// Create a new in-memory store.
    pub fn new() -> Self {
        Self {
            assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.assignments.write().await.clear();
    }

    /// Get assignment count.
    pub async fn count(&self) -> usize {
        self.assignments.read().await.len()
    }
}

#[async_trait::async_trait]
impl AssignmentStore for InMemoryAssignmentStore {
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<EntitlementAssignment>> {
        let assignments = self.assignments.read().await;
        Ok(assignments
            .get(&id)
            .filter(|a| a.tenant_id == tenant_id)
            .cloned())
    }

    async fn get_by_user_entitlement(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<EntitlementAssignment>> {
        let assignments = self.assignments.read().await;
        Ok(assignments
            .values()
            .find(|a| {
                a.tenant_id == tenant_id
                    && a.target_id == user_id
                    && a.entitlement_id == entitlement_id
                    && a.status == AssignmentStatus::Active
            })
            .cloned())
    }

    async fn create(
        &self,
        tenant_id: Uuid,
        input: AssignEntitlementInput,
    ) -> Result<EntitlementAssignment> {
        let now = Utc::now();
        let assignment = EntitlementAssignment {
            id: AssignmentId::new(),
            tenant_id,
            entitlement_id: input.entitlement_id,
            target_type: AssignmentTargetType::User,
            target_id: input.user_id,
            assigned_by: input.assigned_by,
            assigned_at: now,
            expires_at: input.expires_at,
            status: AssignmentStatus::Active,
            justification: input.justification,
            created_at: now,
            updated_at: now,
        };

        let mut assignments = self.assignments.write().await;
        assignments.insert(assignment.id.into_inner(), assignment.clone());
        Ok(assignment)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        let mut assignments = self.assignments.write().await;

        if let Some(assignment) = assignments.get(&id) {
            if assignment.tenant_id != tenant_id {
                return Ok(false);
            }
            assignments.remove(&id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<EntitlementAssignment>> {
        let assignments = self.assignments.read().await;
        Ok(assignments
            .values()
            .filter(|a| {
                a.tenant_id == tenant_id
                    && a.target_id == user_id
                    && a.status == AssignmentStatus::Active
            })
            .cloned()
            .collect())
    }

    async fn list_user_entitlement_ids(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let assignments = self.assignments.read().await;
        Ok(assignments
            .values()
            .filter(|a| {
                a.tenant_id == tenant_id
                    && a.target_id == user_id
                    && a.status == AssignmentStatus::Active
            })
            .map(|a| a.entitlement_id)
            .collect())
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service for managing entitlement assignments.
pub struct AssignmentService {
    assignment_store: Arc<dyn AssignmentStore>,
    entitlement_store: Arc<dyn EntitlementStore>,
    audit_store: Arc<dyn AuditStore>,
    validation_service: Option<Arc<ValidationService>>,
}

impl AssignmentService {
    /// Create a new assignment service.
    pub fn new(
        assignment_store: Arc<dyn AssignmentStore>,
        entitlement_store: Arc<dyn EntitlementStore>,
        audit_store: Arc<dyn AuditStore>,
    ) -> Self {
        Self {
            assignment_store,
            entitlement_store,
            audit_store,
            validation_service: None,
        }
    }

    /// Create a new assignment service with validation.
    pub fn with_validation(
        assignment_store: Arc<dyn AssignmentStore>,
        entitlement_store: Arc<dyn EntitlementStore>,
        audit_store: Arc<dyn AuditStore>,
        validation_service: Arc<ValidationService>,
    ) -> Self {
        Self {
            assignment_store,
            entitlement_store,
            audit_store,
            validation_service: Some(validation_service),
        }
    }

    /// Assign an entitlement to a user.
    pub async fn assign(
        &self,
        tenant_id: Uuid,
        input: AssignEntitlementInput,
    ) -> Result<EntitlementAssignment> {
        // Check entitlement exists
        let _entitlement: crate::services::entitlement::Entitlement = self
            .entitlement_store
            .get(tenant_id, input.entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(input.entitlement_id))?;

        // Check for duplicate assignment
        if let Some(_existing) = self
            .assignment_store
            .get_by_user_entitlement(tenant_id, input.user_id, input.entitlement_id)
            .await?
        {
            return Err(GovernanceError::AssignmentAlreadyExists);
        }

        // Validate expiry date if provided
        if let Some(expires_at) = input.expires_at {
            if expires_at <= Utc::now() {
                return Err(GovernanceError::InvalidExpirationDate);
            }
        }

        // Run validation if configured
        if let Some(ref validation_service) = self.validation_service {
            let user_entitlements: Vec<Uuid> = self
                .assignment_store
                .list_user_entitlement_ids(tenant_id, input.user_id)
                .await?;

            let result = validation_service
                .validate_assignment(tenant_id, &input, &user_entitlements)
                .await;

            if !result.is_valid {
                let errors: Vec<String> = result.errors.into_iter().map(|e| e.message).collect();
                return Err(GovernanceError::ValidationFailed(errors));
            }
        }

        let assignment = self.assignment_store.create(tenant_id, input.clone()).await?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                entitlement_id: Some(input.entitlement_id),
                assignment_id: Some(assignment.id.into_inner()),
                user_id: Some(input.user_id),
                action: EntitlementAuditAction::Assigned,
                actor_id: input.assigned_by,
                after_state: Some(serde_json::to_value(&assignment).unwrap_or_default()),
                ..Default::default()
            })
            .await?;

        Ok(assignment)
    }

    /// Revoke an entitlement assignment.
    pub async fn revoke(&self, tenant_id: Uuid, assignment_id: Uuid, actor_id: Uuid) -> Result<bool> {
        // Get current state for audit
        let before: EntitlementAssignment = self
            .assignment_store
            .get(tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))?;

        let deleted = self.assignment_store.delete(tenant_id, assignment_id).await?;

        if deleted {
            // Log audit event
            self.audit_store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    entitlement_id: Some(before.entitlement_id),
                    assignment_id: Some(assignment_id),
                    user_id: Some(before.target_id),
                    action: EntitlementAuditAction::Revoked,
                    actor_id,
                    before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                    ..Default::default()
                })
                .await?;
        }

        Ok(deleted)
    }

    /// List all entitlement assignments for a user.
    pub async fn list_user_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<EntitlementAssignment>> {
        self.assignment_store
            .list_user_assignments(tenant_id, user_id)
            .await
    }

    /// Get an assignment by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<EntitlementAssignment>> {
        self.assignment_store.get(tenant_id, id).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAuditStore;
    use crate::services::entitlement::{CreateEntitlementInput, InMemoryEntitlementStore};
    use crate::types::RiskLevel;

    async fn create_test_service() -> (
        AssignmentService,
        Arc<InMemoryAssignmentStore>,
        Arc<InMemoryEntitlementStore>,
        Arc<InMemoryAuditStore>,
    ) {
        let assignment_store = Arc::new(InMemoryAssignmentStore::new());
        let entitlement_store = Arc::new(InMemoryEntitlementStore::new());
        let audit_store = Arc::new(InMemoryAuditStore::new());

        let service = AssignmentService::new(
            assignment_store.clone(),
            entitlement_store.clone(),
            audit_store.clone(),
        );

        (service, assignment_store, entitlement_store, audit_store)
    }

    async fn create_test_entitlement(
        store: &InMemoryEntitlementStore,
        tenant_id: Uuid,
    ) -> Uuid {
        let input = CreateEntitlementInput {
            application_id: Uuid::new_v4(),
            name: "Test Entitlement".to_string(),
            description: None,
            risk_level: RiskLevel::Low,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        };
        let entitlement = store.create(tenant_id, input).await.unwrap();
        entitlement.id.into_inner()
    }

    #[tokio::test]
    async fn test_assign_entitlement() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_id).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: Some("Required for project".to_string()),
        };

        let assignment = service.assign(tenant_id, input).await.unwrap();
        assert_eq!(assignment.entitlement_id, entitlement_id);
        assert_eq!(assignment.target_id, user_id);
        assert_eq!(assignment.status, AssignmentStatus::Active);
    }

    #[tokio::test]
    async fn test_revoke_assignment() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_id).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: None,
        };

        let assignment = service.assign(tenant_id, input).await.unwrap();

        let revoked = service
            .revoke(tenant_id, assignment.id.into_inner(), actor_id)
            .await
            .unwrap();
        assert!(revoked);

        let retrieved = service
            .get(tenant_id, assignment.id.into_inner())
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_user_entitlements() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Create 2 entitlements and assign both
        for i in 1..=2 {
            let input = CreateEntitlementInput {
                application_id: Uuid::new_v4(),
                name: format!("Entitlement {}", i),
                description: None,
                risk_level: RiskLevel::Low,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            };
            let entitlement = entitlement_store.create(tenant_id, input).await.unwrap();

            service
                .assign(
                    tenant_id,
                    AssignEntitlementInput {
                        entitlement_id: entitlement.id.into_inner(),
                        user_id,
                        assigned_by: actor_id,
                        expires_at: None,
                        justification: None,
                    },
                )
                .await
                .unwrap();
        }

        let assignments = service.list_user_entitlements(tenant_id, user_id).await.unwrap();
        assert_eq!(assignments.len(), 2);
    }

    #[tokio::test]
    async fn test_duplicate_assignment_rejected() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_id).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: None,
        };

        // First assignment succeeds
        service.assign(tenant_id, input.clone()).await.unwrap();

        // Second assignment fails
        let result = service.assign(tenant_id, input).await;
        assert!(matches!(result, Err(GovernanceError::AssignmentAlreadyExists)));
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_fails() {
        let (service, _, _, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let result = service.revoke(tenant_id, Uuid::new_v4(), actor_id).await;
        assert!(matches!(result, Err(GovernanceError::AssignmentNotFound(_))));
    }

    #[tokio::test]
    async fn test_assign_nonexistent_entitlement_fails() {
        let (service, _, _, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = AssignEntitlementInput {
            entitlement_id: Uuid::new_v4(), // Non-existent
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: None,
        };

        let result = service.assign(tenant_id, input).await;
        assert!(matches!(result, Err(GovernanceError::EntitlementNotFound(_))));
    }

    #[tokio::test]
    async fn test_audit_events_assign_revoke() {
        let (service, _, entitlement_store, audit_store) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_id).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: None,
        };

        let assignment = service.assign(tenant_id, input).await.unwrap();
        service
            .revoke(tenant_id, assignment.id.into_inner(), actor_id)
            .await
            .unwrap();

        // Should have 2 audit events: assign, revoke
        assert_eq!(audit_store.count().await, 2);
    }

    #[tokio::test]
    async fn test_assignment_tenant_isolation() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_a).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: None,
            justification: None,
        };

        let assignment = service.assign(tenant_a, input).await.unwrap();

        // Cannot access from tenant B
        let retrieved = service
            .get(tenant_b, assignment.id.into_inner())
            .await
            .unwrap();
        assert!(retrieved.is_none());

        // List in tenant B returns empty
        let assignments = service.list_user_entitlements(tenant_b, user_id).await.unwrap();
        assert!(assignments.is_empty());
    }

    #[tokio::test]
    async fn test_expired_assignment_rejected() {
        let (service, _, entitlement_store, _) = create_test_service().await;
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entitlement_id = create_test_entitlement(&entitlement_store, tenant_id).await;

        let input = AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by: actor_id,
            expires_at: Some(Utc::now() - chrono::Duration::days(1)), // Past date
            justification: None,
        };

        let result = service.assign(tenant_id, input).await;
        assert!(matches!(result, Err(GovernanceError::InvalidExpirationDate)));
    }
}
