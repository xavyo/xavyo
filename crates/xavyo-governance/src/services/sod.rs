//! SoD (Separation of Duties) service for managing SoD rules.
//!
//! This module provides the `SodService` for creating, updating, and deleting
//! SoD rules that define prohibited or required entitlement combinations.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEventInput};
use crate::error::{GovernanceError, Result};
use crate::types::{SodConflictType, SodRuleId, SodRuleStatus, SodSeverity};

// ============================================================================
// Domain Types
// ============================================================================

/// An SoD rule defining prohibited or required entitlement combinations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodRule {
    /// Unique identifier.
    pub id: SodRuleId,
    /// Tenant this rule belongs to.
    pub tenant_id: Uuid,
    /// Human-readable rule name.
    pub name: String,
    /// Detailed description.
    pub description: Option<String>,
    /// Type of conflict.
    pub conflict_type: SodConflictType,
    /// Entitlements involved in the rule.
    pub entitlement_ids: Vec<Uuid>,
    /// Maximum count (for cardinality type).
    pub max_count: Option<u32>,
    /// Severity level.
    pub severity: SodSeverity,
    /// Rule status.
    pub status: SodRuleStatus,
    /// Whether rule references deleted entitlement.
    pub orphaned: bool,
    /// Who created the rule.
    pub created_by: Uuid,
    /// When created.
    pub created_at: DateTime<Utc>,
    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating an SoD rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSodRuleInput {
    /// Human-readable rule name.
    pub name: String,
    /// Detailed description.
    pub description: Option<String>,
    /// Type of conflict.
    pub conflict_type: SodConflictType,
    /// Entitlements involved in the rule.
    pub entitlement_ids: Vec<Uuid>,
    /// Maximum count (required for cardinality type).
    pub max_count: Option<u32>,
    /// Severity level.
    pub severity: SodSeverity,
    /// Who is creating the rule.
    pub created_by: Uuid,
}

/// Input for updating an SoD rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSodRuleInput {
    /// New name (if updating).
    pub name: Option<String>,
    /// New description (if updating).
    pub description: Option<String>,
    /// New severity (if updating).
    pub severity: Option<SodSeverity>,
    /// New status (if updating).
    pub status: Option<SodRuleStatus>,
}

// ============================================================================
// Store Trait
// ============================================================================

/// Trait for SoD rule storage backends.
#[async_trait::async_trait]
pub trait SodRuleStore: Send + Sync {
    /// Get a rule by ID.
    async fn get(&self, tenant_id: Uuid, id: SodRuleId) -> Result<Option<SodRule>>;

    /// List all active rules for a tenant.
    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodRule>>;

    /// List rules that reference any of the given entitlements.
    async fn list_by_entitlements(
        &self,
        tenant_id: Uuid,
        entitlement_ids: &[Uuid],
    ) -> Result<Vec<SodRule>>;

    /// Create a new rule.
    async fn create(&self, tenant_id: Uuid, input: CreateSodRuleInput) -> Result<SodRule>;

    /// Update a rule.
    async fn update(
        &self,
        tenant_id: Uuid,
        id: SodRuleId,
        input: UpdateSodRuleInput,
    ) -> Result<Option<SodRule>>;

    /// Delete a rule.
    async fn delete(&self, tenant_id: Uuid, id: SodRuleId) -> Result<bool>;

    /// Mark rules referencing an entitlement as orphaned.
    async fn mark_orphaned(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<u64>;
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory SoD rule store for testing.
#[derive(Debug, Default)]
pub struct InMemorySodRuleStore {
    rules: Arc<RwLock<HashMap<Uuid, SodRule>>>,
}

impl InMemorySodRuleStore {
    /// Create a new in-memory store.
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.rules.write().await.clear();
    }

    /// Get rule count.
    pub async fn count(&self) -> usize {
        self.rules.read().await.len()
    }
}

#[async_trait::async_trait]
impl SodRuleStore for InMemorySodRuleStore {
    async fn get(&self, tenant_id: Uuid, id: SodRuleId) -> Result<Option<SodRule>> {
        let rules = self.rules.read().await;
        Ok(rules
            .get(&id.into_inner())
            .filter(|r| r.tenant_id == tenant_id)
            .cloned())
    }

    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodRule>> {
        let rules = self.rules.read().await;
        Ok(rules
            .values()
            .filter(|r| r.tenant_id == tenant_id && r.status == SodRuleStatus::Active)
            .cloned()
            .collect())
    }

    async fn list_by_entitlements(
        &self,
        tenant_id: Uuid,
        entitlement_ids: &[Uuid],
    ) -> Result<Vec<SodRule>> {
        let rules = self.rules.read().await;
        Ok(rules
            .values()
            .filter(|r| {
                r.tenant_id == tenant_id
                    && r.status == SodRuleStatus::Active
                    && r.entitlement_ids
                        .iter()
                        .any(|e| entitlement_ids.contains(e))
            })
            .cloned()
            .collect())
    }

    async fn create(&self, tenant_id: Uuid, input: CreateSodRuleInput) -> Result<SodRule> {
        let now = Utc::now();
        let rule = SodRule {
            id: SodRuleId::new(),
            tenant_id,
            name: input.name,
            description: input.description,
            conflict_type: input.conflict_type,
            entitlement_ids: input.entitlement_ids,
            max_count: input.max_count,
            severity: input.severity,
            status: SodRuleStatus::Active,
            orphaned: false,
            created_by: input.created_by,
            created_at: now,
            updated_at: now,
        };

        let mut rules = self.rules.write().await;
        rules.insert(rule.id.into_inner(), rule.clone());
        Ok(rule)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: SodRuleId,
        input: UpdateSodRuleInput,
    ) -> Result<Option<SodRule>> {
        let mut rules = self.rules.write().await;

        if let Some(rule) = rules.get_mut(&id.into_inner()) {
            if rule.tenant_id != tenant_id {
                return Ok(None);
            }

            if let Some(name) = input.name {
                rule.name = name;
            }
            if let Some(description) = input.description {
                rule.description = Some(description);
            }
            if let Some(severity) = input.severity {
                rule.severity = severity;
            }
            if let Some(status) = input.status {
                rule.status = status;
            }
            rule.updated_at = Utc::now();

            Ok(Some(rule.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, tenant_id: Uuid, id: SodRuleId) -> Result<bool> {
        let mut rules = self.rules.write().await;

        if let Some(rule) = rules.get(&id.into_inner()) {
            if rule.tenant_id != tenant_id {
                return Ok(false);
            }
            rules.remove(&id.into_inner());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn mark_orphaned(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<u64> {
        let mut rules = self.rules.write().await;
        let mut count = 0u64;

        for rule in rules.values_mut() {
            if rule.tenant_id == tenant_id && rule.entitlement_ids.contains(&entitlement_id) {
                rule.orphaned = true;
                rule.status = SodRuleStatus::Inactive;
                rule.updated_at = Utc::now();
                count += 1;
            }
        }

        Ok(count)
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service for managing SoD rules.
pub struct SodService {
    rule_store: Arc<dyn SodRuleStore>,
    audit_store: Arc<dyn AuditStore>,
}

impl SodService {
    /// Create a new SoD service.
    pub fn new(rule_store: Arc<dyn SodRuleStore>, audit_store: Arc<dyn AuditStore>) -> Self {
        Self {
            rule_store,
            audit_store,
        }
    }

    /// Validate rule input.
    fn validate_rule_input(input: &CreateSodRuleInput) -> Result<()> {
        // Must have at least 2 entitlements
        if input.entitlement_ids.len() < 2 {
            return Err(GovernanceError::SodRuleTooFewEntitlements(
                input.entitlement_ids.len(),
            ));
        }

        // Cardinality requires max_count
        if input.conflict_type == SodConflictType::Cardinality {
            match input.max_count {
                None => return Err(GovernanceError::SodRuleMaxCountRequired),
                Some(max) if max as usize >= input.entitlement_ids.len() => {
                    return Err(GovernanceError::SodRuleInvalidMaxCount(
                        max,
                        input.entitlement_ids.len(),
                    ));
                }
                Some(max) if max < 1 => {
                    return Err(GovernanceError::SodRuleInvalidMaxCount(
                        max,
                        input.entitlement_ids.len(),
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Create a new SoD rule.
    pub async fn create_rule(&self, tenant_id: Uuid, input: CreateSodRuleInput) -> Result<SodRule> {
        Self::validate_rule_input(&input)?;

        let rule = self.rule_store.create(tenant_id, input.clone()).await?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: input.created_by,
                after_state: Some(serde_json::to_value(&rule).unwrap_or_default()),
                metadata: Some(serde_json::json!({"sod_rule_id": rule.id.to_string()})),
                ..Default::default()
            })
            .await?;

        Ok(rule)
    }

    /// Get an SoD rule by ID.
    pub async fn get_rule(&self, tenant_id: Uuid, id: SodRuleId) -> Result<Option<SodRule>> {
        self.rule_store.get(tenant_id, id).await
    }

    /// List all active SoD rules for a tenant.
    pub async fn list_rules(&self, tenant_id: Uuid) -> Result<Vec<SodRule>> {
        self.rule_store.list_active(tenant_id).await
    }

    /// Update an SoD rule.
    pub async fn update_rule(
        &self,
        tenant_id: Uuid,
        id: SodRuleId,
        input: UpdateSodRuleInput,
        actor_id: Uuid,
    ) -> Result<SodRule> {
        // Get before state
        let before = self
            .rule_store
            .get(tenant_id, id)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(id.into_inner()))?;

        let updated = self
            .rule_store
            .update(tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(id.into_inner()))?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Updated,
                actor_id,
                before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                after_state: Some(serde_json::to_value(&updated).unwrap_or_default()),
                metadata: Some(serde_json::json!({"sod_rule_id": id.to_string()})),
                ..Default::default()
            })
            .await?;

        Ok(updated)
    }

    /// Delete an SoD rule.
    pub async fn delete_rule(
        &self,
        tenant_id: Uuid,
        id: SodRuleId,
        actor_id: Uuid,
    ) -> Result<bool> {
        // Get before state for audit
        let before = self
            .rule_store
            .get(tenant_id, id)
            .await?
            .ok_or(GovernanceError::SodRuleNotFound(id.into_inner()))?;

        let deleted = self.rule_store.delete(tenant_id, id).await?;

        if deleted {
            // Log audit event
            self.audit_store
                .log_event(EntitlementAuditEventInput {
                    tenant_id,
                    action: EntitlementAuditAction::Deleted,
                    actor_id,
                    before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                    metadata: Some(serde_json::json!({"sod_rule_id": id.to_string()})),
                    ..Default::default()
                })
                .await?;
        }

        Ok(deleted)
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
        SodService,
        Arc<InMemorySodRuleStore>,
        Arc<InMemoryAuditStore>,
    ) {
        let rule_store = Arc::new(InMemorySodRuleStore::new());
        let audit_store = Arc::new(InMemoryAuditStore::new());
        let service = SodService::new(rule_store.clone(), audit_store.clone());
        (service, rule_store, audit_store)
    }

    fn create_exclusive_input() -> CreateSodRuleInput {
        CreateSodRuleInput {
            name: "AP Segregation".to_string(),
            description: Some("Prevent AP fraud".to_string()),
            conflict_type: SodConflictType::Exclusive,
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            max_count: None,
            severity: SodSeverity::Critical,
            created_by: Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn test_create_exclusive_rule() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let input = create_exclusive_input();

        let rule = service.create_rule(tenant_id, input.clone()).await.unwrap();
        assert_eq!(rule.name, input.name);
        assert_eq!(rule.conflict_type, SodConflictType::Exclusive);
        assert_eq!(rule.severity, SodSeverity::Critical);
        assert_eq!(rule.status, SodRuleStatus::Active);
        assert!(!rule.orphaned);
    }

    #[tokio::test]
    async fn test_create_cardinality_rule() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodRuleInput {
            name: "Financial Role Limit".to_string(),
            description: None,
            conflict_type: SodConflictType::Cardinality,
            entitlement_ids: vec![
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            ],
            max_count: Some(2),
            severity: SodSeverity::High,
            created_by: Uuid::new_v4(),
        };

        let rule = service.create_rule(tenant_id, input).await.unwrap();
        assert_eq!(rule.conflict_type, SodConflictType::Cardinality);
        assert_eq!(rule.max_count, Some(2));
        assert_eq!(rule.entitlement_ids.len(), 5);
    }

    #[tokio::test]
    async fn test_create_inclusive_rule() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodRuleInput {
            name: "Required Together".to_string(),
            description: None,
            conflict_type: SodConflictType::Inclusive,
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            max_count: None,
            severity: SodSeverity::Medium,
            created_by: Uuid::new_v4(),
        };

        let rule = service.create_rule(tenant_id, input).await.unwrap();
        assert_eq!(rule.conflict_type, SodConflictType::Inclusive);
    }

    #[tokio::test]
    async fn test_update_rule() {
        let (service, _, audit_store) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let input = create_exclusive_input();

        let rule = service.create_rule(tenant_id, input).await.unwrap();

        let update = UpdateSodRuleInput {
            severity: Some(SodSeverity::Low),
            description: Some("Updated description".to_string()),
            ..Default::default()
        };

        let updated = service
            .update_rule(tenant_id, rule.id, update, actor_id)
            .await
            .unwrap();
        assert_eq!(updated.severity, SodSeverity::Low);
        assert_eq!(updated.description, Some("Updated description".to_string()));

        // Should have 2 audit events (create + update)
        assert_eq!(audit_store.count().await, 2);
    }

    #[tokio::test]
    async fn test_delete_rule() {
        let (service, rule_store, audit_store) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let input = create_exclusive_input();

        let rule = service.create_rule(tenant_id, input).await.unwrap();
        assert_eq!(rule_store.count().await, 1);

        let deleted = service
            .delete_rule(tenant_id, rule.id, actor_id)
            .await
            .unwrap();
        assert!(deleted);
        assert_eq!(rule_store.count().await, 0);

        // Should have 2 audit events (create + delete)
        assert_eq!(audit_store.count().await, 2);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let (service, _, _) = create_test_service();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let input = create_exclusive_input();

        let rule = service.create_rule(tenant_a, input).await.unwrap();

        // Should find in tenant A
        let found = service.get_rule(tenant_a, rule.id).await.unwrap();
        assert!(found.is_some());

        // Should not find in tenant B
        let not_found = service.get_rule(tenant_b, rule.id).await.unwrap();
        assert!(not_found.is_none());

        // List should be empty for tenant B
        let list = service.list_rules(tenant_b).await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_rule_validation_min_entitlements() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodRuleInput {
            name: "Bad Rule".to_string(),
            description: None,
            conflict_type: SodConflictType::Exclusive,
            entitlement_ids: vec![Uuid::new_v4()], // Only 1!
            max_count: None,
            severity: SodSeverity::Medium,
            created_by: Uuid::new_v4(),
        };

        let result = service.create_rule(tenant_id, input).await;
        assert!(matches!(
            result,
            Err(GovernanceError::SodRuleTooFewEntitlements(1))
        ));
    }

    #[tokio::test]
    async fn test_cardinality_requires_max_count() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodRuleInput {
            name: "Bad Cardinality".to_string(),
            description: None,
            conflict_type: SodConflictType::Cardinality,
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            max_count: None, // Missing!
            severity: SodSeverity::Medium,
            created_by: Uuid::new_v4(),
        };

        let result = service.create_rule(tenant_id, input).await;
        assert!(matches!(
            result,
            Err(GovernanceError::SodRuleMaxCountRequired)
        ));
    }

    #[tokio::test]
    async fn test_cardinality_max_count_validation() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        // max_count >= entitlement count is invalid
        let input = CreateSodRuleInput {
            name: "Bad Max Count".to_string(),
            description: None,
            conflict_type: SodConflictType::Cardinality,
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            max_count: Some(3), // Same as count!
            severity: SodSeverity::Medium,
            created_by: Uuid::new_v4(),
        };

        let result = service.create_rule(tenant_id, input).await;
        assert!(matches!(
            result,
            Err(GovernanceError::SodRuleInvalidMaxCount(3, 3))
        ));
    }

    #[tokio::test]
    async fn test_list_by_entitlements() {
        let rule_store = Arc::new(InMemorySodRuleStore::new());
        let tenant_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();
        let ent_c = Uuid::new_v4();
        let ent_d = Uuid::new_v4();

        // Rule 1: A + B
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Rule 1".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Medium,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // Rule 2: C + D
        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Rule 2".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_c, ent_d],
                    max_count: None,
                    severity: SodSeverity::Medium,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // Search for rules containing A
        let rules = rule_store
            .list_by_entitlements(tenant_id, &[ent_a])
            .await
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Rule 1");

        // Search for rules containing A or C
        let rules = rule_store
            .list_by_entitlements(tenant_id, &[ent_a, ent_c])
            .await
            .unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[tokio::test]
    async fn test_mark_orphaned() {
        let rule_store = Arc::new(InMemorySodRuleStore::new());
        let tenant_id = Uuid::new_v4();

        let ent_a = Uuid::new_v4();
        let ent_b = Uuid::new_v4();

        rule_store
            .create(
                tenant_id,
                CreateSodRuleInput {
                    name: "Rule 1".to_string(),
                    description: None,
                    conflict_type: SodConflictType::Exclusive,
                    entitlement_ids: vec![ent_a, ent_b],
                    max_count: None,
                    severity: SodSeverity::Medium,
                    created_by: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();

        // Mark entitlement A as orphaned
        let count = rule_store.mark_orphaned(tenant_id, ent_a).await.unwrap();
        assert_eq!(count, 1);

        // Rule should now be inactive and orphaned
        let rules = rule_store.list_active(tenant_id).await.unwrap();
        assert!(rules.is_empty());
    }
}
