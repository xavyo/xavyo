//! `SoD` exemption service for managing approved violations.
//!
//! This module provides the `SodExemptionService` for creating, revoking, and
//! checking `SoD` exemptions that allow users to bypass specific `SoD` rules.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEventInput};
use crate::error::{GovernanceError, Result};
use crate::types::{SodExemptionId, SodRuleId};

// ============================================================================
// Domain Types
// ============================================================================

/// Exemption status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodExemptionStatus {
    /// Exemption is active.
    #[default]
    Active,
    /// Exemption has been revoked.
    Revoked,
    /// Exemption has expired.
    Expired,
}

impl std::fmt::Display for SodExemptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Revoked => write!(f, "revoked"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// An `SoD` exemption allowing a user to bypass a specific rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodExemption {
    /// Unique identifier.
    pub id: SodExemptionId,
    /// Tenant this exemption belongs to.
    pub tenant_id: Uuid,
    /// The rule being exempted.
    pub rule_id: SodRuleId,
    /// The user granted the exemption.
    pub user_id: Uuid,
    /// Business justification for the exemption.
    pub justification: String,
    /// When the exemption was granted.
    pub granted_at: DateTime<Utc>,
    /// Who granted the exemption.
    pub granted_by: Uuid,
    /// When the exemption expires (if time-limited).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the exemption was revoked (if revoked).
    pub revoked_at: Option<DateTime<Utc>>,
    /// Who revoked the exemption (if revoked).
    pub revoked_by: Option<Uuid>,
    /// Exemption status.
    pub status: SodExemptionStatus,
}

impl SodExemption {
    /// Check if the exemption is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.status != SodExemptionStatus::Active {
            return false;
        }

        // Check expiration
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }

        true
    }
}

/// Input for creating an `SoD` exemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSodExemptionInput {
    /// The rule to exempt.
    pub rule_id: SodRuleId,
    /// The user to exempt.
    pub user_id: Uuid,
    /// Business justification (minimum 10 characters).
    pub justification: String,
    /// When the exemption expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who is granting the exemption.
    pub granted_by: Uuid,
}

// ============================================================================
// Store Trait
// ============================================================================

/// Trait for `SoD` exemption storage backends.
#[async_trait::async_trait]
pub trait SodExemptionStore: Send + Sync {
    /// Get an exemption by ID.
    async fn get(&self, tenant_id: Uuid, id: SodExemptionId) -> Result<Option<SodExemption>>;

    /// Get active exemption for a user+rule.
    async fn get_active(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<Option<SodExemption>>;

    /// List all exemptions for a user.
    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodExemption>>;

    /// List all exemptions for a rule.
    async fn list_by_rule(&self, tenant_id: Uuid, rule_id: SodRuleId) -> Result<Vec<SodExemption>>;

    /// List all active exemptions for a tenant.
    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodExemption>>;

    /// Create a new exemption.
    async fn create(&self, tenant_id: Uuid, input: CreateSodExemptionInput)
        -> Result<SodExemption>;

    /// Revoke an exemption.
    async fn revoke(
        &self,
        tenant_id: Uuid,
        id: SodExemptionId,
        revoked_by: Uuid,
    ) -> Result<Option<SodExemption>>;

    /// Check if a user is exempted from a rule.
    async fn is_exempted(&self, tenant_id: Uuid, rule_id: SodRuleId, user_id: Uuid)
        -> Result<bool>;

    /// Mark expired exemptions as expired.
    async fn expire_stale(&self, tenant_id: Uuid) -> Result<u64>;
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory `SoD` exemption store for testing.
#[derive(Debug, Default)]
pub struct InMemorySodExemptionStore {
    exemptions: Arc<RwLock<HashMap<Uuid, SodExemption>>>,
}

impl InMemorySodExemptionStore {
    /// Create a new in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exemptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.exemptions.write().await.clear();
    }

    /// Get exemption count.
    pub async fn count(&self) -> usize {
        self.exemptions.read().await.len()
    }
}

#[async_trait::async_trait]
impl SodExemptionStore for InMemorySodExemptionStore {
    async fn get(&self, tenant_id: Uuid, id: SodExemptionId) -> Result<Option<SodExemption>> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions
            .get(&id.into_inner())
            .filter(|e| e.tenant_id == tenant_id)
            .cloned())
    }

    async fn get_active(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<Option<SodExemption>> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions
            .values()
            .find(|e| {
                e.tenant_id == tenant_id
                    && e.rule_id == rule_id
                    && e.user_id == user_id
                    && e.is_valid()
            })
            .cloned())
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodExemption>> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions
            .values()
            .filter(|e| e.tenant_id == tenant_id && e.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_by_rule(&self, tenant_id: Uuid, rule_id: SodRuleId) -> Result<Vec<SodExemption>> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions
            .values()
            .filter(|e| e.tenant_id == tenant_id && e.rule_id == rule_id)
            .cloned()
            .collect())
    }

    async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<SodExemption>> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions
            .values()
            .filter(|e| e.tenant_id == tenant_id && e.is_valid())
            .cloned()
            .collect())
    }

    async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateSodExemptionInput,
    ) -> Result<SodExemption> {
        let now = Utc::now();
        let exemption = SodExemption {
            id: SodExemptionId::new(),
            tenant_id,
            rule_id: input.rule_id,
            user_id: input.user_id,
            justification: input.justification,
            granted_at: now,
            granted_by: input.granted_by,
            expires_at: input.expires_at,
            revoked_at: None,
            revoked_by: None,
            status: SodExemptionStatus::Active,
        };

        let mut exemptions = self.exemptions.write().await;
        exemptions.insert(exemption.id.into_inner(), exemption.clone());
        Ok(exemption)
    }

    async fn revoke(
        &self,
        tenant_id: Uuid,
        id: SodExemptionId,
        revoked_by: Uuid,
    ) -> Result<Option<SodExemption>> {
        let mut exemptions = self.exemptions.write().await;

        if let Some(exemption) = exemptions.get_mut(&id.into_inner()) {
            if exemption.tenant_id != tenant_id {
                return Ok(None);
            }
            if exemption.status != SodExemptionStatus::Active {
                return Ok(None);
            }

            exemption.status = SodExemptionStatus::Revoked;
            exemption.revoked_at = Some(Utc::now());
            exemption.revoked_by = Some(revoked_by);
            Ok(Some(exemption.clone()))
        } else {
            Ok(None)
        }
    }

    async fn is_exempted(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<bool> {
        let exemptions = self.exemptions.read().await;
        Ok(exemptions.values().any(|e| {
            e.tenant_id == tenant_id && e.rule_id == rule_id && e.user_id == user_id && e.is_valid()
        }))
    }

    async fn expire_stale(&self, tenant_id: Uuid) -> Result<u64> {
        let mut exemptions = self.exemptions.write().await;
        let now = Utc::now();
        let mut count = 0u64;

        for exemption in exemptions.values_mut() {
            if exemption.tenant_id == tenant_id && exemption.status == SodExemptionStatus::Active {
                if let Some(expires_at) = exemption.expires_at {
                    if now > expires_at {
                        exemption.status = SodExemptionStatus::Expired;
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }
}

// ============================================================================
// Service
// ============================================================================

/// Minimum justification length.
const MIN_JUSTIFICATION_LENGTH: usize = 10;

/// Service for managing `SoD` exemptions.
pub struct SodExemptionService {
    exemption_store: Arc<dyn SodExemptionStore>,
    audit_store: Arc<dyn AuditStore>,
}

impl SodExemptionService {
    /// Create a new `SoD` exemption service.
    pub fn new(
        exemption_store: Arc<dyn SodExemptionStore>,
        audit_store: Arc<dyn AuditStore>,
    ) -> Self {
        Self {
            exemption_store,
            audit_store,
        }
    }

    /// Validate exemption input.
    fn validate_input(input: &CreateSodExemptionInput) -> Result<()> {
        // Justification must be at least MIN_JUSTIFICATION_LENGTH characters
        if input.justification.trim().len() < MIN_JUSTIFICATION_LENGTH {
            return Err(GovernanceError::SodExemptionJustificationTooShort(
                MIN_JUSTIFICATION_LENGTH,
            ));
        }

        // Expiry must be in the future
        if let Some(expires_at) = input.expires_at {
            if expires_at < Utc::now() {
                return Err(GovernanceError::SodExemptionExpiryInPast);
            }
        }

        Ok(())
    }

    /// Grant a new exemption.
    pub async fn grant_exemption(
        &self,
        tenant_id: Uuid,
        input: CreateSodExemptionInput,
    ) -> Result<SodExemption> {
        Self::validate_input(&input)?;

        let exemption = self
            .exemption_store
            .create(tenant_id, input.clone())
            .await?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Created,
                actor_id: input.granted_by,
                after_state: Some(serde_json::to_value(&exemption).unwrap_or_default()),
                metadata: Some(serde_json::json!({
                    "sod_exemption_id": exemption.id.to_string(),
                    "rule_id": input.rule_id.to_string(),
                    "user_id": input.user_id.to_string(),
                })),
                ..Default::default()
            })
            .await?;

        Ok(exemption)
    }

    /// Revoke an exemption.
    pub async fn revoke_exemption(
        &self,
        tenant_id: Uuid,
        id: SodExemptionId,
        revoked_by: Uuid,
    ) -> Result<SodExemption> {
        // Get before state for audit
        let before = self
            .exemption_store
            .get(tenant_id, id)
            .await?
            .ok_or(GovernanceError::SodExemptionNotFound(id.into_inner()))?;

        let revoked = self
            .exemption_store
            .revoke(tenant_id, id, revoked_by)
            .await?
            .ok_or(GovernanceError::SodExemptionNotFound(id.into_inner()))?;

        // Log audit event
        self.audit_store
            .log_event(EntitlementAuditEventInput {
                tenant_id,
                action: EntitlementAuditAction::Deleted,
                actor_id: revoked_by,
                before_state: Some(serde_json::to_value(&before).unwrap_or_default()),
                after_state: Some(serde_json::to_value(&revoked).unwrap_or_default()),
                metadata: Some(serde_json::json!({
                    "sod_exemption_id": id.to_string(),
                    "action": "revoked",
                })),
                ..Default::default()
            })
            .await?;

        Ok(revoked)
    }

    /// Get an exemption by ID.
    pub async fn get_exemption(
        &self,
        tenant_id: Uuid,
        id: SodExemptionId,
    ) -> Result<Option<SodExemption>> {
        self.exemption_store.get(tenant_id, id).await
    }

    /// List all exemptions for a user.
    pub async fn list_user_exemptions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SodExemption>> {
        self.exemption_store.list_by_user(tenant_id, user_id).await
    }

    /// List all exemptions for a rule.
    pub async fn list_rule_exemptions(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
    ) -> Result<Vec<SodExemption>> {
        self.exemption_store.list_by_rule(tenant_id, rule_id).await
    }

    /// List all active exemptions.
    pub async fn list_active_exemptions(&self, tenant_id: Uuid) -> Result<Vec<SodExemption>> {
        self.exemption_store.list_active(tenant_id).await
    }

    /// Check if a user is exempted from a rule.
    pub async fn is_exempted(
        &self,
        tenant_id: Uuid,
        rule_id: SodRuleId,
        user_id: Uuid,
    ) -> Result<bool> {
        self.exemption_store
            .is_exempted(tenant_id, rule_id, user_id)
            .await
    }

    /// Expire stale exemptions.
    pub async fn expire_stale_exemptions(&self, tenant_id: Uuid) -> Result<u64> {
        self.exemption_store.expire_stale(tenant_id).await
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
        SodExemptionService,
        Arc<InMemorySodExemptionStore>,
        Arc<InMemoryAuditStore>,
    ) {
        let exemption_store = Arc::new(InMemorySodExemptionStore::new());
        let audit_store = Arc::new(InMemoryAuditStore::new());
        let service = SodExemptionService::new(exemption_store.clone(), audit_store.clone());
        (service, exemption_store, audit_store)
    }

    fn create_valid_input() -> CreateSodExemptionInput {
        CreateSodExemptionInput {
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Business need for project X during audit period".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            granted_by: Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn test_grant_exemption() {
        let (service, _, audit_store) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let input = create_valid_input();

        let exemption = service
            .grant_exemption(tenant_id, input.clone())
            .await
            .unwrap();

        assert_eq!(exemption.rule_id, input.rule_id);
        assert_eq!(exemption.user_id, input.user_id);
        assert_eq!(exemption.justification, input.justification);
        assert_eq!(exemption.status, SodExemptionStatus::Active);
        assert!(exemption.is_valid());

        // Should have audit event
        assert_eq!(audit_store.count().await, 1);
    }

    #[tokio::test]
    async fn test_grant_exemption_justification_too_short() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodExemptionInput {
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Short".to_string(), // < 10 chars
            expires_at: None,
            granted_by: Uuid::new_v4(),
        };

        let result = service.grant_exemption(tenant_id, input).await;
        assert!(matches!(
            result,
            Err(GovernanceError::SodExemptionJustificationTooShort(10))
        ));
    }

    #[tokio::test]
    async fn test_grant_exemption_expiry_in_past() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodExemptionInput {
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Valid justification for exemption".to_string(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            granted_by: Uuid::new_v4(),
        };

        let result = service.grant_exemption(tenant_id, input).await;
        assert!(matches!(
            result,
            Err(GovernanceError::SodExemptionExpiryInPast)
        ));
    }

    #[tokio::test]
    async fn test_revoke_exemption() {
        let (service, _, audit_store) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let revoker = Uuid::new_v4();
        let input = create_valid_input();

        let exemption = service.grant_exemption(tenant_id, input).await.unwrap();

        let revoked = service
            .revoke_exemption(tenant_id, exemption.id, revoker)
            .await
            .unwrap();

        assert_eq!(revoked.status, SodExemptionStatus::Revoked);
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoked.revoked_by, Some(revoker));
        assert!(!revoked.is_valid());

        // Should have 2 audit events (grant + revoke)
        assert_eq!(audit_store.count().await, 2);
    }

    #[tokio::test]
    async fn test_revoke_not_found() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let revoker = Uuid::new_v4();

        let result = service
            .revoke_exemption(tenant_id, SodExemptionId::new(), revoker)
            .await;

        assert!(matches!(
            result,
            Err(GovernanceError::SodExemptionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_is_exempted() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let input = create_valid_input();

        // Not exempted before granting
        let is_exempted = service
            .is_exempted(tenant_id, input.rule_id, input.user_id)
            .await
            .unwrap();
        assert!(!is_exempted);

        // Grant exemption
        service
            .grant_exemption(tenant_id, input.clone())
            .await
            .unwrap();

        // Now exempted
        let is_exempted = service
            .is_exempted(tenant_id, input.rule_id, input.user_id)
            .await
            .unwrap();
        assert!(is_exempted);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let (service, _, _) = create_test_service();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let input = create_valid_input();

        let exemption = service
            .grant_exemption(tenant_a, input.clone())
            .await
            .unwrap();

        // Should find in tenant A
        let found = service.get_exemption(tenant_a, exemption.id).await.unwrap();
        assert!(found.is_some());

        // Should not find in tenant B
        let not_found = service.get_exemption(tenant_b, exemption.id).await.unwrap();
        assert!(not_found.is_none());

        // is_exempted should return false for tenant B
        let is_exempted = service
            .is_exempted(tenant_b, input.rule_id, input.user_id)
            .await
            .unwrap();
        assert!(!is_exempted);
    }

    #[tokio::test]
    async fn test_list_user_exemptions() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Create exemptions for the user
        for _ in 0..3 {
            let input = CreateSodExemptionInput {
                rule_id: SodRuleId::new(),
                user_id,
                justification: "Valid justification for testing".to_string(),
                expires_at: None,
                granted_by: Uuid::new_v4(),
            };
            service.grant_exemption(tenant_id, input).await.unwrap();
        }

        // Create exemption for different user
        let other_input = CreateSodExemptionInput {
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Valid justification for testing".to_string(),
            expires_at: None,
            granted_by: Uuid::new_v4(),
        };
        service
            .grant_exemption(tenant_id, other_input)
            .await
            .unwrap();

        let exemptions = service
            .list_user_exemptions(tenant_id, user_id)
            .await
            .unwrap();
        assert_eq!(exemptions.len(), 3);
    }

    #[tokio::test]
    async fn test_list_rule_exemptions() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();
        let rule_id = SodRuleId::new();

        // Create exemptions for the rule
        for _ in 0..2 {
            let input = CreateSodExemptionInput {
                rule_id,
                user_id: Uuid::new_v4(),
                justification: "Valid justification for testing".to_string(),
                expires_at: None,
                granted_by: Uuid::new_v4(),
            };
            service.grant_exemption(tenant_id, input).await.unwrap();
        }

        let exemptions = service
            .list_rule_exemptions(tenant_id, rule_id)
            .await
            .unwrap();
        assert_eq!(exemptions.len(), 2);
    }

    #[tokio::test]
    async fn test_expired_exemption_not_valid() {
        let store = Arc::new(InMemorySodExemptionStore::new());
        let tenant_id = Uuid::new_v4();
        let rule_id = SodRuleId::new();
        let user_id = Uuid::new_v4();

        // Create exemption that's already expired (bypass validation by using store directly)
        let exemption = SodExemption {
            id: SodExemptionId::new(),
            tenant_id,
            rule_id,
            user_id,
            justification: "Test exemption".to_string(),
            granted_at: Utc::now() - chrono::Duration::days(10),
            granted_by: Uuid::new_v4(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)), // Already expired
            revoked_at: None,
            revoked_by: None,
            status: SodExemptionStatus::Active,
        };

        // Manually insert
        {
            let mut exemptions = store.exemptions.write().await;
            exemptions.insert(exemption.id.into_inner(), exemption.clone());
        }

        // is_valid should return false because it's expired
        assert!(!exemption.is_valid());

        // is_exempted should return false
        let is_exempted = store
            .is_exempted(tenant_id, rule_id, user_id)
            .await
            .unwrap();
        assert!(!is_exempted);
    }

    #[tokio::test]
    async fn test_expire_stale() {
        let store = Arc::new(InMemorySodExemptionStore::new());
        let tenant_id = Uuid::new_v4();

        // Create expired exemption
        let expired_exemption = SodExemption {
            id: SodExemptionId::new(),
            tenant_id,
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Expired exemption".to_string(),
            granted_at: Utc::now() - chrono::Duration::days(10),
            granted_by: Uuid::new_v4(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            revoked_at: None,
            revoked_by: None,
            status: SodExemptionStatus::Active,
        };

        // Create valid exemption
        let valid_exemption = SodExemption {
            id: SodExemptionId::new(),
            tenant_id,
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Valid exemption".to_string(),
            granted_at: Utc::now(),
            granted_by: Uuid::new_v4(),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            revoked_at: None,
            revoked_by: None,
            status: SodExemptionStatus::Active,
        };

        // Insert both
        {
            let mut exemptions = store.exemptions.write().await;
            exemptions.insert(expired_exemption.id.into_inner(), expired_exemption.clone());
            exemptions.insert(valid_exemption.id.into_inner(), valid_exemption.clone());
        }

        // Expire stale
        let count = store.expire_stale(tenant_id).await.unwrap();
        assert_eq!(count, 1);

        // Check status
        let expired = store
            .get(tenant_id, expired_exemption.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.status, SodExemptionStatus::Expired);

        let valid = store
            .get(tenant_id, valid_exemption.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(valid.status, SodExemptionStatus::Active);
    }

    #[tokio::test]
    async fn test_exemption_status_display() {
        assert_eq!(SodExemptionStatus::Active.to_string(), "active");
        assert_eq!(SodExemptionStatus::Revoked.to_string(), "revoked");
        assert_eq!(SodExemptionStatus::Expired.to_string(), "expired");
    }

    #[tokio::test]
    async fn test_permanent_exemption() {
        let (service, _, _) = create_test_service();
        let tenant_id = Uuid::new_v4();

        let input = CreateSodExemptionInput {
            rule_id: SodRuleId::new(),
            user_id: Uuid::new_v4(),
            justification: "Permanent exemption for executive".to_string(),
            expires_at: None, // No expiration
            granted_by: Uuid::new_v4(),
        };

        let exemption = service
            .grant_exemption(tenant_id, input.clone())
            .await
            .unwrap();
        assert!(exemption.expires_at.is_none());
        assert!(exemption.is_valid());

        // Check is_exempted
        let is_exempted = service
            .is_exempted(tenant_id, input.rule_id, input.user_id)
            .await
            .unwrap();
        assert!(is_exempted);
    }
}
