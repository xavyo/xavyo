//! Authorization audit trail (F083, F-020).
//!
//! Emits structured tracing events for all authorization decisions
//! for SIEM integration. Also provides policy change audit logging.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;
use xavyo_authorization::{AuthorizationDecision, AuthorizationRequest};

use crate::models::{
    PolicyAuditEvent, PolicyAuditEventInput, PolicyAuditFilter, PolicyVersion, PolicyVersionInput,
};

/// Result type for policy audit operations.
pub type PolicyAuditResult<T> = Result<T, PolicyAuditError>;

/// Error type for policy audit operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyAuditError {
    /// Storage error.
    #[error("audit storage error: {0}")]
    Storage(String),

    /// Event not found.
    #[error("audit event not found")]
    NotFound,

    /// Version not found.
    #[error("policy version not found")]
    VersionNotFound,
}

/// Authorization audit trail for decisions.
pub struct AuthorizationAudit;

impl AuthorizationAudit {
    /// Emit a structured log entry for an authorization decision.
    ///
    /// Respects verbosity settings:
    /// - "all": log all decisions
    /// - "`deny_only"`: only log denied decisions
    pub fn emit_decision(
        decision: &AuthorizationDecision,
        request: &AuthorizationRequest,
        verbosity: &str,
    ) {
        // If verbosity is "deny_only" and the decision is allowed, skip logging
        if verbosity == "deny_only" && decision.allowed {
            return;
        }

        tracing::info!(
            target: "authorization",
            decision_id = %decision.decision_id,
            subject_id = %request.subject_id,
            tenant_id = %request.tenant_id,
            action = %request.action,
            resource_type = %request.resource_type,
            resource_id = ?request.resource_id,
            decision = if decision.allowed { "allow" } else { "deny" },
            reason = %decision.reason,
            source = %decision.source,
            policy_id = ?decision.policy_id,
            latency_ms = decision.latency_ms,
            "authorization decision"
        );
    }
}

// ============================================================================
// Policy Audit Store (F-020)
// ============================================================================

/// Trait for policy audit event storage backends.
#[async_trait::async_trait]
pub trait PolicyAuditStore: Send + Sync {
    /// Log a policy audit event.
    async fn log_event(&self, input: PolicyAuditEventInput) -> PolicyAuditResult<PolicyAuditEvent>;

    /// Query policy audit events.
    async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: PolicyAuditFilter,
    ) -> PolicyAuditResult<(Vec<PolicyAuditEvent>, i64)>;

    /// Get a specific audit event by ID.
    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> PolicyAuditResult<Option<PolicyAuditEvent>>;

    /// Store a policy version snapshot.
    async fn store_version(&self, input: PolicyVersionInput) -> PolicyAuditResult<PolicyVersion>;

    /// List all versions of a policy.
    async fn list_versions(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> PolicyAuditResult<Vec<PolicyVersion>>;

    /// Get a specific policy version.
    async fn get_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        version_number: i32,
    ) -> PolicyAuditResult<Option<PolicyVersion>>;

    /// Get the next version number for a policy.
    async fn next_version_number(&self, tenant_id: Uuid, policy_id: Uuid)
        -> PolicyAuditResult<i32>;
}

/// In-memory policy audit store for testing.
#[derive(Debug, Default)]
pub struct InMemoryPolicyAuditStore {
    events: Arc<RwLock<HashMap<Uuid, PolicyAuditEvent>>>,
    versions: Arc<RwLock<HashMap<(Uuid, Uuid), Vec<PolicyVersion>>>>,
}

impl InMemoryPolicyAuditStore {
    /// Create a new in-memory policy audit store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(HashMap::new())),
            versions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the count of events in the store.
    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Clear all events (for testing).
    pub async fn clear(&self) {
        self.events.write().await.clear();
        self.versions.write().await.clear();
    }

    /// Get all events (for testing).
    pub async fn get_all_events(&self) -> Vec<PolicyAuditEvent> {
        self.events.read().await.values().cloned().collect()
    }
}

#[async_trait::async_trait]
impl PolicyAuditStore for InMemoryPolicyAuditStore {
    async fn log_event(&self, input: PolicyAuditEventInput) -> PolicyAuditResult<PolicyAuditEvent> {
        let event = PolicyAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            policy_id: input.policy_id,
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
        filter: PolicyAuditFilter,
    ) -> PolicyAuditResult<(Vec<PolicyAuditEvent>, i64)> {
        let events = self.events.read().await;
        let mut results: Vec<_> = events
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| filter.policy_id.is_none_or(|id| e.policy_id == id))
            .filter(|e| filter.actor_id.is_none_or(|id| e.actor_id == id))
            .filter(|e| filter.action.is_none_or(|a| e.action == a))
            .filter(|e| filter.from_date.is_none_or(|d| e.timestamp >= d))
            .filter(|e| filter.to_date.is_none_or(|d| e.timestamp <= d))
            .cloned()
            .collect();

        // Sort by timestamp descending (most recent first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        let total = results.len() as i64;

        // Apply offset and limit
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(100);

        let results: Vec<_> = results.into_iter().skip(offset).take(limit).collect();

        Ok((results, total))
    }

    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> PolicyAuditResult<Option<PolicyAuditEvent>> {
        let events = self.events.read().await;
        Ok(events
            .get(&event_id)
            .filter(|e| e.tenant_id == tenant_id)
            .cloned())
    }

    async fn store_version(&self, input: PolicyVersionInput) -> PolicyAuditResult<PolicyVersion> {
        let mut versions = self.versions.write().await;
        let key = (input.tenant_id, input.policy_id);

        let version_number = versions.get(&key).map_or(1, |v| {
            v.iter().map(|pv| pv.version_number).max().unwrap_or(0) + 1
        });

        let version = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id: input.policy_id,
            tenant_id: input.tenant_id,
            version_number,
            policy_state: input.policy_state,
            created_at: Utc::now(),
            created_by: input.created_by,
        };

        versions.entry(key).or_default().push(version.clone());

        Ok(version)
    }

    async fn list_versions(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> PolicyAuditResult<Vec<PolicyVersion>> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        let mut results = versions.get(&key).cloned().unwrap_or_default();
        results.sort_by_key(|v| v.version_number);

        Ok(results)
    }

    async fn get_version(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        version_number: i32,
    ) -> PolicyAuditResult<Option<PolicyVersion>> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        Ok(versions
            .get(&key)
            .and_then(|v| v.iter().find(|pv| pv.version_number == version_number))
            .cloned())
    }

    async fn next_version_number(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> PolicyAuditResult<i32> {
        let versions = self.versions.read().await;
        let key = (tenant_id, policy_id);

        Ok(versions.get(&key).map_or(1, |v| {
            v.iter().map(|pv| pv.version_number).max().unwrap_or(0) + 1
        }))
    }
}

/// A policy audit store that always fails (for testing graceful degradation).
#[derive(Debug, Default)]
pub struct FailingPolicyAuditStore;

#[async_trait::async_trait]
impl PolicyAuditStore for FailingPolicyAuditStore {
    async fn log_event(
        &self,
        _input: PolicyAuditEventInput,
    ) -> PolicyAuditResult<PolicyAuditEvent> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn query_events(
        &self,
        _tenant_id: Uuid,
        _filter: PolicyAuditFilter,
    ) -> PolicyAuditResult<(Vec<PolicyAuditEvent>, i64)> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn get_event(
        &self,
        _tenant_id: Uuid,
        _event_id: Uuid,
    ) -> PolicyAuditResult<Option<PolicyAuditEvent>> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn store_version(&self, _input: PolicyVersionInput) -> PolicyAuditResult<PolicyVersion> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn list_versions(
        &self,
        _tenant_id: Uuid,
        _policy_id: Uuid,
    ) -> PolicyAuditResult<Vec<PolicyVersion>> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn get_version(
        &self,
        _tenant_id: Uuid,
        _policy_id: Uuid,
        _version_number: i32,
    ) -> PolicyAuditResult<Option<PolicyVersion>> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }

    async fn next_version_number(
        &self,
        _tenant_id: Uuid,
        _policy_id: Uuid,
    ) -> PolicyAuditResult<i32> {
        Err(PolicyAuditError::Storage("simulated failure".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PolicyAuditAction;

    #[test]
    fn test_emit_decision_all_verbosity() {
        use xavyo_authorization::DecisionSource;

        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "report".to_string(),
            resource_id: None,
            delegation: None,
        };

        let decision = AuthorizationDecision {
            allowed: true,
            reason: "allowed by policy".to_string(),
            source: DecisionSource::Policy,
            policy_id: Some(Uuid::new_v4()),
            decision_id: Uuid::new_v4(),
            latency_ms: 0.5,
        };

        // Should not panic with "all" verbosity
        AuthorizationAudit::emit_decision(&decision, &request, "all");
    }

    #[test]
    fn test_emit_decision_deny_only_skips_allowed() {
        use xavyo_authorization::DecisionSource;

        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "report".to_string(),
            resource_id: None,
            delegation: None,
        };

        let decision = AuthorizationDecision {
            allowed: true,
            reason: "allowed by entitlement".to_string(),
            source: DecisionSource::Entitlement,
            policy_id: None,
            decision_id: Uuid::new_v4(),
            latency_ms: 0.3,
        };

        // Should not emit (allowed + deny_only mode)
        AuthorizationAudit::emit_decision(&decision, &request, "deny_only");
    }

    #[test]
    fn test_emit_decision_deny_only_logs_denied() {
        use xavyo_authorization::DecisionSource;

        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "delete".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some("user-123".to_string()),
            delegation: None,
        };

        let decision = AuthorizationDecision {
            allowed: false,
            reason: "denied by policy".to_string(),
            source: DecisionSource::Policy,
            policy_id: Some(Uuid::new_v4()),
            decision_id: Uuid::new_v4(),
            latency_ms: 1.2,
        };

        // Should log (denied + deny_only mode)
        AuthorizationAudit::emit_decision(&decision, &request, "deny_only");
    }

    #[tokio::test]
    async fn test_policy_audit_store_log_event() {
        let store = InMemoryPolicyAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let input = PolicyAuditEventInput {
            tenant_id,
            policy_id,
            action: PolicyAuditAction::Created,
            actor_id,
            after_state: Some(serde_json::json!({"name": "test policy"})),
            ..Default::default()
        };

        let event = store.log_event(input).await.unwrap();
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.policy_id, policy_id);
        assert_eq!(event.action, PolicyAuditAction::Created);
        assert_eq!(event.actor_id, actor_id);
        assert!(event.after_state.is_some());
    }

    #[tokio::test]
    async fn test_policy_audit_store_query_by_policy() {
        let store = InMemoryPolicyAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let policy_id_1 = Uuid::new_v4();
        let policy_id_2 = Uuid::new_v4();

        // Log events for two policies
        store
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: policy_id_1,
                action: PolicyAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        store
            .log_event(PolicyAuditEventInput {
                tenant_id,
                policy_id: policy_id_2,
                action: PolicyAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Filter by policy_id_1
        let filter = PolicyAuditFilter {
            policy_id: Some(policy_id_1),
            ..Default::default()
        };

        let (events, total) = store.query_events(tenant_id, filter).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(total, 1);
        assert_eq!(events[0].policy_id, policy_id_1);
    }

    #[tokio::test]
    async fn test_policy_audit_store_tenant_isolation() {
        let store = InMemoryPolicyAuditStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        store
            .log_event(PolicyAuditEventInput {
                tenant_id: tenant_a,
                policy_id: Uuid::new_v4(),
                action: PolicyAuditAction::Created,
                actor_id: Uuid::new_v4(),
                ..Default::default()
            })
            .await
            .unwrap();

        let (events_a, _) = store
            .query_events(tenant_a, PolicyAuditFilter::default())
            .await
            .unwrap();
        let (events_b, _) = store
            .query_events(tenant_b, PolicyAuditFilter::default())
            .await
            .unwrap();

        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 0);
    }

    #[tokio::test]
    async fn test_policy_version_store() {
        let store = InMemoryPolicyAuditStore::new();
        let tenant_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Store first version
        let v1 = store
            .store_version(PolicyVersionInput {
                tenant_id,
                policy_id,
                policy_state: serde_json::json!({"name": "v1"}),
                created_by: actor_id,
            })
            .await
            .unwrap();
        assert_eq!(v1.version_number, 1);

        // Store second version
        let v2 = store
            .store_version(PolicyVersionInput {
                tenant_id,
                policy_id,
                policy_state: serde_json::json!({"name": "v2"}),
                created_by: actor_id,
            })
            .await
            .unwrap();
        assert_eq!(v2.version_number, 2);

        // List versions
        let versions = store.list_versions(tenant_id, policy_id).await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version_number, 1);
        assert_eq!(versions[1].version_number, 2);

        // Get specific version
        let found = store.get_version(tenant_id, policy_id, 1).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().version_number, 1);
    }

    #[tokio::test]
    async fn test_failing_audit_store() {
        let store = FailingPolicyAuditStore;

        let result = store.log_event(PolicyAuditEventInput::default()).await;
        assert!(result.is_err());
    }
}
