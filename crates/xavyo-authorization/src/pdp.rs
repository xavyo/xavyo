//! Policy Decision Point (PDP) — the core of F083.
//!
//! The PDP evaluates authorization requests by:
//! 1. Checking explicit deny policies (deny-first)
//! 2. Checking explicit allow policies
//! 3. Resolving user's effective entitlements (direct + group + role)
//! 4. Matching entitlements against action mappings
//! 5. Default deny if no match (fail-closed)

use std::collections::HashSet;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::{MappingCache, PolicyCache};
use crate::entitlement_resolver::EntitlementResolver;
use crate::policy_evaluator::PolicyEvaluator;
use crate::types::{AuthorizationDecision, AuthorizationRequest, DecisionSource, PolicyEffect};

/// The Policy Decision Point — evaluates "Can user X do action Y on resource Z?"
pub struct PolicyDecisionPoint {
    policy_cache: Arc<PolicyCache>,
    mapping_cache: Arc<MappingCache>,
}

impl PolicyDecisionPoint {
    /// Create a new PDP with the given caches.
    pub fn new(policy_cache: Arc<PolicyCache>, mapping_cache: Arc<MappingCache>) -> Self {
        Self {
            policy_cache,
            mapping_cache,
        }
    }

    /// Main evaluation method.
    ///
    /// Returns an `AuthorizationDecision` (allow/deny with reason, source, and timing).
    ///
    /// Evaluation order:
    /// 1. Check explicit deny policies (deny-first, sorted by priority)
    /// 2. Check explicit allow policies
    /// 3. Resolve user's effective entitlements (direct + group + role)
    /// 4. Match entitlements against action mappings
    /// 5. Default deny if no match (fail-closed)
    pub async fn evaluate(
        &self,
        pool: &PgPool,
        request: AuthorizationRequest,
        user_roles: &[String],
        user_attributes: Option<&serde_json::Value>,
    ) -> AuthorizationDecision {
        let start = std::time::Instant::now();
        let decision_id = Uuid::new_v4();

        // Step 1: Load policies from cache
        let policies = match self
            .policy_cache
            .get_policies(pool, request.tenant_id)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                // Fail-closed: deny on error
                tracing::error!(
                    target: "authorization",
                    error = %e,
                    tenant_id = %request.tenant_id,
                    "Failed to load policies"
                );
                return AuthorizationDecision {
                    allowed: false,
                    reason: "internal error: failed to load policies".to_string(),
                    source: DecisionSource::DefaultDeny,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
        };

        // Step 3: Resolve entitlements (needed for both policy conditions and mapping checks)
        let entitlements = EntitlementResolver::resolve_entitlements(
            pool,
            request.tenant_id,
            request.subject_id,
            user_roles,
        )
        .await;

        // Step 2: Evaluate policies (deny policies are sorted first)
        // Pass entitlements so entitlement_check conditions can be evaluated
        if let Some((effect, policy_id)) = PolicyEvaluator::evaluate_policies(
            &policies,
            &request,
            user_attributes,
            Some(&entitlements),
        ) {
            let allowed = matches!(effect, PolicyEffect::Allow);
            return AuthorizationDecision {
                allowed,
                reason: format!("{} by policy", if allowed { "allowed" } else { "denied" }),
                source: DecisionSource::Policy,
                policy_id: Some(policy_id),
                decision_id,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Step 3 (already resolved above): Check if user has any entitlements
        if entitlements.is_empty() {
            return AuthorizationDecision {
                allowed: false,
                reason: "no entitlements found for user".to_string(),
                source: DecisionSource::DefaultDeny,
                policy_id: None,
                decision_id,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Step 4: Load mappings and check against entitlements
        let mappings = match self
            .mapping_cache
            .get_mappings(pool, request.tenant_id)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(
                    target: "authorization",
                    error = %e,
                    tenant_id = %request.tenant_id,
                    "Failed to load mappings"
                );
                return AuthorizationDecision {
                    allowed: false,
                    reason: "internal error: failed to load mappings".to_string(),
                    source: DecisionSource::DefaultDeny,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
        };

        // Check if any entitlement has a mapping matching the requested action + resource_type
        let entitlement_ids: HashSet<Uuid> =
            entitlements.iter().map(|e| e.entitlement_id).collect();

        for mapping in mappings.iter() {
            if !entitlement_ids.contains(&mapping.entitlement_id) {
                continue;
            }

            let action_matches = mapping.action == "*" || mapping.action == request.action;
            let resource_matches =
                mapping.resource_type == "*" || mapping.resource_type == request.resource_type;

            if action_matches && resource_matches {
                return AuthorizationDecision {
                    allowed: true,
                    reason: format!(
                        "entitlement mapping: {} -> {} on {}",
                        mapping.entitlement_id, mapping.action, mapping.resource_type
                    ),
                    source: DecisionSource::Entitlement,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
        }

        // Step 5: Default deny
        AuthorizationDecision {
            allowed: false,
            reason: "no matching entitlement mapping".to_string(),
            source: DecisionSource::DefaultDeny,
            policy_id: None,
            decision_id,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// Invalidate the policy cache for a tenant.
    pub async fn invalidate_policies(&self, tenant_id: Uuid) {
        self.policy_cache.invalidate(tenant_id).await;
    }

    /// Invalidate the mapping cache for a tenant.
    pub async fn invalidate_mappings(&self, tenant_id: Uuid) {
        self.mapping_cache.invalidate(tenant_id).await;
    }

    /// Invalidate all caches for a tenant.
    pub async fn invalidate_all(&self, tenant_id: Uuid) {
        self.policy_cache.invalidate(tenant_id).await;
        self.mapping_cache.invalidate(tenant_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pdp_construction() {
        let policy_cache = Arc::new(PolicyCache::new());
        let mapping_cache = Arc::new(MappingCache::new());
        let pdp = PolicyDecisionPoint::new(Arc::clone(&policy_cache), Arc::clone(&mapping_cache));

        // Test invalidation methods don't panic
        let tenant_id = Uuid::new_v4();
        pdp.invalidate_policies(tenant_id).await;
        pdp.invalidate_mappings(tenant_id).await;
        pdp.invalidate_all(tenant_id).await;
    }

    #[test]
    fn test_authorization_request_construction() {
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "document".to_string(),
            resource_id: Some("doc-123".to_string()),
        };

        assert_eq!(req.action, "read");
        assert_eq!(req.resource_type, "document");
        assert_eq!(req.resource_id, Some("doc-123".to_string()));
    }

    #[test]
    fn test_decision_defaults() {
        let decision = AuthorizationDecision {
            allowed: false,
            reason: "default deny".to_string(),
            source: DecisionSource::DefaultDeny,
            policy_id: None,
            decision_id: Uuid::new_v4(),
            latency_ms: 0.5,
        };

        assert!(!decision.allowed);
        assert_eq!(decision.source, DecisionSource::DefaultDeny);
        assert!(decision.policy_id.is_none());
    }

    #[test]
    fn test_decision_serialization() {
        let decision = AuthorizationDecision {
            allowed: true,
            reason: "allowed by policy".to_string(),
            source: DecisionSource::Policy,
            policy_id: Some(Uuid::new_v4()),
            decision_id: Uuid::new_v4(),
            latency_ms: 2.3,
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(json.contains("\"source\":\"policy\""));
        assert!(json.contains("allowed by policy"));
    }
}
