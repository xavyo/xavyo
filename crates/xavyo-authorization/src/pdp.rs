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
use crate::types::{
    AuthorizationDecision, AuthorizationRequest, DecisionSource, DelegationContext, PolicyEffect,
};

/// The Policy Decision Point — evaluates "Can user X do action Y on resource Z?"
pub struct PolicyDecisionPoint {
    policy_cache: Arc<PolicyCache>,
    mapping_cache: Arc<MappingCache>,
    #[cfg(feature = "cedar")]
    cedar_engine: Option<Arc<crate::cedar::CedarPolicyEngine>>,
}

impl PolicyDecisionPoint {
    /// Create a new PDP with the given caches.
    #[must_use]
    pub fn new(policy_cache: Arc<PolicyCache>, mapping_cache: Arc<MappingCache>) -> Self {
        Self {
            policy_cache,
            mapping_cache,
            #[cfg(feature = "cedar")]
            cedar_engine: None,
        }
    }

    /// Set a Cedar policy engine for additional policy evaluation.
    ///
    /// When set, Cedar policies are evaluated after native policy evaluation.
    /// A Cedar deny always overrides. A Cedar allow supplements native authorization.
    #[cfg(feature = "cedar")]
    #[must_use]
    pub fn with_cedar(mut self, engine: Arc<crate::cedar::CedarPolicyEngine>) -> Self {
        self.cedar_engine = Some(engine);
        self
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

            // If the base policy allows, intersect with delegation scope.
            if allowed {
                if let Some(deny) = Self::check_delegation_scope(
                    request.delegation.as_ref(),
                    &request,
                    decision_id,
                    start,
                ) {
                    return deny;
                }
            }

            return AuthorizationDecision {
                allowed,
                reason: format!("{} by policy", if allowed { "allowed" } else { "denied" }),
                source: DecisionSource::Policy,
                policy_id: Some(policy_id),
                decision_id,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Step 2b: Cedar policy evaluation (if enabled)
        #[cfg(feature = "cedar")]
        if let Some(ref cedar) = self.cedar_engine {
            let cedar_decision = cedar.evaluate(&request, user_roles, user_attributes, None);
            if !cedar_decision.allowed {
                // Cedar deny overrides everything
                return AuthorizationDecision {
                    allowed: false,
                    reason: cedar_decision.reason,
                    source: DecisionSource::Cedar,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
            // Cedar allow — continue to entitlement checks for defense-in-depth,
            // but record that Cedar approved.
            tracing::debug!(
                target: "authorization",
                decision_id = %decision_id,
                "Cedar policy approved, continuing to entitlement checks"
            );
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
                // Intersect with delegation scope before allowing.
                if let Some(deny) = Self::check_delegation_scope(
                    request.delegation.as_ref(),
                    &request,
                    decision_id,
                    start,
                ) {
                    return deny;
                }

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

    /// Check delegation scope constraints against an allow decision.
    ///
    /// If delegation is `Some`, the action and resource_type must fall within
    /// the grant's `allowed_scopes` and `allowed_resource_types` respectively.
    /// An empty list means "all allowed" (no restriction).
    ///
    /// Scopes can be in three formats:
    /// - Simple action: `"read"` — matches `request.action`
    /// - Compound `action:resource_type`: `"read:tools"` — matches the combination
    /// - Wildcard action: `"read:*"` — matches any resource for that action
    ///
    /// Returns `None` if the delegation scope is satisfied (or no delegation),
    /// or `Some(AuthorizationDecision)` with a deny if the scope is exceeded.
    fn check_delegation_scope(
        delegation: Option<&DelegationContext>,
        request: &AuthorizationRequest,
        decision_id: Uuid,
        start: std::time::Instant,
    ) -> Option<AuthorizationDecision> {
        let delegation = delegation?; // No delegation context — allow stands.

        // Check allowed_scopes (empty = all allowed).
        if !delegation.allowed_scopes.is_empty() {
            let compound = format!("{}:{}", request.action, request.resource_type);
            let wildcard = format!("{}:*", request.action);
            let scope_matched = delegation.allowed_scopes.iter().any(|s| {
                // Match: exact action ("read"), compound ("read:tools"), or wildcard ("read:*")
                s == &request.action || s == &compound || s == &wildcard
            });
            if !scope_matched {
                return Some(AuthorizationDecision {
                    allowed: false,
                    reason: "delegation_scope_exceeded".to_string(),
                    source: DecisionSource::DefaultDeny,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                });
            }
        }

        // Check allowed_resource_types (empty = all allowed).
        if !delegation.allowed_resource_types.is_empty()
            && !delegation
                .allowed_resource_types
                .contains(&request.resource_type)
        {
            return Some(AuthorizationDecision {
                allowed: false,
                reason: "delegation_scope_exceeded".to_string(),
                source: DecisionSource::DefaultDeny,
                policy_id: None,
                decision_id,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            });
        }

        None // Delegation scope satisfied.
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
            delegation: None,
        };

        assert_eq!(req.action, "read");
        assert_eq!(req.resource_type, "document");
        assert_eq!(req.resource_id, Some("doc-123".to_string()));
        assert!(req.delegation.is_none());
    }

    #[test]
    fn test_delegation_scope_check_no_delegation() {
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "document".to_string(),
            resource_id: None,
            delegation: None,
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            None,
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(result.is_none()); // No delegation = allow stands
    }

    #[test]
    fn test_delegation_scope_check_allowed() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            allowed_resource_types: vec!["document".to_string()],
            depth: 0,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "document".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(result.is_none()); // Within scope = allow stands
    }

    #[test]
    fn test_delegation_scope_check_action_exceeded() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec!["read".to_string()],
            allowed_resource_types: vec![],
            depth: 0,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "delete".to_string(),
            resource_type: "document".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(result.is_some());
        let deny = result.unwrap();
        assert!(!deny.allowed);
        assert_eq!(deny.reason, "delegation_scope_exceeded");
    }

    #[test]
    fn test_delegation_scope_check_resource_type_exceeded() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec![],
            allowed_resource_types: vec!["document".to_string()],
            depth: 0,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "secret".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(result.is_some());
        let deny = result.unwrap();
        assert!(!deny.allowed);
        assert_eq!(deny.reason, "delegation_scope_exceeded");
    }

    #[test]
    fn test_delegation_scope_check_empty_lists_allow_all() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec![],
            allowed_resource_types: vec![],
            depth: 2,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "any_action".to_string(),
            resource_type: "any_resource".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(result.is_none()); // Empty lists = all allowed
    }

    #[test]
    fn test_delegation_scope_check_compound_scope_match() {
        use crate::types::DelegationContext;

        // OAuth2-style compound scopes "read:tools" should match action="read" + resource_type="tools"
        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec!["read:tools".to_string(), "write:documents".to_string()],
            allowed_resource_types: vec![],
            depth: 1,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "tools".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(
            result.is_none(),
            "compound scope 'read:tools' should match action=read + resource=tools"
        );
    }

    #[test]
    fn test_delegation_scope_check_compound_scope_denied() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec!["read:tools".to_string()],
            allowed_resource_types: vec![],
            depth: 1,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "write".to_string(),
            resource_type: "tools".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(
            result.is_some(),
            "scope 'read:tools' should not match action=write"
        );
    }

    #[test]
    fn test_delegation_scope_check_wildcard_action() {
        use crate::types::DelegationContext;

        let delegation = DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec!["read:*".to_string()],
            allowed_resource_types: vec![],
            depth: 1,
        };
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "anything".to_string(),
            resource_id: None,
            delegation: Some(delegation.clone()),
        };
        let result = PolicyDecisionPoint::check_delegation_scope(
            Some(&delegation),
            &req,
            Uuid::new_v4(),
            std::time::Instant::now(),
        );
        assert!(
            result.is_none(),
            "wildcard 'read:*' should match any resource for read action"
        );
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
