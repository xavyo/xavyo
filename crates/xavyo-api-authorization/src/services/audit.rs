//! Authorization audit trail (F083).
//!
//! Emits structured tracing events for all authorization decisions
//! for SIEM integration.

use xavyo_authorization::{AuthorizationDecision, AuthorizationRequest};

/// Authorization audit trail.
pub struct AuthorizationAudit;

impl AuthorizationAudit {
    /// Emit a structured log entry for an authorization decision.
    ///
    /// Respects verbosity settings:
    /// - "all": log all decisions
    /// - "deny_only": only log denied decisions
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xavyo_authorization::DecisionSource;

    #[test]
    fn test_emit_decision_all_verbosity() {
        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "report".to_string(),
            resource_id: None,
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
        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "report".to_string(),
            resource_id: None,
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
        let request = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "delete".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some("user-123".to_string()),
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
}
