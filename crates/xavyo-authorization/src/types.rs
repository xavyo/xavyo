//! Core types for the authorization engine.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AuthorizationRequest
// ---------------------------------------------------------------------------

/// An authorization check request: "Can subject X perform action Y on resource Z?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The user (subject) requesting access.
    pub subject_id: Uuid,

    /// The tenant scope for this request.
    pub tenant_id: Uuid,

    /// The action being requested (e.g., "read", "write", "delete").
    pub action: String,

    /// The type of resource being accessed (e.g., "document", "project").
    pub resource_type: String,

    /// Optional specific resource instance ID.
    pub resource_id: Option<String>,
}

// ---------------------------------------------------------------------------
// AuthorizationDecision
// ---------------------------------------------------------------------------

/// The result of an authorization evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Whether the action is allowed.
    pub allowed: bool,

    /// Human-readable reason for the decision.
    pub reason: String,

    /// Where the decision came from.
    pub source: DecisionSource,

    /// The ID of the policy that made the decision (if applicable).
    pub policy_id: Option<Uuid>,

    /// Unique identifier for this decision (for audit trail).
    pub decision_id: Uuid,

    /// Time taken to evaluate, in milliseconds.
    pub latency_ms: f64,
}

// ---------------------------------------------------------------------------
// PolicyEffect
// ---------------------------------------------------------------------------

/// The effect a policy has when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    /// Grant access.
    Allow,
    /// Deny access.
    Deny,
}

impl PolicyEffect {
    /// Parse from a string value (case-insensitive).
    #[must_use] 
    pub fn from_effect_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => PolicyEffect::Allow,
            _ => PolicyEffect::Deny,
        }
    }
}

impl fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyEffect::Allow => write!(f, "allow"),
            PolicyEffect::Deny => write!(f, "deny"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionSource
// ---------------------------------------------------------------------------

/// Where an authorization decision originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    /// Decision came from a policy evaluation.
    Policy,
    /// Decision came from an entitlement-to-action mapping.
    Entitlement,
    /// No policy or entitlement matched; default deny.
    DefaultDeny,
}

impl fmt::Display for DecisionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecisionSource::Policy => write!(f, "policy"),
            DecisionSource::Entitlement => write!(f, "entitlement"),
            DecisionSource::DefaultDeny => write!(f, "default_deny"),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyWithConditions
// ---------------------------------------------------------------------------

/// A policy together with its conditions, ready for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyWithConditions {
    /// Policy ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Policy name.
    pub name: String,

    /// Effect: "allow" or "deny".
    pub effect: String,

    /// Priority (lower = higher precedence).
    pub priority: i32,

    /// Status: "active" or "inactive".
    pub status: String,

    /// Optional resource type filter (None = wildcard).
    pub resource_type: Option<String>,

    /// Optional action filter (None = wildcard).
    pub action: Option<String>,

    /// Conditions attached to this policy (AND-combined).
    pub conditions: Vec<ConditionData>,
}

// ---------------------------------------------------------------------------
// ConditionData
// ---------------------------------------------------------------------------

/// Data for a single policy condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionData {
    /// Condition ID.
    pub id: Uuid,

    /// Condition type: "`time_window`", "`user_attribute`", "`entitlement_check`".
    pub condition_type: String,

    /// Attribute path for `user_attribute` conditions.
    pub attribute_path: Option<String>,

    /// Comparison operator for `user_attribute` conditions.
    pub operator: Option<String>,

    /// Condition value (JSON).
    pub value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// ResolvedEntitlement
// ---------------------------------------------------------------------------

/// An entitlement that has been resolved for a user, with its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedEntitlement {
    /// The entitlement ID.
    pub entitlement_id: Uuid,

    /// How this entitlement was obtained.
    pub source: EntitlementSource,
}

// ---------------------------------------------------------------------------
// EntitlementSource
// ---------------------------------------------------------------------------

/// How an entitlement was resolved for a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntitlementSource {
    /// Directly assigned to the user.
    Direct,
    /// Inherited through group membership.
    Group {
        /// The group that grants this entitlement.
        group_id: Uuid,
    },
    /// Inherited through a role assignment.
    Role {
        /// The role name that grants this entitlement.
        role_name: String,
    },
}

// ---------------------------------------------------------------------------
// ComparisonOperator
// ---------------------------------------------------------------------------

/// Supported comparison operators for ABAC conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    Contains,
    InList,
    GreaterThan,
    LessThan,
}

impl FromStr for ComparisonOperator {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "equals" => Ok(ComparisonOperator::Equals),
            "not_equals" => Ok(ComparisonOperator::NotEquals),
            "contains" => Ok(ComparisonOperator::Contains),
            "in_list" => Ok(ComparisonOperator::InList),
            "greater_than" => Ok(ComparisonOperator::GreaterThan),
            "less_than" => Ok(ComparisonOperator::LessThan),
            other => Err(format!("Unknown comparison operator: {other}")),
        }
    }
}

impl fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComparisonOperator::Equals => write!(f, "equals"),
            ComparisonOperator::NotEquals => write!(f, "not_equals"),
            ComparisonOperator::Contains => write!(f, "contains"),
            ComparisonOperator::InList => write!(f, "in_list"),
            ComparisonOperator::GreaterThan => write!(f, "greater_than"),
            ComparisonOperator::LessThan => write!(f, "less_than"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_effect_from_str() {
        assert_eq!(PolicyEffect::from_effect_str("allow"), PolicyEffect::Allow);
        assert_eq!(PolicyEffect::from_effect_str("Allow"), PolicyEffect::Allow);
        assert_eq!(PolicyEffect::from_effect_str("ALLOW"), PolicyEffect::Allow);
        assert_eq!(PolicyEffect::from_effect_str("deny"), PolicyEffect::Deny);
        assert_eq!(PolicyEffect::from_effect_str("Deny"), PolicyEffect::Deny);
        // Unknown defaults to Deny (fail-safe)
        assert_eq!(PolicyEffect::from_effect_str("unknown"), PolicyEffect::Deny);
    }

    #[test]
    fn test_policy_effect_display() {
        assert_eq!(PolicyEffect::Allow.to_string(), "allow");
        assert_eq!(PolicyEffect::Deny.to_string(), "deny");
    }

    #[test]
    fn test_decision_source_display() {
        assert_eq!(DecisionSource::Policy.to_string(), "policy");
        assert_eq!(DecisionSource::Entitlement.to_string(), "entitlement");
        assert_eq!(DecisionSource::DefaultDeny.to_string(), "default_deny");
    }

    #[test]
    fn test_comparison_operator_from_str() {
        assert_eq!(
            ComparisonOperator::from_str("equals").unwrap(),
            ComparisonOperator::Equals
        );
        assert_eq!(
            ComparisonOperator::from_str("not_equals").unwrap(),
            ComparisonOperator::NotEquals
        );
        assert_eq!(
            ComparisonOperator::from_str("contains").unwrap(),
            ComparisonOperator::Contains
        );
        assert_eq!(
            ComparisonOperator::from_str("in_list").unwrap(),
            ComparisonOperator::InList
        );
        assert_eq!(
            ComparisonOperator::from_str("greater_than").unwrap(),
            ComparisonOperator::GreaterThan
        );
        assert_eq!(
            ComparisonOperator::from_str("less_than").unwrap(),
            ComparisonOperator::LessThan
        );
        assert!(ComparisonOperator::from_str("invalid").is_err());
    }

    #[test]
    fn test_comparison_operator_roundtrip() {
        let ops = [
            ComparisonOperator::Equals,
            ComparisonOperator::NotEquals,
            ComparisonOperator::Contains,
            ComparisonOperator::InList,
            ComparisonOperator::GreaterThan,
            ComparisonOperator::LessThan,
        ];
        for op in ops {
            let s = op.to_string();
            let parsed = ComparisonOperator::from_str(&s).unwrap();
            assert_eq!(op, parsed);
        }
    }

    #[test]
    fn test_authorization_request_serialization() {
        let req = AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_type: "document".to_string(),
            resource_id: Some("doc-123".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("read"));
        assert!(json.contains("document"));
        assert!(json.contains("doc-123"));
    }

    #[test]
    fn test_authorization_decision_serialization() {
        let decision = AuthorizationDecision {
            allowed: true,
            reason: "allowed by policy".to_string(),
            source: DecisionSource::Policy,
            policy_id: Some(Uuid::new_v4()),
            decision_id: Uuid::new_v4(),
            latency_ms: 1.5,
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("policy"));
    }

    #[test]
    fn test_entitlement_source_serialization() {
        let direct = EntitlementSource::Direct;
        let json = serde_json::to_string(&direct).unwrap();
        assert!(json.contains("direct"));

        let group = EntitlementSource::Group {
            group_id: Uuid::new_v4(),
        };
        let json = serde_json::to_string(&group).unwrap();
        assert!(json.contains("group"));

        let role = EntitlementSource::Role {
            role_name: "admin".to_string(),
        };
        let json = serde_json::to_string(&role).unwrap();
        assert!(json.contains("admin"));
    }

    #[test]
    fn test_resolved_entitlement() {
        let ent = ResolvedEntitlement {
            entitlement_id: Uuid::new_v4(),
            source: EntitlementSource::Direct,
        };
        assert_eq!(ent.source, EntitlementSource::Direct);
    }
}
