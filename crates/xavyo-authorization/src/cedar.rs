//! Cedar policy engine integration.
//!
//! Provides fine-grained authorization using the Cedar policy language.
//! Cedar policies are evaluated per tool call:
//! `permit(agent, action, resource) when { user.roles.contains("sales") }`
//!
//! This module wraps the `cedar-policy` crate and converts xavyo authorization
//! requests into Cedar evaluation requests.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    Schema, ValidationMode,
};
use uuid::Uuid;

use crate::error::{AuthorizationError, Result};
use crate::types::{AuthorizationDecision, AuthorizationRequest, DecisionSource};

/// The Cedar namespace for xavyo entities.
const NAMESPACE: &str = "Xavyo";

/// Cedar policy engine — evaluates Cedar policies against authorization requests.
///
/// Thread-safe and cheaply cloneable (policies and schema are `Arc`-wrapped).
#[derive(Clone)]
pub struct CedarPolicyEngine {
    policy_set: Arc<PolicySet>,
    schema: Option<Arc<Schema>>,
}

impl CedarPolicyEngine {
    /// Create a new Cedar policy engine from policy text.
    ///
    /// Policies should be in Cedar syntax. If a schema is provided,
    /// policies are validated against it.
    pub fn new(policy_text: &str, schema_text: Option<&str>) -> Result<Self> {
        let schema = if let Some(schema_src) = schema_text {
            let (schema, warnings) = Schema::from_cedarschema_str(schema_src)
                .map_err(|e| AuthorizationError::CedarError(format!("invalid schema: {e}")))?;
            for w in warnings {
                tracing::warn!(target: "cedar", warning = %w, "Cedar schema warning");
            }
            Some(Arc::new(schema))
        } else {
            None
        };

        let policy_set = policy_text
            .parse::<PolicySet>()
            .map_err(|e| AuthorizationError::CedarError(format!("invalid policy: {e}")))?;

        // Validate policies against schema if present
        if let Some(ref s) = schema {
            let validation_result = cedar_policy::Validator::new((**s).clone())
                .validate(&policy_set, ValidationMode::default());
            if !validation_result.validation_passed() {
                let errors: Vec<String> = validation_result
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect();
                return Err(AuthorizationError::CedarError(format!(
                    "policy validation failed: {}",
                    errors.join("; ")
                )));
            }
        }

        Ok(Self {
            policy_set: Arc::new(policy_set),
            schema,
        })
    }

    /// Create a Cedar policy engine from multiple policy texts.
    ///
    /// Each policy text is parsed separately, then merged into a single `PolicySet`.
    pub fn from_policies(policy_texts: &[&str], schema_text: Option<&str>) -> Result<Self> {
        let combined = policy_texts.join("\n\n");
        Self::new(&combined, schema_text)
    }

    /// Evaluate an authorization request against the Cedar policies.
    ///
    /// Converts the xavyo `AuthorizationRequest` into Cedar entities and
    /// evaluates the policy set. Returns an `AuthorizationDecision`.
    ///
    /// # Arguments
    ///
    /// * `request` - The authorization request to evaluate
    /// * `user_roles` - The user's role names (added as parent entities)
    /// * `user_attributes` - Optional user attributes (added to Cedar context)
    /// * `extra_context` - Additional context key-value pairs for Cedar evaluation
    pub fn evaluate(
        &self,
        request: &AuthorizationRequest,
        user_roles: &[String],
        user_attributes: Option<&serde_json::Value>,
        extra_context: Option<&HashMap<String, serde_json::Value>>,
    ) -> AuthorizationDecision {
        let start = std::time::Instant::now();
        let decision_id = Uuid::new_v4();

        // Build Cedar entities
        let entities = match self.build_entities(request, user_roles) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(target: "cedar", error = %e, "Failed to build Cedar entities");
                return AuthorizationDecision {
                    allowed: false,
                    reason: format!("cedar entity construction failed: {e}"),
                    source: DecisionSource::Cedar,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
        };

        // Build Cedar request
        let cedar_request = match self.build_request(request, user_attributes, extra_context) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(target: "cedar", error = %e, "Failed to build Cedar request");
                return AuthorizationDecision {
                    allowed: false,
                    reason: format!("cedar request construction failed: {e}"),
                    source: DecisionSource::Cedar,
                    policy_id: None,
                    decision_id,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
        };

        // Evaluate
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&cedar_request, &self.policy_set, &entities);

        let allowed = matches!(response.decision(), cedar_policy::Decision::Allow);

        // Collect diagnostics
        let reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|p| p.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        if !errors.is_empty() {
            tracing::warn!(
                target: "cedar",
                errors = ?errors,
                "Cedar evaluation produced errors"
            );
        }

        let reason = if !reasons.is_empty() {
            format!(
                "{} by cedar polic{}: {}",
                if allowed { "allowed" } else { "denied" },
                if reasons.len() == 1 { "y" } else { "ies" },
                reasons.join(", ")
            )
        } else if allowed {
            "allowed by cedar (no specific policy ID)".to_string()
        } else {
            "denied by cedar (no matching allow policy)".to_string()
        };

        AuthorizationDecision {
            allowed,
            reason,
            source: DecisionSource::Cedar,
            policy_id: None,
            decision_id,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// Build Cedar entities from the authorization request.
    fn build_entities(
        &self,
        request: &AuthorizationRequest,
        user_roles: &[String],
    ) -> Result<Entities> {
        let mut entities_vec = Vec::new();

        // Build role entities
        let mut role_uids = HashSet::new();
        for role in user_roles {
            let role_uid = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str(&format!("{NAMESPACE}::Role"))
                    .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
                EntityId::new(role),
            );
            let role_entity = Entity::new_no_attrs(role_uid.clone(), HashSet::new());
            entities_vec.push(role_entity);
            role_uids.insert(role_uid);
        }

        // Build principal (User) entity with role parents
        let principal_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::User"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(request.subject_id.to_string()),
        );
        let principal_entity = Entity::new_no_attrs(principal_uid, role_uids);
        entities_vec.push(principal_entity);

        // Build resource entity
        let resource_id = request.resource_id.as_deref().unwrap_or("*");
        let resource_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::Resource"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(resource_id),
        );
        let resource_entity = Entity::new_no_attrs(resource_uid, HashSet::new());
        entities_vec.push(resource_entity);

        // Build action entity
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::Action"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(&request.action),
        );
        let action_entity = Entity::new_no_attrs(action_uid, HashSet::new());
        entities_vec.push(action_entity);

        // Build delegation actor entity if present
        if let Some(ref delegation) = request.delegation {
            let actor_uid = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str(&format!("{NAMESPACE}::Agent"))
                    .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
                EntityId::new(delegation.actor_nhi_id.to_string()),
            );
            let actor_entity = Entity::new_no_attrs(actor_uid, HashSet::new());
            entities_vec.push(actor_entity);
        }

        Entities::from_entities(entities_vec, self.schema.as_deref())
            .map_err(|e| AuthorizationError::CedarError(format!("entity construction: {e}")))
    }

    /// Build a Cedar `Request` from the authorization request.
    fn build_request(
        &self,
        request: &AuthorizationRequest,
        user_attributes: Option<&serde_json::Value>,
        extra_context: Option<&HashMap<String, serde_json::Value>>,
    ) -> Result<Request> {
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::User"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(request.subject_id.to_string()),
        );

        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::Action"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(&request.action),
        );

        let resource_id = request.resource_id.as_deref().unwrap_or("*");
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&format!("{NAMESPACE}::Resource"))
                .map_err(|e| AuthorizationError::CedarError(e.to_string()))?,
            EntityId::new(resource_id),
        );

        // Build context
        let mut ctx_map = serde_json::Map::new();
        ctx_map.insert(
            "tenant_id".to_string(),
            serde_json::Value::String(request.tenant_id.to_string()),
        );
        ctx_map.insert(
            "resource_type".to_string(),
            serde_json::Value::String(request.resource_type.clone()),
        );

        if let Some(ref delegation) = request.delegation {
            ctx_map.insert("is_delegated".to_string(), serde_json::Value::Bool(true));
            ctx_map.insert(
                "actor_nhi_id".to_string(),
                serde_json::Value::String(delegation.actor_nhi_id.to_string()),
            );
            ctx_map.insert(
                "delegation_depth".to_string(),
                serde_json::Value::Number(delegation.depth.into()),
            );
        } else {
            ctx_map.insert("is_delegated".to_string(), serde_json::Value::Bool(false));
        }

        if let Some(attrs) = user_attributes {
            if let Some(obj) = attrs.as_object() {
                for (k, v) in obj {
                    ctx_map.insert(format!("user_{k}"), v.clone());
                }
            }
        }

        if let Some(extra) = extra_context {
            for (k, v) in extra {
                ctx_map.insert(k.clone(), v.clone());
            }
        }

        let context = Context::from_json_value(serde_json::Value::Object(ctx_map), None)
            .map_err(|e| AuthorizationError::CedarError(format!("context construction: {e}")))?;

        Request::new(principal, action, resource, context, self.schema.as_deref())
            .map_err(|e| AuthorizationError::CedarError(format!("request construction: {e}")))
    }

    /// Returns the number of policies in the engine.
    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policy_set.policies().count()
    }

    /// Validate a Cedar policy text without creating an engine.
    ///
    /// Returns `Ok(())` if the policy text is syntactically valid,
    /// or an error describing the parse failure.
    pub fn validate_policy(policy_text: &str) -> Result<()> {
        policy_text
            .parse::<PolicySet>()
            .map_err(|e| AuthorizationError::CedarError(format!("invalid policy: {e}")))?;
        Ok(())
    }

    /// Validate a Cedar policy text against a schema.
    ///
    /// Returns `Ok(())` if the policy is both syntactically and semantically valid.
    pub fn validate_policy_with_schema(policy_text: &str, schema_text: &str) -> Result<()> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_text)
            .map_err(|e| AuthorizationError::CedarError(format!("invalid schema: {e}")))?;

        let policy_set = policy_text
            .parse::<PolicySet>()
            .map_err(|e| AuthorizationError::CedarError(format!("invalid policy: {e}")))?;

        let validation_result =
            cedar_policy::Validator::new(schema).validate(&policy_set, ValidationMode::default());
        if !validation_result.validation_passed() {
            let errors: Vec<String> = validation_result
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(AuthorizationError::CedarError(format!(
                "validation failed: {}",
                errors.join("; ")
            )));
        }

        Ok(())
    }
}

impl std::fmt::Debug for CedarPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarPolicyEngine")
            .field("policy_count", &self.policy_count())
            .field("has_schema", &self.schema.is_some())
            .finish()
    }
}

/// The default xavyo Cedar schema for agent authorization.
///
/// This schema defines the entity types and actions used by the xavyo
/// authorization engine. Policies written against this schema can
/// reference users, roles, agents, resources, and actions.
pub const XAVYO_CEDAR_SCHEMA: &str = r#"
namespace Xavyo {
    entity Role;

    entity User in [Role];

    entity Agent;

    entity Resource;

    entity Action;

    action "read" appliesTo {
        principal: [User, Agent],
        resource: [Resource]
    };

    action "write" appliesTo {
        principal: [User, Agent],
        resource: [Resource]
    };

    action "delete" appliesTo {
        principal: [User, Agent],
        resource: [Resource]
    };

    action "execute" appliesTo {
        principal: [User, Agent],
        resource: [Resource]
    };

    action "admin" appliesTo {
        principal: [User, Agent],
        resource: [Resource]
    };
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(action: &str, resource_type: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            subject_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            delegation: None,
        }
    }

    #[test]
    fn test_cedar_engine_creation_valid_policy() {
        let policy = r#"
            permit(principal, action, resource);
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        assert_eq!(engine.policy_count(), 1);
    }

    #[test]
    fn test_cedar_engine_creation_invalid_policy() {
        let policy = "this is not valid cedar syntax {{{";
        let result = CedarPolicyEngine::new(policy, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthorizationError::CedarError(_)));
    }

    #[test]
    fn test_cedar_engine_multiple_policies() {
        let policies = &[
            r#"permit(principal, action, resource) when { context.resource_type == "document" };"#,
            r#"forbid(principal, action, resource) when { context.resource_type == "secret" };"#,
        ];
        let engine = CedarPolicyEngine::from_policies(policies, None).unwrap();
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn test_cedar_evaluate_permit_all() {
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        let decision = engine.evaluate(&request, &["viewer".to_string()], None, None);
        assert!(decision.allowed);
        assert_eq!(decision.source, DecisionSource::Cedar);
    }

    #[test]
    fn test_cedar_evaluate_deny_all() {
        // No permit policy = default deny in Cedar
        let policy = r#"forbid(principal, action, resource);"#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        let decision = engine.evaluate(&request, &["viewer".to_string()], None, None);
        assert!(!decision.allowed);
        assert_eq!(decision.source, DecisionSource::Cedar);
    }

    #[test]
    fn test_cedar_evaluate_context_condition() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.resource_type == "document" };
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();

        // Should allow for documents
        let req = make_request("read", "document");
        let decision = engine.evaluate(&req, &[], None, None);
        assert!(decision.allowed);

        // Should deny for secrets
        let req = make_request("read", "secret");
        let decision = engine.evaluate(&req, &[], None, None);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_evaluate_user_attribute_context() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.user_department == "engineering" };
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        // Engineering user — allowed
        let attrs = json!({"department": "engineering"});
        let decision = engine.evaluate(&request, &[], Some(&attrs), None);
        assert!(decision.allowed);

        // Marketing user — denied
        let attrs = json!({"department": "marketing"});
        let decision = engine.evaluate(&request, &[], Some(&attrs), None);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_evaluate_delegation_context() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.is_delegated == false };

            forbid(principal, action, resource)
            when { context.is_delegated == true && context.delegation_depth > 2 };
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();

        // Non-delegated request — allowed
        let request = make_request("read", "document");
        let decision = engine.evaluate(&request, &[], None, None);
        assert!(decision.allowed);

        // Delegated request with depth 1 — no matching permit (no explicit allow for delegated)
        let mut request = make_request("read", "document");
        request.delegation = Some(crate::types::DelegationContext {
            actor_nhi_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            allowed_scopes: vec![],
            allowed_resource_types: vec![],
            depth: 1,
        });
        let decision = engine.evaluate(&request, &[], None, None);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_evaluate_extra_context() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.tool_name == "crm_search" };
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("execute", "tool");

        // With matching tool_name
        let mut extra = HashMap::new();
        extra.insert(
            "tool_name".to_string(),
            serde_json::Value::String("crm_search".to_string()),
        );
        let decision = engine.evaluate(&request, &[], None, Some(&extra));
        assert!(decision.allowed);

        // With non-matching tool_name
        let mut extra = HashMap::new();
        extra.insert(
            "tool_name".to_string(),
            serde_json::Value::String("file_delete".to_string()),
        );
        let decision = engine.evaluate(&request, &[], None, Some(&extra));
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_validate_policy_valid() {
        let policy = "permit(principal, action, resource);";
        assert!(CedarPolicyEngine::validate_policy(policy).is_ok());
    }

    #[test]
    fn test_cedar_validate_policy_invalid() {
        let policy = "not valid cedar at all {{{}}}";
        assert!(CedarPolicyEngine::validate_policy(policy).is_err());
    }

    #[test]
    fn test_cedar_forbid_overrides_permit() {
        let policy = r#"
            permit(principal, action, resource);
            forbid(principal, action, resource)
            when { context.resource_type == "secret" };
        "#;
        let engine = CedarPolicyEngine::new(policy, None).unwrap();

        // Regular document — allowed (permit matches, no forbid)
        let req = make_request("read", "document");
        let decision = engine.evaluate(&req, &[], None, None);
        assert!(decision.allowed);

        // Secret — denied (forbid overrides permit)
        let req = make_request("read", "secret");
        let decision = engine.evaluate(&req, &[], None, None);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_engine_debug() {
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let debug = format!("{engine:?}");
        assert!(debug.contains("CedarPolicyEngine"));
        assert!(debug.contains("policy_count: 1"));
        assert!(debug.contains("has_schema: false"));
    }

    #[test]
    fn test_cedar_empty_policy_set_denies() {
        // Cedar default-deny: if no permit matches, deny
        let engine = CedarPolicyEngine::new("", None).unwrap();
        assert_eq!(engine.policy_count(), 0);

        let request = make_request("read", "document");
        let decision = engine.evaluate(&request, &[], None, None);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_cedar_decision_has_latency() {
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        let decision = engine.evaluate(&request, &[], None, None);
        assert!(decision.latency_ms >= 0.0);
    }

    #[test]
    fn test_cedar_decision_has_unique_id() {
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        let d1 = engine.evaluate(&request, &[], None, None);
        let d2 = engine.evaluate(&request, &[], None, None);
        assert_ne!(d1.decision_id, d2.decision_id);
    }

    #[test]
    fn test_cedar_resource_id_propagation() {
        // When resource_id is specified, it should be used as Cedar entity ID
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();

        let mut request = make_request("read", "document");
        request.resource_id = Some("doc-42".to_string());

        let decision = engine.evaluate(&request, &[], None, None);
        assert!(decision.allowed);
    }

    #[test]
    fn test_cedar_multiple_roles() {
        // User with multiple roles should have all role entities as parents
        let policy = "permit(principal, action, resource);";
        let engine = CedarPolicyEngine::new(policy, None).unwrap();
        let request = make_request("read", "document");

        let decision = engine.evaluate(
            &request,
            &[
                "admin".to_string(),
                "editor".to_string(),
                "viewer".to_string(),
            ],
            None,
            None,
        );
        assert!(decision.allowed);
    }
}
