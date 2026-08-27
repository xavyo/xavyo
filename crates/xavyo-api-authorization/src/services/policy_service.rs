//! Policy service for authorization policy CRUD (F083).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_authorization::PolicyCache;
use xavyo_db::models::policy_condition::CreatePolicyCondition;
use xavyo_db::models::{
    AuthorizationPolicy, CreateAuthorizationPolicy, PolicyConditionRecord,
    UpdateAuthorizationPolicy,
};

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::policy::{
    CreatePolicyRequest, ListPoliciesQuery, PolicyListResponse, PolicyResponse, UpdatePolicyRequest,
};

/// Service for managing authorization policies.
pub struct PolicyService {
    pool: PgPool,
    policy_cache: std::sync::Arc<PolicyCache>,
}

impl PolicyService {
    /// Create a new policy service.
    #[must_use]
    pub fn new(pool: PgPool, policy_cache: std::sync::Arc<PolicyCache>) -> Self {
        Self { pool, policy_cache }
    }

    /// Create a new authorization policy with optional conditions.
    pub async fn create_policy(
        &self,
        tenant_id: Uuid,
        input: CreatePolicyRequest,
        created_by: Uuid,
    ) -> ApiResult<PolicyResponse> {
        // Validate input
        if input.name.trim().is_empty() {
            return Err(ApiAuthorizationError::Validation(
                "Policy name cannot be empty".to_string(),
            ));
        }
        if input.name.len() > 255 {
            return Err(ApiAuthorizationError::Validation(
                "Policy name cannot exceed 255 characters".to_string(),
            ));
        }
        if input.effect != "allow" && input.effect != "deny" {
            return Err(ApiAuthorizationError::Validation(
                "Effect must be 'allow' or 'deny'".to_string(),
            ));
        }

        let priority = input.priority.unwrap_or(100);

        // Insert the policy
        let create_input = CreateAuthorizationPolicy {
            name: input.name.clone(),
            description: input.description.clone(),
            effect: input.effect.clone(),
            priority,
            resource_type: input.resource_type.clone(),
            action: input.action.clone(),
            created_by: Some(created_by),
        };

        let policy = AuthorizationPolicy::create(&self.pool, tenant_id, create_input)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(ref db_err) = e {
                    if db_err.constraint().is_some() {
                        return ApiAuthorizationError::Conflict(format!(
                            "A policy named '{}' already exists",
                            input.name
                        ));
                    }
                }
                ApiAuthorizationError::Database(e)
            })?;

        // Insert conditions if any
        let mut conditions = Vec::new();
        if let Some(condition_inputs) = input.conditions {
            for cond_input in condition_inputs {
                // Validate condition type
                match cond_input.condition_type.as_str() {
                    "time_window" | "user_attribute" | "entitlement_check" => {}
                    other => {
                        return Err(ApiAuthorizationError::Validation(format!(
                            "Invalid condition type: '{other}'. Must be 'time_window', 'user_attribute', or 'entitlement_check'"
                        )));
                    }
                }

                let create_cond = CreatePolicyCondition {
                    condition_type: cond_input.condition_type,
                    attribute_path: cond_input.attribute_path,
                    operator: cond_input.operator,
                    value: cond_input.value,
                };

                let condition =
                    PolicyConditionRecord::create(&self.pool, tenant_id, policy.id, create_cond)
                        .await?;
                conditions.push(condition);
            }
        }

        // Invalidate cache
        self.policy_cache.invalidate(tenant_id).await;

        Ok(PolicyResponse::from_policy_and_conditions(
            policy, conditions,
        ))
    }

    /// List policies with optional filters and pagination.
    pub async fn list_policies(
        &self,
        tenant_id: Uuid,
        query: ListPoliciesQuery,
    ) -> ApiResult<PolicyListResponse> {
        let limit = query.limit.min(100);
        let offset = query.offset;
        let status = parse_optional_policy_status(query.status.as_deref())?;
        let effect = parse_optional_policy_effect(query.effect.as_deref())?;

        let policies = AuthorizationPolicy::list_filtered(
            &self.pool, tenant_id, status, effect, limit, offset,
        )
        .await?;

        let total =
            AuthorizationPolicy::count_filtered(&self.pool, tenant_id, status, effect).await?;

        // Load conditions for each policy
        let mut items = Vec::with_capacity(policies.len());
        for policy in policies {
            let conditions =
                PolicyConditionRecord::find_by_policy_id(&self.pool, tenant_id, policy.id).await?;
            items.push(PolicyResponse::from_policy_and_conditions(
                policy, conditions,
            ));
        }

        Ok(PolicyListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a single policy by ID, including its conditions.
    pub async fn get_policy(&self, tenant_id: Uuid, id: Uuid) -> ApiResult<PolicyResponse> {
        let policy = AuthorizationPolicy::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or_else(|| ApiAuthorizationError::NotFound(format!("Policy not found: {id}")))?;

        let conditions =
            PolicyConditionRecord::find_by_policy_id(&self.pool, tenant_id, id).await?;

        Ok(PolicyResponse::from_policy_and_conditions(
            policy, conditions,
        ))
    }

    /// Update an existing policy.
    pub async fn update_policy(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePolicyRequest,
    ) -> ApiResult<PolicyResponse> {
        // Validate provided fields
        if let Some(ref name) = input.name {
            if name.trim().is_empty() {
                return Err(ApiAuthorizationError::Validation(
                    "Policy name cannot be empty".to_string(),
                ));
            }
        }
        if let Some(ref effect) = input.effect {
            if effect != "allow" && effect != "deny" {
                return Err(ApiAuthorizationError::Validation(
                    "Effect must be 'allow' or 'deny'".to_string(),
                ));
            }
        }
        if let Some(ref status) = input.status {
            if status != "active" && status != "inactive" {
                return Err(ApiAuthorizationError::Validation(
                    "Status must be 'active' or 'inactive'".to_string(),
                ));
            }
        }

        let update_input = UpdateAuthorizationPolicy {
            name: input.name,
            description: input.description,
            effect: input.effect,
            priority: input.priority,
            status: input.status,
            resource_type: input.resource_type,
            action: input.action,
        };

        let updated = AuthorizationPolicy::update(&self.pool, tenant_id, id, update_input)
            .await?
            .ok_or_else(|| ApiAuthorizationError::NotFound(format!("Policy not found: {id}")))?;

        let conditions =
            PolicyConditionRecord::find_by_policy_id(&self.pool, tenant_id, id).await?;

        // Invalidate cache
        self.policy_cache.invalidate(tenant_id).await;

        Ok(PolicyResponse::from_policy_and_conditions(
            updated, conditions,
        ))
    }

    /// Deactivate a policy by setting its status to "inactive".
    pub async fn deactivate_policy(&self, tenant_id: Uuid, id: Uuid) -> ApiResult<PolicyResponse> {
        let update_input = UpdateAuthorizationPolicy {
            name: None,
            description: None,
            effect: None,
            priority: None,
            status: Some("inactive".to_string()),
            resource_type: None,
            action: None,
        };

        let deactivated = AuthorizationPolicy::update(&self.pool, tenant_id, id, update_input)
            .await?
            .ok_or_else(|| ApiAuthorizationError::NotFound(format!("Policy not found: {id}")))?;

        let conditions =
            PolicyConditionRecord::find_by_policy_id(&self.pool, tenant_id, id).await?;

        // Invalidate cache
        self.policy_cache.invalidate(tenant_id).await;

        Ok(PolicyResponse::from_policy_and_conditions(
            deactivated,
            conditions,
        ))
    }
}

/// Advertised `status` query must 400 on unknown values, not list everything.
pub(crate) fn parse_optional_policy_status(status: Option<&str>) -> ApiResult<Option<&str>> {
    match status {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "active" | "inactive") => Ok(Some(s)),
        Some(s) => Err(ApiAuthorizationError::Validation(format!(
            "Invalid policy status '{s}'. Must be one of: active, inactive"
        ))),
    }
}

/// Advertised `effect` query must 400 on unknown values, not list everything.
pub(crate) fn parse_optional_policy_effect(effect: Option<&str>) -> ApiResult<Option<&str>> {
    match effect {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "allow" | "deny") => Ok(Some(s)),
        Some(s) => Err(ApiAuthorizationError::Validation(format!(
            "Invalid policy effect '{s}'. Must be one of: allow, deny"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_list_filters_do_not_fail_open() {
        assert_eq!(parse_optional_policy_status(None).unwrap(), None);
        assert_eq!(
            parse_optional_policy_status(Some("active")).unwrap(),
            Some("active")
        );
        assert!(parse_optional_policy_status(Some("bogus")).is_err());
        assert_eq!(parse_optional_policy_effect(None).unwrap(), None);
        assert_eq!(
            parse_optional_policy_effect(Some("deny")).unwrap(),
            Some("deny")
        );
        assert!(parse_optional_policy_effect(Some("permit")).is_err());

        let src = include_str!("policy_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_policy_status(")
                && production.contains("parse_optional_policy_effect(")
                && production.contains("list_filtered(")
                && production.contains("count_filtered("),
            "list_policies must honor and validate advertised status/effect filters"
        );
    }
}
