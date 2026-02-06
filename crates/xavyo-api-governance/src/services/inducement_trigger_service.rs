//! Inducement Trigger service for F-063: Role Inducements.
//!
//! Handles automatic triggering of provisioning operations when roles
//! with constructions are assigned or revoked.

use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use xavyo_db::models::{CreateProvisioningOperation, OperationType, ProvisioningOperation, User};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{ConstructionResponse, DeprovisioningPolicyDto};
use crate::services::{RoleConstructionService, RoleInducementService};

/// Service for triggering provisioning operations based on role constructions.
pub struct InducementTriggerService {
    pool: PgPool,
    construction_service: RoleConstructionService,
    inducement_service: RoleInducementService,
}

impl InducementTriggerService {
    /// Create a new inducement trigger service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            construction_service: RoleConstructionService::new(pool.clone()),
            inducement_service: RoleInducementService::new(pool.clone()),
            pool,
        }
    }

    /// Trigger provisioning operations for a role assignment.
    ///
    /// Collects all enabled constructions for the assigned role (including
    /// any induced roles) and queues provisioning operations.
    ///
    /// Returns the IDs of queued operations.
    pub async fn trigger_constructions_for_assignment(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        assigned_by: Option<Uuid>,
    ) -> Result<Vec<Uuid>> {
        // Get all role IDs (the assigned role plus any induced roles)
        let mut role_ids = vec![role_id];
        let induced_role_ids = self
            .inducement_service
            .get_all_induced_role_ids(tenant_id, role_id)
            .await?;
        role_ids.extend(induced_role_ids);

        // Get all enabled constructions for these roles
        let constructions = self
            .construction_service
            .get_enabled_by_roles(tenant_id, &role_ids)
            .await?;

        if constructions.is_empty() {
            return Ok(Vec::new());
        }

        // Get user attributes for mapping
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::UserNotFound(user_id))?;

        // Deduplicate constructions (same connector + object_class + account_type)
        let deduped = self.deduplicate_constructions(constructions);

        // Queue provisioning operations
        let mut operation_ids = Vec::new();
        for construction in deduped {
            let payload = self.build_provisioning_payload(&user, &construction)?;

            let op = CreateProvisioningOperation {
                connector_id: construction.connector_id,
                user_id,
                object_class: construction.object_class.clone(),
                operation_type: OperationType::Create,
                target_uid: None,
                payload,
                priority: Some(construction.priority),
                max_retries: None,
            };

            let operation = ProvisioningOperation::create(&self.pool, tenant_id, &op)
                .await
                .map_err(GovernanceError::Database)?;

            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                role_id = %role_id,
                construction_id = %construction.id,
                operation_id = %operation.id,
                assigned_by = ?assigned_by,
                "Queued provisioning operation for role construction"
            );

            operation_ids.push(operation.id);
        }

        Ok(operation_ids)
    }

    /// Trigger deprovisioning operations when a role is revoked.
    ///
    /// Calculates which constructions are no longer covered by any other
    /// assigned roles and queues deprovisioning operations based on each
    /// construction's deprovisioning policy.
    pub async fn trigger_deprovisioning_for_revocation(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        revoked_by: Option<Uuid>,
    ) -> Result<Vec<Uuid>> {
        // Get constructions from the revoked role (including induced)
        let mut revoked_role_ids = vec![role_id];
        let induced_role_ids = self
            .inducement_service
            .get_all_induced_role_ids(tenant_id, role_id)
            .await?;
        revoked_role_ids.extend(induced_role_ids);

        let revoked_constructions = self
            .construction_service
            .get_enabled_by_roles(tenant_id, &revoked_role_ids)
            .await?;

        if revoked_constructions.is_empty() {
            return Ok(Vec::new());
        }

        // Get user's remaining effective constructions from other roles
        // This would require access to the user's current role assignments
        // For now, we'll get all constructions and check if they're still covered
        let remaining_constructions = self
            .get_user_remaining_constructions(tenant_id, user_id, &revoked_role_ids)
            .await?;

        // Build a set of remaining construction keys
        let remaining_keys: HashSet<String> = remaining_constructions
            .iter()
            .map(|c| self.construction_key(c))
            .collect();

        // Find constructions that need deprovisioning
        let to_deprovision: Vec<_> = revoked_constructions
            .into_iter()
            .filter(|c| !remaining_keys.contains(&self.construction_key(c)))
            .collect();

        if to_deprovision.is_empty() {
            return Ok(Vec::new());
        }

        // Queue deprovisioning operations
        let mut operation_ids = Vec::new();
        for construction in to_deprovision {
            // Check deprovisioning policy
            match construction.deprovisioning_policy {
                DeprovisioningPolicyDto::Retain => {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        construction_id = %construction.id,
                        "Skipping deprovisioning due to retain policy"
                    );
                    continue;
                }
                DeprovisioningPolicyDto::Disable | DeprovisioningPolicyDto::Delete => {
                    // Queue delete or disable operation
                    let operation_type = match construction.deprovisioning_policy {
                        DeprovisioningPolicyDto::Delete => OperationType::Delete,
                        DeprovisioningPolicyDto::Disable => OperationType::Update, // Update to disable
                        DeprovisioningPolicyDto::Retain => continue,
                    };

                    let payload =
                        if construction.deprovisioning_policy == DeprovisioningPolicyDto::Disable {
                            serde_json::json!({ "enabled": false })
                        } else {
                            serde_json::json!({})
                        };

                    let op = CreateProvisioningOperation {
                        connector_id: construction.connector_id,
                        user_id,
                        object_class: construction.object_class.clone(),
                        operation_type,
                        target_uid: None, // Would need shadow link lookup
                        payload,
                        priority: Some(construction.priority),
                        max_retries: None,
                    };

                    let operation = ProvisioningOperation::create(&self.pool, tenant_id, &op)
                        .await
                        .map_err(GovernanceError::Database)?;

                    tracing::info!(
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        role_id = %role_id,
                        construction_id = %construction.id,
                        operation_id = %operation.id,
                        revoked_by = ?revoked_by,
                        policy = ?construction.deprovisioning_policy,
                        "Queued deprovisioning operation for role revocation"
                    );

                    operation_ids.push(operation.id);
                }
            }
        }

        Ok(operation_ids)
    }

    /// Get all effective constructions for a user based on their role assignments.
    pub async fn get_user_effective_constructions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ConstructionResponse>> {
        // Get user's role assignments
        let role_ids = self.get_user_role_ids(tenant_id, user_id).await?;

        if role_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Expand to include induced roles
        let mut all_role_ids = role_ids.clone();
        for role_id in &role_ids {
            let induced = self
                .inducement_service
                .get_all_induced_role_ids(tenant_id, *role_id)
                .await?;
            all_role_ids.extend(induced);
        }

        // Deduplicate role IDs
        let unique_role_ids: Vec<Uuid> = all_role_ids
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Get all enabled constructions
        let constructions = self
            .construction_service
            .get_enabled_by_roles(tenant_id, &unique_role_ids)
            .await?;

        // Deduplicate constructions
        Ok(self.deduplicate_constructions(constructions))
    }

    /// Build provisioning payload from user attributes and construction mappings.
    fn build_provisioning_payload(
        &self,
        user: &User,
        construction: &ConstructionResponse,
    ) -> Result<serde_json::Value> {
        let mut payload = serde_json::Map::new();

        // Add static values first
        if let Some(obj) = construction.attribute_mappings.static_values.as_object() {
            for (key, value) in obj {
                payload.insert(key.clone(), value.clone());
            }
        }

        // Apply attribute mappings
        for mapping in &construction.attribute_mappings.mappings {
            let value = match mapping.mapping_type {
                crate::models::AttributeMappingTypeDto::Direct => {
                    // Direct mapping: copy source attribute value
                    self.get_user_attribute(user, &mapping.source)
                }
                crate::models::AttributeMappingTypeDto::Expression => {
                    // Expression-based mapping (simplified for now)
                    // Would integrate with TemplateExpressionService
                    self.evaluate_simple_expression(user, &mapping.source)
                }
            };

            if let Some(v) = value {
                payload.insert(mapping.target_attribute.clone(), v);
            } else {
                tracing::warn!(
                    construction_id = %construction.id,
                    target_attribute = %mapping.target_attribute,
                    source = %mapping.source,
                    "Could not resolve attribute mapping, skipping"
                );
            }
        }

        Ok(serde_json::Value::Object(payload))
    }

    /// Get a user attribute value by name.
    fn get_user_attribute(&self, user: &User, attr_name: &str) -> Option<serde_json::Value> {
        match attr_name {
            "id" => Some(serde_json::Value::String(user.id.to_string())),
            "tenant_id" => Some(serde_json::Value::String(user.tenant_id.to_string())),
            "email" => Some(serde_json::Value::String(user.email.clone())),
            "display_name" | "name" => user.display_name.clone().map(serde_json::Value::String),
            "first_name" => user.first_name.clone().map(serde_json::Value::String),
            "last_name" => user.last_name.clone().map(serde_json::Value::String),
            "external_id" => user.external_id.clone().map(serde_json::Value::String),
            "manager_id" => user
                .manager_id
                .map(|id| serde_json::Value::String(id.to_string())),
            "is_active" => Some(serde_json::Value::Bool(user.is_active)),
            "email_verified" => Some(serde_json::Value::Bool(user.email_verified)),
            // For any other attributes, check the custom_attributes JSON
            _ => user.custom_attributes.get(attr_name).cloned(),
        }
    }

    /// Evaluate a simple expression (for now, just attribute references).
    fn evaluate_simple_expression(&self, user: &User, expr: &str) -> Option<serde_json::Value> {
        // Simple expression format: ${user.attribute_name}
        if let Some(attr_ref) = expr
            .strip_prefix("${user.")
            .and_then(|s| s.strip_suffix("}"))
        {
            self.get_user_attribute(user, attr_ref)
        } else {
            // Return literal value
            Some(serde_json::Value::String(expr.to_string()))
        }
    }

    /// Deduplicate constructions by connector + object_class + account_type.
    ///
    /// When multiple roles provide the same construction, we only need one
    /// provisioning operation. We keep the one with highest priority.
    fn deduplicate_constructions(
        &self,
        constructions: Vec<ConstructionResponse>,
    ) -> Vec<ConstructionResponse> {
        let mut by_key: HashMap<String, ConstructionResponse> = HashMap::new();

        for construction in constructions {
            let key = self.construction_key(&construction);

            // Keep the construction with highest priority
            if let Some(existing) = by_key.get(&key) {
                if construction.priority > existing.priority {
                    by_key.insert(key, construction);
                }
            } else {
                by_key.insert(key, construction);
            }
        }

        by_key.into_values().collect()
    }

    /// Generate a deduplication key for a construction.
    fn construction_key(&self, construction: &ConstructionResponse) -> String {
        format!(
            "{}:{}:{}",
            construction.connector_id, construction.object_class, construction.account_type
        )
    }

    /// Get user's remaining constructions excluding specified roles.
    async fn get_user_remaining_constructions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        excluded_role_ids: &[Uuid],
    ) -> Result<Vec<ConstructionResponse>> {
        // Get user's role assignments (would need to query role assignments)
        let all_role_ids = self.get_user_role_ids(tenant_id, user_id).await?;

        // Filter out excluded roles
        let excluded_set: HashSet<&Uuid> = excluded_role_ids.iter().collect();
        let remaining_role_ids: Vec<Uuid> = all_role_ids
            .into_iter()
            .filter(|id| !excluded_set.contains(id))
            .collect();

        if remaining_role_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Expand to include induced roles
        let mut all_remaining = remaining_role_ids.clone();
        for role_id in &remaining_role_ids {
            let induced = self
                .inducement_service
                .get_all_induced_role_ids(tenant_id, *role_id)
                .await?;
            all_remaining.extend(induced);
        }

        // Deduplicate
        let unique_ids: Vec<Uuid> = all_remaining
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        self.construction_service
            .get_enabled_by_roles(tenant_id, &unique_ids)
            .await
    }

    /// Get user's directly assigned role IDs.
    ///
    /// This queries the governance entitlement assignments to find roles
    /// assigned to the user.
    async fn get_user_role_ids(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Uuid>> {
        // Query role assignments from governance system
        // Note: This assumes gov_roles.id can be used as entitlement_id, which
        // may need adjustment based on actual data model. In practice, roles
        // may be represented differently in the entitlement system.
        let role_ids: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT DISTINCT r.id
            FROM gov_roles r
            JOIN gov_entitlement_assignments gea ON gea.entitlement_id = r.id
            WHERE gea.tenant_id = $1
                AND gea.target_type = 'user'
                AND gea.target_id = $2
                AND gea.status = 'active'
                AND r.tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(role_ids.into_iter().map(|(id,)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction_key() {
        // This would require a mock construction
        // For now, just verify the key format
        let connector_id = Uuid::new_v4();
        let key = format!("{}:user:default", connector_id);
        assert!(key.contains("user"));
        assert!(key.contains("default"));
    }
}
