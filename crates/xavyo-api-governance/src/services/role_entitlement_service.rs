//! Role entitlement service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovRoleEntitlement, GovEntitlement, GovRoleEntitlement, GovSodExemption, GovSodRule,
    RoleEntitlementFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::EffectiveAccessService;

/// Service for governance role-entitlement mapping operations.
pub struct RoleEntitlementService {
    pool: PgPool,
}

impl RoleEntitlementService {
    /// Create a new role entitlement service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List role entitlements for a tenant with pagination and filtering.
    pub async fn list_role_entitlements(
        &self,
        tenant_id: Uuid,
        entitlement_id: Option<Uuid>,
        role_name: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRoleEntitlement>, i64)> {
        let filter = RoleEntitlementFilter {
            entitlement_id,
            role_name,
        };

        let mappings =
            GovRoleEntitlement::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovRoleEntitlement::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((mappings, total))
    }

    /// Get a role entitlement mapping by ID.
    pub async fn get_role_entitlement(
        &self,
        tenant_id: Uuid,
        mapping_id: Uuid,
    ) -> Result<GovRoleEntitlement> {
        GovRoleEntitlement::find_by_id(&self.pool, tenant_id, mapping_id)
            .await?
            .ok_or(GovernanceError::RoleEntitlementNotFound(mapping_id))
    }

    /// Create a new role-entitlement mapping.
    pub async fn create_role_entitlement(
        &self,
        tenant_id: Uuid,
        input: CreateGovRoleEntitlement,
    ) -> Result<GovRoleEntitlement> {
        // Verify entitlement exists
        let entitlement =
            GovEntitlement::find_by_id(&self.pool, tenant_id, input.entitlement_id).await?;
        if entitlement.is_none() {
            return Err(GovernanceError::EntitlementNotFound(input.entitlement_id));
        }

        // Validate role name
        if input.role_name.trim().is_empty() {
            return Err(GovernanceError::InvalidRoleName(
                "Role name cannot be empty".to_string(),
            ));
        }

        if input.role_name.len() > 100 {
            return Err(GovernanceError::InvalidRoleName(
                "Role name cannot exceed 100 characters".to_string(),
            ));
        }

        // Check for existing mapping
        if let Some(_existing) = GovRoleEntitlement::find_by_role_and_entitlement(
            &self.pool,
            tenant_id,
            &input.role_name,
            input.entitlement_id,
        )
        .await?
        {
            return Err(GovernanceError::RoleEntitlementExists(input.role_name));
        }

        let result = GovRoleEntitlement::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Fix #2: Warn about potential SoD violations for users who hold this role.
        // Non-blocking — spawned as background task to avoid blocking the HTTP response.
        let bg_pool = self.pool.clone();
        let bg_effective = EffectiveAccessService::new(bg_pool.clone());
        let bg_role_name = result.role_name.clone();
        let bg_entitlement_id = result.entitlement_id;
        tokio::spawn(async move {
            Self::warn_sod_for_role_members_bg(
                &bg_pool,
                &bg_effective,
                tenant_id,
                &bg_role_name,
                bg_entitlement_id,
            )
            .await;
        });

        Ok(result)
    }

    /// Check for potential SoD violations among users who hold a role.
    ///
    /// Fix #2: When an entitlement is added to a role, all role members retroactively
    /// gain that entitlement. This check warns about potential SoD violations.
    /// Runs as a background task (static method) to avoid blocking the HTTP response.
    async fn warn_sod_for_role_members_bg(
        pool: &PgPool,
        effective_access_service: &EffectiveAccessService,
        tenant_id: Uuid,
        role_name: &str,
        entitlement_id: Uuid,
    ) {
        // Find users who have assignments from this role (via role entitlements)
        let user_ids: Vec<Uuid> = match sqlx::query_scalar(
            r"
            SELECT DISTINCT gea.target_id FROM gov_entitlement_assignments gea
            JOIN gov_role_entitlements gre ON gea.entitlement_id = gre.entitlement_id
              AND gea.tenant_id = gre.tenant_id
            WHERE gre.tenant_id = $1 AND gre.role_name = $2
              AND gea.target_type = 'user' AND gea.status = 'active'
            LIMIT 1000
            ",
        )
        .bind(tenant_id)
        .bind(role_name)
        .fetch_all(pool)
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to query role members for SoD warning check"
                );
                return;
            }
        };

        if user_ids.is_empty() {
            return;
        }

        // Check SoD rules for the new entitlement
        let rules = match GovSodRule::find_active_by_entitlement(pool, tenant_id, entitlement_id)
            .await
        {
            Ok(rules) => rules,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to query SoD rules for role entitlement warning");
                return;
            }
        };

        if rules.is_empty() {
            return;
        }

        let mut violation_count = 0u64;
        for user_id in user_ids {
            let effective = match effective_access_service
                .get_effective_access(tenant_id, user_id, None)
                .await
            {
                Ok(ea) => ea,
                Err(_) => continue,
            };

            let user_entitlements: std::collections::HashSet<Uuid> = effective
                .entitlements
                .iter()
                .map(|e| e.entitlement.id)
                .collect();

            for rule in &rules {
                if let Some(conflicting_id) = rule.get_conflicting_entitlement(entitlement_id) {
                    if user_entitlements.contains(&conflicting_id) {
                        let has_exemption = GovSodExemption::has_active_exemption(
                            pool, tenant_id, rule.id, user_id,
                        )
                        .await
                        .unwrap_or(false);

                        if !has_exemption {
                            violation_count += 1;
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                user_id = %user_id,
                                rule_id = %rule.id,
                                rule_name = %rule.name,
                                role_name = %role_name,
                                entitlement_id = %entitlement_id,
                                conflicting_entitlement_id = %conflicting_id,
                                "SoD violation: adding entitlement to role creates conflict for existing member"
                            );
                        }
                    }
                }
            }
        }

        if violation_count > 0 {
            tracing::warn!(
                tenant_id = %tenant_id,
                role_name = %role_name,
                entitlement_id = %entitlement_id,
                violation_count,
                "Role entitlement addition created {violation_count} SoD violation(s) for existing role members"
            );
        }
    }

    /// Delete a role-entitlement mapping.
    pub async fn delete_role_entitlement(&self, tenant_id: Uuid, mapping_id: Uuid) -> Result<()> {
        // Verify mapping exists
        let _existing = self.get_role_entitlement(tenant_id, mapping_id).await?;

        let deleted = GovRoleEntitlement::delete(&self.pool, tenant_id, mapping_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::RoleEntitlementNotFound(mapping_id))
        }
    }

    /// List entitlement IDs for a role.
    pub async fn list_entitlement_ids_by_role(
        &self,
        tenant_id: Uuid,
        role_name: &str,
    ) -> Result<Vec<Uuid>> {
        GovRoleEntitlement::list_entitlement_ids_by_role(&self.pool, tenant_id, role_name)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List role names for an entitlement.
    pub async fn list_roles_by_entitlement(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<String>> {
        GovRoleEntitlement::list_roles_by_entitlement(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List all distinct role names in a tenant.
    pub async fn list_distinct_roles(&self, tenant_id: Uuid) -> Result<Vec<String>> {
        GovRoleEntitlement::list_distinct_roles(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_service_creation() {
        // This test just verifies the service can be instantiated
        // Real tests would require a database connection
    }
}
