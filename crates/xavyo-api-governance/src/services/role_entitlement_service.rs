//! Role entitlement service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovRoleEntitlement, GovEntitlement, GovRoleEntitlement, RoleEntitlementFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

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

        GovRoleEntitlement::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
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
