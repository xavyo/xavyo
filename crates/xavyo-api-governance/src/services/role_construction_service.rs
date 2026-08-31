//! Role construction service for F-063: Role Inducements.
//!
//! Provides business logic for managing role constructions, which define
//! what accounts/resources are automatically provisioned when a role is assigned.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    models::{ConnectorConfiguration, GovRole},
    CreateRoleConstruction, RoleConstruction, RoleConstructionFilter, UpdateRoleConstruction,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ConstructionListResponse, ConstructionResponse, CreateConstructionRequest,
    ListConstructionsQuery, UpdateConstructionRequest,
};

/// Service for role construction operations.
pub struct RoleConstructionService {
    pool: PgPool,
}

impl RoleConstructionService {
    /// Create a new role construction service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List constructions for a role with pagination and filtering.
    pub async fn list_by_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        query: &ListConstructionsQuery,
    ) -> Result<ConstructionListResponse> {
        // Verify role exists
        self.verify_role_exists(tenant_id, role_id).await?;

        let filter = RoleConstructionFilter {
            connector_id: query.connector_id,
            enabled_only: query.enabled_only,
            object_class: query.object_class.clone(),
        };

        let constructions = RoleConstruction::list_by_role(
            &self.pool,
            tenant_id,
            role_id,
            &filter,
            query.limit,
            query.offset,
        )
        .await?;

        let total =
            RoleConstruction::count_by_role(&self.pool, tenant_id, role_id, &filter).await?;

        let mut items = Vec::with_capacity(constructions.len());
        for construction in constructions {
            items
                .push(construction_with_connector_name(&self.pool, tenant_id, construction).await?);
        }

        Ok(ConstructionListResponse { items, total })
    }

    /// Get a construction by ID.
    pub async fn get_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
    ) -> Result<ConstructionResponse> {
        let construction =
            RoleConstruction::find_by_id_and_role(&self.pool, tenant_id, role_id, construction_id)
                .await?
                .ok_or(GovernanceError::RoleConstructionNotFound(construction_id))?;

        construction_with_connector_name(&self.pool, tenant_id, construction).await
    }

    /// Create a new construction for a role.
    pub async fn create_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        request: CreateConstructionRequest,
        created_by: Uuid,
    ) -> Result<ConstructionResponse> {
        // Verify role exists
        self.verify_role_exists(tenant_id, role_id).await?;

        // Validate connector exists
        self.validate_connector(tenant_id, request.connector_id)
            .await?;

        // Check for duplicate construction
        if RoleConstruction::exists(
            &self.pool,
            tenant_id,
            role_id,
            request.connector_id,
            &request.object_class,
            &request.account_type,
        )
        .await?
        {
            return Err(GovernanceError::RoleConstructionExists);
        }

        // Validate object_class is not empty
        if request.object_class.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Object class cannot be empty".to_string(),
            ));
        }

        // Convert request to database model input
        let input = CreateRoleConstruction {
            connector_id: request.connector_id,
            object_class: request.object_class,
            account_type: request.account_type,
            attribute_mappings: request.attribute_mappings.into(),
            condition: request.condition.map(Into::into),
            deprovisioning_policy: request.deprovisioning_policy.into(),
            priority: request.priority,
            description: request.description,
        };

        let construction =
            RoleConstruction::create(&self.pool, tenant_id, role_id, &input, created_by).await?;

        construction_with_connector_name(&self.pool, tenant_id, construction).await
    }

    /// Update a construction.
    pub async fn update_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
        request: UpdateConstructionRequest,
    ) -> Result<ConstructionResponse> {
        // Verify construction exists
        let _existing = self
            .get_construction(tenant_id, role_id, construction_id)
            .await?;

        // Validate object_class if provided
        if let Some(ref object_class) = request.object_class {
            if object_class.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Object class cannot be empty".to_string(),
                ));
            }
        }

        // Convert request to database model input
        let input = UpdateRoleConstruction {
            object_class: request.object_class,
            account_type: request.account_type,
            attribute_mappings: request.attribute_mappings.map(Into::into),
            condition: request.condition.map(|opt| opt.map(Into::into)),
            deprovisioning_policy: request.deprovisioning_policy.map(Into::into),
            priority: request.priority,
            description: request.description,
            version: request.version,
        };

        let updated =
            RoleConstruction::update(&self.pool, tenant_id, construction_id, &input).await?;

        match updated {
            Some(construction) => {
                construction_with_connector_name(&self.pool, tenant_id, construction).await
            }
            None => Err(GovernanceError::RoleConstructionVersionConflict),
        }
    }

    /// Delete a construction.
    pub async fn delete_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
    ) -> Result<()> {
        // Verify construction exists
        let _existing = self
            .get_construction(tenant_id, role_id, construction_id)
            .await?;

        let deleted = RoleConstruction::delete(&self.pool, tenant_id, construction_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::RoleConstructionNotFound(construction_id))
        }
    }

    /// Enable a construction.
    pub async fn enable_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
    ) -> Result<ConstructionResponse> {
        // Verify construction exists
        let _existing = self
            .get_construction(tenant_id, role_id, construction_id)
            .await?;

        let updated = RoleConstruction::enable(&self.pool, tenant_id, construction_id)
            .await?
            .ok_or(GovernanceError::RoleConstructionNotFound(construction_id))?;

        construction_with_connector_name(&self.pool, tenant_id, updated).await
    }

    /// Disable a construction.
    pub async fn disable_construction(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
    ) -> Result<ConstructionResponse> {
        // Verify construction exists
        let _existing = self
            .get_construction(tenant_id, role_id, construction_id)
            .await?;

        let updated = RoleConstruction::disable(&self.pool, tenant_id, construction_id)
            .await?
            .ok_or(GovernanceError::RoleConstructionNotFound(construction_id))?;

        construction_with_connector_name(&self.pool, tenant_id, updated).await
    }

    /// Get all enabled constructions for a set of role IDs.
    /// Used when evaluating constructions for role assignment.
    pub async fn get_enabled_by_roles(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<Vec<ConstructionResponse>> {
        let constructions =
            RoleConstruction::list_enabled_by_roles(&self.pool, tenant_id, role_ids).await?;

        let mut items = Vec::with_capacity(constructions.len());
        for construction in constructions {
            items
                .push(construction_with_connector_name(&self.pool, tenant_id, construction).await?);
        }
        Ok(items)
    }

    /// Get effective constructions for a role (own + induced roles).
    ///
    /// This returns all constructions that would be triggered when this role
    /// is assigned, including constructions from any induced roles.
    pub async fn get_effective_constructions(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        inducement_service: &crate::services::RoleInducementService,
    ) -> Result<Vec<ConstructionResponse>> {
        // Verify role exists
        self.verify_role_exists(tenant_id, role_id).await?;

        // Get all role IDs (this role + induced roles)
        let mut role_ids = vec![role_id];
        let induced = inducement_service
            .get_all_induced_role_ids(tenant_id, role_id)
            .await?;
        role_ids.extend(induced);

        // Get all enabled constructions for these roles
        self.get_enabled_by_roles(tenant_id, &role_ids).await
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Verify that a role exists.
    async fn verify_role_exists(&self, tenant_id: Uuid, role_id: Uuid) -> Result<()> {
        GovRole::find_by_id(&self.pool, tenant_id, role_id)
            .await?
            .ok_or(GovernanceError::GovRoleNotFound(role_id))?;
        Ok(())
    }

    /// Validate that a connector exists in this tenant.
    async fn validate_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<()> {
        let exists: bool = sqlx::query_scalar(
            r"SELECT EXISTS(SELECT 1 FROM connector_configurations WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        if !exists {
            return Err(GovernanceError::ConnectorNotFound(connector_id));
        }

        Ok(())
    }
}

async fn construction_with_connector_name(
    pool: &PgPool,
    tenant_id: Uuid,
    construction: RoleConstruction,
) -> Result<ConstructionResponse> {
    let connector_name =
        ConnectorConfiguration::find_by_id(pool, tenant_id, construction.connector_id)
            .await?
            .map(|connector| connector.name);
    ConstructionResponse::from_model(construction, connector_name)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_service_creation() {
        // This is a compile-time test to ensure the service can be created
        // Actual database tests would require a test database setup
    }

    #[test]
    fn validate_connector_scopes_by_tenant() {
        let src = include_str!("role_construction_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("FROM connector_configurations WHERE id = $1 AND tenant_id = $2"),
            "connector lookup must include tenant_id"
        );
        assert!(
            !production.contains("FROM connector_configurations WHERE id = $1)"),
            "must not look up connectors by id alone"
        );
    }

    #[test]
    fn role_construction_responses_look_up_connector_names() {
        let src = include_str!("role_construction_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        for (fn_name, label) in [
            ("pub async fn list_by_role", "GET list constructions"),
            ("pub async fn get_construction", "GET construction"),
            (
                "pub async fn create_construction",
                "POST create construction",
            ),
            (
                "pub async fn update_construction",
                "PUT update construction",
            ),
            (
                "pub async fn enable_construction",
                "POST enable construction",
            ),
            (
                "pub async fn disable_construction",
                "POST disable construction",
            ),
            (
                "pub async fn get_enabled_by_roles",
                "GET enabled constructions by roles",
            ),
        ] {
            let body = production
                .split(fn_name)
                .nth(1)
                .and_then(|s| s.split("pub async fn ").next())
                .unwrap_or_else(|| panic!("{fn_name}"));
            assert!(
                body.contains("construction_with_connector_name(")
                    && !body.contains("ConstructionResponse::try_from("),
                "{label} must look up advertised connector_name"
            );
        }

        let effective = production
            .split("pub async fn get_effective_constructions")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_effective_constructions");
        assert!(
            effective.contains("get_enabled_by_roles("),
            "GET effective constructions must inherit connector_name lookups"
        );
    }
}
