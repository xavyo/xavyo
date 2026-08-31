//! Role inducement service for F-063: Role Inducements.
//!
//! Provides business logic for managing role inducements, which define
//! role-to-role construction inheritance patterns.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{models::GovRole, CreateRoleInducement, RoleInducement, RoleInducementFilter};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateInducementRequest, CycleDetectedError, InducedRoleInfoResponse, InducementListResponse,
    InducementResponse, ListInducementsQuery,
};

/// Service for role inducement operations.
pub struct RoleInducementService {
    pool: PgPool,
}

impl RoleInducementService {
    /// Create a new role inducement service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List inducements for a role with pagination and filtering.
    pub async fn list_by_role(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        query: &ListInducementsQuery,
    ) -> Result<InducementListResponse> {
        // Verify role exists
        self.verify_role_exists(tenant_id, inducing_role_id).await?;

        let filter = RoleInducementFilter {
            enabled_only: query.enabled_only,
        };

        let inducements = RoleInducement::list_by_inducing_role(
            &self.pool,
            tenant_id,
            inducing_role_id,
            &filter,
            query.limit,
            query.offset,
        )
        .await?;

        let total = RoleInducement::count_by_inducing_role(
            &self.pool,
            tenant_id,
            inducing_role_id,
            &filter,
        )
        .await?;

        let mut items = Vec::with_capacity(inducements.len());
        for inducement in inducements {
            items.push(inducement_with_role_names(&self.pool, tenant_id, inducement).await?);
        }

        Ok(InducementListResponse { items, total })
    }

    /// Get an inducement by ID.
    pub async fn get_inducement(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        inducement_id: Uuid,
    ) -> Result<InducementResponse> {
        let inducement = RoleInducement::find_by_id_and_role(
            &self.pool,
            tenant_id,
            inducing_role_id,
            inducement_id,
        )
        .await?
        .ok_or(GovernanceError::RoleInducementNotFound(inducement_id))?;

        inducement_with_role_names(&self.pool, tenant_id, inducement).await
    }

    /// Create a new inducement for a role.
    pub async fn create_inducement(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        request: CreateInducementRequest,
        created_by: Uuid,
    ) -> Result<InducementResponse> {
        // Verify inducing role exists
        self.verify_role_exists(tenant_id, inducing_role_id).await?;

        // Verify induced role exists
        self.verify_role_exists(tenant_id, request.induced_role_id)
            .await?;

        // Check for duplicate inducement
        if RoleInducement::exists(
            &self.pool,
            tenant_id,
            inducing_role_id,
            request.induced_role_id,
        )
        .await?
        {
            return Err(GovernanceError::RoleInducementExists);
        }

        // Check for cycle
        if RoleInducement::would_create_cycle(
            &self.pool,
            tenant_id,
            inducing_role_id,
            request.induced_role_id,
        )
        .await?
        {
            // Get cycle path for error message
            let cycle_path = RoleInducement::get_cycle_path(
                &self.pool,
                tenant_id,
                inducing_role_id,
                request.induced_role_id,
            )
            .await
            .unwrap_or_default();

            let error = CycleDetectedError::new(cycle_path);
            return Err(GovernanceError::RoleInducementCycleDetected(error.message));
        }

        // Convert request to database model input
        let input = CreateRoleInducement {
            induced_role_id: request.induced_role_id,
            description: request.description,
        };

        let inducement =
            RoleInducement::create(&self.pool, tenant_id, inducing_role_id, &input, created_by)
                .await?;

        inducement_with_role_names(&self.pool, tenant_id, inducement).await
    }

    /// Delete an inducement.
    pub async fn delete_inducement(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        inducement_id: Uuid,
    ) -> Result<()> {
        // Verify inducement exists
        let _existing = self
            .get_inducement(tenant_id, inducing_role_id, inducement_id)
            .await?;

        let deleted = RoleInducement::delete(&self.pool, tenant_id, inducement_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::RoleInducementNotFound(inducement_id))
        }
    }

    /// Enable an inducement.
    pub async fn enable_inducement(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        inducement_id: Uuid,
    ) -> Result<InducementResponse> {
        // Verify inducement exists
        let _existing = self
            .get_inducement(tenant_id, inducing_role_id, inducement_id)
            .await?;

        let updated = RoleInducement::enable(&self.pool, tenant_id, inducement_id)
            .await?
            .ok_or(GovernanceError::RoleInducementNotFound(inducement_id))?;

        inducement_with_role_names(&self.pool, tenant_id, updated).await
    }

    /// Disable an inducement.
    pub async fn disable_inducement(
        &self,
        tenant_id: Uuid,
        inducing_role_id: Uuid,
        inducement_id: Uuid,
    ) -> Result<InducementResponse> {
        // Verify inducement exists
        let _existing = self
            .get_inducement(tenant_id, inducing_role_id, inducement_id)
            .await?;

        let updated = RoleInducement::disable(&self.pool, tenant_id, inducement_id)
            .await?
            .ok_or(GovernanceError::RoleInducementNotFound(inducement_id))?;

        inducement_with_role_names(&self.pool, tenant_id, updated).await
    }

    /// Get all induced roles for a role (recursive traversal).
    pub async fn get_induced_roles(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<InducedRoleInfoResponse>> {
        // Verify role exists
        self.verify_role_exists(tenant_id, role_id).await?;

        let induced_roles =
            RoleInducement::get_all_induced_roles(&self.pool, tenant_id, role_id).await?;

        Ok(induced_roles
            .into_iter()
            .map(|info| InducedRoleInfoResponse {
                role_id: info.role_id,
                role_name: info.role_name,
                depth: info.depth,
            })
            .collect())
    }

    /// Get all induced role IDs for a role (recursive traversal).
    /// This is used internally for construction evaluation.
    pub async fn get_all_induced_role_ids(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let ids = RoleInducement::get_all_induced_role_ids(&self.pool, tenant_id, role_id).await?;
        Ok(ids)
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
}

async fn inducement_with_role_names(
    pool: &PgPool,
    tenant_id: Uuid,
    inducement: RoleInducement,
) -> Result<InducementResponse> {
    let inducing_role_name = GovRole::find_by_id(pool, tenant_id, inducement.inducing_role_id)
        .await?
        .map(|role| role.name);
    let induced_role_name = GovRole::find_by_id(pool, tenant_id, inducement.induced_role_id)
        .await?
        .map(|role| role.name);
    Ok(InducementResponse::from_model(
        inducement,
        inducing_role_name,
        induced_role_name,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn role_inducement_responses_look_up_role_names() {
        let src = include_str!("role_inducement_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        for (fn_name, label) in [
            ("pub async fn list_by_role", "GET list inducements"),
            ("pub async fn get_inducement", "GET inducement"),
            ("pub async fn create_inducement", "POST create inducement"),
            ("pub async fn enable_inducement", "POST enable inducement"),
            ("pub async fn disable_inducement", "POST disable inducement"),
        ] {
            let body = production
                .split(fn_name)
                .nth(1)
                .and_then(|s| s.split("pub async fn ").next())
                .unwrap_or_else(|| panic!("{fn_name}"));
            assert!(
                body.contains("inducement_with_role_names(")
                    && !body.contains("InducementResponse::from("),
                "{label} must look up inducing_role_name and induced_role_name"
            );
        }
    }
}
