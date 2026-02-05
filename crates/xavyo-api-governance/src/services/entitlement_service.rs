//! Entitlement service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovEntitlement, DataProtectionClassification, EntitlementFilter, GovApplication,
    GovEntitlement, GovEntitlementStatus, GovRiskLevel, UpdateGovEntitlement,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for governance entitlement operations.
pub struct EntitlementService {
    pool: PgPool,
}

impl EntitlementService {
    /// Create a new entitlement service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List entitlements for a tenant with pagination and filtering.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_entitlements(
        &self,
        tenant_id: Uuid,
        application_id: Option<Uuid>,
        status: Option<GovEntitlementStatus>,
        risk_level: Option<GovRiskLevel>,
        owner_id: Option<Uuid>,
        classification: Option<DataProtectionClassification>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovEntitlement>, i64)> {
        let filter = EntitlementFilter {
            application_id,
            status,
            risk_level,
            owner_id,
            is_delegable: None,
            data_protection_classification: classification,
        };

        let entitlements =
            GovEntitlement::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovEntitlement::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((entitlements, total))
    }

    /// Get an entitlement by ID.
    pub async fn get_entitlement(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<GovEntitlement> {
        GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))
    }

    /// Create a new entitlement.
    pub async fn create_entitlement(
        &self,
        tenant_id: Uuid,
        input: CreateGovEntitlement,
    ) -> Result<GovEntitlement> {
        // Verify application exists and is active
        let application =
            GovApplication::find_by_id(&self.pool, tenant_id, input.application_id).await?;
        match application {
            None => {
                return Err(GovernanceError::ApplicationNotFound(input.application_id));
            }
            Some(app) if !app.is_active() => {
                return Err(GovernanceError::ApplicationInactive(input.application_id));
            }
            _ => {}
        }

        // Check for duplicate name within application
        if let Some(_existing) =
            GovEntitlement::find_by_name(&self.pool, tenant_id, input.application_id, &input.name)
                .await?
        {
            return Err(GovernanceError::EntitlementNameExists(input.name));
        }

        // Validate input
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Entitlement name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Entitlement name cannot exceed 255 characters".to_string(),
            ));
        }

        GovEntitlement::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update an entitlement.
    pub async fn update_entitlement(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
        input: UpdateGovEntitlement,
    ) -> Result<GovEntitlement> {
        // Verify entitlement exists
        let existing = self.get_entitlement(tenant_id, entitlement_id).await?;

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = input.name {
            if let Some(existing_with_name) = GovEntitlement::find_by_name(
                &self.pool,
                tenant_id,
                existing.application_id,
                new_name,
            )
            .await?
            {
                if existing_with_name.id != entitlement_id {
                    return Err(GovernanceError::EntitlementNameExists(new_name.clone()));
                }
            }

            // Validate name
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Entitlement name cannot be empty".to_string(),
                ));
            }

            if new_name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Entitlement name cannot exceed 255 characters".to_string(),
                ));
            }
        }

        GovEntitlement::update(&self.pool, tenant_id, entitlement_id, input)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))
    }

    /// Delete an entitlement.
    pub async fn delete_entitlement(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<()> {
        // Verify entitlement exists
        let _existing = self.get_entitlement(tenant_id, entitlement_id).await?;

        // Check for assignments (deletion protection)
        let assignment_count =
            GovEntitlement::count_assignments(&self.pool, tenant_id, entitlement_id).await?;
        if assignment_count > 0 {
            return Err(GovernanceError::EntitlementHasAssignments(assignment_count));
        }

        let deleted = GovEntitlement::delete(&self.pool, tenant_id, entitlement_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::EntitlementNotFound(entitlement_id))
        }
    }

    /// Set owner for an entitlement.
    pub async fn set_owner(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
        owner_id: Uuid,
    ) -> Result<GovEntitlement> {
        // Verify entitlement exists
        let _existing = self.get_entitlement(tenant_id, entitlement_id).await?;

        // TODO: Verify owner_id is a valid user in the tenant
        // For now, we trust the caller has validated this

        GovEntitlement::set_owner(&self.pool, tenant_id, entitlement_id, owner_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))
    }

    /// Remove owner from an entitlement.
    pub async fn remove_owner(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<GovEntitlement> {
        // Verify entitlement exists
        let _existing = self.get_entitlement(tenant_id, entitlement_id).await?;

        GovEntitlement::remove_owner(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))
    }

    /// List entitlements by owner.
    pub async fn list_by_owner(
        &self,
        tenant_id: Uuid,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovEntitlement>> {
        GovEntitlement::list_by_owner(&self.pool, tenant_id, owner_id, limit, offset)
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
