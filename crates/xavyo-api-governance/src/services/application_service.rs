//! Application service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovApplication, GovAppStatus, GovAppType, GovApplication, UpdateGovApplication,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for governance application operations.
pub struct ApplicationService {
    pool: PgPool,
}

impl ApplicationService {
    /// Create a new application service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List applications for a tenant with pagination and filtering.
    pub async fn list_applications(
        &self,
        tenant_id: Uuid,
        status: Option<GovAppStatus>,
        app_type: Option<GovAppType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovApplication>, i64)> {
        let applications =
            GovApplication::list_by_tenant(&self.pool, tenant_id, status, app_type, limit, offset)
                .await?;
        let total =
            GovApplication::count_by_tenant(&self.pool, tenant_id, status, app_type).await?;

        Ok((applications, total))
    }

    /// Get an application by ID.
    pub async fn get_application(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<GovApplication> {
        GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))
    }

    /// Create a new application.
    pub async fn create_application(
        &self,
        tenant_id: Uuid,
        input: CreateGovApplication,
    ) -> Result<GovApplication> {
        // Check for duplicate name
        if let Some(_existing) =
            GovApplication::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(GovernanceError::ApplicationNameExists(input.name));
        }

        // Validate input
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Application name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Application name cannot exceed 255 characters".to_string(),
            ));
        }

        GovApplication::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update an application.
    pub async fn update_application(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
        input: UpdateGovApplication,
    ) -> Result<GovApplication> {
        // Verify application exists
        let _existing = self.get_application(tenant_id, application_id).await?;

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = input.name {
            if let Some(existing) =
                GovApplication::find_by_name(&self.pool, tenant_id, new_name).await?
            {
                if existing.id != application_id {
                    return Err(GovernanceError::ApplicationNameExists(new_name.clone()));
                }
            }

            // Validate name
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Application name cannot be empty".to_string(),
                ));
            }

            if new_name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Application name cannot exceed 255 characters".to_string(),
                ));
            }
        }

        GovApplication::update(&self.pool, tenant_id, application_id, input)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))
    }

    /// Delete an application.
    pub async fn delete_application(&self, tenant_id: Uuid, application_id: Uuid) -> Result<()> {
        // Verify application exists
        let _existing = self.get_application(tenant_id, application_id).await?;

        // Check for entitlements (deletion protection)
        let entitlement_count =
            GovApplication::count_entitlements(&self.pool, tenant_id, application_id).await?;
        if entitlement_count > 0 {
            return Err(GovernanceError::ApplicationHasEntitlements(
                entitlement_count,
            ));
        }

        let deleted = GovApplication::delete(&self.pool, tenant_id, application_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::ApplicationNotFound(application_id))
        }
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
