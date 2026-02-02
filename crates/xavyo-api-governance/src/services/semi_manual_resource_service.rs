//! Semi-manual Resource Service for governance API (F064).
//!
//! Orchestrates the configuration of semi-manual resources, including
//! marking applications as semi-manual and assigning default ticketing
//! and SLA policies.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    GovAppStatus, GovApplication, GovSlaPolicy, GovTicketingConfiguration, UpdateGovApplication,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ConfigureSemiManualRequest, ListSemiManualApplicationsQuery, SemiManualApplicationResponse,
    SemiManualApplicationsListResponse,
};

/// Convert GovAppStatus to a string representation.
fn status_to_string(status: GovAppStatus) -> String {
    match status {
        GovAppStatus::Active => "active".to_string(),
        GovAppStatus::Inactive => "inactive".to_string(),
    }
}

/// Service for managing semi-manual resources.
pub struct SemiManualResourceService {
    pool: PgPool,
}

impl SemiManualResourceService {
    /// Create a new semi-manual resource service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List applications configured as semi-manual.
    pub async fn list_semi_manual_applications(
        &self,
        tenant_id: Uuid,
        query: &ListSemiManualApplicationsQuery,
    ) -> Result<SemiManualApplicationsListResponse> {
        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        // Get all semi-manual applications to calculate total count
        let all_applications =
            GovApplication::list_semi_manual(&self.pool, tenant_id, 10000, 0).await?;
        let total = all_applications.len() as i64;

        // Get paginated results
        let applications =
            GovApplication::list_semi_manual(&self.pool, tenant_id, limit, offset).await?;

        let items = applications
            .into_iter()
            .map(|app| SemiManualApplicationResponse {
                id: app.id,
                name: app.name,
                description: app.description,
                is_semi_manual: app.is_semi_manual,
                ticketing_config_id: app.ticketing_config_id,
                sla_policy_id: app.sla_policy_id,
                requires_approval_before_ticket: app.requires_approval_before_ticket,
                status: status_to_string(app.status),
                created_at: app.created_at,
                updated_at: app.updated_at,
            })
            .collect();

        Ok(SemiManualApplicationsListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get semi-manual configuration for an application.
    pub async fn get_semi_manual_config(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<SemiManualApplicationResponse> {
        let app = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        Ok(SemiManualApplicationResponse {
            id: app.id,
            name: app.name,
            description: app.description,
            is_semi_manual: app.is_semi_manual,
            ticketing_config_id: app.ticketing_config_id,
            sla_policy_id: app.sla_policy_id,
            requires_approval_before_ticket: app.requires_approval_before_ticket,
            status: status_to_string(app.status),
            created_at: app.created_at,
            updated_at: app.updated_at,
        })
    }

    /// Configure an application as semi-manual.
    pub async fn configure_semi_manual(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
        request: ConfigureSemiManualRequest,
    ) -> Result<SemiManualApplicationResponse> {
        // Verify application exists
        let _app = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        // Verify ticketing configuration exists if provided
        if let Some(config_id) = request.ticketing_config_id {
            let _config = GovTicketingConfiguration::find_by_id(&self.pool, tenant_id, config_id)
                .await?
                .ok_or(GovernanceError::TicketingConfigurationNotFound(config_id))?;
        }

        // Verify SLA policy exists if provided
        if let Some(policy_id) = request.sla_policy_id {
            let _policy = GovSlaPolicy::find_by_id(&self.pool, tenant_id, policy_id)
                .await?
                .ok_or(GovernanceError::SlaPolicyNotFound(policy_id))?;
        }

        // Update application with semi-manual configuration
        let update = UpdateGovApplication {
            name: None,
            description: None,
            owner_id: None,
            status: None,
            external_id: None,
            metadata: None,
            is_delegable: None,
            is_semi_manual: Some(request.is_semi_manual),
            ticketing_config_id: request.ticketing_config_id,
            sla_policy_id: request.sla_policy_id,
            requires_approval_before_ticket: Some(request.requires_approval_before_ticket),
        };

        let updated_app = GovApplication::update(&self.pool, tenant_id, application_id, update)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            application_id = %application_id,
            is_semi_manual = request.is_semi_manual,
            "Application semi-manual configuration updated"
        );

        Ok(SemiManualApplicationResponse {
            id: updated_app.id,
            name: updated_app.name,
            description: updated_app.description,
            is_semi_manual: updated_app.is_semi_manual,
            ticketing_config_id: updated_app.ticketing_config_id,
            sla_policy_id: updated_app.sla_policy_id,
            requires_approval_before_ticket: updated_app.requires_approval_before_ticket,
            status: status_to_string(updated_app.status),
            created_at: updated_app.created_at,
            updated_at: updated_app.updated_at,
        })
    }

    /// Remove semi-manual configuration from an application.
    pub async fn remove_semi_manual_config(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<SemiManualApplicationResponse> {
        // Verify application exists
        let _app = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        // Update application to remove semi-manual configuration
        let update = UpdateGovApplication {
            name: None,
            description: None,
            owner_id: None,
            status: None,
            external_id: None,
            metadata: None,
            is_delegable: None,
            is_semi_manual: Some(false),
            ticketing_config_id: None,
            sla_policy_id: None,
            requires_approval_before_ticket: Some(false),
        };

        let updated_app = GovApplication::update(&self.pool, tenant_id, application_id, update)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            application_id = %application_id,
            "Application semi-manual configuration removed"
        );

        Ok(SemiManualApplicationResponse {
            id: updated_app.id,
            name: updated_app.name,
            description: updated_app.description,
            is_semi_manual: updated_app.is_semi_manual,
            ticketing_config_id: updated_app.ticketing_config_id,
            sla_policy_id: updated_app.sla_policy_id,
            requires_approval_before_ticket: updated_app.requires_approval_before_ticket,
            status: status_to_string(updated_app.status),
            created_at: updated_app.created_at,
            updated_at: updated_app.updated_at,
        })
    }

    /// Check if an application is configured as semi-manual.
    pub async fn is_semi_manual(&self, tenant_id: Uuid, application_id: Uuid) -> Result<bool> {
        let app = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        Ok(app.is_semi_manual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        // This test verifies the types compile correctly
        // Actual service tests would require a database connection
    }
}
