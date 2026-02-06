//! SLA Policy Service for semi-manual resources (F064).
//!
//! Manages SLA policies for manual provisioning task deadlines.

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::{CreateSlaPolicy, GovSlaPolicy, SlaPolicyFilter, UpdateSlaPolicy};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateSlaPolicyRequest, ListSlaPoliciesQuery, SlaPolicyListResponse, SlaPolicyResponse,
    UpdateSlaPolicyRequest,
};

/// Service for managing SLA policies.
pub struct SlaPolicyService {
    pool: PgPool,
}

impl SlaPolicyService {
    /// Create a new SLA policy service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List SLA policies with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListSlaPoliciesQuery,
    ) -> Result<SlaPolicyListResponse> {
        let filter = SlaPolicyFilter {
            is_active: query.is_active,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let policies =
            GovSlaPolicy::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;

        let total = GovSlaPolicy::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(SlaPolicyListResponse {
            items: policies.into_iter().map(SlaPolicyResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get an SLA policy by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<SlaPolicyResponse> {
        let policy = GovSlaPolicy::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::SlaPolicyNotFound(id))?;

        Ok(SlaPolicyResponse::from(policy))
    }

    /// Create a new SLA policy.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateSlaPolicyRequest,
    ) -> Result<SlaPolicyResponse> {
        let input = CreateSlaPolicy {
            name: request.name,
            description: request.description,
            target_duration_seconds: request.target_duration_seconds,
            warning_threshold_percent: Some(request.warning_threshold_percent),
            escalation_contacts: request.escalation_contacts,
            breach_notification_enabled: Some(request.breach_notification_enabled),
        };

        let policy = GovSlaPolicy::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            policy_id = %policy.id,
            target_duration = policy.target_duration_seconds,
            "SLA policy created"
        );

        Ok(SlaPolicyResponse::from(policy))
    }

    /// Update an SLA policy.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: UpdateSlaPolicyRequest,
    ) -> Result<SlaPolicyResponse> {
        let input = UpdateSlaPolicy {
            name: request.name,
            description: request.description,
            target_duration_seconds: request.target_duration_seconds,
            warning_threshold_percent: request.warning_threshold_percent,
            escalation_contacts: request.escalation_contacts,
            breach_notification_enabled: request.breach_notification_enabled,
            is_active: request.is_active,
        };

        let policy = GovSlaPolicy::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::SlaPolicyNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            policy_id = %id,
            "SLA policy updated"
        );

        Ok(SlaPolicyResponse::from(policy))
    }

    /// Delete an SLA policy.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        // Check if policy is in use
        let in_use = GovSlaPolicy::is_in_use(&self.pool, tenant_id, id).await?;

        if in_use {
            return Err(GovernanceError::SlaPolicyInUse(id));
        }

        let deleted = GovSlaPolicy::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(GovernanceError::SlaPolicyNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            policy_id = %id,
            "SLA policy deleted"
        );

        Ok(())
    }

    /// Get an SLA policy by ID (internal use, returns full model).
    pub async fn get_policy(&self, tenant_id: Uuid, id: Uuid) -> Result<GovSlaPolicy> {
        GovSlaPolicy::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::SlaPolicyNotFound(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_policy_service_creation() {
        // This test just verifies the type compiles correctly
        // Actual service tests would require a database connection
    }
}
