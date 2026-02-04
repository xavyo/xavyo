//! Script Binding Service (F066).
//! Manages script-to-connector hook bindings.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    BindingFilter, CreateScriptHookBinding, FailurePolicy, GovHookPhase, GovProvisioningScript,
    GovScriptHookBinding, GovScriptStatus, ScriptOperationType, UpdateScriptHookBinding,
    MAX_BINDINGS_PER_HOOK,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for managing script-to-connector hook bindings.
pub struct ScriptBindingService {
    pool: PgPool,
}

impl ScriptBindingService {
    /// Create a new script binding service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new hook binding.
    ///
    /// Validates that the referenced script exists and is active, and that the
    /// maximum number of bindings per hook point is not exceeded.
    pub async fn create_binding(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        connector_id: Uuid,
        hook_phase: GovHookPhase,
        operation_type: ScriptOperationType,
        execution_order: i32,
        failure_policy: FailurePolicy,
        max_retries: i32,
        timeout_seconds: i32,
    ) -> Result<GovScriptHookBinding> {
        // Validate script exists and is active.
        let script = GovProvisioningScript::get_by_id(&self.pool, script_id, tenant_id)
            .await?
            .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))?;

        if script.status != GovScriptStatus::Active {
            return Err(GovernanceError::ScriptNotActive(script_id));
        }

        // Check binding count for this connector/phase/operation does not exceed the limit.
        let count = GovScriptHookBinding::count_by_connector_phase(
            &self.pool,
            connector_id,
            hook_phase,
            operation_type,
            tenant_id,
        )
        .await?;

        if count >= i64::from(MAX_BINDINGS_PER_HOOK) {
            return Err(GovernanceError::MaxBindingsExceeded(MAX_BINDINGS_PER_HOOK));
        }

        // Create the binding.
        let params = CreateScriptHookBinding {
            tenant_id,
            script_id,
            connector_id,
            hook_phase,
            operation_type,
            execution_order,
            failure_policy,
            max_retries,
            timeout_seconds,
        };

        let binding = GovScriptHookBinding::create(&self.pool, &params).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            binding_id = %binding.id,
            script_id = %script_id,
            connector_id = %connector_id,
            hook_phase = ?hook_phase,
            operation_type = ?operation_type,
            "Script hook binding created"
        );

        Ok(binding)
    }

    /// Get a binding by ID.
    pub async fn get_binding(
        &self,
        tenant_id: Uuid,
        binding_id: Uuid,
    ) -> Result<GovScriptHookBinding> {
        GovScriptHookBinding::get_by_id(&self.pool, binding_id, tenant_id)
            .await?
            .ok_or(GovernanceError::ScriptHookBindingNotFound(binding_id))
    }

    /// List bindings with filters and pagination.
    ///
    /// Returns a tuple of (bindings, `total_count`).
    pub async fn list_bindings(
        &self,
        tenant_id: Uuid,
        filter: &BindingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovScriptHookBinding>, i64)> {
        let result =
            GovScriptHookBinding::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        Ok(result)
    }

    /// List all bindings for a connector, ordered by `hook_phase`, `operation_type`,
    /// and `execution_order`.
    pub async fn list_by_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Vec<GovScriptHookBinding>> {
        let bindings =
            GovScriptHookBinding::list_by_connector(&self.pool, connector_id, tenant_id).await?;
        Ok(bindings)
    }

    /// Get bindings for execution (hot path).
    ///
    /// Returns only enabled bindings for the given connector, hook phase, and
    /// operation type, ordered by `execution_order` for sequential execution.
    pub async fn get_execution_bindings(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        hook_phase: GovHookPhase,
        operation_type: ScriptOperationType,
    ) -> Result<Vec<GovScriptHookBinding>> {
        let bindings = GovScriptHookBinding::list_for_execution(
            &self.pool,
            connector_id,
            hook_phase,
            operation_type,
            tenant_id,
        )
        .await?;
        Ok(bindings)
    }

    /// Update a binding.
    ///
    /// Only the provided fields are updated; others remain unchanged.
    pub async fn update_binding(
        &self,
        tenant_id: Uuid,
        binding_id: Uuid,
        execution_order: Option<i32>,
        failure_policy: Option<FailurePolicy>,
        max_retries: Option<i32>,
        timeout_seconds: Option<i32>,
        enabled: Option<bool>,
    ) -> Result<GovScriptHookBinding> {
        let params = UpdateScriptHookBinding {
            execution_order,
            failure_policy,
            max_retries,
            timeout_seconds,
            enabled,
        };

        let binding =
            GovScriptHookBinding::update(&self.pool, binding_id, tenant_id, &params).await?;

        binding.ok_or(GovernanceError::ScriptHookBindingNotFound(binding_id))
    }

    /// Delete a binding.
    ///
    /// Returns an error if the binding does not exist.
    pub async fn delete_binding(&self, tenant_id: Uuid, binding_id: Uuid) -> Result<()> {
        // Check that the binding exists first.
        let _binding = GovScriptHookBinding::get_by_id(&self.pool, binding_id, tenant_id)
            .await?
            .ok_or(GovernanceError::ScriptHookBindingNotFound(binding_id))?;

        let deleted = GovScriptHookBinding::delete(&self.pool, binding_id, tenant_id).await?;

        if !deleted {
            return Err(GovernanceError::ScriptHookBindingNotFound(binding_id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            binding_id = %binding_id,
            "Script hook binding deleted"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        // This test verifies the types compile correctly.
        // Actual service tests would require a database connection.
    }
}
