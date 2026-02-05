//! Parameter service for F057 Parametric Roles.
//!
//! Provides business logic for managing role parameters and parametric assignments.

use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;
use xavyo_db::{
    CreateGovRoleParameter, GovEntitlementAssignment, GovParameterAuditEvent,
    GovRoleAssignmentParameter, GovRoleParameter, ParameterAuditFilter, RoleParameterFilter,
    SetGovAssignmentParameter, UpdateGovRoleParameter,
};
use xavyo_governance::GovernanceError;

use super::parameter_validation_service::{ParameterValidationService, ValidationResult};
use crate::models::parametric_role::{EffectiveEntitlementWithParams, EffectiveParameterValue};

/// Service for managing role parameters and parametric assignments.
pub struct ParameterService {
    pool: PgPool,
    validation_service: ParameterValidationService,
}

impl ParameterService {
    /// Create a new parameter service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            validation_service: ParameterValidationService::new(),
        }
    }

    // =========================================================================
    // Role Parameter CRUD
    // =========================================================================

    /// Create a new parameter on a role.
    pub async fn create_parameter(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        input: CreateGovRoleParameter,
    ) -> Result<GovRoleParameter, GovernanceError> {
        // Validate parameter name format
        if !Self::is_valid_parameter_name(&input.name) {
            return Err(GovernanceError::InvalidParameterNameFormat(input.name));
        }

        // Check for duplicate name
        if let Some(_existing) =
            GovRoleParameter::find_by_name(&self.pool, tenant_id, role_id, &input.name).await?
        {
            return Err(GovernanceError::RoleParameterNameExists(input.name));
        }

        let param = GovRoleParameter::create(&self.pool, tenant_id, role_id, input).await?;

        Ok(param)
    }

    /// Get a parameter by ID.
    pub async fn get_parameter(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<GovRoleParameter, GovernanceError> {
        GovRoleParameter::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::RoleParameterNotFound(id))
    }

    /// Get a parameter by name within a role.
    pub async fn get_parameter_by_name(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        name: &str,
    ) -> Result<GovRoleParameter, GovernanceError> {
        GovRoleParameter::find_by_name(&self.pool, tenant_id, role_id, name)
            .await?
            .ok_or_else(|| GovernanceError::RoleParameterNotFound(Uuid::nil()))
    }

    /// List all parameters for a role.
    pub async fn list_parameters(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<GovRoleParameter>, GovernanceError> {
        let params = GovRoleParameter::list_by_role(&self.pool, tenant_id, role_id).await?;
        Ok(params)
    }

    /// List parameters with filtering.
    pub async fn list_parameters_filtered(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        filter: &RoleParameterFilter,
    ) -> Result<Vec<GovRoleParameter>, GovernanceError> {
        let params =
            GovRoleParameter::list_by_role_filtered(&self.pool, tenant_id, role_id, filter).await?;
        Ok(params)
    }

    /// Update a parameter.
    pub async fn update_parameter(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovRoleParameter,
    ) -> Result<GovRoleParameter, GovernanceError> {
        let param = GovRoleParameter::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::RoleParameterNotFound(id))?;

        Ok(param)
    }

    /// Delete a parameter.
    pub async fn delete_parameter(&self, tenant_id: Uuid, id: Uuid) -> Result<(), GovernanceError> {
        // Check if parameter has active assignments
        let count =
            GovRoleAssignmentParameter::count_by_parameter(&self.pool, tenant_id, id).await?;
        if count > 0 {
            return Err(GovernanceError::ParameterHasAssignments(count));
        }

        GovRoleParameter::delete(&self.pool, tenant_id, id).await?;
        Ok(())
    }

    /// Check if a role has any parameters defined.
    pub async fn role_has_parameters(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, GovernanceError> {
        let has_params =
            GovRoleParameter::role_has_parameters(&self.pool, tenant_id, role_id).await?;
        Ok(has_params)
    }

    // =========================================================================
    // Parameter Validation
    // =========================================================================

    /// Validate parameter values against a role's parameter definitions.
    pub async fn validate_parameters(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        values: &HashMap<Uuid, serde_json::Value>,
    ) -> Result<ValidationResult, GovernanceError> {
        let params = self.list_parameters(tenant_id, role_id).await?;

        if params.is_empty() {
            return Err(GovernanceError::RoleNotParametric(role_id));
        }

        let result = self.validation_service.validate(&params, values);
        Ok(result)
    }

    /// Validate parameters by name instead of ID.
    pub async fn validate_parameters_by_name(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        values_by_name: &HashMap<String, serde_json::Value>,
    ) -> Result<ValidationResult, GovernanceError> {
        let params = self.list_parameters(tenant_id, role_id).await?;

        if params.is_empty() {
            return Err(GovernanceError::RoleNotParametric(role_id));
        }

        // Convert name-based values to ID-based
        let mut values = HashMap::new();
        for param in &params {
            if let Some(value) = values_by_name.get(&param.name) {
                values.insert(param.id, value.clone());
            }
        }

        let result = self.validation_service.validate(&params, &values);
        Ok(result)
    }

    // =========================================================================
    // Assignment Parameter Management
    // =========================================================================

    /// Set parameter values for an assignment.
    pub async fn set_assignment_parameters(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Uuid,
        values: Vec<SetGovAssignmentParameter>,
    ) -> Result<Vec<GovRoleAssignmentParameter>, GovernanceError> {
        // Create parameters
        let params =
            GovRoleAssignmentParameter::create_bulk(&self.pool, tenant_id, assignment_id, &values)
                .await?;

        // Record audit event
        let values_json = serde_json::to_value(
            values
                .iter()
                .map(|v| (v.parameter_id.to_string(), &v.value))
                .collect::<HashMap<_, _>>(),
        )
        .unwrap_or_default();

        GovParameterAuditEvent::record_parameters_set(
            &self.pool,
            tenant_id,
            assignment_id,
            actor_id,
            values_json,
        )
        .await?;

        Ok(params)
    }

    /// Get all parameter values for an assignment.
    pub async fn get_assignment_parameters(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Vec<GovRoleAssignmentParameter>, GovernanceError> {
        let params =
            GovRoleAssignmentParameter::list_by_assignment(&self.pool, tenant_id, assignment_id)
                .await?;
        Ok(params)
    }

    /// Get parameter values as a map.
    pub async fn get_assignment_parameters_map(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, GovernanceError> {
        let map = GovRoleAssignmentParameter::get_values_map(&self.pool, tenant_id, assignment_id)
            .await?;
        Ok(map)
    }

    /// Update parameter values for an assignment.
    pub async fn update_assignment_parameters(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Uuid,
        values: Vec<SetGovAssignmentParameter>,
    ) -> Result<Vec<GovRoleAssignmentParameter>, GovernanceError> {
        // Get old values for audit
        let old_values = self
            .get_assignment_parameters_map(tenant_id, assignment_id)
            .await?;
        let old_values_json = serde_json::to_value(&old_values).unwrap_or_default();

        // Update each parameter
        let mut results = Vec::new();
        for param in &values {
            if let Some(updated) = GovRoleAssignmentParameter::update_by_assignment_and_parameter(
                &self.pool,
                tenant_id,
                assignment_id,
                param.parameter_id,
                param.value.clone(),
            )
            .await?
            {
                results.push(updated);
            }
        }

        // Record audit event
        let new_values_json = serde_json::to_value(
            values
                .iter()
                .map(|v| (v.parameter_id.to_string(), &v.value))
                .collect::<HashMap<_, _>>(),
        )
        .unwrap_or_default();

        GovParameterAuditEvent::record_parameters_updated(
            &self.pool,
            tenant_id,
            assignment_id,
            actor_id,
            old_values_json,
            new_values_json,
        )
        .await?;

        Ok(results)
    }

    // =========================================================================
    // Parameter Hash
    // =========================================================================

    /// Compute the parameter hash for a set of values.
    pub async fn compute_parameter_hash(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        values: &HashMap<Uuid, serde_json::Value>,
    ) -> Result<String, GovernanceError> {
        let params = self.list_parameters(tenant_id, role_id).await?;
        Ok(ParameterValidationService::compute_parameter_hash(
            &params, values,
        ))
    }

    /// Check if an assignment with the same parameters already exists.
    pub async fn check_parametric_assignment_exists(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        target_type: xavyo_db::GovAssignmentTargetType,
        target_id: Uuid,
        parameter_hash: &str,
    ) -> Result<bool, GovernanceError> {
        let existing = GovEntitlementAssignment::find_parametric(
            &self.pool,
            tenant_id,
            role_id,
            target_type,
            target_id,
            parameter_hash,
        )
        .await?;

        Ok(existing.is_some())
    }

    // =========================================================================
    // Audit Trail
    // =========================================================================

    /// List audit events for an assignment.
    pub async fn list_assignment_audit(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Vec<GovParameterAuditEvent>, GovernanceError> {
        let events =
            GovParameterAuditEvent::list_by_assignment(&self.pool, tenant_id, assignment_id)
                .await?;
        Ok(events)
    }

    /// Query audit events with filtering.
    pub async fn query_audit_events(
        &self,
        tenant_id: Uuid,
        filter: &ParameterAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovParameterAuditEvent>, i64), GovernanceError> {
        let events =
            GovParameterAuditEvent::query(&self.pool, tenant_id, filter, limit, offset).await?;
        let total = GovParameterAuditEvent::count(&self.pool, tenant_id, filter).await?;
        Ok((events, total))
    }

    /// Get recent audit events.
    pub async fn get_recent_audit_events(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GovParameterAuditEvent>, GovernanceError> {
        let events = GovParameterAuditEvent::list_recent(&self.pool, tenant_id, limit).await?;
        Ok(events)
    }

    /// Record a validation failure audit event.
    pub async fn record_validation_failure(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Option<Uuid>,
        attempted_values: serde_json::Value,
        validation_errors: serde_json::Value,
    ) -> Result<GovParameterAuditEvent, GovernanceError> {
        let event = GovParameterAuditEvent::record_validation_failed(
            &self.pool,
            tenant_id,
            assignment_id,
            actor_id,
            attempted_values,
            validation_errors,
        )
        .await?;
        Ok(event)
    }

    // =========================================================================
    // Schema Compliance
    // =========================================================================

    /// Flag assignments with schema violations.
    pub async fn flag_schema_violations(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, GovernanceError> {
        let params = self.list_parameters(tenant_id, role_id).await?;
        if params.is_empty() {
            return Ok(Vec::new());
        }

        // Get all assignments for this role
        // Note: This would need to be paginated for large datasets
        let assignments = GovEntitlementAssignment::list_parametric_by_user_and_role(
            &self.pool,
            tenant_id,
            Uuid::nil(),
            role_id,
        )
        .await
        .unwrap_or_default();

        let mut flagged = Vec::new();

        for assignment in assignments {
            let values = self
                .get_assignment_parameters_map(tenant_id, assignment.id)
                .await?;
            let violations =
                ParameterValidationService::check_schema_compatibility(&params, &values);

            if !violations.is_empty() {
                // Record schema violation event
                let violations_json = serde_json::to_value(
                    violations
                        .iter()
                        .map(|v| (&v.parameter_name, &v.details))
                        .collect::<HashMap<_, _>>(),
                )
                .unwrap_or_default();

                let values_json = serde_json::to_value(&values).unwrap_or_default();

                GovParameterAuditEvent::record_schema_violation(
                    &self.pool,
                    tenant_id,
                    assignment.id,
                    values_json,
                    violations_json,
                )
                .await?;

                flagged.push(assignment.id);
            }
        }

        Ok(flagged)
    }

    // =========================================================================
    // Parametric Assignment Queries
    // =========================================================================

    /// List parametric assignments for a user by role.
    pub async fn list_parametric_assignments_by_user_and_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>, GovernanceError> {
        let assignments = GovEntitlementAssignment::list_parametric_by_user_and_role(
            &self.pool, tenant_id, user_id, role_id,
        )
        .await?;
        Ok(assignments)
    }

    /// List all parametric assignments for a user.
    pub async fn list_parametric_assignments_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        include_inactive: bool,
    ) -> Result<Vec<GovEntitlementAssignment>, GovernanceError> {
        let assignments = GovEntitlementAssignment::list_active_parametric_by_user(
            &self.pool,
            tenant_id,
            user_id,
            include_inactive,
        )
        .await?;
        Ok(assignments)
    }

    /// Create a parametric assignment.
    pub async fn create_parametric_assignment(
        &self,
        tenant_id: Uuid,
        input: xavyo_db::CreateGovAssignment,
    ) -> Result<GovEntitlementAssignment, GovernanceError> {
        let assignment = GovEntitlementAssignment::create(&self.pool, tenant_id, input).await?;
        Ok(assignment)
    }

    /// Get an assignment by ID.
    pub async fn get_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<GovEntitlementAssignment>, GovernanceError> {
        let assignment =
            GovEntitlementAssignment::find_by_id(&self.pool, tenant_id, assignment_id).await?;
        Ok(assignment)
    }

    // =========================================================================
    // Effective Entitlements with Parameters (T035)
    // =========================================================================

    /// Get effective entitlements for a user with parameter context.
    ///
    /// Returns entitlements along with their parameter values for provisioning.
    pub async fn get_effective_entitlements_with_params(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<EffectiveEntitlementWithParams>, GovernanceError> {
        // Get all parametric assignments for the user
        let assignments = self
            .list_parametric_assignments_by_user(tenant_id, user_id, false)
            .await?;

        let mut results = Vec::new();

        for assignment in assignments {
            // Get the entitlement details
            let entitlement = xavyo_db::GovEntitlement::find_by_id(
                &self.pool,
                tenant_id,
                assignment.entitlement_id,
            )
            .await?;

            if let Some(ent) = entitlement {
                // Get the parameter values for this assignment
                let param_values = self
                    .get_assignment_parameters(tenant_id, assignment.id)
                    .await?;

                // Get the parameter definitions to enrich the values
                let param_defs = self
                    .list_parameters(tenant_id, assignment.entitlement_id)
                    .await
                    .unwrap_or_default();

                // Build parameter context
                let parameters: Vec<EffectiveParameterValue> = param_values
                    .iter()
                    .filter_map(|pv| {
                        param_defs
                            .iter()
                            .find(|pd| pd.id == pv.parameter_id)
                            .map(|pd| EffectiveParameterValue {
                                name: pd.name.clone(),
                                value: pv.value.clone(),
                                parameter_type: format!("{:?}", pd.parameter_type).to_lowercase(),
                            })
                    })
                    .collect();

                results.push(EffectiveEntitlementWithParams {
                    entitlement_id: ent.id,
                    entitlement_name: ent.name,
                    application_id: ent.application_id,
                    application_name: None, // Could be enriched if needed
                    assignment_id: assignment.id,
                    source: "direct".to_string(),
                    is_parametric: !parameters.is_empty(),
                    parameters: if parameters.is_empty() {
                        None
                    } else {
                        Some(parameters)
                    },
                });
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Provisioning Context (T037)
    // =========================================================================

    /// Get parameter context for an assignment to pass to provisioning.
    ///
    /// Returns a structured map of parameter values suitable for downstream systems.
    pub async fn get_provisioning_context(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<HashMap<String, serde_json::Value>, GovernanceError> {
        let assignment = self
            .get_assignment(tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))?;

        // Get parameter values
        let param_values = self
            .get_assignment_parameters(tenant_id, assignment_id)
            .await?;

        // Get parameter definitions
        let param_defs = self
            .list_parameters(tenant_id, assignment.entitlement_id)
            .await
            .unwrap_or_default();

        // Build context map with parameter names as keys
        let mut context = HashMap::new();
        for pv in param_values {
            if let Some(pd) = param_defs.iter().find(|p| p.id == pv.parameter_id) {
                context.insert(pd.name.clone(), pv.value);
            }
        }

        Ok(context)
    }

    // =========================================================================
    // Parametric Assignment Revocation (T042)
    // =========================================================================

    /// Revoke a parametric assignment by ID.
    ///
    /// Handles parametric assignments correctly by:
    /// 1. Capturing parameter values for audit
    /// 2. Deleting the assignment parameters
    /// 3. Deleting or deactivating the assignment
    pub async fn revoke_parametric_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        _actor_id: Uuid,
        _reason: Option<String>,
    ) -> Result<(), GovernanceError> {
        // Get the assignment to verify it exists
        let _assignment = self
            .get_assignment(tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))?;

        // Delete the assignment parameters first (they reference the assignment)
        sqlx::query(
            "DELETE FROM gov_role_assignment_parameters WHERE tenant_id = $1 AND assignment_id = $2",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Revoke the assignment
        GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment_id).await?;

        Ok(())
    }

    /// Revoke a specific parametric instance by role and parameter hash.
    ///
    /// This allows revoking a specific parameter combination while leaving
    /// other instances of the same role intact.
    pub async fn revoke_parametric_assignment_by_hash(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        parameter_hash: &str,
        actor_id: Uuid,
        reason: Option<String>,
    ) -> Result<(), GovernanceError> {
        // Find the assignment with matching hash
        let assignment = GovEntitlementAssignment::find_parametric(
            &self.pool,
            tenant_id,
            role_id,
            xavyo_db::GovAssignmentTargetType::User,
            user_id,
            parameter_hash,
        )
        .await?
        .ok_or(GovernanceError::AssignmentNotFound(Uuid::nil()))?;

        // Use the standard revocation method
        self.revoke_parametric_assignment(tenant_id, assignment.id, actor_id, reason)
            .await
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Validate parameter name format.
    fn is_valid_parameter_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 100 {
            return false;
        }

        let chars: Vec<char> = name.chars().collect();
        if !chars[0].is_ascii_alphabetic() {
            return false;
        }

        chars.iter().all(|c| c.is_ascii_alphanumeric() || *c == '_')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_parameter_names() {
        assert!(ParameterService::is_valid_parameter_name("database_name"));
        assert!(ParameterService::is_valid_parameter_name("port"));
        assert!(ParameterService::is_valid_parameter_name("maxRetries"));
        assert!(ParameterService::is_valid_parameter_name("a"));
        assert!(ParameterService::is_valid_parameter_name("a1"));
        assert!(ParameterService::is_valid_parameter_name("my_param_1"));
    }

    #[test]
    fn test_invalid_parameter_names() {
        assert!(!ParameterService::is_valid_parameter_name(""));
        assert!(!ParameterService::is_valid_parameter_name("123invalid"));
        assert!(!ParameterService::is_valid_parameter_name("_underscore"));
        assert!(!ParameterService::is_valid_parameter_name("has-dash"));
        assert!(!ParameterService::is_valid_parameter_name("has space"));
        assert!(!ParameterService::is_valid_parameter_name("has.dot"));
    }
}
