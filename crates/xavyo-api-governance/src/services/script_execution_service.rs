//! Script Execution Service (F066).
//!
//! Orchestrates script validation, dry-run testing, and execution logging.

use std::collections::HashMap;
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateExecutionLog, ExecutionStatus, GovHookPhase, GovScriptExecutionLog, GovScriptVersion,
    ScriptOperationType,
};
use xavyo_governance::error::{GovernanceError, Result};
use xavyo_provisioning::{DryRunResult, HookContext, RhaiScriptExecutor, ScriptValidationError};

/// Service for script execution, validation, and dry-run testing.
pub struct ScriptExecutionService {
    pool: PgPool,
    executor: RhaiScriptExecutor,
}

/// Validation result for a script.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ScriptValidationError>,
}

/// Dry-run execution result with logging.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunExecutionResult {
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub log_id: Option<Uuid>,
}

impl ScriptExecutionService {
    /// Create a new script execution service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            executor: RhaiScriptExecutor::new(),
        }
    }

    /// Validate a script for syntax errors (without executing it).
    #[must_use]
    pub fn validate_script(&self, script_body: &str) -> ValidationResult {
        let errors = self.executor.validate_script(script_body);
        ValidationResult {
            valid: errors.is_empty(),
            errors,
        }
    }

    /// Execute a dry-run of a script with sample context.
    pub async fn dry_run(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        version_number: i32,
        context_data: serde_json::Value,
        timeout_seconds: i32,
    ) -> Result<DryRunExecutionResult> {
        // Get the script version
        let version = GovScriptVersion::get_by_script_and_version(
            &self.pool,
            script_id,
            version_number,
            tenant_id,
        )
        .await?
        .ok_or(GovernanceError::ScriptVersionNotFound(
            script_id,
            version_number,
        ))?;

        // Build a HookContext from the sample data
        let context = build_hook_context_from_json(&context_data, tenant_id)?;

        // Execute dry-run
        let timeout = Duration::from_secs(timeout_seconds as u64);
        let result = self
            .executor
            .dry_run(&version.script_body, &context, timeout);

        // Log the dry-run execution
        let status = if result.success {
            ExecutionStatus::Success
        } else if result
            .error
            .as_ref()
            .is_some_and(|e| e.contains("Too many operations"))
        {
            ExecutionStatus::Timeout
        } else {
            ExecutionStatus::Failure
        };

        let log = GovScriptExecutionLog::create(
            &self.pool,
            CreateExecutionLog {
                tenant_id,
                script_id: Some(script_id),
                binding_id: None,
                connector_id: context.connector_id,
                script_version: version_number,
                hook_phase: GovHookPhase::Before,
                operation_type: ScriptOperationType::Create,
                execution_status: status,
                input_context: Some(context_data),
                output_result: result.output.clone(),
                error_message: result.error.clone(),
                duration_ms: result.duration_ms as i64,
                dry_run: true,
            },
        )
        .await?;

        Ok(DryRunExecutionResult {
            success: result.success,
            output: result.output,
            error: result.error,
            duration_ms: result.duration_ms,
            log_id: Some(log.id),
        })
    }

    /// Validate a raw script body (not yet saved).
    #[must_use]
    pub fn validate_raw_script(&self, script_body: &str) -> ValidationResult {
        self.validate_script(script_body)
    }

    /// Dry-run a raw script body (not yet saved) with sample context.
    pub fn dry_run_raw(
        &self,
        script_body: &str,
        context_data: serde_json::Value,
        tenant_id: Uuid,
        timeout_seconds: i32,
    ) -> Result<DryRunResult> {
        let context = build_hook_context_from_json(&context_data, tenant_id)?;
        let timeout = Duration::from_secs(timeout_seconds as u64);
        Ok(self.executor.dry_run(script_body, &context, timeout))
    }

    /// Log a script execution result (called by the provisioning engine after hook execution).
    pub async fn log_execution(
        &self,
        tenant_id: Uuid,
        script_id: Option<Uuid>,
        binding_id: Option<Uuid>,
        connector_id: Uuid,
        script_version: i32,
        hook_phase: GovHookPhase,
        operation_type: ScriptOperationType,
        execution_status: ExecutionStatus,
        input_context: Option<serde_json::Value>,
        output_result: Option<serde_json::Value>,
        error_message: Option<String>,
        duration_ms: i64,
    ) -> Result<GovScriptExecutionLog> {
        let log = GovScriptExecutionLog::create(
            &self.pool,
            CreateExecutionLog {
                tenant_id,
                script_id,
                binding_id,
                connector_id,
                script_version,
                hook_phase,
                operation_type,
                execution_status,
                input_context,
                output_result,
                error_message,
                duration_ms,
                dry_run: false,
            },
        )
        .await?;
        Ok(log)
    }
}

/// Build a `HookContext` from a JSON sample context.
/// Invalid UUIDs, unknown operations, and corrupt variables must fail closed.
fn build_hook_context_from_json(data: &serde_json::Value, tenant_id: Uuid) -> Result<HookContext> {
    use xavyo_connector::types::OperationType;

    let connector_id = parse_required_uuid(data, "connector_id")?;
    let user_id = parse_required_uuid(data, "user_id")?;

    let operation_type = match data.get("operation_type").and_then(|v| v.as_str()) {
        Some("create") => OperationType::Create,
        Some("update") => OperationType::Update,
        Some("delete") => OperationType::Delete,
        Some(other) => {
            return Err(GovernanceError::Validation(format!(
                "Invalid operation_type: {other}"
            )));
        }
        None => {
            return Err(GovernanceError::Validation(
                "operation_type is required".to_string(),
            ));
        }
    };

    let object_class = data
        .get("object_class")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GovernanceError::Validation("object_class is required".to_string()))?
        .to_string();

    let target_uid = data
        .get("target_uid")
        .and_then(|v| v.as_str())
        .map(String::from);

    let attributes = data
        .get("attributes")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let variables = match data.get("variables") {
        None | Some(serde_json::Value::Null) => HashMap::new(),
        Some(v) => serde_json::from_value(v.clone()).map_err(GovernanceError::from)?,
    };

    Ok(HookContext {
        tenant_id,
        connector_id,
        user_id,
        operation_type,
        object_class,
        target_uid,
        attributes,
        variables,
        error: None,
    })
}

fn parse_required_uuid(data: &serde_json::Value, field: &str) -> Result<Uuid> {
    let raw = data
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| GovernanceError::Validation(format!("{field} is required")))?;
    Uuid::parse_str(raw).map_err(|_| GovernanceError::Validation(format!("Invalid {field} UUID")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_context_does_not_invent_ids_or_default_to_create() {
        let tenant = Uuid::new_v4();
        assert!(build_hook_context_from_json(&serde_json::json!({}), tenant).is_err());
        assert!(build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": "not-a-uuid",
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "create",
                "object_class": "user"
            }),
            tenant
        )
        .is_err());
        assert!(build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "upsert",
                "object_class": "user"
            }),
            tenant
        )
        .is_err());
        assert!(build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "create",
                "object_class": "user",
                "variables": "nope"
            }),
            tenant
        )
        .is_err());
        assert!(build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "create"
            }),
            tenant
        )
        .is_err());
        assert!(build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "create",
                "object_class": "  "
            }),
            tenant
        )
        .is_err());

        let ctx = build_hook_context_from_json(
            &serde_json::json!({
                "connector_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string(),
                "operation_type": "delete",
                "object_class": "group"
            }),
            tenant,
        )
        .unwrap();
        assert_eq!(
            ctx.operation_type,
            xavyo_connector::types::OperationType::Delete
        );
        assert_eq!(ctx.object_class, "group");

        let src = include_str!("script_execution_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("unwrap_or_else(Uuid::new_v4)")
                && !production.contains("_ => OperationType::Create")
                && !production.contains("unwrap_or(\"user\")"),
            "script dry-run must not invent actors, object_class, or treat unknown ops as Create"
        );
    }
}
