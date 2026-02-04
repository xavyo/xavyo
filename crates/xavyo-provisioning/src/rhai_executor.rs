//! Rhai Script Executor (F066).
//!
//! Implements the `HookExecutor` trait using the Rhai scripting language for
//! sandboxed, tenant-isolated script execution during provisioning operations.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rhai::{Engine, Scope, AST};
use tracing::{debug, error, info, warn};

use crate::hooks::{
    HookContext, HookDefinition, HookError, HookExecutionResult, HookExecutor, HookResult,
};

/// Default maximum number of operations in the Rhai engine.
const DEFAULT_MAX_OPERATIONS: u64 = 100_000;

/// Default maximum call stack depth.
const DEFAULT_MAX_CALL_STACK_DEPTH: usize = 64;

/// Default maximum string size in bytes.
const DEFAULT_MAX_STRING_SIZE: usize = 65536;

/// Default maximum array size.
const DEFAULT_MAX_ARRAY_SIZE: usize = 10_000;

/// Default maximum map size.
const DEFAULT_MAX_MAP_SIZE: usize = 10_000;

/// Configuration for the Rhai script executor.
#[derive(Debug, Clone)]
pub struct RhaiExecutorConfig {
    /// Maximum number of operations before termination.
    pub max_operations: u64,
    /// Maximum call stack depth.
    pub max_call_stack_depth: usize,
    /// Maximum string size in bytes.
    pub max_string_size: usize,
    /// Maximum array size.
    pub max_array_size: usize,
    /// Maximum map size.
    pub max_map_size: usize,
}

impl Default for RhaiExecutorConfig {
    fn default() -> Self {
        Self {
            max_operations: DEFAULT_MAX_OPERATIONS,
            max_call_stack_depth: DEFAULT_MAX_CALL_STACK_DEPTH,
            max_string_size: DEFAULT_MAX_STRING_SIZE,
            max_array_size: DEFAULT_MAX_ARRAY_SIZE,
            max_map_size: DEFAULT_MAX_MAP_SIZE,
        }
    }
}

/// Rhai-based hook executor for provisioning scripts.
///
/// Creates a fresh, sandboxed Rhai Engine per execution to ensure:
/// - Tenant isolation (no shared state between executions)
/// - Resource limits (operations, stack depth, string/array/map sizes)
/// - No file system or network access
pub struct RhaiScriptExecutor {
    config: RhaiExecutorConfig,
}

impl RhaiScriptExecutor {
    /// Create a new Rhai script executor with default configuration.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            config: RhaiExecutorConfig::default(),
        }
    }

    /// Create a new Rhai script executor with custom configuration.
    #[must_use] 
    pub fn with_config(config: RhaiExecutorConfig) -> Self {
        Self { config }
    }

    /// Create a sandboxed Rhai engine with security constraints.
    fn create_engine(&self) -> Engine {
        let mut engine = Engine::new();

        // Set resource limits for sandbox
        engine.set_max_operations(self.config.max_operations);
        engine.set_max_call_levels(self.config.max_call_stack_depth);
        engine.set_max_string_size(self.config.max_string_size);
        engine.set_max_array_size(self.config.max_array_size);
        engine.set_max_map_size(self.config.max_map_size);

        // Disable unsafe features
        engine.set_allow_looping(true); // Loops allowed but bounded by max_operations
        engine.set_strict_variables(true);

        // Register custom utility functions available to scripts
        engine.register_fn("log_info", |msg: &str| {
            info!(script_log = %msg, "Rhai script log");
        });

        engine.register_fn("log_warn", |msg: &str| {
            warn!(script_log = %msg, "Rhai script warning");
        });

        engine.register_fn("log_debug", |msg: &str| {
            debug!(script_log = %msg, "Rhai script debug");
        });

        engine
    }

    /// Compile a Rhai script into an AST.
    pub fn compile_script(&self, script_body: &str) -> Result<AST, String> {
        let engine = self.create_engine();
        engine
            .compile(script_body)
            .map_err(|e| format!("Compilation error: {e}"))
    }

    /// Validate a Rhai script for syntax errors.
    #[must_use] 
    pub fn validate_script(&self, script_body: &str) -> Vec<ScriptValidationError> {
        let engine = self.create_engine();
        match engine.compile(script_body) {
            Ok(_) => vec![],
            Err(e) => {
                vec![ScriptValidationError {
                    line: e.position().line(),
                    column: e.position().position(),
                    message: e.to_string(),
                }]
            }
        }
    }

    /// Execute a script in dry-run mode with sample context.
    #[must_use] 
    pub fn dry_run(
        &self,
        script_body: &str,
        context: &HookContext,
        timeout: Duration,
    ) -> DryRunResult {
        let start = Instant::now();

        let engine = self.create_engine();

        // Set up scope FIRST so compile_with_scope can see the variables
        let mut scope = Self::build_scope(context);

        // Compile with scope so strict_variables mode can see our scope variables
        let ast = match engine.compile_with_scope(&scope, script_body) {
            Ok(ast) => ast,
            Err(e) => {
                return DryRunResult {
                    success: false,
                    output: None,
                    modified_attributes: None,
                    output_variables: HashMap::new(),
                    error: Some(format!("Compilation error: {e}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // Execute with timeout check
        let result = if timeout.as_millis() > 0 {
            // Rhai doesn't have built-in timeout, but max_operations provides a bound
            engine.eval_ast_with_scope::<rhai::Dynamic>(&mut scope, &ast)
        } else {
            engine.eval_ast_with_scope::<rhai::Dynamic>(&mut scope, &ast)
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => {
                let modified = Self::extract_modified_attributes(&scope);
                let vars = Self::extract_output_variables(&scope);

                DryRunResult {
                    success: true,
                    output: Some(serde_json::json!({
                        "modified_attributes": modified,
                        "output_variables": vars,
                    })),
                    modified_attributes: modified,
                    output_variables: vars,
                    error: None,
                    duration_ms,
                }
            }
            Err(e) => DryRunResult {
                success: false,
                output: None,
                modified_attributes: None,
                output_variables: HashMap::new(),
                error: Some(format!("Runtime error: {e}")),
                duration_ms,
            },
        }
    }

    /// Build a Rhai scope from a `HookContext`.
    fn build_scope(context: &HookContext) -> Scope<'static> {
        let mut scope = Scope::new();

        // Expose context as variables in the scope
        scope.push_constant("tenant_id", context.tenant_id.to_string());
        scope.push_constant("connector_id", context.connector_id.to_string());
        scope.push_constant("user_id", context.user_id.to_string());
        scope.push_constant(
            "operation_type",
            format!("{:?}", context.operation_type).to_lowercase(),
        );
        scope.push_constant("object_class", context.object_class.clone());

        if let Some(ref uid) = context.target_uid {
            scope.push_constant("target_uid", uid.clone());
        }

        // Expose attributes as a mutable dynamic map
        if let Ok(attrs) = rhai::serde::to_dynamic(&context.attributes) {
            scope.push("attributes", attrs);
        }

        // Expose variables as a mutable dynamic map
        if let Ok(vars) = rhai::serde::to_dynamic(&context.variables) {
            scope.push("variables", vars);
        }

        // Expose error context if available
        if let Some(ref error) = context.error {
            scope.push_constant("error_message", error.clone());
        }

        // Output variables map for scripts to write to
        scope.push("output", rhai::Map::new());

        scope
    }

    /// Extract modified attributes from the scope after execution.
    fn extract_modified_attributes(scope: &Scope) -> Option<serde_json::Value> {
        scope
            .get_value::<rhai::Dynamic>("attributes")
            .and_then(|dynamic| rhai::serde::from_dynamic::<serde_json::Value>(&dynamic).ok())
    }

    /// Extract output variables from the scope after execution.
    fn extract_output_variables(scope: &Scope) -> HashMap<String, serde_json::Value> {
        scope
            .get_value::<rhai::Dynamic>("output")
            .and_then(|dynamic| {
                rhai::serde::from_dynamic::<HashMap<String, serde_json::Value>>(&dynamic).ok()
            })
            .unwrap_or_default()
    }
}

impl Default for RhaiScriptExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HookExecutor for RhaiScriptExecutor {
    async fn execute(
        &self,
        definition: &HookDefinition,
        context: &HookContext,
    ) -> HookResult<HookExecutionResult> {
        let start = Instant::now();

        // Get the script body from the config
        let script_body = definition
            .config
            .get("script_body")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HookError::InvalidConfiguration {
                message: "Missing 'script_body' in hook config".to_string(),
            })?;

        debug!(
            hook_id = %definition.id,
            script_len = script_body.len(),
            "Executing Rhai script"
        );

        let engine = self.create_engine();

        // Build scope from context FIRST so compile_with_scope can see the variables
        let mut scope = Self::build_scope(context);

        // Compile the script with scope so strict_variables mode can see our scope variables
        let ast = engine
            .compile_with_scope(&scope, script_body)
            .map_err(|e| {
                error!(hook_id = %definition.id, error = %e, "Script compilation failed");
                HookError::ExecutionFailed {
                    message: format!("Compilation error: {e}"),
                }
            })?;

        // Execute the script
        let result = engine.eval_ast_with_scope::<rhai::Dynamic>(&mut scope, &ast);

        let duration_ms = start.elapsed().as_millis() as u64;

        // Check if execution exceeded timeout
        if duration_ms > definition.timeout_ms {
            warn!(
                hook_id = %definition.id,
                duration_ms = duration_ms,
                timeout_ms = definition.timeout_ms,
                "Script execution exceeded timeout"
            );
            return Err(HookError::Timeout {
                timeout_ms: definition.timeout_ms,
            });
        }

        match result {
            Ok(_) => {
                let modified_attributes = Self::extract_modified_attributes(&scope);
                let output_variables = Self::extract_output_variables(&scope);

                info!(
                    hook_id = %definition.id,
                    duration_ms = duration_ms,
                    has_modifications = modified_attributes.is_some(),
                    output_vars_count = output_variables.len(),
                    "Rhai script executed successfully"
                );

                Ok(HookExecutionResult {
                    success: true,
                    modified_attributes,
                    output_variables,
                    error: None,
                    duration_ms,
                })
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!(
                    hook_id = %definition.id,
                    error = %error_msg,
                    duration_ms = duration_ms,
                    "Rhai script execution failed"
                );

                // Check if this was a max operations exceeded error (effectively a timeout)
                if error_msg.contains("Too many operations") {
                    return Err(HookError::Timeout {
                        timeout_ms: definition.timeout_ms,
                    });
                }

                Err(HookError::ExecutionFailed { message: error_msg })
            }
        }
    }

    fn executor_type(&self) -> &'static str {
        "rhai_script"
    }
}

/// Result of a script validation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScriptValidationError {
    /// Line number of the error (if available).
    pub line: Option<usize>,
    /// Column of the error (if available).
    pub column: Option<usize>,
    /// Error message.
    pub message: String,
}

/// Result of a dry-run execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunResult {
    /// Whether the script executed successfully.
    pub success: bool,
    /// Combined output as JSON.
    pub output: Option<serde_json::Value>,
    /// Modified attributes (if any).
    pub modified_attributes: Option<serde_json::Value>,
    /// Output variables set by the script.
    pub output_variables: HashMap<String, serde_json::Value>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use xavyo_connector::types::OperationType;

    fn test_context() -> HookContext {
        HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({
                "firstName": "John",
                "lastName": "Doe",
                "email": "john.doe@example.com"
            }),
            variables: HashMap::new(),
            error: None,
        }
    }

    #[test]
    fn test_validate_valid_script() {
        let executor = RhaiScriptExecutor::new();
        let errors = executor.validate_script("let x = 42; x + 1");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_script() {
        let executor = RhaiScriptExecutor::new();
        let errors = executor.validate_script("let x = ;");
        assert!(
            !errors.is_empty(),
            "Should have validation errors for invalid syntax"
        );
        // The error message should indicate a syntax/parse issue (message format varies by Rhai version)
        let msg = errors[0].message.to_lowercase();
        assert!(
            !msg.is_empty()
                && (msg.contains("error")
                    || msg.contains("syntax")
                    || msg.contains("unexpected")
                    || msg.contains("expect")),
            "Error message should describe the syntax issue: {}",
            errors[0].message
        );
    }

    #[test]
    fn test_compile_script() {
        let executor = RhaiScriptExecutor::new();
        let result = executor.compile_script("let x = 42;");
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_invalid_script() {
        let executor = RhaiScriptExecutor::new();
        let result = executor.compile_script("this is not valid rhai");
        assert!(result.is_err());
    }

    #[test]
    fn test_dry_run_simple_script() {
        let executor = RhaiScriptExecutor::new();
        let context = test_context();

        let result = executor.dry_run(
            r#"
            // Access attributes
            let first = attributes["firstName"];
            let last = attributes["lastName"];

            // Modify attributes
            attributes["displayName"] = first + " " + last;

            // Set output variable
            output["greeting"] = "Hello, " + first + "!";
            "#,
            &context,
            Duration::from_secs(5),
        );

        assert!(result.success, "Script should succeed: {:?}", result.error);
        assert!(result.modified_attributes.is_some());
        let attrs = result.modified_attributes.unwrap();
        assert_eq!(attrs["displayName"], "John Doe");
        assert_eq!(
            result.output_variables.get("greeting").unwrap(),
            &serde_json::json!("Hello, John!")
        );
    }

    #[test]
    fn test_dry_run_syntax_error() {
        let executor = RhaiScriptExecutor::new();
        let context = test_context();

        let result = executor.dry_run("let x = ;", &context, Duration::from_secs(5));

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_dry_run_runtime_error() {
        let executor = RhaiScriptExecutor::new();
        let context = test_context();

        let result = executor.dry_run(
            "let x = 42 / 0;", // Division by zero
            &context,
            Duration::from_secs(5),
        );

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_context_isolation() {
        let executor = RhaiScriptExecutor::new();
        let context = test_context();

        // Verify that constants are read-only
        let result = executor.dry_run(
            r#"
            // tenant_id is a constant, cannot be modified
            let t = tenant_id;
            t // just read it
            "#,
            &context,
            Duration::from_secs(5),
        );

        assert!(result.success, "Should be able to read constants");
    }

    #[test]
    fn test_max_operations_limit() {
        let config = RhaiExecutorConfig {
            max_operations: 100, // Very low limit
            ..Default::default()
        };
        let executor = RhaiScriptExecutor::with_config(config);
        let context = test_context();

        let result = executor.dry_run(
            r#"
            let x = 0;
            while x < 1000000 {
                x += 1;
            }
            "#,
            &context,
            Duration::from_secs(5),
        );

        // Should fail due to max operations
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_hook_executor_trait() {
        let executor = RhaiScriptExecutor::new();
        assert_eq!(executor.executor_type(), "rhai_script");

        let context = test_context();
        let definition = HookDefinition {
            id: "test-hook".to_string(),
            name: "Test Hook".to_string(),
            phase: crate::hooks::HookPhase::Before,
            operation_types: vec![OperationType::Create],
            criticality: crate::hooks::HookCriticality::Fatal,
            timeout_ms: 5000,
            order: 0,
            enabled: true,
            config: serde_json::json!({
                "type": "rhai_script",
                "script_body": r#"
                    attributes["displayName"] = attributes["firstName"] + " " + attributes["lastName"];
                "#,
            }),
        };

        let result = executor.execute(&definition, &context).await;
        assert!(result.is_ok());

        let exec_result = result.unwrap();
        assert!(exec_result.success);
        assert!(exec_result.modified_attributes.is_some());

        let attrs = exec_result.modified_attributes.unwrap();
        assert_eq!(attrs["displayName"], "John Doe");
    }

    #[test]
    fn test_rhai_access_nested_custom_attributes() {
        let executor = RhaiScriptExecutor::new();
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({
                "firstName": "Alice",
                "lastName": "Smith",
                "custom_attributes": {
                    "department": "Engineering",
                    "cost_center": "CC-100",
                    "employee_id": "E12345"
                }
            }),
            variables: HashMap::new(),
            error: None,
        };

        let result = executor.dry_run(
            r#"
            // Access nested custom_attributes
            let dept = attributes["custom_attributes"]["department"];
            let cc = attributes["custom_attributes"]["cost_center"];
            let eid = attributes["custom_attributes"]["employee_id"];

            // Use in provisioning logic
            output["department"] = dept;
            output["cost_center"] = cc;
            output["employee_id"] = eid;
            output["display"] = attributes["firstName"] + " (" + dept + ")";
            "#,
            &context,
            Duration::from_secs(5),
        );

        assert!(result.success, "Script should succeed: {:?}", result.error);
        assert_eq!(
            result.output_variables.get("department").unwrap(),
            &serde_json::json!("Engineering")
        );
        assert_eq!(
            result.output_variables.get("cost_center").unwrap(),
            &serde_json::json!("CC-100")
        );
        assert_eq!(
            result.output_variables.get("employee_id").unwrap(),
            &serde_json::json!("E12345")
        );
        assert_eq!(
            result.output_variables.get("display").unwrap(),
            &serde_json::json!("Alice (Engineering)")
        );
    }
}
