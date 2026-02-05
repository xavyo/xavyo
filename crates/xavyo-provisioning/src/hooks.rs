//! Provisioning Hooks (Pre/Post Scripts)
//!
//! Allows execution of custom logic before and after provisioning operations.
//! Supports multiple hook types and error handling strategies.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use xavyo_connector::types::OperationType;

/// Hook execution errors.
#[derive(Debug, Error)]
pub enum HookError {
    /// Hook execution failed.
    #[error("Hook execution failed: {message}")]
    ExecutionFailed { message: String },

    /// Hook timed out.
    #[error("Hook timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Hook returned an error.
    #[error("Hook returned error: {message}")]
    HookReturnedError { message: String },

    /// Hook not found.
    #[error("Hook not found: {hook_id}")]
    NotFound { hook_id: String },

    /// Invalid hook configuration.
    #[error("Invalid hook configuration: {message}")]
    InvalidConfiguration { message: String },
}

/// Result type for hook operations.
pub type HookResult<T> = Result<T, HookError>;

/// When the hook should execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Before the operation is executed.
    Before,
    /// After the operation completes successfully.
    After,
    /// After the operation fails.
    OnError,
}

impl HookPhase {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            HookPhase::Before => "before",
            HookPhase::After => "after",
            HookPhase::OnError => "on_error",
        }
    }
}

/// How to handle hook errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookCriticality {
    /// Hook failure is fatal - abort the operation.
    Fatal,
    /// Hook failure is logged but operation continues.
    #[default]
    Partial,
    /// Hook failure is silently ignored.
    Ignore,
}

/// Context passed to hooks during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// User ID being provisioned.
    pub user_id: Uuid,

    /// Operation type.
    pub operation_type: OperationType,

    /// Object class in target system.
    pub object_class: String,

    /// Target UID (if known).
    pub target_uid: Option<String>,

    /// Operation payload/attributes.
    pub attributes: serde_json::Value,

    /// Additional context variables.
    #[serde(default)]
    pub variables: HashMap<String, serde_json::Value>,

    /// Error message (for `OnError` phase).
    #[serde(default)]
    pub error: Option<String>,
}

/// Result of hook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookExecutionResult {
    /// Whether the hook succeeded.
    pub success: bool,

    /// Modified attributes (hooks can modify the payload).
    pub modified_attributes: Option<serde_json::Value>,

    /// Output variables set by the hook.
    #[serde(default)]
    pub output_variables: HashMap<String, serde_json::Value>,

    /// Error message if failed.
    pub error: Option<String>,

    /// Execution time in milliseconds.
    pub duration_ms: u64,
}

/// A provisioning hook definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDefinition {
    /// Unique hook identifier.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// When to execute this hook.
    pub phase: HookPhase,

    /// Which operation types trigger this hook.
    pub operation_types: Vec<OperationType>,

    /// Error handling strategy.
    #[serde(default)]
    pub criticality: HookCriticality,

    /// Timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Order of execution (lower = earlier).
    #[serde(default)]
    pub order: i32,

    /// Whether the hook is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Hook-specific configuration.
    #[serde(default)]
    pub config: serde_json::Value,
}

fn default_timeout() -> u64 {
    30000 // 30 seconds
}

fn default_enabled() -> bool {
    true
}

/// Trait for hook executors.
#[async_trait]
pub trait HookExecutor: Send + Sync {
    /// Execute the hook with the given context.
    async fn execute(
        &self,
        definition: &HookDefinition,
        context: &HookContext,
    ) -> HookResult<HookExecutionResult>;

    /// Get the executor type name.
    fn executor_type(&self) -> &'static str;
}

/// Expression-based hook executor.
/// Evaluates simple expressions for common use cases.
pub struct ExpressionHookExecutor;

impl ExpressionHookExecutor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExpressionHookExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HookExecutor for ExpressionHookExecutor {
    async fn execute(
        &self,
        definition: &HookDefinition,
        context: &HookContext,
    ) -> HookResult<HookExecutionResult> {
        let start = std::time::Instant::now();

        // Get expression from config
        let expression = definition
            .config
            .get("expression")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        debug!(
            hook_id = %definition.id,
            expression = %expression,
            "Executing expression hook"
        );

        // Simple expression evaluation
        let result = evaluate_expression(expression, context)?;

        Ok(HookExecutionResult {
            success: true,
            modified_attributes: result.modified_attributes,
            output_variables: result.output_variables,
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn executor_type(&self) -> &'static str {
        "expression"
    }
}

/// HTTP webhook executor.
/// Calls external HTTP endpoints.
pub struct WebhookExecutor {
    client: reqwest::Client,
}

impl WebhookExecutor {
    /// Create a new webhook executor with the default 30 second timeout.
    ///
    /// # Errors
    ///
    /// Returns `HookError::ExecutionFailed` if the HTTP client cannot be created.
    pub fn new() -> Result<Self, HookError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| HookError::ExecutionFailed {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        Ok(Self { client })
    }

    /// Create a new webhook executor with a custom timeout.
    ///
    /// # Errors
    ///
    /// Returns `HookError::ExecutionFailed` if the HTTP client cannot be created.
    pub fn with_timeout(timeout_secs: u64) -> Result<Self, HookError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| HookError::ExecutionFailed {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HookExecutor for WebhookExecutor {
    async fn execute(
        &self,
        definition: &HookDefinition,
        context: &HookContext,
    ) -> HookResult<HookExecutionResult> {
        let start = std::time::Instant::now();

        // Get webhook URL from config
        let url = definition
            .config
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HookError::InvalidConfiguration {
                message: "Missing 'url' in webhook configuration".to_string(),
            })?;

        // Get optional headers
        let headers: HashMap<String, String> = definition
            .config
            .get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        debug!(
            hook_id = %definition.id,
            url = %url,
            "Executing webhook"
        );

        // Build request
        let mut request = self.client.post(url).json(context);

        for (key, value) in headers {
            request = request.header(&key, &value);
        }

        // Execute with timeout
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(definition.timeout_ms),
            request.send(),
        )
        .await
        .map_err(|_: tokio::time::error::Elapsed| HookError::Timeout {
            timeout_ms: definition.timeout_ms,
        })?
        .map_err(|e: reqwest::Error| HookError::ExecutionFailed {
            message: e.to_string(),
        })?;

        let status = response.status();
        let body: serde_json::Value = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| serde_json::json!({}));

        if status.is_success() {
            Ok(HookExecutionResult {
                success: true,
                modified_attributes: body.get("attributes").cloned(),
                output_variables: body
                    .get("variables")
                    .and_then(|v: &serde_json::Value| {
                        serde_json::from_value::<HashMap<String, serde_json::Value>>(v.clone()).ok()
                    })
                    .unwrap_or_default(),
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
            })
        } else {
            let error_msg = body
                .get("error")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("Webhook returned error status")
                .to_string();

            Err(HookError::HookReturnedError { message: error_msg })
        }
    }

    fn executor_type(&self) -> &'static str {
        "webhook"
    }
}

/// Simple expression evaluation result.
struct ExpressionResult {
    modified_attributes: Option<serde_json::Value>,
    output_variables: HashMap<String, serde_json::Value>,
}

/// Evaluate a simple expression.
/// Supports basic operations like:
/// - `set:attributeName=value` - Set an attribute
/// - `remove:attributeName` - Remove an attribute
/// - `validate:attributeName!=null` - Validate attribute exists
/// - `log:message` - Log a message
fn evaluate_expression(expression: &str, context: &HookContext) -> HookResult<ExpressionResult> {
    let mut modified_attrs = context.attributes.clone();
    let mut output_vars = HashMap::new();

    for line in expression.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(set_expr) = line.strip_prefix("set:") {
            // set:attributeName=value
            if let Some((attr, value)) = set_expr.split_once('=') {
                if let Some(obj) = modified_attrs.as_object_mut() {
                    obj.insert(
                        attr.trim().to_string(),
                        serde_json::Value::String(value.trim().to_string()),
                    );
                }
            }
        } else if let Some(remove_expr) = line.strip_prefix("remove:") {
            // remove:attributeName
            if let Some(obj) = modified_attrs.as_object_mut() {
                obj.remove(remove_expr.trim());
            }
        } else if let Some(validate_expr) = line.strip_prefix("validate:") {
            // validate:attributeName!=null
            if validate_expr.contains("!=null") {
                let attr = validate_expr.replace("!=null", "").trim().to_string();
                let exists = modified_attrs.get(&attr).is_some_and(|v| !v.is_null());
                if !exists {
                    return Err(HookError::HookReturnedError {
                        message: format!("Validation failed: {attr} is null or missing"),
                    });
                }
            }
        } else if let Some(log_msg) = line.strip_prefix("log:") {
            // log:message
            info!(
                hook_message = %log_msg.trim(),
                tenant_id = %context.tenant_id,
                user_id = %context.user_id,
                "Hook log"
            );
        } else if let Some(var_expr) = line.strip_prefix("var:") {
            // var:variableName=value
            if let Some((var_name, value)) = var_expr.split_once('=') {
                output_vars.insert(
                    var_name.trim().to_string(),
                    serde_json::Value::String(value.trim().to_string()),
                );
            }
        }
    }

    Ok(ExpressionResult {
        modified_attributes: Some(modified_attrs),
        output_variables: output_vars,
    })
}

/// Hook manager that coordinates hook execution.
pub struct HookManager {
    /// Registered hook executors by type.
    executors: HashMap<String, Arc<dyn HookExecutor>>,

    /// Hook definitions.
    hooks: Vec<HookDefinition>,
}

impl HookManager {
    /// Create a new hook manager with default executors.
    ///
    /// # Errors
    ///
    /// Returns `HookError` if the webhook executor HTTP client cannot be created.
    pub fn new() -> Result<Self, HookError> {
        let mut executors: HashMap<String, Arc<dyn HookExecutor>> = HashMap::new();
        executors.insert(
            "expression".to_string(),
            Arc::new(ExpressionHookExecutor::new()),
        );
        executors.insert("webhook".to_string(), Arc::new(WebhookExecutor::new()?));

        Ok(Self {
            executors,
            hooks: Vec::new(),
        })
    }

    /// Register a custom hook executor.
    pub fn register_executor(&mut self, executor_type: &str, executor: Arc<dyn HookExecutor>) {
        self.executors.insert(executor_type.to_string(), executor);
    }

    /// Add a hook definition.
    pub fn add_hook(&mut self, hook: HookDefinition) {
        self.hooks.push(hook);
        // Sort by order
        self.hooks.sort_by_key(|h| h.order);
    }

    /// Remove a hook by ID.
    pub fn remove_hook(&mut self, hook_id: &str) -> bool {
        let len_before = self.hooks.len();
        self.hooks.retain(|h| h.id != hook_id);
        self.hooks.len() < len_before
    }

    /// Get hooks for a specific phase and operation type.
    #[must_use]
    pub fn get_hooks(
        &self,
        phase: HookPhase,
        operation_type: OperationType,
    ) -> Vec<&HookDefinition> {
        self.hooks
            .iter()
            .filter(|h| {
                h.enabled && h.phase == phase && h.operation_types.contains(&operation_type)
            })
            .collect()
    }

    /// Execute all hooks for a given phase.
    #[instrument(skip(self, context), fields(phase = ?phase, operation_type = ?context.operation_type))]
    pub async fn execute_hooks(
        &self,
        phase: HookPhase,
        context: &mut HookContext,
    ) -> HookResult<Vec<HookExecutionResult>> {
        let hooks = self.get_hooks(phase, context.operation_type);

        if hooks.is_empty() {
            debug!("No hooks to execute for phase");
            return Ok(vec![]);
        }

        info!(hook_count = hooks.len(), "Executing hooks");

        let mut results = Vec::with_capacity(hooks.len());

        for hook in hooks {
            let executor_type = hook
                .config
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("expression");

            let executor = self.executors.get(executor_type).ok_or_else(|| {
                HookError::InvalidConfiguration {
                    message: format!("Unknown executor type: {executor_type}"),
                }
            })?;

            debug!(hook_id = %hook.id, executor_type = %executor_type, "Executing hook");

            match executor.execute(hook, context).await {
                Ok(result) => {
                    // Apply modified attributes if any
                    if let Some(ref modified) = result.modified_attributes {
                        context.attributes = modified.clone();
                    }

                    // Merge output variables
                    for (k, v) in &result.output_variables {
                        context.variables.insert(k.clone(), v.clone());
                    }

                    results.push(result);
                }
                Err(e) => {
                    warn!(hook_id = %hook.id, error = %e, "Hook execution failed");

                    match hook.criticality {
                        HookCriticality::Fatal => {
                            error!(hook_id = %hook.id, "Fatal hook failure, aborting operation");
                            return Err(e);
                        }
                        HookCriticality::Partial => {
                            results.push(HookExecutionResult {
                                success: false,
                                modified_attributes: None,
                                output_variables: HashMap::new(),
                                error: Some(e.to_string()),
                                duration_ms: 0,
                            });
                        }
                        HookCriticality::Ignore => {
                            debug!(hook_id = %hook.id, "Ignoring hook failure");
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

// Note: HookManager::new() returns Result, so Default is not implemented.
// Use HookManager::new()? explicitly to handle potential HTTP client creation errors.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_phase_as_str() {
        assert_eq!(HookPhase::Before.as_str(), "before");
        assert_eq!(HookPhase::After.as_str(), "after");
        assert_eq!(HookPhase::OnError.as_str(), "on_error");
    }

    #[test]
    fn test_hook_criticality_default() {
        let criticality: HookCriticality = Default::default();
        assert_eq!(criticality, HookCriticality::Partial);
    }

    #[test]
    fn test_hook_definition_defaults() {
        let json = r#"{
            "id": "test-hook",
            "name": "Test Hook",
            "phase": "before",
            "operation_types": ["create"]
        }"#;

        let hook: HookDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(hook.id, "test-hook");
        assert_eq!(hook.timeout_ms, 30000);
        assert!(hook.enabled);
        assert_eq!(hook.criticality, HookCriticality::Partial);
    }

    #[test]
    fn test_expression_set_attribute() {
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({"firstName": "John"}),
            variables: HashMap::new(),
            error: None,
        };

        let result = evaluate_expression("set:lastName=Doe", &context).unwrap();
        let attrs = result.modified_attributes.unwrap();
        assert_eq!(attrs.get("lastName").unwrap().as_str().unwrap(), "Doe");
        assert_eq!(attrs.get("firstName").unwrap().as_str().unwrap(), "John");
    }

    #[test]
    fn test_expression_remove_attribute() {
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({"firstName": "John", "tempField": "value"}),
            variables: HashMap::new(),
            error: None,
        };

        let result = evaluate_expression("remove:tempField", &context).unwrap();
        let attrs = result.modified_attributes.unwrap();
        assert!(attrs.get("tempField").is_none());
        assert!(attrs.get("firstName").is_some());
    }

    #[test]
    fn test_expression_validate_fails() {
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({"firstName": "John"}),
            variables: HashMap::new(),
            error: None,
        };

        let result = evaluate_expression("validate:email!=null", &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_expression_validate_passes() {
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({"email": "john@example.com"}),
            variables: HashMap::new(),
            error: None,
        };

        let result = evaluate_expression("validate:email!=null", &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_expression_set_variable() {
        let context = HookContext {
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            attributes: serde_json::json!({}),
            variables: HashMap::new(),
            error: None,
        };

        let result = evaluate_expression("var:homeDir=/home/john", &context).unwrap();
        assert_eq!(
            result
                .output_variables
                .get("homeDir")
                .unwrap()
                .as_str()
                .unwrap(),
            "/home/john"
        );
    }

    #[test]
    fn test_hook_manager_get_hooks() {
        let mut manager = HookManager::new().expect("Failed to create HookManager");

        manager.add_hook(HookDefinition {
            id: "before-create".to_string(),
            name: "Before Create".to_string(),
            phase: HookPhase::Before,
            operation_types: vec![OperationType::Create],
            criticality: HookCriticality::Partial,
            timeout_ms: 5000,
            order: 1,
            enabled: true,
            config: serde_json::json!({}),
        });

        manager.add_hook(HookDefinition {
            id: "after-create".to_string(),
            name: "After Create".to_string(),
            phase: HookPhase::After,
            operation_types: vec![OperationType::Create],
            criticality: HookCriticality::Partial,
            timeout_ms: 5000,
            order: 1,
            enabled: true,
            config: serde_json::json!({}),
        });

        let before_hooks = manager.get_hooks(HookPhase::Before, OperationType::Create);
        assert_eq!(before_hooks.len(), 1);
        assert_eq!(before_hooks[0].id, "before-create");

        let after_hooks = manager.get_hooks(HookPhase::After, OperationType::Create);
        assert_eq!(after_hooks.len(), 1);

        let update_hooks = manager.get_hooks(HookPhase::Before, OperationType::Update);
        assert_eq!(update_hooks.len(), 0);
    }

    #[test]
    fn test_hook_manager_remove_hook() {
        let mut manager = HookManager::new().expect("Failed to create HookManager");

        manager.add_hook(HookDefinition {
            id: "test-hook".to_string(),
            name: "Test".to_string(),
            phase: HookPhase::Before,
            operation_types: vec![OperationType::Create],
            criticality: HookCriticality::Partial,
            timeout_ms: 5000,
            order: 1,
            enabled: true,
            config: serde_json::json!({}),
        });

        assert!(manager.remove_hook("test-hook"));
        assert!(!manager.remove_hook("non-existent"));
    }
}
