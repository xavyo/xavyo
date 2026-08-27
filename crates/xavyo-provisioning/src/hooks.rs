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
        let expression = required_hook_config_str(&definition.config, "expression")?;

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

        let headers = parse_webhook_hook_headers(&definition.config)?;

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
        let response_text =
            response
                .text()
                .await
                .map_err(|e: reqwest::Error| HookError::ExecutionFailed {
                    message: e.to_string(),
                })?;
        let body = parse_webhook_hook_body(&response_text)?;

        if status.is_success() {
            Ok(HookExecutionResult {
                success: true,
                modified_attributes: body.get("attributes").cloned(),
                output_variables: parse_webhook_hook_variables(&body)?,
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

/// Parse a webhook hook body. Garbage JSON is an error, not a fake `{}` success.
fn parse_webhook_hook_body(text: &str) -> HookResult<serde_json::Value> {
    if text.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(text).map_err(|e| HookError::ExecutionFailed {
        message: format!("Webhook hook returned non-JSON body: {e}"),
    })
}

/// Parse hook `variables`. Invalid JSON is an error, not an empty map.
/// Parse webhook hook headers. Corrupt JSON is an error, not an empty map
/// that drops configured Authorization headers.
fn parse_webhook_hook_headers(config: &serde_json::Value) -> HookResult<HashMap<String, String>> {
    match config.get("headers") {
        None | Some(serde_json::Value::Null) => Ok(HashMap::new()),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| HookError::InvalidConfiguration {
            message: format!("Invalid webhook hook headers JSON: {e}"),
        }),
    }
}

fn parse_webhook_hook_variables(
    body: &serde_json::Value,
) -> HookResult<HashMap<String, serde_json::Value>> {
    match body.get("variables") {
        None | Some(serde_json::Value::Null) => Ok(HashMap::new()),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| HookError::ExecutionFailed {
            message: format!("Webhook hook returned invalid variables JSON: {e}"),
        }),
    }
}

/// Simple expression evaluation result.
struct ExpressionResult {
    modified_attributes: Option<serde_json::Value>,
    output_variables: HashMap<String, serde_json::Value>,
}

/// Required string config field. Missing/empty must not look like a valid hook.
fn required_hook_config_str<'a>(config: &'a serde_json::Value, key: &str) -> HookResult<&'a str> {
    config
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HookError::InvalidConfiguration {
            message: format!("Missing '{key}' in hook configuration"),
        })
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
            let Some((attr, value)) = set_expr.split_once('=') else {
                return Err(HookError::InvalidConfiguration {
                    message: format!("Malformed set expression: {line}"),
                });
            };
            if let Some(obj) = modified_attrs.as_object_mut() {
                obj.insert(
                    attr.trim().to_string(),
                    serde_json::Value::String(value.trim().to_string()),
                );
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
            let Some((var_name, value)) = var_expr.split_once('=') else {
                return Err(HookError::InvalidConfiguration {
                    message: format!("Malformed var expression: {line}"),
                });
            };
            output_vars.insert(
                var_name.trim().to_string(),
                serde_json::Value::String(value.trim().to_string()),
            );
        } else {
            return Err(HookError::InvalidConfiguration {
                message: format!("Unknown hook instruction: {line}"),
            });
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
            let executor_type = required_hook_config_str(&hook.config, "type")?;

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

    #[test]
    fn webhook_hook_body_does_not_default_on_invalid_json() {
        let parsed = parse_webhook_hook_body(r#"{"attributes":{"a":1}}"#).unwrap();
        assert_eq!(parsed["attributes"]["a"], 1);
        assert!(parse_webhook_hook_body("not-json").is_err());
        assert_eq!(parse_webhook_hook_body("").unwrap(), serde_json::json!({}));
        let vars =
            parse_webhook_hook_variables(&serde_json::json!({"variables": {"k": 1}})).unwrap();
        assert_eq!(vars["k"], 1);
        assert!(parse_webhook_hook_variables(&serde_json::json!({"variables": "nope"})).is_err());
        let src = include_str!("hooks.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_webhook_hook_body(")
                && !production.contains("unwrap_or_else(|_| serde_json::json!({}))"),
            "webhook hook GET/execute must fail closed on JSON parse"
        );
    }

    #[test]
    fn webhook_hook_headers_do_not_drop_on_invalid_json() {
        let headers = parse_webhook_hook_headers(&serde_json::json!({
            "headers": {"Authorization": "Bearer secret"}
        }))
        .unwrap();
        assert_eq!(headers.get("Authorization").unwrap(), "Bearer secret");
        assert!(parse_webhook_hook_headers(&serde_json::json!({"headers": "nope"})).is_err());
        assert!(parse_webhook_hook_headers(&serde_json::json!({}))
            .unwrap()
            .is_empty());
        let src = include_str!("hooks.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_webhook_hook_headers(")
                && !production.contains("from_value(v.clone()).ok()"),
            "webhook hook headers must fail closed on JSON parse"
        );
    }

    #[test]
    fn hook_config_and_expression_do_not_default() {
        let ctx = HookContext {
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
        assert!(evaluate_expression("nope", &ctx).is_err());
        assert!(evaluate_expression("set:missing", &ctx).is_err());
        assert!(required_hook_config_str(&serde_json::json!({}), "expression").is_err());
        assert_eq!(
            required_hook_config_str(&serde_json::json!({"type": "webhook"}), "type").unwrap(),
            "webhook"
        );
        let src = include_str!("hooks.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("required_hook_config_str(")
                && !production.contains("unwrap_or(\"expression\")")
                && !production.contains(".unwrap_or(\"\")"),
            "hook type/expression must not default to empty or expression"
        );
    }
}
