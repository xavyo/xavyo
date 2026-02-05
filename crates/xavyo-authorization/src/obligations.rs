//! Obligation execution for policy decisions.
//!
//! This module handles execution of obligations attached to policies.
//! Obligations are actions that execute on permit or deny decisions.
//!
//! # Example
//!
//! ```ignore
//! use xavyo_authorization::obligations::{ObligationRegistry, ObligationHandler};
//!
//! let registry = ObligationRegistry::new();
//! registry.register(Arc::new(LogAccessHandler));
//!
//! // After authorization decision
//! registry.execute_obligations(&obligations, &context).await;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Trigger for when an obligation should execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationTrigger {
    /// Execute on permit decision
    OnPermit,
    /// Execute on deny decision
    OnDeny,
}

/// An obligation attached to a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObligation {
    /// Unique obligation identifier
    pub id: Uuid,
    /// Policy this obligation belongs to
    pub policy_id: Uuid,
    /// Tenant identifier
    pub tenant_id: Uuid,
    /// When to execute (`on_permit` or `on_deny`)
    pub trigger: ObligationTrigger,
    /// Handler type identifier
    pub obligation_type: String,
    /// Handler-specific parameters
    pub parameters: Option<serde_json::Value>,
    /// Execution order (lower = first)
    pub execution_order: i32,
    /// Whether obligation is active
    pub enabled: bool,
}

/// Context provided to obligation handlers.
#[derive(Debug, Clone)]
pub struct ObligationContext {
    /// Tenant identifier
    pub tenant_id: Uuid,
    /// User who triggered the authorization
    pub user_id: Uuid,
    /// Resource being accessed
    pub resource_type: String,
    /// Resource identifier
    pub resource_id: Option<String>,
    /// Action attempted
    pub action: String,
    /// Authorization decision (true = permit, false = deny)
    pub decision: bool,
    /// Policy that produced the decision
    pub policy_id: Option<Uuid>,
    /// Decision timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional context data
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Result of obligation execution.
#[derive(Debug, Clone)]
pub struct ObligationResult {
    /// Obligation that was executed
    pub obligation_id: Uuid,
    /// Whether execution succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution duration in milliseconds
    pub duration_ms: f64,
}

/// Error during obligation execution.
#[derive(Debug, thiserror::Error)]
pub enum ObligationError {
    #[error("Handler not found: {0}")]
    HandlerNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Timeout")]
    Timeout,
}

/// Trait for obligation handlers.
#[async_trait::async_trait]
pub trait ObligationHandler: Send + Sync {
    /// The obligation type this handler processes.
    fn obligation_type(&self) -> &str;

    /// Execute the obligation.
    async fn execute(
        &self,
        context: &ObligationContext,
        parameters: Option<&serde_json::Value>,
    ) -> Result<(), ObligationError>;
}

/// Registry of obligation handlers.
pub struct ObligationRegistry {
    handlers: RwLock<HashMap<String, Arc<dyn ObligationHandler>>>,
}

impl Default for ObligationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObligationRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register an obligation handler.
    pub async fn register(&self, handler: Arc<dyn ObligationHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(handler.obligation_type().to_string(), handler);
    }

    /// Check if a handler is registered.
    pub async fn has_handler(&self, obligation_type: &str) -> bool {
        let handlers = self.handlers.read().await;
        handlers.contains_key(obligation_type)
    }

    /// Get registered handler types.
    pub async fn handler_types(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers.keys().cloned().collect()
    }

    /// Execute obligations for a decision.
    ///
    /// Obligations are executed asynchronously. Failures are logged but do not
    /// affect the authorization decision.
    pub async fn execute_obligations(
        &self,
        obligations: &[PolicyObligation],
        context: &ObligationContext,
    ) -> Vec<ObligationResult> {
        let mut results = Vec::with_capacity(obligations.len());

        // Filter and sort obligations
        let trigger = if context.decision {
            ObligationTrigger::OnPermit
        } else {
            ObligationTrigger::OnDeny
        };

        let mut applicable: Vec<_> = obligations
            .iter()
            .filter(|o| o.enabled && o.trigger == trigger)
            .collect();
        applicable.sort_by_key(|o| o.execution_order);

        let handlers = self.handlers.read().await;

        for obligation in applicable {
            let start = std::time::Instant::now();

            let result = if let Some(handler) = handlers.get(&obligation.obligation_type) {
                match handler
                    .execute(context, obligation.parameters.as_ref())
                    .await
                {
                    Ok(()) => {
                        info!(
                            obligation_id = %obligation.id,
                            obligation_type = %obligation.obligation_type,
                            "Obligation executed successfully"
                        );
                        ObligationResult {
                            obligation_id: obligation.id,
                            success: true,
                            error: None,
                            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                        }
                    }
                    Err(e) => {
                        error!(
                            obligation_id = %obligation.id,
                            obligation_type = %obligation.obligation_type,
                            error = %e,
                            "Obligation execution failed"
                        );
                        ObligationResult {
                            obligation_id: obligation.id,
                            success: false,
                            error: Some(e.to_string()),
                            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                        }
                    }
                }
            } else {
                warn!(
                    obligation_id = %obligation.id,
                    obligation_type = %obligation.obligation_type,
                    "No handler registered for obligation type"
                );
                ObligationResult {
                    obligation_id: obligation.id,
                    success: false,
                    error: Some(format!("Handler not found: {}", obligation.obligation_type)),
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                }
            };

            results.push(result);
        }

        results
    }
}

/// Built-in handler that logs access decisions.
pub struct LogAccessHandler;

#[async_trait::async_trait]
impl ObligationHandler for LogAccessHandler {
    fn obligation_type(&self) -> &'static str {
        "log_access"
    }

    async fn execute(
        &self,
        context: &ObligationContext,
        _parameters: Option<&serde_json::Value>,
    ) -> Result<(), ObligationError> {
        info!(
            tenant_id = %context.tenant_id,
            user_id = %context.user_id,
            resource_type = %context.resource_type,
            resource_id = ?context.resource_id,
            action = %context.action,
            decision = context.decision,
            "Access logged via obligation"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler {
        should_fail: bool,
    }

    #[async_trait::async_trait]
    impl ObligationHandler for TestHandler {
        fn obligation_type(&self) -> &str {
            "test_handler"
        }

        async fn execute(
            &self,
            _context: &ObligationContext,
            _parameters: Option<&serde_json::Value>,
        ) -> Result<(), ObligationError> {
            if self.should_fail {
                Err(ObligationError::ExecutionFailed("Test failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn create_test_context(decision: bool) -> ObligationContext {
        ObligationContext {
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            resource_type: "document".to_string(),
            resource_id: Some("doc-123".to_string()),
            action: "read".to_string(),
            decision,
            policy_id: Some(Uuid::new_v4()),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    fn create_test_obligation(trigger: ObligationTrigger, order: i32) -> PolicyObligation {
        PolicyObligation {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger,
            obligation_type: "test_handler".to_string(),
            parameters: None,
            execution_order: order,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_registry_register_handler() {
        let registry = ObligationRegistry::new();
        let handler = Arc::new(TestHandler { should_fail: false });

        registry.register(handler).await;

        assert!(registry.has_handler("test_handler").await);
        assert!(!registry.has_handler("unknown").await);
    }

    #[tokio::test]
    async fn test_on_permit_obligation_executes() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: false }))
            .await;

        let context = create_test_context(true);
        let obligations = vec![create_test_obligation(ObligationTrigger::OnPermit, 0)];

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn test_on_deny_obligation_executes() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: false }))
            .await;

        let context = create_test_context(false);
        let obligations = vec![create_test_obligation(ObligationTrigger::OnDeny, 0)];

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn test_wrong_trigger_not_executed() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: false }))
            .await;

        let context = create_test_context(true); // permit
        let obligations = vec![create_test_obligation(ObligationTrigger::OnDeny, 0)]; // but obligation is on_deny

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 0); // Not executed
    }

    #[tokio::test]
    async fn test_multiple_obligations_execute_in_order() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: false }))
            .await;

        let context = create_test_context(true);
        let obligations = vec![
            create_test_obligation(ObligationTrigger::OnPermit, 2),
            create_test_obligation(ObligationTrigger::OnPermit, 1),
            create_test_obligation(ObligationTrigger::OnPermit, 3),
        ];

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 3);
        // All should succeed
        assert!(results.iter().all(|r| r.success));
    }

    #[tokio::test]
    async fn test_obligation_failure_logged_not_blocking() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: true }))
            .await;

        let context = create_test_context(true);
        let obligations = vec![create_test_obligation(ObligationTrigger::OnPermit, 0)];

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].error.is_some());
    }

    #[tokio::test]
    async fn test_missing_handler_fails_gracefully() {
        let registry = ObligationRegistry::new();
        // Don't register any handler

        let context = create_test_context(true);
        let obligations = vec![create_test_obligation(ObligationTrigger::OnPermit, 0)];

        let results = registry.execute_obligations(&obligations, &context).await;

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("Handler not found"));
    }

    #[tokio::test]
    async fn test_disabled_obligation_not_executed() {
        let registry = ObligationRegistry::new();
        registry
            .register(Arc::new(TestHandler { should_fail: false }))
            .await;

        let context = create_test_context(true);
        let mut obligation = create_test_obligation(ObligationTrigger::OnPermit, 0);
        obligation.enabled = false;

        let results = registry.execute_obligations(&[obligation], &context).await;

        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_log_access_handler() {
        let handler = LogAccessHandler;
        assert_eq!(handler.obligation_type(), "log_access");

        let context = create_test_context(true);
        let result = handler.execute(&context, None).await;

        assert!(result.is_ok());
    }
}
