//! Remediation action execution for reconciliation.
//!
//! Executes actions to resolve discrepancies detected during reconciliation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::types::{ActionResult, ActionType, RemediationDirection};

/// Result of a remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    /// Discrepancy that was remediated.
    pub discrepancy_id: Uuid,
    /// Action that was executed.
    pub action: ActionType,
    /// Result of the action.
    pub result: ActionResult,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// State before the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_state: Option<JsonValue>,
    /// State after the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_state: Option<JsonValue>,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// When the action was executed.
    pub executed_at: DateTime<Utc>,
}

impl RemediationResult {
    /// Create a successful result.
    pub fn success(discrepancy_id: Uuid, action: ActionType, dry_run: bool) -> Self {
        Self {
            discrepancy_id,
            action,
            result: ActionResult::Success,
            error_message: None,
            before_state: None,
            after_state: None,
            dry_run,
            executed_at: Utc::now(),
        }
    }

    /// Create a failure result.
    pub fn failure(discrepancy_id: Uuid, action: ActionType, error: String, dry_run: bool) -> Self {
        Self {
            discrepancy_id,
            action,
            result: ActionResult::Failure,
            error_message: Some(error),
            before_state: None,
            after_state: None,
            dry_run,
            executed_at: Utc::now(),
        }
    }

    /// Add before state.
    pub fn with_before_state(mut self, state: JsonValue) -> Self {
        self.before_state = Some(state);
        self
    }

    /// Add after state.
    pub fn with_after_state(mut self, state: JsonValue) -> Self {
        self.after_state = Some(state);
        self
    }

    /// Check if successful.
    pub fn is_success(&self) -> bool {
        matches!(self.result, ActionResult::Success)
    }

    /// Check if failed.
    pub fn is_failure(&self) -> bool {
        matches!(self.result, ActionResult::Failure)
    }
}

/// Request to execute a remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRequest {
    /// Discrepancy to remediate.
    pub discrepancy_id: Uuid,
    /// Action to execute.
    pub action: ActionType,
    /// Direction for update action.
    #[serde(default)]
    pub direction: RemediationDirection,
    /// Identity ID (required for link action).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
    /// Whether to perform a dry run.
    #[serde(default)]
    pub dry_run: bool,
}

impl RemediationRequest {
    /// Create a new remediation request.
    pub fn new(discrepancy_id: Uuid, action: ActionType) -> Self {
        Self {
            discrepancy_id,
            action,
            direction: RemediationDirection::default(),
            identity_id: None,
            dry_run: false,
        }
    }

    /// Set direction.
    pub fn with_direction(mut self, direction: RemediationDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Set identity ID for link action.
    pub fn with_identity(mut self, identity_id: Uuid) -> Self {
        self.identity_id = Some(identity_id);
        self
    }

    /// Set dry run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<(), String> {
        match self.action {
            ActionType::Link if self.identity_id.is_none() => {
                Err("identity_id is required for link action".to_string())
            }
            _ => Ok(()),
        }
    }
}

/// Request for bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemediationRequest {
    /// List of remediation items.
    pub items: Vec<BulkRemediationItem>,
    /// Whether to perform a dry run.
    #[serde(default)]
    pub dry_run: bool,
}

/// Single item in bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemediationItem {
    /// Discrepancy ID.
    pub discrepancy_id: Uuid,
    /// Action to execute.
    pub action: ActionType,
    /// Direction for update.
    #[serde(default)]
    pub direction: Option<RemediationDirection>,
    /// Identity ID for link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
}

/// Result of bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemediationResult {
    /// Individual results.
    pub results: Vec<RemediationResult>,
    /// Summary statistics.
    pub summary: BulkRemediationSummary,
}

/// Summary of bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemediationSummary {
    /// Total items processed.
    pub total: usize,
    /// Successful remediations.
    pub succeeded: usize,
    /// Failed remediations.
    pub failed: usize,
}

impl BulkRemediationResult {
    /// Create from results.
    pub fn from_results(results: Vec<RemediationResult>) -> Self {
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.is_success()).count();
        let failed = results.iter().filter(|r| r.is_failure()).count();

        Self {
            results,
            summary: BulkRemediationSummary {
                total,
                succeeded,
                failed,
            },
        }
    }
}

/// Executor for remediation actions.
pub struct RemediationExecutor {
    /// Tenant ID.
    tenant_id: Uuid,
}

impl RemediationExecutor {
    /// Create a new executor.
    pub fn new(tenant_id: Uuid) -> Self {
        Self { tenant_id }
    }

    /// Execute a create action.
    ///
    /// Creates an account in the target system based on identity data.
    pub async fn execute_create(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        connector_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Create, true);
        }

        // TODO: Implement actual provisioning via connector
        // For now, return success placeholder
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            connector_id = %connector_id,
            "Executing create action"
        );

        RemediationResult::success(discrepancy_id, ActionType::Create, false)
    }

    /// Execute an update action.
    ///
    /// Updates attributes in target system or xavyo based on direction.
    pub async fn execute_update(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        direction: RemediationDirection,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Update, true);
        }

        // TODO: Implement actual update via connector or identity service
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            direction = %direction,
            "Executing update action"
        );

        RemediationResult::success(discrepancy_id, ActionType::Update, false)
    }

    /// Execute a delete action.
    ///
    /// Deletes an account from the target system.
    pub async fn execute_delete(
        &self,
        discrepancy_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Delete, true);
        }

        // TODO: Implement actual deletion via connector
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            "Executing delete action"
        );

        RemediationResult::success(discrepancy_id, ActionType::Delete, false)
    }

    /// Execute a link action.
    ///
    /// Establishes a shadow link between identity and account.
    pub async fn execute_link(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Link, true);
        }

        // TODO: Implement shadow link creation
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            "Executing link action"
        );

        RemediationResult::success(discrepancy_id, ActionType::Link, false)
    }

    /// Execute an unlink action.
    ///
    /// Removes a shadow link between identity and account.
    pub async fn execute_unlink(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Unlink, true);
        }

        // TODO: Implement shadow link removal
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            "Executing unlink action"
        );

        RemediationResult::success(discrepancy_id, ActionType::Unlink, false)
    }

    /// Execute an inactivate identity action.
    ///
    /// Disables the identity in xavyo.
    pub async fn execute_inactivate_identity(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        if dry_run {
            return RemediationResult::success(
                discrepancy_id,
                ActionType::InactivateIdentity,
                true,
            );
        }

        // TODO: Implement identity inactivation
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            "Executing inactivate identity action"
        );

        RemediationResult::success(discrepancy_id, ActionType::InactivateIdentity, false)
    }
}

/// Preview of remediation changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPreview {
    /// Preview items.
    pub items: Vec<RemediationPreviewItem>,
    /// Summary.
    pub summary: RemediationPreviewSummary,
}

/// Single item in remediation preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPreviewItem {
    /// Discrepancy ID.
    pub discrepancy_id: Uuid,
    /// Discrepancy type.
    pub discrepancy_type: String,
    /// Suggested action.
    pub suggested_action: ActionType,
    /// What would change.
    pub would_change: JsonValue,
}

/// Summary of remediation preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPreviewSummary {
    /// Total actions.
    pub total_actions: usize,
    /// Actions by type.
    pub by_action: std::collections::HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_result_success() {
        let discrepancy_id = Uuid::new_v4();
        let result = RemediationResult::success(discrepancy_id, ActionType::Create, false);

        assert!(result.is_success());
        assert!(!result.is_failure());
        assert_eq!(result.discrepancy_id, discrepancy_id);
        assert_eq!(result.action, ActionType::Create);
        assert!(!result.dry_run);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_remediation_result_failure() {
        let discrepancy_id = Uuid::new_v4();
        let result = RemediationResult::failure(
            discrepancy_id,
            ActionType::Delete,
            "Connection refused".to_string(),
            false,
        );

        assert!(result.is_failure());
        assert!(!result.is_success());
        assert_eq!(result.error_message, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_remediation_result_with_states() {
        let discrepancy_id = Uuid::new_v4();
        let before = serde_json::json!({"email": "old@example.com"});
        let after = serde_json::json!({"email": "new@example.com"});

        let result = RemediationResult::success(discrepancy_id, ActionType::Update, false)
            .with_before_state(before.clone())
            .with_after_state(after.clone());

        assert_eq!(result.before_state, Some(before));
        assert_eq!(result.after_state, Some(after));
    }

    #[test]
    fn test_remediation_request_new() {
        let discrepancy_id = Uuid::new_v4();
        let request = RemediationRequest::new(discrepancy_id, ActionType::Create);

        assert_eq!(request.discrepancy_id, discrepancy_id);
        assert_eq!(request.action, ActionType::Create);
        assert_eq!(request.direction, RemediationDirection::XavyoToTarget);
        assert!(!request.dry_run);
    }

    #[test]
    fn test_remediation_request_validation() {
        // Link requires identity_id
        let request = RemediationRequest::new(Uuid::new_v4(), ActionType::Link);
        assert!(request.validate().is_err());

        // Link with identity_id is valid
        let request =
            RemediationRequest::new(Uuid::new_v4(), ActionType::Link).with_identity(Uuid::new_v4());
        assert!(request.validate().is_ok());

        // Create doesn't require identity_id
        let request = RemediationRequest::new(Uuid::new_v4(), ActionType::Create);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_bulk_remediation_result() {
        let results = vec![
            RemediationResult::success(Uuid::new_v4(), ActionType::Create, false),
            RemediationResult::success(Uuid::new_v4(), ActionType::Update, false),
            RemediationResult::failure(
                Uuid::new_v4(),
                ActionType::Delete,
                "Error".to_string(),
                false,
            ),
        ];

        let bulk_result = BulkRemediationResult::from_results(results);

        assert_eq!(bulk_result.summary.total, 3);
        assert_eq!(bulk_result.summary.succeeded, 2);
        assert_eq!(bulk_result.summary.failed, 1);
    }
}
