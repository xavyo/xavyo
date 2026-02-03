//! Remediation action execution for reconciliation.
//!
//! Executes actions to resolve discrepancies detected during reconciliation.
//! Supports create, update, delete operations through connectors, shadow link
//! management, and identity inactivation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use uuid::Uuid;

use super::transaction::{CompletedStep, RemediationTransaction};
use super::types::{ActionResult, ActionType, RemediationDirection};
use crate::shadow::{Shadow, ShadowRepository};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{AttributeDelta, AttributeSet, Uid};
use xavyo_connector::traits::{CreateOp, DeleteOp, SearchOp, UpdateOp};

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

/// Trait for providing connector instances at runtime.
#[async_trait]
pub trait ConnectorProvider: Send + Sync {
    /// Get a connector by ID that supports create operations.
    async fn get_create_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn CreateOp>>;

    /// Get a connector by ID that supports update operations.
    async fn get_update_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn UpdateOp>>;

    /// Get a connector by ID that supports delete operations.
    async fn get_delete_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn DeleteOp>>;

    /// Get a connector by ID that supports search operations.
    async fn get_search_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn SearchOp>>;
}

/// Trait for identity service operations.
///
/// This trait abstracts identity management operations to allow the provisioning
/// engine to work with identities without direct database access.
#[async_trait]
pub trait IdentityService: Send + Sync {
    /// Create a new identity with the given attributes.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant to create the identity in
    /// * `attributes` - The initial attributes for the identity
    ///
    /// # Returns
    /// The UUID of the newly created identity
    async fn create_identity(
        &self,
        tenant_id: Uuid,
        attributes: AttributeSet,
    ) -> Result<Uuid, String>;

    /// Get identity attributes for provisioning.
    async fn get_identity_attributes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<AttributeSet, String>;

    /// Update identity with external attributes.
    async fn update_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        attributes: AttributeSet,
    ) -> Result<(), String>;

    /// Delete an identity permanently.
    ///
    /// This performs a hard delete of the identity and all associated data.
    /// For soft delete (keeping the record but marking as inactive), use `inactivate_identity`.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant containing the identity
    /// * `identity_id` - The identity to delete
    async fn delete_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), String>;

    /// Inactivate an identity (soft delete).
    ///
    /// This marks the identity as inactive but preserves the record for audit purposes.
    async fn inactivate_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), String>;

    /// Check if identity is active.
    async fn is_identity_active(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<bool, String>;

    /// Check if an identity exists.
    async fn identity_exists(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<bool, String>;
}

/// Executor for remediation actions.
pub struct RemediationExecutor<C, I>
where
    C: ConnectorProvider,
    I: IdentityService,
{
    /// Tenant ID.
    tenant_id: Uuid,
    /// Connector provider for runtime connector lookup.
    connector_provider: Arc<C>,
    /// Shadow repository for link management.
    shadow_repository: Arc<ShadowRepository>,
    /// Identity service for identity operations.
    identity_service: Arc<I>,
}

impl<C, I> RemediationExecutor<C, I>
where
    C: ConnectorProvider,
    I: IdentityService,
{
    /// Create a new executor with dependencies.
    pub fn new(
        tenant_id: Uuid,
        connector_provider: Arc<C>,
        shadow_repository: Arc<ShadowRepository>,
        identity_service: Arc<I>,
    ) -> Self {
        Self {
            tenant_id,
            connector_provider,
            shadow_repository,
            identity_service,
        }
    }

    /// Execute a create action.
    ///
    /// Creates an account in the target system based on identity data.
    pub async fn execute_create(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
        dry_run: bool,
    ) -> RemediationResult {
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            connector_id = %connector_id,
            object_class = %object_class,
            dry_run = %dry_run,
            "Executing create action"
        );

        // Get identity attributes for provisioning
        let attributes = match self
            .identity_service
            .get_identity_attributes(self.tenant_id, identity_id)
            .await
        {
            Ok(attrs) => attrs,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Create,
                    format!("Failed to get identity attributes: {}", e),
                    dry_run,
                );
            }
        };

        if dry_run {
            // Return success with expected after_state
            return RemediationResult::success(discrepancy_id, ActionType::Create, true)
                .with_after_state(serde_json::to_value(&attributes).unwrap_or_default());
        }

        // Get connector with create capability
        let connector = match self
            .connector_provider
            .get_create_connector(self.tenant_id, connector_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Create,
                    format!("Failed to get connector: {}", e),
                    false,
                );
            }
        };

        // Execute create operation
        let uid = match connector.create(object_class, attributes.clone()).await {
            Ok(uid) => uid,
            Err(e) => {
                let error_msg = format!("{} ({})", e, e.error_code());
                tracing::error!(
                    tenant_id = %self.tenant_id,
                    discrepancy_id = %discrepancy_id,
                    error = %error_msg,
                    transient = %e.is_transient(),
                    "Create operation failed"
                );
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Create,
                    error_msg,
                    false,
                );
            }
        };

        // Create shadow link for the new account
        let shadow = Shadow::new_linked(
            self.tenant_id,
            connector_id,
            identity_id,
            object_class.to_string(),
            uid.value().to_string(),
            serde_json::to_value(&attributes).unwrap_or_default(),
        );

        if let Err(e) = self.shadow_repository.upsert(&shadow).await {
            tracing::warn!(
                tenant_id = %self.tenant_id,
                discrepancy_id = %discrepancy_id,
                error = %e,
                "Failed to create shadow link after account creation"
            );
            // Account was created, but shadow link failed - still return success
            // but log the warning for manual cleanup
        }

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            target_uid = %uid.value(),
            "Create action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Create, false)
            .with_after_state(serde_json::to_value(&attributes).unwrap_or_default())
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
        object_class: &str,
        direction: RemediationDirection,
        dry_run: bool,
    ) -> RemediationResult {
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            direction = %direction,
            dry_run = %dry_run,
            "Executing update action"
        );

        // Get current shadow state for before_state capture
        let shadow = match self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Shadow not found for external UID: {}", external_uid),
                    dry_run,
                );
            }
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Failed to lookup shadow: {}", e),
                    dry_run,
                );
            }
        };

        let before_state = shadow.attributes.clone();

        match direction {
            RemediationDirection::XavyoToTarget => {
                self.update_to_target(
                    discrepancy_id,
                    identity_id,
                    external_uid,
                    connector_id,
                    object_class,
                    before_state,
                    dry_run,
                )
                .await
            }
            RemediationDirection::TargetToXavyo => {
                self.update_to_source(
                    discrepancy_id,
                    identity_id,
                    external_uid,
                    connector_id,
                    object_class,
                    before_state,
                    dry_run,
                )
                .await
            }
        }
    }

    /// Update target system with xavyo attributes.
    async fn update_to_target(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        object_class: &str,
        before_state: JsonValue,
        dry_run: bool,
    ) -> RemediationResult {
        // Get identity attributes
        let identity_attrs = match self
            .identity_service
            .get_identity_attributes(self.tenant_id, identity_id)
            .await
        {
            Ok(attrs) => attrs,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Failed to get identity attributes: {}", e),
                    dry_run,
                )
                .with_before_state(before_state);
            }
        };

        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Update, true)
                .with_before_state(before_state)
                .with_after_state(serde_json::to_value(&identity_attrs).unwrap_or_default());
        }

        // Get connector
        let connector = match self
            .connector_provider
            .get_update_connector(self.tenant_id, connector_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Failed to get connector: {}", e),
                    false,
                )
                .with_before_state(before_state);
            }
        };

        // Build attribute delta
        let mut delta = AttributeDelta::new();
        for (name, value) in identity_attrs.iter() {
            delta.replace(name.clone(), value.clone());
        }

        let uid = Uid::from_value(external_uid);

        // Execute update
        if let Err(e) = connector.update(object_class, &uid, delta).await {
            let error_msg = format!("{} ({})", e, e.error_code());
            tracing::error!(
                tenant_id = %self.tenant_id,
                discrepancy_id = %discrepancy_id,
                error = %error_msg,
                "Update to target failed"
            );
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::Update,
                error_msg,
                false,
            )
            .with_before_state(before_state);
        }

        // Update shadow with new expected state
        if let Ok(Some(mut shadow)) = self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
        {
            shadow.update_attributes(serde_json::to_value(&identity_attrs).unwrap_or_default());
            let _ = self.shadow_repository.upsert(&shadow).await;
        }

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            "Update to target completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Update, false)
            .with_before_state(before_state)
            .with_after_state(serde_json::to_value(&identity_attrs).unwrap_or_default())
    }

    /// Update xavyo with target system attributes.
    async fn update_to_source(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        object_class: &str,
        before_state: JsonValue,
        dry_run: bool,
    ) -> RemediationResult {
        // Get current target attributes
        let connector = match self
            .connector_provider
            .get_search_connector(self.tenant_id, connector_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Failed to get connector: {}", e),
                    dry_run,
                )
                .with_before_state(before_state);
            }
        };

        let uid = Uid::from_value(external_uid);
        let target_attrs = match connector.get(object_class, &uid, None).await {
            Ok(Some(attrs)) => attrs,
            Ok(None) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Object not found in target: {}", external_uid),
                    dry_run,
                )
                .with_before_state(before_state);
            }
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Update,
                    format!("Failed to get target attributes: {}", e),
                    dry_run,
                )
                .with_before_state(before_state);
            }
        };

        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Update, true)
                .with_before_state(before_state)
                .with_after_state(serde_json::to_value(&target_attrs).unwrap_or_default());
        }

        // Update identity with target attributes
        if let Err(e) = self
            .identity_service
            .update_identity(self.tenant_id, identity_id, target_attrs.clone())
            .await
        {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::Update,
                format!("Failed to update identity: {}", e),
                false,
            )
            .with_before_state(before_state);
        }

        // Update shadow
        if let Ok(Some(mut shadow)) = self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
        {
            shadow.update_attributes(serde_json::to_value(&target_attrs).unwrap_or_default());
            let _ = self.shadow_repository.upsert(&shadow).await;
        }

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            "Update to source completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Update, false)
            .with_before_state(before_state)
            .with_after_state(serde_json::to_value(&target_attrs).unwrap_or_default())
    }

    /// Execute a delete action.
    ///
    /// Deletes an account from the target system.
    pub async fn execute_delete(
        &self,
        discrepancy_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
        object_class: &str,
        dry_run: bool,
    ) -> RemediationResult {
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            dry_run = %dry_run,
            "Executing delete action"
        );

        // Get current shadow for before_state
        let shadow = self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
            .ok()
            .flatten();

        let before_state = shadow
            .as_ref()
            .map(|s| s.attributes.clone())
            .unwrap_or_default();

        if dry_run {
            return RemediationResult::success(discrepancy_id, ActionType::Delete, true)
                .with_before_state(before_state);
        }

        // Get connector
        let connector = match self
            .connector_provider
            .get_delete_connector(self.tenant_id, connector_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Delete,
                    format!("Failed to get connector: {}", e),
                    false,
                )
                .with_before_state(before_state);
            }
        };

        let uid = Uid::from_value(external_uid);

        // Execute delete
        match connector.delete(object_class, &uid).await {
            Ok(()) => {}
            Err(ConnectorError::ObjectNotFound { .. }) => {
                // Object already doesn't exist - treat as success (idempotent)
                tracing::info!(
                    tenant_id = %self.tenant_id,
                    discrepancy_id = %discrepancy_id,
                    external_uid = %external_uid,
                    "Object not found during delete - treating as success"
                );
            }
            Err(e) => {
                let error_msg = format!("{} ({})", e, e.error_code());
                tracing::error!(
                    tenant_id = %self.tenant_id,
                    discrepancy_id = %discrepancy_id,
                    error = %error_msg,
                    "Delete operation failed"
                );
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Delete,
                    error_msg,
                    false,
                )
                .with_before_state(before_state);
            }
        }

        // Mark shadow as deleted
        if let Some(mut shadow) = shadow {
            shadow.mark_deleted();
            let _ = self.shadow_repository.upsert(&shadow).await;
        }

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            "Delete action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Delete, false)
            .with_before_state(before_state)
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
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            dry_run = %dry_run,
            "Executing link action"
        );

        // Check for existing shadow
        let shadow = match self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Link,
                    format!("Shadow not found for external UID: {}", external_uid),
                    dry_run,
                );
            }
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Link,
                    format!("Failed to lookup shadow: {}", e),
                    dry_run,
                );
            }
        };

        let before_state = serde_json::json!({
            "user_id": shadow.user_id,
            "sync_situation": shadow.sync_situation.as_str(),
        });

        // Check if already linked to this identity
        if shadow.user_id == Some(identity_id) {
            return RemediationResult::success(discrepancy_id, ActionType::Link, dry_run)
                .with_before_state(before_state.clone())
                .with_after_state(before_state);
        }

        // Check if already linked to a different identity (collision)
        if let Some(existing_user_id) = shadow.user_id {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::Link,
                format!("Shadow already linked to identity: {}", existing_user_id),
                dry_run,
            )
            .with_before_state(before_state);
        }

        if dry_run {
            let after_state = serde_json::json!({
                "user_id": identity_id,
                "sync_situation": "linked",
            });
            return RemediationResult::success(discrepancy_id, ActionType::Link, true)
                .with_before_state(before_state)
                .with_after_state(after_state);
        }

        // Update shadow with link
        let mut updated_shadow = shadow;
        updated_shadow.link_to_user(identity_id);

        if let Err(e) = self.shadow_repository.upsert(&updated_shadow).await {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::Link,
                format!("Failed to update shadow: {}", e),
                false,
            )
            .with_before_state(before_state);
        }

        let after_state = serde_json::json!({
            "user_id": identity_id,
            "sync_situation": "linked",
        });

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            "Link action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Link, false)
            .with_before_state(before_state)
            .with_after_state(after_state)
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
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            connector_id = %connector_id,
            dry_run = %dry_run,
            "Executing unlink action"
        );

        // Get existing shadow
        let shadow = match self
            .shadow_repository
            .find_by_target_uid(self.tenant_id, connector_id, external_uid)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Unlink,
                    format!("Shadow not found for external UID: {}", external_uid),
                    dry_run,
                );
            }
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::Unlink,
                    format!("Failed to lookup shadow: {}", e),
                    dry_run,
                );
            }
        };

        let before_state = serde_json::json!({
            "user_id": shadow.user_id,
            "sync_situation": shadow.sync_situation.as_str(),
        });

        // Check if already unlinked
        if shadow.user_id.is_none() {
            return RemediationResult::success(discrepancy_id, ActionType::Unlink, dry_run)
                .with_before_state(before_state.clone())
                .with_after_state(before_state);
        }

        if dry_run {
            let after_state = serde_json::json!({
                "user_id": null,
                "sync_situation": "unlinked",
            });
            return RemediationResult::success(discrepancy_id, ActionType::Unlink, true)
                .with_before_state(before_state)
                .with_after_state(after_state);
        }

        // Update shadow to unlink
        let mut updated_shadow = shadow;
        updated_shadow.unlink();

        if let Err(e) = self.shadow_repository.upsert(&updated_shadow).await {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::Unlink,
                format!("Failed to update shadow: {}", e),
                false,
            )
            .with_before_state(before_state);
        }

        let after_state = serde_json::json!({
            "user_id": null,
            "sync_situation": "unlinked",
        });

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            external_uid = %external_uid,
            "Unlink action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::Unlink, false)
            .with_before_state(before_state)
            .with_after_state(after_state)
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
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            dry_run = %dry_run,
            "Executing inactivate identity action"
        );

        // Check current identity status
        let is_active = match self
            .identity_service
            .is_identity_active(self.tenant_id, identity_id)
            .await
        {
            Ok(active) => active,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::InactivateIdentity,
                    format!("Failed to check identity status: {}", e),
                    dry_run,
                );
            }
        };

        let before_state = serde_json::json!({
            "identity_id": identity_id,
            "is_active": is_active,
        });

        // Already inactive - idempotent success
        if !is_active {
            return RemediationResult::success(
                discrepancy_id,
                ActionType::InactivateIdentity,
                dry_run,
            )
            .with_before_state(before_state.clone())
            .with_after_state(before_state);
        }

        if dry_run {
            let after_state = serde_json::json!({
                "identity_id": identity_id,
                "is_active": false,
            });
            return RemediationResult::success(
                discrepancy_id,
                ActionType::InactivateIdentity,
                true,
            )
            .with_before_state(before_state)
            .with_after_state(after_state);
        }

        // Inactivate the identity
        if let Err(e) = self
            .identity_service
            .inactivate_identity(self.tenant_id, identity_id)
            .await
        {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::InactivateIdentity,
                format!("Failed to inactivate identity: {}", e),
                false,
            )
            .with_before_state(before_state);
        }

        let after_state = serde_json::json!({
            "identity_id": identity_id,
            "is_active": false,
        });

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            "Inactivate identity action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::InactivateIdentity, false)
            .with_before_state(before_state)
            .with_after_state(after_state)
    }

    /// Execute a create identity action via identity service.
    ///
    /// Creates a new identity in xavyo based on attributes from an external source.
    /// This is used when discovering orphan accounts that should be correlated.
    pub async fn execute_create_identity(
        &self,
        discrepancy_id: Uuid,
        attributes: AttributeSet,
        dry_run: bool,
    ) -> RemediationResult {
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            dry_run = %dry_run,
            "Executing create identity action"
        );

        // Build before state (identity doesn't exist yet)
        let before_state = serde_json::json!({
            "identity_exists": false,
        });

        if dry_run {
            // In dry-run mode, we just preview what would happen
            let after_state = serde_json::json!({
                "identity_exists": true,
                "identity_id": "would-be-generated",
                "attributes": serde_json::to_value(&attributes).unwrap_or_default(),
            });

            return RemediationResult::success(discrepancy_id, ActionType::CreateIdentity, true)
                .with_before_state(before_state)
                .with_after_state(after_state);
        }

        // Actually create the identity via identity service
        let identity_id = match self
            .identity_service
            .create_identity(self.tenant_id, attributes.clone())
            .await
        {
            Ok(id) => id,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::CreateIdentity,
                    format!("Failed to create identity: {}", e),
                    false,
                )
                .with_before_state(before_state);
            }
        };

        let after_state = serde_json::json!({
            "identity_exists": true,
            "identity_id": identity_id,
            "attributes": serde_json::to_value(&attributes).unwrap_or_default(),
        });

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            "Create identity action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::CreateIdentity, false)
            .with_before_state(before_state)
            .with_after_state(after_state)
    }

    /// Execute a delete identity action.
    ///
    /// Permanently deletes an identity from xavyo. This is a hard delete
    /// and should only be used when the identity needs to be completely removed.
    /// For soft delete (keeping audit trail), use `execute_inactivate_identity`.
    pub async fn execute_delete_identity(
        &self,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        dry_run: bool,
    ) -> RemediationResult {
        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            dry_run = %dry_run,
            "Executing delete identity action"
        );

        // Check if identity exists
        let exists = match self
            .identity_service
            .identity_exists(self.tenant_id, identity_id)
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                return RemediationResult::failure(
                    discrepancy_id,
                    ActionType::DeleteIdentity,
                    format!("Failed to check identity existence: {}", e),
                    dry_run,
                );
            }
        };

        // Get current identity state for before_state capture
        let before_state = if exists {
            match self
                .identity_service
                .get_identity_attributes(self.tenant_id, identity_id)
                .await
            {
                Ok(attrs) => serde_json::json!({
                    "identity_id": identity_id,
                    "exists": true,
                    "attributes": serde_json::to_value(&attrs).unwrap_or_default(),
                }),
                Err(_) => serde_json::json!({
                    "identity_id": identity_id,
                    "exists": true,
                }),
            }
        } else {
            serde_json::json!({
                "identity_id": identity_id,
                "exists": false,
            })
        };

        // Identity doesn't exist - idempotent success
        if !exists {
            return RemediationResult::success(discrepancy_id, ActionType::DeleteIdentity, dry_run)
                .with_before_state(before_state.clone())
                .with_after_state(before_state);
        }

        if dry_run {
            let after_state = serde_json::json!({
                "identity_id": identity_id,
                "exists": false,
            });

            return RemediationResult::success(discrepancy_id, ActionType::DeleteIdentity, true)
                .with_before_state(before_state)
                .with_after_state(after_state);
        }

        // Actually delete the identity
        if let Err(e) = self
            .identity_service
            .delete_identity(self.tenant_id, identity_id)
            .await
        {
            return RemediationResult::failure(
                discrepancy_id,
                ActionType::DeleteIdentity,
                format!("Failed to delete identity: {}", e),
                false,
            )
            .with_before_state(before_state);
        }

        let after_state = serde_json::json!({
            "identity_id": identity_id,
            "exists": false,
        });

        tracing::info!(
            tenant_id = %self.tenant_id,
            discrepancy_id = %discrepancy_id,
            identity_id = %identity_id,
            "Delete identity action completed successfully"
        );

        RemediationResult::success(discrepancy_id, ActionType::DeleteIdentity, false)
            .with_before_state(before_state)
            .with_after_state(after_state)
    }

    /// Begin a new remediation transaction.
    pub fn begin_transaction(&self) -> RemediationTransaction {
        RemediationTransaction::new(self.tenant_id)
    }

    /// Execute a create action within a transaction.
    pub async fn execute_create_in_tx(
        &self,
        tx: &mut RemediationTransaction,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
    ) -> RemediationResult {
        let result = self
            .execute_create(
                discrepancy_id,
                identity_id,
                connector_id,
                object_class,
                false,
            )
            .await;

        if result.is_success() {
            // Record step for potential rollback
            let step = CompletedStep::new(
                ActionType::Create,
                result
                    .after_state
                    .as_ref()
                    .and_then(|s| s.get("uid").and_then(|v| v.as_str()))
                    .unwrap_or("unknown"),
            )
            .with_connector(connector_id)
            .with_rollback(ActionType::Delete)
            .with_rollback_context(serde_json::json!({
                "object_class": object_class,
            }));

            tx.add_step(step);
        }

        result
    }

    /// Execute a link action within a transaction.
    pub async fn execute_link_in_tx(
        &self,
        tx: &mut RemediationTransaction,
        discrepancy_id: Uuid,
        identity_id: Uuid,
        external_uid: &str,
        connector_id: Uuid,
    ) -> RemediationResult {
        let result = self
            .execute_link(
                discrepancy_id,
                identity_id,
                external_uid,
                connector_id,
                false,
            )
            .await;

        if result.is_success() {
            let step = CompletedStep::new(ActionType::Link, external_uid)
                .with_connector(connector_id)
                .with_before_state(result.before_state.clone().unwrap_or_default())
                .with_rollback(ActionType::Unlink)
                .with_rollback_context(serde_json::json!({
                    "identity_id": identity_id,
                }));

            tx.add_step(step);
        }

        result
    }

    /// Rollback a transaction by executing inverse operations.
    pub async fn rollback_transaction(&self, tx: &mut RemediationTransaction) {
        let tx_id = tx.id;

        // Collect steps info for iteration to avoid borrow issues
        let steps_info: Vec<_> = tx
            .steps
            .iter()
            .rev()
            .map(|step| {
                (
                    step.action,
                    step.target_id.clone(),
                    step.connector_id,
                    step.rollback_action,
                    step.rollback_context.clone(),
                )
            })
            .collect();

        let mut rollback_errors = Vec::new();

        for (idx, (action, target_id, connector_id, rollback_action, rollback_context)) in
            steps_info.into_iter().enumerate()
        {
            if let Some(inverse_action) = rollback_action {
                tracing::info!(
                    tenant_id = %self.tenant_id,
                    transaction_id = %tx_id,
                    step_index = idx,
                    original_action = %action,
                    rollback_action = %inverse_action,
                    target_id = %target_id,
                    "Rolling back step"
                );

                let rollback_result = match inverse_action {
                    ActionType::Delete => {
                        if let Some(conn_id) = connector_id {
                            let object_class = rollback_context
                                .as_ref()
                                .and_then(|c| c.get("object_class").and_then(|v| v.as_str()))
                                .unwrap_or("user");

                            self.execute_delete(
                                Uuid::new_v4(), // Rollback doesn't have a discrepancy
                                &target_id,
                                conn_id,
                                object_class,
                                false,
                            )
                            .await
                        } else {
                            RemediationResult::failure(
                                Uuid::new_v4(),
                                inverse_action,
                                "No connector ID for rollback".to_string(),
                                false,
                            )
                        }
                    }
                    ActionType::Unlink => {
                        if let Some(conn_id) = connector_id {
                            let identity_id = rollback_context
                                .as_ref()
                                .and_then(|c| c.get("identity_id").and_then(|v| v.as_str()))
                                .and_then(|s| Uuid::parse_str(s).ok())
                                .unwrap_or_default();

                            self.execute_unlink(
                                Uuid::new_v4(),
                                identity_id,
                                &target_id,
                                conn_id,
                                false,
                            )
                            .await
                        } else {
                            RemediationResult::failure(
                                Uuid::new_v4(),
                                inverse_action,
                                "No connector ID for rollback".to_string(),
                                false,
                            )
                        }
                    }
                    _ => {
                        tracing::warn!(
                            transaction_id = %tx_id,
                            action = %inverse_action,
                            "Rollback not implemented for action type"
                        );
                        continue;
                    }
                };

                if rollback_result.is_failure() {
                    rollback_errors.push((
                        idx,
                        inverse_action,
                        rollback_result.error_message.unwrap_or_default(),
                    ));
                }
            }
        }

        // Record errors and mark as rolled back
        for (idx, action, error) in rollback_errors {
            tx.record_rollback_error(idx, action, error);
        }

        tx.mark_rolled_back();
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
