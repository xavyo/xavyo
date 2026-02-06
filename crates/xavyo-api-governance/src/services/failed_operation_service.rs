//! Failed Operation Retry Service for Object Lifecycle States (F052).
//!
//! This service manages retrying failed operations from the retry queue.
//! It handles exponential backoff and dead letter queue management.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use xavyo_db::{
    AuditActionType, CreateFailedOperation, CreateGovStateTransitionAudit, FailedOperationType,
    GovEntitlementAssignment, GovLifecycleFailedOperation, GovStateTransitionAudit,
    LifecycleObjectType, User,
};
use xavyo_governance::error::Result;

use crate::services::StateAccessRuleService;

/// Result of a retry operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetryResult {
    /// Total operations processed.
    pub processed: usize,
    /// Successfully retried operations.
    pub succeeded: usize,
    /// Failed operations (rescheduled for retry).
    pub rescheduled: usize,
    /// Operations moved to dead letter queue.
    pub dead_letter: usize,
}

/// Statistics from retry processing across all tenants.
#[derive(Debug, Clone, Default)]
pub struct RetryStats {
    /// Number of tenants processed.
    pub tenants_processed: usize,
    /// Total retry results.
    pub total: RetryResult,
}

/// Payload for entitlement action operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementActionPayload {
    /// The action to perform.
    pub action: String,
    /// Target user ID.
    pub user_id: Uuid,
    /// Assignment IDs to process.
    pub assignment_ids: Vec<Uuid>,
}

/// Payload for state update operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdatePayload {
    /// Target object ID.
    pub object_id: Uuid,
    /// Object type.
    pub object_type: String,
    /// Target state ID.
    pub state_id: Uuid,
}

/// Payload for audit record creation operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecordPayload {
    /// Related transition request ID.
    pub request_id: Uuid,
    /// Object ID.
    pub object_id: Uuid,
    /// Object type.
    pub object_type: String,
    /// From state name.
    pub from_state: String,
    /// To state name.
    pub to_state: String,
    /// Transition name.
    pub transition_name: String,
    /// Actor who performed the action.
    pub actor_id: Uuid,
    /// Action type.
    pub action_type: String,
    /// Entitlements before snapshot.
    pub entitlements_before: Option<JsonValue>,
    /// Entitlements after snapshot.
    pub entitlements_after: Option<JsonValue>,
    /// Additional metadata.
    pub metadata: Option<JsonValue>,
}

/// Service for failed operation retry management.
pub struct FailedOperationService {
    pool: PgPool,
    #[allow(dead_code)]
    access_rule_service: Arc<StateAccessRuleService>,
}

impl FailedOperationService {
    /// Create a new failed operation service.
    #[must_use]
    pub fn new(pool: PgPool, access_rule_service: Arc<StateAccessRuleService>) -> Self {
        Self {
            pool,
            access_rule_service,
        }
    }

    /// Queue a failed operation for retry.
    #[allow(clippy::too_many_arguments)]
    pub async fn queue_failed_operation(
        &self,
        tenant_id: Uuid,
        operation_type: FailedOperationType,
        related_request_id: Option<Uuid>,
        object_id: Uuid,
        object_type: LifecycleObjectType,
        operation_payload: serde_json::Value,
        error_message: String,
    ) -> Result<GovLifecycleFailedOperation> {
        let input = CreateFailedOperation {
            operation_type,
            related_request_id,
            object_id,
            object_type,
            operation_payload,
            error_message,
            max_retries: 5, // Default to 5 retries
        };

        let operation = GovLifecycleFailedOperation::create(&self.pool, tenant_id, input).await?;

        info!(
            operation_id = %operation.id,
            tenant_id = %tenant_id,
            operation_type = ?operation.operation_type,
            "Queued failed operation for retry"
        );

        Ok(operation)
    }

    /// Process failed operations due for retry for a specific tenant.
    pub async fn process_retries(&self, tenant_id: Uuid, batch_size: i64) -> Result<RetryResult> {
        let mut result = RetryResult::default();

        // Get operations due for retry
        let operations =
            GovLifecycleFailedOperation::find_due_for_retry(&self.pool, tenant_id, batch_size)
                .await?;

        for operation in operations {
            result.processed += 1;

            // Mark as retrying
            if let Err(e) =
                GovLifecycleFailedOperation::mark_retrying(&self.pool, tenant_id, operation.id)
                    .await
            {
                warn!(
                    operation_id = %operation.id,
                    error = %e,
                    "Failed to mark operation as retrying"
                );
                continue;
            }

            // Attempt to execute the operation
            let retry_success = match operation.operation_type {
                FailedOperationType::EntitlementAction => {
                    self.retry_entitlement_action(tenant_id, &operation).await
                }
                FailedOperationType::StateUpdate => {
                    self.retry_state_update(tenant_id, &operation).await
                }
                FailedOperationType::AuditRecord => {
                    self.retry_audit_record(tenant_id, &operation).await
                }
                FailedOperationType::Transition => {
                    // Transition retries are more complex and need special handling
                    warn!(
                        operation_id = %operation.id,
                        "Transition retry not yet implemented"
                    );
                    false
                }
            };

            if retry_success {
                // Mark as succeeded
                if let Err(e) =
                    GovLifecycleFailedOperation::mark_succeeded(&self.pool, tenant_id, operation.id)
                        .await
                {
                    error!(
                        operation_id = %operation.id,
                        error = %e,
                        "Failed to mark operation as succeeded"
                    );
                }
                result.succeeded += 1;
            } else {
                // Schedule next retry or move to dead letter
                match GovLifecycleFailedOperation::schedule_next_retry(
                    &self.pool,
                    tenant_id,
                    operation.id,
                )
                .await
                {
                    Ok(has_more_retries) => {
                        if has_more_retries {
                            result.rescheduled += 1;
                        } else {
                            result.dead_letter += 1;
                            warn!(
                                operation_id = %operation.id,
                                "Operation moved to dead letter queue after max retries"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            operation_id = %operation.id,
                            error = %e,
                            "Failed to schedule next retry"
                        );
                    }
                }
            }
        }

        Ok(result)
    }

    /// Process retries for all tenants with pending operations.
    pub async fn process_all_retries(&self, batch_size: i64) -> Result<RetryStats> {
        let mut stats = RetryStats::default();

        // Get all tenants with pending retries
        let tenant_ids =
            GovLifecycleFailedOperation::get_tenants_with_pending_retries(&self.pool).await?;

        for tenant_id in tenant_ids {
            stats.tenants_processed += 1;

            match self.process_retries(tenant_id, batch_size).await {
                Ok(result) => {
                    stats.total.processed += result.processed;
                    stats.total.succeeded += result.succeeded;
                    stats.total.rescheduled += result.rescheduled;
                    stats.total.dead_letter += result.dead_letter;
                }
                Err(e) => {
                    warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to process retries for tenant"
                    );
                }
            }
        }

        Ok(stats)
    }

    /// Retry an entitlement action operation.
    async fn retry_entitlement_action(
        &self,
        tenant_id: Uuid,
        operation: &GovLifecycleFailedOperation,
    ) -> bool {
        let payload: EntitlementActionPayload =
            match serde_json::from_value(operation.operation_payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    error!(
                        operation_id = %operation.id,
                        error = %e,
                        "Failed to parse entitlement action payload"
                    );
                    return false;
                }
            };

        let action = payload.action.as_str();
        let mut success = true;

        for assignment_id in &payload.assignment_ids {
            let result = match action {
                "pause" => {
                    GovEntitlementAssignment::suspend(&self.pool, tenant_id, *assignment_id).await
                }
                "revoke" => GovEntitlementAssignment::revoke(&self.pool, tenant_id, *assignment_id)
                    .await
                    .map(|_| None),
                "resume" => {
                    GovEntitlementAssignment::reactivate(&self.pool, tenant_id, *assignment_id)
                        .await
                }
                _ => {
                    error!(action = action, "Unknown entitlement action");
                    return false;
                }
            };

            if let Err(e) = result {
                warn!(
                    assignment_id = %assignment_id,
                    action = action,
                    error = %e,
                    "Failed to retry entitlement action"
                );
                success = false;
            }
        }

        success
    }

    /// Retry a state update operation.
    async fn retry_state_update(
        &self,
        tenant_id: Uuid,
        operation: &GovLifecycleFailedOperation,
    ) -> bool {
        debug!(
            operation_id = %operation.id,
            "Retrying state update operation"
        );

        let payload: StateUpdatePayload =
            match serde_json::from_value(operation.operation_payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    error!(
                        operation_id = %operation.id,
                        error = %e,
                        "Failed to parse state update payload"
                    );
                    return false;
                }
            };

        // Determine object type and update accordingly
        let object_type = payload.object_type.to_lowercase();
        match object_type.as_str() {
            "user" => {
                match User::update_lifecycle_state(
                    &self.pool,
                    tenant_id,
                    payload.object_id,
                    Some(payload.state_id),
                )
                .await
                {
                    Ok(Some(_)) => {
                        info!(
                            operation_id = %operation.id,
                            user_id = %payload.object_id,
                            state_id = %payload.state_id,
                            "Successfully retried state update"
                        );
                        true
                    }
                    Ok(None) => {
                        warn!(
                            operation_id = %operation.id,
                            user_id = %payload.object_id,
                            "User not found for state update retry"
                        );
                        false
                    }
                    Err(e) => {
                        warn!(
                            operation_id = %operation.id,
                            error = %e,
                            "Failed to retry state update"
                        );
                        false
                    }
                }
            }
            "entitlement" | "role" => {
                // Not yet implemented for entitlement/role objects
                warn!(
                    operation_id = %operation.id,
                    object_type = %object_type,
                    "State update retry not yet implemented for this object type"
                );
                false
            }
            _ => {
                error!(
                    operation_id = %operation.id,
                    object_type = %object_type,
                    "Unknown object type for state update"
                );
                false
            }
        }
    }

    /// Retry an audit record creation.
    async fn retry_audit_record(
        &self,
        tenant_id: Uuid,
        operation: &GovLifecycleFailedOperation,
    ) -> bool {
        debug!(
            operation_id = %operation.id,
            "Retrying audit record creation"
        );

        let payload: AuditRecordPayload =
            match serde_json::from_value(operation.operation_payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    error!(
                        operation_id = %operation.id,
                        error = %e,
                        "Failed to parse audit record payload"
                    );
                    return false;
                }
            };

        // Parse action type
        let action_type = match payload.action_type.to_lowercase().as_str() {
            "execute" => AuditActionType::Execute,
            "rollback" => AuditActionType::Rollback,
            _ => {
                error!(
                    operation_id = %operation.id,
                    action_type = %payload.action_type,
                    "Unknown action type for audit record"
                );
                return false;
            }
        };

        // Parse object type
        let object_type = match payload.object_type.to_lowercase().as_str() {
            "user" => LifecycleObjectType::User,
            "entitlement" => LifecycleObjectType::Entitlement,
            "role" => LifecycleObjectType::Role,
            _ => {
                error!(
                    operation_id = %operation.id,
                    object_type = %payload.object_type,
                    "Unknown object type for audit record"
                );
                return false;
            }
        };

        let audit_input = CreateGovStateTransitionAudit {
            request_id: payload.request_id,
            object_id: payload.object_id,
            object_type,
            from_state: payload.from_state,
            to_state: payload.to_state,
            transition_name: payload.transition_name,
            actor_id: payload.actor_id,
            action_type,
            approval_details: None,
            entitlements_before: payload.entitlements_before.unwrap_or_default(),
            entitlements_after: payload.entitlements_after.unwrap_or_default(),
            metadata: payload.metadata,
        };

        match GovStateTransitionAudit::create(&self.pool, tenant_id, &audit_input).await {
            Ok(audit) => {
                info!(
                    operation_id = %operation.id,
                    audit_id = %audit.id,
                    request_id = %payload.request_id,
                    "Successfully retried audit record creation"
                );
                true
            }
            Err(e) => {
                warn!(
                    operation_id = %operation.id,
                    error = %e,
                    "Failed to retry audit record creation"
                );
                false
            }
        }
    }

    /// Get dead letter operations for a tenant.
    pub async fn get_dead_letter_operations(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovLifecycleFailedOperation>> {
        Ok(
            GovLifecycleFailedOperation::find_dead_letter(&self.pool, tenant_id, limit, offset)
                .await?,
        )
    }

    /// Count dead letter operations for a tenant.
    pub async fn count_dead_letter_operations(&self, tenant_id: Uuid) -> Result<i64> {
        Ok(GovLifecycleFailedOperation::count_dead_letter(&self.pool, tenant_id).await?)
    }
}
