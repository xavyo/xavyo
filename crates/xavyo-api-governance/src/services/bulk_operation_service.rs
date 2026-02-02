//! Bulk state operation service for Object Lifecycle States (F052).
//!
//! This service manages bulk state operations that transition multiple objects at once.

use std::sync::Arc;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    BulkOperationFilter, BulkOperationResult, BulkOperationStatus, CreateGovBulkStateOperation,
    GovBulkStateOperation, GovLifecycleConfig, GovLifecycleTransition, LifecycleObjectType,
    MAX_BULK_OPERATION_SIZE,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    BulkOperationDetailResponse, BulkOperationListResponse, BulkOperationResponse,
    CreateBulkOperationRequest, ExecuteTransitionRequest, ListBulkOperationsQuery,
};
use crate::services::StateTransitionService;

/// Service for bulk state operation management.
pub struct BulkOperationService {
    pool: PgPool,
    state_transition_service: Arc<StateTransitionService>,
}

impl BulkOperationService {
    /// Create a new bulk operation service.
    pub fn new(pool: PgPool, state_transition_service: Arc<StateTransitionService>) -> Self {
        Self {
            pool,
            state_transition_service,
        }
    }

    /// Create a bulk state operation.
    ///
    /// Validates the request and creates a new bulk operation record.
    /// The operation will be processed asynchronously.
    pub async fn create_bulk_operation(
        &self,
        tenant_id: Uuid,
        created_by: Uuid,
        request: CreateBulkOperationRequest,
    ) -> Result<BulkOperationResponse> {
        // Validate object count
        if request.object_ids.is_empty() {
            return Err(GovernanceError::Validation(
                "At least one object ID is required".to_string(),
            ));
        }

        if request.object_ids.len() > MAX_BULK_OPERATION_SIZE as usize {
            return Err(GovernanceError::Validation(format!(
                "Maximum {} objects per bulk operation, got {}",
                MAX_BULK_OPERATION_SIZE,
                request.object_ids.len()
            )));
        }

        // Validate the transition exists and get its details
        let transition =
            GovLifecycleTransition::find_by_id(&self.pool, tenant_id, request.transition_id)
                .await?
                .ok_or(GovernanceError::LifecycleTransitionNotFound(
                    request.transition_id,
                ))?;

        // Check that we don't have too many active operations
        let active_count = GovBulkStateOperation::count_active(&self.pool, tenant_id).await?;
        if active_count >= 10 {
            return Err(GovernanceError::Validation(
                "Maximum 10 concurrent bulk operations allowed. Please wait for existing operations to complete.".to_string(),
            ));
        }

        // Create the bulk operation
        let create_input = CreateGovBulkStateOperation {
            transition_id: transition.id,
            object_ids: request.object_ids,
            requested_by: created_by,
        };

        let operation = GovBulkStateOperation::create(&self.pool, tenant_id, &create_input).await?;

        Ok(operation.into())
    }

    /// List bulk operations.
    pub async fn list_bulk_operations(
        &self,
        tenant_id: Uuid,
        params: &ListBulkOperationsQuery,
    ) -> Result<BulkOperationListResponse> {
        let filter = BulkOperationFilter {
            status: params.status,
            transition_id: params.transition_id,
            requested_by: params.requested_by,
        };

        let limit = params.limit.unwrap_or(50);
        let offset = params.offset.unwrap_or(0);

        let operations =
            GovBulkStateOperation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        let total = GovBulkStateOperation::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(BulkOperationListResponse {
            items: operations.into_iter().map(|op| op.into()).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a bulk operation by ID.
    pub async fn get_bulk_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<BulkOperationDetailResponse> {
        let operation = GovBulkStateOperation::find_by_id(&self.pool, tenant_id, operation_id)
            .await?
            .ok_or(GovernanceError::BulkStateOperationNotFound(operation_id))?;

        Ok(BulkOperationDetailResponse {
            operation: operation.clone().into(),
            results: operation.results,
        })
    }

    /// Cancel a bulk operation.
    ///
    /// Only pending operations can be cancelled. Running operations
    /// will complete their current object but stop processing further objects.
    pub async fn cancel_bulk_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
        _cancelled_by: Uuid,
    ) -> Result<BulkOperationResponse> {
        // First check if the operation exists
        let operation = GovBulkStateOperation::find_by_id(&self.pool, tenant_id, operation_id)
            .await?
            .ok_or(GovernanceError::BulkStateOperationNotFound(operation_id))?;

        // Only pending operations can be cancelled
        if operation.status != BulkOperationStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Cannot cancel operation in {:?} status. Only pending operations can be cancelled.",
                operation.status
            )));
        }

        let cancelled = GovBulkStateOperation::cancel(&self.pool, tenant_id, operation_id)
            .await?
            .ok_or(GovernanceError::BulkStateOperationNotFound(operation_id))?;

        Ok(cancelled.into())
    }

    /// Process pending bulk operations.
    ///
    /// This method processes all pending and running operations for a tenant.
    /// It's designed to be called by a background job or triggered manually.
    pub async fn process_pending_operations(&self, tenant_id: Uuid) -> Result<()> {
        // Get pending/running operations ordered by creation time
        let operations = GovBulkStateOperation::find_pending_or_running(&self.pool, 10).await?;

        for operation in operations {
            // Only process operations for this tenant
            if operation.tenant_id != tenant_id {
                continue;
            }

            self.process_single_operation(operation).await?;
        }

        Ok(())
    }

    /// Process a single bulk operation.
    async fn process_single_operation(&self, operation: GovBulkStateOperation) -> Result<()> {
        let tenant_id = operation.tenant_id;
        let operation_id = operation.id;

        // If pending, mark as running
        if operation.status == BulkOperationStatus::Pending {
            GovBulkStateOperation::mark_running(&self.pool, operation_id).await?;
        }

        // Determine object type from transition config
        let object_type = self
            .get_object_type_for_transition(tenant_id, operation.transition_id)
            .await?;

        let mut results: Vec<BulkOperationResult> = Vec::new();
        let mut success_count = 0i32;
        let mut failure_count = 0i32;

        // Process each object
        for (idx, object_id) in operation.object_ids.iter().enumerate() {
            // Check if operation was cancelled (re-fetch status)
            let current_op =
                GovBulkStateOperation::find_by_id(&self.pool, tenant_id, operation_id).await?;

            if let Some(op) = current_op {
                if op.status == BulkOperationStatus::Cancelled {
                    // Operation was cancelled, stop processing
                    break;
                }
            }

            // Execute the transition for this object
            let result = self
                .execute_single_transition(
                    tenant_id,
                    operation.requested_by,
                    operation.transition_id,
                    *object_id,
                    object_type,
                )
                .await;

            match result {
                Ok(transition_request_id) => {
                    results.push(BulkOperationResult {
                        object_id: *object_id,
                        success: true,
                        transition_request_id: Some(transition_request_id),
                        error_message: None,
                    });
                    success_count += 1;
                }
                Err(e) => {
                    results.push(BulkOperationResult {
                        object_id: *object_id,
                        success: false,
                        transition_request_id: None,
                        error_message: Some(e.to_string()),
                    });
                    failure_count += 1;
                }
            }

            // Update progress periodically (every 10 objects or at the end)
            let processed = (idx + 1) as i32;
            if processed % 10 == 0 || processed == operation.total_count {
                GovBulkStateOperation::update_progress(
                    &self.pool,
                    operation_id,
                    processed,
                    success_count,
                    failure_count,
                )
                .await?;
            }
        }

        // Mark operation as completed or failed
        let results_json = serde_json::to_value(&results).unwrap_or(json!([]));

        if failure_count > 0 && success_count == 0 {
            // All failed
            GovBulkStateOperation::mark_failed(&self.pool, operation_id, results_json).await?;
        } else {
            // Some or all succeeded
            GovBulkStateOperation::mark_completed(&self.pool, operation_id, results_json).await?;
        }

        Ok(())
    }

    /// Execute a single transition for one object.
    async fn execute_single_transition(
        &self,
        tenant_id: Uuid,
        requested_by: Uuid,
        transition_id: Uuid,
        object_id: Uuid,
        object_type: LifecycleObjectType,
    ) -> Result<Uuid> {
        let request = ExecuteTransitionRequest {
            transition_id,
            object_type,
            object_id,
            scheduled_for: None,
            reason: Some("Bulk state operation".to_string()),
        };

        let (_status, response) = self
            .state_transition_service
            .execute_transition(tenant_id, requested_by, request)
            .await?;

        Ok(response.id)
    }

    /// Get the object type for a transition.
    async fn get_object_type_for_transition(
        &self,
        tenant_id: Uuid,
        transition_id: Uuid,
    ) -> Result<LifecycleObjectType> {
        // Get the transition to find the config_id
        let transition = GovLifecycleTransition::find_by_id(&self.pool, tenant_id, transition_id)
            .await?
            .ok_or(GovernanceError::LifecycleTransitionNotFound(transition_id))?;

        // Get the config to find the object_type
        let config = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, transition.config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(
                transition.config_id,
            ))?;

        Ok(config.object_type)
    }

    /// Process all pending bulk operations across all tenants (for background job).
    pub async fn process_all_pending_operations(&self) -> Result<ProcessingStats> {
        let operations = GovBulkStateOperation::find_pending_or_running(&self.pool, 50).await?;

        let mut stats = ProcessingStats::default();

        for operation in operations {
            stats.operations_found += 1;

            match self.process_single_operation(operation).await {
                Ok(_) => stats.operations_completed += 1,
                Err(e) => {
                    stats.operations_failed += 1;
                    stats.errors.push(e.to_string());
                }
            }
        }

        Ok(stats)
    }
}

/// Statistics from processing bulk operations.
#[derive(Debug, Default)]
pub struct ProcessingStats {
    pub operations_found: usize,
    pub operations_completed: usize,
    pub operations_failed: usize,
    pub errors: Vec<String>,
}
