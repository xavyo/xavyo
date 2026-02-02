//! Approval workflow service for governance API.
//!
//! Handles workflow configuration and management.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovApprovalStep, CreateGovApprovalWorkflow, GovApprovalStep, GovApprovalWorkflow,
    GovApproverType, UpdateGovApprovalWorkflow, WorkflowFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Maximum number of steps allowed in a workflow.
const MAX_WORKFLOW_STEPS: usize = 5;

/// Service for approval workflow operations.
pub struct ApprovalWorkflowService {
    pool: PgPool,
}

impl ApprovalWorkflowService {
    /// Create a new approval workflow service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List workflows for a tenant.
    pub async fn list_workflows(
        &self,
        tenant_id: Uuid,
        is_active: Option<bool>,
        is_default: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<WorkflowWithSteps>, i64)> {
        let filter = WorkflowFilter {
            is_active,
            is_default,
        };

        let workflows =
            GovApprovalWorkflow::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovApprovalWorkflow::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let mut result = Vec::with_capacity(workflows.len());
        for workflow in workflows {
            let steps = GovApprovalStep::find_by_workflow(&self.pool, workflow.id).await?;
            result.push(WorkflowWithSteps { workflow, steps });
        }

        Ok((result, total))
    }

    /// Get a specific workflow by ID.
    pub async fn get_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<WorkflowWithSteps> {
        let workflow = GovApprovalWorkflow::find_by_id(&self.pool, tenant_id, workflow_id)
            .await?
            .ok_or(GovernanceError::WorkflowNotFound(workflow_id))?;

        let steps = GovApprovalStep::find_by_workflow(&self.pool, workflow.id).await?;

        Ok(WorkflowWithSteps { workflow, steps })
    }

    /// Create a new workflow with steps.
    pub async fn create_workflow(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        is_default: bool,
        steps: Vec<CreateStepInput>,
    ) -> Result<WorkflowWithSteps> {
        // Validate step count
        if steps.is_empty() || steps.len() > MAX_WORKFLOW_STEPS {
            return Err(GovernanceError::InvalidWorkflowSteps);
        }

        // Validate steps
        for step in &steps {
            self.validate_step(step)?;
        }

        // Check for duplicate name
        if GovApprovalWorkflow::find_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::WorkflowNameExists(name));
        }

        // Create workflow
        let workflow_input = CreateGovApprovalWorkflow {
            name,
            description,
            is_default,
        };

        let workflow = GovApprovalWorkflow::create(&self.pool, tenant_id, workflow_input).await?;

        // Create steps
        let mut created_steps = Vec::with_capacity(steps.len());
        for (i, step) in steps.into_iter().enumerate() {
            let step_input = CreateGovApprovalStep {
                step_order: (i + 1) as i32,
                approver_type: step.approver_type,
                specific_approvers: step.specific_approvers,
                escalation_enabled: false, // Default to disabled, can be configured later via F054
            };

            let created = GovApprovalStep::create(&self.pool, workflow.id, step_input).await?;
            created_steps.push(created);
        }

        Ok(WorkflowWithSteps {
            workflow,
            steps: created_steps,
        })
    }

    /// Update an existing workflow.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        name: Option<String>,
        description: Option<String>,
        is_default: Option<bool>,
        is_active: Option<bool>,
        steps: Option<Vec<CreateStepInput>>,
    ) -> Result<WorkflowWithSteps> {
        // Verify workflow exists
        let existing = self.get_workflow(tenant_id, workflow_id).await?;

        // Check for name conflict if updating name
        if let Some(ref new_name) = name {
            if let Some(other) =
                GovApprovalWorkflow::find_by_name(&self.pool, tenant_id, new_name).await?
            {
                if other.id != workflow_id {
                    return Err(GovernanceError::WorkflowNameExists(new_name.clone()));
                }
            }
        }

        // Validate new steps if provided
        if let Some(ref new_steps) = steps {
            if new_steps.is_empty() || new_steps.len() > MAX_WORKFLOW_STEPS {
                return Err(GovernanceError::InvalidWorkflowSteps);
            }
            for step in new_steps {
                self.validate_step(step)?;
            }
        }

        // Update workflow
        let update_input = UpdateGovApprovalWorkflow {
            name,
            description,
            is_default,
            is_active,
        };

        let workflow =
            GovApprovalWorkflow::update(&self.pool, tenant_id, workflow_id, update_input)
                .await?
                .ok_or(GovernanceError::WorkflowNotFound(workflow_id))?;

        // Update steps if provided
        let final_steps = if let Some(new_steps) = steps {
            // Delete existing steps
            GovApprovalStep::delete_by_workflow(&self.pool, workflow_id).await?;

            // Create new steps
            let mut created_steps = Vec::with_capacity(new_steps.len());
            for (i, step) in new_steps.into_iter().enumerate() {
                let step_input = CreateGovApprovalStep {
                    step_order: (i + 1) as i32,
                    approver_type: step.approver_type,
                    specific_approvers: step.specific_approvers,
                    escalation_enabled: false, // Default to disabled, can be configured later via F054
                };

                let created = GovApprovalStep::create(&self.pool, workflow_id, step_input).await?;
                created_steps.push(created);
            }
            created_steps
        } else {
            existing.steps
        };

        Ok(WorkflowWithSteps {
            workflow,
            steps: final_steps,
        })
    }

    /// Delete a workflow.
    pub async fn delete_workflow(&self, tenant_id: Uuid, workflow_id: Uuid) -> Result<()> {
        // Verify workflow exists
        let _ = self.get_workflow(tenant_id, workflow_id).await?;

        // Check for pending requests using this workflow
        let pending_count =
            GovApprovalWorkflow::count_pending_requests(&self.pool, tenant_id, workflow_id).await?;

        if pending_count > 0 {
            return Err(GovernanceError::WorkflowHasPendingRequests(pending_count));
        }

        // Delete steps first (cascade should handle this, but be explicit)
        GovApprovalStep::delete_by_workflow(&self.pool, workflow_id).await?;

        // Delete workflow
        GovApprovalWorkflow::delete(&self.pool, tenant_id, workflow_id).await?;

        Ok(())
    }

    /// Set a workflow as the default.
    pub async fn set_default_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<WorkflowWithSteps> {
        let workflow = GovApprovalWorkflow::set_default(&self.pool, tenant_id, workflow_id)
            .await?
            .ok_or(GovernanceError::WorkflowNotFound(workflow_id))?;

        let steps = GovApprovalStep::find_by_workflow(&self.pool, workflow.id).await?;

        Ok(WorkflowWithSteps { workflow, steps })
    }

    /// Validate a step configuration.
    fn validate_step(&self, step: &CreateStepInput) -> Result<()> {
        match step.approver_type {
            GovApproverType::SpecificUsers => match &step.specific_approvers {
                Some(approvers) if !approvers.is_empty() => Ok(()),
                _ => Err(GovernanceError::Validation(
                    "Specific approvers required for SpecificUsers type".to_string(),
                )),
            },
            _ => {
                if step.specific_approvers.is_some() {
                    Err(GovernanceError::Validation(
                        "Specific approvers not allowed for this approver type".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Get database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Workflow with its steps.
#[derive(Debug, Clone)]
pub struct WorkflowWithSteps {
    pub workflow: GovApprovalWorkflow,
    pub steps: Vec<GovApprovalStep>,
}

/// Input for creating a step.
#[derive(Debug, Clone)]
pub struct CreateStepInput {
    pub approver_type: GovApproverType,
    pub specific_approvers: Option<Vec<Uuid>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::GovApproverType;

    #[test]
    fn test_max_workflow_steps() {
        assert_eq!(MAX_WORKFLOW_STEPS, 5);
    }

    #[test]
    fn test_workflow_with_steps() {
        let workflow = GovApprovalWorkflow {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Workflow".to_string(),
            description: None,
            is_default: false,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let steps = vec![];
        let wws = WorkflowWithSteps { workflow, steps };

        assert_eq!(wws.workflow.name, "Test Workflow");
        assert!(wws.steps.is_empty());
    }

    #[test]
    fn test_create_step_input_manager() {
        let step = CreateStepInput {
            approver_type: GovApproverType::Manager,
            specific_approvers: None,
        };

        assert!(matches!(step.approver_type, GovApproverType::Manager));
        assert!(step.specific_approvers.is_none());
    }

    #[test]
    fn test_create_step_input_specific_users() {
        let approvers = vec![Uuid::new_v4(), Uuid::new_v4()];
        let step = CreateStepInput {
            approver_type: GovApproverType::SpecificUsers,
            specific_approvers: Some(approvers.clone()),
        };

        assert!(matches!(step.approver_type, GovApproverType::SpecificUsers));
        assert_eq!(step.specific_approvers.unwrap().len(), 2);
    }

    #[test]
    fn test_create_step_input_entitlement_owner() {
        let step = CreateStepInput {
            approver_type: GovApproverType::EntitlementOwner,
            specific_approvers: None,
        };

        assert!(matches!(
            step.approver_type,
            GovApproverType::EntitlementOwner
        ));
        assert!(step.specific_approvers.is_none());
    }

    #[test]
    fn test_workflow_with_multiple_steps() {
        let workflow = GovApprovalWorkflow {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Multi-Level Workflow".to_string(),
            description: Some("Requires manager then owner approval".to_string()),
            is_default: true,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let steps = vec![
            GovApprovalStep {
                id: Uuid::new_v4(),
                workflow_id: workflow.id,
                step_order: 1,
                approver_type: GovApproverType::Manager,
                specific_approvers: None,
                escalation_enabled: false,
                created_at: chrono::Utc::now(),
            },
            GovApprovalStep {
                id: Uuid::new_v4(),
                workflow_id: workflow.id,
                step_order: 2,
                approver_type: GovApproverType::EntitlementOwner,
                specific_approvers: None,
                escalation_enabled: false,
                created_at: chrono::Utc::now(),
            },
        ];

        let wws = WorkflowWithSteps {
            workflow,
            steps: steps.clone(),
        };

        assert_eq!(wws.workflow.name, "Multi-Level Workflow");
        assert_eq!(wws.steps.len(), 2);
        assert_eq!(wws.steps[0].step_order, 1);
        assert_eq!(wws.steps[1].step_order, 2);
    }
}
