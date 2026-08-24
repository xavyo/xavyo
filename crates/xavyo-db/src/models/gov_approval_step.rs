//! Governance Approval Step model.
//!
//! Represents a single level within a multi-level approval workflow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Types of approvers for workflow steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_approver_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovApproverType {
    /// The requester's manager.
    Manager,
    /// The owner of the entitlement.
    EntitlementOwner,
    /// Specific users defined in the step.
    SpecificUsers,
}

/// A single approval step within a workflow.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApprovalStep {
    /// Unique identifier for the step.
    pub id: Uuid,

    /// The workflow this step belongs to.
    pub workflow_id: Uuid,

    /// Order in the approval chain (1, 2, 3...).
    pub step_order: i32,

    /// Type of approver for this step.
    pub approver_type: GovApproverType,

    /// Specific approver user IDs (only for `SpecificUsers` type).
    pub specific_approvers: Option<Vec<Uuid>>,

    /// When the step was created.
    pub created_at: DateTime<Utc>,

    /// Whether escalation is enabled for this step (F054).
    pub escalation_enabled: bool,
}

/// Request to create a new approval step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovApprovalStep {
    pub step_order: i32,
    pub approver_type: GovApproverType,
    pub specific_approvers: Option<Vec<Uuid>>,
    /// Whether escalation is enabled for this step. Defaults to true.
    #[serde(default = "default_escalation_enabled")]
    pub escalation_enabled: bool,
}

fn default_escalation_enabled() -> bool {
    true
}

impl GovApprovalStep {
    /// Find a step by ID within a tenant (via its parent workflow).
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT s.id, s.workflow_id, s.step_order, s.approver_type,
                   s.specific_approvers, s.created_at, s.escalation_enabled
            FROM gov_approval_steps s
            INNER JOIN gov_approval_workflows w ON w.id = s.workflow_id
            WHERE s.id = $1 AND w.tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all steps for a workflow, ordered by `step_order`.
    pub async fn find_by_workflow(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT s.id, s.workflow_id, s.step_order, s.approver_type,
                   s.specific_approvers, s.created_at, s.escalation_enabled
            FROM gov_approval_steps s
            INNER JOIN gov_approval_workflows w ON w.id = s.workflow_id
            WHERE s.workflow_id = $1 AND w.tenant_id = $2
            ORDER BY s.step_order ASC
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Find a specific step by workflow and order.
    pub async fn find_by_workflow_and_order(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
        step_order: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT s.id, s.workflow_id, s.step_order, s.approver_type,
                   s.specific_approvers, s.created_at, s.escalation_enabled
            FROM gov_approval_steps s
            INNER JOIN gov_approval_workflows w ON w.id = s.workflow_id
            WHERE s.workflow_id = $1 AND s.step_order = $2 AND w.tenant_id = $3
            ",
        )
        .bind(workflow_id)
        .bind(step_order)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Count steps in a workflow.
    pub async fn count_by_workflow(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_approval_steps s
            INNER JOIN gov_approval_workflows w ON w.id = s.workflow_id
            WHERE s.workflow_id = $1 AND w.tenant_id = $2
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new step.
    pub async fn create(
        pool: &sqlx::PgPool,
        workflow_id: Uuid,
        input: CreateGovApprovalStep,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_approval_steps (workflow_id, step_order, approver_type, specific_approvers, escalation_enabled)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(workflow_id)
        .bind(input.step_order)
        .bind(input.approver_type)
        .bind(&input.specific_approvers)
        .bind(input.escalation_enabled)
        .fetch_one(pool)
        .await
    }

    /// Create multiple steps in a batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        workflow_id: Uuid,
        steps: Vec<CreateGovApprovalStep>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(steps.len());
        for step in steps {
            let created = Self::create(pool, workflow_id, step).await?;
            results.push(created);
        }
        Ok(results)
    }

    /// Delete all steps for a workflow within a tenant.
    pub async fn delete_by_workflow(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_approval_steps s
            USING gov_approval_workflows w
            WHERE s.workflow_id = w.id AND s.workflow_id = $1 AND w.tenant_id = $2
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete a specific step within a tenant.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_approval_steps s
            USING gov_approval_workflows w
            WHERE s.workflow_id = w.id AND s.id = $1 AND w.tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if this is the final step in the workflow.
    pub async fn is_final_step(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
        step_order: i32,
    ) -> Result<bool, sqlx::Error> {
        let max_order: Option<i32> = sqlx::query_scalar(
            r"
            SELECT MAX(s.step_order) FROM gov_approval_steps s
            INNER JOIN gov_approval_workflows w ON w.id = s.workflow_id
            WHERE s.workflow_id = $1 AND w.tenant_id = $2
            ",
        )
        .bind(workflow_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(max_order.is_none_or(|max| step_order >= max))
    }

    /// Validate that `specific_approvers` is properly set based on `approver_type`.
    #[must_use]
    pub fn validate(&self) -> bool {
        match self.approver_type {
            GovApproverType::SpecificUsers => self
                .specific_approvers
                .as_ref()
                .is_some_and(|approvers| !approvers.is_empty()),
            _ => self.specific_approvers.is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_by_id_scopes_by_tenant() {
        let src = include_str!("gov_approval_step.rs");
        let production = src.split("mod tests").next().expect("production source");
        let lookup = production
            .split("pub async fn find_by_id")
            .nth(1)
            .expect("find_by_id")
            .split("pub async fn find_by_workflow")
            .next()
            .expect("find_by_id body");
        assert!(
            lookup.contains("AND w.tenant_id = $2"),
            "approval step lookup must join workflow tenant_id"
        );
        assert!(
            !lookup.contains("FROM gov_approval_steps\n            WHERE id = $1"),
            "must not look up approval steps by id alone"
        );
    }

    #[test]
    fn workflow_scoped_step_queries_join_tenant() {
        let src = include_str!("gov_approval_step.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("WHERE s.workflow_id = $1 AND w.tenant_id = $2"),
            "workflow-scoped step queries must filter tenant_id"
        );
        assert!(
            !production.contains("FROM gov_approval_steps\n            WHERE workflow_id = $1"),
            "must not query approval steps by workflow_id alone"
        );
        assert!(
            production.contains("AND s.workflow_id = $1 AND w.tenant_id = $2"),
            "step deletes must filter tenant_id via parent workflow"
        );
    }

    #[test]
    fn test_approver_type_serialization() {
        let manager = GovApproverType::Manager;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"manager\"");

        let owner = GovApproverType::EntitlementOwner;
        let json = serde_json::to_string(&owner).unwrap();
        assert_eq!(json, "\"entitlement_owner\"");

        let specific = GovApproverType::SpecificUsers;
        let json = serde_json::to_string(&specific).unwrap();
        assert_eq!(json, "\"specific_users\"");
    }

    #[test]
    fn test_step_validation_manager() {
        let step = GovApprovalStep {
            id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            step_order: 1,
            approver_type: GovApproverType::Manager,
            specific_approvers: None,
            created_at: Utc::now(),
            escalation_enabled: true,
        };

        assert!(step.validate());
    }

    #[test]
    fn test_step_validation_specific_users_valid() {
        let step = GovApprovalStep {
            id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            step_order: 1,
            approver_type: GovApproverType::SpecificUsers,
            specific_approvers: Some(vec![Uuid::new_v4()]),
            created_at: Utc::now(),
            escalation_enabled: true,
        };

        assert!(step.validate());
    }

    #[test]
    fn test_step_validation_specific_users_invalid() {
        let step = GovApprovalStep {
            id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            step_order: 1,
            approver_type: GovApproverType::SpecificUsers,
            specific_approvers: None,
            created_at: Utc::now(),
            escalation_enabled: true,
        };

        assert!(!step.validate());
    }
}
