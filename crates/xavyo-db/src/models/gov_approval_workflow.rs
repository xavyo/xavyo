//! Governance Approval Workflow model.
//!
//! Represents configurable approval workflows for access requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A governance approval workflow definition.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApprovalWorkflow {
    /// Unique identifier for the workflow.
    pub id: Uuid,

    /// The tenant this workflow belongs to.
    pub tenant_id: Uuid,

    /// Workflow display name.
    pub name: String,

    /// Workflow description.
    pub description: Option<String>,

    /// Whether this is the tenant's default workflow.
    pub is_default: bool,

    /// Whether the workflow is active.
    pub is_active: bool,

    /// When the workflow was created.
    pub created_at: DateTime<Utc>,

    /// When the workflow was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovApprovalWorkflow {
    pub name: String,
    pub description: Option<String>,
    pub is_default: bool,
}

/// Request to update an approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovApprovalWorkflow {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_default: Option<bool>,
    pub is_active: Option<bool>,
}

/// Filter options for listing workflows.
#[derive(Debug, Clone, Default)]
pub struct WorkflowFilter {
    pub is_active: Option<bool>,
    pub is_default: Option<bool>,
}

impl GovApprovalWorkflow {
    /// Find a workflow by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_workflows
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a workflow by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_workflows
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find the default workflow for a tenant.
    pub async fn find_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_approval_workflows
            WHERE tenant_id = $1 AND is_default = TRUE AND is_active = TRUE
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List workflows for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &WorkflowFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_approval_workflows
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }
        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY is_default DESC, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovApprovalWorkflow>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count workflows in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &WorkflowFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_approval_workflows
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }
        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }

        q.fetch_one(pool).await
    }

    /// Create a new workflow.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovApprovalWorkflow,
    ) -> Result<Self, sqlx::Error> {
        // If this is the default, clear other defaults first
        if input.is_default {
            sqlx::query(
                r#"
                UPDATE gov_approval_workflows
                SET is_default = FALSE, updated_at = NOW()
                WHERE tenant_id = $1 AND is_default = TRUE
                "#,
            )
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }

        sqlx::query_as(
            r#"
            INSERT INTO gov_approval_workflows (tenant_id, name, description, is_default)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.is_default)
        .fetch_one(pool)
        .await
    }

    /// Update a workflow.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovApprovalWorkflow,
    ) -> Result<Option<Self>, sqlx::Error> {
        // If setting as default, clear other defaults first
        if input.is_default == Some(true) {
            sqlx::query(
                r#"
                UPDATE gov_approval_workflows
                SET is_default = FALSE, updated_at = NOW()
                WHERE tenant_id = $1 AND is_default = TRUE AND id != $2
                "#,
            )
            .bind(tenant_id)
            .bind(id)
            .execute(pool)
            .await?;
        }

        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_default.is_some() {
            updates.push(format!("is_default = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${}", param_idx));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_approval_workflows SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovApprovalWorkflow>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(is_default) = input.is_default {
            q = q.bind(is_default);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }

        q.fetch_optional(pool).await
    }

    /// Set a workflow as the default.
    pub async fn set_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Clear existing default
        sqlx::query(
            r#"
            UPDATE gov_approval_workflows
            SET is_default = FALSE, updated_at = NOW()
            WHERE tenant_id = $1 AND is_default = TRUE AND id != $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        // Set new default
        sqlx::query_as(
            r#"
            UPDATE gov_approval_workflows
            SET is_default = TRUE, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a workflow.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_approval_workflows
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count pending requests using this workflow.
    pub async fn count_pending_requests(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_access_requests
            WHERE tenant_id = $1 AND workflow_id = $2 AND status IN ('pending', 'pending_approval')
            "#,
        )
        .bind(tenant_id)
        .bind(workflow_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_workflow_request() {
        let request = CreateGovApprovalWorkflow {
            name: "Manager Approval".to_string(),
            description: Some("Simple manager approval workflow".to_string()),
            is_default: true,
        };

        assert_eq!(request.name, "Manager Approval");
        assert!(request.is_default);
    }

    #[test]
    fn test_workflow_serialization() {
        let workflow = GovApprovalWorkflow {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Workflow".to_string(),
            description: None,
            is_default: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&workflow).unwrap();
        assert!(json.contains("Test Workflow"));
    }
}
