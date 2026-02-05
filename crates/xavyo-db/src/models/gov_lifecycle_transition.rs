//! Governance Lifecycle Transition model.
//!
//! Represents allowed transitions between lifecycle states.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A governance lifecycle transition.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleTransition {
    /// Unique identifier for the transition.
    pub id: Uuid,

    /// The configuration this transition belongs to.
    pub config_id: Uuid,

    /// The tenant this transition belongs to (denormalized for RLS).
    pub tenant_id: Uuid,

    /// Transition name (e.g., activate, suspend, archive).
    pub name: String,

    /// Source state ID.
    pub from_state_id: Uuid,

    /// Target state ID.
    pub to_state_id: Uuid,

    /// Whether this transition requires approval.
    pub requires_approval: bool,

    /// Linked approval workflow ID (required if `requires_approval` is true).
    pub approval_workflow_id: Option<Uuid>,

    /// Grace period in hours for rollback (0-720).
    pub grace_period_hours: i32,

    /// Conditions that must be satisfied for this transition.
    /// Format: [{"type": "termination_date_set", "config": {}}]
    #[sqlx(default)]
    pub conditions: Option<serde_json::Value>,

    /// When the transition was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new lifecycle transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLifecycleTransition {
    pub name: String,
    pub from_state_id: Uuid,
    pub to_state_id: Uuid,
    pub requires_approval: bool,
    pub approval_workflow_id: Option<Uuid>,
    pub grace_period_hours: i32,
}

/// Request to update a lifecycle transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovLifecycleTransition {
    pub name: Option<String>,
    pub requires_approval: Option<bool>,
    pub approval_workflow_id: Option<Uuid>,
    pub grace_period_hours: Option<i32>,
}

/// Filter options for listing lifecycle transitions.
#[derive(Debug, Clone, Default)]
pub struct LifecycleTransitionFilter {
    pub config_id: Option<Uuid>,
    pub from_state_id: Option<Uuid>,
    pub to_state_id: Option<Uuid>,
    pub requires_approval: Option<bool>,
}

/// Transition with state names for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleTransitionWithStates {
    pub id: Uuid,
    pub config_id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub from_state_id: Uuid,
    pub from_state_name: String,
    pub to_state_id: Uuid,
    pub to_state_name: String,
    pub requires_approval: bool,
    pub approval_workflow_id: Option<Uuid>,
    pub grace_period_hours: i32,
    #[sqlx(default)]
    pub conditions: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl GovLifecycleTransition {
    /// Find a transition by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a transition by name within a configuration.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE config_id = $1 AND tenant_id = $2 AND name = $3
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find a transition by state pair.
    pub async fn find_by_states(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_state_id: Uuid,
        to_state_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE from_state_id = $1 AND to_state_id = $2 AND tenant_id = $3
            ",
        )
        .bind(from_state_id)
        .bind(to_state_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List transitions from a specific state.
    pub async fn list_from_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_state_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE from_state_id = $1 AND tenant_id = $2
            ORDER BY name ASC
            ",
        )
        .bind(from_state_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List transitions for a configuration.
    pub async fn list_by_config(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE config_id = $1 AND tenant_id = $2
            ORDER BY name ASC
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List transitions for a configuration with state names.
    pub async fn list_by_config_with_states(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<Vec<GovLifecycleTransitionWithStates>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT
                t.id, t.config_id, t.tenant_id, t.name,
                t.from_state_id, fs.name as from_state_name,
                t.to_state_id, ts.name as to_state_name,
                t.requires_approval, t.approval_workflow_id,
                t.grace_period_hours, t.created_at
            FROM gov_lifecycle_transitions t
            JOIN gov_lifecycle_states fs ON t.from_state_id = fs.id
            JOIN gov_lifecycle_states ts ON t.to_state_id = ts.id
            WHERE t.config_id = $1 AND t.tenant_id = $2
            ORDER BY t.name ASC
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List transitions from a state with target state names.
    pub async fn list_available_from_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_state_id: Uuid,
    ) -> Result<Vec<GovLifecycleTransitionWithStates>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT
                t.id, t.config_id, t.tenant_id, t.name,
                t.from_state_id, fs.name as from_state_name,
                t.to_state_id, ts.name as to_state_name,
                t.requires_approval, t.approval_workflow_id,
                t.grace_period_hours, t.created_at
            FROM gov_lifecycle_transitions t
            JOIN gov_lifecycle_states fs ON t.from_state_id = fs.id
            JOIN gov_lifecycle_states ts ON t.to_state_id = ts.id
            WHERE t.from_state_id = $1 AND t.tenant_id = $2
            ORDER BY t.name ASC
            ",
        )
        .bind(from_state_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List transitions for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleTransitionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_lifecycle_transitions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.config_id.is_some() {
            query.push_str(&format!(" AND config_id = ${param_num}"));
            param_num += 1;
        }

        if filter.from_state_id.is_some() {
            query.push_str(&format!(" AND from_state_id = ${param_num}"));
            param_num += 1;
        }

        if filter.to_state_id.is_some() {
            query.push_str(&format!(" AND to_state_id = ${param_num}"));
            param_num += 1;
        }

        if filter.requires_approval.is_some() {
            query.push_str(&format!(" AND requires_approval = ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(config_id) = filter.config_id {
            db_query = db_query.bind(config_id);
        }

        if let Some(from_state_id) = filter.from_state_id {
            db_query = db_query.bind(from_state_id);
        }

        if let Some(to_state_id) = filter.to_state_id {
            db_query = db_query.bind(to_state_id);
        }

        if let Some(requires_approval) = filter.requires_approval {
            db_query = db_query.bind(requires_approval);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count transitions for a configuration.
    pub async fn count_by_config(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_lifecycle_transitions
            WHERE config_id = $1 AND tenant_id = $2
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Count transitions involving a state (from or to).
    pub async fn count_involving_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        state_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_lifecycle_transitions
            WHERE tenant_id = $1 AND (from_state_id = $2 OR to_state_id = $2)
            ",
        )
        .bind(tenant_id)
        .bind(state_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new lifecycle transition.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
        input: &CreateGovLifecycleTransition,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_lifecycle_transitions (
                config_id, tenant_id, name, from_state_id, to_state_id,
                requires_approval, approval_workflow_id, grace_period_hours
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.from_state_id)
        .bind(input.to_state_id)
        .bind(input.requires_approval)
        .bind(input.approval_workflow_id)
        .bind(input.grace_period_hours)
        .fetch_one(pool)
        .await
    }

    /// Update a lifecycle transition.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovLifecycleTransition,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_transitions
            SET
                name = COALESCE($3, name),
                requires_approval = COALESCE($4, requires_approval),
                approval_workflow_id = COALESCE($5, approval_workflow_id),
                grace_period_hours = COALESCE($6, grace_period_hours)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.requires_approval)
        .bind(input.approval_workflow_id)
        .bind(input.grace_period_hours)
        .fetch_optional(pool)
        .await
    }

    /// Delete a lifecycle transition.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_lifecycle_transitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all transitions for a configuration.
    pub async fn delete_by_config(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_lifecycle_transitions
            WHERE config_id = $1 AND tenant_id = $2
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get conditions for a transition.
    pub async fn get_conditions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT conditions FROM gov_lifecycle_transitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update conditions for a transition.
    pub async fn update_conditions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        conditions: &serde_json::Value,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_transitions
            SET conditions = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(conditions)
        .fetch_optional(pool)
        .await
    }
}
