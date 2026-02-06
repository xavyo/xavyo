//! Governance Lifecycle State model.
//!
//! Represents named states within a lifecycle configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Action to take on entitlements when entering a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_entitlement_action", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntitlementAction {
    /// No action on entitlements.
    #[default]
    None,
    /// Pause entitlements (temporary suspension).
    Pause,
    /// Revoke entitlements (permanent removal).
    Revoke,
}

/// A governance lifecycle state.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleState {
    /// Unique identifier for the state.
    pub id: Uuid,

    /// The configuration this state belongs to.
    pub config_id: Uuid,

    /// The tenant this state belongs to (denormalized for RLS).
    pub tenant_id: Uuid,

    /// State name (e.g., Draft, Active, Suspended).
    pub name: String,

    /// State description.
    pub description: Option<String>,

    /// Whether this is the initial state for new objects.
    pub is_initial: bool,

    /// Whether this is a terminal state (no outgoing transitions).
    pub is_terminal: bool,

    /// Action to take on entitlements when entering this state.
    pub entitlement_action: EntitlementAction,

    /// Display order position.
    pub position: i32,

    /// Actions to execute when entering this state.
    /// Format: [{"type": "disable_access", "config": {}}]
    #[sqlx(default)]
    pub entry_actions: Option<serde_json::Value>,

    /// Actions to execute when leaving this state.
    /// Format: [{"type": "notify_manager", "config": {}}]
    #[sqlx(default)]
    pub exit_actions: Option<serde_json::Value>,

    /// When the state was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLifecycleState {
    pub name: String,
    pub description: Option<String>,
    pub is_initial: bool,
    pub is_terminal: bool,
    pub entitlement_action: EntitlementAction,
    pub position: i32,
}

/// Request to update a lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovLifecycleState {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_initial: Option<bool>,
    pub is_terminal: Option<bool>,
    pub entitlement_action: Option<EntitlementAction>,
    pub position: Option<i32>,
}

/// Filter options for listing lifecycle states.
#[derive(Debug, Clone, Default)]
pub struct LifecycleStateFilter {
    pub config_id: Option<Uuid>,
    pub is_initial: Option<bool>,
    pub is_terminal: Option<bool>,
}

impl GovLifecycleState {
    /// Find a state by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_states
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a state by name within a configuration.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_states
            WHERE config_id = $1 AND tenant_id = $2 AND name = $3
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find the initial state for a configuration.
    pub async fn find_initial_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_states
            WHERE config_id = $1 AND tenant_id = $2 AND is_initial = true
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List states for a configuration ordered by position.
    pub async fn list_by_config(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_states
            WHERE config_id = $1 AND tenant_id = $2
            ORDER BY position ASC
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List states for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleStateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_lifecycle_states
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.config_id.is_some() {
            query.push_str(&format!(" AND config_id = ${param_num}"));
            param_num += 1;
        }

        if filter.is_initial.is_some() {
            query.push_str(&format!(" AND is_initial = ${param_num}"));
            param_num += 1;
        }

        if filter.is_terminal.is_some() {
            query.push_str(&format!(" AND is_terminal = ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY position ASC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(config_id) = filter.config_id {
            db_query = db_query.bind(config_id);
        }

        if let Some(is_initial) = filter.is_initial {
            db_query = db_query.bind(is_initial);
        }

        if let Some(is_terminal) = filter.is_terminal {
            db_query = db_query.bind(is_terminal);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count states for a configuration.
    pub async fn count_by_config(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_lifecycle_states
            WHERE config_id = $1 AND tenant_id = $2
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Count objects in a specific state (users only for now).
    pub async fn count_objects_in_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        state_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM users
            WHERE tenant_id = $1 AND lifecycle_state_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(state_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new lifecycle state.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
        input: &CreateGovLifecycleState,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_lifecycle_states (
                config_id, tenant_id, name, description,
                is_initial, is_terminal, entitlement_action, position
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.is_initial)
        .bind(input.is_terminal)
        .bind(input.entitlement_action)
        .bind(input.position)
        .fetch_one(pool)
        .await
    }

    /// Update a lifecycle state.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovLifecycleState,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_states
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                is_initial = COALESCE($5, is_initial),
                is_terminal = COALESCE($6, is_terminal),
                entitlement_action = COALESCE($7, entitlement_action),
                position = COALESCE($8, position)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.is_initial)
        .bind(input.is_terminal)
        .bind(input.entitlement_action)
        .bind(input.position)
        .fetch_optional(pool)
        .await
    }

    /// Clear the initial flag for all states in a configuration.
    pub async fn clear_initial_flag(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_lifecycle_states
            SET is_initial = false
            WHERE config_id = $1 AND tenant_id = $2 AND is_initial = true
            ",
        )
        .bind(config_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete a lifecycle state.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_lifecycle_states
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get entry and exit actions for a state.
    pub async fn get_actions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<(Option<serde_json::Value>, Option<serde_json::Value>)>, sqlx::Error> {
        sqlx::query_as::<_, (Option<serde_json::Value>, Option<serde_json::Value>)>(
            r"
            SELECT entry_actions, exit_actions FROM gov_lifecycle_states
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update entry and exit actions for a state.
    pub async fn update_actions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        entry_actions: Option<&serde_json::Value>,
        exit_actions: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_states
            SET
                entry_actions = COALESCE($3, entry_actions),
                exit_actions = COALESCE($4, exit_actions)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(entry_actions)
        .bind(exit_actions)
        .fetch_optional(pool)
        .await
    }
}
