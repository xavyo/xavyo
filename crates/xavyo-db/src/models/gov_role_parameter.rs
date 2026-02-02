//! Role Parameter model (F057).
//!
//! Represents a parameter definition on a role (entitlement with is_role=true).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_role_parameter_types::{ParameterConstraints, ParameterType};

/// A parameter definition on a role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleParameter {
    /// Unique identifier for the parameter.
    pub id: Uuid,

    /// The tenant this parameter belongs to.
    pub tenant_id: Uuid,

    /// The role (entitlement) this parameter is defined on.
    pub role_id: Uuid,

    /// Parameter name (alphanumeric with underscores, e.g., "database_name").
    pub name: String,

    /// Human-readable display name.
    pub display_name: Option<String>,

    /// Description of the parameter.
    pub description: Option<String>,

    /// The type of this parameter.
    pub parameter_type: ParameterType,

    /// Whether a value must be provided at assignment time.
    pub is_required: bool,

    /// Default value (JSONB) if not provided at assignment time.
    pub default_value: Option<serde_json::Value>,

    /// Validation constraints (JSONB).
    pub constraints: Option<serde_json::Value>,

    /// Order for UI display.
    pub display_order: i32,

    /// When the parameter was created.
    pub created_at: DateTime<Utc>,

    /// When the parameter was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new role parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRoleParameter {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub parameter_type: ParameterType,
    pub is_required: Option<bool>,
    pub default_value: Option<serde_json::Value>,
    pub constraints: Option<ParameterConstraints>,
    pub display_order: Option<i32>,
}

/// Request to update a role parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovRoleParameter {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_required: Option<bool>,
    pub default_value: Option<serde_json::Value>,
    pub constraints: Option<ParameterConstraints>,
    pub display_order: Option<i32>,
}

/// Filter options for listing role parameters.
#[derive(Debug, Clone, Default)]
pub struct RoleParameterFilter {
    pub parameter_type: Option<ParameterType>,
    pub is_required: Option<bool>,
    pub name_contains: Option<String>,
}

impl GovRoleParameter {
    /// Find a parameter by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_parameters
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a parameter by name within a role.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_parameters
            WHERE tenant_id = $1 AND role_id = $2 AND name = $3
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all parameters for a role.
    pub async fn list_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_parameters
            WHERE tenant_id = $1 AND role_id = $2
            ORDER BY display_order ASC, name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    /// List all required parameters for a role.
    pub async fn list_required_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_parameters
            WHERE tenant_id = $1 AND role_id = $2 AND is_required = true
            ORDER BY display_order ASC, name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    /// List parameters with filtering.
    pub async fn list_by_role_filtered(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        filter: &RoleParameterFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from("SELECT * FROM gov_role_parameters WHERE tenant_id = $1 AND role_id = $2");
        let mut param_count = 2;

        if filter.parameter_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND parameter_type = ${}", param_count));
        }
        if filter.is_required.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_required = ${}", param_count));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${}", param_count));
        }

        query.push_str(" ORDER BY display_order ASC, name ASC");

        let mut q = sqlx::query_as::<_, Self>(&query)
            .bind(tenant_id)
            .bind(role_id);

        if let Some(param_type) = filter.parameter_type {
            q = q.bind(param_type);
        }
        if let Some(is_required) = filter.is_required {
            q = q.bind(is_required);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{}%", name_contains));
        }

        q.fetch_all(pool).await
    }

    /// Count parameters for a role.
    pub async fn count_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_parameters
            WHERE tenant_id = $1 AND role_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new role parameter.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        input: CreateGovRoleParameter,
    ) -> Result<Self, sqlx::Error> {
        let is_required = input.is_required.unwrap_or(false);
        let display_order = input.display_order.unwrap_or(0);
        let constraints_json = input.constraints.and_then(|c| serde_json::to_value(c).ok());

        sqlx::query_as(
            r#"
            INSERT INTO gov_role_parameters (
                tenant_id, role_id, name, display_name, description,
                parameter_type, is_required, default_value, constraints, display_order
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.description)
        .bind(input.parameter_type)
        .bind(is_required)
        .bind(&input.default_value)
        .bind(&constraints_json)
        .bind(display_order)
        .fetch_one(pool)
        .await
    }

    /// Update a role parameter.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovRoleParameter,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_count = 2; // $1 = id, $2 = tenant_id

        if input.display_name.is_some() {
            param_count += 1;
            updates.push(format!("display_name = ${}", param_count));
        }
        if input.description.is_some() {
            param_count += 1;
            updates.push(format!("description = ${}", param_count));
        }
        if input.is_required.is_some() {
            param_count += 1;
            updates.push(format!("is_required = ${}", param_count));
        }
        if input.default_value.is_some() {
            param_count += 1;
            updates.push(format!("default_value = ${}", param_count));
        }
        if input.constraints.is_some() {
            param_count += 1;
            updates.push(format!("constraints = ${}", param_count));
        }
        if input.display_order.is_some() {
            param_count += 1;
            updates.push(format!("display_order = ${}", param_count));
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        updates.push("updated_at = NOW()".to_string());
        let query = format!(
            "UPDATE gov_role_parameters SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref display_name) = input.display_name {
            q = q.bind(display_name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(is_required) = input.is_required {
            q = q.bind(is_required);
        }
        if let Some(ref default_value) = input.default_value {
            q = q.bind(default_value);
        }
        if let Some(ref constraints) = input.constraints {
            let constraints_json = serde_json::to_value(constraints).ok();
            q = q.bind(constraints_json);
        }
        if let Some(display_order) = input.display_order {
            q = q.bind(display_order);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a role parameter.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_parameters
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a role has any parameters defined.
    pub async fn role_has_parameters(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_parameters
            WHERE tenant_id = $1 AND role_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Get the parsed constraints.
    pub fn get_constraints(&self) -> Option<ParameterConstraints> {
        self.constraints
            .as_ref()
            .and_then(|c| serde_json::from_value(c.clone()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_parameter_defaults() {
        let input = CreateGovRoleParameter {
            name: "database_name".to_string(),
            display_name: Some("Database Name".to_string()),
            description: None,
            parameter_type: ParameterType::String,
            is_required: None,
            default_value: None,
            constraints: None,
            display_order: None,
        };

        assert_eq!(input.name, "database_name");
        assert_eq!(input.parameter_type, ParameterType::String);
        assert!(input.is_required.is_none());
    }

    #[test]
    fn test_filter_default() {
        let filter = RoleParameterFilter::default();
        assert!(filter.parameter_type.is_none());
        assert!(filter.is_required.is_none());
        assert!(filter.name_contains.is_none());
    }

    #[test]
    fn test_constraints_parsing() {
        let constraints =
            ParameterConstraints::string(Some(1), Some(100), Some("^[a-z]+$".to_string()));
        let json = serde_json::to_value(&constraints).unwrap();

        let parsed: ParameterConstraints = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.min_length, Some(1));
        assert_eq!(parsed.max_length, Some(100));
        assert_eq!(parsed.pattern, Some("^[a-z]+$".to_string()));
    }
}
