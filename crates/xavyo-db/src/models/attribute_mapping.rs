//! Attribute Mapping model.
//!
//! Defines how xavyo attributes map to target system attributes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Deprovision action when user is terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeprovisionAction {
    /// Disable the account in the target system.
    Disable,
    /// Delete the account from the target system.
    Delete,
}

impl std::fmt::Display for DeprovisionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeprovisionAction::Disable => write!(f, "disable"),
            DeprovisionAction::Delete => write!(f, "delete"),
        }
    }
}

impl std::str::FromStr for DeprovisionAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disable" => Ok(DeprovisionAction::Disable),
            "delete" => Ok(DeprovisionAction::Delete),
            _ => Err(format!("Unknown deprovision action: {s}")),
        }
    }
}

/// An attribute mapping configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// The tenant this mapping belongs to.
    pub tenant_id: Uuid,

    /// The connector this mapping is for.
    pub connector_id: Uuid,

    /// The object class this mapping applies to.
    pub object_class: String,

    /// Mapping set name (e.g., "default", "contractors").
    pub name: String,

    /// Whether this is the default mapping for the object class.
    pub is_default: bool,

    /// Attribute mappings (JSON object: {`source_attr`: `target_attr`}).
    pub mappings: serde_json::Value,

    /// Correlation rule for identity matching (JSON).
    pub correlation_rule: Option<serde_json::Value>,

    /// What to do when deprovisioning.
    pub deprovision_action: DeprovisionAction,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,

    /// When the mapping was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create an attribute mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttributeMapping {
    pub object_class: String,
    pub name: String,
    pub is_default: bool,
    pub mappings: serde_json::Value,
    pub correlation_rule: Option<serde_json::Value>,
    pub deprovision_action: Option<DeprovisionAction>,
}

/// Request to update an attribute mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAttributeMapping {
    pub name: Option<String>,
    pub is_default: Option<bool>,
    pub mappings: Option<serde_json::Value>,
    pub correlation_rule: Option<serde_json::Value>,
    pub deprovision_action: Option<DeprovisionAction>,
}

/// Filter for listing attribute mappings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingFilter {
    pub connector_id: Option<Uuid>,
    pub object_class: Option<String>,
    pub is_default: Option<bool>,
}

impl AttributeMapping {
    /// Find a mapping by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM attribute_mappings
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the default mapping for a connector and object class.
    pub async fn find_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM attribute_mappings
            WHERE connector_id = $1 AND tenant_id = $2
                AND object_class = $3 AND is_default = true
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(object_class)
        .fetch_optional(pool)
        .await
    }

    /// List all mappings for a connector.
    pub async fn list_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: Option<&str>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(oc) = object_class {
            sqlx::query_as(
                r"
                SELECT * FROM attribute_mappings
                WHERE connector_id = $1 AND tenant_id = $2 AND object_class = $3
                ORDER BY is_default DESC, name
                ",
            )
            .bind(connector_id)
            .bind(tenant_id)
            .bind(oc)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM attribute_mappings
                WHERE connector_id = $1 AND tenant_id = $2
                ORDER BY object_class, is_default DESC, name
                ",
            )
            .bind(connector_id)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Create a new attribute mapping.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateAttributeMapping,
    ) -> Result<Self, sqlx::Error> {
        // If setting as default, first unset any existing default
        if input.is_default {
            sqlx::query(
                r"
                UPDATE attribute_mappings
                SET is_default = false, updated_at = NOW()
                WHERE connector_id = $1 AND tenant_id = $2
                    AND object_class = $3 AND is_default = true
                ",
            )
            .bind(connector_id)
            .bind(tenant_id)
            .bind(&input.object_class)
            .execute(pool)
            .await?;
        }

        let deprovision = input
            .deprovision_action
            .unwrap_or(DeprovisionAction::Disable);

        sqlx::query_as(
            r"
            INSERT INTO attribute_mappings (
                tenant_id, connector_id, object_class, name, is_default,
                mappings, correlation_rule, deprovision_action
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(&input.object_class)
        .bind(&input.name)
        .bind(input.is_default)
        .bind(&input.mappings)
        .bind(&input.correlation_rule)
        .bind(deprovision.to_string())
        .fetch_one(pool)
        .await
    }

    /// Update an attribute mapping.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateAttributeMapping,
    ) -> Result<Option<Self>, sqlx::Error> {
        // If setting as default, first get the connector_id and object_class
        if input.is_default == Some(true) {
            if let Some(mapping) = Self::find_by_id(pool, tenant_id, id).await? {
                sqlx::query(
                    r"
                    UPDATE attribute_mappings
                    SET is_default = false, updated_at = NOW()
                    WHERE connector_id = $1 AND tenant_id = $2
                        AND object_class = $3 AND is_default = true AND id != $4
                    ",
                )
                .bind(mapping.connector_id)
                .bind(tenant_id)
                .bind(&mapping.object_class)
                .bind(id)
                .execute(pool)
                .await?;
            }
        }

        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3; // $1 = id, $2 = tenant_id

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_default.is_some() {
            updates.push(format!("is_default = ${param_idx}"));
            param_idx += 1;
        }
        if input.mappings.is_some() {
            updates.push(format!("mappings = ${param_idx}"));
            param_idx += 1;
        }
        if input.correlation_rule.is_some() {
            updates.push(format!("correlation_rule = ${param_idx}"));
            param_idx += 1;
        }
        if input.deprovision_action.is_some() {
            updates.push(format!("deprovision_action = ${param_idx}"));
        }

        let query = format!(
            "UPDATE attribute_mappings SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, AttributeMapping>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(is_default) = input.is_default {
            q = q.bind(is_default);
        }
        if let Some(ref mappings) = input.mappings {
            q = q.bind(mappings);
        }
        if let Some(ref correlation_rule) = input.correlation_rule {
            q = q.bind(correlation_rule);
        }
        if let Some(deprovision_action) = input.deprovision_action {
            q = q.bind(deprovision_action.to_string());
        }

        q.fetch_optional(pool).await
    }

    /// Delete an attribute mapping.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM attribute_mappings
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all mappings for a connector.
    pub async fn delete_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM attribute_mappings
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprovision_action_display() {
        assert_eq!(DeprovisionAction::Disable.to_string(), "disable");
        assert_eq!(DeprovisionAction::Delete.to_string(), "delete");
    }

    #[test]
    fn test_deprovision_action_from_str() {
        assert_eq!(
            "disable".parse::<DeprovisionAction>().unwrap(),
            DeprovisionAction::Disable
        );
        assert_eq!(
            "DELETE".parse::<DeprovisionAction>().unwrap(),
            DeprovisionAction::Delete
        );
        assert!("unknown".parse::<DeprovisionAction>().is_err());
    }

    #[test]
    fn test_create_mapping_request() {
        let request = CreateAttributeMapping {
            object_class: "user".to_string(),
            name: "default".to_string(),
            is_default: true,
            mappings: serde_json::json!({
                "email": "mail",
                "first_name": "givenName",
                "last_name": "sn"
            }),
            correlation_rule: Some(serde_json::json!({
                "match_attribute": "email",
                "target_attribute": "mail"
            })),
            deprovision_action: Some(DeprovisionAction::Disable),
        };

        assert_eq!(request.object_class, "user");
        assert!(request.is_default);
    }

    #[test]
    fn test_mapping_filter_default() {
        let filter = MappingFilter::default();
        assert!(filter.connector_id.is_none());
        assert!(filter.object_class.is_none());
        assert!(filter.is_default.is_none());
    }
}
