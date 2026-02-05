//! Role Construction model for role-based provisioning.
//!
//! Represents a construction that defines what accounts/resources are automatically
//! provisioned when a role is assigned to a user. Implements the MidPoint-style
//! inducement/construction pattern (F-063).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Deprovisioning policy for when a role is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "deprovisioning_policy", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeprovisioningPolicy {
    /// Disable the provisioned account (update status).
    #[default]
    Disable,
    /// Delete the provisioned account.
    Delete,
    /// Retain the account (no deprovisioning action).
    Retain,
}

impl std::fmt::Display for DeprovisioningPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeprovisioningPolicy::Disable => write!(f, "disable"),
            DeprovisioningPolicy::Delete => write!(f, "delete"),
            DeprovisioningPolicy::Retain => write!(f, "retain"),
        }
    }
}

impl std::str::FromStr for DeprovisioningPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disable" => Ok(DeprovisioningPolicy::Disable),
            "delete" => Ok(DeprovisioningPolicy::Delete),
            "retain" => Ok(DeprovisioningPolicy::Retain),
            _ => Err(format!("Unknown deprovisioning policy: {s}")),
        }
    }
}

/// Attribute mapping configuration for constructions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConstructionAttributeMappings {
    /// Dynamic attribute mappings from user to target.
    #[serde(default)]
    pub mappings: Vec<ConstructionAttributeMapping>,

    /// Static values to set on the provisioned object.
    #[serde(default)]
    pub static_values: serde_json::Value,
}

/// A single attribute mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConstructionAttributeMapping {
    /// Target attribute name in the connector's object.
    pub target_attribute: String,

    /// Source expression (e.g., "user.email" or "concat(user.firstName, ' ', user.lastName)").
    pub source: String,

    /// Mapping type: direct or expression.
    #[serde(rename = "type")]
    pub mapping_type: AttributeMappingType,

    /// Optional condition for this mapping (skip if condition false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// Type of attribute mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum AttributeMappingType {
    /// Direct mapping: source is a dot-notation path like "user.email".
    Direct,
    /// Expression mapping: source is an expression like "concat(...)".
    Expression,
}

/// Condition expression for conditional constructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ConstructionCondition {
    /// Simple comparison condition.
    Comparison {
        /// Left operand (attribute path).
        left: String,
        /// Comparison operator.
        operator: ConstructionConditionOperator,
        /// Right operand (value or array).
        right: serde_json::Value,
    },
    /// Logical AND of multiple conditions.
    And {
        /// Nested conditions.
        conditions: Vec<ConstructionCondition>,
    },
    /// Logical OR of multiple conditions.
    Or {
        /// Nested conditions.
        conditions: Vec<ConstructionCondition>,
    },
    /// Logical NOT of a condition.
    Not {
        /// Nested condition.
        condition: Box<ConstructionCondition>,
    },
}

/// Comparison operators for construction conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConstructionConditionOperator {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gte,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// Value is in array.
    In,
    /// String contains.
    Contains,
    /// String starts with.
    StartsWith,
    /// String ends with.
    EndsWith,
}

/// A role construction defining what to provision when a role is assigned.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleConstruction {
    /// Unique identifier for the construction.
    pub id: Uuid,

    /// The tenant this construction belongs to.
    pub tenant_id: Uuid,

    /// The role this construction is attached to.
    pub role_id: Uuid,

    /// Target connector for provisioning.
    pub connector_id: Uuid,

    /// Object class to provision (e.g., "user", "group").
    pub object_class: String,

    /// Account type identifier (e.g., "standard", "privileged").
    #[serde(default = "default_account_type")]
    pub account_type: String,

    /// Attribute mapping configuration as JSONB.
    #[sqlx(json)]
    pub attribute_mappings: serde_json::Value,

    /// Optional condition expression as JSONB.
    #[sqlx(json)]
    pub condition: Option<serde_json::Value>,

    /// Policy for handling deprovisioning.
    pub deprovisioning_policy: DeprovisioningPolicy,

    /// Execution priority (higher = executed first).
    #[serde(default)]
    pub priority: i32,

    /// Whether this construction is enabled.
    #[serde(default = "default_true")]
    pub is_enabled: bool,

    /// Optional description.
    pub description: Option<String>,

    /// Optimistic concurrency version.
    pub version: i32,

    /// User who created this construction.
    pub created_by: Uuid,

    /// When the construction was created.
    pub created_at: DateTime<Utc>,

    /// When the construction was last updated.
    pub updated_at: DateTime<Utc>,
}

fn default_account_type() -> String {
    "default".to_string()
}

fn default_true() -> bool {
    true
}

/// Request to create a new role construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateRoleConstruction {
    /// Target connector for provisioning.
    pub connector_id: Uuid,

    /// Object class to provision.
    pub object_class: String,

    /// Account type identifier.
    #[serde(default = "default_account_type")]
    pub account_type: String,

    /// Attribute mapping configuration.
    #[serde(default)]
    pub attribute_mappings: ConstructionAttributeMappings,

    /// Optional condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConstructionCondition>,

    /// Deprovisioning policy.
    #[serde(default)]
    pub deprovisioning_policy: DeprovisioningPolicy,

    /// Execution priority.
    #[serde(default)]
    pub priority: i32,

    /// Optional description.
    pub description: Option<String>,
}

/// Request to update a role construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateRoleConstruction {
    /// Updated object class.
    pub object_class: Option<String>,

    /// Updated account type.
    pub account_type: Option<String>,

    /// Updated attribute mappings.
    pub attribute_mappings: Option<ConstructionAttributeMappings>,

    /// Updated condition.
    pub condition: Option<Option<ConstructionCondition>>,

    /// Updated deprovisioning policy.
    pub deprovisioning_policy: Option<DeprovisioningPolicy>,

    /// Updated priority.
    pub priority: Option<i32>,

    /// Updated description.
    pub description: Option<Option<String>>,

    /// Version for optimistic concurrency check (required).
    pub version: i32,
}

/// Filter options for listing constructions.
#[derive(Debug, Clone, Default)]
pub struct RoleConstructionFilter {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Filter by enabled status.
    pub enabled_only: bool,

    /// Filter by object class.
    pub object_class: Option<String>,
}

/// Construction with additional context (e.g., connector name).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleConstructionWithDetails {
    /// The construction.
    #[serde(flatten)]
    pub construction: RoleConstruction,

    /// Connector display name.
    pub connector_name: Option<String>,
}

/// Effective construction from a role including inducement source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EffectiveConstruction {
    /// The construction.
    pub construction: RoleConstruction,

    /// Source role ID (may differ from construction.role_id if induced).
    pub source_role_id: Uuid,

    /// Source role name.
    pub source_role_name: String,

    /// True if from the queried role, false if induced.
    pub is_direct: bool,
}

/// User's effective construction with source roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserEffectiveConstruction {
    /// The construction.
    pub construction: RoleConstruction,

    /// All roles that provide this construction to the user.
    pub source_roles: Vec<ConstructionSourceRole>,
}

/// Source role info for user effective constructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConstructionSourceRole {
    /// Role ID.
    pub role_id: Uuid,

    /// Role name.
    pub role_name: String,
}

impl RoleConstruction {
    /// Find a construction by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM role_constructions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a construction by ID and role ID.
    pub async fn find_by_id_and_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        construction_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM role_constructions
            WHERE id = $1 AND role_id = $2 AND tenant_id = $3
            ",
        )
        .bind(construction_id)
        .bind(role_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List constructions for a role.
    pub async fn list_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        filter: &RoleConstructionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM role_constructions
            WHERE tenant_id = $1 AND role_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.enabled_only {
            query.push_str(" AND is_enabled = true");
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.object_class.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_class = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY priority DESC, created_at ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, RoleConstruction>(&query)
            .bind(tenant_id)
            .bind(role_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(ref object_class) = filter.object_class {
            q = q.bind(object_class);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count constructions for a role.
    pub async fn count_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        filter: &RoleConstructionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM role_constructions
            WHERE tenant_id = $1 AND role_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.enabled_only {
            query.push_str(" AND is_enabled = true");
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.object_class.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_class = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(role_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(ref object_class) = filter.object_class {
            q = q.bind(object_class);
        }

        q.fetch_one(pool).await
    }

    /// Create a new construction.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        input: &CreateRoleConstruction,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4();
        let attribute_mappings = serde_json::to_value(&input.attribute_mappings)
            .unwrap_or_else(|_| serde_json::json!({}));
        let condition = input
            .condition
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or_default());

        sqlx::query_as(
            r"
            INSERT INTO role_constructions (
                id, tenant_id, role_id, connector_id, object_class, account_type,
                attribute_mappings, condition, deprovisioning_policy,
                priority, description, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(role_id)
        .bind(input.connector_id)
        .bind(&input.object_class)
        .bind(&input.account_type)
        .bind(&attribute_mappings)
        .bind(&condition)
        .bind(input.deprovisioning_policy)
        .bind(input.priority)
        .bind(&input.description)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a construction.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateRoleConstruction,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut sets = vec![
            "updated_at = NOW()".to_string(),
            "version = version + 1".to_string(),
        ];
        let mut param_count = 3; // $1 = id, $2 = tenant_id, $3 = version

        if input.object_class.is_some() {
            param_count += 1;
            sets.push(format!("object_class = ${param_count}"));
        }
        if input.account_type.is_some() {
            param_count += 1;
            sets.push(format!("account_type = ${param_count}"));
        }
        if input.attribute_mappings.is_some() {
            param_count += 1;
            sets.push(format!("attribute_mappings = ${param_count}"));
        }
        if input.condition.is_some() {
            param_count += 1;
            sets.push(format!("condition = ${param_count}"));
        }
        if input.deprovisioning_policy.is_some() {
            param_count += 1;
            sets.push(format!("deprovisioning_policy = ${param_count}"));
        }
        if input.priority.is_some() {
            param_count += 1;
            sets.push(format!("priority = ${param_count}"));
        }
        if input.description.is_some() {
            param_count += 1;
            sets.push(format!("description = ${param_count}"));
        }

        let query = format!(
            r"
            UPDATE role_constructions
            SET {}
            WHERE id = $1 AND tenant_id = $2 AND version = $3
            RETURNING *
            ",
            sets.join(", ")
        );

        let mut q = sqlx::query_as::<_, RoleConstruction>(&query)
            .bind(id)
            .bind(tenant_id)
            .bind(input.version);

        if let Some(ref object_class) = input.object_class {
            q = q.bind(object_class);
        }
        if let Some(ref account_type) = input.account_type {
            q = q.bind(account_type);
        }
        if let Some(ref attribute_mappings) = input.attribute_mappings {
            let json = serde_json::to_value(attribute_mappings).unwrap_or_default();
            q = q.bind(json);
        }
        if let Some(ref condition_opt) = input.condition {
            let json: Option<serde_json::Value> = condition_opt
                .as_ref()
                .map(|c| serde_json::to_value(c).unwrap_or_default());
            q = q.bind(json);
        }
        if let Some(policy) = input.deprovisioning_policy {
            q = q.bind(policy);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        if let Some(ref description_opt) = input.description {
            q = q.bind(description_opt.as_ref());
        }

        q.fetch_optional(pool).await
    }

    /// Delete a construction.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM role_constructions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable a construction.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE role_constructions
            SET is_enabled = true, updated_at = NOW(), version = version + 1
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a construction.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE role_constructions
            SET is_enabled = false, updated_at = NOW(), version = version + 1
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get all enabled constructions for a set of role IDs.
    /// Used when evaluating constructions for role assignment.
    pub async fn list_enabled_by_roles(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM role_constructions
            WHERE tenant_id = $1
                AND role_id = ANY($2)
                AND is_enabled = true
            ORDER BY priority DESC, created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(role_ids)
        .fetch_all(pool)
        .await
    }

    /// Check if a construction exists for a role/connector/object_class/account_type combo.
    pub async fn exists(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
        account_type: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM role_constructions
            WHERE tenant_id = $1 AND role_id = $2 AND connector_id = $3
                AND object_class = $4 AND account_type = $5
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(connector_id)
        .bind(object_class)
        .bind(account_type)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprovisioning_policy_display() {
        assert_eq!(DeprovisioningPolicy::Disable.to_string(), "disable");
        assert_eq!(DeprovisioningPolicy::Delete.to_string(), "delete");
        assert_eq!(DeprovisioningPolicy::Retain.to_string(), "retain");
    }

    #[test]
    fn test_deprovisioning_policy_from_str() {
        assert_eq!(
            "disable".parse::<DeprovisioningPolicy>().unwrap(),
            DeprovisioningPolicy::Disable
        );
        assert_eq!(
            "DELETE".parse::<DeprovisioningPolicy>().unwrap(),
            DeprovisioningPolicy::Delete
        );
        assert!("unknown".parse::<DeprovisioningPolicy>().is_err());
    }

    #[test]
    fn test_default_deprovisioning_policy() {
        assert_eq!(
            DeprovisioningPolicy::default(),
            DeprovisioningPolicy::Disable
        );
    }

    #[test]
    fn test_attribute_mappings_default() {
        let mappings = ConstructionAttributeMappings::default();
        assert!(mappings.mappings.is_empty());
        assert_eq!(mappings.static_values, serde_json::Value::Null);
    }

    #[test]
    fn test_attribute_mapping_serialization() {
        let mapping = ConstructionAttributeMapping {
            target_attribute: "mail".to_string(),
            source: "user.email".to_string(),
            mapping_type: AttributeMappingType::Direct,
            condition: None,
        };

        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"target_attribute\":\"mail\""));
        assert!(json.contains("\"type\":\"direct\""));
    }

    #[test]
    fn test_construction_condition_serialization() {
        let condition = ConstructionCondition::Comparison {
            left: "user.employeeType".to_string(),
            operator: ConstructionConditionOperator::Eq,
            right: serde_json::json!("FTE"),
        };

        let json = serde_json::to_string(&condition).unwrap();
        assert!(json.contains("\"type\":\"comparison\""));
        assert!(json.contains("\"operator\":\"eq\""));
    }

    #[test]
    fn test_create_construction_defaults() {
        let input: CreateRoleConstruction = serde_json::from_str(
            r#"{
                "connector_id": "00000000-0000-0000-0000-000000000001",
                "object_class": "user"
            }"#,
        )
        .unwrap();

        assert_eq!(input.account_type, "default");
        assert_eq!(input.deprovisioning_policy, DeprovisioningPolicy::Disable);
        assert_eq!(input.priority, 0);
    }
}
