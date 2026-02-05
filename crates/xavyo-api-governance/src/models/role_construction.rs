//! Role construction request/response models for governance API.
//!
//! DTOs for the role construction endpoints (F-063).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::{
    ConstructionAttributeMapping, ConstructionAttributeMappings, ConstructionCondition,
    ConstructionConditionOperator, DeprovisioningPolicy, RoleConstruction,
};

/// Query parameters for listing role constructions.
#[derive(Debug, Clone, Deserialize, IntoParams, Default)]
pub struct ListConstructionsQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Only return enabled constructions.
    #[serde(default)]
    pub enabled_only: bool,

    /// Filter by object class.
    pub object_class: Option<String>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Request to create a new role construction.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateConstructionRequest {
    /// Target connector for provisioning.
    pub connector_id: Uuid,

    /// Object class to provision (e.g., "user", "group").
    #[validate(length(
        min = 1,
        max = 255,
        message = "Object class must be between 1 and 255 characters"
    ))]
    pub object_class: String,

    /// Account type identifier (e.g., "standard", "privileged").
    #[serde(default = "default_account_type")]
    #[validate(length(max = 100, message = "Account type must be at most 100 characters"))]
    pub account_type: String,

    /// Attribute mapping configuration.
    #[serde(default)]
    pub attribute_mappings: AttributeMappingsDto,

    /// Optional condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionDto>,

    /// Deprovisioning policy.
    #[serde(default)]
    pub deprovisioning_policy: DeprovisioningPolicyDto,

    /// Execution priority (higher = executed first).
    #[serde(default)]
    pub priority: i32,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2000, message = "Description must be at most 2000 characters"))]
    pub description: Option<String>,
}

fn default_account_type() -> String {
    "default".to_string()
}

/// Request to update a role construction.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateConstructionRequest {
    /// Updated object class.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(
        min = 1,
        max = 255,
        message = "Object class must be between 1 and 255 characters"
    ))]
    pub object_class: Option<String>,

    /// Updated account type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 100, message = "Account type must be at most 100 characters"))]
    pub account_type: Option<String>,

    /// Updated attribute mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_mappings: Option<AttributeMappingsDto>,

    /// Updated condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<Option<ConditionDto>>,

    /// Updated deprovisioning policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprovisioning_policy: Option<DeprovisioningPolicyDto>,

    /// Updated priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Updated description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2000, message = "Description must be at most 2000 characters"))]
    pub description: Option<Option<String>>,

    /// Version for optimistic concurrency check (required).
    pub version: i32,
}

/// Deprovisioning policy DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeprovisioningPolicyDto {
    /// Disable the provisioned account.
    #[default]
    Disable,
    /// Delete the provisioned account.
    Delete,
    /// Retain the account (no action).
    Retain,
}

impl From<DeprovisioningPolicy> for DeprovisioningPolicyDto {
    fn from(policy: DeprovisioningPolicy) -> Self {
        match policy {
            DeprovisioningPolicy::Disable => DeprovisioningPolicyDto::Disable,
            DeprovisioningPolicy::Delete => DeprovisioningPolicyDto::Delete,
            DeprovisioningPolicy::Retain => DeprovisioningPolicyDto::Retain,
        }
    }
}

impl From<DeprovisioningPolicyDto> for DeprovisioningPolicy {
    fn from(dto: DeprovisioningPolicyDto) -> Self {
        match dto {
            DeprovisioningPolicyDto::Disable => DeprovisioningPolicy::Disable,
            DeprovisioningPolicyDto::Delete => DeprovisioningPolicy::Delete,
            DeprovisioningPolicyDto::Retain => DeprovisioningPolicy::Retain,
        }
    }
}

/// Attribute mappings configuration DTO.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct AttributeMappingsDto {
    /// Dynamic attribute mappings.
    #[serde(default)]
    pub mappings: Vec<AttributeMappingDto>,

    /// Static values to set on the provisioned object.
    #[serde(default)]
    pub static_values: serde_json::Value,
}

impl From<ConstructionAttributeMappings> for AttributeMappingsDto {
    fn from(mappings: ConstructionAttributeMappings) -> Self {
        Self {
            mappings: mappings.mappings.into_iter().map(Into::into).collect(),
            static_values: mappings.static_values,
        }
    }
}

impl From<AttributeMappingsDto> for ConstructionAttributeMappings {
    fn from(dto: AttributeMappingsDto) -> Self {
        Self {
            mappings: dto.mappings.into_iter().map(Into::into).collect(),
            static_values: dto.static_values,
        }
    }
}

/// A single attribute mapping rule DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttributeMappingDto {
    /// Target attribute name in the connector's object.
    pub target_attribute: String,

    /// Source expression (e.g., "user.email").
    pub source: String,

    /// Mapping type.
    #[serde(rename = "type")]
    pub mapping_type: AttributeMappingTypeDto,

    /// Optional condition for this mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

impl From<ConstructionAttributeMapping> for AttributeMappingDto {
    fn from(mapping: ConstructionAttributeMapping) -> Self {
        Self {
            target_attribute: mapping.target_attribute,
            source: mapping.source,
            mapping_type: mapping.mapping_type.into(),
            condition: mapping.condition,
        }
    }
}

impl From<AttributeMappingDto> for ConstructionAttributeMapping {
    fn from(dto: AttributeMappingDto) -> Self {
        Self {
            target_attribute: dto.target_attribute,
            source: dto.source,
            mapping_type: dto.mapping_type.into(),
            condition: dto.condition,
        }
    }
}

/// Attribute mapping type DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AttributeMappingTypeDto {
    /// Direct mapping.
    Direct,
    /// Expression mapping.
    Expression,
}

impl From<xavyo_db::AttributeMappingType> for AttributeMappingTypeDto {
    fn from(mt: xavyo_db::AttributeMappingType) -> Self {
        match mt {
            xavyo_db::AttributeMappingType::Direct => AttributeMappingTypeDto::Direct,
            xavyo_db::AttributeMappingType::Expression => AttributeMappingTypeDto::Expression,
        }
    }
}

impl From<AttributeMappingTypeDto> for xavyo_db::AttributeMappingType {
    fn from(dto: AttributeMappingTypeDto) -> Self {
        match dto {
            AttributeMappingTypeDto::Direct => xavyo_db::AttributeMappingType::Direct,
            AttributeMappingTypeDto::Expression => xavyo_db::AttributeMappingType::Expression,
        }
    }
}

/// Condition expression DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ConditionDto {
    /// Comparison condition.
    Comparison {
        /// Left operand (attribute path).
        left: String,
        /// Comparison operator.
        operator: ConditionOperatorDto,
        /// Right operand (value or array).
        right: serde_json::Value,
    },
    /// Logical AND of conditions.
    And {
        /// Nested conditions.
        conditions: Vec<ConditionDto>,
    },
    /// Logical OR of conditions.
    Or {
        /// Nested conditions.
        conditions: Vec<ConditionDto>,
    },
    /// Logical NOT of a condition.
    Not {
        /// Nested condition.
        condition: Box<ConditionDto>,
    },
}

impl From<ConstructionCondition> for ConditionDto {
    fn from(condition: ConstructionCondition) -> Self {
        match condition {
            ConstructionCondition::Comparison {
                left,
                operator,
                right,
            } => ConditionDto::Comparison {
                left,
                operator: operator.into(),
                right,
            },
            ConstructionCondition::And { conditions } => ConditionDto::And {
                conditions: conditions.into_iter().map(Into::into).collect(),
            },
            ConstructionCondition::Or { conditions } => ConditionDto::Or {
                conditions: conditions.into_iter().map(Into::into).collect(),
            },
            ConstructionCondition::Not { condition } => ConditionDto::Not {
                condition: Box::new((*condition).into()),
            },
        }
    }
}

impl From<ConditionDto> for ConstructionCondition {
    fn from(dto: ConditionDto) -> Self {
        match dto {
            ConditionDto::Comparison {
                left,
                operator,
                right,
            } => ConstructionCondition::Comparison {
                left,
                operator: operator.into(),
                right,
            },
            ConditionDto::And { conditions } => ConstructionCondition::And {
                conditions: conditions.into_iter().map(Into::into).collect(),
            },
            ConditionDto::Or { conditions } => ConstructionCondition::Or {
                conditions: conditions.into_iter().map(Into::into).collect(),
            },
            ConditionDto::Not { condition } => ConstructionCondition::Not {
                condition: Box::new((*condition).into()),
            },
        }
    }
}

/// Condition operator DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperatorDto {
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

impl From<ConstructionConditionOperator> for ConditionOperatorDto {
    fn from(op: ConstructionConditionOperator) -> Self {
        match op {
            ConstructionConditionOperator::Eq => ConditionOperatorDto::Eq,
            ConstructionConditionOperator::Ne => ConditionOperatorDto::Ne,
            ConstructionConditionOperator::Gt => ConditionOperatorDto::Gt,
            ConstructionConditionOperator::Gte => ConditionOperatorDto::Gte,
            ConstructionConditionOperator::Lt => ConditionOperatorDto::Lt,
            ConstructionConditionOperator::Lte => ConditionOperatorDto::Lte,
            ConstructionConditionOperator::In => ConditionOperatorDto::In,
            ConstructionConditionOperator::Contains => ConditionOperatorDto::Contains,
            ConstructionConditionOperator::StartsWith => ConditionOperatorDto::StartsWith,
            ConstructionConditionOperator::EndsWith => ConditionOperatorDto::EndsWith,
        }
    }
}

impl From<ConditionOperatorDto> for ConstructionConditionOperator {
    fn from(dto: ConditionOperatorDto) -> Self {
        match dto {
            ConditionOperatorDto::Eq => ConstructionConditionOperator::Eq,
            ConditionOperatorDto::Ne => ConstructionConditionOperator::Ne,
            ConditionOperatorDto::Gt => ConstructionConditionOperator::Gt,
            ConditionOperatorDto::Gte => ConstructionConditionOperator::Gte,
            ConditionOperatorDto::Lt => ConstructionConditionOperator::Lt,
            ConditionOperatorDto::Lte => ConstructionConditionOperator::Lte,
            ConditionOperatorDto::In => ConstructionConditionOperator::In,
            ConditionOperatorDto::Contains => ConstructionConditionOperator::Contains,
            ConditionOperatorDto::StartsWith => ConstructionConditionOperator::StartsWith,
            ConditionOperatorDto::EndsWith => ConstructionConditionOperator::EndsWith,
        }
    }
}

/// Role construction response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConstructionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Role ID.
    pub role_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// Connector name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,

    /// Object class.
    pub object_class: String,

    /// Account type.
    pub account_type: String,

    /// Attribute mappings.
    pub attribute_mappings: AttributeMappingsDto,

    /// Condition expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionDto>,

    /// Deprovisioning policy.
    pub deprovisioning_policy: DeprovisioningPolicyDto,

    /// Execution priority.
    pub priority: i32,

    /// Whether enabled.
    pub is_enabled: bool,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optimistic concurrency version.
    pub version: i32,

    /// Creator user ID.
    pub created_by: Uuid,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl ConstructionResponse {
    /// Create response from database model.
    pub fn from_model(construction: RoleConstruction, connector_name: Option<String>) -> Self {
        let attribute_mappings: AttributeMappingsDto =
            serde_json::from_value(construction.attribute_mappings.clone()).unwrap_or_default();

        let condition: Option<ConditionDto> = construction
            .condition
            .as_ref()
            .and_then(|c| serde_json::from_value(c.clone()).ok());

        Self {
            id: construction.id,
            tenant_id: construction.tenant_id,
            role_id: construction.role_id,
            connector_id: construction.connector_id,
            connector_name,
            object_class: construction.object_class,
            account_type: construction.account_type,
            attribute_mappings,
            condition,
            deprovisioning_policy: construction.deprovisioning_policy.into(),
            priority: construction.priority,
            is_enabled: construction.is_enabled,
            description: construction.description,
            version: construction.version,
            created_by: construction.created_by,
            created_at: construction.created_at,
            updated_at: construction.updated_at,
        }
    }
}

impl From<RoleConstruction> for ConstructionResponse {
    fn from(construction: RoleConstruction) -> Self {
        Self::from_model(construction, None)
    }
}

/// List constructions response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConstructionListResponse {
    /// List of constructions.
    pub items: Vec<ConstructionResponse>,

    /// Total count.
    pub total: i64,
}

/// Effective construction response (includes source role info).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveConstructionResponse {
    /// The construction.
    pub construction: ConstructionResponse,

    /// Source role ID.
    pub source_role_id: Uuid,

    /// Source role name.
    pub source_role_name: String,

    /// True if from the queried role, false if induced.
    pub is_direct: bool,
}

/// Effective constructions response for a role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveConstructionsResponse {
    /// List of effective constructions.
    pub constructions: Vec<EffectiveConstructionResponse>,
}

/// User effective construction response (includes all source roles).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserEffectiveConstructionResponse {
    /// The construction.
    pub construction: ConstructionResponse,

    /// All roles that provide this construction to the user.
    pub source_roles: Vec<SourceRoleInfo>,
}

/// Source role info for user effective constructions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourceRoleInfo {
    /// Role ID.
    pub role_id: Uuid,

    /// Role name.
    pub role_name: String,
}

/// User effective constructions response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserEffectiveConstructionsResponse {
    /// User ID.
    pub user_id: Uuid,

    /// List of effective constructions.
    pub constructions: Vec<UserEffectiveConstructionResponse>,
}
