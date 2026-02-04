//! SCIM Attribute Mapping entity model.
//!
//! Custom attribute mapping configuration per tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Transform function for attribute values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributeTransform {
    Lowercase,
    Uppercase,
    Trim,
}

impl std::fmt::Display for AttributeTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttributeTransform::Lowercase => write!(f, "lowercase"),
            AttributeTransform::Uppercase => write!(f, "uppercase"),
            AttributeTransform::Trim => write!(f, "trim"),
        }
    }
}

impl std::str::FromStr for AttributeTransform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lowercase" => Ok(AttributeTransform::Lowercase),
            "uppercase" => Ok(AttributeTransform::Uppercase),
            "trim" => Ok(AttributeTransform::Trim),
            _ => Err(format!("Invalid transform: {s}")),
        }
    }
}

/// A SCIM attribute mapping configuration.
///
/// Maps SCIM attribute paths to Xavyo user fields.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScimAttributeMapping {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// The tenant this mapping belongs to.
    pub tenant_id: Uuid,

    /// SCIM attribute path (e.g., "name.givenName").
    pub scim_path: String,

    /// Target Xavyo user field.
    pub xavyo_field: String,

    /// Optional transform function.
    pub transform: Option<String>,

    /// Whether the attribute is required.
    pub required: bool,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,

    /// When the mapping was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update a mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRequest {
    pub scim_path: String,
    pub xavyo_field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Bulk update request for mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMappingsRequest {
    pub mappings: Vec<MappingRequest>,
}

impl ScimAttributeMapping {
    /// Get the transform function if valid.
    #[must_use]
    pub fn get_transform(&self) -> Option<AttributeTransform> {
        self.transform.as_ref().and_then(|t| t.parse().ok())
    }

    /// Apply the transform to a value.
    #[must_use]
    pub fn apply_transform(&self, value: &str) -> String {
        match self.get_transform() {
            Some(AttributeTransform::Lowercase) => value.to_lowercase(),
            Some(AttributeTransform::Uppercase) => value.to_uppercase(),
            Some(AttributeTransform::Trim) => value.trim().to_string(),
            None => value.to_string(),
        }
    }

    /// List all mappings for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM scim_attribute_mappings
            WHERE tenant_id = $1
            ORDER BY scim_path
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Find a mapping by SCIM path.
    pub async fn find_by_path(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        scim_path: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM scim_attribute_mappings
            WHERE tenant_id = $1 AND scim_path = $2
            ",
        )
        .bind(tenant_id)
        .bind(scim_path)
        .fetch_optional(pool)
        .await
    }

    /// Upsert a mapping.
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        scim_path: &str,
        xavyo_field: &str,
        transform: Option<&str>,
        required: bool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO scim_attribute_mappings (tenant_id, scim_path, xavyo_field, transform, required)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, scim_path) DO UPDATE SET
                xavyo_field = EXCLUDED.xavyo_field,
                transform = EXCLUDED.transform,
                required = EXCLUDED.required,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(scim_path)
        .bind(xavyo_field)
        .bind(transform)
        .bind(required)
        .fetch_one(pool)
        .await
    }

    /// Delete a mapping.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        scim_path: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM scim_attribute_mappings
            WHERE tenant_id = $1 AND scim_path = $2
            ",
        )
        .bind(tenant_id)
        .bind(scim_path)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Create default mappings for a tenant.
    pub async fn create_defaults(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT create_default_scim_mappings($1)")
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_parsing() {
        assert_eq!(
            "lowercase".parse::<AttributeTransform>().unwrap(),
            AttributeTransform::Lowercase
        );
        assert_eq!(
            "UPPERCASE".parse::<AttributeTransform>().unwrap(),
            AttributeTransform::Uppercase
        );
        assert!("invalid".parse::<AttributeTransform>().is_err());
    }

    #[test]
    fn test_apply_transform() {
        let mapping = ScimAttributeMapping {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            scim_path: "userName".to_string(),
            xavyo_field: "email".to_string(),
            transform: Some("lowercase".to_string()),
            required: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(
            mapping.apply_transform("John@Example.COM"),
            "john@example.com"
        );
    }

    #[test]
    fn test_apply_trim() {
        let mapping = ScimAttributeMapping {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            scim_path: "displayName".to_string(),
            xavyo_field: "display_name".to_string(),
            transform: Some("trim".to_string()),
            required: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(mapping.apply_transform("  John Doe  "), "John Doe");
    }
}
