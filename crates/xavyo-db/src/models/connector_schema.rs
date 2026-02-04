//! Connector Schema model.
//!
//! Represents cached schema discovery results from target systems.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Error type for schema validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaValidationError {
    /// Attributes field is not an array.
    #[error("attributes must be an array")]
    AttributesNotArray,

    /// An attribute is missing a required field.
    #[error("attribute at index {index} is missing required field: {field}")]
    MissingRequiredField { index: usize, field: String },

    /// An attribute field has an invalid type.
    #[error("attribute '{name}' has invalid type for field '{field}': expected {expected}")]
    InvalidFieldType {
        name: String,
        field: String,
        expected: String,
    },

    /// Unknown data type in attribute.
    #[error("attribute '{name}' has unknown data_type: {data_type}")]
    UnknownDataType { name: String, data_type: String },
}

/// Valid data types for schema attributes.
pub const VALID_DATA_TYPES: &[&str] = &[
    "string",
    "integer",
    "long",
    "boolean",
    "binary",
    "datetime",
    "date",
    "timestamp",
    "uuid",
    "dn",
    "biginteger",
    "decimal",
    "json",
];

/// A cached connector schema (object class definition).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ConnectorSchema {
    /// Unique identifier for the schema.
    pub id: Uuid,

    /// The tenant this schema belongs to.
    pub tenant_id: Uuid,

    /// The connector this schema was discovered from.
    pub connector_id: Uuid,

    /// Object class name (canonical).
    pub object_class: String,

    /// Native name in the target system.
    pub native_name: String,

    /// Attributes definition (JSON array of `SchemaAttribute`).
    pub attributes: serde_json::Value,

    /// Whether this object class supports create operations.
    pub supports_create: bool,

    /// Whether this object class supports update operations.
    pub supports_update: bool,

    /// Whether this object class supports delete operations.
    pub supports_delete: bool,

    /// When the schema was discovered.
    pub discovered_at: DateTime<Utc>,

    /// When the cached schema expires.
    pub expires_at: DateTime<Utc>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create/update a cached schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertConnectorSchema {
    pub object_class: String,
    pub native_name: String,
    pub attributes: serde_json::Value,
    pub supports_create: bool,
    pub supports_update: bool,
    pub supports_delete: bool,
    /// TTL in seconds for cache expiry.
    pub ttl_seconds: i64,
}

/// Filter for listing schemas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaFilter {
    pub connector_id: Option<Uuid>,
    pub object_class: Option<String>,
    pub include_expired: bool,
}

impl ConnectorSchema {
    /// Find a schema by connector and object class.
    pub async fn find_by_object_class(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_schemas
            WHERE connector_id = $1 AND tenant_id = $2 AND object_class = $3
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(object_class)
        .fetch_optional(pool)
        .await
    }

    /// List all schemas for a connector.
    pub async fn list_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        include_expired: bool,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if include_expired {
            sqlx::query_as(
                r"
                SELECT * FROM connector_schemas
                WHERE connector_id = $1 AND tenant_id = $2
                ORDER BY object_class
                ",
            )
            .bind(connector_id)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM connector_schemas
                WHERE connector_id = $1 AND tenant_id = $2 AND expires_at > NOW()
                ORDER BY object_class
                ",
            )
            .bind(connector_id)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Upsert a schema (insert or update on conflict).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &UpsertConnectorSchema,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO connector_schemas (
                tenant_id, connector_id, object_class, native_name, attributes,
                supports_create, supports_update, supports_delete,
                discovered_at, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW() + ($9 || ' seconds')::interval)
            ON CONFLICT (connector_id, object_class)
            DO UPDATE SET
                native_name = EXCLUDED.native_name,
                attributes = EXCLUDED.attributes,
                supports_create = EXCLUDED.supports_create,
                supports_update = EXCLUDED.supports_update,
                supports_delete = EXCLUDED.supports_delete,
                discovered_at = NOW(),
                expires_at = NOW() + ($9 || ' seconds')::interval
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(&input.object_class)
        .bind(&input.native_name)
        .bind(&input.attributes)
        .bind(input.supports_create)
        .bind(input.supports_update)
        .bind(input.supports_delete)
        .bind(input.ttl_seconds.to_string())
        .fetch_one(pool)
        .await
    }

    /// Delete all schemas for a connector.
    pub async fn delete_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM connector_schemas
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete expired schemas.
    pub async fn delete_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM connector_schemas
            WHERE expires_at < NOW()
            ",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if schema is expired.
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Validate `schema_data` JSONB structure.
    ///
    /// Ensures the attributes array has the correct format:
    /// - Must be an array
    /// - Each item must have: name (string), `native_name` (string), `data_type` (string)
    /// - `data_type` must be one of the valid types
    pub fn validate_schema_data(
        schema_data: &serde_json::Value,
    ) -> Result<(), SchemaValidationError> {
        // For version schemas, validate object_classes array
        if let Some(object_classes) = schema_data.get("object_classes") {
            if let Some(arr) = object_classes.as_array() {
                for (oc_idx, oc) in arr.iter().enumerate() {
                    if let Some(attrs) = oc.get("attributes") {
                        Self::validate_attributes(attrs)?;
                    }
                    // Validate name field exists
                    if oc.get("name").and_then(|v| v.as_str()).is_none() {
                        return Err(SchemaValidationError::MissingRequiredField {
                            index: oc_idx,
                            field: "name".to_string(),
                        });
                    }
                }
            }
        }

        // For direct attributes array (connector_schemas table)
        if schema_data.is_array() {
            Self::validate_attributes(schema_data)?;
        }

        Ok(())
    }

    /// Validate an attributes array.
    fn validate_attributes(attributes: &serde_json::Value) -> Result<(), SchemaValidationError> {
        let arr = attributes
            .as_array()
            .ok_or(SchemaValidationError::AttributesNotArray)?;

        for (idx, attr) in arr.iter().enumerate() {
            // Check required fields exist
            let name = attr.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
                SchemaValidationError::MissingRequiredField {
                    index: idx,
                    field: "name".to_string(),
                }
            })?;

            attr.get("native_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SchemaValidationError::MissingRequiredField {
                    index: idx,
                    field: "native_name".to_string(),
                })?;

            let data_type = attr
                .get("data_type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SchemaValidationError::MissingRequiredField {
                    index: idx,
                    field: "data_type".to_string(),
                })?;

            // Validate data_type is known
            if !VALID_DATA_TYPES.contains(&data_type) {
                return Err(SchemaValidationError::UnknownDataType {
                    name: name.to_string(),
                    data_type: data_type.to_string(),
                });
            }

            // Validate boolean fields if present
            for field in &[
                "multi_valued",
                "required",
                "readable",
                "writable",
                "returned_by_default",
            ] {
                if let Some(val) = attr.get(*field) {
                    if !val.is_boolean() {
                        return Err(SchemaValidationError::InvalidFieldType {
                            name: name.to_string(),
                            field: field.to_string(),
                            expected: "boolean".to_string(),
                        });
                    }
                }
            }

            // Validate integer fields if present
            for field in &["min_length", "max_length"] {
                if let Some(val) = attr.get(*field) {
                    if !val.is_i64() && !val.is_u64() {
                        return Err(SchemaValidationError::InvalidFieldType {
                            name: name.to_string(),
                            field: field.to_string(),
                            expected: "integer".to_string(),
                        });
                    }
                }
            }

            // Validate allowed_values is an array if present
            if let Some(val) = attr.get("allowed_values") {
                if !val.is_array() {
                    return Err(SchemaValidationError::InvalidFieldType {
                        name: name.to_string(),
                        field: "allowed_values".to_string(),
                        expected: "array".to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_schema_request() {
        let request = UpsertConnectorSchema {
            object_class: "user".to_string(),
            native_name: "inetOrgPerson".to_string(),
            attributes: serde_json::json!([
                {"name": "uid", "native_name": "uid", "data_type": "string", "required": true},
                {"name": "email", "native_name": "mail", "data_type": "string"}
            ]),
            supports_create: true,
            supports_update: true,
            supports_delete: true,
            ttl_seconds: 3600,
        };

        assert_eq!(request.object_class, "user");
        assert_eq!(request.native_name, "inetOrgPerson");
        assert_eq!(request.ttl_seconds, 3600);
    }

    #[test]
    fn test_schema_filter_default() {
        let filter = SchemaFilter::default();
        assert!(filter.connector_id.is_none());
        assert!(filter.object_class.is_none());
        assert!(!filter.include_expired);
    }

    #[test]
    fn test_validate_attributes_valid() {
        let attrs = serde_json::json!([
            {"name": "uid", "native_name": "uid", "data_type": "string", "required": true},
            {"name": "email", "native_name": "mail", "data_type": "string", "multi_valued": true}
        ]);

        assert!(ConnectorSchema::validate_schema_data(&attrs).is_ok());
    }

    #[test]
    fn test_validate_attributes_missing_name() {
        let attrs = serde_json::json!([
            {"native_name": "uid", "data_type": "string"}
        ]);

        let result = ConnectorSchema::validate_schema_data(&attrs);
        assert!(matches!(
            result,
            Err(SchemaValidationError::MissingRequiredField { field, .. }) if field == "name"
        ));
    }

    #[test]
    fn test_validate_attributes_invalid_data_type() {
        let attrs = serde_json::json!([
            {"name": "uid", "native_name": "uid", "data_type": "invalid_type"}
        ]);

        let result = ConnectorSchema::validate_schema_data(&attrs);
        assert!(matches!(
            result,
            Err(SchemaValidationError::UnknownDataType { data_type, .. }) if data_type == "invalid_type"
        ));
    }

    #[test]
    fn test_validate_attributes_invalid_boolean() {
        let attrs = serde_json::json!([
            {"name": "uid", "native_name": "uid", "data_type": "string", "required": "yes"}
        ]);

        let result = ConnectorSchema::validate_schema_data(&attrs);
        assert!(matches!(
            result,
            Err(SchemaValidationError::InvalidFieldType { field, expected, .. })
            if field == "required" && expected == "boolean"
        ));
    }

    #[test]
    fn test_validate_schema_data_object_classes() {
        let schema = serde_json::json!({
            "object_classes": [
                {
                    "name": "user",
                    "native_name": "inetOrgPerson",
                    "attributes": [
                        {"name": "uid", "native_name": "uid", "data_type": "string"}
                    ]
                }
            ]
        });

        assert!(ConnectorSchema::validate_schema_data(&schema).is_ok());
    }

    #[test]
    fn test_valid_data_types() {
        assert!(VALID_DATA_TYPES.contains(&"string"));
        assert!(VALID_DATA_TYPES.contains(&"integer"));
        assert!(VALID_DATA_TYPES.contains(&"boolean"));
        assert!(VALID_DATA_TYPES.contains(&"dn"));
        assert!(VALID_DATA_TYPES.contains(&"json"));
        assert!(!VALID_DATA_TYPES.contains(&"unknown"));
    }
}
