//! Mapping Service for managing attribute mappings.
//!
//! Provides CRUD operations and preview functionality for attribute mappings.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use sqlx::PgPool;
use xavyo_connector::mapping::{
    AttributeSource, CorrelationRule, MappingConfiguration, MappingRule,
};
use xavyo_connector::transform::TransformEngine;
use xavyo_connector::types::DeprovisionAction as ConnectorDeprovisionAction;
use xavyo_db::models::{
    ConnectorAttributeMapping as AttributeMapping,
    CreateConnectorAttributeMapping as CreateAttributeMapping,
    DeprovisionAction as DbDeprovisionAction,
    UpdateConnectorAttributeMapping as UpdateAttributeMapping,
};

use crate::error::{ConnectorApiError, Result};

/// Response type for mapping operations.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MappingResponse {
    /// Mapping ID.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Object class this mapping applies to.
    pub object_class: String,
    /// Mapping name.
    pub name: String,
    /// Whether this is the default mapping.
    pub is_default: bool,
    /// Attribute mapping rules.
    pub mappings: serde_json::Value,
    /// Correlation rule for identity matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_rule: Option<serde_json::Value>,
    /// Deprovision action.
    pub deprovision_action: String,
    /// When the mapping was created.
    pub created_at: chrono::DateTime<Utc>,
    /// When the mapping was last updated.
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<AttributeMapping> for MappingResponse {
    fn from(m: AttributeMapping) -> Self {
        Self {
            id: m.id,
            connector_id: m.connector_id,
            object_class: m.object_class,
            name: m.name,
            is_default: m.is_default,
            mappings: m.mappings,
            correlation_rule: m.correlation_rule,
            deprovision_action: m.deprovision_action.to_string(),
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// Request to create a mapping.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateMappingRequest {
    /// Object class this mapping applies to.
    pub object_class: String,
    /// Mapping name.
    pub name: String,
    /// Whether this is the default mapping for the object class.
    #[serde(default)]
    pub is_default: bool,
    /// Attribute mapping rules.
    pub mappings: serde_json::Value,
    /// Optional correlation rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_rule: Option<serde_json::Value>,
    /// Deprovision action (defaults to "disable").
    #[serde(default = "default_deprovision_action")]
    pub deprovision_action: String,
}

fn default_deprovision_action() -> String {
    "disable".to_string()
}

/// Request to update a mapping.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateMappingRequest {
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether this is the default mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    /// Updated attribute mapping rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<serde_json::Value>,
    /// Updated correlation rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_rule: Option<serde_json::Value>,
    /// Updated deprovision action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprovision_action: Option<String>,
}

/// Request to preview a mapping transformation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PreviewMappingRequest {
    /// Source attributes to transform.
    pub source_attributes: HashMap<String, String>,
    /// Whether this is a create operation (vs update).
    #[serde(default = "default_true")]
    pub is_create: bool,
}

fn default_true() -> bool {
    true
}

/// Response for mapping preview.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PreviewMappingResponse {
    /// Transformed attributes (target_attr -> value).
    pub attributes: HashMap<String, String>,
    /// Any errors during transformation.
    pub errors: Vec<TransformError>,
    /// Whether the transformation has fatal errors.
    pub has_errors: bool,
}

/// A transformation error.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TransformError {
    /// Target attribute that failed.
    pub target_attribute: String,
    /// Error message.
    pub message: String,
    /// Whether this is a fatal error.
    pub fatal: bool,
}

/// Service for managing attribute mappings.
pub struct MappingService {
    pool: PgPool,
    transform_engine: Arc<TransformEngine>,
}

impl MappingService {
    /// Create a new mapping service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            transform_engine: Arc::new(TransformEngine::new()),
        }
    }

    /// Create a new mapping.
    pub async fn create_mapping(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        request: CreateMappingRequest,
    ) -> Result<MappingResponse> {
        debug!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            object_class = %request.object_class,
            name = %request.name,
            "Creating attribute mapping"
        );

        // Validate deprovision action
        let deprovision_action: DbDeprovisionAction =
            request.deprovision_action.parse().map_err(|_| {
                ConnectorApiError::Validation(format!(
                    "Invalid deprovision action: {}",
                    request.deprovision_action
                ))
            })?;

        // Validate mappings structure
        self.validate_mappings(&request.mappings)?;

        let create = CreateAttributeMapping {
            object_class: request.object_class,
            name: request.name,
            is_default: request.is_default,
            mappings: request.mappings,
            correlation_rule: request.correlation_rule,
            deprovision_action: Some(deprovision_action),
        };

        let mapping =
            AttributeMapping::create(&self.pool, tenant_id, connector_id, &create).await?;

        info!(
            tenant_id = %tenant_id,
            mapping_id = %mapping.id,
            object_class = %mapping.object_class,
            "Attribute mapping created"
        );

        Ok(mapping.into())
    }

    /// Get a mapping by ID.
    pub async fn get_mapping(&self, tenant_id: Uuid, mapping_id: Uuid) -> Result<MappingResponse> {
        let mapping = AttributeMapping::find_by_id(&self.pool, tenant_id, mapping_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "mapping".to_string(),
                id: mapping_id.to_string(),
            })?;

        Ok(mapping.into())
    }

    /// List mappings for a connector.
    pub async fn list_mappings(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: Option<&str>,
    ) -> Result<Vec<MappingResponse>> {
        let mappings =
            AttributeMapping::list_by_connector(&self.pool, tenant_id, connector_id, object_class)
                .await?;

        Ok(mappings.into_iter().map(Into::into).collect())
    }

    /// Get the default mapping for a connector and object class.
    pub async fn get_default_mapping(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
    ) -> Result<Option<MappingResponse>> {
        let mapping =
            AttributeMapping::find_default(&self.pool, tenant_id, connector_id, object_class)
                .await?;

        Ok(mapping.map(Into::into))
    }

    /// Update a mapping.
    pub async fn update_mapping(
        &self,
        tenant_id: Uuid,
        mapping_id: Uuid,
        request: UpdateMappingRequest,
    ) -> Result<MappingResponse> {
        debug!(
            tenant_id = %tenant_id,
            mapping_id = %mapping_id,
            "Updating attribute mapping"
        );

        // Validate deprovision action if provided
        let deprovision_action: Option<DbDeprovisionAction> =
            if let Some(ref action) = request.deprovision_action {
                Some(action.parse().map_err(|_| {
                    ConnectorApiError::Validation(format!("Invalid deprovision action: {}", action))
                })?)
            } else {
                None
            };

        // Validate mappings if provided
        if let Some(ref mappings) = request.mappings {
            self.validate_mappings(mappings)?;
        }

        let update = UpdateAttributeMapping {
            name: request.name,
            is_default: request.is_default,
            mappings: request.mappings,
            correlation_rule: request.correlation_rule,
            deprovision_action,
        };

        let mapping = AttributeMapping::update(&self.pool, tenant_id, mapping_id, &update)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "mapping".to_string(),
                id: mapping_id.to_string(),
            })?;

        info!(
            tenant_id = %tenant_id,
            mapping_id = %mapping.id,
            "Attribute mapping updated"
        );

        Ok(mapping.into())
    }

    /// Delete a mapping.
    pub async fn delete_mapping(&self, tenant_id: Uuid, mapping_id: Uuid) -> Result<()> {
        debug!(
            tenant_id = %tenant_id,
            mapping_id = %mapping_id,
            "Deleting attribute mapping"
        );

        let deleted = AttributeMapping::delete(&self.pool, tenant_id, mapping_id).await?;

        if !deleted {
            return Err(ConnectorApiError::NotFound {
                resource: "mapping".to_string(),
                id: mapping_id.to_string(),
            });
        }

        info!(
            tenant_id = %tenant_id,
            mapping_id = %mapping_id,
            "Attribute mapping deleted"
        );

        Ok(())
    }

    /// Preview a mapping transformation.
    pub async fn preview_mapping(
        &self,
        tenant_id: Uuid,
        mapping_id: Uuid,
        request: PreviewMappingRequest,
    ) -> Result<PreviewMappingResponse> {
        debug!(
            tenant_id = %tenant_id,
            mapping_id = %mapping_id,
            is_create = request.is_create,
            "Previewing mapping transformation"
        );

        // Get the mapping
        let mapping = AttributeMapping::find_by_id(&self.pool, tenant_id, mapping_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "mapping".to_string(),
                id: mapping_id.to_string(),
            })?;

        // Parse mappings to MappingConfiguration
        let config = self.parse_mapping_config(&mapping)?;

        // Evaluate the mapping
        let result =
            self.transform_engine
                .evaluate(&config, &request.source_attributes, request.is_create);

        let errors: Vec<TransformError> = result
            .errors
            .into_iter()
            .map(|e| TransformError {
                target_attribute: e.target_attribute,
                message: e.message,
                fatal: e.fatal,
            })
            .collect();

        let has_errors = errors.iter().any(|e| e.fatal);

        Ok(PreviewMappingResponse {
            attributes: result.attributes,
            errors,
            has_errors,
        })
    }

    /// Validate mappings JSON structure.
    fn validate_mappings(&self, mappings: &serde_json::Value) -> Result<()> {
        // Mappings should be an array of MappingRule objects
        if !mappings.is_array() && !mappings.is_object() {
            return Err(ConnectorApiError::Validation(
                "Mappings must be an array of rules or an object".to_string(),
            ));
        }

        // If it's an object, assume it's the simple format {source: target}
        if mappings.is_object() {
            return Ok(());
        }

        // Validate array format
        let rules = mappings.as_array().unwrap();
        for (i, rule) in rules.iter().enumerate() {
            if !rule.is_object() {
                return Err(ConnectorApiError::Validation(format!(
                    "Mapping rule {} must be an object",
                    i
                )));
            }

            // Check required fields
            if rule.get("target_attribute").is_none() {
                return Err(ConnectorApiError::Validation(format!(
                    "Mapping rule {} missing 'target_attribute'",
                    i
                )));
            }
            if rule.get("source").is_none() {
                return Err(ConnectorApiError::Validation(format!(
                    "Mapping rule {} missing 'source'",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Parse a database mapping to a MappingConfiguration for the transform engine.
    fn parse_mapping_config(&self, mapping: &AttributeMapping) -> Result<MappingConfiguration> {
        // Try to parse mappings as array of MappingRule
        let attribute_mappings: Vec<MappingRule> = if mapping.mappings.is_array() {
            serde_json::from_value(mapping.mappings.clone()).map_err(|e| {
                ConnectorApiError::Validation(format!("Invalid mapping rules: {}", e))
            })?
        } else if mapping.mappings.is_object() {
            // Simple format: {source_attr: target_attr}
            let obj = mapping.mappings.as_object().unwrap();
            obj.iter()
                .map(|(source, target)| {
                    let target_attr = target.as_str().unwrap_or_default().to_string();
                    MappingRule {
                        target_attribute: target_attr,
                        source: AttributeSource::Attribute {
                            name: source.clone(),
                        },
                        transform: None,
                        required: false,
                        on_create: true,
                        on_update: true,
                    }
                })
                .collect()
        } else {
            return Err(ConnectorApiError::Validation(
                "Mappings must be an array or object".to_string(),
            ));
        };

        // Parse correlation rules
        let correlation_rules: Vec<CorrelationRule> = if let Some(ref cr) = mapping.correlation_rule
        {
            serde_json::from_value(cr.clone()).unwrap_or_default()
        } else {
            vec![]
        };

        // Parse deprovision action
        let deprovision_action = match mapping.deprovision_action {
            DbDeprovisionAction::Disable => ConnectorDeprovisionAction::Disable,
            DbDeprovisionAction::Delete => ConnectorDeprovisionAction::Delete,
        };

        Ok(MappingConfiguration {
            object_class: mapping.object_class.clone(),
            attribute_mappings,
            correlation_rules,
            deprovision_action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_response_from_attribute_mapping() {
        let mapping = AttributeMapping {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            object_class: "user".to_string(),
            name: "default".to_string(),
            is_default: true,
            mappings: serde_json::json!([
                {
                    "target_attribute": "mail",
                    "source": { "type": "attribute", "name": "email" }
                }
            ]),
            correlation_rule: None,
            deprovision_action: DbDeprovisionAction::Disable,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response: MappingResponse = mapping.into();
        assert_eq!(response.object_class, "user");
        assert_eq!(response.name, "default");
        assert!(response.is_default);
        assert_eq!(response.deprovision_action, "disable");
    }

    #[test]
    fn test_create_mapping_request_defaults() {
        let json = r#"{
            "object_class": "user",
            "name": "test",
            "mappings": {}
        }"#;

        let request: CreateMappingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.object_class, "user");
        assert_eq!(request.name, "test");
        assert!(!request.is_default);
        assert_eq!(request.deprovision_action, "disable");
    }

    #[test]
    fn test_preview_request_defaults() {
        let json = r#"{
            "source_attributes": {"email": "test@example.com"}
        }"#;

        let request: PreviewMappingRequest = serde_json::from_str(json).unwrap();
        assert!(request.is_create);
        assert_eq!(
            request.source_attributes.get("email"),
            Some(&"test@example.com".to_string())
        );
    }

    #[test]
    fn test_transform_error_serialization() {
        let error = TransformError {
            target_attribute: "mail".to_string(),
            message: "Required attribute missing".to_string(),
            fatal: true,
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"fatal\":true"));
    }
}
