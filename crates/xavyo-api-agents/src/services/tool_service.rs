//! Tool service for managing AI tools.
//!
//! Provides business logic for tool CRUD operations and JSON Schema validation.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    CreateToolRequest, ListToolsQuery, ToolListResponse, ToolResponse, UpdateToolRequest,
};
use xavyo_db::models::ai_tool::{AiTool, AiToolFilter, CreateAiTool, UpdateAiTool};

/// Service for managing AI tools.
#[derive(Clone)]
pub struct ToolService {
    pool: PgPool,
}

impl ToolService {
    /// Create a new ToolService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new tool.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateToolRequest,
    ) -> Result<ToolResponse, ApiAgentsError> {
        // Validate risk level
        self.validate_risk_level(&request.risk_level)?;

        // Validate input schema is a valid JSON Schema
        self.validate_json_schema(&request.input_schema)?;

        // Check for duplicate name
        if let Some(_existing) = AiTool::find_by_name(&self.pool, tenant_id, &request.name).await? {
            return Err(ApiAgentsError::ToolNameExists);
        }

        let input = CreateAiTool {
            name: request.name,
            description: request.description,
            category: request.category,
            input_schema: request.input_schema,
            output_schema: request.output_schema,
            risk_level: Some(request.risk_level),
            requires_approval: Some(request.requires_approval),
            max_calls_per_hour: request.max_calls_per_hour,
            provider: request.provider,
            provider_verified: Some(false),
            checksum: None,
        };

        let tool = AiTool::create(&self.pool, tenant_id, input).await?;

        Ok(self.to_response(tool))
    }

    /// Get a tool by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        tool_id: Uuid,
    ) -> Result<ToolResponse, ApiAgentsError> {
        let tool = AiTool::find_by_id(&self.pool, tenant_id, tool_id)
            .await?
            .ok_or(ApiAgentsError::ToolNotFound)?;

        Ok(self.to_response(tool))
    }

    /// Get a tool by name.
    pub async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<AiTool>, ApiAgentsError> {
        Ok(AiTool::find_by_name(&self.pool, tenant_id, name).await?)
    }

    /// List tools for a tenant with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListToolsQuery,
    ) -> Result<ToolListResponse, ApiAgentsError> {
        let filter = AiToolFilter {
            status: query.status,
            category: query.category,
            risk_level: query.risk_level,
            requires_approval: query.requires_approval,
            provider_verified: None,
            name_contains: query.name,
        };

        let limit = query.limit.min(1000) as i64;
        let offset = query.offset.max(0) as i64;

        let tools = AiTool::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = AiTool::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(ToolListResponse {
            tools: tools.into_iter().map(|t| self.to_response(t)).collect(),
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }

    /// Update a tool.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        tool_id: Uuid,
        request: UpdateToolRequest,
    ) -> Result<ToolResponse, ApiAgentsError> {
        // Validate risk level if provided
        if let Some(ref risk_level) = request.risk_level {
            self.validate_risk_level(risk_level)?;
        }

        // Validate input schema if provided
        if let Some(ref schema) = request.input_schema {
            self.validate_json_schema(schema)?;
        }

        // Validate status if provided
        if let Some(ref status) = request.status {
            self.validate_tool_status(status)?;
        }

        // Check tool exists
        AiTool::find_by_id(&self.pool, tenant_id, tool_id)
            .await?
            .ok_or(ApiAgentsError::ToolNotFound)?;

        let input = UpdateAiTool {
            name: None, // Name is not updatable
            description: request.description,
            category: request.category,
            input_schema: request.input_schema,
            output_schema: request.output_schema,
            risk_level: request.risk_level,
            requires_approval: request.requires_approval,
            max_calls_per_hour: request.max_calls_per_hour,
            provider: request.provider,
            provider_verified: None,
            checksum: None,
            status: request.status,
        };

        let tool = AiTool::update(&self.pool, tenant_id, tool_id, input)
            .await?
            .ok_or(ApiAgentsError::ToolNotFound)?;

        Ok(self.to_response(tool))
    }

    /// Delete a tool.
    pub async fn delete(&self, tenant_id: Uuid, tool_id: Uuid) -> Result<(), ApiAgentsError> {
        let deleted = AiTool::delete(&self.pool, tenant_id, tool_id).await?;

        if !deleted {
            return Err(ApiAgentsError::ToolNotFound);
        }

        Ok(())
    }

    /// Validate risk level.
    fn validate_risk_level(&self, risk_level: &str) -> Result<(), ApiAgentsError> {
        match risk_level.to_lowercase().as_str() {
            "low" | "medium" | "high" | "critical" => Ok(()),
            _ => Err(ApiAgentsError::InvalidRiskLevel(risk_level.to_string())),
        }
    }

    /// Validate tool status.
    fn validate_tool_status(&self, status: &str) -> Result<(), ApiAgentsError> {
        match status.to_lowercase().as_str() {
            "active" | "inactive" | "deprecated" => Ok(()),
            _ => Err(ApiAgentsError::InvalidStatus(status.to_string())),
        }
    }

    /// Validate JSON Schema (basic validation).
    fn validate_json_schema(&self, schema: &serde_json::Value) -> Result<(), ApiAgentsError> {
        // Basic validation: must be an object
        if !schema.is_object() {
            return Err(ApiAgentsError::InvalidInputSchema(
                "Schema must be a JSON object".to_string(),
            ));
        }

        // Check for $schema if present (optional, but validates if exists)
        if let Some(schema_uri) = schema.get("$schema") {
            if !schema_uri.is_string() {
                return Err(ApiAgentsError::InvalidInputSchema(
                    "$schema must be a string".to_string(),
                ));
            }
        }

        // Check for type field (recommended but not required)
        // Most JSON Schemas should have a "type" field
        // We allow schemas without type for flexibility

        Ok(())
    }

    /// Convert database model to API response.
    fn to_response(&self, tool: AiTool) -> ToolResponse {
        ToolResponse {
            id: tool.id,
            name: tool.name,
            description: tool.description,
            category: tool.category,
            input_schema: tool.input_schema,
            output_schema: tool.output_schema,
            risk_level: tool.risk_level,
            requires_approval: tool.requires_approval,
            max_calls_per_hour: tool.max_calls_per_hour,
            provider: tool.provider,
            provider_verified: tool.provider_verified,
            status: tool.status,
            created_at: tool.created_at,
            updated_at: tool.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Test validation functions without requiring a database connection
    fn validate_risk_level(risk_level: &str) -> Result<(), ApiAgentsError> {
        match risk_level.to_lowercase().as_str() {
            "low" | "medium" | "high" | "critical" => Ok(()),
            _ => Err(ApiAgentsError::InvalidRiskLevel(risk_level.to_string())),
        }
    }

    fn validate_tool_status(status: &str) -> Result<(), ApiAgentsError> {
        match status.to_lowercase().as_str() {
            "active" | "inactive" | "deprecated" => Ok(()),
            _ => Err(ApiAgentsError::InvalidStatus(status.to_string())),
        }
    }

    fn validate_json_schema(schema: &serde_json::Value) -> Result<(), ApiAgentsError> {
        if !schema.is_object() {
            return Err(ApiAgentsError::InvalidInputSchema(
                "Schema must be a JSON object".to_string(),
            ));
        }
        if let Some(schema_uri) = schema.get("$schema") {
            if !schema_uri.is_string() {
                return Err(ApiAgentsError::InvalidInputSchema(
                    "$schema must be a string".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn test_validate_risk_level() {
        assert!(validate_risk_level("low").is_ok());
        assert!(validate_risk_level("medium").is_ok());
        assert!(validate_risk_level("high").is_ok());
        assert!(validate_risk_level("critical").is_ok());
        assert!(validate_risk_level("invalid").is_err());
    }

    #[test]
    fn test_validate_tool_status() {
        assert!(validate_tool_status("active").is_ok());
        assert!(validate_tool_status("inactive").is_ok());
        assert!(validate_tool_status("deprecated").is_ok());
        assert!(validate_tool_status("invalid").is_err());
    }

    #[test]
    fn test_validate_json_schema() {
        // Valid schema
        let valid_schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        assert!(validate_json_schema(&valid_schema).is_ok());

        // Empty object is valid
        let empty_schema = json!({});
        assert!(validate_json_schema(&empty_schema).is_ok());

        // Array is invalid
        let array_schema = json!([]);
        assert!(validate_json_schema(&array_schema).is_err());

        // String is invalid
        let string_schema = json!("invalid");
        assert!(validate_json_schema(&string_schema).is_err());

        // Schema with $schema field
        let with_meta = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object"
        });
        assert!(validate_json_schema(&with_meta).is_ok());

        // Invalid $schema type
        let invalid_meta = json!({
            "$schema": 123,
            "type": "object"
        });
        assert!(validate_json_schema(&invalid_meta).is_err());
    }
}
