//! AI Tool model for the tool registry (F089 - AI Agent Security Platform).
//!
//! Represents tools that AI agents can invoke, following MCP-style patterns.
//! Supports JSON Schema for parameter validation and OWASP ASI02/ASI04 compliance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Risk level enum (shared between agents and tools)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AiRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiRiskLevel::Low => write!(f, "low"),
            AiRiskLevel::Medium => write!(f, "medium"),
            AiRiskLevel::High => write!(f, "high"),
            AiRiskLevel::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for AiRiskLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(AiRiskLevel::Low),
            "medium" => Ok(AiRiskLevel::Medium),
            "high" => Ok(AiRiskLevel::High),
            "critical" => Ok(AiRiskLevel::Critical),
            _ => Err(format!("Invalid risk level: {}", s)),
        }
    }
}

/// Tool status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AiToolStatus {
    Active,
    Inactive,
    Deprecated,
}

impl std::fmt::Display for AiToolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiToolStatus::Active => write!(f, "active"),
            AiToolStatus::Inactive => write!(f, "inactive"),
            AiToolStatus::Deprecated => write!(f, "deprecated"),
        }
    }
}

impl std::str::FromStr for AiToolStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(AiToolStatus::Active),
            "inactive" => Ok(AiToolStatus::Inactive),
            "deprecated" => Ok(AiToolStatus::Deprecated),
            _ => Err(format!("Invalid tool status: {}", s)),
        }
    }
}

/// AI Tool model representing a tool in the registry.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AiTool {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub risk_level: String,
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: bool,
    pub checksum: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AiTool {
    /// Returns the tool status as an enum
    pub fn status_enum(&self) -> Result<AiToolStatus, String> {
        self.status.parse()
    }

    /// Returns the risk level as an enum
    pub fn risk_level_enum(&self) -> Result<AiRiskLevel, String> {
        self.risk_level.parse()
    }
}

/// Request struct for creating a new AI tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAiTool {
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub risk_level: Option<String>,
    pub requires_approval: Option<bool>,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: Option<bool>,
    pub checksum: Option<String>,
}

/// Request struct for updating an existing AI tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateAiTool {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
    pub risk_level: Option<String>,
    pub requires_approval: Option<bool>,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: Option<bool>,
    pub checksum: Option<String>,
    pub status: Option<String>,
}

/// Filter struct for listing AI tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiToolFilter {
    pub status: Option<String>,
    pub category: Option<String>,
    pub risk_level: Option<String>,
    pub requires_approval: Option<bool>,
    pub provider_verified: Option<bool>,
    pub name_contains: Option<String>,
}

impl AiTool {
    /// Find a tool by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, tenant_id, name, description, category, input_schema, output_schema,
                   risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                   checksum, status, created_at, updated_at
            FROM ai_tools
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find multiple tools by their IDs within a tenant.
    pub async fn find_by_ids(
        pool: &PgPool,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> Result<Vec<Self>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(vec![]);
        }

        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, tenant_id, name, description, category, input_schema, output_schema,
                   risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                   checksum, status, created_at, updated_at
            FROM ai_tools
            WHERE tenant_id = $1 AND id = ANY($2)
            "#,
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_all(pool)
        .await
    }

    /// Find a tool by name within a tenant.
    pub async fn find_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, tenant_id, name, description, category, input_schema, output_schema,
                   risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                   checksum, status, created_at, updated_at
            FROM ai_tools
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List tools for a tenant with optional filtering.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &AiToolFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT id, tenant_id, name, description, category, input_schema, output_schema,
                   risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                   checksum, status, created_at, updated_at
            FROM ai_tools
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.status.is_some() {
            conditions.push(format!("status = ${}", param_idx));
            param_idx += 1;
        }
        if filter.category.is_some() {
            conditions.push(format!("category = ${}", param_idx));
            param_idx += 1;
        }
        if filter.risk_level.is_some() {
            conditions.push(format!("risk_level = ${}", param_idx));
            param_idx += 1;
        }
        if filter.requires_approval.is_some() {
            conditions.push(format!("requires_approval = ${}", param_idx));
            param_idx += 1;
        }
        if filter.provider_verified.is_some() {
            conditions.push(format!("provider_verified = ${}", param_idx));
            param_idx += 1;
        }
        if filter.name_contains.is_some() {
            conditions.push(format!("name ILIKE ${}", param_idx));
            param_idx += 1;
        }

        for condition in conditions {
            query.push_str(" AND ");
            query.push_str(&condition);
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut query_builder = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            query_builder = query_builder.bind(status);
        }
        if let Some(ref category) = filter.category {
            query_builder = query_builder.bind(category);
        }
        if let Some(ref risk_level) = filter.risk_level {
            query_builder = query_builder.bind(risk_level);
        }
        if let Some(requires_approval) = filter.requires_approval {
            query_builder = query_builder.bind(requires_approval);
        }
        if let Some(provider_verified) = filter.provider_verified {
            query_builder = query_builder.bind(provider_verified);
        }
        if let Some(ref name_contains) = filter.name_contains {
            query_builder = query_builder.bind(format!("%{}%", name_contains));
        }

        query_builder = query_builder.bind(limit).bind(offset);

        query_builder.fetch_all(pool).await
    }

    /// Count tools for a tenant with optional filtering.
    pub async fn count_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &AiToolFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) as count
            FROM ai_tools
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.status.is_some() {
            conditions.push(format!("status = ${}", param_idx));
            param_idx += 1;
        }
        if filter.category.is_some() {
            conditions.push(format!("category = ${}", param_idx));
            param_idx += 1;
        }
        if filter.risk_level.is_some() {
            conditions.push(format!("risk_level = ${}", param_idx));
            param_idx += 1;
        }
        if filter.requires_approval.is_some() {
            conditions.push(format!("requires_approval = ${}", param_idx));
            param_idx += 1;
        }
        if filter.provider_verified.is_some() {
            conditions.push(format!("provider_verified = ${}", param_idx));
            param_idx += 1;
        }
        if filter.name_contains.is_some() {
            conditions.push(format!("name ILIKE ${}", param_idx));
        }

        for condition in conditions {
            query.push_str(" AND ");
            query.push_str(&condition);
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            query_builder = query_builder.bind(status);
        }
        if let Some(ref category) = filter.category {
            query_builder = query_builder.bind(category);
        }
        if let Some(ref risk_level) = filter.risk_level {
            query_builder = query_builder.bind(risk_level);
        }
        if let Some(requires_approval) = filter.requires_approval {
            query_builder = query_builder.bind(requires_approval);
        }
        if let Some(provider_verified) = filter.provider_verified {
            query_builder = query_builder.bind(provider_verified);
        }
        if let Some(ref name_contains) = filter.name_contains {
            query_builder = query_builder.bind(format!("%{}%", name_contains));
        }

        query_builder.fetch_one(pool).await
    }

    /// Create a new AI tool.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateAiTool,
    ) -> Result<Self, sqlx::Error> {
        let risk_level = input.risk_level.unwrap_or_else(|| "medium".to_string());
        let requires_approval = input.requires_approval.unwrap_or(false);
        let provider_verified = input.provider_verified.unwrap_or(false);

        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO ai_tools (
                tenant_id, name, description, category, input_schema, output_schema,
                risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                checksum, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active')
            RETURNING id, tenant_id, name, description, category, input_schema, output_schema,
                      risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                      checksum, status, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.category)
        .bind(&input.input_schema)
        .bind(&input.output_schema)
        .bind(&risk_level)
        .bind(requires_approval)
        .bind(input.max_calls_per_hour)
        .bind(&input.provider)
        .bind(provider_verified)
        .bind(&input.checksum)
        .fetch_one(pool)
        .await
    }

    /// Update an existing AI tool.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateAiTool,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE ai_tools
            SET name = COALESCE($3, name),
                description = COALESCE($4, description),
                category = COALESCE($5, category),
                input_schema = COALESCE($6, input_schema),
                output_schema = COALESCE($7, output_schema),
                risk_level = COALESCE($8, risk_level),
                requires_approval = COALESCE($9, requires_approval),
                max_calls_per_hour = COALESCE($10, max_calls_per_hour),
                provider = COALESCE($11, provider),
                provider_verified = COALESCE($12, provider_verified),
                checksum = COALESCE($13, checksum),
                status = COALESCE($14, status),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, name, description, category, input_schema, output_schema,
                      risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                      checksum, status, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.category)
        .bind(&input.input_schema)
        .bind(&input.output_schema)
        .bind(&input.risk_level)
        .bind(input.requires_approval)
        .bind(input.max_calls_per_hour)
        .bind(&input.provider)
        .bind(input.provider_verified)
        .bind(&input.checksum)
        .bind(&input.status)
        .fetch_optional(pool)
        .await
    }

    /// Delete a tool (hard delete).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM ai_tools
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Deprecate a tool (sets status to 'deprecated').
    pub async fn deprecate(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE ai_tools
            SET status = 'deprecated', updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND status != 'deprecated'
            RETURNING id, tenant_id, name, description, category, input_schema, output_schema,
                      risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                      checksum, status, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate a tool (sets status to 'inactive').
    pub async fn deactivate(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE ai_tools
            SET status = 'inactive', updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND status = 'active'
            RETURNING id, tenant_id, name, description, category, input_schema, output_schema,
                      risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                      checksum, status, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Reactivate a tool (sets status back to 'active').
    pub async fn reactivate(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE ai_tools
            SET status = 'active', updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND status = 'inactive'
            RETURNING id, tenant_id, name, description, category, input_schema, output_schema,
                      risk_level, requires_approval, max_calls_per_hour, provider, provider_verified,
                      checksum, status, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ai_tool_status_display() {
        assert_eq!(AiToolStatus::Active.to_string(), "active");
        assert_eq!(AiToolStatus::Inactive.to_string(), "inactive");
        assert_eq!(AiToolStatus::Deprecated.to_string(), "deprecated");
    }

    #[test]
    fn test_ai_tool_status_from_str() {
        assert_eq!(
            "active".parse::<AiToolStatus>().unwrap(),
            AiToolStatus::Active
        );
        assert_eq!(
            "inactive".parse::<AiToolStatus>().unwrap(),
            AiToolStatus::Inactive
        );
        assert_eq!(
            "deprecated".parse::<AiToolStatus>().unwrap(),
            AiToolStatus::Deprecated
        );
        assert_eq!(
            "ACTIVE".parse::<AiToolStatus>().unwrap(),
            AiToolStatus::Active
        );
        assert!("invalid".parse::<AiToolStatus>().is_err());
    }

    #[test]
    fn test_ai_tool_serialization() {
        let tool = AiTool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "send_email".to_string(),
            description: Some("Send an email to a recipient".to_string()),
            category: Some("communication".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "to": { "type": "string", "format": "email" },
                    "subject": { "type": "string" },
                    "body": { "type": "string" }
                },
                "required": ["to", "subject", "body"]
            }),
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "sent_at": { "type": "string", "format": "date-time" }
                }
            })),
            risk_level: "medium".to_string(),
            requires_approval: false,
            max_calls_per_hour: Some(100),
            provider: Some("internal".to_string()),
            provider_verified: true,
            checksum: Some("abc123def456".to_string()),
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&tool).unwrap();
        let deserialized: AiTool = serde_json::from_str(&json).unwrap();

        assert_eq!(tool.id, deserialized.id);
        assert_eq!(tool.name, deserialized.name);
        assert_eq!(tool.category, deserialized.category);
        assert_eq!(tool.risk_level, deserialized.risk_level);
        assert_eq!(tool.requires_approval, deserialized.requires_approval);
        assert_eq!(tool.provider_verified, deserialized.provider_verified);
    }

    #[test]
    fn test_ai_tool_status_enum() {
        let tool = AiTool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test_tool".to_string(),
            description: None,
            category: None,
            input_schema: json!({}),
            output_schema: None,
            risk_level: "high".to_string(),
            requires_approval: true,
            max_calls_per_hour: None,
            provider: None,
            provider_verified: false,
            checksum: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(tool.status_enum().unwrap(), AiToolStatus::Active);
    }

    #[test]
    fn test_create_ai_tool_serialization() {
        let input = CreateAiTool {
            name: "query_database".to_string(),
            description: Some("Execute SQL queries".to_string()),
            category: Some("data".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "params": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["query"]
            }),
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "rows": { "type": "array" },
                    "affected_rows": { "type": "integer" }
                }
            })),
            risk_level: Some("critical".to_string()),
            requires_approval: Some(true),
            max_calls_per_hour: Some(50),
            provider: Some("internal".to_string()),
            provider_verified: Some(true),
            checksum: Some("sha256hash".to_string()),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: CreateAiTool = serde_json::from_str(&json).unwrap();

        assert_eq!(input.name, deserialized.name);
        assert_eq!(input.risk_level, deserialized.risk_level);
        assert_eq!(input.requires_approval, deserialized.requires_approval);
    }

    #[test]
    fn test_create_ai_tool_minimal() {
        let input = CreateAiTool {
            name: "simple_tool".to_string(),
            description: None,
            category: None,
            input_schema: json!({}),
            output_schema: None,
            risk_level: None,
            requires_approval: None,
            max_calls_per_hour: None,
            provider: None,
            provider_verified: None,
            checksum: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"name\":\"simple_tool\""));
    }

    #[test]
    fn test_update_ai_tool_serialization() {
        let input = UpdateAiTool {
            name: Some("updated_tool".to_string()),
            description: Some("Updated description".to_string()),
            category: None,
            input_schema: Some(json!({"type": "object"})),
            output_schema: None,
            risk_level: Some("high".to_string()),
            requires_approval: Some(true),
            max_calls_per_hour: Some(200),
            provider: None,
            provider_verified: Some(true),
            checksum: None,
            status: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: UpdateAiTool = serde_json::from_str(&json).unwrap();

        assert_eq!(input.name, deserialized.name);
        assert_eq!(input.risk_level, deserialized.risk_level);
    }

    #[test]
    fn test_update_ai_tool_default() {
        let input = UpdateAiTool::default();

        assert!(input.name.is_none());
        assert!(input.description.is_none());
        assert!(input.status.is_none());
    }

    #[test]
    fn test_ai_tool_filter_serialization() {
        let filter = AiToolFilter {
            status: Some("active".to_string()),
            category: Some("communication".to_string()),
            risk_level: Some("high".to_string()),
            requires_approval: Some(true),
            provider_verified: Some(false),
            name_contains: Some("email".to_string()),
        };

        let json = serde_json::to_string(&filter).unwrap();
        let deserialized: AiToolFilter = serde_json::from_str(&json).unwrap();

        assert_eq!(filter.status, deserialized.status);
        assert_eq!(filter.category, deserialized.category);
        assert_eq!(filter.name_contains, deserialized.name_contains);
    }

    #[test]
    fn test_ai_tool_filter_default() {
        let filter = AiToolFilter::default();

        assert!(filter.status.is_none());
        assert!(filter.category.is_none());
        assert!(filter.risk_level.is_none());
        assert!(filter.requires_approval.is_none());
        assert!(filter.provider_verified.is_none());
        assert!(filter.name_contains.is_none());
    }

    #[test]
    fn test_ai_tool_input_schema_complex() {
        // Test that complex JSON schemas can be stored and retrieved
        let complex_schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "recipients": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "email": { "type": "string", "format": "email" },
                            "name": { "type": "string" }
                        },
                        "required": ["email"]
                    },
                    "minItems": 1,
                    "maxItems": 100
                },
                "template_id": { "type": "string", "format": "uuid" },
                "variables": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                }
            },
            "required": ["recipients", "template_id"]
        });

        let input = CreateAiTool {
            name: "send_bulk_email".to_string(),
            description: Some("Send bulk templated emails".to_string()),
            category: Some("communication".to_string()),
            input_schema: complex_schema.clone(),
            output_schema: None,
            risk_level: Some("high".to_string()),
            requires_approval: Some(true),
            max_calls_per_hour: Some(10),
            provider: None,
            provider_verified: None,
            checksum: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: CreateAiTool = serde_json::from_str(&json).unwrap();

        assert_eq!(input.input_schema, deserialized.input_schema);
        assert_eq!(
            deserialized.input_schema["properties"]["recipients"]["items"]["properties"]["email"]
                ["format"],
            "email"
        );
    }

    #[test]
    fn test_ai_tool_mcp_compatible_schema() {
        // Test MCP-style tool definition
        let mcp_tool = CreateAiTool {
            name: "get_weather".to_string(),
            description: Some("Get current weather for a location".to_string()),
            category: Some("data".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City name or coordinates"
                    },
                    "units": {
                        "type": "string",
                        "enum": ["celsius", "fahrenheit"],
                        "default": "celsius"
                    }
                },
                "required": ["location"]
            }),
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "temperature": { "type": "number" },
                    "conditions": { "type": "string" },
                    "humidity": { "type": "number" }
                }
            })),
            risk_level: Some("low".to_string()),
            requires_approval: Some(false),
            max_calls_per_hour: Some(1000),
            provider: Some("mcp:weather-service".to_string()),
            provider_verified: Some(true),
            checksum: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
        };

        let json = serde_json::to_string(&mcp_tool).unwrap();
        assert!(json.contains("\"mcp:weather-service\""));
        assert!(json.contains("\"location\""));
    }
}
