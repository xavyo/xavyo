//! NHI Tool extension model (201-tool-nhi-promotion).
//!
//! Type-specific fields for tools. 1:1 relationship with `nhi_identities`
//! where `nhi_type = 'tool'`. Always queried via JOIN with `nhi_identities`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_nhi::NhiLifecycleState;

/// Tool extension row (the `nhi_tools` table only).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiTool {
    pub nhi_id: Uuid,
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: bool,
    pub checksum: Option<String>,
}

/// Combined NHI identity + tool extension fields.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiToolWithIdentity {
    // Base identity fields
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub lifecycle_state: NhiLifecycleState,
    pub suspension_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub risk_score: Option<i32>,
    pub last_certified_at: Option<DateTime<Utc>>,
    pub next_certification_at: Option<DateTime<Utc>>,
    pub last_certified_by: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    // Tool-specific fields
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: bool,
    pub checksum: Option<String>,
}

/// Request to create a tool extension row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiTool {
    pub nhi_id: Uuid,
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: bool,
    pub checksum: Option<String>,
}

/// Request to update a tool extension row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNhiTool {
    pub category: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: Option<bool>,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: Option<bool>,
    pub checksum: Option<String>,
}

/// Filter options for listing NHI tools.
#[derive(Debug, Clone, Default)]
pub struct NhiToolFilter {
    pub category: Option<String>,
    pub requires_approval: Option<bool>,
    pub provider_verified: Option<bool>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
}

const TOOL_JOIN_SELECT: &str = r"
    SELECT i.id, i.tenant_id, i.name, i.description, i.owner_id, i.backup_owner_id,
           i.lifecycle_state, i.suspension_reason, i.expires_at, i.last_activity_at,
           i.inactivity_threshold_days, i.grace_period_ends_at, i.risk_score,
           i.last_certified_at, i.next_certification_at, i.last_certified_by,
           i.rotation_interval_days, i.last_rotation_at, i.created_at, i.updated_at, i.created_by,
           t.category, t.input_schema, t.output_schema, t.requires_approval,
           t.max_calls_per_hour, t.provider, t.provider_verified, t.checksum
    FROM nhi_identities i
    INNER JOIN nhi_tools t ON t.nhi_id = i.id
";

impl NhiTool {
    /// Insert a tool extension row. The base `nhi_identities` row must exist already.
    pub async fn create(pool: &PgPool, input: CreateNhiTool) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_tools (
                nhi_id, category, input_schema, output_schema, requires_approval,
                max_calls_per_hour, provider, provider_verified, checksum
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(input.nhi_id)
        .bind(&input.category)
        .bind(&input.input_schema)
        .bind(&input.output_schema)
        .bind(input.requires_approval)
        .bind(input.max_calls_per_hour)
        .bind(&input.provider)
        .bind(input.provider_verified)
        .bind(&input.checksum)
        .fetch_one(pool)
        .await
    }

    /// Find a tool by NHI ID (returns joined identity + tool data).
    pub async fn find_by_nhi_id(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<NhiToolWithIdentity>, sqlx::Error> {
        let query = format!("{TOOL_JOIN_SELECT} WHERE i.tenant_id = $1 AND i.id = $2");
        sqlx::query_as::<_, NhiToolWithIdentity>(&query)
            .bind(tenant_id)
            .bind(nhi_id)
            .fetch_optional(pool)
            .await
    }

    /// Update a tool extension row.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        input: UpdateNhiTool,
    ) -> Result<Option<NhiTool>, sqlx::Error> {
        sqlx::query_as::<_, NhiTool>(
            r"
            UPDATE nhi_tools
            SET category = COALESCE($3, category),
                input_schema = COALESCE($4, input_schema),
                output_schema = COALESCE($5, output_schema),
                requires_approval = COALESCE($6, requires_approval),
                max_calls_per_hour = COALESCE($7, max_calls_per_hour),
                provider = COALESCE($8, provider),
                provider_verified = COALESCE($9, provider_verified),
                checksum = COALESCE($10, checksum)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(&input.category)
        .bind(&input.input_schema)
        .bind(&input.output_schema)
        .bind(input.requires_approval)
        .bind(input.max_calls_per_hour)
        .bind(&input.provider)
        .bind(input.provider_verified)
        .bind(&input.checksum)
        .fetch_optional(pool)
        .await
    }

    /// Delete a tool extension row (tenant-scoped).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, nhi_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM nhi_tools WHERE nhi_id = $1 AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(nhi_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List tools for a tenant with optional filtering and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiToolFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiToolWithIdentity>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        let mut query = format!("{TOOL_JOIN_SELECT} WHERE i.tenant_id = $1");
        let mut param_idx = 2;

        if filter.category.is_some() {
            query.push_str(&format!(" AND t.category = ${param_idx}"));
            param_idx += 1;
        }
        if filter.requires_approval.is_some() {
            query.push_str(&format!(" AND t.requires_approval = ${param_idx}"));
            param_idx += 1;
        }
        if filter.provider_verified.is_some() {
            query.push_str(&format!(" AND t.provider_verified = ${param_idx}"));
            param_idx += 1;
        }
        if filter.lifecycle_state.is_some() {
            query.push_str(&format!(" AND i.lifecycle_state = ${param_idx}"));
            param_idx += 1;
        }
        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND i.owner_id = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY i.name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, NhiToolWithIdentity>(&query).bind(tenant_id);

        if let Some(ref category) = filter.category {
            q = q.bind(category);
        }
        if let Some(requires_approval) = filter.requires_approval {
            q = q.bind(requires_approval);
        }
        if let Some(provider_verified) = filter.provider_verified {
            q = q.bind(provider_verified);
        }
        if let Some(lifecycle_state) = filter.lifecycle_state {
            q = q.bind(lifecycle_state);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_nhi_tool_serialization() {
        let tool = NhiTool {
            nhi_id: Uuid::new_v4(),
            category: Some("data".to_string()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            requires_approval: false,
            max_calls_per_hour: Some(100),
            provider: Some("mcp:provider".to_string()),
            provider_verified: true,
            checksum: Some("abc123".to_string()),
        };

        let json_str = serde_json::to_string(&tool).unwrap();
        let deserialized: NhiTool = serde_json::from_str(&json_str).unwrap();
        assert_eq!(tool.category, deserialized.category);
        assert_eq!(tool.requires_approval, deserialized.requires_approval);
    }

    #[test]
    fn test_create_nhi_tool() {
        let input = CreateNhiTool {
            nhi_id: Uuid::new_v4(),
            category: Some("code".to_string()),
            input_schema: json!({}),
            output_schema: None,
            requires_approval: true,
            max_calls_per_hour: Some(50),
            provider: None,
            provider_verified: false,
            checksum: None,
        };

        assert!(input.requires_approval);
        assert_eq!(input.max_calls_per_hour, Some(50));
    }

    #[test]
    fn test_update_nhi_tool_default() {
        let update = UpdateNhiTool::default();
        assert!(update.category.is_none());
        assert!(update.input_schema.is_none());
        assert!(update.requires_approval.is_none());
    }

    #[test]
    fn test_nhi_tool_filter_default() {
        let filter = NhiToolFilter::default();
        assert!(filter.category.is_none());
        assert!(filter.requires_approval.is_none());
    }
}
