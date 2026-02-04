//! IAM Role Mapping model for Workload Identity Federation (F121).
//!
//! Maps agent types to cloud IAM roles per provider.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Minimum TTL in seconds (15 minutes).
pub const MIN_TTL_SECONDS: i32 = 900;

/// Maximum TTL in seconds (12 hours).
pub const MAX_TTL_SECONDS: i32 = 43200;

/// Default TTL in seconds (1 hour).
pub const DEFAULT_TTL_SECONDS: i32 = 3600;

/// IAM role mapping.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IamRoleMapping {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant this mapping belongs to.
    pub tenant_id: Uuid,
    /// Identity provider configuration this mapping belongs to.
    pub provider_config_id: Uuid,
    /// Agent type (NULL for default mapping that applies to all agents).
    pub agent_type: Option<String>,
    /// Role identifier (AWS ARN, GCP service account, Azure app ID).
    pub role_identifier: String,
    /// Allowed scopes/permissions.
    pub allowed_scopes: Vec<String>,
    /// Maximum credential TTL in seconds.
    pub max_ttl_seconds: i32,
    /// Additional constraints (JSONB).
    pub constraints: serde_json::Value,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request to create an IAM role mapping.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateIamRoleMapping {
    /// Identity provider configuration ID.
    pub provider_config_id: Uuid,
    /// Agent type (NULL for default mapping).
    pub agent_type: Option<String>,
    /// Role identifier.
    pub role_identifier: String,
    /// Allowed scopes/permissions.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// Maximum credential TTL in seconds.
    #[serde(default = "default_ttl")]
    pub max_ttl_seconds: i32,
    /// Additional constraints.
    #[serde(default)]
    pub constraints: serde_json::Value,
}

fn default_ttl() -> i32 {
    DEFAULT_TTL_SECONDS
}

/// Request to update an IAM role mapping.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateIamRoleMapping {
    /// New role identifier.
    pub role_identifier: Option<String>,
    /// New allowed scopes.
    pub allowed_scopes: Option<Vec<String>>,
    /// New maximum TTL.
    pub max_ttl_seconds: Option<i32>,
    /// New constraints.
    pub constraints: Option<serde_json::Value>,
}

/// Filter for listing IAM role mappings.
#[derive(Debug, Clone, Default)]
pub struct IamRoleMappingFilter {
    /// Filter by provider configuration ID.
    pub provider_config_id: Option<Uuid>,
    /// Filter by agent type.
    pub agent_type: Option<String>,
}

impl IamRoleMapping {
    /// Create a new IAM role mapping.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        request: &CreateIamRoleMapping,
    ) -> Result<Self, sqlx::Error> {
        // Clamp TTL to valid range
        let ttl = request
            .max_ttl_seconds
            .clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS);

        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO iam_role_mappings (
                tenant_id, provider_config_id, agent_type, role_identifier,
                allowed_scopes, max_ttl_seconds, constraints
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            "#,
            tenant_id,
            request.provider_config_id,
            request.agent_type.as_ref(),
            &request.role_identifier,
            &request.allowed_scopes,
            ttl,
            request.constraints,
        )
        .fetch_one(pool)
        .await
    }

    /// Get an IAM role mapping by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
        )
        .fetch_optional(pool)
        .await
    }

    /// List IAM role mappings for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IamRoleMappingFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            FROM iam_role_mappings
            WHERE tenant_id = $1
                AND ($2::uuid IS NULL OR provider_config_id = $2)
                AND ($3::text IS NULL OR agent_type = $3)
            ORDER BY created_at DESC
            "#,
            tenant_id,
            filter.provider_config_id,
            filter.agent_type.as_ref(),
        )
        .fetch_all(pool)
        .await
    }

    /// Update an IAM role mapping.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpdateIamRoleMapping,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Clamp TTL to valid range if provided
        let ttl = request
            .max_ttl_seconds
            .map(|t| t.clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS));

        sqlx::query_as!(
            Self,
            r#"
            UPDATE iam_role_mappings
            SET
                role_identifier = COALESCE($3, role_identifier),
                allowed_scopes = COALESCE($4, allowed_scopes),
                max_ttl_seconds = COALESCE($5, max_ttl_seconds),
                constraints = COALESCE($6, constraints),
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            "#,
            tenant_id,
            id,
            request.role_identifier.as_ref(),
            request.allowed_scopes.as_ref().map(std::vec::Vec::as_slice),
            ttl,
            request.constraints.clone(),
        )
        .fetch_optional(pool)
        .await
    }

    /// Delete an IAM role mapping.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM iam_role_mappings
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find the best matching role mapping for an agent type.
    ///
    /// Returns the specific mapping if one exists for the agent type,
    /// otherwise returns the default mapping (`agent_type` = NULL).
    pub async fn find_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_config_id: Uuid,
        agent_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First try to find a specific mapping for the agent type
        let specific = sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2 AND agent_type = $3
            "#,
            tenant_id,
            provider_config_id,
            agent_type,
        )
        .fetch_optional(pool)
        .await?;

        if specific.is_some() {
            return Ok(specific);
        }

        // Fall back to the default mapping (agent_type = NULL)
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2 AND agent_type IS NULL
            "#,
            tenant_id,
            provider_config_id,
        )
        .fetch_optional(pool)
        .await
    }

    /// Get mappings for a provider configuration.
    pub async fn get_by_provider(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_config_id, agent_type, role_identifier,
                COALESCE(allowed_scopes, ARRAY[]::TEXT[]) as "allowed_scopes!: Vec<String>",
                max_ttl_seconds, constraints, created_at, updated_at
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2
            ORDER BY agent_type NULLS LAST, created_at ASC
            "#,
            tenant_id,
            provider_config_id,
        )
        .fetch_all(pool)
        .await
    }

    /// Check if a provider has any role mappings.
    pub async fn has_mappings(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2
            "#,
            tenant_id,
            provider_config_id,
        )
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Delete all role mappings for a provider (cascade delete support - T044).
    ///
    /// Returns the number of mappings deleted.
    pub async fn delete_by_provider(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2
            "#,
            tenant_id,
            provider_config_id,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count role mappings for a provider.
    pub async fn count_by_provider(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM iam_role_mappings
            WHERE tenant_id = $1 AND provider_config_id = $2
            "#,
            tenant_id,
            provider_config_id,
        )
        .fetch_one(pool)
        .await
    }
}
