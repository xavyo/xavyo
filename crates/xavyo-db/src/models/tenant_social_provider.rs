//! Tenant social provider configuration model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Tenant social provider configuration entity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantSocialProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub additional_config: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
    pub claims_mapping: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating or updating a tenant social provider.
#[derive(Debug, Clone)]
pub struct UpsertTenantSocialProvider {
    pub tenant_id: Uuid,
    pub provider: String,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub additional_config: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
    pub claims_mapping: Option<serde_json::Value>,
}

impl TenantSocialProvider {
    /// Create or update a tenant social provider configuration.
    pub async fn upsert(
        pool: &sqlx::PgPool,
        input: UpsertTenantSocialProvider,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO tenant_social_providers (
                tenant_id, provider, enabled, client_id, client_secret_encrypted,
                additional_config, scopes, claims_mapping
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, provider)
            DO UPDATE SET
                enabled = EXCLUDED.enabled,
                client_id = EXCLUDED.client_id,
                client_secret_encrypted = EXCLUDED.client_secret_encrypted,
                additional_config = EXCLUDED.additional_config,
                scopes = EXCLUDED.scopes,
                claims_mapping = EXCLUDED.claims_mapping,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.provider)
        .bind(input.enabled)
        .bind(&input.client_id)
        .bind(&input.client_secret_encrypted)
        .bind(&input.additional_config)
        .bind(&input.scopes)
        .bind(&input.claims_mapping)
        .fetch_one(pool)
        .await
    }

    /// Find a provider configuration by tenant and provider type.
    pub async fn find_by_provider(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_social_providers
            WHERE tenant_id = $1 AND provider = $2
            ",
        )
        .bind(tenant_id)
        .bind(provider)
        .fetch_optional(pool)
        .await
    }

    /// Find an enabled provider configuration.
    pub async fn find_enabled_provider(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_social_providers
            WHERE tenant_id = $1 AND provider = $2 AND enabled = true
            ",
        )
        .bind(tenant_id)
        .bind(provider)
        .fetch_optional(pool)
        .await
    }

    /// List all provider configurations for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_social_providers
            WHERE tenant_id = $1
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List all enabled providers for a tenant (for login page).
    pub async fn list_enabled_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_social_providers
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Disable a provider.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE tenant_social_providers
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND provider = $2
            ",
        )
        .bind(tenant_id)
        .bind(provider)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a provider configuration.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM tenant_social_providers
            WHERE tenant_id = $1 AND provider = $2
            ",
        )
        .bind(tenant_id)
        .bind(provider)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
