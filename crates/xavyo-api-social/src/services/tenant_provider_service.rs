//! Tenant provider service for managing per-tenant social provider configurations.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ProviderType, SocialResult};
use crate::models::TenantProviderResponse;
use crate::services::encryption::EncryptionService;

/// Tenant provider service for managing social provider configurations.
#[derive(Clone)]
pub struct TenantProviderService {
    pool: PgPool,
    encryption: EncryptionService,
}

/// Provider configuration (with decrypted secret for internal use).
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider: ProviderType,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: String,
    pub additional_config: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
}

impl TenantProviderService {
    /// Create a new tenant provider service.
    #[must_use] 
    pub fn new(pool: PgPool, encryption: EncryptionService) -> Self {
        Self { pool, encryption }
    }

    /// Get an enabled provider configuration.
    pub async fn get_enabled_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<Option<ProviderConfig>> {
        let row: Option<ProviderRow> = sqlx::query_as(
            r"
            SELECT provider, enabled, client_id, client_secret_encrypted, additional_config, scopes
            FROM tenant_social_providers
            WHERE tenant_id = $1 AND provider = $2 AND enabled = true
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let client_secret = self
                    .encryption
                    .decrypt_string(tenant_id, &r.client_secret_encrypted)?;

                Ok(Some(ProviderConfig {
                    provider,
                    enabled: r.enabled,
                    client_id: r.client_id,
                    client_secret,
                    additional_config: r.additional_config,
                    scopes: r.scopes,
                }))
            }
            None => Ok(None),
        }
    }

    /// List all enabled providers for a tenant (for login page).
    pub async fn list_enabled_providers(&self, tenant_id: Uuid) -> SocialResult<Vec<ProviderType>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r"
            SELECT provider FROM tenant_social_providers
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut providers = Vec::new();
        for (provider_str,) in rows {
            if let Ok(provider) = provider_str.parse::<ProviderType>() {
                providers.push(provider);
            }
        }

        Ok(providers)
    }

    /// List all provider configurations for a tenant (admin view).
    pub async fn list_providers(
        &self,
        tenant_id: Uuid,
    ) -> SocialResult<Vec<TenantProviderResponse>> {
        let rows: Vec<AdminProviderRow> = sqlx::query_as(
            r"
            SELECT provider, enabled, client_id, scopes, created_at, updated_at
            FROM tenant_social_providers
            WHERE tenant_id = $1
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| TenantProviderResponse {
                provider: r.provider,
                enabled: r.enabled,
                client_id: r.client_id,
                has_client_secret: true, // If row exists, secret is configured
                scopes: r.scopes,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    /// Update or create a provider configuration.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
        enabled: bool,
        client_id: &str,
        client_secret: &str,
        additional_config: Option<serde_json::Value>,
        scopes: Option<Vec<String>>,
    ) -> SocialResult<TenantProviderResponse> {
        let client_secret_encrypted = self.encryption.encrypt_string(tenant_id, client_secret)?;

        let row: AdminProviderRow = sqlx::query_as(
            r"
            INSERT INTO tenant_social_providers (
                tenant_id, provider, enabled, client_id, client_secret_encrypted,
                additional_config, scopes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, provider)
            DO UPDATE SET
                enabled = EXCLUDED.enabled,
                client_id = EXCLUDED.client_id,
                client_secret_encrypted = EXCLUDED.client_secret_encrypted,
                additional_config = EXCLUDED.additional_config,
                scopes = EXCLUDED.scopes,
                updated_at = NOW()
            RETURNING provider, enabled, client_id, scopes, created_at, updated_at
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .bind(enabled)
        .bind(client_id)
        .bind(&client_secret_encrypted)
        .bind(&additional_config)
        .bind(&scopes)
        .fetch_one(&self.pool)
        .await?;

        Ok(TenantProviderResponse {
            provider: row.provider,
            enabled: row.enabled,
            client_id: row.client_id,
            has_client_secret: true,
            scopes: row.scopes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// Disable a provider.
    pub async fn disable_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<bool> {
        let result = sqlx::query(
            r"
            UPDATE tenant_social_providers
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND provider = $2
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a provider configuration.
    pub async fn delete_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<bool> {
        let result = sqlx::query(
            "DELETE FROM tenant_social_providers WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Internal row type for provider queries.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct ProviderRow {
    provider: String,
    enabled: bool,
    client_id: String,
    client_secret_encrypted: Vec<u8>,
    additional_config: Option<serde_json::Value>,
    scopes: Option<Vec<String>>,
}

/// Admin view row type (without secret).
#[derive(Debug, sqlx::FromRow)]
struct AdminProviderRow {
    provider: String,
    enabled: bool,
    client_id: String,
    scopes: Option<Vec<String>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}
