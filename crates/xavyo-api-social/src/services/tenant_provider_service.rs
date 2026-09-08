//! Tenant provider service for managing per-tenant social provider configurations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ProviderType, SocialResult};
use crate::models::TenantProviderResponse;
use crate::services::encryption::EncryptionService;

/// Keys within `additional_config` JSON that contain secrets and must be encrypted at rest.
/// On write, these are encrypted and stored under `{key}_encrypted` (base64-encoded ciphertext).
/// On read, `{key}_encrypted` is decrypted and returned under the original key name.
const SENSITIVE_CONFIG_KEYS: &[&str] = &["private_key"];

/// Tenant provider service for managing social provider configurations.
#[derive(Clone)]
pub struct TenantProviderService {
    pool: PgPool,
    encryption: EncryptionService,
}

/// Provider configuration (with decrypted secret for internal use).
#[derive(Clone)]
pub struct ProviderConfig {
    pub provider: ProviderType,
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: String,
    pub additional_config: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
}

// R10: Custom Debug to prevent secret leakage in logs (client_secret + additional_config may contain private keys)
impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("provider", &self.provider)
            .field("enabled", &self.enabled)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field(
                "additional_config",
                &self.additional_config.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl TenantProviderService {
    /// Create a new tenant provider service.
    #[must_use]
    pub fn new(pool: PgPool, encryption: EncryptionService) -> Self {
        Self { pool, encryption }
    }

    /// Encrypt sensitive fields within `additional_config` before persisting.
    ///
    /// For each key in `SENSITIVE_CONFIG_KEYS`, if the plaintext key exists:
    /// 1. Encrypt the value using `EncryptionService`
    /// 2. Base64-encode the ciphertext
    /// 3. Store under `{key}_encrypted`
    /// 4. Remove the plaintext key
    fn encrypt_additional_config(
        &self,
        tenant_id: Uuid,
        config: &mut serde_json::Value,
    ) -> SocialResult<()> {
        if let Some(obj) = config.as_object_mut() {
            for &key in SENSITIVE_CONFIG_KEYS {
                let encrypted_key = format!("{key}_encrypted");
                if let Some(value) = obj.remove(key) {
                    if let Some(plaintext) = value.as_str() {
                        let ciphertext = self.encryption.encrypt_string(tenant_id, plaintext)?;
                        let encoded = BASE64.encode(&ciphertext);
                        obj.insert(encrypted_key, serde_json::Value::String(encoded));
                    } else {
                        // Non-string sensitive value — put it back unmodified (shouldn't happen)
                        obj.insert(key.to_string(), value);
                    }
                }
            }
        }
        Ok(())
    }

    /// Decrypt sensitive fields within `additional_config` after reading from DB.
    ///
    /// For each key in `SENSITIVE_CONFIG_KEYS`, if `{key}_encrypted` exists:
    /// 1. Base64-decode the value
    /// 2. Decrypt using `EncryptionService`
    /// 3. Store the plaintext under the original key name
    /// 4. Remove the `{key}_encrypted` key
    ///
    /// Also handles legacy plaintext values (logs a warning).
    fn decrypt_additional_config(
        &self,
        tenant_id: Uuid,
        config: &mut serde_json::Value,
    ) -> SocialResult<()> {
        if let Some(obj) = config.as_object_mut() {
            for &key in SENSITIVE_CONFIG_KEYS {
                let encrypted_key = format!("{key}_encrypted");
                if let Some(encrypted_value) = obj.remove(&encrypted_key) {
                    if let Some(encoded) = encrypted_value.as_str() {
                        let ciphertext = BASE64.decode(encoded).map_err(|e| {
                            crate::error::SocialError::EncryptionError {
                                operation: format!("decode {encrypted_key}: {e}"),
                            }
                        })?;
                        let plaintext = self.encryption.decrypt_string(tenant_id, &ciphertext)?;
                        obj.insert(key.to_string(), serde_json::Value::String(plaintext));
                    }
                } else if obj.contains_key(key) {
                    // Legacy: plaintext value still in DB — log warning but allow it
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        key = %key,
                        "additional_config contains unencrypted sensitive key — re-save provider to encrypt"
                    );
                }
            }
        }
        Ok(())
    }

    /// Get an enabled provider configuration.
    pub async fn get_enabled_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<Option<ProviderConfig>> {
        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let row: Option<ProviderRow> = sqlx::query_as(
            r"
            SELECT provider, enabled, client_id, client_secret_encrypted, additional_config, scopes
            FROM tenant_social_providers
            WHERE tenant_id = $1 AND provider = $2 AND enabled = true
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(r) => {
                let client_secret = self
                    .encryption
                    .decrypt_string(tenant_id, &r.client_secret_encrypted)?;

                // R10: Decrypt sensitive fields within additional_config
                let mut additional_config = r.additional_config;
                if let Some(ref mut config) = additional_config {
                    self.decrypt_additional_config(tenant_id, config)?;
                }

                Ok(Some(ProviderConfig {
                    provider,
                    enabled: r.enabled,
                    client_id: r.client_id,
                    client_secret,
                    additional_config,
                    scopes: r.scopes,
                }))
            }
            None => Ok(None),
        }
    }

    /// List all enabled providers for a tenant (for login page).
    pub async fn list_enabled_providers(&self, tenant_id: Uuid) -> SocialResult<Vec<ProviderType>> {
        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let rows: Vec<(String,)> = sqlx::query_as(
            r"
            SELECT provider FROM tenant_social_providers
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
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
        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let rows: Vec<AdminProviderRow> = sqlx::query_as(
            r"
            SELECT provider, enabled, client_id, scopes, created_at, updated_at
            FROM tenant_social_providers
            WHERE tenant_id = $1
            ORDER BY provider ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
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
        client_secret: Option<&str>,
        additional_config: Option<serde_json::Value>,
        scopes: Option<Vec<String>>,
    ) -> SocialResult<TenantProviderResponse> {
        // Look up the existing row once: whether it exists at all and whether it
        // already has a stored secret. This lets a plain enable/disable toggle
        // ({ enabled }) succeed without re-sending client_id / secret / scopes
        // (the UPDATE branch below preserves the stored values), while still
        // requiring them the first time a provider is configured.
        let mut check_conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *check_conn)
            .await?;
        let existing: Option<(bool,)> = sqlx::query_as(
            "SELECT client_secret_encrypted IS NOT NULL \
             FROM tenant_social_providers WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .fetch_optional(&mut *check_conn)
        .await?;
        drop(check_conn);
        let provider_exists = existing.is_some();
        let has_stored_secret = existing.map(|r| r.0).unwrap_or(false);

        // client_id is required to CREATE a provider; an existing provider keeps
        // its stored client_id when the request omits it (e.g. a toggle).
        if client_id.trim().is_empty() && !provider_exists {
            return Err(crate::error::SocialError::ConfigurationError {
                message: "client_id cannot be empty".to_string(),
            });
        }
        // A secret is required to ENABLE a provider that has none stored yet.
        // Toggling an already-configured provider on does not need to re-send it.
        if enabled && client_secret.is_none() && !has_stored_secret {
            return Err(crate::error::SocialError::ConfigurationError {
                message: "client_secret cannot be empty".to_string(),
            });
        }

        // R9: Validate additional_config size to prevent storage abuse
        if let Some(ref config) = additional_config {
            let config_str = config.to_string();
            if config_str.len() > 8192 {
                return Err(crate::error::SocialError::ConfigurationError {
                    message: "additional_config too large (max 8KB)".to_string(),
                });
            }
        }

        let client_secret_encrypted = match client_secret {
            Some(secret) => Some(self.encryption.encrypt_string(tenant_id, secret)?),
            None => None,
        };

        // R10: Encrypt sensitive fields within additional_config before persisting
        let mut additional_config = additional_config;
        if let Some(ref mut config) = additional_config {
            self.encrypt_additional_config(tenant_id, config)?;
        }

        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let row: AdminProviderRow = if let Some(ref secret) = client_secret_encrypted {
            sqlx::query_as(
                r"
                INSERT INTO tenant_social_providers (
                    tenant_id, provider, enabled, client_id, client_secret_encrypted,
                    additional_config, scopes
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (tenant_id, provider)
                DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    client_id = COALESCE(NULLIF(EXCLUDED.client_id, ''), tenant_social_providers.client_id),
                    client_secret_encrypted = EXCLUDED.client_secret_encrypted,
                    additional_config = COALESCE(EXCLUDED.additional_config, tenant_social_providers.additional_config),
                    scopes = COALESCE(EXCLUDED.scopes, tenant_social_providers.scopes),
                    updated_at = NOW()
                RETURNING provider, enabled, client_id, scopes, created_at, updated_at
                ",
            )
            .bind(tenant_id)
            .bind(provider.to_string())
            .bind(enabled)
            .bind(client_id)
            .bind(secret)
            .bind(&additional_config)
            .bind(&scopes)
            .fetch_one(&mut *conn)
            .await?
        } else {
            sqlx::query_as(
                r"
                UPDATE tenant_social_providers
                SET enabled = $3,
                    client_id = COALESCE(NULLIF($4, ''), client_id),
                    additional_config = COALESCE($5, additional_config),
                    scopes = COALESCE($6, scopes),
                    updated_at = NOW()
                WHERE tenant_id = $1 AND provider = $2
                RETURNING provider, enabled, client_id, scopes, created_at, updated_at
                ",
            )
            .bind(tenant_id)
            .bind(provider.to_string())
            .bind(enabled)
            .bind(client_id)
            .bind(&additional_config)
            .bind(&scopes)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| crate::error::SocialError::ConfigurationError {
                message: "Provider is not configured".to_string(),
            })?
        };

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
        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let result = sqlx::query(
            r"
            UPDATE tenant_social_providers
            SET enabled = false, updated_at = NOW()
            WHERE tenant_id = $1 AND provider = $2
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a provider configuration.
    pub async fn delete_provider(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<bool> {
        // SECURITY: Set RLS context for defense-in-depth (query already has tenant_id filter)
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let result = sqlx::query(
            "DELETE FROM tenant_social_providers WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .execute(&mut *conn)
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

#[cfg(test)]
mod tests {
    /// Regression: a plain enable/disable toggle from the admin UI sends only
    /// `{ enabled }` — no client_id, secret, or scopes. update_provider must
    /// treat that as a partial update against an existing provider: keep the
    /// stored client_id/secret/scopes and only flip `enabled`. Previously it
    /// rejected the empty client_id ("client_id cannot be empty") and the missing
    /// secret ("client_secret cannot be empty") with a 500, so an admin could not
    /// enable a provider they had already configured. First-time configuration
    /// still requires client_id + secret.
    #[test]
    fn enable_toggle_preserves_stored_config_for_existing_provider() {
        let src = include_str!("tenant_provider_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let update = production
            .split("pub async fn update_provider")
            .nth(1)
            .expect("update_provider");
        // Existence is checked so create-vs-update can be distinguished.
        assert!(
            update.contains("provider_exists") && update.contains("has_stored_secret"),
            "update_provider must distinguish an existing provider from a new one"
        );
        // client_id / secret only required when the provider does NOT yet exist.
        assert!(
            update.contains("client_id.trim().is_empty() && !provider_exists"),
            "client_id must be required only when creating a provider"
        );
        assert!(
            update.contains("enabled && client_secret.is_none() && !has_stored_secret"),
            "a secret must be required only when enabling an unconfigured provider"
        );
        // The UPDATE branch must preserve stored values on a toggle.
        assert!(
            update.contains("client_id = COALESCE(NULLIF($4, ''), client_id)")
                && update.contains("scopes = COALESCE($6, scopes)"),
            "toggling must preserve the stored client_id and scopes"
        );
    }
}
