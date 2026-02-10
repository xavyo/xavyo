//! Tenant provisioning service.
//!
//! Orchestrates the atomic creation of a new tenant with all associated resources.
//! Includes comprehensive audit logging for compliance (F-AUDIT-PROV).

use rand::{rngs::OsRng, RngCore};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_auth::hash_password;
use xavyo_db::models::{
    AdminAction, AdminAuditLog, AdminResourceType, ApiKey, CreateApiKey, CreateAuditLogEntry,
    Tenant, TenantMfaConfig, TenantPasswordPolicy, TenantSessionPolicy, TenantType, User,
};
use xavyo_db::set_tenant_context;

use crate::error::TenantError;
use crate::models::{
    AdminInfo, EndpointInfo, OAuthClientInfo, ProvisionContext, ProvisionTenantRequest,
    ProvisionTenantResponse, TenantInfo,
};
use crate::services::{ApiKeyService, SlugService};

/// Configuration for endpoint URLs returned in provisioning responses.
///
/// SECURITY: These URLs should be configured via environment variables
/// and not hardcoded to avoid exposing incorrect endpoints to tenants.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    /// Base URL for API access (e.g., "<https://api.xavyo.net>").
    pub api_url: String,
    /// Base URL for authentication (e.g., "<https://auth.xavyo.net>").
    pub auth_url: String,
    /// Base URL for documentation (e.g., "<https://docs.xavyo.net>").
    pub docs_url: String,
}

impl EndpointConfig {
    /// Create endpoint configuration from environment variables.
    ///
    /// Environment variables:
    /// - `API_BASE_URL`: Base URL for API (default: "<https://api.xavyo.net>")
    /// - `AUTH_BASE_URL`: Base URL for auth (default: "<https://auth.xavyo.net>")
    /// - `DOCS_BASE_URL`: Base URL for docs (default: "<https://docs.xavyo.net>")
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            api_url: std::env::var("API_BASE_URL")
                .unwrap_or_else(|_| "https://api.xavyo.net".to_string()),
            auth_url: std::env::var("AUTH_BASE_URL")
                .unwrap_or_else(|_| "https://auth.xavyo.net".to_string()),
            docs_url: std::env::var("DOCS_BASE_URL")
                .unwrap_or_else(|_| "https://docs.xavyo.net".to_string()),
        }
    }
}

/// Free tier limits applied to new tenants.
pub const FREE_TIER_MAX_MAU: i64 = 1000;
pub const FREE_TIER_MAX_AGENTS: i64 = 5;
pub const FREE_TIER_MAX_AUTH_CALLS: i64 = 10000;

/// Length of generated OAuth client IDs (bytes).
const CLIENT_ID_LENGTH: usize = 16;

/// Length of generated OAuth client secrets (bytes).
const CLIENT_SECRET_LENGTH: usize = 32;

/// Service for provisioning new tenants.
#[derive(Clone)]
pub struct ProvisioningService {
    pool: PgPool,
    slug_service: Arc<SlugService>,
    api_key_service: Arc<ApiKeyService>,
    endpoint_config: EndpointConfig,
}

impl ProvisioningService {
    /// Create a new provisioning service.
    #[must_use]
    pub fn new(
        pool: PgPool,
        slug_service: Arc<SlugService>,
        api_key_service: Arc<ApiKeyService>,
    ) -> Self {
        Self {
            pool,
            slug_service,
            api_key_service,
            endpoint_config: EndpointConfig::from_env(),
        }
    }

    /// Create a new provisioning service with custom endpoint configuration.
    #[must_use]
    pub fn with_endpoint_config(
        pool: PgPool,
        slug_service: Arc<SlugService>,
        api_key_service: Arc<ApiKeyService>,
        endpoint_config: EndpointConfig,
    ) -> Self {
        Self {
            pool,
            slug_service,
            api_key_service,
            endpoint_config,
        }
    }

    /// Provision a new tenant with all associated resources.
    ///
    /// This creates:
    /// - The tenant record with free tier settings
    /// - An admin user (passwordless, email from JWT claims)
    /// - An API key for programmatic access
    /// - A default OAuth client
    /// - Default MFA policy
    /// - Default session policy
    /// - Default password policy
    ///
    /// All operations are performed in a single transaction for atomicity.
    /// Each resource creation is logged to the admin audit trail for compliance.
    pub async fn provision(
        &self,
        request: ProvisionTenantRequest,
        email: &str,
        context: ProvisionContext,
    ) -> Result<ProvisionTenantResponse, TenantError> {
        // Validate the request
        if let Some(error) = request.validate() {
            return Err(TenantError::Validation(error));
        }

        // Generate unique slug
        let slug = self
            .slug_service
            .generate_unique_slug(&request.organization_name)
            .await?;

        // Start transaction
        let mut tx = self.pool.begin().await.map_err(|e| {
            tracing::error!("Failed to begin transaction: {}", e);
            TenantError::Database(e.to_string())
        })?;

        // Set RLS context to system tenant for tenant creation (tenants table
        // uses system tenant context for admin operations).
        set_tenant_context(
            &mut *tx,
            xavyo_core::TenantId::from_uuid(context.system_tenant_id),
        )
        .await
        .map_err(|e| TenantError::Database(format!("Failed to set tenant context: {e}")))?;

        // 1. Create tenant with free tier settings
        let settings = self.free_tier_settings();
        let tenant = Tenant::create_in_tx(
            &mut tx,
            &request.organization_name,
            &slug,
            TenantType::User,
            settings.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create tenant: {}", e);
            TenantError::Database(e.to_string())
        })?;

        // Audit: tenant.provisioned (audit logs belong to system tenant)
        self.log_audit(
            &mut tx,
            &context,
            AdminResourceType::Tenant,
            tenant.id,
            serde_json::json!({
                "name": tenant.name,
                "slug": tenant.slug,
                "plan": settings["plan"]
            }),
        )
        .await?;

        // Switch RLS context to the new tenant for resource creation
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant.id))
            .await
            .map_err(|e| TenantError::Database(format!("Failed to set tenant context: {e}")))?;

        // 2. Create admin user (passwordless, email verified)
        let admin_user =
            User::create_admin_in_tx(&mut tx, tenant.id, email, Some(&request.organization_name))
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create admin user: {}", e);
                    TenantError::Database(e.to_string())
                })?;

        // 2a. Copy password hash from system-tenant user so admin can login with same password
        let password_copied: bool = sqlx::query_scalar(
            r"
            UPDATE users SET password_hash = src.password_hash
            FROM (SELECT password_hash FROM users WHERE email = $1 AND tenant_id = $2 AND password_hash != '') src
            WHERE users.id = $3
            RETURNING true
            ",
        )
        .bind(email)
        .bind(context.system_tenant_id)
        .bind(admin_user.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to copy password hash: {e}");
            TenantError::Database(e.to_string())
        })?
        .unwrap_or(false);

        if !password_copied {
            tracing::info!(
                "No password to copy for {email}; admin must set password via reset flow"
            );
        }

        // 2b. Assign super_admin role to the new admin user
        sqlx::query(
            r"
            INSERT INTO user_roles (user_id, role_name, created_at)
            VALUES ($1, 'super_admin', NOW())
            ON CONFLICT (user_id, role_name) DO NOTHING
            ",
        )
        .bind(admin_user.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to assign admin role: {e}");
            TenantError::Database(e.to_string())
        })?;

        // Switch back to system tenant for audit logging
        set_tenant_context(
            &mut *tx,
            xavyo_core::TenantId::from_uuid(context.system_tenant_id),
        )
        .await
        .map_err(|e| TenantError::Database(format!("Failed to set tenant context: {e}")))?;

        // Audit: user.created
        self.log_audit(
            &mut tx,
            &context,
            AdminResourceType::User,
            admin_user.id,
            serde_json::json!({
                "email": admin_user.email,
                "tenant_id": tenant.id,
                "role": "admin"
            }),
        )
        .await?;

        // Switch to new tenant for resource creation
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant.id))
            .await
            .map_err(|e| TenantError::Database(format!("Failed to set tenant context: {e}")))?;

        // 3. Create API key
        let (plaintext_key, key_hash, key_prefix) = self.api_key_service.create_key_pair();
        let api_key_data = CreateApiKey {
            tenant_id: tenant.id,
            user_id: admin_user.id,
            name: "Default Admin Key".to_string(),
            key_prefix: key_prefix.clone(),
            key_hash,
            scopes: vec![], // Empty = all scopes
            expires_at: None,
        };

        let api_key = ApiKey::create_in_tx(&mut tx, api_key_data)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create API key: {}", e);
                TenantError::Database(e.to_string())
            })?;

        // 4. Create default OAuth client
        let (client_id, client_secret, oauth_client_id) = self
            .create_oauth_client_in_tx(&mut tx, tenant.id, &request.organization_name)
            .await?;

        // 5. Create default MFA policy
        TenantMfaConfig::create_default(&mut *tx, tenant.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create MFA policy: {}", e);
                TenantError::Database(e.to_string())
            })?;

        // 6. Create default session policy
        TenantSessionPolicy::create_default(&mut *tx, tenant.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create session policy: {}", e);
                TenantError::Database(e.to_string())
            })?;

        // 7. Create default password policy (T043)
        TenantPasswordPolicy::create_default(&mut *tx, tenant.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create password policy: {}", e);
                TenantError::Database(e.to_string())
            })?;

        // Switch back to system tenant for remaining audit logs
        set_tenant_context(
            &mut *tx,
            xavyo_core::TenantId::from_uuid(context.system_tenant_id),
        )
        .await
        .map_err(|e| TenantError::Database(format!("Failed to set tenant context: {e}")))?;

        // Audit: api_key.created (never log the actual key!)
        self.log_audit(
            &mut tx,
            &context,
            AdminResourceType::ApiKey,
            api_key.id,
            serde_json::json!({
                "name": "Default Admin Key",
                "key_prefix": key_prefix,
                "tenant_id": tenant.id,
                "user_id": admin_user.id
            }),
        )
        .await?;

        // Audit: oauth_client.created (never log the secret!)
        self.log_audit(
            &mut tx,
            &context,
            AdminResourceType::OauthClient,
            oauth_client_id,
            serde_json::json!({
                "client_id": client_id,
                "tenant_id": tenant.id,
                "name": format!("{} - Default Client", request.organization_name)
            }),
        )
        .await?;

        // Commit transaction
        tx.commit().await.map_err(|e| {
            tracing::error!("Failed to commit transaction: {}", e);
            TenantError::Database(e.to_string())
        })?;

        // Build response
        Ok(ProvisionTenantResponse {
            tenant: TenantInfo {
                id: tenant.id,
                slug: tenant.slug,
                name: tenant.name,
            },
            admin: AdminInfo {
                id: admin_user.id,
                email: admin_user.email,
                api_key: plaintext_key,
            },
            oauth_client: OAuthClientInfo {
                client_id,
                client_secret,
            },
            endpoints: EndpointInfo {
                api: self.endpoint_config.api_url.clone(),
                auth: self.endpoint_config.auth_url.clone(),
            },
            next_steps: vec![
                "Create your first AI agent: xavyo agents create".to_string(),
                "Register tools: xavyo tools create".to_string(),
                format!("Read the docs: {}", self.endpoint_config.docs_url),
            ],
        })
    }

    /// Generate free tier settings JSON.
    fn free_tier_settings(&self) -> serde_json::Value {
        serde_json::json!({
            "plan": "free",
            "limits": {
                "max_mau": FREE_TIER_MAX_MAU,
                "max_agents": FREE_TIER_MAX_AGENTS,
                "max_auth_calls_per_month": FREE_TIER_MAX_AUTH_CALLS
            }
        })
    }

    /// Log an audit entry within the transaction.
    async fn log_audit<'e>(
        &self,
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        context: &ProvisionContext,
        resource_type: AdminResourceType,
        resource_id: Uuid,
        new_value: serde_json::Value,
    ) -> Result<(), TenantError> {
        AdminAuditLog::create(
            &mut **tx,
            CreateAuditLogEntry {
                tenant_id: context.system_tenant_id,
                admin_user_id: context.admin_user_id,
                action: AdminAction::Create,
                resource_type,
                resource_id: Some(resource_id),
                old_value: None,
                new_value: Some(new_value),
                ip_address: context.ip_address.clone(),
                user_agent: context.user_agent.clone(),
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create audit log entry: {}", e);
            TenantError::Database(e.to_string())
        })?;

        Ok(())
    }

    /// Create a default OAuth client within a transaction.
    ///
    /// Returns (`client_id`, `client_secret_plaintext`, `oauth_client_uuid`).
    async fn create_oauth_client_in_tx<'e>(
        &self,
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        tenant_id: Uuid,
        org_name: &str,
    ) -> Result<(String, String, Uuid), TenantError> {
        // Generate credentials
        let client_id = self.generate_client_id();
        let plaintext_secret = self.generate_client_secret();
        let secret_hash = hash_password(&plaintext_secret).map_err(|e| {
            tracing::error!("Failed to hash client secret: {}", e);
            TenantError::Internal("Failed to hash client secret".to_string())
        })?;

        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let name = format!("{org_name} - Default Client");

        // Insert the client
        sqlx::query(
            r"
            INSERT INTO oauth_clients (
                id, tenant_id, client_id, client_secret_hash, name, client_type,
                redirect_uris, grant_types, scopes, is_active, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, 'confidential', $6, $7, $8, true, $9, $9)
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&client_id)
        .bind(&secret_hash)
        .bind(&name)
        .bind(vec!["https://localhost/callback".to_string()])
        .bind(vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ])
        .bind(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ])
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create OAuth client: {}", e);
            TenantError::Database(e.to_string())
        })?;

        Ok((client_id, plaintext_secret, id))
    }

    /// Generate a cryptographically secure client ID.
    ///
    /// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
    fn generate_client_id(&self) -> String {
        let mut bytes = vec![0u8; CLIENT_ID_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Generate a cryptographically secure client secret.
    ///
    /// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
    fn generate_client_secret(&self) -> String {
        let mut bytes = vec![0u8; CLIENT_SECRET_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_free_tier_settings() {
        // Test the settings JSON generation without needing a pool
        let settings = serde_json::json!({
            "plan": "free",
            "limits": {
                "max_mau": FREE_TIER_MAX_MAU,
                "max_agents": FREE_TIER_MAX_AGENTS,
                "max_auth_calls_per_month": FREE_TIER_MAX_AUTH_CALLS
            }
        });

        assert_eq!(settings["plan"], "free");
        assert_eq!(settings["limits"]["max_mau"], FREE_TIER_MAX_MAU);
        assert_eq!(settings["limits"]["max_agents"], FREE_TIER_MAX_AGENTS);
        assert_eq!(
            settings["limits"]["max_auth_calls_per_month"],
            FREE_TIER_MAX_AUTH_CALLS
        );
    }

    #[test]
    fn test_generate_client_id() {
        // Test client ID generation using the helper function directly
        fn generate_client_id() -> String {
            let mut bytes = vec![0u8; CLIENT_ID_LENGTH];
            thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        }

        let id1 = generate_client_id();
        let id2 = generate_client_id();

        // Should be 32 hex chars (16 bytes)
        assert_eq!(id1.len(), CLIENT_ID_LENGTH * 2);
        assert_eq!(id2.len(), CLIENT_ID_LENGTH * 2);

        // Should be unique
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_generate_client_secret() {
        // Test client secret generation using the helper function directly
        fn generate_client_secret() -> String {
            let mut bytes = vec![0u8; CLIENT_SECRET_LENGTH];
            thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        }

        let secret1 = generate_client_secret();
        let secret2 = generate_client_secret();

        // Should be 64 hex chars (32 bytes)
        assert_eq!(secret1.len(), CLIENT_SECRET_LENGTH * 2);
        assert_eq!(secret2.len(), CLIENT_SECRET_LENGTH * 2);

        // Should be unique
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_endpoint_config_defaults() {
        // Clear env vars to test defaults
        std::env::remove_var("API_BASE_URL");
        std::env::remove_var("AUTH_BASE_URL");
        std::env::remove_var("DOCS_BASE_URL");

        let config = EndpointConfig::from_env();

        // Verify defaults
        assert_eq!(config.api_url, "https://api.xavyo.net");
        assert_eq!(config.auth_url, "https://auth.xavyo.net");
        assert_eq!(config.docs_url, "https://docs.xavyo.net");
    }

    #[test]
    fn test_endpoint_config_from_env() {
        // Set custom env vars
        std::env::set_var("API_BASE_URL", "https://custom-api.example.com");
        std::env::set_var("AUTH_BASE_URL", "https://custom-auth.example.com");
        std::env::set_var("DOCS_BASE_URL", "https://custom-docs.example.com");

        let config = EndpointConfig::from_env();

        assert_eq!(config.api_url, "https://custom-api.example.com");
        assert_eq!(config.auth_url, "https://custom-auth.example.com");
        assert_eq!(config.docs_url, "https://custom-docs.example.com");

        // Clean up
        std::env::remove_var("API_BASE_URL");
        std::env::remove_var("AUTH_BASE_URL");
        std::env::remove_var("DOCS_BASE_URL");
    }
}
