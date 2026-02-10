//! Service for managing SCIM 2.0 outbound provisioning targets.

use crate::error::{ConnectorApiError, Result};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_core::TenantId;
use xavyo_db::models::{
    CreateScimTarget, ScimTarget, ScimTargetAttributeMapping, UpdateScimTarget,
};
use xavyo_db::set_tenant_context;
use xavyo_scim_client::auth::{ScimAuth, ScimCredentials};
use xavyo_scim_client::client::{ScimClient, ServiceProviderConfig};

/// Service for SCIM target CRUD operations with credential encryption.
pub struct ScimTargetService {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
}

/// Response type for target listing.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ScimTargetListResponse {
    pub items: Vec<ScimTargetResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response type for a single target (never includes raw credentials).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ScimTargetResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub base_url: String,
    pub auth_method: String,
    pub deprovisioning_strategy: String,
    pub tls_verify: bool,
    pub rate_limit_per_minute: i32,
    pub request_timeout_secs: i32,
    pub max_retries: i32,
    pub status: String,
    pub last_health_check_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_health_check_error: Option<String>,
    pub service_provider_config: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ScimTarget> for ScimTargetResponse {
    fn from(t: ScimTarget) -> Self {
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            name: t.name,
            base_url: t.base_url,
            auth_method: t.auth_method,
            deprovisioning_strategy: t.deprovisioning_strategy,
            tls_verify: t.tls_verify,
            rate_limit_per_minute: t.rate_limit_per_minute,
            request_timeout_secs: t.request_timeout_secs,
            max_retries: t.max_retries,
            status: t.status,
            last_health_check_at: t.last_health_check_at,
            last_health_check_error: t.last_health_check_error,
            service_provider_config: t.service_provider_config,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

/// Request to create a SCIM target.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CreateScimTargetRequest {
    pub name: String,
    pub base_url: String,
    pub auth_method: String,
    pub credentials: ScimCredentials,
    #[serde(default = "default_deprovisioning_strategy")]
    pub deprovisioning_strategy: String,
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: i32,
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: i32,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
}

fn default_deprovisioning_strategy() -> String {
    "deactivate".to_string()
}
fn default_true() -> bool {
    true
}
fn default_rate_limit() -> i32 {
    60
}
fn default_timeout() -> i32 {
    30
}
fn default_max_retries() -> i32 {
    5
}

/// Request to update a SCIM target.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct UpdateScimTargetRequest {
    pub name: Option<String>,
    pub base_url: Option<String>,
    pub auth_method: Option<String>,
    pub credentials: Option<ScimCredentials>,
    pub deprovisioning_strategy: Option<String>,
    pub tls_verify: Option<bool>,
    pub rate_limit_per_minute: Option<i32>,
    pub request_timeout_secs: Option<i32>,
    pub max_retries: Option<i32>,
}

/// Health check response.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct HealthCheckResponse {
    pub status: String,
    pub checked_at: chrono::DateTime<chrono::Utc>,
    pub service_provider_config: Option<ServiceProviderConfig>,
    pub error: Option<String>,
}

impl ScimTargetService {
    #[must_use]
    pub fn new(pool: PgPool, encryption: Arc<CredentialEncryption>) -> Self {
        Self { pool, encryption }
    }

    /// Get a reference to the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a new SCIM target with encrypted credentials.
    pub async fn create_target(
        &self,
        tenant_id: Uuid,
        req: CreateScimTargetRequest,
    ) -> Result<ScimTargetResponse> {
        // Validate auth_method.
        if req.auth_method != "bearer" && req.auth_method != "oauth2" {
            return Err(ConnectorApiError::Validation(format!(
                "auth_method must be 'bearer' or 'oauth2', got '{}'",
                req.auth_method
            )));
        }

        // Validate deprovisioning_strategy.
        if req.deprovisioning_strategy != "deactivate" && req.deprovisioning_strategy != "delete" {
            return Err(ConnectorApiError::Validation(format!(
                "deprovisioning_strategy must be 'deactivate' or 'delete', got '{}'",
                req.deprovisioning_strategy
            )));
        }

        // Validate numeric configuration fields.
        if req.request_timeout_secs < 1 || req.request_timeout_secs > 300 {
            return Err(ConnectorApiError::Validation(
                "request_timeout_secs must be between 1 and 300".to_string(),
            ));
        }
        if req.max_retries < 0 || req.max_retries > 20 {
            return Err(ConnectorApiError::Validation(
                "max_retries must be between 0 and 20".to_string(),
            ));
        }
        if req.rate_limit_per_minute < 1 || req.rate_limit_per_minute > 10000 {
            return Err(ConnectorApiError::Validation(
                "rate_limit_per_minute must be between 1 and 10000".to_string(),
            ));
        }

        // SSRF protection: validate base_url before making outbound requests.
        Self::validate_url_not_internal(&req.base_url)?;

        // Encrypt credentials.
        let credentials_encrypted = self
            .encryption
            .encrypt_json(tenant_id, &req.credentials)
            .map_err(|e| ConnectorApiError::EncryptionFailed(e.to_string()))?;

        // Try to validate connection before saving.
        let (status, spc_json) = match self
            .validate_connection(
                &req.base_url,
                &req.credentials,
                req.tls_verify,
                req.request_timeout_secs,
            )
            .await
        {
            Ok(config) => {
                let spc_json = serde_json::to_value(&config).ok();
                ("active".to_string(), spc_json)
            }
            Err(e) => {
                warn!(
                    "SCIM target connection validation failed for {}: {}",
                    req.base_url, e
                );
                ("unreachable".to_string(), None)
            }
        };

        let create = CreateScimTarget {
            tenant_id,
            name: req.name,
            base_url: req.base_url,
            auth_method: req.auth_method,
            credentials_encrypted,
            credentials_key_version: 1,
            deprovisioning_strategy: req.deprovisioning_strategy,
            tls_verify: req.tls_verify,
            rate_limit_per_minute: req.rate_limit_per_minute,
            request_timeout_secs: req.request_timeout_secs,
            max_retries: req.max_retries,
            status,
            service_provider_config: spc_json,
        };

        // Use transaction to ensure tenant context is set for RLS
        let mut tx = self.pool.begin().await.map_err(|e| {
            error!("Failed to begin transaction: {:?}", e);
            ConnectorApiError::Database(e)
        })?;

        set_tenant_context(&mut *tx, TenantId::from_uuid(tenant_id))
            .await
            .map_err(|e| {
                error!("Failed to set tenant context: {:?}", e);
                ConnectorApiError::Internal(format!("Failed to set tenant context: {e}"))
            })?;

        let target = ScimTarget::create(&mut *tx, &create).await.map_err(|e| {
            error!("Failed to create SCIM target in database: {:?}", e);
            ConnectorApiError::Database(e)
        })?;

        // Insert default attribute mappings using the transaction.
        ScimTargetAttributeMapping::insert_defaults_for_target_tx(&mut tx, tenant_id, target.id)
            .await
            .map_err(|e| {
                error!("Failed to insert default attribute mappings: {:?}", e);
                ConnectorApiError::Database(e)
            })?;

        tx.commit().await.map_err(|e| {
            error!("Failed to commit transaction: {:?}", e);
            ConnectorApiError::Database(e)
        })?;

        info!(
            tenant_id = %tenant_id,
            target_id = %target.id,
            target_name = %target.name,
            "SCIM target created"
        );

        Ok(target.into())
    }

    /// Get a SCIM target by ID (never returns raw credentials).
    pub async fn get_target(&self, tenant_id: Uuid, target_id: Uuid) -> Result<ScimTargetResponse> {
        let target = ScimTarget::get_by_id(&self.pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "scim_target".to_string(),
                id: target_id.to_string(),
            })?;
        Ok(target.into())
    }

    /// List SCIM targets for a tenant.
    pub async fn list_targets(
        &self,
        tenant_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ScimTargetListResponse> {
        let (targets, total) =
            ScimTarget::list_by_tenant(&self.pool, tenant_id, status, limit, offset).await?;
        Ok(ScimTargetListResponse {
            items: targets.into_iter().map(Into::into).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Update a SCIM target.
    pub async fn update_target(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        req: UpdateScimTargetRequest,
    ) -> Result<ScimTargetResponse> {
        // Verify target exists.
        let existing = ScimTarget::get_by_id(&self.pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "scim_target".to_string(),
                id: target_id.to_string(),
            })?;

        // Validate numeric configuration fields when provided.
        if let Some(timeout) = req.request_timeout_secs {
            if !(1..=300).contains(&timeout) {
                return Err(ConnectorApiError::Validation(
                    "request_timeout_secs must be between 1 and 300".to_string(),
                ));
            }
        }
        if let Some(retries) = req.max_retries {
            if !(0..=20).contains(&retries) {
                return Err(ConnectorApiError::Validation(
                    "max_retries must be between 0 and 20".to_string(),
                ));
            }
        }
        if let Some(rate) = req.rate_limit_per_minute {
            if !(1..=10000).contains(&rate) {
                return Err(ConnectorApiError::Validation(
                    "rate_limit_per_minute must be between 1 and 10000".to_string(),
                ));
            }
        }

        // Validate auth_method when provided.
        if let Some(ref auth_method) = req.auth_method {
            if auth_method != "bearer" && auth_method != "oauth2" {
                return Err(ConnectorApiError::Validation(format!(
                    "auth_method must be 'bearer' or 'oauth2', got '{auth_method}'"
                )));
            }
        }

        // Validate deprovisioning_strategy when provided.
        if let Some(ref strategy) = req.deprovisioning_strategy {
            if strategy != "deactivate" && strategy != "delete" {
                return Err(ConnectorApiError::Validation(format!(
                    "deprovisioning_strategy must be 'deactivate' or 'delete', got '{strategy}'"
                )));
            }
        }

        // SSRF protection: validate base_url when changed.
        if let Some(ref base_url) = req.base_url {
            Self::validate_url_not_internal(base_url)?;
        }

        // Encrypt new credentials if provided.
        let credentials_encrypted = if let Some(ref creds) = req.credentials {
            Some(
                self.encryption
                    .encrypt_json(tenant_id, creds)
                    .map_err(|e| ConnectorApiError::EncryptionFailed(e.to_string()))?,
            )
        } else {
            None
        };

        // Determine connection validation parameters.
        let base_url = req.base_url.as_deref().unwrap_or(&existing.base_url);
        let tls_verify = req.tls_verify.unwrap_or(existing.tls_verify);
        let timeout_secs = req
            .request_timeout_secs
            .unwrap_or(existing.request_timeout_secs);

        // If credentials or base_url changed, re-validate connection.
        let (status, spc_json) = if req.credentials.is_some() || req.base_url.is_some() {
            let creds = if let Some(ref c) = req.credentials {
                c.clone()
            } else {
                self.decrypt_credentials(tenant_id, &existing)?
            };
            match self
                .validate_connection(base_url, &creds, tls_verify, timeout_secs)
                .await
            {
                Ok(config) => {
                    let spc_json = serde_json::to_value(&config).ok();
                    (Some("active".to_string()), spc_json)
                }
                Err(e) => {
                    warn!("SCIM target re-validation failed: {}", e);
                    (Some("unreachable".to_string()), None)
                }
            }
        } else {
            (None, None)
        };

        let update = UpdateScimTarget {
            name: req.name,
            base_url: req.base_url,
            auth_method: req.auth_method,
            credentials_encrypted,
            deprovisioning_strategy: req.deprovisioning_strategy,
            tls_verify: req.tls_verify,
            rate_limit_per_minute: req.rate_limit_per_minute,
            request_timeout_secs: req.request_timeout_secs,
            max_retries: req.max_retries,
            status,
            service_provider_config: spc_json,
        };

        let updated = ScimTarget::update(&self.pool, tenant_id, target_id, &update)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "scim_target".to_string(),
                id: target_id.to_string(),
            })?;

        info!(
            tenant_id = %tenant_id,
            target_id = %target_id,
            "SCIM target updated"
        );

        Ok(updated.into())
    }

    /// Delete a SCIM target and all associated data.
    pub async fn delete_target(&self, tenant_id: Uuid, target_id: Uuid) -> Result<()> {
        // Verify it exists.
        let _ = ScimTarget::get_by_id(&self.pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "scim_target".to_string(),
                id: target_id.to_string(),
            })?;

        ScimTarget::delete(&self.pool, tenant_id, target_id).await?;

        info!(
            tenant_id = %tenant_id,
            target_id = %target_id,
            "SCIM target deleted"
        );

        Ok(())
    }

    /// Perform a health check on a SCIM target.
    pub async fn health_check(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<HealthCheckResponse> {
        let target = ScimTarget::get_by_id(&self.pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "scim_target".to_string(),
                id: target_id.to_string(),
            })?;

        let credentials = self.decrypt_credentials(tenant_id, &target)?;
        let client = self.build_client(&target, &credentials)?;
        let result = client.health_check().await;

        // Update target with health check results.
        let spc_json = result
            .service_provider_config
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok());
        let new_status = if result.healthy {
            "active"
        } else {
            "unreachable"
        };

        ScimTarget::update_health_check(
            &self.pool,
            tenant_id,
            target_id,
            new_status,
            result.error.as_deref(),
            spc_json.as_ref(),
        )
        .await?;

        Ok(HealthCheckResponse {
            status: new_status.to_string(),
            checked_at: result.checked_at,
            service_provider_config: result.service_provider_config,
            error: result.error,
        })
    }

    /// Build a `ScimClient` from a target's stored configuration.
    pub fn build_client(
        &self,
        target: &ScimTarget,
        credentials: &ScimCredentials,
    ) -> Result<ScimClient> {
        let auth = ScimAuth::new(credentials.clone(), reqwest::Client::new());
        ScimClient::new(
            target.base_url.clone(),
            auth,
            Duration::from_secs(target.request_timeout_secs as u64),
            target.tls_verify,
        )
        .map_err(|e| ConnectorApiError::Internal(e.to_string()))
    }

    /// Decrypt credentials from a stored target.
    pub fn decrypt_credentials(
        &self,
        tenant_id: Uuid,
        target: &ScimTarget,
    ) -> Result<ScimCredentials> {
        self.encryption
            .decrypt_json(tenant_id, &target.credentials_encrypted)
            .map_err(|e| ConnectorApiError::DecryptionFailed(e.to_string()))
    }

    /// SSRF protection: validate that a URL does not target internal/private services.
    fn validate_url_not_internal(url_str: &str) -> Result<()> {
        use std::net::IpAddr;

        let url = reqwest::Url::parse(url_str)
            .map_err(|e| ConnectorApiError::Validation(format!("Invalid URL: {e}")))?;

        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(ConnectorApiError::Validation(format!(
                "Unsupported scheme: {scheme}"
            )));
        }

        let host = url
            .host_str()
            .ok_or_else(|| ConnectorApiError::Validation("URL has no host".to_string()))?;

        if let Ok(ip) = host.parse::<IpAddr>() {
            let blocked = match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.is_documentation()
                        || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            };
            if blocked {
                return Err(ConnectorApiError::Validation(format!(
                    "SSRF protection: internal/private IP not allowed: {host}"
                )));
            }
        } else {
            let lower = host.to_lowercase();
            let blocked_hosts = [
                "localhost",
                "metadata.google.internal",
                "metadata.goog",
                "169.254.169.254",
            ];
            for b in blocked_hosts {
                if lower == b || lower.ends_with(&format!(".{b}")) {
                    return Err(ConnectorApiError::Validation(format!(
                        "SSRF protection: blocked hostname: {host}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a SCIM target connection by discovering `ServiceProviderConfig`.
    async fn validate_connection(
        &self,
        base_url: &str,
        credentials: &ScimCredentials,
        tls_verify: bool,
        timeout_secs: i32,
    ) -> std::result::Result<ServiceProviderConfig, String> {
        let auth = ScimAuth::new(credentials.clone(), reqwest::Client::new());
        let client = ScimClient::new(
            base_url.to_string(),
            auth,
            Duration::from_secs(timeout_secs as u64),
            tls_verify,
        )
        .map_err(|e| e.to_string())?;

        client
            .discover_service_provider_config()
            .await
            .map_err(|e| e.to_string())
    }
}
