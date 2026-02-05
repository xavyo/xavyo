//! API key HTTP client methods
//!
//! This module provides API client methods for managing tenant API keys.
//! Calls F-049 endpoints: POST/GET/DELETE `/tenants/{tenant_id}/api-keys`.

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::api_key::{
    ApiKeyInfo, ApiKeyListResponse, CreateApiKeyRequest, CreateApiKeyResponse, RotateApiKeyRequest,
    RotateApiKeyResponse,
};
use crate::models::Session;
use uuid::Uuid;

impl ApiClient {
    /// Get the current tenant ID, returning an error if not set
    fn require_tenant_id(&self) -> CliResult<Uuid> {
        Session::load(self.paths())
            .ok()
            .flatten()
            .and_then(|s| s.tenant_id)
            .ok_or_else(|| {
                CliError::Validation(
                    "No tenant selected. Run `xavyo tenant switch <tenant-id>` first.".to_string(),
                )
            })
    }

    /// Create a new API key for the current tenant.
    /// POST `/tenants/{tenant_id}/api-keys`
    pub async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
    ) -> CliResult<CreateApiKeyResponse> {
        let tenant_id = self.require_tenant_id()?;
        let url = format!("{}/tenants/{}/api-keys", self.config().api_url, tenant_id);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::TenantAccessDenied(
                "You don't have permission for this tenant.".to_string(),
            ))
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Validation(body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// List all API keys for the current tenant.
    /// GET `/tenants/{tenant_id}/api-keys`
    pub async fn list_api_keys(&self) -> CliResult<ApiKeyListResponse> {
        let tenant_id = self.require_tenant_id()?;
        let url = format!("{}/tenants/{}/api-keys", self.config().api_url, tenant_id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::TenantAccessDenied(
                "You don't have permission for this tenant.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a specific API key by ID.
    /// GET `/tenants/{tenant_id}/api-keys/{key_id}`
    pub async fn get_api_key(&self, key_id: Uuid) -> CliResult<ApiKeyInfo> {
        let tenant_id = self.require_tenant_id()?;
        let url = format!(
            "{}/tenants/{}/api-keys/{}",
            self.config().api_url,
            tenant_id,
            key_id
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(
                "API key not found. Use `xavyo api-keys list` to see available keys.".to_string(),
            ))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::TenantAccessDenied(
                "You don't have permission for this tenant.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Rotate an API key.
    /// POST `/tenants/{tenant_id}/api-keys/{key_id}/rotate`
    pub async fn rotate_api_key(
        &self,
        key_id: Uuid,
        request: RotateApiKeyRequest,
    ) -> CliResult<RotateApiKeyResponse> {
        let tenant_id = self.require_tenant_id()?;
        let url = format!(
            "{}/tenants/{}/api-keys/{}/rotate",
            self.config().api_url,
            tenant_id,
            key_id
        );

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(
                "API key not found. Use `xavyo api-keys list` to see available keys.".to_string(),
            ))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::TenantAccessDenied(
                "You don't have permission for this tenant.".to_string(),
            ))
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Validation(body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Delete (deactivate) an API key.
    /// DELETE `/tenants/{tenant_id}/api-keys/{key_id}`
    pub async fn delete_api_key(&self, key_id: Uuid) -> CliResult<()> {
        let tenant_id = self.require_tenant_id()?;
        let url = format!(
            "{}/tenants/{}/api-keys/{}",
            self.config().api_url,
            tenant_id,
            key_id
        );

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(
                "API key not found. Use `xavyo api-keys list` to see available keys.".to_string(),
            ))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::TenantAccessDenied(
                "You don't have permission for this tenant.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }
}
