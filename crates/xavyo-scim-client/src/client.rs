//! SCIM 2.0 HTTP client (reqwest-based).
//!
//! Provides a `ScimClient` that communicates with SCIM 2.0 target endpoints
//! using RFC 7644 protocol operations.

use crate::auth::ScimAuth;
use crate::error::{ScimClientError, ScimClientResult};
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tracing::{debug, warn};
use xavyo_api_scim::models::{
    ScimGroup, ScimGroupListResponse, ScimPatchRequest, ScimUser, ScimUserListResponse,
};

/// SCIM `ServiceProviderConfig` response (subset of RFC 7643 Section 5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceProviderConfig {
    /// SCIM schema URIs.
    #[serde(default)]
    pub schemas: Vec<String>,

    /// Patch operation support.
    #[serde(default)]
    pub patch: FeatureSupport,

    /// Bulk operation support.
    #[serde(default)]
    pub bulk: BulkSupport,

    /// Filter support.
    #[serde(default)]
    pub filter: FilterSupport,

    /// Change password support.
    #[serde(default)]
    pub change_password: FeatureSupport,

    /// Sort support.
    #[serde(default)]
    pub sort: FeatureSupport,

    /// `ETag` support.
    #[serde(default)]
    pub etag: FeatureSupport,

    /// Authentication schemes.
    #[serde(default)]
    pub authentication_schemes: Vec<serde_json::Value>,
}

/// Simple feature support flag.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FeatureSupport {
    pub supported: bool,
}

/// Bulk operation support details.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BulkSupport {
    pub supported: bool,
    #[serde(default)]
    pub max_operations: i64,
    #[serde(default)]
    pub max_payload_size: i64,
}

/// Filter support details.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FilterSupport {
    pub supported: bool,
    #[serde(default)]
    pub max_results: i64,
}

/// Health check result from a SCIM target.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckResult {
    /// Whether the target is reachable and responding.
    pub healthy: bool,
    /// Timestamp of the check.
    pub checked_at: chrono::DateTime<chrono::Utc>,
    /// Cached `ServiceProviderConfig` if healthy.
    pub service_provider_config: Option<ServiceProviderConfig>,
    /// Error message if unhealthy.
    pub error: Option<String>,
}

/// SCIM 2.0 HTTP client for outbound provisioning.
///
/// Wraps `reqwest::Client` with SCIM-specific operations, authentication,
/// and error handling per RFC 7644.
#[derive(Debug, Clone)]
pub struct ScimClient {
    /// Base URL of the SCIM target (e.g., "<https://api.example.com/scim/v2>").
    base_url: String,
    /// Authentication handler.
    auth: ScimAuth,
    /// Underlying HTTP client.
    http_client: Client,
    /// Whether the target supports PATCH (from `ServiceProviderConfig`).
    patch_supported: bool,
}

impl ScimClient {
    /// Create a new SCIM client.
    pub fn new(
        base_url: String,
        auth: ScimAuth,
        timeout: Duration,
        tls_verify: bool,
    ) -> ScimClientResult<Self> {
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(!tls_verify)
            .user_agent("xavyo-scim-client/1.0")
            .build()
            .map_err(|e| {
                ScimClientError::InvalidConfig(format!("Failed to build HTTP client: {e}"))
            })?;

        // Normalize base URL: strip trailing slash.
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            base_url,
            auth,
            http_client,
            patch_supported: true, // default; updated after discovery
        })
    }

    /// Create a client with a pre-built `reqwest::Client` (for testing).
    #[must_use]
    pub fn with_http_client(base_url: String, auth: ScimAuth, http_client: Client) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            auth,
            http_client,
            patch_supported: true,
        }
    }

    /// Set whether PATCH is supported by this target.
    pub fn set_patch_supported(&mut self, supported: bool) {
        self.patch_supported = supported;
    }

    /// Whether the target supports PATCH operations.
    #[must_use]
    pub fn patch_supported(&self) -> bool {
        self.patch_supported
    }

    /// Get the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ── Discovery ─────────────────────────────────────────────────────

    /// Discover the target's `ServiceProviderConfig` (RFC 7643 Section 5).
    pub async fn discover_service_provider_config(
        &self,
    ) -> ScimClientResult<ServiceProviderConfig> {
        let url = format!("{}/ServiceProviderConfig", self.base_url);
        let builder = self.http_client.get(&url);
        let builder = self.auth.apply(builder).await?;
        let response = builder.send().await?;
        self.handle_response(response).await
    }

    /// Perform a health check on the target.
    pub async fn health_check(&self) -> HealthCheckResult {
        let checked_at = chrono::Utc::now();
        match self.discover_service_provider_config().await {
            Ok(config) => HealthCheckResult {
                healthy: true,
                checked_at,
                service_provider_config: Some(config),
                error: None,
            },
            Err(e) => HealthCheckResult {
                healthy: false,
                checked_at,
                service_provider_config: None,
                error: Some(e.to_string()),
            },
        }
    }

    // ── User Operations ───────────────────────────────────────────────

    /// Create a user on the SCIM target (POST /Users).
    pub async fn create_user(&self, user: &ScimUser) -> ScimClientResult<ScimUser> {
        let url = format!("{}/Users", self.base_url);
        self.post(&url, user).await
    }

    /// Get a user by their SCIM ID (GET /Users/:id).
    pub async fn get_user(&self, id: &str) -> ScimClientResult<ScimUser> {
        let url = format!("{}/Users/{}", self.base_url, id);
        self.get(&url).await
    }

    /// Replace a user (PUT /Users/:id).
    pub async fn replace_user(&self, id: &str, user: &ScimUser) -> ScimClientResult<ScimUser> {
        let url = format!("{}/Users/{}", self.base_url, id);
        self.put(&url, user).await
    }

    /// Patch a user (PATCH /Users/:id).
    pub async fn patch_user(
        &self,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> ScimClientResult<ScimUser> {
        let url = format!("{}/Users/{}", self.base_url, id);
        self.patch(&url, patch).await
    }

    /// Delete a user (DELETE /Users/:id).
    pub async fn delete_user(&self, id: &str) -> ScimClientResult<()> {
        let url = format!("{}/Users/{}", self.base_url, id);
        self.delete(&url).await
    }

    /// Deactivate a user by setting active=false (PATCH /Users/:id).
    pub async fn deactivate_user(&self, id: &str) -> ScimClientResult<ScimUser> {
        let patch = ScimPatchRequest {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
            operations: vec![xavyo_api_scim::models::ScimPatchOp {
                op: "replace".to_string(),
                path: Some("active".to_string()),
                value: Some(serde_json::Value::Bool(false)),
            }],
        };
        self.patch_user(id, &patch).await
    }

    /// List users with optional filter and pagination (GET /Users).
    pub async fn list_users(
        &self,
        filter: Option<&str>,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> ScimClientResult<ScimUserListResponse> {
        let url = format!("{}/Users", self.base_url);
        self.get_with_params(&url, filter, start_index, count).await
    }

    /// Find a user by externalId filter.
    pub async fn find_user_by_external_id(
        &self,
        external_id: &str,
    ) -> ScimClientResult<Option<ScimUser>> {
        let escaped = escape_scim_filter_value(external_id);
        let filter = format!("externalId eq \"{escaped}\"");
        let response: ScimUserListResponse = self.list_users(Some(&filter), None, Some(1)).await?;
        Ok(response.resources.into_iter().next())
    }

    // ── Group Operations ──────────────────────────────────────────────

    /// Create a group on the SCIM target (POST /Groups).
    pub async fn create_group(&self, group: &ScimGroup) -> ScimClientResult<ScimGroup> {
        let url = format!("{}/Groups", self.base_url);
        self.post(&url, group).await
    }

    /// Get a group by SCIM ID (GET /Groups/:id).
    pub async fn get_group(&self, id: &str) -> ScimClientResult<ScimGroup> {
        let url = format!("{}/Groups/{}", self.base_url, id);
        self.get(&url).await
    }

    /// Replace a group (PUT /Groups/:id).
    pub async fn replace_group(&self, id: &str, group: &ScimGroup) -> ScimClientResult<ScimGroup> {
        let url = format!("{}/Groups/{}", self.base_url, id);
        self.put(&url, group).await
    }

    /// Patch a group (PATCH /Groups/:id).
    pub async fn patch_group(
        &self,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> ScimClientResult<ScimGroup> {
        let url = format!("{}/Groups/{}", self.base_url, id);
        self.patch(&url, patch).await
    }

    /// Delete a group (DELETE /Groups/:id).
    pub async fn delete_group(&self, id: &str) -> ScimClientResult<()> {
        let url = format!("{}/Groups/{}", self.base_url, id);
        self.delete(&url).await
    }

    /// List groups with optional filter and pagination (GET /Groups).
    pub async fn list_groups(
        &self,
        filter: Option<&str>,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> ScimClientResult<ScimGroupListResponse> {
        let url = format!("{}/Groups", self.base_url);
        self.get_with_params(&url, filter, start_index, count).await
    }

    /// Find a group by externalId filter.
    pub async fn find_group_by_external_id(
        &self,
        external_id: &str,
    ) -> ScimClientResult<Option<ScimGroup>> {
        let escaped = escape_scim_filter_value(external_id);
        let filter = format!("externalId eq \"{escaped}\"");
        let response: ScimGroupListResponse =
            self.list_groups(Some(&filter), None, Some(1)).await?;
        Ok(response.resources.into_iter().next())
    }

    /// Patch group members — add and/or remove members.
    pub async fn patch_group_members(
        &self,
        group_id: &str,
        add_member_ids: &[String],
        remove_member_ids: &[String],
    ) -> ScimClientResult<()> {
        let mut operations = Vec::new();

        if !add_member_ids.is_empty() {
            let members: Vec<serde_json::Value> = add_member_ids
                .iter()
                .map(|id| serde_json::json!({ "value": id }))
                .collect();
            operations.push(xavyo_api_scim::models::ScimPatchOp {
                op: "add".to_string(),
                path: Some("members".to_string()),
                value: Some(serde_json::Value::Array(members)),
            });
        }

        if !remove_member_ids.is_empty() {
            for id in remove_member_ids {
                operations.push(xavyo_api_scim::models::ScimPatchOp {
                    op: "remove".to_string(),
                    path: Some(format!("members[value eq \"{id}\"]")),
                    value: None,
                });
            }
        }

        if operations.is_empty() {
            return Ok(());
        }

        let patch = ScimPatchRequest {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
            operations,
        };

        let url = format!("{}/Groups/{}", self.base_url, group_id);
        let builder = self.http_client.patch(&url);
        let builder = self.auth.apply(builder).await?;
        let response = builder
            .header("Content-Type", "application/scim+json")
            .json(&patch)
            .send()
            .await?;

        let status = response.status();
        if status == StatusCode::NO_CONTENT || status.is_success() {
            Ok(())
        } else {
            self.handle_error_response(response).await
        }
    }

    // ── Internal HTTP Methods ─────────────────────────────────────────

    async fn get_with_params<T: DeserializeOwned>(
        &self,
        url: &str,
        filter: Option<&str>,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> ScimClientResult<T> {
        debug!("SCIM GET {} (filter={:?})", url, filter);
        let mut builder = self.http_client.get(url);
        let mut query_params: Vec<(&str, String)> = Vec::new();
        if let Some(f) = filter {
            query_params.push(("filter", f.to_string()));
        }
        if let Some(si) = start_index {
            query_params.push(("startIndex", si.to_string()));
        }
        if let Some(c) = count {
            query_params.push(("count", c.to_string()));
        }
        if !query_params.is_empty() {
            builder = builder.query(&query_params);
        }
        let builder = self.auth.apply(builder).await?;
        let response = builder.send().await?;
        self.handle_response(response).await
    }

    async fn get<T: DeserializeOwned>(&self, url: &str) -> ScimClientResult<T> {
        debug!("SCIM GET {}", url);
        let builder = self.http_client.get(url);
        let builder = self.auth.apply(builder).await?;
        let response = builder.send().await?;
        self.handle_response(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> ScimClientResult<T> {
        debug!("SCIM POST {}", url);
        let builder = self.http_client.post(url);
        let builder = self.auth.apply(builder).await?;
        let response = builder
            .header("Content-Type", "application/scim+json")
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> ScimClientResult<T> {
        debug!("SCIM PUT {}", url);
        let builder = self.http_client.put(url);
        let builder = self.auth.apply(builder).await?;
        let response = builder
            .header("Content-Type", "application/scim+json")
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> ScimClientResult<T> {
        debug!("SCIM PATCH {}", url);
        let builder = self.http_client.patch(url);
        let builder = self.auth.apply(builder).await?;
        let response = builder
            .header("Content-Type", "application/scim+json")
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    async fn delete(&self, url: &str) -> ScimClientResult<()> {
        debug!("SCIM DELETE {}", url);
        let builder = self.http_client.delete(url);
        let builder = self.auth.apply(builder).await?;
        let response = builder.send().await?;

        let status = response.status();
        if status == StatusCode::NO_CONTENT || status.is_success() {
            Ok(())
        } else {
            self.handle_error_response(response).await
        }
    }

    // ── Response Handling ─────────────────────────────────────────────

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> ScimClientResult<T> {
        let status = response.status();

        if status.is_success() {
            let body = response.text().await?;
            serde_json::from_str(&body)
                .map_err(|e| ScimClientError::ParseError(format!("Failed to parse response: {e}")))
        } else {
            self.handle_error_response(response).await
        }
    }

    async fn handle_error_response<T>(&self, response: reqwest::Response) -> ScimClientResult<T> {
        let status = response.status();

        // Check for Retry-After header (rate limiting).
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());

        match status {
            StatusCode::NOT_FOUND => Err(ScimClientError::NotFound(body)),
            StatusCode::CONFLICT => Err(ScimClientError::Conflict(body)),
            StatusCode::TOO_MANY_REQUESTS => {
                warn!("SCIM target rate limited, retry after {:?}s", retry_after);
                Err(ScimClientError::RateLimited {
                    retry_after_secs: retry_after,
                })
            }
            StatusCode::UNAUTHORIZED => {
                // Invalidate cached OAuth2 token on 401.
                self.auth.invalidate_cache().await;
                Err(ScimClientError::AuthError(format!(
                    "Authentication failed (401): {body}"
                )))
            }
            _ => {
                let detail = if body.is_empty() {
                    format!("HTTP {status}")
                } else {
                    body
                };
                Err(ScimClientError::ScimError {
                    status: status.as_u16(),
                    detail,
                })
            }
        }
    }
}

/// Escape a value for use inside a SCIM filter string literal.
///
/// Per RFC 7644 Section 3.4.2.2, string values in filter expressions are
/// enclosed in double-quotes.  We escape backslashes and double-quotes to
/// prevent filter injection.
fn escape_scim_filter_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
