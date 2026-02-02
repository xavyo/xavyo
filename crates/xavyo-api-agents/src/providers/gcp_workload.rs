//! GCP Workload Identity Provider for Workload Identity Federation (F121).
//!
//! Implements Google's Workload Identity Federation to exchange agent JWTs
//! for short-lived GCP access tokens via service account impersonation.
//!
//! Flow:
//! 1. Exchange Xavyo JWT for a GCP STS token
//! 2. Use STS token to impersonate a GCP service account
//! 3. Return the impersonated access token

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use super::{
    CloudCredential, CloudIdentityProvider, CloudProviderError, CredentialRequest,
    GcpWorkloadIdentityConfig, ProviderResult, TokenValidation,
};

/// GCP STS token exchange endpoint.
const GCP_STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";

/// GCP IAM Credentials API endpoint template.
const GCP_IAM_CREDENTIALS_ENDPOINT: &str =
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts";

/// GCP Workload Identity provider for obtaining GCP access tokens.
///
/// Uses Workload Identity Federation to exchange agent JWTs for GCP credentials:
/// 1. Exchange JWT for GCP STS token via Google's Security Token Service
/// 2. Use STS token to impersonate a service account
/// 3. Return the impersonated access token
pub struct GcpWorkloadProvider {
    /// HTTP client for API calls.
    client: Client,

    /// Provider configuration.
    config: GcpWorkloadIdentityConfig,
}

/// Request body for GCP STS token exchange.
#[derive(Debug, Serialize)]
struct StsTokenRequest {
    grant_type: String,
    audience: String,
    scope: String,
    requested_token_type: String,
    subject_token: String,
    subject_token_type: String,
}

/// Response from GCP STS token exchange.
#[derive(Debug, Deserialize)]
struct StsTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    issued_token_type: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: i64,
}

/// Request body for service account token generation.
#[derive(Debug, Serialize)]
struct GenerateAccessTokenRequest {
    scope: Vec<String>,
    lifetime: String,
}

/// Response from service account token generation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: String,
}

/// Error response from GCP APIs.
#[derive(Debug, Deserialize)]
struct GcpErrorResponse {
    error: GcpError,
}

#[derive(Debug, Deserialize)]
struct GcpError {
    code: i32,
    message: String,
    #[allow(dead_code)]
    status: Option<String>,
}

impl GcpWorkloadProvider {
    /// Create a new GCP Workload Identity provider.
    pub fn new(config: GcpWorkloadIdentityConfig) -> ProviderResult<Self> {
        // Validate configuration
        if config.project_id.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "project_id is required".to_string(),
            ));
        }
        if config.workload_identity_pool_id.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "workload_identity_pool_id is required".to_string(),
            ));
        }
        if config.workload_identity_provider_id.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "workload_identity_provider_id is required".to_string(),
            ));
        }
        if config.service_account_email.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "service_account_email is required".to_string(),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CloudProviderError::NetworkError(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Create a provider with a custom HTTP client (for testing).
    #[cfg(test)]
    pub fn with_client(client: Client, config: GcpWorkloadIdentityConfig) -> Self {
        Self { client, config }
    }

    /// Build the full audience URL for STS token exchange.
    fn build_audience(&self) -> String {
        if !self.config.audience.is_empty() {
            return self.config.audience.clone();
        }

        // Default audience format for workload identity pools
        format!(
            "//iam.googleapis.com/projects/{}/locations/global/workloadIdentityPools/{}/providers/{}",
            self.config.project_id,
            self.config.workload_identity_pool_id,
            self.config.workload_identity_provider_id
        )
    }

    /// Exchange an external JWT for a GCP STS token.
    async fn exchange_token(&self, jwt: &str) -> ProviderResult<StsTokenResponse> {
        let audience = self.build_audience();

        let request = StsTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            audience,
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            subject_token: jwt.to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        };

        debug!(
            endpoint = GCP_STS_ENDPOINT,
            "Exchanging JWT for GCP STS token"
        );

        let response = self
            .client
            .post(GCP_STS_ENDPOINT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&request)
            .send()
            .await
            .map_err(|e| CloudProviderError::NetworkError(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| CloudProviderError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            let error_msg = self.parse_error_response(&body);
            error!(
                status = %status,
                error = %error_msg,
                "GCP STS token exchange failed"
            );

            return Err(self.map_gcp_error(status.as_u16(), &error_msg));
        }

        serde_json::from_str(&body).map_err(|e| {
            CloudProviderError::ProviderError(format!("Failed to parse STS response: {}", e))
        })
    }

    /// Impersonate a service account to get an access token.
    async fn impersonate_service_account(
        &self,
        sts_token: &str,
        scopes: &[String],
        ttl_seconds: i32,
    ) -> ProviderResult<GenerateAccessTokenResponse> {
        let endpoint = format!(
            "{}/{}:generateAccessToken",
            GCP_IAM_CREDENTIALS_ENDPOINT, self.config.service_account_email
        );

        // Default scopes if none provided
        let effective_scopes = if scopes.is_empty() {
            vec!["https://www.googleapis.com/auth/cloud-platform".to_string()]
        } else {
            scopes.to_vec()
        };

        // GCP allows lifetime up to 3600 seconds (1 hour) by default,
        // or up to 12 hours if the service account has the right constraint lifted
        let lifetime_seconds = ttl_seconds.clamp(300, 3600);
        let lifetime = format!("{}s", lifetime_seconds);

        let request = GenerateAccessTokenRequest {
            scope: effective_scopes,
            lifetime,
        };

        debug!(
            endpoint = %endpoint,
            service_account = %self.config.service_account_email,
            lifetime = %request.lifetime,
            "Impersonating service account"
        );

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .bearer_auth(sts_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudProviderError::NetworkError(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| CloudProviderError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            let error_msg = self.parse_error_response(&body);
            error!(
                status = %status,
                error = %error_msg,
                service_account = %self.config.service_account_email,
                "Service account impersonation failed"
            );

            return Err(self.map_gcp_error(status.as_u16(), &error_msg));
        }

        serde_json::from_str(&body).map_err(|e| {
            CloudProviderError::ProviderError(format!(
                "Failed to parse impersonation response: {}",
                e
            ))
        })
    }

    /// Parse a GCP error response body.
    fn parse_error_response(&self, body: &str) -> String {
        match serde_json::from_str::<GcpErrorResponse>(body) {
            Ok(err) => format!("[{}] {}", err.error.code, err.error.message),
            Err(_) => body.to_string(),
        }
    }

    /// Map GCP HTTP status and error to our error type.
    fn map_gcp_error(&self, status: u16, message: &str) -> CloudProviderError {
        match status {
            401 => CloudProviderError::AuthenticationFailed(message.to_string()),
            403 => {
                if message.contains("PERMISSION_DENIED") || message.contains("permission") {
                    CloudProviderError::RoleNotAllowed(message.to_string())
                } else {
                    CloudProviderError::AuthenticationFailed(message.to_string())
                }
            }
            404 => {
                CloudProviderError::InvalidConfiguration(format!("Resource not found: {}", message))
            }
            429 => CloudProviderError::RateLimitExceeded,
            503 | 504 => CloudProviderError::NotAvailable(message.to_string()),
            _ => CloudProviderError::ProviderError(message.to_string()),
        }
    }

    /// Parse an RFC 3339 timestamp to Unix seconds.
    fn parse_expire_time(&self, expire_time: &str) -> ProviderResult<i64> {
        chrono::DateTime::parse_from_rfc3339(expire_time)
            .map(|dt| dt.timestamp())
            .map_err(|e| {
                CloudProviderError::ProviderError(format!("Failed to parse expiry time: {}", e))
            })
    }
}

#[async_trait]
impl CloudIdentityProvider for GcpWorkloadProvider {
    fn provider_type(&self) -> &'static str {
        "gcp"
    }

    #[instrument(skip(self), fields(provider = "gcp-workload"))]
    async fn health_check(&self) -> ProviderResult<()> {
        // Check if we can reach the STS endpoint with an OPTIONS request
        // This doesn't require authentication and verifies network connectivity
        let response = self
            .client
            .head(GCP_STS_ENDPOINT)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "GCP STS health check failed");
                CloudProviderError::NotAvailable(format!("GCP STS not reachable: {}", e))
            })?;

        // GCP STS endpoint should respond with an HTTP status (even if error for HEAD)
        if response.status().is_server_error() {
            return Err(CloudProviderError::NotAvailable(format!(
                "GCP STS returned server error: {}",
                response.status()
            )));
        }

        debug!("GCP Workload Identity health check passed");
        Ok(())
    }

    #[instrument(skip(self, request), fields(
        provider = "gcp-workload",
        agent_id = %request.agent_id,
        service_account = %self.config.service_account_email
    ))]
    async fn get_credentials(
        &self,
        request: &CredentialRequest,
    ) -> ProviderResult<CloudCredential> {
        info!(
            project_id = %self.config.project_id,
            pool_id = %self.config.workload_identity_pool_id,
            "Requesting GCP credentials via Workload Identity Federation"
        );

        // Step 1: Exchange the agent JWT for a GCP STS token
        let sts_response = self.exchange_token(&request.agent_jwt).await?;

        debug!(
            expires_in = sts_response.expires_in,
            "Got GCP STS token, impersonating service account"
        );

        // Step 2: Use the STS token to impersonate the service account
        let impersonation_response = self
            .impersonate_service_account(
                &sts_response.access_token,
                &request.allowed_scopes,
                request.requested_ttl_seconds,
            )
            .await?;

        // Parse the expiration time
        let expires_at = self.parse_expire_time(&impersonation_response.expire_time)?;

        info!(
            expires_at = expires_at,
            service_account = %self.config.service_account_email,
            "GCP credentials obtained successfully"
        );

        // Build the credential response
        let cred =
            CloudCredential::gcp_access_token(impersonation_response.access_token, expires_at)
                .with_metadata("project_id", &self.config.project_id)
                .with_metadata("service_account", &self.config.service_account_email)
                .with_metadata(
                    "workload_identity_pool",
                    &self.config.workload_identity_pool_id,
                );

        Ok(cred)
    }

    async fn validate_token(&self, _token: &str) -> ProviderResult<TokenValidation> {
        // GCP Workload Identity doesn't do token validation - it trusts the OIDC provider
        // Token validation is handled by GCP during the STS exchange
        Ok(TokenValidation::invalid(
            "GCP Workload Identity provider does not validate tokens directly",
        ))
    }
}

/// Builder for GCP Workload Identity configuration.
pub struct GcpWorkloadIdentityConfigBuilder {
    project_id: String,
    workload_identity_pool_id: String,
    workload_identity_provider_id: String,
    audience: String,
    service_account_email: String,
}

impl GcpWorkloadIdentityConfigBuilder {
    /// Create a new builder with required fields.
    pub fn new(
        project_id: impl Into<String>,
        workload_identity_pool_id: impl Into<String>,
        workload_identity_provider_id: impl Into<String>,
        service_account_email: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            workload_identity_pool_id: workload_identity_pool_id.into(),
            workload_identity_provider_id: workload_identity_provider_id.into(),
            audience: String::new(), // Will be auto-generated if empty
            service_account_email: service_account_email.into(),
        }
    }

    /// Set a custom audience (overrides the auto-generated one).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Build the configuration.
    pub fn build(self) -> GcpWorkloadIdentityConfig {
        GcpWorkloadIdentityConfig {
            project_id: self.project_id,
            workload_identity_pool_id: self.workload_identity_pool_id,
            workload_identity_provider_id: self.workload_identity_provider_id,
            audience: self.audience,
            service_account_email: self.service_account_email,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_config() -> GcpWorkloadIdentityConfig {
        GcpWorkloadIdentityConfigBuilder::new(
            "my-project-123",
            "xavyo-pool",
            "xavyo-provider",
            "xavyo-agent@my-project-123.iam.gserviceaccount.com",
        )
        .build()
    }

    #[test]
    fn test_config_validation_missing_project_id() {
        let config = GcpWorkloadIdentityConfig {
            project_id: String::new(),
            workload_identity_pool_id: "pool".to_string(),
            workload_identity_provider_id: "provider".to_string(),
            audience: String::new(),
            service_account_email: "sa@example.iam.gserviceaccount.com".to_string(),
        };

        let result = GcpWorkloadProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_config_validation_missing_pool_id() {
        let config = GcpWorkloadIdentityConfig {
            project_id: "project".to_string(),
            workload_identity_pool_id: String::new(),
            workload_identity_provider_id: "provider".to_string(),
            audience: String::new(),
            service_account_email: "sa@example.iam.gserviceaccount.com".to_string(),
        };

        let result = GcpWorkloadProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_config_validation_missing_service_account() {
        let config = GcpWorkloadIdentityConfig {
            project_id: "project".to_string(),
            workload_identity_pool_id: "pool".to_string(),
            workload_identity_provider_id: "provider".to_string(),
            audience: String::new(),
            service_account_email: String::new(),
        };

        let result = GcpWorkloadProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_build_audience_auto() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let audience = provider.build_audience();
        assert_eq!(
            audience,
            "//iam.googleapis.com/projects/my-project-123/locations/global/workloadIdentityPools/xavyo-pool/providers/xavyo-provider"
        );
    }

    #[test]
    fn test_build_audience_custom() {
        let config = GcpWorkloadIdentityConfigBuilder::new(
            "my-project-123",
            "xavyo-pool",
            "xavyo-provider",
            "xavyo-agent@my-project-123.iam.gserviceaccount.com",
        )
        .audience("custom-audience")
        .build();

        let provider = GcpWorkloadProvider::new(config).unwrap();

        let audience = provider.build_audience();
        assert_eq!(audience, "custom-audience");
    }

    #[test]
    fn test_config_builder() {
        let config = GcpWorkloadIdentityConfigBuilder::new(
            "test-project",
            "test-pool",
            "test-provider",
            "test-sa@test-project.iam.gserviceaccount.com",
        )
        .audience("custom-audience")
        .build();

        assert_eq!(config.project_id, "test-project");
        assert_eq!(config.workload_identity_pool_id, "test-pool");
        assert_eq!(config.workload_identity_provider_id, "test-provider");
        assert_eq!(config.audience, "custom-audience");
        assert_eq!(
            config.service_account_email,
            "test-sa@test-project.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn test_map_gcp_error_401() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let error = provider.map_gcp_error(401, "Invalid token");
        assert!(matches!(error, CloudProviderError::AuthenticationFailed(_)));
    }

    #[test]
    fn test_map_gcp_error_403_permission() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let error = provider.map_gcp_error(403, "PERMISSION_DENIED: No access");
        assert!(matches!(error, CloudProviderError::RoleNotAllowed(_)));
    }

    #[test]
    fn test_map_gcp_error_429() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let error = provider.map_gcp_error(429, "Rate limit exceeded");
        assert!(matches!(error, CloudProviderError::RateLimitExceeded));
    }

    #[test]
    fn test_map_gcp_error_503() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let error = provider.map_gcp_error(503, "Service unavailable");
        assert!(matches!(error, CloudProviderError::NotAvailable(_)));
    }

    #[test]
    fn test_parse_expire_time() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        // Valid RFC 3339 timestamp
        let result = provider.parse_expire_time("2026-01-15T10:30:00Z");
        assert!(result.is_ok());

        // Invalid timestamp
        let result = provider.parse_expire_time("invalid-timestamp");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_response_json() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let json =
            r#"{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}"#;
        let result = provider.parse_error_response(json);
        assert!(result.contains("403"));
        assert!(result.contains("Permission denied"));
    }

    #[test]
    fn test_parse_error_response_plaintext() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let plaintext = "Some plain error message";
        let result = provider.parse_error_response(plaintext);
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_provider_type() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();
        assert_eq!(provider.provider_type(), "gcp");
    }

    #[tokio::test]
    async fn test_validate_token_returns_invalid() {
        let config = test_config();
        let provider = GcpWorkloadProvider::new(config).unwrap();

        let result = provider.validate_token("any-token").await;
        assert!(result.is_ok());
        let validation = result.unwrap();
        assert!(!validation.valid);
    }

    // Mock-based tests for actual API calls would require a test server
    // These are kept as integration tests in a separate file

    #[test]
    fn test_credential_request_building() {
        // Verify that CredentialRequest can be built for GCP
        let request = CredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_type: "automation".to_string(),
            agent_jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(),
            requested_ttl_seconds: 3600,
            role_identifier: "xavyo-agent@project.iam.gserviceaccount.com".to_string(),
            allowed_scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
            constraints: serde_json::json!({}),
        };

        assert_eq!(request.agent_type, "automation");
        assert_eq!(request.requested_ttl_seconds, 3600);
    }
}
