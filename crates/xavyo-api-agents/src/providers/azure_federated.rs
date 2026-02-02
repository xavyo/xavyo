//! Azure Federated Credentials Provider for Workload Identity Federation (F121).
//!
//! Implements Azure AD Federated Identity Credentials to exchange agent JWTs
//! for short-lived Azure access tokens.
//!
//! Flow:
//! 1. Exchange Xavyo JWT for an Azure AD access token using federated credentials
//! 2. Return the access token for Azure API calls

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use super::{
    AzureFederatedConfig, CloudCredential, CloudIdentityProvider, CloudProviderError,
    CredentialRequest, ProviderResult, TokenValidation,
};

/// Azure AD token endpoint template.
const AZURE_TOKEN_ENDPOINT_TEMPLATE: &str =
    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";

/// Default Azure scope for management APIs.
const DEFAULT_AZURE_SCOPE: &str = "https://management.azure.com/.default";

/// Azure Federated Credentials provider for obtaining Azure access tokens.
///
/// Uses Federated Identity Credentials to exchange external JWTs for Azure tokens:
/// 1. Application is configured with a federated credential that trusts Xavyo
/// 2. Agent presents JWT to Azure AD token endpoint
/// 3. Azure AD validates the JWT and issues an access token
pub struct AzureFederatedProvider {
    /// HTTP client for API calls.
    client: Client,

    /// Provider configuration.
    config: AzureFederatedConfig,
}

/// Request body for Azure AD token exchange.
#[derive(Debug, Serialize)]
struct AzureTokenRequest {
    grant_type: String,
    client_id: String,
    scope: String,
    client_assertion_type: String,
    client_assertion: String,
}

/// Response from Azure AD token endpoint.
#[derive(Debug, Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: i64,
    #[allow(dead_code)]
    ext_expires_in: Option<i64>,
}

/// Error response from Azure AD.
#[derive(Debug, Deserialize)]
struct AzureErrorResponse {
    error: String,
    error_description: String,
    #[allow(dead_code)]
    error_codes: Option<Vec<i64>>,
    #[allow(dead_code)]
    correlation_id: Option<String>,
}

impl AzureFederatedProvider {
    /// Create a new Azure Federated Credentials provider.
    pub fn new(config: AzureFederatedConfig) -> ProviderResult<Self> {
        // Validate configuration
        if config.tenant_id.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "tenant_id is required".to_string(),
            ));
        }
        if config.client_id.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "client_id is required".to_string(),
            ));
        }
        if config.issuer.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "issuer is required".to_string(),
            ));
        }
        if config.subject_claim.is_empty() {
            return Err(CloudProviderError::InvalidConfiguration(
                "subject_claim is required".to_string(),
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
    pub fn with_client(client: Client, config: AzureFederatedConfig) -> Self {
        Self { client, config }
    }

    /// Build the token endpoint URL.
    fn build_token_endpoint(&self) -> String {
        AZURE_TOKEN_ENDPOINT_TEMPLATE.replace("{tenant_id}", &self.config.tenant_id)
    }

    /// Build the scope for the token request.
    fn build_scope(&self, requested_scopes: &[String]) -> String {
        if requested_scopes.is_empty() {
            // Use default Azure Management scope if none specified
            if self.config.audience.is_empty() {
                DEFAULT_AZURE_SCOPE.to_string()
            } else {
                format!("{}/.default", self.config.audience)
            }
        } else {
            // Azure expects space-separated scopes
            requested_scopes.join(" ")
        }
    }

    /// Exchange an external JWT for an Azure AD access token.
    async fn exchange_token(
        &self,
        jwt: &str,
        scopes: &[String],
    ) -> ProviderResult<AzureTokenResponse> {
        let endpoint = self.build_token_endpoint();
        let scope = self.build_scope(scopes);

        let request = AzureTokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: self.config.client_id.clone(),
            scope,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            client_assertion: jwt.to_string(),
        };

        debug!(
            endpoint = %endpoint,
            client_id = %self.config.client_id,
            "Exchanging JWT for Azure AD access token"
        );

        let response = self
            .client
            .post(&endpoint)
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
                "Azure AD token exchange failed"
            );

            return Err(self.map_azure_error(status.as_u16(), &error_msg));
        }

        serde_json::from_str(&body).map_err(|e| {
            CloudProviderError::ProviderError(format!("Failed to parse Azure response: {}", e))
        })
    }

    /// Parse an Azure AD error response body.
    fn parse_error_response(&self, body: &str) -> String {
        match serde_json::from_str::<AzureErrorResponse>(body) {
            Ok(err) => format!("{}: {}", err.error, err.error_description),
            Err(_) => body.to_string(),
        }
    }

    /// Map Azure HTTP status and error to our error type.
    fn map_azure_error(&self, status: u16, message: &str) -> CloudProviderError {
        // Azure AD error codes reference:
        // https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
        match status {
            400 => {
                // AADSTS7xxxxx are federation/assertion errors
                if message.contains("AADSTS7") || message.contains("invalid_client") {
                    CloudProviderError::AuthenticationFailed(message.to_string())
                } else if message.contains("invalid_request") {
                    CloudProviderError::InvalidConfiguration(message.to_string())
                } else {
                    CloudProviderError::ProviderError(message.to_string())
                }
            }
            401 => CloudProviderError::AuthenticationFailed(message.to_string()),
            403 => CloudProviderError::RoleNotAllowed(message.to_string()),
            429 => CloudProviderError::RateLimitExceeded,
            500 | 503 | 504 => CloudProviderError::NotAvailable(message.to_string()),
            _ => CloudProviderError::ProviderError(message.to_string()),
        }
    }
}

#[async_trait]
impl CloudIdentityProvider for AzureFederatedProvider {
    fn provider_type(&self) -> &'static str {
        "azure"
    }

    #[instrument(skip(self), fields(provider = "azure-federated"))]
    async fn health_check(&self) -> ProviderResult<()> {
        // Check if we can reach the Azure AD OpenID configuration endpoint
        let openid_config_url = format!(
            "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
            self.config.tenant_id
        );

        let response = self
            .client
            .get(&openid_config_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "Azure AD health check failed");
                CloudProviderError::NotAvailable(format!("Azure AD not reachable: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(CloudProviderError::NotAvailable(format!(
                "Azure AD returned error: {}",
                response.status()
            )));
        }

        debug!(tenant_id = %self.config.tenant_id, "Azure Federated Credentials health check passed");
        Ok(())
    }

    #[instrument(skip(self, request), fields(
        provider = "azure-federated",
        agent_id = %request.agent_id,
        client_id = %self.config.client_id
    ))]
    async fn get_credentials(
        &self,
        request: &CredentialRequest,
    ) -> ProviderResult<CloudCredential> {
        info!(
            tenant_id = %self.config.tenant_id,
            client_id = %self.config.client_id,
            "Requesting Azure credentials via Federated Identity"
        );

        // Exchange the agent JWT for an Azure AD access token
        let token_response = self
            .exchange_token(&request.agent_jwt, &request.allowed_scopes)
            .await?;

        // Calculate expiration time
        let expires_at = chrono::Utc::now().timestamp() + token_response.expires_in;

        info!(
            expires_at = expires_at,
            expires_in = token_response.expires_in,
            "Azure credentials obtained successfully"
        );

        // Build the credential response
        let cred = CloudCredential::azure_token(token_response.access_token, expires_at)
            .with_metadata("tenant_id", &self.config.tenant_id)
            .with_metadata("client_id", &self.config.client_id);

        Ok(cred)
    }

    async fn validate_token(&self, _token: &str) -> ProviderResult<TokenValidation> {
        // Azure Federated Credentials doesn't do token validation - it trusts the OIDC provider
        // Token validation is handled by Azure AD during the token exchange
        Ok(TokenValidation::invalid(
            "Azure Federated Credentials provider does not validate tokens directly",
        ))
    }
}

/// Builder for Azure Federated Credentials configuration.
pub struct AzureFederatedConfigBuilder {
    tenant_id: String,
    client_id: String,
    audience: String,
    issuer: String,
    subject_claim: String,
}

impl AzureFederatedConfigBuilder {
    /// Create a new builder with required fields.
    pub fn new(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        issuer: impl Into<String>,
        subject_claim: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            audience: String::new(), // Will use default if empty
            issuer: issuer.into(),
            subject_claim: subject_claim.into(),
        }
    }

    /// Set a custom audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Build the configuration.
    pub fn build(self) -> AzureFederatedConfig {
        AzureFederatedConfig {
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            audience: self.audience,
            issuer: self.issuer,
            subject_claim: self.subject_claim,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_config() -> AzureFederatedConfig {
        AzureFederatedConfigBuilder::new(
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "https://xavyo.net",
            "agent_id",
        )
        .build()
    }

    #[test]
    fn test_config_validation_missing_tenant_id() {
        let config = AzureFederatedConfig {
            tenant_id: String::new(),
            client_id: "client".to_string(),
            audience: String::new(),
            issuer: "https://issuer.com".to_string(),
            subject_claim: "sub".to_string(),
        };

        let result = AzureFederatedProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_config_validation_missing_client_id() {
        let config = AzureFederatedConfig {
            tenant_id: "tenant".to_string(),
            client_id: String::new(),
            audience: String::new(),
            issuer: "https://issuer.com".to_string(),
            subject_claim: "sub".to_string(),
        };

        let result = AzureFederatedProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_config_validation_missing_issuer() {
        let config = AzureFederatedConfig {
            tenant_id: "tenant".to_string(),
            client_id: "client".to_string(),
            audience: String::new(),
            issuer: String::new(),
            subject_claim: "sub".to_string(),
        };

        let result = AzureFederatedProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_config_validation_missing_subject_claim() {
        let config = AzureFederatedConfig {
            tenant_id: "tenant".to_string(),
            client_id: "client".to_string(),
            audience: String::new(),
            issuer: "https://issuer.com".to_string(),
            subject_claim: String::new(),
        };

        let result = AzureFederatedProvider::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_build_token_endpoint() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let endpoint = provider.build_token_endpoint();
        assert_eq!(
            endpoint,
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
        );
    }

    #[test]
    fn test_build_scope_default() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let scope = provider.build_scope(&[]);
        assert_eq!(scope, DEFAULT_AZURE_SCOPE);
    }

    #[test]
    fn test_build_scope_with_audience() {
        let config =
            AzureFederatedConfigBuilder::new("tenant", "client", "https://xavyo.net", "agent_id")
                .audience("https://graph.microsoft.com")
                .build();

        let provider = AzureFederatedProvider::new(config).unwrap();

        let scope = provider.build_scope(&[]);
        assert_eq!(scope, "https://graph.microsoft.com/.default");
    }

    #[test]
    fn test_build_scope_with_explicit_scopes() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let scopes = vec!["User.Read".to_string(), "User.ReadBasic.All".to_string()];
        let scope = provider.build_scope(&scopes);
        assert_eq!(scope, "User.Read User.ReadBasic.All");
    }

    #[test]
    fn test_config_builder() {
        let config = AzureFederatedConfigBuilder::new(
            "test-tenant",
            "test-client",
            "https://xavyo.net",
            "agent_id",
        )
        .audience("https://api.example.com")
        .build();

        assert_eq!(config.tenant_id, "test-tenant");
        assert_eq!(config.client_id, "test-client");
        assert_eq!(config.issuer, "https://xavyo.net");
        assert_eq!(config.subject_claim, "agent_id");
        assert_eq!(config.audience, "https://api.example.com");
    }

    #[test]
    fn test_map_azure_error_400_invalid_client() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(400, "AADSTS700027: invalid_client assertion");
        assert!(matches!(error, CloudProviderError::AuthenticationFailed(_)));
    }

    #[test]
    fn test_map_azure_error_400_invalid_request() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(400, "invalid_request: Missing scope");
        assert!(matches!(error, CloudProviderError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_map_azure_error_401() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(401, "unauthorized_client");
        assert!(matches!(error, CloudProviderError::AuthenticationFailed(_)));
    }

    #[test]
    fn test_map_azure_error_403() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(403, "access_denied");
        assert!(matches!(error, CloudProviderError::RoleNotAllowed(_)));
    }

    #[test]
    fn test_map_azure_error_429() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(429, "Rate limit exceeded");
        assert!(matches!(error, CloudProviderError::RateLimitExceeded));
    }

    #[test]
    fn test_map_azure_error_503() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let error = provider.map_azure_error(503, "Service unavailable");
        assert!(matches!(error, CloudProviderError::NotAvailable(_)));
    }

    #[test]
    fn test_parse_error_response_json() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let json = r#"{"error":"invalid_grant","error_description":"AADSTS700027: Client assertion validation failed"}"#;
        let result = provider.parse_error_response(json);
        assert!(result.contains("invalid_grant"));
        assert!(result.contains("AADSTS700027"));
    }

    #[test]
    fn test_parse_error_response_plaintext() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let plaintext = "Some plain error message";
        let result = provider.parse_error_response(plaintext);
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_provider_type() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();
        assert_eq!(provider.provider_type(), "azure");
    }

    #[tokio::test]
    async fn test_validate_token_returns_invalid() {
        let config = test_config();
        let provider = AzureFederatedProvider::new(config).unwrap();

        let result = provider.validate_token("any-token").await;
        assert!(result.is_ok());
        let validation = result.unwrap();
        assert!(!validation.valid);
    }

    #[test]
    fn test_credential_request_building() {
        // Verify that CredentialRequest can be built for Azure
        let request = CredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_type: "automation".to_string(),
            agent_jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(),
            requested_ttl_seconds: 3600,
            role_identifier: "Azure-Agent-Role".to_string(),
            allowed_scopes: vec!["https://management.azure.com/.default".to_string()],
            constraints: serde_json::json!({}),
        };

        assert_eq!(request.agent_type, "automation");
        assert_eq!(request.requested_ttl_seconds, 3600);
    }
}
