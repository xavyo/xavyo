//! AWS STS Provider for Workload Identity Federation (F121).
//!
//! Implements `AssumeRoleWithWebIdentity` to exchange agent JWTs
//! for short-lived AWS credentials.

use async_trait::async_trait;
use tracing::instrument;
#[cfg(feature = "aws-federation")]
use tracing::{debug, error, info};

use super::{
    AwsStsConfig, CloudCredential, CloudIdentityProvider, CloudProviderError, CredentialRequest,
    ProviderResult, TokenValidation,
};

/// AWS STS provider for obtaining temporary AWS credentials.
///
/// Uses `AssumeRoleWithWebIdentity` to exchange agent JWTs for AWS credentials.
pub struct AwsStsProvider {
    /// AWS STS client.
    #[cfg(feature = "aws-federation")]
    sts_client: aws_sdk_sts::Client,

    /// Provider configuration.
    #[allow(dead_code)] // Used when aws-federation feature is enabled
    config: AwsStsConfig,
}

impl AwsStsProvider {
    /// Create a new AWS STS provider.
    #[cfg(feature = "aws-federation")]
    pub async fn new(config: AwsStsConfig) -> ProviderResult<Self> {
        // Load AWS config for the specified region
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()))
            .load()
            .await;

        let sts_client = aws_sdk_sts::Client::new(&aws_config);

        Ok(Self { sts_client, config })
    }

    /// Create a new AWS STS provider (stub when feature disabled).
    #[cfg(not(feature = "aws-federation"))]
    pub async fn new(config: AwsStsConfig) -> ProviderResult<Self> {
        Ok(Self { config })
    }

    /// Create a provider from existing components (for testing).
    #[cfg(feature = "aws-federation")]
    pub fn from_client(sts_client: aws_sdk_sts::Client, config: AwsStsConfig) -> Self {
        Self { sts_client, config }
    }

    /// Generate a unique session name for the STS call.
    #[allow(dead_code)] // Used when aws-federation feature is enabled
    fn session_name(&self, agent_id: &uuid::Uuid) -> String {
        format!("{}-{}", self.config.session_name_prefix, agent_id)
    }

    /// Calculate the session duration based on requested and max TTL.
    #[allow(dead_code)] // Used when aws-federation feature is enabled
    fn session_duration(&self, requested_ttl: i32) -> i32 {
        // AWS minimum is 900 seconds (15 minutes), maximum is 12 hours (43200)
        // But also constrained by the role's max session duration
        requested_ttl
            .max(900)
            .min(self.config.max_duration_seconds)
            .min(43200)
    }
}

#[async_trait]
impl CloudIdentityProvider for AwsStsProvider {
    fn provider_type(&self) -> &'static str {
        "aws"
    }

    #[instrument(skip(self), fields(provider = "aws-sts"))]
    async fn health_check(&self) -> ProviderResult<()> {
        #[cfg(feature = "aws-federation")]
        {
            // Try to get caller identity to verify AWS connectivity
            match self.sts_client.get_caller_identity().send().await {
                Ok(response) => {
                    debug!(
                        account = ?response.account(),
                        arn = ?response.arn(),
                        "AWS STS health check passed"
                    );
                    Ok(())
                }
                Err(err) => {
                    error!(error = %err, "AWS STS health check failed");
                    Err(CloudProviderError::NotAvailable(format!(
                        "AWS STS not available: {}",
                        err
                    )))
                }
            }
        }

        #[cfg(not(feature = "aws-federation"))]
        {
            Err(CloudProviderError::NotAvailable(
                "AWS federation feature not enabled".to_string(),
            ))
        }
    }

    #[instrument(skip(self, request), fields(
        provider = "aws-sts",
        agent_id = %request.agent_id,
        role = %request.role_identifier
    ))]
    async fn get_credentials(
        &self,
        request: &CredentialRequest,
    ) -> ProviderResult<CloudCredential> {
        #[cfg(feature = "aws-federation")]
        {
            let session_name = self.session_name(&request.agent_id);
            let duration = self.session_duration(request.requested_ttl_seconds);

            info!(
                session_name = %session_name,
                duration_seconds = duration,
                "Requesting AWS credentials via AssumeRoleWithWebIdentity"
            );

            // Build the AssumeRoleWithWebIdentity request
            // Note: ExternalId is not supported for AssumeRoleWithWebIdentity (only for AssumeRole)
            // The config.external_id field is preserved for backward compatibility but unused
            let sts_request = self
                .sts_client
                .assume_role_with_web_identity()
                .role_arn(&request.role_identifier)
                .role_session_name(&session_name)
                .web_identity_token(&request.agent_jwt)
                .duration_seconds(duration);

            // Execute the request
            let response = sts_request.send().await.map_err(|err| {
                error!(error = %err, "AssumeRoleWithWebIdentity failed");

                // Map specific AWS errors to our error types
                let err_str = err.to_string();
                if err_str.contains("AccessDenied") || err_str.contains("not authorized") {
                    CloudProviderError::RoleNotAllowed(request.role_identifier.clone())
                } else if err_str.contains("ThrottlingException")
                    || err_str.contains("Rate exceeded")
                {
                    CloudProviderError::RateLimitExceeded
                } else if err_str.contains("InvalidIdentityToken")
                    || err_str.contains("ExpiredToken")
                {
                    CloudProviderError::AuthenticationFailed(err_str)
                } else {
                    CloudProviderError::ProviderError(err_str)
                }
            })?;

            // Extract credentials from response
            // Note: credentials() returns Option<&Credentials>, but the inner fields are direct &str
            let credentials = response.credentials().ok_or_else(|| {
                CloudProviderError::ProviderError("No credentials in response".to_string())
            })?;

            let access_key = credentials.access_key_id();
            let secret_key = credentials.secret_access_key();
            let session_token = credentials.session_token();
            let expiration = credentials.expiration();

            let expires_at = expiration.secs();

            info!(
                expires_at = expires_at,
                "AWS credentials obtained successfully"
            );

            // Build the credential response
            let mut cred = CloudCredential::aws_sts(
                access_key.to_string(),
                secret_key.to_string(),
                session_token.to_string(),
                expires_at,
            );

            // Add metadata about the assumed role
            // Note: assumed_role_user() returns Option<&AssumedRoleUser>, but arn() and assumed_role_id() return &str
            if let Some(assumed_role) = response.assumed_role_user() {
                cred = cred.with_metadata("assumed_role_arn", assumed_role.arn());
                cred = cred.with_metadata("assumed_role_id", assumed_role.assumed_role_id());
            }

            Ok(cred)
        }

        #[cfg(not(feature = "aws-federation"))]
        {
            Err(CloudProviderError::NotAvailable(
                "AWS federation feature not enabled".to_string(),
            ))
        }
    }

    async fn validate_token(&self, _token: &str) -> ProviderResult<TokenValidation> {
        // AWS STS doesn't do token validation - it trusts the OIDC provider
        // Token validation is handled by AWS during AssumeRoleWithWebIdentity
        Ok(TokenValidation::invalid(
            "AWS STS provider does not validate tokens directly",
        ))
    }
}

/// Builder for AWS STS provider configuration.
pub struct AwsStsConfigBuilder {
    region: String,
    oidc_provider_arn: String,
    session_name_prefix: String,
    external_id: Option<String>,
    max_duration_seconds: i32,
}

impl AwsStsConfigBuilder {
    /// Create a new builder with required fields.
    pub fn new(region: impl Into<String>, oidc_provider_arn: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            oidc_provider_arn: oidc_provider_arn.into(),
            session_name_prefix: "xavyo-agent".to_string(),
            external_id: None,
            max_duration_seconds: 3600,
        }
    }

    /// Set the session name prefix.
    pub fn session_name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.session_name_prefix = prefix.into();
        self
    }

    /// Set the external ID.
    pub fn external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }

    /// Set the maximum session duration.
    #[must_use] 
    pub fn max_duration_seconds(mut self, duration: i32) -> Self {
        self.max_duration_seconds = duration.clamp(900, 43200);
        self
    }

    /// Build the configuration.
    #[must_use] 
    pub fn build(self) -> AwsStsConfig {
        AwsStsConfig {
            region: self.region,
            oidc_provider_arn: self.oidc_provider_arn,
            session_name_prefix: self.session_name_prefix,
            external_id: self.external_id,
            max_duration_seconds: self.max_duration_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_name_generation() {
        let config = AwsStsConfigBuilder::new(
            "us-east-1",
            "arn:aws:iam::123456789012:oidc-provider/xavyo.net",
        )
        .session_name_prefix("test-prefix")
        .build();

        // Create provider without AWS SDK for testing
        #[cfg(not(feature = "aws-federation"))]
        {
            let provider = AwsStsProvider { config };
            let agent_id = uuid::Uuid::new_v4();
            let session = provider.session_name(&agent_id);
            assert!(session.starts_with("test-prefix-"));
            assert!(session.contains(&agent_id.to_string()));
        }
    }

    #[test]
    fn test_session_duration_clamping() {
        let config = AwsStsConfigBuilder::new(
            "us-east-1",
            "arn:aws:iam::123456789012:oidc-provider/xavyo.net",
        )
        .max_duration_seconds(7200)
        .build();

        #[cfg(not(feature = "aws-federation"))]
        {
            let provider = AwsStsProvider { config };

            // Below minimum
            assert_eq!(provider.session_duration(100), 900);

            // Within range
            assert_eq!(provider.session_duration(3600), 3600);

            // Above configured max
            assert_eq!(provider.session_duration(10000), 7200);

            // Above AWS max
            let config2 = AwsStsConfigBuilder::new(
                "us-east-1",
                "arn:aws:iam::123456789012:oidc-provider/xavyo.net",
            )
            .max_duration_seconds(50000)
            .build();
            let provider2 = AwsStsProvider { config: config2 };
            assert_eq!(provider2.session_duration(50000), 43200);
        }
    }

    #[test]
    fn test_config_builder() {
        let config = AwsStsConfigBuilder::new(
            "eu-west-1",
            "arn:aws:iam::123456789012:oidc-provider/example.com",
        )
        .session_name_prefix("my-app")
        .external_id("ext-123")
        .max_duration_seconds(1800)
        .build();

        assert_eq!(config.region, "eu-west-1");
        assert_eq!(
            config.oidc_provider_arn,
            "arn:aws:iam::123456789012:oidc-provider/example.com"
        );
        assert_eq!(config.session_name_prefix, "my-app");
        assert_eq!(config.external_id, Some("ext-123".to_string()));
        assert_eq!(config.max_duration_seconds, 1800);
    }
}
