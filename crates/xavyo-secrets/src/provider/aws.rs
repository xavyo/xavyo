//! AWS Secrets Manager secret provider.
//!
//! Uses the official aws-sdk-secretsmanager crate with IAM role or
//! explicit credential authentication.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::config::SecretProviderConfig;
use crate::{SecretError, SecretProvider, SecretValue};

/// Secret provider that reads from AWS Secrets Manager.
#[derive(Debug)]
pub struct AwsSecretProvider {
    client: aws_sdk_secretsmanager::Client,
    mappings: HashMap<String, String>,
    region: String,
}

impl AwsSecretProvider {
    /// Create a new AwsSecretProvider from configuration.
    pub async fn new(config: &SecretProviderConfig) -> Result<Self, SecretError> {
        let aws_config = config.aws.as_ref().ok_or(SecretError::ConfigError {
            detail: "AWS configuration is required when SECRET_PROVIDER=aws".to_string(),
        })?;

        let region = aws_config.region.clone();

        // Build AWS SDK config
        let mut aws_builder =
            aws_config::from_env().region(aws_config::Region::new(region.clone()));

        // Use explicit credentials if provided
        if let (Some(access_key), Some(secret_key)) =
            (&aws_config.access_key_id, &aws_config.secret_access_key)
        {
            let creds = aws_sdk_secretsmanager::config::Credentials::new(
                access_key,
                secret_key,
                None, // session token
                None, // expiry
                "xavyo-secrets-explicit",
            );
            aws_builder = aws_builder.credentials_provider(creds);
        }

        let sdk_config = aws_builder.load().await;
        let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

        tracing::info!(
            region = %region,
            explicit_creds = aws_config.access_key_id.is_some(),
            "AWS Secrets Manager provider initialized"
        );

        Ok(Self {
            client,
            mappings: config.secret_mappings.clone(),
            region,
        })
    }
}

#[async_trait]
impl SecretProvider for AwsSecretProvider {
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
        let aws_secret_name = self
            .mappings
            .get(name)
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_string(),
            })?;

        let result = self
            .client
            .get_secret_value()
            .secret_id(aws_secret_name)
            .send()
            .await
            .map_err(|e| {
                let detail = format!(
                    "Failed to get secret '{}' (AWS name: '{}', region: {}): {}",
                    name, aws_secret_name, self.region, e
                );
                SecretError::ProviderUnavailable {
                    provider: "aws".to_string(),
                    detail,
                }
            })?;

        // Extract secret value (string or binary)
        let value_bytes = if let Some(secret_string) = result.secret_string() {
            secret_string.as_bytes().to_vec()
        } else if let Some(secret_binary) = result.secret_binary() {
            secret_binary.as_ref().to_vec()
        } else {
            return Err(SecretError::InvalidValue {
                name: name.to_string(),
                detail: "AWS secret has neither SecretString nor SecretBinary".to_string(),
            });
        };

        if value_bytes.is_empty() {
            return Err(SecretError::InvalidValue {
                name: name.to_string(),
                detail: "AWS secret value is empty".to_string(),
            });
        }

        let version = result.version_id().map(|v| v.to_string());

        tracing::info!(
            secret_name = name,
            aws_name = %aws_secret_name,
            version = ?version,
            "Secret loaded from AWS Secrets Manager"
        );

        let mut sv = SecretValue::new(name, value_bytes);
        sv.version = version;
        Ok(sv)
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        // Try to describe the first mapped secret to verify connectivity
        if let Some((name, aws_name)) = self.mappings.iter().next() {
            match self
                .client
                .describe_secret()
                .secret_id(aws_name)
                .send()
                .await
            {
                Ok(_) => Ok(true),
                Err(e) => {
                    tracing::warn!(
                        secret_name = %name,
                        aws_name = %aws_name,
                        error = %e,
                        "AWS Secrets Manager health check failed"
                    );
                    Ok(false)
                }
            }
        } else {
            // No mappings, consider healthy (no secrets to check)
            Ok(true)
        }
    }

    fn provider_type(&self) -> &'static str {
        "aws"
    }
}
