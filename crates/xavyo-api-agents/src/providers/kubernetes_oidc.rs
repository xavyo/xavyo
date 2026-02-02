//! Kubernetes OIDC Provider for Workload Identity Federation (F121).
//!
//! Verifies Kubernetes service account tokens using the cluster's OIDC
//! configuration and maps them to agent identities.

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use super::{
    CloudCredential, CloudIdentityProvider, CloudProviderError, CredentialRequest,
    KubernetesOidcConfig, ProviderResult, TokenValidation,
};
use xavyo_auth::JwksClient;

/// Kubernetes OIDC provider for verifying service account tokens.
///
/// This provider validates Kubernetes service account tokens using the
/// cluster's JWKS endpoint and extracts identity information for
/// agent authentication.
pub struct KubernetesOidcProvider {
    /// Provider configuration.
    config: KubernetesOidcConfig,

    /// JWKS client for fetching and caching public keys.
    jwks_client: JwksClient,
}

impl KubernetesOidcProvider {
    /// Create a new Kubernetes OIDC provider.
    ///
    /// # Arguments
    ///
    /// * `config` - The Kubernetes OIDC configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the JWKS client cannot be created.
    pub fn new(config: KubernetesOidcConfig) -> ProviderResult<Self> {
        let jwks_client = JwksClient::new(&config.jwks_url).map_err(|e| {
            CloudProviderError::InvalidConfiguration(format!("Failed to create JWKS client: {}", e))
        })?;

        Ok(Self {
            config,
            jwks_client,
        })
    }

    /// Create a provider with a custom JWKS client (for testing).
    #[cfg(test)]
    pub fn with_jwks_client(config: KubernetesOidcConfig, jwks_client: JwksClient) -> Self {
        Self {
            config,
            jwks_client,
        }
    }

    /// Extract the key ID (kid) from a JWT header.
    fn extract_kid(token: &str) -> ProviderResult<String> {
        let header = decode_header(token).map_err(|e| {
            CloudProviderError::AuthenticationFailed(format!("Invalid token header: {}", e))
        })?;

        header.kid.ok_or_else(|| {
            CloudProviderError::AuthenticationFailed("Token missing key ID (kid)".to_string())
        })
    }

    /// Get the decoding key for a token.
    async fn get_decoding_key(&self, kid: &str) -> ProviderResult<DecodingKey> {
        let pem = self.jwks_client.get_key_pem(kid).await.map_err(|e| {
            CloudProviderError::AuthenticationFailed(format!("Failed to get key: {}", e))
        })?;

        DecodingKey::from_rsa_pem(&pem).map_err(|e| {
            CloudProviderError::AuthenticationFailed(format!("Invalid RSA key: {}", e))
        })
    }
}

/// Claims from a Kubernetes service account token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesTokenClaims {
    /// Issuer (the Kubernetes API server).
    #[serde(rename = "iss")]
    pub issuer: String,

    /// Subject - format: system:serviceaccount:<namespace>:<name>
    #[serde(rename = "sub")]
    pub subject: String,

    /// Audience - who the token is intended for.
    #[serde(rename = "aud")]
    pub audience: Audience,

    /// Expiration timestamp.
    #[serde(rename = "exp")]
    pub expires_at: i64,

    /// Issued at timestamp.
    #[serde(rename = "iat")]
    pub issued_at: i64,

    /// Not before timestamp.
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,

    /// Kubernetes-specific claims.
    #[serde(rename = "kubernetes.io", skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesClaims>,
}

/// Kubernetes-specific claims in the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesClaims {
    /// Namespace of the service account.
    pub namespace: Option<String>,

    /// Pod information.
    pub pod: Option<PodInfo>,

    /// Service account information.
    pub serviceaccount: Option<ServiceAccountInfo>,
}

/// Pod information from the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    /// Pod name.
    pub name: String,

    /// Pod UID.
    pub uid: String,
}

/// Service account information from the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountInfo {
    /// Service account name.
    pub name: String,

    /// Service account UID.
    pub uid: String,
}

/// Audience can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience string.
    Single(String),
    /// Multiple audience strings.
    Multiple(Vec<String>),
}

impl Audience {
    /// Get the audience as a vector of strings.
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Audience::Single(s) => vec![s.clone()],
            Audience::Multiple(v) => v.clone(),
        }
    }

    /// Check if the audience contains a specific value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(v) => v.iter().any(|a| a == value),
        }
    }
}

#[async_trait]
impl CloudIdentityProvider for KubernetesOidcProvider {
    fn provider_type(&self) -> &'static str {
        "kubernetes"
    }

    #[instrument(skip(self), fields(provider = "kubernetes-oidc"))]
    async fn health_check(&self) -> ProviderResult<()> {
        // Verify we can fetch the JWKS
        match self.jwks_client.get_jwks().await {
            Ok(jwks) => {
                let key_count = jwks.keys.len();
                debug!(key_count, "Kubernetes OIDC health check passed");
                if key_count == 0 {
                    warn!("JWKS endpoint returned no keys");
                }
                Ok(())
            }
            Err(err) => {
                error!(error = %err, "Kubernetes OIDC health check failed");
                Err(CloudProviderError::NotAvailable(format!(
                    "Cannot fetch JWKS: {}",
                    err
                )))
            }
        }
    }

    #[instrument(skip(self, request), fields(
        provider = "kubernetes-oidc",
        agent_id = %request.agent_id
    ))]
    async fn get_credentials(
        &self,
        request: &CredentialRequest,
    ) -> ProviderResult<CloudCredential> {
        // Kubernetes OIDC provider doesn't issue credentials directly
        // It validates incoming tokens from K8s workloads
        // The agent JWT in the request should be a K8s service account token

        // First validate the token
        let validation = self.validate_token(&request.agent_jwt).await?;

        if !validation.valid {
            return Err(CloudProviderError::AuthenticationFailed(
                validation
                    .error
                    .unwrap_or_else(|| "Token validation failed".to_string()),
            ));
        }

        // Return a "credential" that represents the validated K8s identity
        // This is primarily for audit/tracking - the actual credential is the original token
        let expires_at = validation.expires_at.unwrap_or_else(|| {
            // Default to 1 hour if no expiration
            chrono::Utc::now().timestamp() + 3600
        });

        let mut cred = CloudCredential::kubernetes_token(request.agent_jwt.clone(), expires_at);

        // Add metadata from the validated token
        if let Some(subject) = &validation.subject {
            cred = cred.with_metadata("subject", subject);
        }
        if let Some(issuer) = &validation.issuer {
            cred = cred.with_metadata("issuer", issuer);
        }

        // Extract namespace and service account from claims
        if let Some(namespace) = validation.claims.get("namespace") {
            if let Some(ns) = namespace.as_str() {
                cred = cred.with_metadata("namespace", ns);
            }
        }
        if let Some(sa) = validation.claims.get("serviceaccount") {
            if let Some(name) = sa.as_str() {
                cred = cred.with_metadata("serviceaccount", name);
            }
        }

        info!(
            subject = ?validation.subject,
            expires_at,
            "Kubernetes token validated and credential issued"
        );

        Ok(cred)
    }

    #[instrument(skip(self, token), fields(provider = "kubernetes-oidc"))]
    async fn validate_token(&self, token: &str) -> ProviderResult<TokenValidation> {
        // Extract the key ID from the token header
        let kid = match Self::extract_kid(token) {
            Ok(kid) => kid,
            Err(e) => {
                debug!(error = %e, "Failed to extract kid from token");
                return Ok(TokenValidation::invalid(e.to_string()));
            }
        };

        debug!(kid = %kid, "Extracted key ID from token");

        // Get the decoding key
        let decoding_key = match self.get_decoding_key(&kid).await {
            Ok(key) => key,
            Err(e) => {
                debug!(error = %e, "Failed to get decoding key");
                return Ok(TokenValidation::invalid(e.to_string()));
            }
        };

        // Set up validation rules
        let mut validation = Validation::new(Algorithm::RS256);

        // Validate the issuer
        validation.set_issuer(&[&self.config.issuer_url]);

        // Validate the audience
        validation.set_audience(&[&self.config.audience]);

        // Validate expiration
        validation.validate_exp = true;

        // Decode and validate the token
        let token_data = match decode::<KubernetesTokenClaims>(token, &decoding_key, &validation) {
            Ok(data) => data,
            Err(e) => {
                debug!(error = %e, "Token validation failed");
                let error_msg = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token has expired",
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => "Invalid issuer",
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => "Invalid audience",
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => "Invalid signature",
                    _ => "Token validation failed",
                };
                return Ok(TokenValidation::invalid(error_msg));
            }
        };

        let claims = &token_data.claims;

        info!(
            subject = %claims.subject,
            issuer = %claims.issuer,
            "Kubernetes token validated successfully"
        );

        // Build the validation result
        let mut result = TokenValidation::valid(
            claims.subject.clone(),
            claims.issuer.clone(),
            claims.expires_at,
        )
        .with_audience(claims.audience.as_vec());

        // Add Kubernetes-specific claims
        let mut extra_claims: HashMap<String, serde_json::Value> = HashMap::new();

        if let Some(k8s) = &claims.kubernetes {
            if let Some(ns) = &k8s.namespace {
                extra_claims.insert(
                    "namespace".to_string(),
                    serde_json::Value::String(ns.clone()),
                );
            }
            if let Some(pod) = &k8s.pod {
                extra_claims.insert(
                    "pod_name".to_string(),
                    serde_json::Value::String(pod.name.clone()),
                );
                extra_claims.insert(
                    "pod_uid".to_string(),
                    serde_json::Value::String(pod.uid.clone()),
                );
            }
            if let Some(sa) = &k8s.serviceaccount {
                extra_claims.insert(
                    "serviceaccount".to_string(),
                    serde_json::Value::String(sa.name.clone()),
                );
                extra_claims.insert(
                    "serviceaccount_uid".to_string(),
                    serde_json::Value::String(sa.uid.clone()),
                );
            }
        }

        // Parse subject to extract namespace and service account name
        // Format: system:serviceaccount:<namespace>:<name>
        let parts: Vec<&str> = claims.subject.split(':').collect();
        if parts.len() == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
            if !extra_claims.contains_key("namespace") {
                extra_claims.insert(
                    "namespace".to_string(),
                    serde_json::Value::String(parts[2].to_string()),
                );
            }
            if !extra_claims.contains_key("serviceaccount") {
                extra_claims.insert(
                    "serviceaccount".to_string(),
                    serde_json::Value::String(parts[3].to_string()),
                );
            }
        }

        for (key, value) in extra_claims {
            result = result.with_claim(key, value);
        }

        Ok(result)
    }
}

/// Builder for Kubernetes OIDC provider configuration.
pub struct KubernetesOidcConfigBuilder {
    api_server_url: String,
    issuer_url: String,
    jwks_url: String,
    audience: String,
    ca_cert: Option<String>,
}

impl KubernetesOidcConfigBuilder {
    /// Create a new builder with required fields.
    ///
    /// # Arguments
    ///
    /// * `api_server_url` - The Kubernetes API server URL
    /// * `audience` - The expected audience in tokens
    pub fn new(api_server_url: impl Into<String>, audience: impl Into<String>) -> Self {
        let api_url = api_server_url.into();
        // Default JWKS URL is the API server's OIDC discovery endpoint
        let jwks_url = format!("{}/openid/v1/jwks", api_url.trim_end_matches('/'));

        Self {
            api_server_url: api_url.clone(),
            issuer_url: api_url,
            jwks_url,
            audience: audience.into(),
            ca_cert: None,
        }
    }

    /// Set a custom issuer URL.
    pub fn issuer_url(mut self, url: impl Into<String>) -> Self {
        self.issuer_url = url.into();
        self
    }

    /// Set a custom JWKS URL.
    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = url.into();
        self
    }

    /// Set the CA certificate for the API server.
    pub fn ca_cert(mut self, cert: impl Into<String>) -> Self {
        self.ca_cert = Some(cert.into());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> KubernetesOidcConfig {
        KubernetesOidcConfig {
            api_server_url: self.api_server_url,
            issuer_url: self.issuer_url,
            jwks_url: self.jwks_url,
            audience: self.audience,
            ca_cert: self.ca_cert,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_single() {
        let aud = Audience::Single("https://kubernetes.default.svc".to_string());
        assert!(aud.contains("https://kubernetes.default.svc"));
        assert!(!aud.contains("other"));
        assert_eq!(aud.as_vec(), vec!["https://kubernetes.default.svc"]);
    }

    #[test]
    fn test_audience_multiple() {
        let aud = Audience::Multiple(vec![
            "https://kubernetes.default.svc".to_string(),
            "xavyo".to_string(),
        ]);
        assert!(aud.contains("https://kubernetes.default.svc"));
        assert!(aud.contains("xavyo"));
        assert!(!aud.contains("other"));
        assert_eq!(aud.as_vec().len(), 2);
    }

    #[test]
    fn test_config_builder() {
        let config =
            KubernetesOidcConfigBuilder::new("https://kubernetes.example.com:6443", "xavyo-agent")
                .build();

        assert_eq!(config.api_server_url, "https://kubernetes.example.com:6443");
        assert_eq!(config.issuer_url, "https://kubernetes.example.com:6443");
        assert_eq!(
            config.jwks_url,
            "https://kubernetes.example.com:6443/openid/v1/jwks"
        );
        assert_eq!(config.audience, "xavyo-agent");
        assert!(config.ca_cert.is_none());
    }

    #[test]
    fn test_config_builder_custom_urls() {
        let config =
            KubernetesOidcConfigBuilder::new("https://kubernetes.example.com:6443", "xavyo-agent")
                .issuer_url("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE")
                .jwks_url("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE/keys")
                .ca_cert("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
                .build();

        assert_eq!(
            config.issuer_url,
            "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
        );
        assert_eq!(
            config.jwks_url,
            "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE/keys"
        );
        assert!(config.ca_cert.is_some());
    }

    #[test]
    fn test_extract_kid_invalid_token() {
        let result = KubernetesOidcProvider::extract_kid("not-a-valid-token");
        assert!(result.is_err());
    }

    #[test]
    fn test_kubernetes_claims_deserialization() {
        let json = r#"{
            "iss": "https://kubernetes.default.svc",
            "sub": "system:serviceaccount:default:my-agent",
            "aud": "xavyo",
            "exp": 1700000000,
            "iat": 1699990000,
            "kubernetes.io": {
                "namespace": "default",
                "serviceaccount": {
                    "name": "my-agent",
                    "uid": "sa-uid-123"
                },
                "pod": {
                    "name": "my-agent-pod-xyz",
                    "uid": "pod-uid-456"
                }
            }
        }"#;

        let claims: KubernetesTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.issuer, "https://kubernetes.default.svc");
        assert_eq!(claims.subject, "system:serviceaccount:default:my-agent");
        assert!(claims.audience.contains("xavyo"));
        assert_eq!(claims.expires_at, 1700000000);

        let k8s = claims.kubernetes.unwrap();
        assert_eq!(k8s.namespace, Some("default".to_string()));
        let sa = k8s.serviceaccount.unwrap();
        assert_eq!(sa.name, "my-agent");
        let pod = k8s.pod.unwrap();
        assert_eq!(pod.name, "my-agent-pod-xyz");
    }

    #[test]
    fn test_kubernetes_claims_audience_array() {
        let json = r#"{
            "iss": "https://kubernetes.default.svc",
            "sub": "system:serviceaccount:default:my-agent",
            "aud": ["xavyo", "https://kubernetes.default.svc"],
            "exp": 1700000000,
            "iat": 1699990000
        }"#;

        let claims: KubernetesTokenClaims = serde_json::from_str(json).unwrap();
        let audiences = claims.audience.as_vec();
        assert_eq!(audiences.len(), 2);
        assert!(audiences.contains(&"xavyo".to_string()));
    }

    #[test]
    fn test_token_validation_result() {
        let valid = TokenValidation::valid(
            "system:serviceaccount:default:agent".to_string(),
            "https://kubernetes.default.svc".to_string(),
            chrono::Utc::now().timestamp() + 3600,
        )
        .with_audience(vec!["xavyo".to_string()])
        .with_claim(
            "namespace",
            serde_json::Value::String("default".to_string()),
        );

        assert!(valid.valid);
        assert_eq!(
            valid.subject,
            Some("system:serviceaccount:default:agent".to_string())
        );
        assert!(valid.claims.contains_key("namespace"));
    }

    #[test]
    fn test_token_validation_invalid() {
        let invalid = TokenValidation::invalid("Token expired");
        assert!(!invalid.valid);
        assert_eq!(invalid.error, Some("Token expired".to_string()));
    }
}
