//! OIDC Discovery service for fetching provider metadata.

use crate::error::{FederationError, FederationResult};
use openidconnect::{core::CoreProviderMetadata, IssuerUrl};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Discovered OIDC endpoints from provider metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub issuer: String,
}

/// OIDC Discovery service.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryService;

impl DiscoveryService {
    /// Create a new discovery service.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Discover OIDC provider metadata from issuer URL.
    #[instrument(skip(self), fields(issuer = %issuer_url))]
    pub async fn discover(&self, issuer_url: &str) -> FederationResult<DiscoveredEndpoints> {
        // Normalize issuer URL (remove trailing slash)
        let issuer_url = issuer_url.trim_end_matches('/');

        // Parse issuer URL
        let issuer = IssuerUrl::new(issuer_url.to_string()).map_err(|e| {
            FederationError::InvalidConfiguration(format!("Invalid issuer URL: {e}"))
        })?;

        // Create HTTP client (no redirects for SSRF protection)
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                FederationError::InvalidConfiguration(format!("Failed to create HTTP client: {e}"))
            })?;

        // Fetch provider metadata
        let metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| FederationError::DiscoveryFailed {
                issuer: issuer_url.to_string(),
                message: e.to_string(),
            })?;

        // Extract endpoints
        let endpoints = DiscoveredEndpoints {
            authorization_endpoint: metadata.authorization_endpoint().url().to_string(),
            token_endpoint: metadata
                .token_endpoint()
                .ok_or_else(|| FederationError::DiscoveryFailed {
                    issuer: issuer_url.to_string(),
                    message: "Token endpoint not found".to_string(),
                })?
                .url()
                .to_string(),
            userinfo_endpoint: metadata.userinfo_endpoint().map(|e| e.url().to_string()),
            jwks_uri: metadata.jwks_uri().url().to_string(),
            issuer: metadata.issuer().url().to_string(),
        };

        tracing::info!(
            authorization_endpoint = %endpoints.authorization_endpoint,
            token_endpoint = %endpoints.token_endpoint,
            "Successfully discovered OIDC endpoints"
        );

        Ok(endpoints)
    }

    /// Validate that an issuer URL is reachable and returns valid OIDC metadata.
    #[instrument(skip(self), fields(issuer = %issuer_url))]
    pub async fn validate_issuer(&self, issuer_url: &str) -> FederationResult<bool> {
        match self.discover(issuer_url).await {
            Ok(_) => Ok(true),
            Err(FederationError::DiscoveryFailed { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get well-known configuration URL for an issuer.
    #[must_use]
    pub fn get_well_known_url(issuer_url: &str) -> String {
        let issuer_url = issuer_url.trim_end_matches('/');
        format!("{issuer_url}/.well-known/openid-configuration")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_well_known_url() {
        assert_eq!(
            DiscoveryService::get_well_known_url("https://example.com"),
            "https://example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            DiscoveryService::get_well_known_url("https://example.com/"),
            "https://example.com/.well-known/openid-configuration"
        );
    }
}
