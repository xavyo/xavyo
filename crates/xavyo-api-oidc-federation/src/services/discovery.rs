//! OIDC Discovery service for fetching provider metadata.

use crate::error::{FederationError, FederationResult};
use openidconnect::{core::CoreProviderMetadata, IssuerUrl};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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

        // SSRF protection: validate URL before making outbound requests
        validate_url_not_internal(issuer_url)
            .map_err(|e| FederationError::InvalidConfiguration(format!("SSRF protection: {e}")))?;

        // Parse issuer URL
        let issuer = IssuerUrl::new(issuer_url.to_string()).map_err(|e| {
            FederationError::InvalidConfiguration(format!("Invalid issuer URL: {e}"))
        })?;

        // Create HTTP client (no redirects for SSRF protection, with timeout)
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
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

/// SSRF protection: validate that a URL does not target internal/private services.
pub(crate) fn validate_url_not_internal(url_str: &str) -> Result<(), String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    let scheme = url.scheme();
    // SECURITY: Only allow HTTPS for IdP URLs in production.
    // HTTP is insecure and allows MITM attacks on token endpoints.
    if scheme != "https" {
        return Err(format!("Only HTTPS is allowed for IdP URLs, got: {scheme}"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_documentation()
                    || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                {
                    return Err(format!("Internal/private IP not allowed: {host}"));
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return Err(format!("Internal/private IP not allowed: {host}"));
                }
                let segs = v6.segments();
                if (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80 {
                    return Err(format!("Internal/private IP not allowed: {host}"));
                }
            }
        }
    } else {
        let lower = host.to_lowercase();
        let blocked = [
            "localhost",
            "metadata.google.internal",
            "metadata.goog",
            "169.254.169.254",
        ];
        for b in blocked {
            if lower == b || lower.ends_with(&format!(".{b}")) {
                return Err(format!("Blocked hostname: {host}"));
            }
        }
    }

    Ok(())
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
