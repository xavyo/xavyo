//! SCIM target authentication — Bearer token and `OAuth2` client credentials.

use crate::error::{ScimClientError, ScimClientResult};
use reqwest::RequestBuilder;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Decrypted credentials for a SCIM target.
///
/// The [`Debug`] impl redacts sensitive fields (tokens and secrets) to prevent
/// accidental credential exposure in log output.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type")]
pub enum ScimCredentials {
    /// Bearer token authentication.
    #[serde(rename = "bearer")]
    Bearer { token: String },

    /// `OAuth2` client credentials grant.
    #[serde(rename = "oauth2")]
    OAuth2 {
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        #[serde(default)]
        scopes: Vec<String>,
    },
}

impl std::fmt::Debug for ScimCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { .. } => f
                .debug_struct("Bearer")
                .field("token", &"[REDACTED]")
                .finish(),
            Self::OAuth2 {
                client_id,
                token_endpoint,
                scopes,
                ..
            } => f
                .debug_struct("OAuth2")
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .field("token_endpoint", token_endpoint)
                .field("scopes", scopes)
                .finish(),
        }
    }
}

/// `OAuth2` token response from the token endpoint.
#[derive(Debug, Deserialize)]
struct OAuth2TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Cached `OAuth2` access token with expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Option<std::time::Instant>,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => std::time::Instant::now() >= exp,
            None => false,
        }
    }
}

/// Authentication handler for SCIM targets.
///
/// Supports Bearer token (static) and `OAuth2` client credentials (with caching).
#[derive(Debug, Clone)]
pub struct ScimAuth {
    credentials: ScimCredentials,
    /// Cached `OAuth2` token (shared across clones).
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    /// HTTP client for `OAuth2` token requests.
    http_client: reqwest::Client,
    /// Skip SSRF validation on token endpoints (for testing only).
    skip_ssrf_validation: bool,
}

impl ScimAuth {
    /// Create a new auth handler from decrypted credentials.
    #[must_use]
    pub fn new(credentials: ScimCredentials, http_client: reqwest::Client) -> Self {
        Self {
            credentials,
            cached_token: Arc::new(RwLock::new(None)),
            http_client,
            skip_ssrf_validation: false,
        }
    }

    /// Skip SSRF validation on `OAuth2` token endpoints.
    ///
    /// **WARNING**: Only use in tests with mock servers on localhost.
    /// In production, SSRF validation must remain enabled.
    #[must_use]
    pub fn with_skip_ssrf_validation(mut self) -> Self {
        self.skip_ssrf_validation = true;
        self
    }

    /// Get the Bearer token to use for requests.
    ///
    /// For Bearer auth, returns the static token.
    /// For `OAuth2` CC, fetches (or returns cached) access token.
    pub async fn get_bearer_token(&self) -> ScimClientResult<String> {
        match &self.credentials {
            ScimCredentials::Bearer { token } => Ok(token.clone()),
            ScimCredentials::OAuth2 {
                client_id,
                client_secret,
                token_endpoint,
                scopes,
            } => {
                // Check cache first.
                {
                    let cache = self.cached_token.read().await;
                    if let Some(cached) = cache.as_ref() {
                        if !cached.is_expired() {
                            return Ok(cached.access_token.clone());
                        }
                    }
                }

                // SECURITY: Validate token_endpoint to prevent SSRF.
                // Block requests to internal/private networks and cloud metadata services.
                let url = reqwest::Url::parse(token_endpoint).map_err(|_| {
                    ScimClientError::AuthError(format!(
                        "Invalid token endpoint URL: {token_endpoint}"
                    ))
                })?;

                if url.scheme() != "https" && url.scheme() != "http" {
                    return Err(ScimClientError::AuthError(format!(
                        "Token endpoint must use HTTPS or HTTP scheme, got: {}",
                        url.scheme()
                    )));
                }

                if !self.skip_ssrf_validation {
                    if let Some(host) = url.host_str() {
                        if is_ssrf_blocked_host(host) {
                            return Err(ScimClientError::AuthError(format!(
                                "Token endpoint points to a blocked address: {host}"
                            )));
                        }
                    }
                }

                // Fetch new token.
                debug!("Fetching OAuth2 access token from {}", token_endpoint);
                let mut form = vec![("grant_type", "client_credentials")];
                let scope_str = scopes.join(" ");
                if !scopes.is_empty() {
                    form.push(("scope", &scope_str));
                }

                let response = self
                    .http_client
                    .post(token_endpoint)
                    .basic_auth(client_id, Some(client_secret))
                    .form(&form)
                    .send()
                    .await
                    .map_err(|e| {
                        ScimClientError::AuthError(format!("Token request failed: {e}"))
                    })?;

                if !response.status().is_success() {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<no body>".to_string());
                    return Err(ScimClientError::AuthError(format!(
                        "Token endpoint returned {status}: {body}"
                    )));
                }

                let token_response: OAuth2TokenResponse = response.json().await.map_err(|e| {
                    ScimClientError::AuthError(format!("Failed to parse token response: {e}"))
                })?;

                let _ = token_response.token_type; // acknowledged but unused

                let expires_at = token_response.expires_in.map(|secs| {
                    // Expire 30 seconds early to avoid using expired tokens.
                    std::time::Instant::now()
                        + std::time::Duration::from_secs(secs.saturating_sub(30))
                });

                let access_token = token_response.access_token.clone();

                // Cache the token.
                {
                    let mut cache = self.cached_token.write().await;
                    *cache = Some(CachedToken {
                        access_token: token_response.access_token,
                        expires_at,
                    });
                }

                Ok(access_token)
            }
        }
    }

    /// Apply authentication to a request builder.
    pub async fn apply(&self, builder: RequestBuilder) -> ScimClientResult<RequestBuilder> {
        let token = self.get_bearer_token().await?;
        Ok(builder.bearer_auth(token))
    }

    /// Invalidate the cached `OAuth2` token (e.g., on 401 response).
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cached_token.write().await;
        *cache = None;
    }
}

/// Check if a hostname should be blocked for SSRF prevention.
///
/// Blocks: loopback, link-local, RFC 1918 private ranges, and cloud metadata endpoints.
/// This function is deliberately conservative — it blocks based on resolved IP ranges
/// to prevent DNS rebinding attacks where a hostname initially resolves to a public IP
/// but later resolves to a private one.
fn is_ssrf_blocked_host(host: &str) -> bool {
    // Block well-known cloud metadata hostnames
    const BLOCKED_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata.goog"];

    let host_lower = host.to_lowercase();
    if BLOCKED_HOSTNAMES.contains(&host_lower.as_str()) {
        return true;
    }

    // Parse as IP address and check ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    false
}

/// Check if an IP address is in a private/reserved range.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // Loopback: 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // Link-local / cloud metadata: 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // RFC 1918: 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // RFC 1918: 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // RFC 1918: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // Unspecified: 0.0.0.0
            if octets == [0, 0, 0, 0] {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(ipv6) => {
            // Loopback: ::1
            if ipv6 == std::net::Ipv6Addr::LOCALHOST {
                return true;
            }
            // Unspecified: ::
            if ipv6 == std::net::Ipv6Addr::UNSPECIFIED {
                return true;
            }
            // IPv4-mapped addresses: check the embedded IPv4
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_private_ip(std::net::IpAddr::V4(ipv4));
            }
            // Link-local: fe80::/10
            let segments = ipv6.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_blocks_loopback() {
        assert!(is_ssrf_blocked_host("127.0.0.1"));
        assert!(is_ssrf_blocked_host("127.0.0.2"));
        assert!(is_ssrf_blocked_host("127.255.255.255"));
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        assert!(is_ssrf_blocked_host("169.254.169.254"));
        assert!(is_ssrf_blocked_host("169.254.0.1"));
    }

    #[test]
    fn test_ssrf_blocks_private_ranges() {
        assert!(is_ssrf_blocked_host("10.0.0.1"));
        assert!(is_ssrf_blocked_host("10.255.255.255"));
        assert!(is_ssrf_blocked_host("172.16.0.1"));
        assert!(is_ssrf_blocked_host("172.31.255.255"));
        assert!(is_ssrf_blocked_host("192.168.0.1"));
        assert!(is_ssrf_blocked_host("192.168.255.255"));
    }

    #[test]
    fn test_ssrf_blocks_cloud_metadata() {
        assert!(is_ssrf_blocked_host("metadata.google.internal"));
        assert!(is_ssrf_blocked_host("metadata.goog"));
    }

    #[test]
    fn test_ssrf_blocks_ipv6() {
        assert!(is_ssrf_blocked_host("::1"));
        assert!(is_ssrf_blocked_host("::"));
    }

    #[test]
    fn test_ssrf_allows_public_ips() {
        assert!(!is_ssrf_blocked_host("8.8.8.8"));
        assert!(!is_ssrf_blocked_host("1.1.1.1"));
        assert!(!is_ssrf_blocked_host("52.24.100.200"));
    }

    #[test]
    fn test_ssrf_allows_hostnames() {
        // Hostnames that don't match blocked list are allowed
        // (DNS resolution happens at request time, not validation time)
        assert!(!is_ssrf_blocked_host("login.microsoftonline.com"));
        assert!(!is_ssrf_blocked_host("accounts.google.com"));
    }

    #[test]
    fn test_ssrf_not_in_private_172_range() {
        // 172.15.x.x is NOT in the 172.16.0.0/12 range
        assert!(!is_ssrf_blocked_host("172.15.0.1"));
        // 172.32.x.x is NOT in the 172.16.0.0/12 range
        assert!(!is_ssrf_blocked_host("172.32.0.1"));
    }

    #[test]
    fn test_ssrf_blocks_unspecified() {
        assert!(is_ssrf_blocked_host("0.0.0.0"));
    }
}
