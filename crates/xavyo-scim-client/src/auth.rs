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
}

impl ScimAuth {
    /// Create a new auth handler from decrypted credentials.
    #[must_use]
    pub fn new(credentials: ScimCredentials, http_client: reqwest::Client) -> Self {
        Self {
            credentials,
            cached_token: Arc::new(RwLock::new(None)),
            http_client,
        }
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
