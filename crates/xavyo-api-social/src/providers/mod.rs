//! Social provider implementations.
//!
//! This module provides OAuth2/OIDC implementations for Google, Microsoft, Apple, and GitHub.

pub mod apple;
pub mod github;
pub mod google;
pub mod microsoft;

pub use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderType, SocialResult};

/// Token response from a social provider.
#[derive(Debug, Clone)]
pub struct TokenResponse {
    /// Access token for API calls.
    pub access_token: String,
    /// Refresh token for obtaining new access tokens.
    pub refresh_token: Option<String>,
    /// Token expiration in seconds.
    pub expires_in: Option<i64>,
    /// ID token (OIDC providers).
    pub id_token: Option<String>,
}

/// User information from a social provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserInfo {
    /// Unique identifier from the provider (sub claim).
    pub provider_user_id: String,
    /// User's email address.
    pub email: Option<String>,
    /// Whether the email is verified.
    pub email_verified: Option<bool>,
    /// User's display name.
    pub name: Option<String>,
    /// User's first name.
    pub given_name: Option<String>,
    /// User's last name.
    pub family_name: Option<String>,
    /// Profile picture URL.
    pub picture: Option<String>,
    /// Whether the email is a private relay (Apple).
    pub is_private_email: bool,
    /// Raw claims for debugging.
    pub raw_claims: serde_json::Value,
}

impl SocialUserInfo {
    /// Get the display name, falling back to email or provider ID.
    #[must_use] 
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| match (&self.given_name, &self.family_name) {
                (Some(given), Some(family)) => Some(format!("{given} {family}")),
                (Some(given), None) => Some(given.clone()),
                (None, Some(family)) => Some(family.clone()),
                _ => None,
            })
            .or_else(|| self.email.clone())
            .unwrap_or_else(|| self.provider_user_id.clone())
    }
}

/// Trait for social provider implementations.
#[async_trait]
pub trait SocialProvider: Send + Sync {
    /// Get the provider type.
    fn provider_type(&self) -> ProviderType;

    /// Get the authorization URL for initiating the OAuth flow.
    ///
    /// # Arguments
    ///
    /// * `state` - CSRF protection state parameter
    /// * `pkce_challenge` - PKCE code challenge (S256)
    /// * `redirect_uri` - Callback URL
    fn authorization_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String;

    /// Exchange an authorization code for tokens.
    ///
    /// # Arguments
    ///
    /// * `code` - Authorization code from the callback
    /// * `pkce_verifier` - PKCE code verifier
    /// * `redirect_uri` - Callback URL (must match authorization request)
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> SocialResult<TokenResponse>;

    /// Fetch user information using an access token.
    ///
    /// For OIDC providers, this may decode the ID token instead of calling userinfo.
    async fn fetch_user_info(
        &self,
        access_token: &str,
        id_token: Option<&str>,
    ) -> SocialResult<SocialUserInfo>;

    /// Get the default scopes for this provider.
    fn default_scopes(&self) -> Vec<String>;
}

/// Provider factory for creating provider instances from configuration.
pub struct ProviderFactory;

impl ProviderFactory {
    /// Create a Google provider.
    #[must_use] 
    pub fn google(client_id: String, client_secret: String) -> google::GoogleProvider {
        google::GoogleProvider::new(client_id, client_secret)
    }

    /// Create a Microsoft provider.
    #[must_use] 
    pub fn microsoft(
        client_id: String,
        client_secret: String,
        azure_tenant: Option<String>,
    ) -> microsoft::MicrosoftProvider {
        microsoft::MicrosoftProvider::new(client_id, client_secret, azure_tenant)
    }

    /// Create an Apple provider.
    pub fn apple(
        client_id: String,
        team_id: String,
        key_id: String,
        private_key: String,
    ) -> SocialResult<apple::AppleProvider> {
        apple::AppleProvider::new(client_id, team_id, key_id, private_key)
    }

    /// Create a GitHub provider.
    #[must_use] 
    pub fn github(client_id: String, client_secret: String) -> github::GithubProvider {
        github::GithubProvider::new(client_id, client_secret)
    }
}

// Re-export providers
pub use apple::AppleProvider;
pub use github::GithubProvider;
pub use google::GoogleProvider;
pub use microsoft::MicrosoftProvider;
