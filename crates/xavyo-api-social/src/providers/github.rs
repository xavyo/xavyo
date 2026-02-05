//! GitHub `OAuth2` provider implementation.

use super::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

use super::{SocialProvider, SocialUserInfo, TokenResponse};
use crate::error::{ProviderType, SocialError, SocialResult};

/// GitHub `OAuth2` endpoints.
const AUTHORIZATION_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
const USERINFO_ENDPOINT: &str = "https://api.github.com/user";
const USER_EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails";

/// GitHub token response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GithubTokenResponse {
    access_token: String,
    token_type: String,
    scope: Option<String>,
}

/// GitHub userinfo response.
#[derive(Debug, Deserialize, serde::Serialize)]
struct GithubUserInfo {
    id: i64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

/// GitHub email response (for getting verified primary email).
#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// GitHub `OAuth2` provider.
#[derive(Clone)]
pub struct GithubProvider {
    client_id: String,
    client_secret: String,
    http_client: Client,
}

impl GithubProvider {
    /// Create a new GitHub provider.
    #[must_use]
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http_client: Client::new(),
        }
    }

    /// Fetch the primary verified email from GitHub.
    async fn fetch_primary_email(
        &self,
        access_token: &str,
    ) -> SocialResult<Option<(String, bool)>> {
        let response = self
            .http_client
            .get(USER_EMAILS_ENDPOINT)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "xavyo")
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            // F116: Log the error instead of silently returning None
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            warn!(
                status = %status,
                error = %error_body,
                "GitHub emails endpoint failed - falling back to profile email"
            );
            return Ok(None);
        }

        let emails: Vec<GithubEmail> = response.json().await?;

        // Find primary verified email
        for email in &emails {
            if email.primary && email.verified {
                return Ok(Some((email.email.clone(), true)));
            }
        }

        // Fall back to any verified email
        for email in &emails {
            if email.verified {
                return Ok(Some((email.email.clone(), true)));
            }
        }

        // Fall back to primary email (may not be verified)
        for email in emails {
            if email.primary {
                return Ok(Some((email.email, false)));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl SocialProvider for GithubProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Github
    }

    fn authorization_url(&self, state: &str, _pkce_challenge: &str, redirect_uri: &str) -> String {
        let scopes = self.default_scopes().join(" ");

        // Note: GitHub doesn't support PKCE, so we ignore the challenge
        format!(
            "{}?client_id={}&redirect_uri={}&scope={}&state={}",
            AUTHORIZATION_ENDPOINT,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        _pkce_verifier: &str,
        redirect_uri: &str,
    ) -> SocialResult<TokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];

        let response = self
            .http_client
            .post(TOKEN_ENDPOINT)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SocialError::TokenExchangeFailed {
                provider: ProviderType::Github,
                status: status.as_u16(),
            });
        }

        let token_response: GithubTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: token_response.access_token,
            refresh_token: None, // GitHub doesn't return refresh tokens
            expires_in: None,    // GitHub tokens don't expire (unless revoked)
            id_token: None,      // GitHub is not OIDC
        })
    }

    async fn fetch_user_info(
        &self,
        access_token: &str,
        _id_token: Option<&str>,
    ) -> SocialResult<SocialUserInfo> {
        let response = self
            .http_client
            .get(USERINFO_ENDPOINT)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "xavyo")
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialError::UserInfoFailed {
                provider: ProviderType::Github,
            });
        }

        let user_info: GithubUserInfo = response.json().await?;
        let raw_claims = serde_json::to_value(&user_info).unwrap_or_default();

        // F116: Always fetch from emails endpoint to get actual verification status.
        // The email in the profile may not be verified, so we can't assume it is.
        let (email, email_verified) = match self.fetch_primary_email(access_token).await? {
            Some((email, verified)) => (Some(email), Some(verified)),
            None => {
                // Fall back to profile email if emails endpoint fails/returns nothing.
                // Mark as NOT verified since we couldn't confirm it.
                (user_info.email.clone(), Some(false))
            }
        };

        // F116: Use GitHub username (login) as fallback when name is not set.
        // This provides a more meaningful display name than the numeric ID.
        let name = user_info.name.or_else(|| Some(user_info.login.clone()));

        Ok(SocialUserInfo {
            provider_user_id: user_info.id.to_string(),
            email,
            email_verified,
            name,
            given_name: None, // GitHub doesn't split names
            family_name: None,
            picture: user_info.avatar_url,
            is_private_email: false,
            raw_claims,
        })
    }

    fn default_scopes(&self) -> Vec<String> {
        vec!["read:user".to_string(), "user:email".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_url() {
        let provider = GithubProvider::new("client-id".to_string(), "client-secret".to_string());

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge", // Ignored for GitHub
            "https://example.com/callback",
        );

        assert!(url.starts_with(AUTHORIZATION_ENDPOINT));
        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("state=state-token"));
        assert!(url.contains("scope=read%3Auser")); // read:user URL encoded
    }

    #[test]
    fn test_default_scopes() {
        let provider = GithubProvider::new("client-id".to_string(), "client-secret".to_string());
        let scopes = provider.default_scopes();

        assert!(scopes.contains(&"read:user".to_string()));
        assert!(scopes.contains(&"user:email".to_string()));
    }

    #[test]
    fn test_provider_type() {
        let provider = GithubProvider::new("client-id".to_string(), "client-secret".to_string());
        assert_eq!(provider.provider_type(), ProviderType::Github);
    }
}
