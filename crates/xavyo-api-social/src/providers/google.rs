//! Google OAuth2/OIDC provider implementation.

use super::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{SocialProvider, SocialUserInfo, TokenResponse};
use crate::error::{ProviderType, SocialError, SocialResult};

/// Google `OAuth2` endpoints.
const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Google token response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GoogleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
    token_type: String,
}

/// Google userinfo response.
#[derive(Debug, Deserialize, serde::Serialize)]
struct GoogleUserInfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

/// Google `OAuth2` provider.
#[derive(Clone)]
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    http_client: Client,
}

impl GoogleProvider {
    /// Create a new Google provider.
    #[must_use]
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

#[async_trait]
impl SocialProvider for GoogleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Google
    }

    fn authorization_url(
        &self,
        state: &str,
        pkce_challenge: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> String {
        let scopes = self.default_scopes().join(" ");

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent",
            AUTHORIZATION_ENDPOINT,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        );

        if let Some(nonce) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
        }

        url
    }

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> SocialResult<TokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("code_verifier", pkce_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];

        let response = self
            .http_client
            .post(TOKEN_ENDPOINT)
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SocialError::TokenExchangeFailed {
                provider: ProviderType::Google,
                status: status.as_u16(),
            });
        }

        let token_response: GoogleTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
            id_token: token_response.id_token,
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
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialError::UserInfoFailed {
                provider: ProviderType::Google,
            });
        }

        let user_info: GoogleUserInfo = response.json().await?;
        let raw_claims = serde_json::to_value(&user_info).unwrap_or_default();

        Ok(SocialUserInfo {
            provider_user_id: user_info.sub,
            email: user_info.email,
            email_verified: user_info.email_verified,
            name: user_info.name,
            given_name: user_info.given_name,
            family_name: user_info.family_name,
            picture: user_info.picture,
            is_private_email: false,
            raw_claims,
        })
    }

    fn default_scopes(&self) -> Vec<String> {
        vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_url() {
        let provider = GoogleProvider::new("client-id".to_string(), "client-secret".to_string());

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
            None,
        );

        assert!(url.starts_with(AUTHORIZATION_ENDPOINT));
        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("state=state-token"));
        assert!(url.contains("code_challenge=pkce-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("access_type=offline"));
        assert!(!url.contains("nonce="));
    }

    #[test]
    fn test_authorization_url_with_nonce() {
        let provider = GoogleProvider::new("client-id".to_string(), "client-secret".to_string());

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
            Some("my-nonce-value"),
        );

        assert!(url.contains("nonce=my-nonce-value"));
    }

    #[test]
    fn test_default_scopes() {
        let provider = GoogleProvider::new("client-id".to_string(), "client-secret".to_string());
        let scopes = provider.default_scopes();

        assert!(scopes.contains(&"openid".to_string()));
        assert!(scopes.contains(&"email".to_string()));
        assert!(scopes.contains(&"profile".to_string()));
    }

    #[test]
    fn test_provider_type() {
        let provider = GoogleProvider::new("client-id".to_string(), "client-secret".to_string());
        assert_eq!(provider.provider_type(), ProviderType::Google);
    }
}
