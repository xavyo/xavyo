//! Microsoft (Azure AD) OAuth2/OIDC provider implementation.

use super::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{SocialProvider, SocialUserInfo, TokenResponse};
use crate::error::{ProviderType, SocialError, SocialResult};

/// Default Azure tenant (allows all Microsoft accounts).
const DEFAULT_TENANT: &str = "common";

/// Microsoft token response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MicrosoftTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
    token_type: String,
}

/// Microsoft userinfo response.
#[derive(Debug, Deserialize, serde::Serialize)]
struct MicrosoftUserInfo {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

/// Microsoft (Azure AD) `OAuth2` provider.
#[derive(Clone)]
pub struct MicrosoftProvider {
    client_id: String,
    client_secret: String,
    tenant: String,
    http_client: Client,
}

impl MicrosoftProvider {
    /// Create a new Microsoft provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Azure AD application client ID
    /// * `client_secret` - Azure AD application client secret
    /// * `tenant` - Azure tenant ID or "common"/"organizations"/"consumers"
    #[must_use] 
    pub fn new(client_id: String, client_secret: String, tenant: Option<String>) -> Self {
        Self {
            client_id,
            client_secret,
            tenant: tenant.unwrap_or_else(|| DEFAULT_TENANT.to_string()),
            http_client: Client::new(),
        }
    }

    /// Get the authorization endpoint URL.
    fn authorization_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            self.tenant
        )
    }

    /// Get the token endpoint URL.
    fn token_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        )
    }

    /// Get the userinfo endpoint URL.
    fn userinfo_endpoint(&self) -> String {
        "https://graph.microsoft.com/oidc/userinfo".to_string()
    }
}

#[async_trait]
impl SocialProvider for MicrosoftProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Microsoft
    }

    fn authorization_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        let scopes = self.default_scopes().join(" ");

        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&response_mode=query",
            self.authorization_endpoint(),
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> SocialResult<TokenResponse> {
        let scopes = self.default_scopes().join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("code_verifier", pkce_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
            ("scope", &scopes),
        ];

        let response = self
            .http_client
            .post(self.token_endpoint())
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(SocialError::TokenExchangeFailed {
                provider: ProviderType::Microsoft,
                status: status.as_u16(),
            });
        }

        let token_response: MicrosoftTokenResponse = response.json().await?;

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
            .get(self.userinfo_endpoint())
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialError::UserInfoFailed {
                provider: ProviderType::Microsoft,
            });
        }

        let user_info: MicrosoftUserInfo = response.json().await?;
        let raw_claims = serde_json::to_value(&user_info).unwrap_or_default();

        // Use preferred_username as email fallback
        let email = user_info.email.or(user_info.preferred_username);

        Ok(SocialUserInfo {
            provider_user_id: user_info.sub,
            email,
            email_verified: Some(true), // Microsoft verifies emails
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
            "offline_access".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_url_with_default_tenant() {
        let provider =
            MicrosoftProvider::new("client-id".to_string(), "client-secret".to_string(), None);

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
        );

        assert!(url.contains("login.microsoftonline.com/common"));
        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("state=state-token"));
        assert!(url.contains("code_challenge=pkce-challenge"));
    }

    #[test]
    fn test_authorization_url_with_custom_tenant() {
        let provider = MicrosoftProvider::new(
            "client-id".to_string(),
            "client-secret".to_string(),
            Some("my-tenant-id".to_string()),
        );

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
        );

        assert!(url.contains("login.microsoftonline.com/my-tenant-id"));
    }

    #[test]
    fn test_default_scopes() {
        let provider =
            MicrosoftProvider::new("client-id".to_string(), "client-secret".to_string(), None);
        let scopes = provider.default_scopes();

        assert!(scopes.contains(&"openid".to_string()));
        assert!(scopes.contains(&"email".to_string()));
        assert!(scopes.contains(&"profile".to_string()));
        assert!(scopes.contains(&"offline_access".to_string()));
    }

    #[test]
    fn test_provider_type() {
        let provider =
            MicrosoftProvider::new("client-id".to_string(), "client-secret".to_string(), None);
        assert_eq!(provider.provider_type(), ProviderType::Microsoft);
    }
}
