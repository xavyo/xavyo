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
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
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

        // Use preferred_username as email fallback only with strict validation.
        // When falling back to preferred_username, always mark email_verified = false
        // because Microsoft does not guarantee it is a verified email address.
        let (email, email_verified) = if let Some(email) = user_info.email {
            (Some(email), Some(true)) // Microsoft verifies primary emails
        } else if let Some(ref preferred) = user_info.preferred_username {
            // Validate with a basic RFC 5322-ish pattern: local@domain.tld
            // Must have exactly one @, domain must have a dot, no spaces
            if is_plausible_email(preferred) {
                (Some(preferred.clone()), Some(false)) // explicitly unverified
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(SocialUserInfo {
            provider_user_id: user_info.sub,
            email,
            email_verified,
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

/// Basic email format validation for `preferred_username` fallback.
///
/// Checks: non-empty local part, exactly one `@`, domain has at least one dot,
/// no whitespace, and reasonable length bounds.
fn is_plausible_email(s: &str) -> bool {
    // Length bounds: at least a@b.c (5 chars), max 254 per RFC 5321
    if s.len() < 5 || s.len() > 254 {
        return false;
    }
    // No whitespace
    if s.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    // Exactly one @
    let parts: Vec<&str> = s.splitn(3, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    // Local part must be non-empty
    if local.is_empty() {
        return false;
    }
    // Domain must contain a dot and not start/end with one
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_plausible_email() {
        assert!(is_plausible_email("user@example.com"));
        assert!(is_plausible_email("a@b.co"));
        assert!(!is_plausible_email("not-an-email"));
        assert!(!is_plausible_email("@example.com"));
        assert!(!is_plausible_email("user@"));
        assert!(!is_plausible_email("user@domain"));
        assert!(!is_plausible_email("user @example.com"));
        assert!(!is_plausible_email("user@@example.com"));
        assert!(!is_plausible_email("user@.com"));
        assert!(!is_plausible_email("user@com."));
        assert!(!is_plausible_email(""));
        assert!(!is_plausible_email("ab"));
    }

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
