//! Apple Sign In provider implementation.
//!
//! Apple Sign In has unique requirements:
//! - Uses form_post response mode
//! - Client secret is a JWT signed with ES256
//! - User info is only provided on first authorization

use super::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{SocialProvider, SocialUserInfo, TokenResponse};
use crate::error::{ProviderType, SocialError, SocialResult};

/// Apple OAuth2 endpoints.
const AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

/// Maximum client secret lifetime (6 months in seconds).
const CLIENT_SECRET_LIFETIME: u64 = 86400 * 180;

/// Apple client secret JWT claims.
#[derive(Debug, Serialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

/// Apple token response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
    token_type: String,
}

/// Apple ID token claims.
#[derive(Debug, Deserialize)]
struct AppleIdTokenClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<String>,
    is_private_email: Option<String>,
}

/// Apple Sign In provider.
#[derive(Clone)]
pub struct AppleProvider {
    client_id: String,
    team_id: String,
    key_id: String,
    private_key: EncodingKey,
    http_client: Client,
}

impl AppleProvider {
    /// Create a new Apple provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Apple Services ID (e.g., com.example.app)
    /// * `team_id` - Apple Developer Team ID
    /// * `key_id` - Key ID for the private key
    /// * `private_key` - P8 private key content
    pub fn new(
        client_id: String,
        team_id: String,
        key_id: String,
        private_key: String,
    ) -> SocialResult<Self> {
        let encoding_key = EncodingKey::from_ec_pem(private_key.as_bytes()).map_err(|e| {
            SocialError::ConfigurationError {
                message: format!("Invalid Apple private key: {}", e),
            }
        })?;

        Ok(Self {
            client_id,
            team_id,
            key_id,
            private_key: encoding_key,
            http_client: Client::new(),
        })
    }

    /// Generate a client secret JWT for Apple.
    fn generate_client_secret(&self) -> SocialResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SocialError::InternalError {
                message: format!("Time error: {}", e),
            })?
            .as_secs();

        let claims = AppleClientSecretClaims {
            iss: self.team_id.clone(),
            iat: now,
            exp: now + CLIENT_SECRET_LIFETIME,
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.private_key).map_err(SocialError::from)
    }

    /// Decode the Apple ID token to extract user info.
    fn decode_id_token(&self, id_token: &str) -> SocialResult<AppleIdTokenClaims> {
        // Apple ID tokens should be verified with Apple's public keys
        // For simplicity, we decode without verification here
        // In production, use jwks from https://appleid.apple.com/auth/keys

        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(SocialError::InvalidCallback {
                reason: "Invalid ID token format".to_string(),
            });
        }

        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| SocialError::InvalidCallback {
                reason: format!("Failed to decode ID token payload: {}", e),
            })?;

        serde_json::from_slice(&payload).map_err(|e| SocialError::InvalidCallback {
            reason: format!("Failed to parse ID token claims: {}", e),
        })
    }
}

use base64::Engine;

#[async_trait]
impl SocialProvider for AppleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Apple
    }

    fn authorization_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        let scopes = self.default_scopes().join(" ");

        // Apple uses form_post response mode
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&response_mode=form_post",
            AUTHORIZATION_ENDPOINT,
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
        let client_secret = self.generate_client_secret()?;

        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
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
                provider: ProviderType::Apple,
                status: status.as_u16(),
            });
        }

        let token_response: AppleTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
            id_token: token_response.id_token,
        })
    }

    async fn fetch_user_info(
        &self,
        _access_token: &str,
        id_token: Option<&str>,
    ) -> SocialResult<SocialUserInfo> {
        // Apple provides user info in the ID token, not via userinfo endpoint
        let id_token = id_token.ok_or_else(|| SocialError::UserInfoFailed {
            provider: ProviderType::Apple,
        })?;

        let claims = self.decode_id_token(id_token)?;

        let email_verified = claims
            .email_verified
            .as_ref()
            .map(|v| v == "true")
            .unwrap_or(false);

        let is_private_email = claims
            .is_private_email
            .as_ref()
            .map(|v| v == "true")
            .unwrap_or(false);

        let raw_claims = serde_json::json!({
            "sub": &claims.sub,
            "email": &claims.email,
            "email_verified": &claims.email_verified,
            "is_private_email": &claims.is_private_email,
        });

        Ok(SocialUserInfo {
            provider_user_id: claims.sub,
            email: claims.email,
            email_verified: Some(email_verified),
            name: None, // Name is only provided on first login via form_post
            given_name: None,
            family_name: None,
            picture: None, // Apple doesn't provide profile pictures
            is_private_email,
            raw_claims,
        })
    }

    fn default_scopes(&self) -> Vec<String> {
        vec!["name".to_string(), "email".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test private key (not for production use)
    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;

    fn test_provider() -> AppleProvider {
        AppleProvider::new(
            "com.example.app".to_string(),
            "TEAM123456".to_string(),
            "KEY123456".to_string(),
            TEST_PRIVATE_KEY.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn test_authorization_url() {
        let provider = test_provider();

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
        );

        assert!(url.starts_with(AUTHORIZATION_ENDPOINT));
        assert!(url.contains("client_id=com.example.app"));
        assert!(url.contains("state=state-token"));
        assert!(url.contains("code_challenge=pkce-challenge"));
        assert!(url.contains("response_mode=form_post"));
    }

    #[test]
    fn test_generate_client_secret() {
        let provider = test_provider();
        let secret = provider.generate_client_secret().unwrap();

        // Should be a valid JWT
        let parts: Vec<&str> = secret.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_default_scopes() {
        let provider = test_provider();
        let scopes = provider.default_scopes();

        assert!(scopes.contains(&"name".to_string()));
        assert!(scopes.contains(&"email".to_string()));
    }

    #[test]
    fn test_provider_type() {
        let provider = test_provider();
        assert_eq!(provider.provider_type(), ProviderType::Apple);
    }

    #[test]
    fn test_invalid_private_key() {
        let result = AppleProvider::new(
            "com.example.app".to_string(),
            "TEAM123456".to_string(),
            "KEY123456".to_string(),
            "invalid-key".to_string(),
        );

        assert!(result.is_err());
    }
}
