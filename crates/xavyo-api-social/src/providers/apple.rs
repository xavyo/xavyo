//! Apple Sign In provider implementation.
//!
//! Apple Sign In has unique requirements:
//! - Uses `form_post` response mode
//! - Client secret is a JWT signed with ES256
//! - User info is only provided on first authorization

use super::async_trait;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use moka::sync::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{SocialProvider, SocialUserInfo, TokenResponse};
use crate::error::{ProviderType, SocialError, SocialResult};

/// Cache key for Apple JWKS (only one endpoint).
const APPLE_JWKS_CACHE_KEY: &str = "apple_jwks";

/// JWKS cache TTL: 1 hour.
const JWKS_CACHE_TTL_SECS: u64 = 3600;

/// Apple `OAuth2` endpoints.
const AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";
/// Apple JWKS endpoint for ID token signature verification.
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
/// Apple issuer for token validation.
const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Client secret lifetime (1 day in seconds).
/// SECURITY: Use a short-lived client secret to limit exposure window if leaked.
/// Apple allows up to 6 months, but shorter lifetime reduces risk.
const CLIENT_SECRET_LIFETIME: u64 = 86400;

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
    /// OIDC nonce — deserialized for future use but validation is centralized in the callback handler.
    #[serde(default)]
    #[allow(dead_code)]
    nonce: Option<String>,
}

/// Apple JWKS response structure.
#[derive(Debug, Clone, Deserialize)]
struct AppleJwkSet {
    keys: Vec<AppleJwk>,
}

/// Individual JWK from Apple's JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
struct AppleJwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    /// RSA modulus (base64url encoded). Present for RSA keys.
    n: Option<String>,
    /// RSA exponent (base64url encoded). Present for RSA keys.
    e: Option<String>,
    /// EC curve name (e.g., "P-256"). Present for EC keys.
    #[allow(dead_code)]
    crv: Option<String>,
    /// EC X coordinate (base64url encoded). Present for EC keys.
    x: Option<String>,
    /// EC Y coordinate (base64url encoded). Present for EC keys.
    y: Option<String>,
}

/// Global JWKS cache shared across all AppleProvider instances.
///
/// SECURITY: AppleProvider is constructed per-request (via ProviderFactory), so a
/// per-instance cache would be recreated on every request and never hit.
/// Using a process-global static ensures the cache actually persists across requests.
fn apple_jwks_cache() -> &'static Cache<String, AppleJwkSet> {
    static CACHE: OnceLock<Cache<String, AppleJwkSet>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(1)
            .time_to_live(Duration::from_secs(JWKS_CACHE_TTL_SECS))
            .build()
    })
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
                message: format!("Invalid Apple private key: {e}"),
            }
        })?;

        Ok(Self {
            client_id,
            team_id,
            key_id,
            private_key: encoding_key,
            http_client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
        })
    }

    /// Generate a client secret JWT for Apple.
    fn generate_client_secret(&self) -> SocialResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SocialError::InternalError {
                message: format!("Time error: {e}"),
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

    /// Fetch Apple JWKS with response size cap to prevent OOM from malicious responses.
    async fn fetch_jwks_with_size_limit(&self) -> SocialResult<AppleJwkSet> {
        const MAX_JWKS_SIZE: usize = 512 * 1024; // 512 KB

        let response = self
            .http_client
            .get(APPLE_JWKS_URL)
            .send()
            .await
            .map_err(|e| SocialError::InternalError {
                message: format!("Failed to fetch Apple JWKS: {e}"),
            })?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| SocialError::InternalError {
                message: format!("Failed to read Apple JWKS response: {e}"),
            })?;

        if bytes.len() > MAX_JWKS_SIZE {
            return Err(SocialError::InternalError {
                message: format!(
                    "Apple JWKS response too large: {} bytes (max {MAX_JWKS_SIZE})",
                    bytes.len()
                ),
            });
        }

        serde_json::from_slice(&bytes).map_err(|e| SocialError::InternalError {
            message: format!("Failed to parse Apple JWKS: {e}"),
        })
    }

    /// Verify and decode the Apple ID token using Apple's JWKS public keys.
    ///
    /// Fetches Apple's public keys from their JWKS endpoint, finds the key
    /// matching the token's `kid` header, and verifies the RS256 signature.
    /// Also validates issuer and audience claims.
    ///
    /// If the `kid` is not found in the cached JWKS, this function will
    /// refresh the cache once and retry before failing.
    async fn verify_and_decode_id_token(&self, id_token: &str) -> SocialResult<AppleIdTokenClaims> {
        // Decode header to get the key ID (kid)
        let header =
            jsonwebtoken::decode_header(id_token).map_err(|e| SocialError::InvalidCallback {
                reason: format!("Failed to decode ID token header: {e}"),
            })?;

        let kid = header.kid.ok_or_else(|| SocialError::InvalidCallback {
            reason: "Apple ID token missing kid in header".to_string(),
        })?;

        // Check cache first; on miss, fetch from Apple and cache with TTL
        let jwks = if let Some(cached) = apple_jwks_cache().get(APPLE_JWKS_CACHE_KEY) {
            cached
        } else {
            let fetched: AppleJwkSet = self.fetch_jwks_with_size_limit().await?;
            apple_jwks_cache().insert(APPLE_JWKS_CACHE_KEY.to_string(), fetched.clone());
            fetched
        };

        // Try to find the matching key by kid. If not found, refresh JWKS once and retry.
        let jwk = if let Some(key) = jwks.keys.iter().find(|k| k.kid == kid) {
            key.clone()
        } else {
            // SECURITY: kid not found in cached JWKS. Clear cache and re-fetch once
            // to handle key rotation. This prevents failures when Apple rotates keys.
            tracing::info!(
                target: "social_auth",
                kid = %kid,
                "Apple JWKS kid not found in cache — refreshing JWKS and retrying"
            );
            apple_jwks_cache().invalidate(APPLE_JWKS_CACHE_KEY);

            // Re-fetch JWKS from Apple
            let refreshed: AppleJwkSet = self.fetch_jwks_with_size_limit().await?;

            // Retry finding the key in refreshed JWKS
            let key = refreshed.keys.iter().find(|k| k.kid == kid).ok_or_else(|| {
                SocialError::InvalidCallback {
                    reason: format!("No matching Apple public key found for kid '{kid}' (even after JWKS refresh)"),
                }
            })?.clone();

            // Cache the refreshed JWKS for future requests
            apple_jwks_cache().insert(APPLE_JWKS_CACHE_KEY.to_string(), refreshed);

            key
        };

        // Build decoding key and determine algorithm based on key type
        let (decoding_key, algorithm) = match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_ref().ok_or_else(|| SocialError::InternalError {
                    message: "Apple RSA JWK missing 'n' field".to_string(),
                })?;
                let e = jwk.e.as_ref().ok_or_else(|| SocialError::InternalError {
                    message: "Apple RSA JWK missing 'e' field".to_string(),
                })?;
                let key = DecodingKey::from_rsa_components(n, e).map_err(|e| {
                    SocialError::InternalError {
                        message: format!("Failed to build RSA decoding key from Apple JWK: {e}"),
                    }
                })?;
                let alg = match jwk.alg.as_deref() {
                    Some("RS384") => Algorithm::RS384,
                    Some("RS512") => Algorithm::RS512,
                    _ => Algorithm::RS256,
                };
                (key, alg)
            }
            "EC" => {
                let x = jwk.x.as_ref().ok_or_else(|| SocialError::InternalError {
                    message: "Apple EC JWK missing 'x' field".to_string(),
                })?;
                let y = jwk.y.as_ref().ok_or_else(|| SocialError::InternalError {
                    message: "Apple EC JWK missing 'y' field".to_string(),
                })?;
                let key = DecodingKey::from_ec_components(x, y).map_err(|e| {
                    SocialError::InternalError {
                        message: format!("Failed to build EC decoding key from Apple JWK: {e}"),
                    }
                })?;
                let alg = match jwk.alg.as_deref() {
                    Some("ES384") => Algorithm::ES384,
                    _ => Algorithm::ES256,
                };
                (key, alg)
            }
            other => {
                return Err(SocialError::InternalError {
                    message: format!("Unsupported Apple JWK key type: {other}"),
                });
            }
        };

        // Configure validation with detected algorithm, check issuer and audience
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[APPLE_ISSUER]);

        // Decode and verify the token
        let token_data = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| SocialError::InvalidCallback {
                reason: format!("Apple ID token verification failed: {e}"),
            })?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl SocialProvider for AppleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Apple
    }

    fn authorization_url(
        &self,
        state: &str,
        pkce_challenge: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> String {
        let scopes = self.default_scopes().join(" ");

        // Apple uses form_post response mode
        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&response_mode=form_post",
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

        let claims = self.verify_and_decode_id_token(id_token).await?;

        let email_verified = claims.email_verified.as_ref().is_some_and(|v| v == "true");

        let is_private_email = claims
            .is_private_email
            .as_ref()
            .is_some_and(|v| v == "true");

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
            None,
        );

        assert!(url.starts_with(AUTHORIZATION_ENDPOINT));
        assert!(url.contains("client_id=com.example.app"));
        assert!(url.contains("state=state-token"));
        assert!(url.contains("code_challenge=pkce-challenge"));
        assert!(url.contains("response_mode=form_post"));
        assert!(!url.contains("nonce="));
    }

    #[test]
    fn test_authorization_url_with_nonce() {
        let provider = test_provider();

        let url = provider.authorization_url(
            "state-token",
            "pkce-challenge",
            "https://example.com/callback",
            Some("my-nonce-value"),
        );

        assert!(url.contains("nonce=my-nonce-value"));
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
