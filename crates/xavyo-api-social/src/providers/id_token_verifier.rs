//! Defense-in-depth ID token verification for Google and Microsoft OIDC providers.
//!
//! Fetches JWKS from the provider, verifies the ID token signature, and validates
//! standard claims (issuer, audience, expiry). Cross-checks the verified `sub` against
//! the userinfo `sub` to detect token substitution attacks.
//!
//! Apple already performs JWKS-based verification in its provider implementation.
//! GitHub does not issue ID tokens.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::sync::Cache;
use reqwest::Client;
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::info;
use url::Url;

use crate::error::{ProviderType, SocialError};

/// Maximum JWKS response size (512 KB) to prevent OOM from malicious responses.
const MAX_JWKS_SIZE: usize = 512 * 1024;

/// JWKS cache TTL: 10 minutes.
const JWKS_CACHE_TTL_SECS: u64 = 600;

/// Maximum number of cached JWKS entries (one per provider endpoint).
const JWKS_CACHE_MAX_CAPACITY: u64 = 4;

/// HTTP client timeout for JWKS fetches.
const JWKS_FETCH_TIMEOUT_SECS: u64 = 10;

/// Clock skew leeway for token expiry validation (60 seconds).
const LEEWAY_SECS: u64 = 60;

/// Allowed JWKS host domains (SSRF protection).
/// Only these domains are permitted for JWKS fetches since we know exactly
/// which IdPs we're talking to.
const ALLOWED_JWKS_HOSTS: &[&str] = &[
    "www.googleapis.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
];

/// OIDC ID token claims for Google/Microsoft.
#[derive(Debug, Deserialize)]
pub struct OidcIdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: StringOrArray,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Handles `aud` being either a single string or an array of strings.
/// Google returns a string; Microsoft may return an array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrArray {
    /// Check if the audience contains a specific value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            StringOrArray::Single(s) => s == value,
            StringOrArray::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

/// JWKS response structure (standard RFC 7517).
#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Individual JWK from a JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    /// RSA modulus (base64url encoded).
    n: Option<String>,
    /// RSA exponent (base64url encoded).
    e: Option<String>,
    /// EC X coordinate (base64url encoded).
    x: Option<String>,
    /// EC Y coordinate (base64url encoded).
    y: Option<String>,
}

/// Global JWKS cache shared across requests.
///
/// Providers are constructed per-request via ProviderFactory, so a per-instance
/// cache would never hit. A process-global static cache persists across requests.
fn jwks_cache() -> &'static Cache<String, JwkSet> {
    static CACHE: OnceLock<Cache<String, JwkSet>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(JWKS_CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(JWKS_CACHE_TTL_SECS))
            .build()
    })
}

/// Defense-in-depth ID token verifier for OIDC social providers.
///
/// Verifies ID token signatures using provider JWKS endpoints.
/// Constructed once and stored in `SocialState`.
#[derive(Clone)]
pub struct IdTokenVerifier {
    http_client: Client,
}

impl Default for IdTokenVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl IdTokenVerifier {
    /// Create a new ID token verifier with a dedicated HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(JWKS_FETCH_TIMEOUT_SECS))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Verify an ID token's signature, issuer, audience, and expiry.
    ///
    /// Returns the verified claims on success. On JWKS fetch failure, returns
    /// `JwksFetchFailed` (callers should warn and continue). On signature/claim
    /// failures, returns `IdTokenVerificationFailed` (callers should block).
    pub async fn verify(
        &self,
        token: &str,
        jwks_uri: &str,
        expected_issuer: &str,
        expected_audience: &str,
    ) -> Result<OidcIdTokenClaims, SocialError> {
        // SSRF protection: only allow known JWKS hosts
        self.validate_jwks_uri(jwks_uri)?;

        // Decode header to get kid
        let header = decode_header(token).map_err(|e| SocialError::IdTokenVerificationFailed {
            provider: self.provider_from_issuer(expected_issuer),
            reason: format!("Failed to decode ID token header: {e}"),
        })?;

        let kid = header
            .kid
            .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                provider: self.provider_from_issuer(expected_issuer),
                reason: "ID token missing kid in header".to_string(),
            })?;

        // Fetch JWKS (from cache or network)
        let jwks = self.get_jwks(jwks_uri).await?;

        // Find matching key by kid; if not found, force-refresh for key rotation
        let jwk = if let Some(key) = jwks.keys.iter().find(|k| k.kid.as_deref() == Some(&kid)) {
            key.clone()
        } else {
            info!(
                kid = %kid,
                jwks_uri = %jwks_uri,
                "JWKS kid not found in cache — refreshing for key rotation"
            );
            jwks_cache().invalidate(jwks_uri);

            let refreshed = self.fetch_jwks(jwks_uri).await?;
            let key = refreshed
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(&kid))
                .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                    provider: self.provider_from_issuer(expected_issuer),
                    reason: format!(
                        "No matching public key found for kid '{kid}' (even after JWKS refresh)"
                    ),
                })?
                .clone();
            jwks_cache().insert(jwks_uri.to_string(), refreshed);
            key
        };

        // Determine algorithm from JWK (never from JWT header — prevents algorithm confusion)
        let (decoding_key, algorithm) = self.build_decoding_key(&jwk, expected_issuer)?;

        // Configure validation
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[expected_issuer]);
        validation.leeway = LEEWAY_SECS;

        // Decode and verify
        let token_data =
            decode::<OidcIdTokenClaims>(token, &decoding_key, &validation).map_err(|e| {
                SocialError::IdTokenVerificationFailed {
                    provider: self.provider_from_issuer(expected_issuer),
                    reason: format!("Signature or claims validation failed: {e}"),
                }
            })?;

        Ok(token_data.claims)
    }

    /// Validate that the JWKS URI points to an allowed domain.
    fn validate_jwks_uri(&self, jwks_uri: &str) -> Result<(), SocialError> {
        let url = Url::parse(jwks_uri).map_err(|_| SocialError::IdTokenVerificationFailed {
            provider: ProviderType::Google, // generic fallback
            reason: "Invalid JWKS URI".to_string(),
        })?;

        if url.scheme() != "https" {
            return Err(SocialError::IdTokenVerificationFailed {
                provider: ProviderType::Google,
                reason: "JWKS URI must use HTTPS".to_string(),
            });
        }

        let host = url.host_str().unwrap_or("");
        if !ALLOWED_JWKS_HOSTS.contains(&host) {
            return Err(SocialError::IdTokenVerificationFailed {
                provider: ProviderType::Google,
                reason: format!("JWKS host '{host}' not in allowlist"),
            });
        }

        Ok(())
    }

    /// Get JWKS from cache or fetch from network.
    async fn get_jwks(&self, jwks_uri: &str) -> Result<JwkSet, SocialError> {
        if let Some(cached) = jwks_cache().get(jwks_uri) {
            return Ok(cached);
        }
        let fetched = self.fetch_jwks(jwks_uri).await?;
        jwks_cache().insert(jwks_uri.to_string(), fetched.clone());
        Ok(fetched)
    }

    /// Fetch JWKS from the provider with size limit.
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, SocialError> {
        let provider = self.provider_from_uri(jwks_uri);

        let response = self.http_client.get(jwks_uri).send().await.map_err(|e| {
            SocialError::JwksFetchFailed {
                provider,
                reason: format!("HTTP request failed: {e}"),
            }
        })?;

        if !response.status().is_success() {
            return Err(SocialError::JwksFetchFailed {
                provider,
                reason: format!("HTTP {}", response.status()),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| SocialError::JwksFetchFailed {
                provider,
                reason: format!("Failed to read response: {e}"),
            })?;

        if bytes.len() > MAX_JWKS_SIZE {
            return Err(SocialError::JwksFetchFailed {
                provider,
                reason: format!(
                    "Response too large: {} bytes (max {MAX_JWKS_SIZE})",
                    bytes.len()
                ),
            });
        }

        serde_json::from_slice(&bytes).map_err(|e| SocialError::JwksFetchFailed {
            provider,
            reason: format!("Failed to parse JWKS: {e}"),
        })
    }

    /// Build a decoding key and algorithm from a JWK.
    ///
    /// Algorithm is determined from the JWK's `alg` field, not the JWT header,
    /// to prevent algorithm confusion attacks.
    fn build_decoding_key(
        &self,
        jwk: &Jwk,
        expected_issuer: &str,
    ) -> Result<(DecodingKey, Algorithm), SocialError> {
        let provider = self.provider_from_issuer(expected_issuer);

        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: "RSA JWK missing 'n' field".to_string(),
                    })?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: "RSA JWK missing 'e' field".to_string(),
                    })?;
                let key = DecodingKey::from_rsa_components(n, e).map_err(|e| {
                    SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: format!("Failed to build RSA decoding key: {e}"),
                    }
                })?;
                let alg = match jwk.alg.as_deref() {
                    Some("RS384") => Algorithm::RS384,
                    Some("RS512") => Algorithm::RS512,
                    _ => Algorithm::RS256, // Google and Microsoft both use RS256
                };
                Ok((key, alg))
            }
            "EC" => {
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: "EC JWK missing 'x' field".to_string(),
                    })?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: "EC JWK missing 'y' field".to_string(),
                    })?;
                let key = DecodingKey::from_ec_components(x, y).map_err(|e| {
                    SocialError::IdTokenVerificationFailed {
                        provider,
                        reason: format!("Failed to build EC decoding key: {e}"),
                    }
                })?;
                let alg = match jwk.alg.as_deref() {
                    Some("ES384") => Algorithm::ES384,
                    _ => Algorithm::ES256,
                };
                Ok((key, alg))
            }
            other => Err(SocialError::IdTokenVerificationFailed {
                provider,
                reason: format!("Unsupported JWK key type: {other}"),
            }),
        }
    }

    /// Infer provider type from issuer URL (for error messages).
    fn provider_from_issuer(&self, issuer: &str) -> ProviderType {
        if issuer.contains("google") {
            ProviderType::Google
        } else if issuer.contains("apple") {
            ProviderType::Apple
        } else {
            ProviderType::Microsoft
        }
    }

    /// Infer provider type from JWKS URI (for error messages).
    fn provider_from_uri(&self, uri: &str) -> ProviderType {
        if uri.contains("googleapis.com") {
            ProviderType::Google
        } else if uri.contains("apple.com") {
            ProviderType::Apple
        } else {
            ProviderType::Microsoft
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_or_array_single() {
        let s: StringOrArray = serde_json::from_str(r#""my-client-id""#).unwrap();
        assert!(s.contains("my-client-id"));
        assert!(!s.contains("other"));
    }

    #[test]
    fn test_string_or_array_multiple() {
        let s: StringOrArray =
            serde_json::from_str(r#"["my-client-id", "another-client"]"#).unwrap();
        assert!(s.contains("my-client-id"));
        assert!(s.contains("another-client"));
        assert!(!s.contains("not-present"));
    }

    #[test]
    fn test_validate_jwks_uri_allowed() {
        let verifier = IdTokenVerifier::new();
        assert!(verifier
            .validate_jwks_uri("https://www.googleapis.com/oauth2/v3/certs")
            .is_ok());
        assert!(verifier
            .validate_jwks_uri("https://login.microsoftonline.com/common/discovery/v2.0/keys")
            .is_ok());
        assert!(verifier
            .validate_jwks_uri("https://appleid.apple.com/auth/keys")
            .is_ok());
    }

    #[test]
    fn test_validate_jwks_uri_blocked() {
        let verifier = IdTokenVerifier::new();
        assert!(verifier
            .validate_jwks_uri("https://evil.example.com/jwks")
            .is_err());
        assert!(verifier
            .validate_jwks_uri("http://www.googleapis.com/oauth2/v3/certs")
            .is_err()); // HTTP not allowed
    }

    #[test]
    fn test_provider_from_issuer() {
        let verifier = IdTokenVerifier::new();
        assert_eq!(
            verifier.provider_from_issuer("https://accounts.google.com"),
            ProviderType::Google
        );
        assert_eq!(
            verifier.provider_from_issuer("https://login.microsoftonline.com/common/v2.0"),
            ProviderType::Microsoft
        );
        assert_eq!(
            verifier.provider_from_issuer("https://appleid.apple.com"),
            ProviderType::Apple
        );
    }

    #[test]
    fn test_provider_from_uri() {
        let verifier = IdTokenVerifier::new();
        assert_eq!(
            verifier.provider_from_uri("https://www.googleapis.com/oauth2/v3/certs"),
            ProviderType::Google
        );
        assert_eq!(
            verifier
                .provider_from_uri("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
            ProviderType::Microsoft
        );
        assert_eq!(
            verifier.provider_from_uri("https://appleid.apple.com/auth/keys"),
            ProviderType::Apple
        );
    }

    #[test]
    fn test_oidc_claims_deserialization() {
        let json = r#"{
            "sub": "12345",
            "iss": "https://accounts.google.com",
            "aud": "my-client-id",
            "exp": 1700000000,
            "iat": 1699999000,
            "email": "user@example.com",
            "email_verified": true
        }"#;
        let claims: OidcIdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "12345");
        assert!(claims.aud.contains("my-client-id"));
        assert_eq!(claims.email, Some("user@example.com".to_string()));
        assert_eq!(claims.email_verified, Some(true));
    }
}
