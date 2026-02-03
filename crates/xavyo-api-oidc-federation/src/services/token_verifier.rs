//! Token verification service for validating federated IdP tokens.
//!
//! This service verifies JWT tokens from federated Identity Providers using
//! JWKS (JSON Web Key Sets) for signature verification.

use crate::error::{FederationError, FederationResult};
use crate::services::jwks_cache::JwksCache;
use tracing::{debug, info, instrument, warn};
use xavyo_auth::{decode_token_with_config, JwtClaims, ValidationConfig};

/// Configuration for token verification.
#[derive(Clone)]
pub struct VerificationConfig {
    /// Clock skew tolerance in seconds (default: 300 = 5 minutes).
    pub clock_skew_tolerance: u64,
    /// Expected issuer (optional - if set, tokens with different issuer are rejected).
    pub expected_issuer: Option<String>,
    /// Expected audience (optional - if set, tokens without matching audience are rejected).
    pub expected_audience: Option<Vec<String>>,
    /// Whether to validate expiration (default: true).
    pub validate_exp: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            clock_skew_tolerance: 300, // 5 minutes
            expected_issuer: None,
            expected_audience: None,
            validate_exp: true,
        }
    }
}

impl VerificationConfig {
    /// Create a new verification config with custom clock skew tolerance.
    pub fn with_clock_skew(tolerance_secs: u64) -> Self {
        Self {
            clock_skew_tolerance: tolerance_secs,
            ..Default::default()
        }
    }

    /// Set the expected issuer.
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.expected_issuer = Some(iss.into());
        self
    }

    /// Set the expected audience.
    pub fn audience(mut self, aud: Vec<impl Into<String>>) -> Self {
        self.expected_audience = Some(aud.into_iter().map(Into::into).collect());
        self
    }

    /// Disable expiration validation (use with caution).
    pub fn skip_exp_validation(mut self) -> Self {
        self.validate_exp = false;
        self
    }
}

/// Result of successful token verification.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// Validated claims from the token.
    pub claims: JwtClaims,
    /// Key ID used for verification (if present in token header).
    pub kid: Option<String>,
    /// Issuer from the token.
    pub issuer: String,
}

/// Token verification service.
///
/// Verifies JWT tokens from federated IdPs using JWKS-based signature verification.
#[derive(Clone)]
pub struct TokenVerifierService {
    jwks_cache: JwksCache,
    config: VerificationConfig,
}

impl TokenVerifierService {
    /// Create a new token verifier with default configuration.
    pub fn new(config: VerificationConfig) -> Self {
        Self {
            jwks_cache: JwksCache::default(),
            config,
        }
    }

    /// Create a new token verifier with custom JWKS cache.
    pub fn with_cache(config: VerificationConfig, jwks_cache: JwksCache) -> Self {
        Self { jwks_cache, config }
    }

    /// Verify a JWT token using the IdP's JWKS.
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token string to verify
    /// * `jwks_uri` - The JWKS endpoint URI for the IdP
    ///
    /// # Returns
    ///
    /// Verified token containing the validated claims.
    ///
    /// # Errors
    ///
    /// - `TokenVerificationFailed` - Signature verification failed
    /// - `TokenExpired` - Token has expired
    /// - `InvalidIssuer` - Issuer doesn't match expected value
    /// - `JwksFetchFailed` - Could not retrieve JWKS
    /// - `JwksKeyNotFound` - No matching key for token's kid
    #[instrument(skip(self, token))]
    pub async fn verify_token(
        &self,
        token: &str,
        jwks_uri: &str,
    ) -> FederationResult<VerifiedToken> {
        // Extract kid from token header
        let kid = xavyo_auth::extract_kid(token)
            .map_err(|e| FederationError::TokenVerificationFailed(e.to_string()))?;

        debug!(kid = ?kid, jwks_uri = %jwks_uri, "Verifying token");

        // Find the signing key
        let jwk = self
            .jwks_cache
            .find_signing_key(jwks_uri, kid.as_deref())
            .await?
            .ok_or_else(|| {
                FederationError::JwksKeyNotFound(
                    kid.clone().unwrap_or_else(|| "no kid".to_string()),
                )
            })?;

        // Convert JWK to PEM
        let public_key_pem = jwk.to_pem().ok_or_else(|| {
            FederationError::TokenVerificationFailed("Failed to convert JWK to PEM".to_string())
        })?;

        // Build validation config
        let mut validation = ValidationConfig::with_leeway(self.config.clock_skew_tolerance);

        if let Some(ref issuer) = self.config.expected_issuer {
            validation = validation.issuer(issuer.clone());
        }

        if let Some(ref audience) = self.config.expected_audience {
            validation = validation.audience(audience.clone());
        }

        if !self.config.validate_exp {
            validation = validation.skip_exp_validation();
        }

        // Verify the token
        let claims =
            decode_token_with_config(token, &public_key_pem, &validation).map_err(|e| match e {
                xavyo_auth::AuthError::TokenExpired => FederationError::TokenExpired,
                xavyo_auth::AuthError::InvalidSignature => {
                    FederationError::TokenVerificationFailed("Invalid signature".to_string())
                }
                xavyo_auth::AuthError::InvalidAlgorithm => {
                    FederationError::TokenVerificationFailed("Unsupported algorithm".to_string())
                }
                _ => FederationError::TokenVerificationFailed(e.to_string()),
            })?;

        // Validate issuer if expected
        if let Some(ref expected) = self.config.expected_issuer {
            if claims.iss != *expected {
                warn!(
                    expected = %expected,
                    actual = %claims.iss,
                    "Issuer mismatch"
                );
                return Err(FederationError::InvalidIssuer(claims.iss.clone()));
            }
        }

        info!(
            issuer = %claims.iss,
            subject = %claims.sub,
            kid = ?kid,
            "Token verified successfully"
        );

        Ok(VerifiedToken {
            issuer: claims.iss.clone(),
            claims,
            kid,
        })
    }

    /// Verify a token with a specific expected issuer.
    ///
    /// This is a convenience method that temporarily overrides the configured issuer.
    #[instrument(skip(self, token))]
    pub async fn verify_token_with_issuer(
        &self,
        token: &str,
        jwks_uri: &str,
        expected_issuer: &str,
    ) -> FederationResult<VerifiedToken> {
        // Extract kid from token header
        let kid = xavyo_auth::extract_kid(token)
            .map_err(|e| FederationError::TokenVerificationFailed(e.to_string()))?;

        // Find the signing key
        let jwk = self
            .jwks_cache
            .find_signing_key(jwks_uri, kid.as_deref())
            .await?
            .ok_or_else(|| {
                FederationError::JwksKeyNotFound(
                    kid.clone().unwrap_or_else(|| "no kid".to_string()),
                )
            })?;

        // Convert JWK to PEM
        let public_key_pem = jwk.to_pem().ok_or_else(|| {
            FederationError::TokenVerificationFailed("Failed to convert JWK to PEM".to_string())
        })?;

        // Build validation config with the specific issuer
        let validation =
            ValidationConfig::with_leeway(self.config.clock_skew_tolerance).issuer(expected_issuer);

        // Verify the token
        let claims =
            decode_token_with_config(token, &public_key_pem, &validation).map_err(|e| match e {
                xavyo_auth::AuthError::TokenExpired => FederationError::TokenExpired,
                xavyo_auth::AuthError::InvalidSignature => {
                    FederationError::TokenVerificationFailed("Invalid signature".to_string())
                }
                _ => FederationError::TokenVerificationFailed(e.to_string()),
            })?;

        Ok(VerifiedToken {
            issuer: claims.iss.clone(),
            claims,
            kid,
        })
    }

    /// Get a reference to the JWKS cache.
    pub fn jwks_cache(&self) -> &JwksCache {
        &self.jwks_cache
    }

    /// Force refresh the JWKS for an IdP.
    ///
    /// Call this when you suspect keys have rotated.
    pub async fn refresh_jwks(&self, jwks_uri: &str) -> FederationResult<()> {
        self.jwks_cache.get_keys_force_refresh(jwks_uri).await?;
        Ok(())
    }
}

impl Default for TokenVerifierService {
    fn default() -> Self {
        Self::new(VerificationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test RSA key pair (same as in token_issuer tests)
    const TEST_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC46zZuOStUrVWL
q5KtkAaPL9hNCULR4zPhgskdUOB1c+bxRiOicEHKTBsqb4LSnizIb3fIEN5XuUL5
TzOBKT3hAc/gKKU71VKE5EMcbfuLLVxTqj08K2j7PzCChzzydZGjAWfisndASeQP
IJ1HM3Lh3VhXar3uwxbpT2Kqx59C7SDpCTHsZwvLVMupyEiL+18rFI7vDvlnHxuo
G5dkGZhyZrLfKx1A3eX49UibiJz8Km4UtbReZ5O+VSndHYmhLFXJKHd9pOr7Xxyy
mTucGJbmZOmSjb3bgaIhYyH+CtpoxTtqCfUi2kHCZdC1cGF93UnqLmNIq7nc0Ybh
JJc++72NAgMBAAECggEAA4ZeSP8Xe5t7PjiUyPCuI1QY5i0HREt1rXaKAWBNiwec
zxwUaVAE/Qdy3B34iy2/MknnqV1i856hL3HqTCu+VXfsn7v+nFOeaVCVk+jnytkg
QasE1E0KiQGFGfPcfk2t60LHWWun+MZ/zacEQHtzVOlcefwbpz26RdPA0HsSJtso
cqgiF274eoWfzOqWvGxmbPwvToVVb+PPRw8r1+EcQ95vaWM24O83/lfVNmUgonzD
S7qqRq3g51enCHBuoqE2a9tIx3UGut/MP5MECxdgw+bfcOAZ1z7hzai5difHF/vr
amWytmlPdJJIvYeKU7H4YISmYQUQ8JB9fGCMMeX1+QKBgQD1iyJy4RFDBL3Izl5b
p2vyu1GkUiJw7dz8F1MTrz25uRnMdyqvkV6X9u8uw7BzQ7D9ecTPrJrHlvaLeISP
RR/4EfjY9wC5VrEpwrrKYaf12DGqhVyTpwktrVgUkUmOXSTi8256DkOwuR3QgIhD
Cbkvq6iwHEhIxLzv8iApVsDt+QKBgQDAyyjvzWJnsew+iFcXqwAPRXkv1bXGrFYE
iub3K5HqGe6G2JS89dEvqqjmne9qZshG9M7FyHapX8NdKE5e6a5mADLr4thpMqJY
gKTi1gs4vlq55ziz5LW3gYLbPkp+P8bKBzVa/M/457oudHpPR4+EwVwsP4I9YCAO
EoNqYiCBNQKBgQCCc1Lv+Yb0NhamEo2q3/3HzaEITeKiYJzhCXtHn/iJLT/5ku4I
rJC256gXDjw2YKYtZH4dXzQ0CY4edv7mJvFfGB0/F6s4zEf/Scd3Mf7L6/onAAc5
IqsLq2Z6Nt3/Vpj8QhxVmDJ6Nz8RwNej1gyeuPI77iqxDmTajaZsj/yb8QKBgQCR
K2kTyI9EjZDaNUd/Jt/Qn/t0rXNGuhW7LexkSYaBxCz7lLHK5z4wqkyr+liAwgwk
gcoA28WeG+G7j9ITXdpYK+YsAI/8BoiAI74EoC+q9orSWO01aA38s6SY+fqVvegt
z+e5L4xaXAKxYDuI3tWOnRqOpvOmy27XqdESlfjr0QKBgDpS1FtG9JN1Bg01GoOp
Hzl/YpRraobBYDOtv70uNx9QyKAeFmvhDkwmgbOA1efFMgcPG7bdvL5ld7/N6d7D
RSiBP/6TepaXLEdSsrN4dARjpDeuV87IokbrVay54JWW0yTStzAzbLFcodp3sBNn
6iYwOxn6PHzksnM+GSuHzWGz
-----END PRIVATE KEY-----"#;

    // JWKS JSON with the public key that matches TEST_PRIVATE_KEY
    fn test_jwks_json() -> String {
        r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-1",
                    "alg": "RS256",
                    "n": "uOs2bjkrVK1Vi6uSrZAGjy_YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm-C0p4syG93yBDeV7lC-U8zgSk94QHP4CilO9VShORDHG37iy1cU6o9PCto-z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi_tfKxSO7w75Zx8bqBuXZBmYcmay3ysdQN3l-PVIm4ic_CpuFLW0XmeTvlUp3R2JoSxVySh3faTq-18cspk7nBiW5mTpko2924GiIWMh_graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9jQ",
                    "e": "AQAB"
                }
            ]
        }"#
        .to_string()
    }

    fn create_test_token(exp_offset_secs: i64, issuer: &str) -> String {
        let claims = xavyo_auth::JwtClaims::builder()
            .subject("user-123")
            .issuer(issuer)
            .expiration(Utc::now().timestamp() + exp_offset_secs)
            .build();

        xavyo_auth::encode_token_with_kid(&claims, TEST_PRIVATE_KEY, "test-key-1").unwrap()
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_jwks_json()))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let token = create_test_token(3600, "https://idp.example.com");

        let verifier = TokenVerifierService::new(VerificationConfig::default());
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims.sub, "user-123");
        assert_eq!(verified.issuer, "https://idp.example.com");
        assert_eq!(verified.kid, Some("test-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_verify_expired_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_jwks_json()))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        // Token expired 1 hour ago
        let token = create_test_token(-3600, "https://idp.example.com");

        let verifier = TokenVerifierService::new(VerificationConfig::default());
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FederationError::TokenExpired));
    }

    #[tokio::test]
    async fn test_verify_with_clock_skew_tolerance() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_jwks_json()))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        // Token expired 2 minutes ago
        let token = create_test_token(-120, "https://idp.example.com");

        // With 5 minute tolerance, should still pass
        let verifier = TokenVerifierService::new(VerificationConfig::with_clock_skew(300));
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_invalid_issuer() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_jwks_json()))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let token = create_test_token(3600, "https://wrong-idp.example.com");

        let verifier = TokenVerifierService::new(
            VerificationConfig::default().issuer("https://expected-idp.example.com"),
        );
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_err());
        // jsonwebtoken library rejects mismatched issuer as TokenVerificationFailed
        // since the issuer validation happens during decode
        let err = result.unwrap_err();
        assert!(
            matches!(err, FederationError::TokenVerificationFailed(_))
                || matches!(err, FederationError::InvalidIssuer(_)),
            "Expected TokenVerificationFailed or InvalidIssuer, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_verify_jwks_fetch_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let token = create_test_token(3600, "https://idp.example.com");

        let verifier = TokenVerifierService::new(VerificationConfig::default());
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FederationError::JwksFetchFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_verify_key_not_found() {
        let mock_server = MockServer::start().await;

        // JWKS with different key ID
        let different_jwks = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "different-key",
                    "alg": "RS256",
                    "n": "test",
                    "e": "AQAB"
                }
            ]
        }"#;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(different_jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let token = create_test_token(3600, "https://idp.example.com");

        let verifier = TokenVerifierService::new(VerificationConfig::default());
        let result = verifier.verify_token(&token, &jwks_uri).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FederationError::JwksKeyNotFound(_)
        ));
    }
}
