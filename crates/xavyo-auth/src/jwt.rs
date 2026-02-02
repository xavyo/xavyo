//! JWT encoding and decoding with RS256 algorithm.
//!
//! Provides functions to encode and decode JWT tokens using RSA keys.

use crate::claims::JwtClaims;
use crate::error::AuthError;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};

/// Configuration for JWT validation.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Leeway in seconds for exp/iat validation (clock skew tolerance).
    pub leeway: u64,
    /// Expected issuer (if set, tokens with different issuer are rejected).
    pub issuer: Option<String>,
    /// Expected audience (if set, tokens without matching audience are rejected).
    pub audience: Option<Vec<String>>,
    /// Whether to validate expiration.
    pub validate_exp: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            leeway: 60, // 60 seconds clock skew tolerance
            issuer: None,
            audience: None,
            validate_exp: true,
        }
    }
}

impl ValidationConfig {
    /// Create a new validation config with custom leeway.
    #[must_use]
    pub fn with_leeway(leeway: u64) -> Self {
        Self {
            leeway,
            ..Default::default()
        }
    }

    /// Set the expected issuer.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.issuer = Some(iss.into());
        self
    }

    /// Set the expected audience.
    #[must_use]
    pub fn audience(mut self, aud: Vec<impl Into<String>>) -> Self {
        self.audience = Some(aud.into_iter().map(Into::into).collect());
        self
    }

    /// Disable expiration validation (use with caution).
    #[must_use]
    pub fn skip_exp_validation(mut self) -> Self {
        self.validate_exp = false;
        self
    }
}

/// Encode JWT claims into a signed token string using RS256.
///
/// # Arguments
///
/// * `claims` - The JWT claims to encode
/// * `private_key_pem` - PEM-encoded RSA private key
///
/// # Returns
///
/// A signed JWT token string.
///
/// # Errors
///
/// Returns `AuthError::InvalidKey` if the private key is invalid.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_auth::{encode_token, JwtClaims};
///
/// let claims = JwtClaims::builder()
///     .subject("user-123")
///     .expires_in_secs(3600)
///     .build();
///
/// let token = encode_token(&claims, private_key_pem)?;
/// ```
pub fn encode_token(claims: &JwtClaims, private_key_pem: &[u8]) -> Result<String, AuthError> {
    let key = EncodingKey::from_rsa_pem(private_key_pem)
        .map_err(|e| AuthError::InvalidKey(format!("Invalid private key: {}", e)))?;

    let header = Header::new(Algorithm::RS256);

    encode(&header, claims, &key)
        .map_err(|e| AuthError::InvalidToken(format!("Encoding failed: {}", e)))
}

/// Encode JWT claims with a custom key ID (kid) header.
///
/// Useful when using JWKS with multiple keys.
///
/// # Arguments
///
/// * `claims` - The JWT claims to encode
/// * `private_key_pem` - PEM-encoded RSA private key
/// * `kid` - Key ID to include in the token header
///
/// # Returns
///
/// A signed JWT token string with kid in header.
pub fn encode_token_with_kid(
    claims: &JwtClaims,
    private_key_pem: &[u8],
    kid: &str,
) -> Result<String, AuthError> {
    let key = EncodingKey::from_rsa_pem(private_key_pem)
        .map_err(|e| AuthError::InvalidKey(format!("Invalid private key: {}", e)))?;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    encode(&header, claims, &key)
        .map_err(|e| AuthError::InvalidToken(format!("Encoding failed: {}", e)))
}

/// Decode and validate a JWT token.
///
/// # Arguments
///
/// * `token` - The JWT token string
/// * `public_key_pem` - PEM-encoded RSA public key
///
/// # Returns
///
/// The decoded JWT claims.
///
/// # Errors
///
/// - `AuthError::TokenExpired` - Token has expired
/// - `AuthError::InvalidSignature` - Signature verification failed
/// - `AuthError::InvalidToken` - Token format is invalid
/// - `AuthError::InvalidAlgorithm` - Token uses unsupported algorithm
/// - `AuthError::InvalidKey` - Public key is invalid
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_auth::decode_token;
///
/// let claims = decode_token(&token, public_key_pem)?;
/// println!("User: {}", claims.sub);
/// ```
pub fn decode_token(token: &str, public_key_pem: &[u8]) -> Result<JwtClaims, AuthError> {
    decode_token_with_config(token, public_key_pem, &ValidationConfig::default())
}

/// Decode and validate a JWT token with custom validation config.
///
/// # Arguments
///
/// * `token` - The JWT token string
/// * `public_key_pem` - PEM-encoded RSA public key
/// * `config` - Validation configuration
///
/// # Returns
///
/// The decoded JWT claims.
pub fn decode_token_with_config(
    token: &str,
    public_key_pem: &[u8],
    config: &ValidationConfig,
) -> Result<JwtClaims, AuthError> {
    let key = DecodingKey::from_rsa_pem(public_key_pem)
        .map_err(|e| AuthError::InvalidKey(format!("Invalid public key: {}", e)))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = config.leeway;
    validation.validate_exp = config.validate_exp;

    // Only accept RS256
    validation.algorithms = vec![Algorithm::RS256];

    // Set issuer validation if configured
    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }

    // Set audience validation if configured, otherwise disable it
    if let Some(ref aud) = config.audience {
        validation.set_audience(aud);
    } else {
        validation.validate_aud = false;
    }

    let token_data: TokenData<JwtClaims> =
        decode(token, &key, &validation).map_err(map_jwt_error)?;

    Ok(token_data.claims)
}

/// Extract the key ID (kid) from a JWT token header without validation.
///
/// Useful for selecting the correct key from a JWKS.
///
/// # Arguments
///
/// * `token` - The JWT token string
///
/// # Returns
///
/// The kid from the token header, if present.
pub fn extract_kid(token: &str) -> Result<Option<String>, AuthError> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| AuthError::InvalidToken(format!("Invalid token header: {}", e)))?;

    Ok(header.kid)
}

/// Map jsonwebtoken errors to AuthError.
fn map_jwt_error(err: jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;

    match err.kind() {
        ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        ErrorKind::InvalidSignature => AuthError::InvalidSignature,
        ErrorKind::InvalidAlgorithm => AuthError::InvalidAlgorithm,
        ErrorKind::InvalidToken => AuthError::InvalidToken("Malformed token".to_string()),
        ErrorKind::Base64(_) => AuthError::InvalidToken("Invalid base64 encoding".to_string()),
        ErrorKind::Json(_) => AuthError::InvalidToken("Invalid JSON in claims".to_string()),
        ErrorKind::MissingRequiredClaim(claim) => AuthError::MissingClaim(claim.to_string()),
        _ => AuthError::InvalidToken(format!("Token validation failed: {}", err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JwtClaims;
    use chrono::Utc;
    use xavyo_core::TenantId;

    // Test RSA key pair (2048-bit, PKCS#8 format, for testing only)
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

    const TEST_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOs2bjkrVK1Vi6uSrZAG
jy/YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm+C0p4syG93yBDeV7lC+U8zgSk9
4QHP4CilO9VShORDHG37iy1cU6o9PCto+z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy
4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi/tfKxSO7w75Zx8bqBuXZBmY
cmay3ysdQN3l+PVIm4ic/CpuFLW0XmeTvlUp3R2JoSxVySh3faTq+18cspk7nBiW
5mTpko2924GiIWMh/graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9
jQIDAQAB
-----END PUBLIC KEY-----"#;

    // Different key pair for testing invalid signature
    const WRONG_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsoT/1BaKX9vOFY44wkk4
lQTBzuPlpfPYiGna37yso2Ko8tQjYeRDmTcK8JUjsJgAbYBzmDb6et7iFaxvhClm
HGnG/ytKE9yeItqVuG29VRV3/5Th3JDVzp0ux9ovX1JgKDorVJw2Hq9mxPhPOttb
y8JqTbPVKEf7LzPvga8EATThQWyVm5fu4Q8VimSVfx6ew9pAu4mp9Ar+qY/etNOn
hO0p0rQRVSeTlFU60OLGbGWkeDYK9HXNShjG0XCVtom8hd/3FbPyY2HEx13Ou5cu
fNkXoE0XYxD9OK7vRKUDtE1k4tXVsJcMFgmfghZRKZalhr/ujuYMkEm4GooTOMah
pwIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn test_encode_token_valid_claims() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test-issuer")
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();

        // Token should have 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_encode_token_with_tenant_id() {
        let tenant_id = TenantId::new();
        let claims = JwtClaims::builder()
            .subject("user-123")
            .tenant_id(tenant_id)
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let decoded = decode_token(&token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(decoded.tenant_id(), Some(tenant_id));
    }

    #[test]
    fn test_encode_token_with_exp() {
        let exp = Utc::now().timestamp() + 7200; // 2 hours from now
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(exp)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let decoded = decode_token(&token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(decoded.exp, exp);
    }

    #[test]
    fn test_encode_token_invalid_key() {
        let claims = JwtClaims::builder().subject("user-123").build();

        let result = encode_token(&claims, b"invalid key");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidKey(_)));
    }

    #[test]
    fn test_decode_token_valid() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test-issuer")
            .roles(vec!["admin"])
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let decoded = decode_token(&token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(decoded.sub, "user-123");
        assert_eq!(decoded.iss, "test-issuer");
        assert!(decoded.has_role("admin"));
    }

    #[test]
    fn test_decode_token_expired() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(Utc::now().timestamp() - 3600) // 1 hour ago
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let result = decode_token(&token, TEST_PUBLIC_KEY);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::TokenExpired));
    }

    #[test]
    fn test_decode_token_invalid_signature() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let result = decode_token(&token, WRONG_PUBLIC_KEY);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidSignature));
    }

    #[test]
    fn test_decode_token_malformed() {
        let result = decode_token("not.a.valid.token", TEST_PUBLIC_KEY);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidToken(_)));
    }

    #[test]
    fn test_decode_token_with_leeway() {
        // Token that expired 30 seconds ago
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(Utc::now().timestamp() - 30)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();

        // Should fail with default leeway (60 seconds is the leeway, but token is 30 seconds expired)
        // Actually with 60 second leeway, a token expired 30 seconds ago should still be valid
        let result = decode_token(&token, TEST_PUBLIC_KEY);
        assert!(result.is_ok());

        // Token expired 120 seconds ago should fail even with 60 second leeway
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(Utc::now().timestamp() - 120)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let result = decode_token(&token, TEST_PUBLIC_KEY);
        assert!(matches!(result.unwrap_err(), AuthError::TokenExpired));
    }

    #[test]
    fn test_encode_token_with_kid() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expires_in_secs(3600)
            .build();

        let token = encode_token_with_kid(&claims, TEST_PRIVATE_KEY, "key-1").unwrap();
        let kid = extract_kid(&token).unwrap();

        assert_eq!(kid, Some("key-1".to_string()));
    }

    #[test]
    fn test_extract_kid_no_kid() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let kid = extract_kid(&token).unwrap();

        assert_eq!(kid, None);
    }

    #[test]
    fn test_validation_config_issuer() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("correct-issuer")
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();

        // Should succeed with matching issuer
        let config = ValidationConfig::default().issuer("correct-issuer");
        let result = decode_token_with_config(&token, TEST_PUBLIC_KEY, &config);
        assert!(result.is_ok());

        // Should fail with different issuer
        let config = ValidationConfig::default().issuer("wrong-issuer");
        let result = decode_token_with_config(&token, TEST_PUBLIC_KEY, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_trip_preserves_claims() {
        let tenant_id = TenantId::new();
        let original = JwtClaims::builder()
            .subject("user-456")
            .issuer("xavyo")
            .audience(vec!["api-1", "api-2"])
            .tenant_id(tenant_id)
            .roles(vec!["admin", "user"])
            .expires_in_secs(3600)
            .build();

        let token = encode_token(&original, TEST_PRIVATE_KEY).unwrap();
        let decoded = decode_token(&token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(decoded.sub, original.sub);
        assert_eq!(decoded.iss, original.iss);
        assert_eq!(decoded.aud, original.aud);
        assert_eq!(decoded.tid, original.tid);
        assert_eq!(decoded.roles, original.roles);
        assert_eq!(decoded.jti, original.jti);
    }
}
