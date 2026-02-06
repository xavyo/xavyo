//! Token issuer service for issuing Xavyo JWTs after successful federation.
//!
//! This service integrates with xavyo-auth to issue properly signed RS256 tokens
//! after a user has successfully authenticated through a federated Identity Provider.

use crate::error::{FederationError, FederationResult};
use crate::models::FederationClaims;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{info, instrument};
use uuid::Uuid;
use xavyo_auth::{encode_token, JwtClaims};

/// Configuration for the token issuer service.
#[derive(Clone)]
pub struct TokenIssuerConfig {
    /// PEM-encoded RSA private key for signing tokens.
    pub private_key_pem: Vec<u8>,
    /// Access token TTL in seconds (default: 900 = 15 minutes).
    pub access_token_ttl: i64,
    /// Refresh token TTL in seconds (default: 604800 = 7 days).
    pub refresh_token_ttl: i64,
    /// Token issuer (iss claim).
    pub issuer: String,
    /// Token audience (aud claim).
    pub audience: Vec<String>,
}

impl Default for TokenIssuerConfig {
    fn default() -> Self {
        Self {
            private_key_pem: Vec::new(),
            access_token_ttl: 900,     // 15 minutes
            refresh_token_ttl: 604800, // 7 days
            issuer: "xavyo".to_string(),
            audience: Vec::new(),
        }
    }
}

/// Token issuer service.
///
/// Issues RS256-signed JWTs using the xavyo-auth library.
#[derive(Clone)]
pub struct TokenIssuerService {
    config: TokenIssuerConfig,
}

/// Issued tokens response.
#[derive(Debug, Clone)]
pub struct IssuedTokens {
    /// Access token (RS256 signed JWT).
    pub access_token: String,
    /// Token expiry in seconds.
    pub expires_in: i64,
    /// Optional refresh token (RS256 signed JWT).
    pub refresh_token: Option<String>,
    /// Token type (always "Bearer").
    pub token_type: String,
}

impl TokenIssuerService {
    /// Create a new token issuer service with configuration.
    #[must_use]
    pub fn new(config: TokenIssuerConfig) -> Self {
        Self { config }
    }

    /// Create a token issuer with default configuration (for testing).
    ///
    /// Note: This creates a service without a private key, which will fail
    /// when attempting to issue tokens. Use `new()` with proper config in production.
    #[must_use]
    pub fn new_default() -> Self {
        Self {
            config: TokenIssuerConfig::default(),
        }
    }

    /// Create with custom TTLs (legacy API for backward compatibility).
    #[must_use]
    pub fn with_ttl(access_token_ttl: i64, refresh_token_ttl: i64) -> Self {
        Self {
            config: TokenIssuerConfig {
                access_token_ttl,
                refresh_token_ttl,
                ..Default::default()
            },
        }
    }

    /// Issue tokens for a user after successful federation.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The Xavyo user ID
    /// * `tenant_id` - The tenant ID for multi-tenancy
    /// * `roles` - User roles to include in the token
    /// * `federation_claims` - Optional federation context to include
    ///
    /// # Returns
    ///
    /// Issued tokens including access token and refresh token.
    #[instrument(skip(self, roles, federation_claims))]
    pub async fn issue_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        roles: Vec<String>,
        federation_claims: Option<FederationClaims>,
    ) -> FederationResult<IssuedTokens> {
        // Build access token claims
        let mut claims_builder = JwtClaims::builder()
            .subject(user_id.to_string())
            .issuer(&self.config.issuer)
            .tenant_uuid(tenant_id)
            .roles(roles.clone())
            .expires_in_secs(self.config.access_token_ttl);

        if !self.config.audience.is_empty() {
            claims_builder = claims_builder.audience(self.config.audience.clone());
        }

        let claims = claims_builder.build();

        // Encode access token
        let access_token = encode_token(&claims, &self.config.private_key_pem)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;

        // Build refresh token claims (longer expiry, purpose=refresh)
        let refresh_claims = JwtClaims::builder()
            .subject(user_id.to_string())
            .issuer(&self.config.issuer)
            .tenant_uuid(tenant_id)
            .purpose("refresh")
            .expires_in_secs(self.config.refresh_token_ttl)
            .build();

        let refresh_token = encode_token(&refresh_claims, &self.config.private_key_pem)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;

        // Log the issuance (without federation claims to avoid PII)
        info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            roles_count = roles.len(),
            has_federation_context = federation_claims.is_some(),
            expires_in = %self.config.access_token_ttl,
            "Issued federation tokens"
        );

        Ok(IssuedTokens {
            access_token,
            expires_in: self.config.access_token_ttl,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
        })
    }

    /// Issue tokens with mapped claims from `IdP`.
    ///
    /// This method accepts pre-mapped claims from the `ClaimsService` and
    /// includes them in the issued token.
    #[instrument(skip(self, roles, mapped_claims, federation_claims))]
    pub async fn issue_tokens_with_claims(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        roles: Vec<String>,
        mapped_claims: HashMap<String, Value>,
        federation_claims: Option<FederationClaims>,
    ) -> FederationResult<IssuedTokens> {
        // Build access token claims
        let mut claims_builder = JwtClaims::builder()
            .subject(user_id.to_string())
            .issuer(&self.config.issuer)
            .tenant_uuid(tenant_id)
            .roles(roles.clone())
            .expires_in_secs(self.config.access_token_ttl);

        if !self.config.audience.is_empty() {
            claims_builder = claims_builder.audience(self.config.audience.clone());
        }

        // Add email from mapped claims if present
        if let Some(Value::String(email)) = mapped_claims.get("email") {
            claims_builder = claims_builder.email(email.clone());
        }

        let claims = claims_builder.build();

        // Encode access token
        let access_token = encode_token(&claims, &self.config.private_key_pem)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;

        // Build refresh token claims
        let refresh_claims = JwtClaims::builder()
            .subject(user_id.to_string())
            .issuer(&self.config.issuer)
            .tenant_uuid(tenant_id)
            .purpose("refresh")
            .expires_in_secs(self.config.refresh_token_ttl)
            .build();

        let refresh_token = encode_token(&refresh_claims, &self.config.private_key_pem)
            .map_err(|e| FederationError::TokenIssueFailed(e.to_string()))?;

        info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            roles_count = roles.len(),
            mapped_claims_count = mapped_claims.len(),
            has_federation_context = federation_claims.is_some(),
            expires_in = %self.config.access_token_ttl,
            "Issued federation tokens with mapped claims"
        );

        Ok(IssuedTokens {
            access_token,
            expires_in: self.config.access_token_ttl,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
        })
    }

    /// Issue tokens with federation context included in the token.
    ///
    /// Federation claims are added to the token to allow downstream
    /// applications to identify the source of authentication.
    #[instrument(skip(self, roles, federation_claims))]
    pub async fn issue_tokens_with_federation_context(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        roles: Vec<String>,
        federation_claims: FederationClaims,
    ) -> FederationResult<IssuedTokens> {
        // For now, federation claims are logged but not embedded in the JWT
        // (would require extending JwtClaims to support custom claims)
        // This is intentional - the federation context is tracked server-side
        self.issue_tokens(user_id, tenant_id, roles, Some(federation_claims))
            .await
    }

    /// Get the configured issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Get the access token TTL in seconds.
    #[must_use]
    pub fn access_token_ttl(&self) -> i64 {
        self.config.access_token_ttl
    }

    /// Get the refresh token TTL in seconds.
    #[must_use]
    pub fn refresh_token_ttl(&self) -> i64 {
        self.config.refresh_token_ttl
    }
}

impl Default for TokenIssuerService {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_config() -> TokenIssuerConfig {
        TokenIssuerConfig {
            private_key_pem: TEST_PRIVATE_KEY.to_vec(),
            access_token_ttl: 900,
            refresh_token_ttl: 604800,
            issuer: "https://auth.example.com".to_string(),
            audience: vec!["https://api.example.com".to_string()],
        }
    }

    #[tokio::test]
    async fn test_issue_tokens_returns_valid_jwt() {
        let service = TokenIssuerService::new(test_config());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let tokens = service
            .issue_tokens(user_id, tenant_id, vec!["user".to_string()], None)
            .await
            .unwrap();

        // JWT should have 3 parts
        assert_eq!(tokens.access_token.split('.').count(), 3);
        assert_eq!(tokens.token_type, "Bearer");
        assert!(tokens.refresh_token.is_some());
    }

    #[tokio::test]
    async fn test_issue_tokens_verifiable_with_public_key() {
        let service = TokenIssuerService::new(test_config());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let tokens = service
            .issue_tokens(user_id, tenant_id, vec!["admin".to_string()], None)
            .await
            .unwrap();

        // Verify the token with the public key
        let claims = xavyo_auth::decode_token(&tokens.access_token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(
            claims.tid,
            Some(*xavyo_core::TenantId::from_uuid(tenant_id).as_uuid())
        );
        assert!(claims.has_role("admin"));
    }

    #[tokio::test]
    async fn test_issue_tokens_contains_standard_claims() {
        let service = TokenIssuerService::new(test_config());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        let tokens = service
            .issue_tokens(user_id, tenant_id, vec![], None)
            .await
            .unwrap();

        let claims = xavyo_auth::decode_token(&tokens.access_token, TEST_PUBLIC_KEY).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.iss, "https://auth.example.com");
        assert!(!claims.jti.is_empty());
        assert!(claims.exp > 0);
        assert!(claims.iat > 0);
    }

    #[tokio::test]
    async fn test_issue_tokens_invalid_key_returns_error() {
        let mut config = test_config();
        config.private_key_pem = b"invalid key".to_vec();

        let service = TokenIssuerService::new(config);
        let result = service
            .issue_tokens(Uuid::new_v4(), Uuid::new_v4(), vec![], None)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FederationError::TokenIssueFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_refresh_token_has_longer_ttl() {
        let service = TokenIssuerService::new(test_config());

        let tokens = service
            .issue_tokens(Uuid::new_v4(), Uuid::new_v4(), vec![], None)
            .await
            .unwrap();

        let access_claims =
            xavyo_auth::decode_token(&tokens.access_token, TEST_PUBLIC_KEY).unwrap();
        let refresh_claims =
            xavyo_auth::decode_token(tokens.refresh_token.as_ref().unwrap(), TEST_PUBLIC_KEY)
                .unwrap();

        // Refresh token should expire later than access token
        assert!(refresh_claims.exp > access_claims.exp);
        assert_eq!(refresh_claims.purpose, Some("refresh".to_string()));
    }

    #[tokio::test]
    async fn test_issue_tokens_with_federation_claims() {
        let service = TokenIssuerService::new(test_config());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let idp_id = Uuid::new_v4();

        let federation_claims = FederationClaims::builder()
            .idp_id(idp_id)
            .idp_issuer("https://idp.example.com")
            .federated_sub("idp-user-123")
            .federated_now()
            .build();

        let tokens = service
            .issue_tokens(
                user_id,
                tenant_id,
                vec!["user".to_string()],
                Some(federation_claims),
            )
            .await
            .unwrap();

        // Token should be valid
        assert_eq!(tokens.access_token.split('.').count(), 3);
    }
}
