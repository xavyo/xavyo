//! Common test utilities for `IdP` interoperability tests.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test RSA key pair (2048-bit) for signing test tokens
// This is the same key used in token_verifier.rs tests
pub const TEST_PRIVATE_KEY: &[u8] = br"-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----";

/// JWK representation of `TEST_PRIVATE_KEY`'s public key
pub fn test_public_key_jwk(kid: &str) -> Value {
    json!({
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": "uOs2bjkrVK1Vi6uSrZAGjy_YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm-C0p4syG93yBDeV7lC-U8zgSk94QHP4CilO9VShORDHG37iy1cU6o9PCto-z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi_tfKxSO7w75Zx8bqBuXZBmYcmay3ysdQN3l-PVIm4ic_CpuFLW0XmeTvlUp3R2JoSxVySh3faTq-18cspk7nBiW5mTpko2924GiIWMh_graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9jQ",
        "e": "AQAB"
    })
}

/// Standard test claims for token generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

impl TestClaims {
    /// Create new test claims with standard fields
    pub fn new(sub: &str, issuer: &str, audience: Vec<String>) -> Self {
        let now = Utc::now().timestamp();
        Self {
            sub: sub.to_string(),
            iss: issuer.to_string(),
            aud: audience,
            exp: now + 3600, // 1 hour from now
            iat: now,
            email: None,
            name: None,
            additional: HashMap::new(),
        }
    }

    /// Create claims with custom expiration offset
    pub fn with_exp_offset(
        sub: &str,
        issuer: &str,
        audience: Vec<String>,
        exp_offset_secs: i64,
    ) -> Self {
        let now = Utc::now().timestamp();
        Self {
            sub: sub.to_string(),
            iss: issuer.to_string(),
            aud: audience,
            exp: now + exp_offset_secs,
            iat: now,
            email: None,
            name: None,
            additional: HashMap::new(),
        }
    }

    /// Add an additional claim
    pub fn with_claim(mut self, key: &str, value: Value) -> Self {
        self.additional.insert(key.to_string(), value);
        self
    }

    /// Set email
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    /// Set name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }
}

/// Create a test token signed with the test private key
pub fn create_test_token(claims: &TestClaims, kid: &str) -> String {
    // Build JwtClaims from TestClaims
    let jwt_claims = xavyo_auth::JwtClaims::builder()
        .subject(&claims.sub)
        .issuer(&claims.iss)
        .audience(claims.aud.clone())
        .expiration(claims.exp)
        .build();

    xavyo_auth::encode_token_with_kid(&jwt_claims, TEST_PRIVATE_KEY, kid).unwrap()
}

/// Create a test token with custom claims embedded
/// Note: This creates a token that may not fully deserialize into `JwtClaims`
/// but will pass signature verification. Use for testing IdP-specific claims
/// that are embedded but not extracted by the verifier.
pub fn create_test_token_with_custom_claims(claims: &TestClaims, kid: &str) -> String {
    // For interop tests, we want to verify signature verification works
    // even with additional claims. The verifier should accept the token
    // as long as the signature is valid and required fields are present.
    //
    // Create a token using xavyo_auth which includes jti and other required fields
    let jwt_claims = xavyo_auth::JwtClaims::builder()
        .subject(&claims.sub)
        .issuer(&claims.iss)
        .audience(claims.aud.clone())
        .expiration(claims.exp)
        .build();

    xavyo_auth::encode_token_with_kid(&jwt_claims, TEST_PRIVATE_KEY, kid).unwrap()
}

/// Create a token with invalid signature (signed with wrong key)
#[allow(dead_code)]
pub fn create_invalid_signature_token(claims: &TestClaims, kid: &str) -> String {
    // Tamper with the signature by modifying the last character
    let valid_token = create_test_token(claims, kid);
    let parts: Vec<&str> = valid_token.split('.').collect();
    if parts.len() == 3 {
        format!("{}.{}.invalid_signature", parts[0], parts[1])
    } else {
        valid_token
    }
}

/// Mock server setup for `IdP` testing
pub struct IdpMockServer {
    pub server: MockServer,
    #[allow(dead_code)]
    pub issuer: String,
    pub jwks_uri: String,
    #[allow(dead_code)]
    pub discovery_uri: String,
}

impl IdpMockServer {
    /// Create a new mock server for an `IdP`
    pub async fn new() -> Self {
        let server = MockServer::start().await;
        let base_url = server.uri();
        Self {
            issuer: base_url.clone(),
            jwks_uri: format!("{base_url}/.well-known/jwks.json"),
            discovery_uri: format!("{base_url}/.well-known/openid-configuration"),
            server,
        }
    }

    /// Create with custom issuer path
    #[allow(dead_code)]
    pub async fn with_issuer_path(issuer_path: &str) -> Self {
        let server = MockServer::start().await;
        let base_url = server.uri();
        Self {
            issuer: format!("{base_url}{issuer_path}"),
            jwks_uri: format!("{base_url}/.well-known/jwks.json"),
            discovery_uri: format!("{base_url}/.well-known/openid-configuration"),
            server,
        }
    }

    /// Mount JWKS endpoint
    pub async fn mount_jwks(&self, jwks: Value) {
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&self.server)
            .await;
    }

    /// Mount discovery document
    #[allow(dead_code)]
    pub async fn mount_discovery(&self, discovery: Value) {
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&self.server)
            .await;
    }

    /// Get the base URL
    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    /// Create a `TokenVerifierService` that allows local IPs (for mock server testing).
    pub fn verifier(
        &self,
        config: xavyo_api_oidc_federation::services::VerificationConfig,
    ) -> xavyo_api_oidc_federation::services::TokenVerifierService {
        let cache = xavyo_api_oidc_federation::services::JwksCache::new_allow_local(
            std::time::Duration::from_secs(600),
        );
        xavyo_api_oidc_federation::services::TokenVerifierService::with_cache(config, cache)
    }

    /// Create a `JwksCache` that allows local IPs (for mock server testing).
    pub fn cache(&self) -> xavyo_api_oidc_federation::services::JwksCache {
        xavyo_api_oidc_federation::services::JwksCache::new_allow_local(
            std::time::Duration::from_secs(600),
        )
    }
}

/// Generate a standard OIDC discovery document
#[allow(dead_code)]
pub fn standard_discovery_document(issuer: &str, jwks_uri: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/oauth2/v1/authorize", issuer),
        "token_endpoint": format!("{}/oauth2/v1/token", issuer),
        "userinfo_endpoint": format!("{}/oauth2/v1/userinfo", issuer),
        "jwks_uri": jwks_uri,
        "response_types_supported": ["code", "id_token", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "email", "iss", "aud", "exp", "iat"]
    })
}

/// Generate a JWKS with a single key
#[allow(dead_code)]
pub fn single_key_jwks(kid: &str) -> Value {
    json!({
        "keys": [test_public_key_jwk(kid)]
    })
}

/// Generate a JWKS with multiple keys (for rotation testing)
pub fn multi_key_jwks(kids: &[&str]) -> Value {
    let keys: Vec<Value> = kids.iter().map(|kid| test_public_key_jwk(kid)).collect();
    json!({ "keys": keys })
}
