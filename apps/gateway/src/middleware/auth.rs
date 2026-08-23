//! JWT authentication middleware.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::config::GatewayConfig;
use crate::error::ErrorResponse;

/// Extracted JWT claims for authenticated requests.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthClaims {
    pub sub: String,
    pub tenant_id: Option<String>,
    pub roles: Vec<String>,
}

/// Layer for authentication middleware.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    config: Arc<GatewayConfig>,
}

impl AuthLayer {
    /// Create a new auth layer with the given configuration.
    pub fn new(config: Arc<GatewayConfig>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Authentication service wrapper.
#[derive(Debug, Clone)]
pub struct AuthService<S> {
    inner: S,
    config: Arc<GatewayConfig>,
}

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();
        let path = request.uri().path().to_string();

        Box::pin(async move {
            // Check if path is public (no auth required)
            if config.is_public_path(&path) {
                return inner.call(request).await;
            }

            // Check for backend-specific auth requirements
            if let Some(backend) = config.find_backend(&path) {
                if !backend.requires_auth {
                    return inner.call(request).await;
                }
            }

            // Extract Authorization header
            let auth_header = request
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok());

            let token = match auth_header {
                Some(header) if header.starts_with("Bearer ") => &header[7..],
                _ => {
                    return Ok(unauthorized_response(
                        "Missing or invalid authorization header",
                    ));
                }
            };

            // Validate JWT token (signature + iss/aud)
            match validate_jwt(token, &config) {
                Ok(claims) => {
                    // Add claims as extension
                    request.extensions_mut().insert(claims);
                    inner.call(request).await
                }
                Err(e) => Ok(unauthorized_response(&e)),
            }
        })
    }
}

/// Validate JWT token and extract claims.
fn validate_jwt(token: &str, config: &GatewayConfig) -> Result<AuthClaims, String> {
    let pem = std::fs::read(&config.auth.public_key_path)
        .map_err(|e| format!("Failed to read JWT public key: {e}"))?;
    validate_jwt_with_pem(token, &pem, &config.auth.issuer, &config.auth.audience)
}

/// Signature-checking JWT validation used by the gateway and unit tests.
pub fn validate_jwt_with_pem(
    token: &str,
    public_key_pem: &[u8],
    issuer: &str,
    audience: &str,
) -> Result<AuthClaims, String> {
    let validation = xavyo_auth::ValidationConfig::default()
        .issuer(issuer.to_string())
        .audience(vec![audience.to_string()]);
    let claims = xavyo_auth::decode_token_with_config(token, public_key_pem, &validation)
        .map_err(|e| format!("Invalid JWT: {e}"))?;
    Ok(AuthClaims {
        sub: claims.sub,
        tenant_id: claims.tid.map(|u| u.to_string()),
        roles: claims.roles,
    })
}

/// Create an unauthorized response.
fn unauthorized_response(message: &str) -> Response {
    let body = ErrorResponse {
        error: "UNAUTHORIZED".to_string(),
        message: message.to_string(),
        request_id: None,
    };

    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

/// Middleware function for authentication (alternative to layer).
#[allow(dead_code)]
pub async fn auth_middleware(request: Request, next: Next) -> Response {
    // This is a simplified version - the AuthLayer provides full functionality
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_auth::{encode_token, JwtClaims};
    use xavyo_core::TenantId;

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

    #[test]
    fn test_validate_jwt_invalid_format() {
        let result = validate_jwt_with_pem("not-a-jwt", TEST_PUBLIC_KEY, "xavyo", "xavyo");
        assert!(result.is_err());
    }

    #[test]
    fn dummy_signature_segment_is_rejected() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature";
        let result = validate_jwt_with_pem(token, TEST_PUBLIC_KEY, "xavyo", "xavyo");
        assert!(result.is_err());
    }

    #[test]
    fn signed_token_with_matching_iss_aud_is_accepted() {
        let tenant = TenantId::new();
        let claims = JwtClaims::builder()
            .subject("user123")
            .issuer("https://example.com")
            .audience(vec!["test"])
            .tenant_id(tenant)
            .roles(vec!["admin"])
            .expires_in_secs(3600)
            .build();
        let token = encode_token(&claims, TEST_PRIVATE_KEY).unwrap();
        let result =
            validate_jwt_with_pem(&token, TEST_PUBLIC_KEY, "https://example.com", "test").unwrap();
        assert_eq!(result.sub, "user123");
        assert_eq!(result.roles, vec!["admin"]);
        assert_eq!(
            result.tenant_id.as_deref(),
            Some(tenant.as_uuid().to_string().as_str())
        );
    }
}
