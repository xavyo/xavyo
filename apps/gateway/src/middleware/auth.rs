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

            // Validate JWT token
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
fn validate_jwt(token: &str, _config: &GatewayConfig) -> Result<AuthClaims, String> {
    // For now, do basic JWT structure validation
    // In production, this would use xavyo-auth for full validation
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (middle part)
    let payload = parts[1];
    let decoded = base64_decode_url_safe(payload).map_err(|()| "Invalid JWT payload encoding")?;

    let payload_str = String::from_utf8(decoded).map_err(|_| "Invalid JWT payload encoding")?;

    // Parse JSON payload
    let payload: serde_json::Value =
        serde_json::from_str(&payload_str).map_err(|_| "Invalid JWT payload JSON")?;

    // Extract claims
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'sub' claim")?
        .to_string();

    let tenant_id = payload
        .get("tid")
        .and_then(|v| v.as_str())
        .map(std::string::ToString::to_string);

    let roles = payload
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(std::string::ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(AuthClaims {
        sub,
        tenant_id,
        roles,
    })
}

/// Base64 URL-safe decoding for JWT.
fn base64_decode_url_safe(input: &str) -> Result<Vec<u8>, ()> {
    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };

    // Replace URL-safe characters
    let standard = padded.replace('-', "+").replace('_', "/");

    // Decode
    use std::io::Read;
    let mut decoder = base64_decoder(&standard);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).map_err(|_| ())?;
    Ok(output)
}

fn base64_decoder(input: &str) -> impl std::io::Read + '_ {
    struct Base64Reader<'a> {
        input: &'a [u8],
        pos: usize,
        buffer: [u8; 3],
        buffer_pos: usize,
        buffer_len: usize,
    }

    impl std::io::Read for Base64Reader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            const DECODE_TABLE: [i8; 128] = [
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1,
                -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
                36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
            ];

            let mut written = 0;
            while written < buf.len() {
                // Use buffered bytes first
                while self.buffer_pos < self.buffer_len && written < buf.len() {
                    buf[written] = self.buffer[self.buffer_pos];
                    self.buffer_pos += 1;
                    written += 1;
                }

                if written >= buf.len() {
                    break;
                }

                // Decode next 4 bytes
                if self.pos >= self.input.len() {
                    break;
                }

                let mut chunk = [0u8; 4];
                let mut chunk_len = 0;
                let mut padding = 0;

                while chunk_len < 4 && self.pos < self.input.len() {
                    let byte = self.input[self.pos];
                    self.pos += 1;

                    if byte == b'=' {
                        padding += 1;
                        chunk[chunk_len] = 0;
                        chunk_len += 1;
                    } else if byte < 128 && DECODE_TABLE[byte as usize] >= 0 {
                        chunk[chunk_len] = DECODE_TABLE[byte as usize] as u8;
                        chunk_len += 1;
                    }
                }

                if chunk_len == 0 {
                    break;
                }

                // Decode the chunk
                let decoded_len = 3 - padding;
                self.buffer[0] = (chunk[0] << 2) | (chunk[1] >> 4);
                if decoded_len > 1 {
                    self.buffer[1] = (chunk[1] << 4) | (chunk[2] >> 2);
                }
                if decoded_len > 2 {
                    self.buffer[2] = (chunk[2] << 6) | chunk[3];
                }

                self.buffer_pos = 0;
                self.buffer_len = decoded_len;
            }

            Ok(written)
        }
    }

    Base64Reader {
        input: input.as_bytes(),
        pos: 0,
        buffer: [0; 3],
        buffer_pos: 0,
        buffer_len: 0,
    }
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

    #[test]
    fn test_validate_jwt_invalid_format() {
        let config = create_test_config();
        let result = validate_jwt("not-a-jwt", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_valid_structure() {
        let config = create_test_config();
        // Create a minimal valid JWT structure (header.payload.signature)
        // Payload: {"sub": "user123", "tid": "tenant456", "roles": ["admin"]}
        let payload = r#"{"sub":"user123","tid":"tenant456","roles":["admin"]}"#;
        let encoded_payload = base64_encode_url_safe(payload.as_bytes());
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{}.signature", encoded_payload);

        let result = validate_jwt(&token, &config);
        assert!(result.is_ok());

        let claims = result.unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.tenant_id, Some("tenant456".to_string()));
        assert_eq!(claims.roles, vec!["admin"]);
    }

    fn create_test_config() -> GatewayConfig {
        let yaml = r#"
server:
  port: 8080
backends: []
rate_limits:
  enabled: true
auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
"#;
        GatewayConfig::from_yaml(yaml).unwrap()
    }

    fn base64_encode_url_safe(input: &[u8]) -> String {
        const ENCODE_TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut output = String::new();
        let mut i = 0;

        while i < input.len() {
            let b0 = input[i];
            let b1 = input.get(i + 1).copied().unwrap_or(0);
            let b2 = input.get(i + 2).copied().unwrap_or(0);

            output.push(ENCODE_TABLE[(b0 >> 2) as usize] as char);
            output.push(ENCODE_TABLE[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);

            if i + 1 < input.len() {
                output.push(ENCODE_TABLE[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
            }
            if i + 2 < input.len() {
                output.push(ENCODE_TABLE[(b2 & 0x3f) as usize] as char);
            }

            i += 3;
        }

        output
    }
}
