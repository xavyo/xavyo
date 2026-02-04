//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! Provides async functions to fetch public keys from JWKS endpoints
//! for JWT validation with key rotation support.

use crate::error::AuthError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A JSON Web Key as defined in RFC 7517.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA").
    pub kty: String,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Public key use (e.g., "sig" for signature).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Algorithm (e.g., "RS256").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// RSA modulus (`Base64URL` encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    /// RSA exponent (`Base64URL` encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    /// X.509 certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

impl Jwk {
    /// Convert JWK to PEM-encoded public key.
    ///
    /// # Errors
    ///
    /// Returns error if the key cannot be converted to PEM.
    pub fn to_pem(&self) -> Result<Vec<u8>, AuthError> {
        let n = self
            .n
            .as_ref()
            .ok_or_else(|| AuthError::InvalidKey("Missing modulus (n)".to_string()))?;
        let e = self
            .e
            .as_ref()
            .ok_or_else(|| AuthError::InvalidKey("Missing exponent (e)".to_string()))?;

        // Decode Base64URL
        let n_bytes = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|e| AuthError::InvalidKey(format!("Invalid modulus encoding: {e}")))?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|e| AuthError::InvalidKey(format!("Invalid exponent encoding: {e}")))?;

        // Build RSA public key in DER format
        let der = build_rsa_public_key_der(&n_bytes, &e_bytes);

        // Convert to PEM
        use base64::engine::general_purpose::STANDARD;
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(&der)
        );

        Ok(pem.into_bytes())
    }
}

/// Build RSA public key DER encoding.
fn build_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // RSA public key structure:
    // SEQUENCE {
    //   SEQUENCE {
    //     OID rsaEncryption
    //     NULL
    //   }
    //   BIT STRING {
    //     SEQUENCE {
    //       INTEGER n
    //       INTEGER e
    //     }
    //   }
    // }

    // RSA OID: 1.2.840.113549.1.1.1
    let rsa_oid = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let null = &[0x05, 0x00];

    // Build inner SEQUENCE (n, e)
    let n_der = encode_integer(n);
    let e_der = encode_integer(e);
    let inner_seq = encode_sequence(&[&n_der, &e_der]);

    // Build BIT STRING
    let bit_string = encode_bit_string(&inner_seq);

    // Build algorithm SEQUENCE
    let algo_seq = encode_sequence(&[rsa_oid, null]);

    // Build outer SEQUENCE
    encode_sequence(&[&algo_seq, &bit_string])
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn encode_integer(data: &[u8]) -> Vec<u8> {
    // Add leading zero if high bit is set (to keep it positive)
    let needs_padding = !data.is_empty() && (data[0] & 0x80) != 0;
    let len = data.len() + usize::from(needs_padding);

    let mut result = vec![0x02]; // INTEGER tag
    result.extend(encode_length(len));
    if needs_padding {
        result.push(0x00);
    }
    result.extend(data);
    result
}

fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flat_map(|&item| item.to_vec()).collect();
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x03]; // BIT STRING tag
    result.extend(encode_length(data.len() + 1));
    result.push(0x00); // No unused bits
    result.extend(data);
    result
}

/// A JSON Web Key Set as defined in RFC 7517.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// Array of JWK values.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Find a key by its kid.
    #[must_use]
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Get the first key (useful when there's only one key).
    #[must_use]
    pub fn first_key(&self) -> Option<&Jwk> {
        self.keys.first()
    }
}

/// Cached JWKS entry.
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

/// JWKS client with caching support.
///
/// Fetches and caches JWKS from an endpoint, with automatic
/// re-fetch when a key is not found.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_auth::JwksClient;
///
/// let client = JwksClient::new("https://idp.example.com/.well-known/jwks.json")?;
///
/// // Get a key by kid
/// let pem = client.get_key_pem("key-1").await?;
/// ```
#[derive(Clone)]
pub struct JwksClient {
    url: String,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    cache_ttl: Duration,
    http_client: reqwest::Client,
}

impl JwksClient {
    /// Create a new JWKS client.
    ///
    /// # Arguments
    ///
    /// * `url` - The JWKS endpoint URL
    ///
    /// # Errors
    ///
    /// Returns `AuthError::JwksFetchFailed` if the HTTP client cannot be created.
    pub fn new(url: impl Into<String>) -> Result<Self, AuthError> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AuthError::JwksFetchFailed(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            url: url.into(),
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(300), // 5 minutes default
            http_client,
        })
    }

    /// Set the cache TTL.
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Fetch JWKS from the endpoint.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::JwksFetchFailed` if the fetch fails.
    pub async fn fetch_jwks(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .http_client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetchFailed(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(AuthError::JwksFetchFailed(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| AuthError::JwksFetchFailed(format!("Invalid JSON: {e}")))?;

        // Update cache
        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            jwks: jwks.clone(),
            fetched_at: Instant::now(),
        });

        Ok(jwks)
    }

    /// Get JWKS, using cache if available and not expired.
    pub async fn get_jwks(&self) -> Result<JwkSet, AuthError> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        // Cache miss or expired, fetch fresh
        self.fetch_jwks().await
    }

    /// Get a key by kid, with automatic re-fetch on miss.
    ///
    /// # Arguments
    ///
    /// * `kid` - The key ID to look up
    ///
    /// # Errors
    ///
    /// Returns `AuthError::KeyNotFound` if the key is not found after re-fetch.
    pub async fn get_key(&self, kid: &str) -> Result<Jwk, AuthError> {
        // Try cache first
        let jwks = self.get_jwks().await?;
        if let Some(key) = jwks.find_key(kid) {
            return Ok(key.clone());
        }

        // Key not found, try re-fetching
        let jwks = self.fetch_jwks().await?;
        jwks.find_key(kid)
            .cloned()
            .ok_or_else(|| AuthError::KeyNotFound(kid.to_string()))
    }

    /// Get a key's PEM by kid.
    ///
    /// Convenience method that fetches the key and converts to PEM.
    pub async fn get_key_pem(&self, kid: &str) -> Result<Vec<u8>, AuthError> {
        let key = self.get_key(kid).await?;
        key.to_pem()
    }

    /// Clear the cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }
}

impl std::fmt::Debug for JwksClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksClient")
            .field("url", &self.url)
            .field("cache_ttl", &self.cache_ttl)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_set_find_key() {
        let jwks = JwkSet {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key-1".to_string()),
                    key_use: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some("test-n".to_string()),
                    e: Some("test-e".to_string()),
                    x5c: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key-2".to_string()),
                    key_use: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some("test-n-2".to_string()),
                    e: Some("test-e-2".to_string()),
                    x5c: None,
                },
            ],
        };

        let key = jwks.find_key("key-1");
        assert!(key.is_some());
        assert_eq!(key.unwrap().n, Some("test-n".to_string()));

        let key = jwks.find_key("key-2");
        assert!(key.is_some());

        let key = jwks.find_key("key-3");
        assert!(key.is_none());
    }

    #[test]
    fn test_jwk_set_first_key() {
        let jwks = JwkSet {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: Some("key-1".to_string()),
                key_use: None,
                alg: None,
                n: Some("test-n".to_string()),
                e: Some("test-e".to_string()),
                x5c: None,
            }],
        };

        assert!(jwks.first_key().is_some());

        let empty_jwks = JwkSet { keys: vec![] };
        assert!(empty_jwks.first_key().is_none());
    }

    #[test]
    fn test_jwk_to_pem_missing_n() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            key_use: None,
            alg: None,
            n: None,
            e: Some("AQAB".to_string()),
            x5c: None,
        };

        let result = jwk.to_pem();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidKey(_)));
    }

    #[test]
    fn test_jwk_to_pem_missing_e() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            key_use: None,
            alg: None,
            n: Some("test".to_string()),
            e: None,
            x5c: None,
        };

        let result = jwk.to_pem();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidKey(_)));
    }

    #[test]
    fn test_jwks_client_new() {
        let client = JwksClient::new("https://example.com/.well-known/jwks.json")
            .expect("Failed to create JwksClient");
        assert_eq!(client.url, "https://example.com/.well-known/jwks.json");
    }

    #[test]
    fn test_jwks_client_with_cache_ttl() {
        let client = JwksClient::new("https://example.com/jwks")
            .expect("Failed to create JwksClient")
            .with_cache_ttl(Duration::from_secs(600));
        assert_eq!(client.cache_ttl, Duration::from_secs(600));
    }

    #[test]
    fn test_jwk_serialization() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: Some("key-1".to_string()),
            key_use: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
            n: Some("modulus".to_string()),
            e: Some("AQAB".to_string()),
            x5c: None,
        };

        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"kty\":\"RSA\""));
        assert!(json.contains("\"kid\":\"key-1\""));
        assert!(json.contains("\"use\":\"sig\"")); // Renamed field
    }

    #[test]
    fn test_jwks_deserialization() {
        let json = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "test-modulus",
                    "e": "AQAB"
                }
            ]
        }"#;

        let jwks: JwkSet = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, Some("key-1".to_string()));
        assert_eq!(jwks.keys[0].key_use, Some("sig".to_string()));
    }

    // Integration tests would use wiremock to mock the JWKS endpoint
    // but those are skipped in unit tests
}
