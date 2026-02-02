//! OIDC Discovery endpoint handlers.

use crate::models::{Jwk, JwkSet, OpenIdConfiguration};
use crate::router::OAuthState;
use axum::{extract::State, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;

/// Returns the OpenID Connect Discovery document.
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    responses(
        (status = 200, description = "OIDC Discovery document", body = OpenIdConfiguration),
    ),
    tag = "OIDC Discovery"
)]
pub async fn discovery_handler(State(state): State<OAuthState>) -> Json<OpenIdConfiguration> {
    let config = OpenIdConfiguration::new(&state.issuer);
    Json(config)
}

/// Returns the JSON Web Key Set containing public keys for token verification.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "JSON Web Key Set", body = JwkSet),
    ),
    tag = "OIDC Discovery"
)]
pub async fn jwks_handler(State(state): State<OAuthState>) -> Json<JwkSet> {
    let mut jwk_set = JwkSet::new();

    // Add all signing keys to the JWKS (F069-S5: multi-key rotation support)
    if !state.signing_keys.is_empty() {
        for key in &state.signing_keys {
            match create_jwk_from_pem(key.public_key_pem.as_bytes(), &key.kid) {
                Ok(jwk) => {
                    jwk_set = jwk_set.add_key(jwk);
                }
                Err(e) => {
                    tracing::error!(kid = %key.kid, "Failed to create JWK from public key: {}", e);
                }
            }
        }
    } else {
        // Fallback to single key for backward compatibility
        match create_jwk_from_pem(&state.public_key, &state.key_id) {
            Ok(jwk) => {
                jwk_set = jwk_set.add_key(jwk);
            }
            Err(e) => {
                tracing::error!("Failed to create JWK from public key: {}", e);
            }
        }
    }

    Json(jwk_set)
}

/// Create a JWK from a PEM-encoded RSA public key.
fn create_jwk_from_pem(pem_data: &[u8], key_id: &str) -> Result<Jwk, String> {
    use pkcs8::DecodePublicKey;

    // Parse PEM to string
    let pem_str =
        std::str::from_utf8(pem_data).map_err(|e| format!("Invalid PEM encoding: {}", e))?;

    // Try to parse as RSA public key from PEM
    let public_key = RsaPublicKey::from_public_key_pem(pem_str)
        .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;

    // Extract n (modulus) and e (exponent)
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    // Encode as base64url
    let n = URL_SAFE_NO_PAD.encode(&n_bytes);
    let e = URL_SAFE_NO_PAD.encode(&e_bytes);

    Ok(Jwk {
        kty: "RSA".to_string(),
        kid: key_id.to_string(),
        key_use: "sig".to_string(),
        alg: "RS256".to_string(),
        n,
        e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openid_configuration_creation() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert_eq!(config.issuer, "https://idp.example.com");
        assert_eq!(
            config.authorization_endpoint,
            "https://idp.example.com/oauth/authorize"
        );
        assert_eq!(config.token_endpoint, "https://idp.example.com/oauth/token");
        assert_eq!(
            config.userinfo_endpoint,
            "https://idp.example.com/oauth/userinfo"
        );
        assert_eq!(
            config.jwks_uri,
            "https://idp.example.com/.well-known/jwks.json"
        );
        assert!(config
            .response_types_supported
            .contains(&"code".to_string()));
        assert!(config
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
        assert!(config.scopes_supported.contains(&"openid".to_string()));
        assert!(config.scopes_supported.contains(&"profile".to_string()));
        assert!(config.scopes_supported.contains(&"email".to_string()));
        assert!(config
            .scopes_supported
            .contains(&"offline_access".to_string()));
    }

    #[test]
    fn test_openid_configuration_grants() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert!(config
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        assert!(config
            .grant_types_supported
            .contains(&"client_credentials".to_string()));
        assert!(config
            .grant_types_supported
            .contains(&"refresh_token".to_string()));
        // RFC 8628: Device code grant
        assert!(config
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string()));
    }

    #[test]
    fn test_openid_configuration_device_authorization() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        // RFC 8628: Device authorization endpoint
        assert_eq!(
            config.device_authorization_endpoint,
            Some("https://idp.example.com/oauth/device/code".to_string())
        );
    }

    #[test]
    fn test_openid_configuration_signing() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert!(config
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
    }

    #[test]
    fn test_openid_configuration_claims() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        // Required OIDC claims
        assert!(config.claims_supported.contains(&"sub".to_string()));
        assert!(config.claims_supported.contains(&"iss".to_string()));
        assert!(config.claims_supported.contains(&"aud".to_string()));
        assert!(config.claims_supported.contains(&"exp".to_string()));
        assert!(config.claims_supported.contains(&"iat".to_string()));

        // Profile claims
        assert!(config.claims_supported.contains(&"name".to_string()));

        // Email claims
        assert!(config.claims_supported.contains(&"email".to_string()));
        assert!(config
            .claims_supported
            .contains(&"email_verified".to_string()));
    }

    // Note: Testing create_jwk_from_pem requires a valid RSA key pair.
    // Integration tests should verify this with actual keys.
    #[test]
    fn test_jwk_set_creation() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-key-1".to_string(),
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            n: "test-modulus".to_string(),
            e: "AQAB".to_string(),
        };

        let jwk_set = JwkSet::new().add_key(jwk);
        assert_eq!(jwk_set.keys.len(), 1);
        assert_eq!(jwk_set.keys[0].kid, "test-key-1");
        assert_eq!(jwk_set.keys[0].kty, "RSA");
        assert_eq!(jwk_set.keys[0].alg, "RS256");
    }
}
