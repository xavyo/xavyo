//! `private_key_jwt` client authentication (RFC 7523 §3 / OIDC Core §9).
//!
//! Pure (no DB, no I/O), unit-testable validation of a `client_assertion` JWT
//! presented for client authentication at the token / PAR endpoints. The FAPI
//! 2.0 Security Profile (§5.3.2.1-6) mandates this (or mTLS) instead of shared
//! `client_secret`s.
//!
//! # Security notes
//! - The verification algorithm is chosen from the **client JWK key type**,
//!   never the assertion's `alg` header (algorithm-confusion defense, as in
//!   [`crate::dpop`]). `none` and symmetric (`oct`) keys are rejected.
//! - `iss` and `sub` MUST both equal the `client_id`; `aud` MUST name this AS.
//! - The caller performs the tenant-scoped `jti` replay check using the
//!   returned [`ValidatedClientAssertion::jti`].

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;

/// RFC 7523 §2.2 client-assertion type for `private_key_jwt`.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Maximum accepted assertion lifetime: `exp` may be at most this far in the
/// future relative to `now`. Bounds the replay-cache retention window.
pub const CLIENT_ASSERTION_MAX_LIFETIME_SECS: i64 = 300;

/// Maximum tolerated future clock skew for `iat`.
pub const CLIENT_ASSERTION_MAX_FUTURE_SKEW_SECS: i64 = 60;

/// Maximum `iat` age (how far in the past the assertion may have been issued).
pub const CLIENT_ASSERTION_MAX_AGE_SECS: i64 = 300;

/// Errors from client-assertion validation. All map to OAuth `invalid_client`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientAssertionError {
    /// The assertion was structurally invalid, failed signature verification,
    /// or a claim did not satisfy the rules.
    #[error("invalid client_assertion: {0}")]
    Invalid(String),

    /// No usable client key matched (missing/ambiguous `kid`, or unsupported
    /// key type).
    #[error("no usable client key: {0}")]
    NoUsableKey(String),
}

/// A successfully-validated client assertion.
#[derive(Debug, Clone)]
pub struct ValidatedClientAssertion {
    /// The authenticated client (`iss` == `sub`).
    pub client_id: String,
    /// The assertion `jti` — feed to the tenant-scoped replay cache.
    pub jti: String,
}

/// `aud` may be a single string or an array of strings (RFC 7519 §4.1.3).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudClaim {
    One(String),
    Many(Vec<String>),
}

impl AudClaim {
    fn contains(&self, value: &str) -> bool {
        match self {
            AudClaim::One(s) => s == value,
            AudClaim::Many(vs) => vs.iter().any(|s| s == value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: AudClaim,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    jti: Option<String>,
}

/// Validate a `private_key_jwt` client assertion (RFC 7523 §3).
///
/// Verifies the signature against one of `client_jwks` (algorithm chosen from
/// the JWK key type, not the header `alg`), then checks `iss == sub ==
/// expected_client_id`, that `aud` names one of `accepted_audiences`, `exp`
/// freshness (not expired, not absurdly far in the future), `iat` freshness,
/// and `jti` presence. Returns the `client_id` and `jti` on success; the caller
/// MUST then perform the tenant-scoped `jti` replay check.
///
/// # Errors
/// [`ClientAssertionError::Invalid`] on any validation failure;
/// [`ClientAssertionError::NoUsableKey`] when no client key can verify it.
pub fn validate_client_assertion(
    assertion_jwt: &str,
    expected_client_id: &str,
    accepted_audiences: &[&str],
    client_jwks: &JwkSet,
    now: i64,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    // 1. Header → select the verifying key (by kid, or the sole key).
    let header = decode_header(assertion_jwt)
        .map_err(|e| ClientAssertionError::Invalid(format!("undecodable header: {e}")))?;
    let jwk = select_key(client_jwks, header.kid.as_deref())?;

    // 2. Allowed algorithms come from the key type, NOT the header `alg`.
    let allowed = algs_for_jwk(jwk)?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|e| ClientAssertionError::NoUsableKey(format!("unusable jwk: {e}")))?;

    // 3. Verify signature + decode claims. We validate time/aud manually below
    //    (so `now` is injectable and `aud` can match a set), so disable the
    //    library's automatic checks here.
    let mut validation = Validation::new(allowed[0]);
    validation.algorithms = allowed;
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::new();
    let data = decode::<ClientAssertionClaims>(assertion_jwt, &key, &validation)
        .map_err(|e| ClientAssertionError::Invalid(format!("signature/claims: {e}")))?;
    let c = data.claims;

    // 4. Claim checks (RFC 7523 §3).
    if c.iss != expected_client_id {
        return Err(ClientAssertionError::Invalid(
            "iss must equal client_id".into(),
        ));
    }
    if c.sub != expected_client_id {
        return Err(ClientAssertionError::Invalid(
            "sub must equal client_id".into(),
        ));
    }
    if !accepted_audiences.iter().any(|a| c.aud.contains(a)) {
        return Err(ClientAssertionError::Invalid(
            "aud does not name this authorization server".into(),
        ));
    }
    if now >= c.exp {
        return Err(ClientAssertionError::Invalid(
            "assertion has expired".into(),
        ));
    }
    if c.exp - now > CLIENT_ASSERTION_MAX_LIFETIME_SECS {
        return Err(ClientAssertionError::Invalid(
            "exp too far in the future".into(),
        ));
    }
    if let Some(iat) = c.iat {
        if iat - now > CLIENT_ASSERTION_MAX_FUTURE_SKEW_SECS {
            return Err(ClientAssertionError::Invalid("iat in the future".into()));
        }
        if now - iat > CLIENT_ASSERTION_MAX_AGE_SECS {
            return Err(ClientAssertionError::Invalid("iat too old".into()));
        }
    }
    let jti = c.jti.filter(|j| !j.trim().is_empty()).ok_or_else(|| {
        ClientAssertionError::Invalid("missing jti (required for replay protection)".into())
    })?;

    Ok(ValidatedClientAssertion {
        client_id: c.iss,
        jti,
    })
}

/// Select the verifying key: by `kid` when the header carries one, else the
/// single key in the set. Ambiguous (`kid` absent + multiple keys) is rejected.
fn select_key<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Result<&'a Jwk, ClientAssertionError> {
    if let Some(kid) = kid {
        return jwks
            .find(kid)
            .ok_or_else(|| ClientAssertionError::NoUsableKey(format!("no key with kid `{kid}`")));
    }
    match jwks.keys.as_slice() {
        [single] => Ok(single),
        [] => Err(ClientAssertionError::NoUsableKey(
            "client has no registered keys".into(),
        )),
        _ => Err(ClientAssertionError::NoUsableKey(
            "assertion has no `kid` but client has multiple keys".into(),
        )),
    }
}

/// Allowed algorithms for a JWK, chosen from the key type (alg-confusion guard).
/// Symmetric (`oct`) keys are rejected.
fn algs_for_jwk(jwk: &Jwk) -> Result<Vec<Algorithm>, ClientAssertionError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Ok(vec![Algorithm::ES256]),
            EllipticCurve::P384 => Ok(vec![Algorithm::ES384]),
            _ => Err(ClientAssertionError::NoUsableKey(
                "unsupported EC curve".into(),
            )),
        },
        AlgorithmParameters::RSA(_) => Ok(vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ]),
        AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            EllipticCurve::Ed25519 => Ok(vec![Algorithm::EdDSA]),
            _ => Err(ClientAssertionError::NoUsableKey(
                "unsupported OKP curve".into(),
            )),
        },
        AlgorithmParameters::OctetKey(_) => Err(ClientAssertionError::Invalid(
            "symmetric (oct) keys cannot authenticate a client".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use serde_json::{json, Value};

    const ISSUER: &str = "https://idp.example.com";
    const CLIENT: &str = "client-123";

    /// Build a single-key JwkSet for the deterministic test P-256 key, plus an
    /// `EncodingKey` to sign with. `kid` is attached when `Some`.
    fn test_keypair(kid: Option<&str>) -> (JwkSet, EncodingKey) {
        let sk = SigningKey::from_slice(&[0x22u8; 32]).expect("valid p256 scalar");
        let pem = sk
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pkcs8 pem");
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(pt.x().expect("x"));
        let y = URL_SAFE_NO_PAD.encode(pt.y().expect("y"));
        let mut jwk_json = json!({"kty":"EC","crv":"P-256","x":x,"y":y,"use":"sig","alg":"ES256"});
        if let Some(k) = kid {
            jwk_json["kid"] = json!(k);
        }
        let jwks: JwkSet = serde_json::from_value(json!({"keys":[jwk_json]})).expect("jwks");
        let key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("encoding key");
        (jwks, key)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign(
        key: &EncodingKey,
        kid: Option<&str>,
        iss: &str,
        sub: &str,
        aud: Value,
        exp: i64,
        iat: Option<i64>,
        jti: Option<&str>,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = kid.map(String::from);
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), json!(iss));
        claims.insert("sub".into(), json!(sub));
        claims.insert("aud".into(), aud);
        claims.insert("exp".into(), json!(exp));
        if let Some(i) = iat {
            claims.insert("iat".into(), json!(i));
        }
        if let Some(j) = jti {
            claims.insert("jti".into(), json!(j));
        }
        encode(&header, &Value::Object(claims), key).expect("encode assertion")
    }

    #[test]
    fn valid_assertion_is_accepted() {
        let now = 1_000_000;
        let (jwks, key) = test_keypair(None);
        let jwt = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("jti-1"),
        );
        let v = validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now).expect("valid");
        assert_eq!(v.client_id, CLIENT);
        assert_eq!(v.jti, "jti-1");
    }

    #[test]
    fn aud_may_be_array_and_match_token_endpoint() {
        let now = 1_000_000;
        let endpoint = "https://idp.example.com/oauth/token";
        let (jwks, key) = test_keypair(None);
        let jwt = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!([endpoint, "https://other"]),
            now + 60,
            Some(now),
            Some("jti-arr"),
        );
        assert!(validate_client_assertion(&jwt, CLIENT, &[ISSUER, endpoint], &jwks, now).is_ok());
    }

    #[test]
    fn wrong_iss_or_sub_rejected() {
        let now = 1_000_000;
        let (jwks, key) = test_keypair(None);
        let bad_iss = sign(
            &key,
            None,
            "other",
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&bad_iss, CLIENT, &[ISSUER], &jwks, now).is_err());
        let bad_sub = sign(
            &key,
            None,
            CLIENT,
            "other",
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&bad_sub, CLIENT, &[ISSUER], &jwks, now).is_err());
    }

    #[test]
    fn wrong_aud_rejected() {
        let now = 1_000_000;
        let (jwks, key) = test_keypair(None);
        let jwt = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!("https://attacker.example"),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now).is_err());
    }

    #[test]
    fn expired_or_far_future_rejected() {
        let now = 1_000_000;
        let (jwks, key) = test_keypair(None);
        let expired = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now - 1,
            Some(now - 120),
            Some("j"),
        );
        assert!(validate_client_assertion(&expired, CLIENT, &[ISSUER], &jwks, now).is_err());
        let far = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + CLIENT_ASSERTION_MAX_LIFETIME_SECS + 1,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&far, CLIENT, &[ISSUER], &jwks, now).is_err());
    }

    #[test]
    fn missing_jti_rejected() {
        let now = 1_000_000;
        let (jwks, key) = test_keypair(None);
        let jwt = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            None,
        );
        assert!(validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now).is_err());
    }

    #[test]
    fn bad_signature_rejected() {
        // Sign with one key, verify against a *different* registered key.
        let now = 1_000_000;
        let (_signer_jwks, signer_key) = test_keypair(None);
        // A different key in the client's JWKS.
        let other_sk = SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let other_vk = other_sk.verifying_key();
        let pt = other_vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(pt.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(pt.y().unwrap());
        let jwks: JwkSet =
            serde_json::from_value(json!({"keys":[{"kty":"EC","crv":"P-256","x":x,"y":y}]}))
                .unwrap();
        let jwt = sign(
            &signer_key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now).is_err());
    }

    #[test]
    fn kid_selects_key_among_many() {
        let now = 1_000_000;
        // Build a JWKS with the real key under kid "k1" plus a decoy under "k2".
        let (single, key) = test_keypair(Some("k1"));
        let real = single.keys[0].clone();
        let decoy: Jwk = serde_json::from_value(
            json!({"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB","kid":"k2"}),
        )
        .unwrap();
        let jwks = JwkSet {
            keys: vec![decoy, real],
        };
        let jwt = sign(
            &key,
            Some("k1"),
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now).is_ok());
    }

    #[test]
    fn missing_kid_with_multiple_keys_rejected() {
        let now = 1_000_000;
        let (single, key) = test_keypair(None);
        let real = single.keys[0].clone();
        let decoy: Jwk =
            serde_json::from_value(json!({"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}))
                .unwrap();
        let jwks = JwkSet {
            keys: vec![real, decoy],
        };
        let jwt = sign(
            &key,
            None,
            CLIENT,
            CLIENT,
            json!(ISSUER),
            now + 60,
            Some(now),
            Some("j"),
        );
        assert!(matches!(
            validate_client_assertion(&jwt, CLIENT, &[ISSUER], &jwks, now),
            Err(ClientAssertionError::NoUsableKey(_))
        ));
    }
}
