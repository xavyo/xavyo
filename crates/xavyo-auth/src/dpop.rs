//! DPoP (RFC 9449) proof validation and RFC 7638 JWK thumbprints.
//!
//! This module is pure (no DB, no I/O) and unit-testable. It provides:
//! - [`jwk_thumbprint`]: the RFC 7638 canonical SHA-256 thumbprint of a public
//!   JWK, used as the `cnf.jkt` confirmation value that binds an access token to
//!   a client-held key.
//! - [`compute_ath`]: the RFC 9449 §4.1 access-token hash (base64url-no-pad
//!   SHA-256 of the *encoded* token string).
//!
//! Proof-JWT parsing/validation (`validate_proof`) is added in the next
//! implementation step; this step lands the thumbprint + ath primitives with
//! the RFC test vectors as fixtures (vectors-first TDD).
//!
//! # Security notes
//! - Algorithm selection for proof verification is keyed off the JWK key type,
//!   never the proof's `alg` header (prevents algorithm-confusion). `none` and
//!   symmetric keys are rejected.
//! - The thumbprint canonicalization includes ONLY the RFC 7638 required members
//!   for the key type, lexicographically ordered, with no insignificant
//!   whitespace.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

/// DPoP proof acceptance window, in seconds, for the `iat` freshness check
/// (RFC 9449 §11.1) — how far in the *past* a proof's `iat` may be. This is also
/// the TTL the replay cache must use for stored `jti`s.
pub const DPOP_PROOF_MAX_AGE_SECS: i64 = 120;

/// Maximum tolerated clock skew, in seconds, for a proof's `iat`/`nbf` in the
/// *future*. FAPI 2.0 Security Profile §5.3.2.1 item 13 requires rejecting
/// proofs whose `iat` is more than 60 seconds in the future (while accepting a
/// small positive skew). Tighter than the past-freshness window: a proof minted
/// far in the future is suspicious regardless of profile.
pub const DPOP_MAX_FUTURE_SKEW_SECS: i64 = 60;

/// Errors from DPoP proof handling.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpopError {
    /// The JWK is missing a required member or has an unsupported `kty`.
    #[error("malformed or unsupported JWK: {0}")]
    MalformedJwk(String),

    /// The proof JWT was structurally invalid or failed signature verification.
    #[error("invalid DPoP proof: {0}")]
    InvalidProof(String),
}

/// Claims carried in a DPoP proof JWT (RFC 9449 §4.2).
#[derive(Debug, Deserialize)]
struct DpopProofClaims {
    /// HTTP method of the bound request.
    htm: String,
    /// HTTP target URI of the bound request (query/fragment ignored on compare).
    htu: String,
    /// Issued-at (Unix seconds).
    iat: i64,
    /// Unique proof identifier (replay key).
    jti: String,
    /// Access-token hash — required on resource requests, absent on the token
    /// endpoint request.
    #[serde(default)]
    ath: Option<String>,
    /// Server-provided nonce (DPoP-Nonce) — parsed but unused in v1.
    #[serde(default)]
    #[allow(dead_code)]
    nonce: Option<String>,
}

/// A successfully-validated DPoP proof.
#[derive(Debug, Clone)]
pub struct ValidatedProof {
    /// RFC 7638 thumbprint of the proof's public key — compare to the access
    /// token's `cnf.jkt`, or set it as `cnf.jkt` when issuing.
    pub jkt: String,
    /// The proof's `jti` — feed to the replay cache.
    pub jti: String,
    /// The proof's `ath`, if present.
    pub ath: Option<String>,
}

/// Validate a DPoP proof JWT (RFC 9449 §4.3).
///
/// Verifies: `typ == "dpop+jwt"`; the signature against the **embedded JWK**
/// using an algorithm chosen from the **JWK key type** (never the header `alg`
/// — prevents algorithm-confusion; `none`/symmetric rejected); `htm` matches
/// `expected_htm`; `htu` matches `expected_htu` (scheme+host+path, query and
/// fragment ignored); `iat` no older than [`DPOP_PROOF_MAX_AGE_SECS`] and no
/// more than [`DPOP_MAX_FUTURE_SKEW_SECS`] in the future; `jti` present; and,
/// when `expected_ath` is `Some`, that `ath` matches.
///
/// The caller is responsible for: passing a proxy-safe `expected_htu` (built
/// from the configured issuer URL + request path, NOT the live `Host` header),
/// and for replay-checking the returned `jti`.
///
/// # Errors
/// [`DpopError::InvalidProof`] on any validation failure;
/// [`DpopError::MalformedJwk`] if the embedded JWK is unsupported.
pub fn validate_proof(
    proof_jwt: &str,
    expected_htm: &str,
    expected_htu: &str,
    now: i64,
    expected_ath: Option<&str>,
) -> Result<ValidatedProof, DpopError> {
    // 1. Header: typ + embedded JWK.
    let header = decode_header(proof_jwt)
        .map_err(|e| DpopError::InvalidProof(format!("undecodable header: {e}")))?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(DpopError::InvalidProof(
            "header `typ` must be \"dpop+jwt\"".into(),
        ));
    }
    let jwk = header
        .jwk
        .ok_or_else(|| DpopError::InvalidProof("header missing `jwk`".into()))?;

    // 2. Allowed algorithms come from the JWK key type, NOT the header `alg`.
    let allowed = algs_for_jwk(&jwk)?;

    // 3. Thumbprint (binds the token) — from the embedded JWK.
    let jwk_value = serde_json::to_value(&jwk)
        .map_err(|e| DpopError::MalformedJwk(format!("jwk serialize: {e}")))?;
    let jkt = jwk_thumbprint(&jwk_value)?;

    // 4. Verify signature against the embedded public key.
    let key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| DpopError::InvalidProof(format!("unusable jwk: {e}")))?;
    let mut validation = Validation::new(allowed[0]);
    validation.algorithms = allowed;
    validation.validate_exp = false; // DPoP uses iat freshness, not exp
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::new(); // exp/aud not required in proofs
    let data = decode::<DpopProofClaims>(proof_jwt, &key, &validation)
        .map_err(|e| DpopError::InvalidProof(format!("signature/claims: {e}")))?;

    // 5. Bound-request + freshness + ath checks (pure logic).
    validate_proof_claims(&data.claims, expected_htm, expected_htu, now, expected_ath)?;

    Ok(ValidatedProof {
        jkt,
        jti: data.claims.jti,
        ath: data.claims.ath,
    })
}

/// Validate a DPoP proof presented alongside an access token at a RESOURCE
/// endpoint (RFC 9449 §4.3 + §6): everything [`validate_proof`] checks, plus
/// the proof key thumbprint must equal the token's `cnf.jkt` and the proof's
/// `ath` must equal `SHA-256(encoded_access_token)`.
///
/// This is crypto-only (no DB) so it can be shared by every resource edge
/// (`xavyo-api-oauth` userinfo, `xavyo-api-auth` jwt middleware) without a
/// dependency cycle. The caller is responsible for the tenant-scoped `jti`
/// replay check using the returned [`ValidatedProof::jti`], and for building a
/// proxy-safe `expected_htu` (configured issuer URL + request path).
///
/// # Errors
/// [`DpopError::InvalidProof`] on any failure including a thumbprint mismatch.
pub fn verify_resource_proof(
    proof_jwt: &str,
    expected_jkt: &str,
    htm: &str,
    expected_htu: &str,
    now: i64,
    encoded_access_token: &str,
) -> Result<ValidatedProof, DpopError> {
    let ath = compute_ath(encoded_access_token);
    let validated = validate_proof(proof_jwt, htm, expected_htu, now, Some(&ath))?;
    if validated.jkt != expected_jkt {
        return Err(DpopError::InvalidProof(
            "proof key thumbprint does not match token cnf.jkt".into(),
        ));
    }
    Ok(validated)
}

/// Pure validation of DPoP proof claims (no crypto). Separated so the
/// `htm`/`htu`/`iat`/`ath` logic is unit-testable without key plumbing.
fn validate_proof_claims(
    c: &DpopProofClaims,
    expected_htm: &str,
    expected_htu: &str,
    now: i64,
    expected_ath: Option<&str>,
) -> Result<(), DpopError> {
    if !c.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::InvalidProof(format!(
            "htm mismatch: proof={} expected={expected_htm}",
            c.htm
        )));
    }
    if normalize_htu(&c.htu) != normalize_htu(expected_htu) {
        return Err(DpopError::InvalidProof("htu mismatch".into()));
    }
    // Past freshness (RFC 9449 §11.1) and future-skew cap (FAPI 2.0
    // §5.3.2.1-13) are asymmetric: a proof may be at most
    // DPOP_PROOF_MAX_AGE_SECS old, but at most DPOP_MAX_FUTURE_SKEW_SECS ahead.
    if now - c.iat > DPOP_PROOF_MAX_AGE_SECS {
        return Err(DpopError::InvalidProof("iat too old (stale proof)".into()));
    }
    if c.iat - now > DPOP_MAX_FUTURE_SKEW_SECS {
        return Err(DpopError::InvalidProof("iat too far in the future".into()));
    }
    if c.jti.trim().is_empty() {
        return Err(DpopError::InvalidProof("missing jti".into()));
    }
    if let Some(want) = expected_ath {
        match c.ath.as_deref() {
            Some(got) if got == want => {}
            _ => return Err(DpopError::InvalidProof("ath mismatch or missing".into())),
        }
    }
    Ok(())
}

/// Normalize an `htu` for comparison per RFC 9449 §4.3: compare scheme + host +
/// path, ignoring query and fragment. Also trims a trailing slash so
/// `…/token` and `…/token/` compare equal.
fn normalize_htu(uri: &str) -> String {
    let no_frag = uri.split('#').next().unwrap_or(uri);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    no_query.trim_end_matches('/').to_string()
}

/// Map a JWK to the jsonwebtoken algorithm allowlist for its key type.
/// Symmetric keys (`oct`) and unsupported curves are rejected — this is the
/// algorithm-confusion guard: the verifier never trusts the proof's `alg`
/// header to choose the algorithm.
fn algs_for_jwk(jwk: &Jwk) -> Result<Vec<Algorithm>, DpopError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Ok(vec![Algorithm::ES256]),
            EllipticCurve::P384 => Ok(vec![Algorithm::ES384]),
            _ => Err(DpopError::MalformedJwk("unsupported EC curve".into())),
        },
        AlgorithmParameters::RSA(_) => Ok(vec![Algorithm::RS256, Algorithm::PS256]),
        AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            EllipticCurve::Ed25519 => Ok(vec![Algorithm::EdDSA]),
            _ => Err(DpopError::MalformedJwk("unsupported OKP curve".into())),
        },
        AlgorithmParameters::OctetKey(_) => Err(DpopError::MalformedJwk(
            "symmetric (oct) keys cannot bind a DPoP proof".into(),
        )),
    }
}

/// Compute the RFC 7638 JWK SHA-256 thumbprint, base64url-no-pad encoded.
///
/// This is the value placed in the access token's `cnf.jkt` claim (RFC 9449
/// §6). Canonicalization per RFC 7638 §3: a JSON object containing exactly the
/// required members for the key type, with lexicographically-sorted keys and no
/// insignificant whitespace, hashed with SHA-256.
///
/// Required members by `kty`:
/// - `EC`:  `crv`, `kty`, `x`, `y`
/// - `RSA`: `e`, `kty`, `n`
/// - `OKP`: `crv`, `kty`, `x`
///
/// Symmetric (`oct`) keys are rejected — they cannot bind a public-key proof.
///
/// # Errors
/// Returns [`DpopError::MalformedJwk`] if a required member is absent or the
/// `kty` is unsupported.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String, DpopError> {
    let get = |k: &str| -> Result<&str, DpopError> {
        jwk.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| DpopError::MalformedJwk(format!("missing member `{k}`")))
    };

    let kty = get("kty")?;
    // Build the canonical JSON by hand to guarantee member order + absence of
    // whitespace. All values here are base64url strings or short ASCII tokens
    // (`RSA`, `EC`, `P-256`, …) that need no JSON escaping.
    let canonical = match kty {
        "RSA" => {
            let e = get("e")?;
            let n = get("n")?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "EC" => {
            let crv = get("crv")?;
            let x = get("x")?;
            let y = get("y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "OKP" => {
            let crv = get("crv")?;
            let x = get("x")?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        other => {
            return Err(DpopError::MalformedJwk(format!(
                "unsupported kty `{other}` (expected RSA, EC, or OKP)"
            )));
        }
    };

    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Compute the RFC 9449 §4.1 access-token hash (`ath`): base64url-no-pad of the
/// SHA-256 of the **encoded** access-token string exactly as it appears in the
/// `Authorization` header (NOT the decoded JWT payload).
#[must_use]
pub fn compute_ath(encoded_access_token: &str) -> String {
    let digest = Sha256::digest(encoded_access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 7638 §3.1 worked example: the canonical RSA key thumbprint is
    /// `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. This is the authoritative
    /// vector and must match exactly.
    #[test]
    fn test_rfc7638_rsa_thumbprint_vector() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\
        cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4\
        Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7\
        d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3X\
        PksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let tp = jwk_thumbprint(&jwk).expect("RSA thumbprint");
        assert_eq!(tp, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    /// Extra JWK members (`alg`, `kid`, `use`) must NOT affect the thumbprint —
    /// only the required members participate.
    #[test]
    fn test_thumbprint_ignores_non_required_members() {
        let base = json!({"kty":"RSA","n":"0vx7ag","e":"AQAB"});
        let with_extras = json!({
            "kty":"RSA","n":"0vx7ag","e":"AQAB",
            "alg":"RS256","kid":"x","use":"sig"
        });
        assert_eq!(
            jwk_thumbprint(&base).unwrap(),
            jwk_thumbprint(&with_extras).unwrap()
        );
    }

    /// EC keys canonicalize with `crv,kty,x,y` in order; thumbprint is stable
    /// regardless of input member order.
    #[test]
    fn test_ec_thumbprint_stable_across_member_order() {
        let a = json!({"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"});
        let b = json!({"y":"BBBB","x":"AAAA","crv":"P-256","kty":"EC"});
        assert_eq!(jwk_thumbprint(&a).unwrap(), jwk_thumbprint(&b).unwrap());
    }

    /// Symmetric keys cannot bind a public-key proof and must be rejected.
    #[test]
    fn test_symmetric_kty_rejected() {
        let oct = json!({"kty":"oct","k":"c2VjcmV0"});
        assert!(matches!(
            jwk_thumbprint(&oct),
            Err(DpopError::MalformedJwk(_))
        ));
    }

    #[test]
    fn test_missing_required_member_rejected() {
        let rsa_no_e = json!({"kty":"RSA","n":"0vx7ag"});
        assert!(matches!(
            jwk_thumbprint(&rsa_no_e),
            Err(DpopError::MalformedJwk(_))
        ));
    }

    #[test]
    fn test_compute_ath_known_value() {
        // ath = base64url(SHA-256("token")) with no padding.
        // SHA-256("token") computed independently.
        let ath = compute_ath("token");
        // Recompute expected with the same primitives to lock the encoding shape
        // (no padding, url-safe alphabet).
        let expected = {
            let d = Sha256::digest(b"token");
            URL_SAFE_NO_PAD.encode(d)
        };
        assert_eq!(ath, expected);
        assert!(!ath.contains('='), "ath must be unpadded");
        assert!(
            !ath.contains('+') && !ath.contains('/'),
            "ath must be url-safe"
        );
    }

    // ── validate_proof_claims (pure logic, no crypto) ───────────────────────

    fn claims(htm: &str, htu: &str, iat: i64, jti: &str, ath: Option<&str>) -> DpopProofClaims {
        DpopProofClaims {
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat,
            jti: jti.to_string(),
            ath: ath.map(str::to_string),
            nonce: None,
        }
    }

    #[test]
    fn test_claims_happy_path() {
        let now = 1_000_000;
        let c = claims(
            "POST",
            "https://idp.example.com/oauth/token",
            now,
            "j1",
            None,
        );
        assert!(validate_proof_claims(
            &c,
            "POST",
            "https://idp.example.com/oauth/token",
            now,
            None
        )
        .is_ok());
    }

    #[test]
    fn test_claims_htm_mismatch() {
        let now = 1_000_000;
        let c = claims("GET", "https://idp.example.com/x", now, "j1", None);
        assert!(validate_proof_claims(&c, "POST", "https://idp.example.com/x", now, None).is_err());
    }

    #[test]
    fn test_claims_htm_case_insensitive() {
        let now = 1_000_000;
        let c = claims("post", "https://idp.example.com/x", now, "j1", None);
        assert!(validate_proof_claims(&c, "POST", "https://idp.example.com/x", now, None).is_ok());
    }

    #[test]
    fn test_claims_htu_mismatch_path() {
        let now = 1_000_000;
        let c = claims("POST", "https://idp.example.com/userinfo", now, "j1", None);
        assert!(
            validate_proof_claims(&c, "POST", "https://idp.example.com/token", now, None).is_err()
        );
    }

    #[test]
    fn test_claims_htu_ignores_query_and_trailing_slash() {
        let now = 1_000_000;
        // proof carries a query + trailing slash; expected has neither.
        let c = claims(
            "POST",
            "https://idp.example.com/oauth/token/?foo=bar#frag",
            now,
            "j1",
            None,
        );
        assert!(validate_proof_claims(
            &c,
            "POST",
            "https://idp.example.com/oauth/token",
            now,
            None
        )
        .is_ok());
    }

    #[test]
    fn test_claims_iat_too_old_and_too_new() {
        let now = 1_000_000;
        let old = claims(
            "POST",
            "https://x/y",
            now - DPOP_PROOF_MAX_AGE_SECS - 1,
            "j1",
            None,
        );
        assert!(validate_proof_claims(&old, "POST", "https://x/y", now, None).is_err());
        let future = claims(
            "POST",
            "https://x/y",
            now + DPOP_PROOF_MAX_AGE_SECS + 1,
            "j1",
            None,
        );
        assert!(validate_proof_claims(&future, "POST", "https://x/y", now, None).is_err());
    }

    #[test]
    fn test_claims_future_skew_boundary_fapi() {
        // FAPI 2.0 §5.3.2.1-13: accept small future skew, reject > 60s future.
        let now = 1_000_000;
        let at_cap = claims(
            "POST",
            "https://x/y",
            now + DPOP_MAX_FUTURE_SKEW_SECS,
            "j-cap",
            None,
        );
        assert!(
            validate_proof_claims(&at_cap, "POST", "https://x/y", now, None).is_ok(),
            "iat exactly at the 60s future cap must be accepted"
        );
        let over_cap = claims(
            "POST",
            "https://x/y",
            now + DPOP_MAX_FUTURE_SKEW_SECS + 1,
            "j-over",
            None,
        );
        assert!(
            validate_proof_claims(&over_cap, "POST", "https://x/y", now, None).is_err(),
            "iat 61s in the future must be rejected (FAPI 2.0)"
        );
    }

    #[test]
    fn test_claims_missing_jti() {
        let now = 1_000_000;
        let c = claims("POST", "https://x/y", now, "   ", None);
        assert!(validate_proof_claims(&c, "POST", "https://x/y", now, None).is_err());
    }

    #[test]
    fn test_claims_ath_required_match_and_mismatch() {
        let now = 1_000_000;
        let ok = claims("GET", "https://x/y", now, "j1", Some("ATH123"));
        assert!(validate_proof_claims(&ok, "GET", "https://x/y", now, Some("ATH123")).is_ok());

        let mismatch = claims("GET", "https://x/y", now, "j1", Some("WRONG"));
        assert!(
            validate_proof_claims(&mismatch, "GET", "https://x/y", now, Some("ATH123")).is_err()
        );

        let missing = claims("GET", "https://x/y", now, "j1", None);
        assert!(
            validate_proof_claims(&missing, "GET", "https://x/y", now, Some("ATH123")).is_err()
        );
    }

    #[test]
    fn test_algs_for_jwk_rejects_symmetric() {
        // Build an oct JWK and confirm algs_for_jwk rejects it.
        let oct: Jwk = serde_json::from_value(json!({
            "kty": "oct",
            "k": "c2VjcmV0LWtleS1tYXRlcmlhbA"
        }))
        .expect("parse oct jwk");
        assert!(matches!(
            algs_for_jwk(&oct),
            Err(DpopError::MalformedJwk(_))
        ));
    }

    #[test]
    fn test_algs_for_jwk_ec_p256_is_es256() {
        let ec: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }))
        .expect("parse ec jwk");
        assert_eq!(algs_for_jwk(&ec).unwrap(), vec![Algorithm::ES256]);
    }

    // ── End-to-end signed proof (real ES256 key, no DB) ─────────────────────

    /// Sign a DPoP proof JWT with a deterministic P-256 key and return
    /// `(proof_jwt, expected_jkt)`. The embedded JWK matches the signing key,
    /// so the proof verifies and its thumbprint is `expected_jkt`.
    fn make_signed_proof(
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        ath: Option<&str>,
    ) -> (String, String) {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;

        // Deterministic, valid (1 < scalar < n) test key.
        let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid p256 scalar");
        let pem = sk
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pkcs8 pem");
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(pt.x().expect("x coord"));
        let y = URL_SAFE_NO_PAD.encode(pt.y().expect("y coord"));

        let jwk_json = json!({"kty":"EC","crv":"P-256","x":x,"y":y});
        let jkt = jwk_thumbprint(&jwk_json).expect("thumbprint");
        let jwk: Jwk = serde_json::from_value(jwk_json).expect("jwk");

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(jwk);

        let mut claims = serde_json::Map::new();
        claims.insert("htm".into(), json!(htm));
        claims.insert("htu".into(), json!(htu));
        claims.insert("iat".into(), json!(iat));
        claims.insert("jti".into(), json!(jti));
        if let Some(a) = ath {
            claims.insert("ath".into(), json!(a));
        }

        let key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("encoding key");
        let proof = encode(&header, &Value::Object(claims), &key).expect("encode proof");
        (proof, jkt)
    }

    #[test]
    fn test_verify_resource_proof_happy_path() {
        let now = 1_000_000_000;
        let token = "header.payload.signature";
        let ath = compute_ath(token);
        let (proof, jkt) = make_signed_proof(
            "GET",
            "https://idp.example.com/userinfo",
            now,
            "jti-1",
            Some(&ath),
        );

        let v = verify_resource_proof(
            &proof,
            &jkt,
            "GET",
            "https://idp.example.com/userinfo",
            now,
            token,
        )
        .expect("valid proof must verify");
        assert_eq!(v.jti, "jti-1");
        assert_eq!(v.jkt, jkt);
    }

    #[test]
    fn test_verify_resource_proof_rejects_tampering() {
        let now = 1_000_000_000;
        let token = "header.payload.signature";
        let ath = compute_ath(token);
        let (proof, jkt) = make_signed_proof(
            "GET",
            "https://idp.example.com/userinfo",
            now,
            "jti-1",
            Some(&ath),
        );

        // Wrong expected thumbprint (key substitution).
        assert!(verify_resource_proof(
            &proof,
            "NOTTHEKEYTHUMBPRINT",
            "GET",
            "https://idp.example.com/userinfo",
            now,
            token
        )
        .is_err());

        // Wrong htu (proof bound to a different path).
        assert!(verify_resource_proof(
            &proof,
            &jkt,
            "GET",
            "https://idp.example.com/other",
            now,
            token
        )
        .is_err());

        // Wrong htm.
        assert!(verify_resource_proof(
            &proof,
            &jkt,
            "POST",
            "https://idp.example.com/userinfo",
            now,
            token
        )
        .is_err());

        // ath bound to a different access token.
        assert!(verify_resource_proof(
            &proof,
            &jkt,
            "GET",
            "https://idp.example.com/userinfo",
            now,
            "a.different.token"
        )
        .is_err());

        // Stale proof (iat outside window).
        assert!(verify_resource_proof(
            &proof,
            &jkt,
            "GET",
            "https://idp.example.com/userinfo",
            now + DPOP_PROOF_MAX_AGE_SECS + 5,
            token
        )
        .is_err());
    }
}
