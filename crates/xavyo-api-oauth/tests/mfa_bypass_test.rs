//! Regression tests for the CRITICAL MFA-bypass fix (deep review §2.1).
//!
//! Purpose-bound tokens (e.g. the partial MFA-verification token issued before
//! a user completes MFA) share the same signing key / issuer / audience as a
//! full access token — only the `purpose` claim distinguishes them. OAuth
//! endpoints that accept an access token MUST reject purpose-bound tokens via
//! `JwtClaims::is_access_token()`, or an attacker holding a half-logged-in
//! partial token could exchange it / read profile data as if MFA were done.
//!
//! These tests exercise the `/oauth/userinfo` enforcement, which rejects the
//! token at the `purpose` guard BEFORE any database or revocation-cache access
//! — so they require no PostgreSQL and run in CI without the integration DB.
//! (The token-exchange enforcement at `token.rs:584/625` runs after DB-backed
//! client authentication, so it is covered by the DB-gated
//! `token_exchange_test.rs` suite under `--features integration`.)

use axum::{body::Body, http::Request};
use tower::ServiceExt;
use xavyo_api_oauth::router::oauth_router;
use xavyo_auth::{encode_token, JwtClaims};

mod common;
use common::create_test_state;

/// Matches the keypair embedded in `common::create_test_state` so signatures
/// produced here verify against the state's public key. TEST KEY ONLY.
const TEST_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWvwXoegwG34YX
q+6MmsAfjZz2OZfBwbGVZSW0tiskb9UXZ2Rdz99ayewaKcLw1xwDcmI3BZWKcgfa
T2lnJbMeMv0SuewOAkZQ8ucZEScGHNcmBflGPUR/7ktUp55BJXFzkkqURqS3ORMp
Ds+4yx/GKez5HyOuK+gp0IxpoWhMMAGCA/7A3n3OLRbIkClK92u1sdCxtp5c9vEM
1oBK97p1qsPzRCUS3YLAnXAgbY8JOePbTdMrsqG2Y0/oXkjdGmcXH2KcMuRqnFql
qxegPR66n4k9LsBYk+dmKkDnAikOs0dpTWyaRI1POeLEOsjzfIL/xtZDOEK9QaaC
6S5ekP/dAgMBAAECggEACXmXvjk/nMX7aGz82TcX2NPemAZeMMZDKnP5Vv61PvzN
fMNZpmDctdjnv2w9DcTDhL7xh+pQsCtDLZhctGhE9iK3z+/CM842S7u8xVFT7dkt
t7zb4muS7OSWNQu1EXywQRaim+fFziNm/idpbIDN7jdv5uerZzToyooKbVBBHTq1
dbd+egtlLh6mGdAcpaw4CpURwH5+b5DwPwl2c8hYJKmGTEQj+FK8K9xSDVX0sov8
yseSTPo3Q1gp38lDJBZkNtxbzXORtjvTWldxI9FQtCLasedzX/HXqxh1c3qVbaVw
EZTqTSSmZX4VWD7YgweNSufxhyM5Nbd/vzaEhiFX6QKBgQDTycPQ7G0cImvnlCNX
RGMDYShHxXEe0iCoUDZoONNeVNqrs/MPVYlNiX3+Gy4VTmQpqGOAFr5afXVa3SSf
MDr+bhtJSK0MGNR/SmUsFvrCeDcDh2ZrbYFD69kEdALgM7VLs6YuBH1fJgmhhsjm
4X09bx1VpHEAh5+kSMwA6x2b1QKBgQC2NxiYQS1s005yZ2NcaO+gWk9gFpgQrvfL
C6nl/vt0wOy/P/0YApxAnQd+OQQfcfygQFj8/UZsAoI2HXj22x+ub5ZiJL/dZY6F
SarJQulNVODBsnrNHhUKLhH/mGxX3YB6pOPcX46/h6tJEM+xomBzMwXLkJPfUkkI
Gi9XRFH/6QKBgDqt1nFWcEyxRNBe/QO60OwoyS5JiDQP6Dh6MPjjdbzXKdcU/q0q
9+XhyGTVRwlkNOBN5XOh2Y/c3t0UFId+p3nDLBA78KY/YvD5vdpfa47iG+wAYeI1
7vDQscpIElvoN70Hw21QlSP9uAFnBNbjdv3EgY4vB5gr+5FbEhrXCdcZAoGAJ5Hf
bXD6BF/+8SkykqbXIuN5yUweycC1XwqxYpj00m3y+7VRqR0oAYAYWHjZRFrkmYhf
ytDVsi75R/cuha0gPClPZxDD+bhMMvXEeOBm+bws8uNnd5PIzeUjU3YuUQZxGDEm
qny16zHzKHLWJ6UzfNDfuU00T5L2+SN2lGTpycECgYEAmoV1LnfOnv7ytid8kHE8
tOmUhF0TRxS3K/I1d0EGkM0PcR4BVSxHYz0LU0ChL4SOYuo7yKzESChwdDRvm1MN
6vj1477kZXDY2XxVkiXZSD3kPRZ3RFTRIf4nObHi8sKMbGKkJUyDeN+n2SIvYST2
xxU7T7aU32bKZLygCDtwsN8=
-----END PRIVATE KEY-----";

/// Sign a partial MFA-verification token (the token issued before MFA
/// completes). `purpose = "mfa_verification"` is the only thing that
/// distinguishes it from a full access token.
fn sign_partial_mfa_token() -> String {
    let claims = JwtClaims::builder()
        .subject(uuid::Uuid::new_v4().to_string())
        .issuer("https://idp.test.xavyo.com")
        .audience(vec!["test-client".to_string()])
        .tenant_uuid(uuid::Uuid::new_v4())
        .roles(Vec::<String>::new())
        .expires_in_secs(300)
        .purpose("mfa_verification")
        .build();
    encode_token(&claims, TEST_PRIVATE_KEY.as_bytes()).expect("sign partial MFA token")
}

/// A purpose-bound (partial MFA) token presented to `/oauth/userinfo` must be
/// rejected with 401 — NOT treated as a valid access token. This guards the
/// MFA-bypass fix: the `purpose` check returns before any DB/cache access.
#[tokio::test]
async fn userinfo_rejects_partial_mfa_token() {
    let state = create_test_state();
    let app = oauth_router(state);

    let token = sign_partial_mfa_token();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        401,
        "partial MFA token must be rejected at /oauth/userinfo (MFA-bypass guard)"
    );
}

/// Sign a normal access token that is sender-constrained via `cnf.jkt`
/// (DPoP-bound) but with NO `purpose` — a full access token.
fn sign_dpop_bound_token(jkt: &str) -> String {
    let claims = JwtClaims::builder()
        .subject(uuid::Uuid::new_v4().to_string())
        .issuer("https://idp.test.xavyo.com")
        .audience(vec!["test-client".to_string()])
        .tenant_uuid(uuid::Uuid::new_v4())
        .roles(vec!["user".to_string()])
        .expires_in_secs(3600)
        .dpop_jkt(jkt)
        .build();
    encode_token(&claims, TEST_PRIVATE_KEY.as_bytes()).expect("sign dpop-bound token")
}

/// DPoP downgrade guard (RFC 9449): a sender-constrained (`cnf.jkt`) token
/// presented to `/oauth/userinfo` WITHOUT a DPoP proof header must be rejected
/// with 401 — it cannot be used as a plain bearer token. This fires before any
/// DB access, so it runs without the integration database.
#[tokio::test]
async fn userinfo_rejects_dpop_bound_token_without_proof() {
    let state = create_test_state();
    let app = oauth_router(state);

    let token = sign_dpop_bound_token("sometestthumbprintvalue");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        401,
        "DPoP-bound token presented as bearer (no proof) must be rejected"
    );
}

/// A request with no bearer token is also rejected (sanity check that the
/// 401 above is about the purpose claim, not a missing-token side effect —
/// missing token is 401 too, but via a different path).
#[tokio::test]
async fn userinfo_rejects_missing_token() {
    let state = create_test_state();
    let app = oauth_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}
