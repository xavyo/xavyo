//! Auth layer stack for `/governance` routers.
//!
//! Axum `Router::layer` applies the **last** added layer as the outermost.
//! JWT auth must run *after* `Extension<JwtPublicKey>` and `Extension<PgPool>`
//! are inserted, matching oauth/users nests.

use axum::{middleware, Extension, Router};
use sqlx::PgPool;
use xavyo_api_auth::{api_key_auth_middleware, jwt_auth_middleware, JwtPublicKey};
use xavyo_tenant::TenantLayer;

/// Apply the production JWT/API-key stack used by both self-service and admin
/// governance routers.
pub fn apply_governance_auth_layers(
    router: Router,
    jwt_public_key: String,
    pool: PgPool,
) -> Router {
    router
        .layer(middleware::from_fn(jwt_auth_middleware))
        .layer(middleware::from_fn(api_key_auth_middleware))
        .layer(Extension(JwtPublicKey(jwt_public_key)))
        .layer(Extension(pool))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ))
}

/// Same layer *order* as production, with an in-memory revocation cache so
/// unit tests can authenticate without Postgres.
#[cfg(test)]
fn apply_governance_auth_layers_for_test(router: Router, jwt_public_key: String) -> Router {
    router
        .layer(middleware::from_fn(jwt_auth_middleware))
        .layer(middleware::from_fn(api_key_auth_middleware))
        .layer(Extension(JwtPublicKey(jwt_public_key)))
        .layer(Extension(xavyo_api_auth::RevocationCache::new_in_memory()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;
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

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOs2bjkrVK1Vi6uSrZAG
jy/YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm+C0p4syG93yBDeV7lC+U8zgSk9
4QHP4CilO9VShORDHG37iy1cU6o9PCto+z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy
4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi/tfKxSO7w75Zx8bqBuXZBmY
cmay3ysdQN3l+PVIm4ic/CpuFLW0XmeTvlUp3R2JoSxVySh3faTq+18cspk7nBiW
5mTpko2924GiIWMh/graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9
jQIDAQAB
-----END PUBLIC KEY-----";

    fn signed_user_jwt() -> (String, uuid::Uuid) {
        let tenant = TenantId::new();
        let tid = *tenant.as_uuid();
        let claims = JwtClaims::builder()
            .subject("reviewer-1")
            .issuer("xavyo")
            .audience(vec!["xavyo"])
            .tenant_id(tenant)
            .jwt_id("gov-stack-jti")
            .roles(vec!["user"])
            .expires_in_secs(3600)
            .build();
        (
            encode_token(&claims, TEST_PRIVATE_KEY).expect("sign test jwt"),
            tid,
        )
    }

    fn layered_governance_ping() -> Router {
        async fn ping(Extension(claims): Extension<JwtClaims>) -> String {
            claims.sub.clone()
        }
        apply_governance_auth_layers_for_test(
            Router::new().route("/governance/my-approvals", get(ping)),
            TEST_PUBLIC_KEY.to_string(),
        )
    }

    #[tokio::test]
    async fn signed_jwt_authenticates_layered_governance_route() {
        let (token, tid) = signed_user_jwt();
        let response = layered_governance_ping()
            .oneshot(
                Request::builder()
                    .uri("/governance/my-approvals")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Tenant-ID", tid.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"reviewer-1");
    }

    #[tokio::test]
    async fn missing_bearer_is_unauthorized_on_layered_governance_route() {
        let response = layered_governance_ping()
            .oneshot(
                Request::builder()
                    .uri("/governance/my-approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mismatched_tenant_header_is_unauthorized_on_layered_governance_route() {
        let (token, tid) = signed_user_jwt();
        let other = uuid::Uuid::new_v4();
        assert_ne!(tid, other);
        let response = layered_governance_ping()
            .oneshot(
                Request::builder()
                    .uri("/governance/my-approvals")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Tenant-ID", other.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dummy_signature_is_rejected_on_layered_governance_route() {
        let response = layered_governance_ping()
            .oneshot(
                Request::builder()
                    .uri("/governance/my-approvals")
                    .header(
                        "Authorization",
                        "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
