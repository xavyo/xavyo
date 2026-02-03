//! Azure AD (Entra ID) OIDC Interoperability Tests
//!
//! Tests verifying correct handling of Azure AD v2.0 token formats, multi-tenant
//! issuer patterns, and specific claims like tid, oid, and groups.

use super::common::*;
use serde_json::json;
use xavyo_api_oidc_federation::error::FederationError;
use xavyo_api_oidc_federation::services::{TokenVerifierService, VerificationConfig};

/// Azure AD-specific test fixtures
mod azure_fixtures {
    use super::*;

    /// Azure AD v2.0 issuer pattern
    pub fn issuer_v2(base_url: &str, tenant_id: &str) -> String {
        // In production: https://login.microsoftonline.com/{tenant}/v2.0
        // For testing, we use the mock server URL
        format!("{}/{}/v2.0", base_url, tenant_id)
    }

    /// Azure AD discovery document (v2.0)
    #[allow(dead_code)]
    pub fn discovery_document_v2(base_url: &str, tenant_id: &str) -> serde_json::Value {
        let issuer = issuer_v2(base_url, tenant_id);
        json!({
            "token_endpoint": format!("{}/{}/oauth2/v2.0/token", base_url, tenant_id),
            "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
            "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
            "response_modes_supported": ["query", "fragment", "form_post"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["code", "id_token", "code id_token", "id_token token"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "issuer": issuer,
            "request_uri_parameter_supported": false,
            "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
            "authorization_endpoint": format!("{}/{}/oauth2/v2.0/authorize", base_url, tenant_id),
            "device_authorization_endpoint": format!("{}/{}/oauth2/v2.0/devicecode", base_url, tenant_id),
            "http_logout_supported": true,
            "frontchannel_logout_supported": true,
            "end_session_endpoint": format!("{}/{}/oauth2/v2.0/logout", base_url, tenant_id),
            "claims_supported": ["sub", "iss", "cloud_instance_name", "cloud_instance_host_name", "cloud_graph_host_name", "msgraph_host", "aud", "exp", "iat", "auth_time", "acr", "nonce", "preferred_username", "name", "tid", "ver", "at_hash", "c_hash", "email"],
            "kerberos_endpoint": format!("{}/{}/kerberos", base_url, tenant_id),
            "tenant_region_scope": "NA",
            "cloud_instance_name": "microsoftonline.com",
            "cloud_graph_host_name": "graph.windows.net",
            "msgraph_host": "graph.microsoft.com",
            "rbac_url": "https://pas.windows.net"
        })
    }

    /// Azure AD JWKS (may include x5c certificate chain)
    pub fn jwks(kid: &str) -> serde_json::Value {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "x5t": kid, // Azure often uses same value for kid and x5t
                "alg": "RS256",
                "n": "uOs2bjkrVK1Vi6uSrZAGjy_YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm-C0p4syG93yBDeV7lC-U8zgSk94QHP4CilO9VShORDHG37iy1cU6o9PCto-z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi_tfKxSO7w75Zx8bqBuXZBmYcmay3ysdQN3l-PVIm4ic_CpuFLW0XmeTvlUp3R2JoSxVySh3faTq-18cspk7nBiW5mTpko2924GiIWMh_graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9jQ",
                "e": "AQAB"
                // Note: x5c would contain certificate chain in real Azure AD JWKS
            }]
        })
    }

    /// Create Azure AD-style claims with tenant and object IDs
    pub fn claims_with_azure_ids(
        sub: &str,
        issuer: &str,
        tenant_id: &str,
        object_id: &str,
        groups: Option<Vec<&str>>,
    ) -> TestClaims {
        let mut claims = TestClaims::new(
            sub,
            issuer,
            vec!["https://graph.microsoft.com/.default".to_string()],
        )
        .with_email(&format!("{}@contoso.onmicrosoft.com", sub))
        .with_claim("tid", json!(tenant_id))
        .with_claim("oid", json!(object_id))
        .with_claim("ver", json!("2.0"));

        if let Some(g) = groups {
            claims = claims.with_claim("groups", json!(g));
        }

        claims
    }
}

#[tokio::test]
async fn test_azure_ad_v2_valid_token() {
    let mock = IdpMockServer::new().await;
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let issuer = azure_fixtures::issuer_v2(&mock.base_url(), tenant_id);
    let kid = "azure-key-1";

    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "user@contoso.com",
        &issuer,
        vec!["https://graph.microsoft.com/.default".to_string()],
    );
    let token = create_test_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    let verified = result.unwrap();
    assert_eq!(verified.claims.sub, "user@contoso.com");
    assert!(verified.issuer.contains("v2.0"));
}

#[tokio::test]
async fn test_azure_ad_jwks_with_x5t() {
    let mock = IdpMockServer::new().await;
    let kid = "nOo3ZDrODXEK1jKWhXslHR_KXEg";

    // Azure AD JWKS includes x5t (thumbprint)
    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    let cache = xavyo_api_oidc_federation::services::JwksCache::default();
    let result = cache.get_keys(&mock.jwks_uri).await;

    assert!(result.is_ok());
    let jwks = result.unwrap();
    assert_eq!(jwks.keys.len(), 1);
    // Verify key can be found by kid
    let key = jwks.find_key(kid);
    assert!(key.is_some());
}

#[tokio::test]
async fn test_azure_ad_tid_oid_claims() {
    let mock = IdpMockServer::new().await;
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let object_id = "abc123-def456-ghi789";
    let issuer = azure_fixtures::issuer_v2(&mock.base_url(), tenant_id);
    let kid = "azure-key-1";

    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    let claims = azure_fixtures::claims_with_azure_ids(
        "user@contoso.com",
        &issuer,
        tenant_id,
        object_id,
        None,
    );
    let token = create_test_token_with_custom_claims(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
    // Token verified successfully with Azure-specific claims
}

#[tokio::test]
async fn test_azure_ad_groups_claim() {
    let mock = IdpMockServer::new().await;
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let issuer = azure_fixtures::issuer_v2(&mock.base_url(), tenant_id);
    let kid = "azure-key-1";

    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    // Azure AD groups are GUIDs
    let claims = azure_fixtures::claims_with_azure_ids(
        "user@contoso.com",
        &issuer,
        tenant_id,
        "abc123",
        Some(vec![
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ]),
    );
    let token = create_test_token_with_custom_claims(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_azure_ad_invalid_signature_rejected() {
    let mock = IdpMockServer::new().await;
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let issuer = azure_fixtures::issuer_v2(&mock.base_url(), tenant_id);
    let kid = "azure-key-1";

    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    let claims = TestClaims::new(
        "user@contoso.com",
        &issuer,
        vec!["https://graph.microsoft.com/.default".to_string()],
    );
    let token = create_invalid_signature_token(&claims, kid);

    let verifier = TokenVerifierService::new(VerificationConfig::default());
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            FederationError::TokenVerificationFailed(_)
        ),
        "Expected TokenVerificationFailed error"
    );
}

#[tokio::test]
async fn test_azure_ad_multi_tenant_issuer_validation() {
    let mock = IdpMockServer::new().await;
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let issuer = azure_fixtures::issuer_v2(&mock.base_url(), tenant_id);
    let kid = "azure-key-1";

    mock.mount_jwks(azure_fixtures::jwks(kid)).await;

    // Create token with correct issuer
    let claims = TestClaims::new(
        "user@contoso.com",
        &issuer,
        vec!["https://graph.microsoft.com/.default".to_string()],
    );
    let token = create_test_token(&claims, kid);

    // Verify with expected issuer matching
    let verifier = TokenVerifierService::new(VerificationConfig::default().issuer(&issuer));
    let result = verifier.verify_token(&token, &mock.jwks_uri).await;

    assert!(
        result.is_ok(),
        "Token verification failed: {:?}",
        result.err()
    );
}
