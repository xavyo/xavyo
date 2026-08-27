//! PostgreSQL integration tests for ext_authz.
//!
//! Run with: `cargo test -p xavyo-ext-authz --features integration`

mod common;

use tonic::Request;
use uuid::Uuid;
use xavyo_ext_authz::nhi_cache::NhiCache;
use xavyo_ext_authz::proto::authorization_server::Authorization;

use common::{
    check_request, create_test_agent, create_test_tenant, get_test_pool, tenant_id_type,
    test_service,
};

#[tokio::test]
async fn nhi_cache_loads_seeded_agent_from_postgres() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let agent = create_test_agent(&pool, tenant_id).await;

    let cache = NhiCache::new(60);
    let loaded = cache
        .get_or_load(&pool, tenant_id_type(tenant_id), agent.id)
        .await
        .expect("database query should succeed")
        .expect("seeded NHI should be found");

    assert_eq!(loaded.identity.id, agent.id);
    assert_eq!(loaded.identity.name, "integration-test-agent");
}

#[tokio::test]
async fn check_denies_when_nhi_is_missing() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let service = test_service(pool);
    let missing_subject = Uuid::new_v4();

    let response = service
        .check(Request::new(check_request(
            tenant_id,
            missing_subject,
            "GET",
            "/v1/tools",
        )))
        .await
        .expect("check RPC should return a response")
        .into_inner();

    let denied = match response.http_response {
        Some(xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(denied)) => {
            denied
        }
        other => panic!("expected denied response, got {other:?}"),
    };

    let body: serde_json::Value = serde_json::from_str(&denied.body).expect("valid JSON body");
    assert_eq!(body["error"], "nhi_not_found");
}

#[tokio::test]
async fn check_reaches_pdp_for_seeded_agent_and_denies_by_default() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let agent = create_test_agent(&pool, tenant_id).await;
    let service = test_service(pool);

    let response = service
        .check(Request::new(check_request(
            tenant_id,
            agent.id,
            "GET",
            "/v1/tools",
        )))
        .await
        .expect("check RPC should return a response")
        .into_inner();

    let denied = match response.http_response {
        Some(xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(denied)) => {
            denied
        }
        other => panic!("expected denied response without policies, got {other:?}"),
    };

    let body: serde_json::Value = serde_json::from_str(&denied.body).expect("valid JSON body");
    assert_eq!(body["error"], "authorization_denied");
    assert!(response.dynamic_metadata.is_some());
}
