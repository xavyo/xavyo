//! Shared helpers for ext_authz PostgreSQL integration tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_authorization::cache::{MappingCache, PolicyCache};
use xavyo_core::TenantId;
use xavyo_db::models::{CreateNhiIdentity, NhiIdentity};
use xavyo_ext_authz::config::ExtAuthzConfig;
use xavyo_ext_authz::proto;
use xavyo_ext_authz::server::ExtAuthzService;
use xavyo_nhi::NhiType;

pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";

pub async fn get_test_pool() -> PgPool {
    let database_url = std::env::var(TEST_DATABASE_URL_ENV)
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| {
            "postgres://xavyo:xavyo_test_password@localhost:5432/xavyo_test".to_string()
        });

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("failed to connect to test database")
}

pub async fn create_test_tenant(pool: &PgPool) -> Uuid {
    let tenant_id = Uuid::new_v4();
    let slug = format!("ext-authz-itest-{}", &tenant_id.to_string()[..8]);

    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, settings, created_at)
        VALUES ($1, $2, $3, '{}', NOW())
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(&slug)
    .bind(&slug)
    .execute(pool)
    .await
    .expect("failed to create test tenant");

    tenant_id
}

pub async fn create_test_agent(pool: &PgPool, tenant_id: Uuid) -> NhiIdentity {
    NhiIdentity::create(
        pool,
        tenant_id,
        CreateNhiIdentity {
            nhi_type: NhiType::Agent,
            name: "integration-test-agent".to_string(),
            description: Some("ext_authz integration test fixture".to_string()),
            owner_id: None,
            backup_owner_id: None,
            expires_at: None,
            inactivity_threshold_days: None,
            rotation_interval_days: None,
            created_by: None,
        },
    )
    .await
    .expect("failed to create test NHI agent")
}

pub fn test_service(pool: PgPool) -> ExtAuthzService {
    let config = ExtAuthzConfig {
        listen_addr: "127.0.0.1:0".parse().expect("valid listen addr"),
        database_url: String::new(),
        fail_open: false,
        risk_score_deny_threshold: 75,
        nhi_cache_ttl_secs: 60,
        activity_flush_interval_secs: 30,
        require_metadata_context: false,
    };

    ExtAuthzService::new(
        Arc::new(pool),
        &config,
        Arc::new(PolicyCache::new()),
        Arc::new(MappingCache::new()),
    )
}

pub fn check_request(
    tenant_id: Uuid,
    subject_id: Uuid,
    method: &str,
    path: &str,
) -> proto::CheckRequest {
    let mut jwt_fields = BTreeMap::new();
    jwt_fields.insert(
        "sub".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                subject_id.to_string(),
            )),
        },
    );
    jwt_fields.insert(
        "tid".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(tenant_id.to_string())),
        },
    );
    jwt_fields.insert(
        "roles".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue { values: vec![] },
            )),
        },
    );

    let jwt_payload = prost_types::Value {
        kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
            fields: jwt_fields,
        })),
    };

    let mut jwt_authn_fields = BTreeMap::new();
    jwt_authn_fields.insert("jwt_payload".to_string(), jwt_payload);

    let mut filter_metadata = HashMap::new();
    filter_metadata.insert(
        "envoy.filters.http.jwt_authn".to_string(),
        prost_types::Struct {
            fields: jwt_authn_fields,
        },
    );

    proto::CheckRequest {
        attributes: Some(proto::AttributeContext {
            source: None,
            destination: None,
            request: Some(proto::attribute_context::Request {
                time: None,
                http: Some(proto::attribute_context::HttpRequest {
                    id: String::new(),
                    method: method.to_string(),
                    headers: Default::default(),
                    path: path.to_string(),
                    host: String::new(),
                    scheme: String::new(),
                    query: String::new(),
                    fragment: String::new(),
                    size: 0,
                    protocol: String::new(),
                    body: String::new(),
                    raw_body: vec![],
                }),
            }),
            context_extensions: Default::default(),
            metadata_context: Some(proto::Metadata { filter_metadata }),
            tls_session: None,
        }),
    }
}

pub fn tenant_id_type(tenant_id: Uuid) -> TenantId {
    TenantId::from_uuid(tenant_id)
}
