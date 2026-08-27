//! Shared helpers for SSF API PostgreSQL integration tests.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;
use xavyo_db::models::{CreateSsfStream, SsfStream};
use xavyo_ssf::SESSION_REVOKED_URI;

pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";
pub const POLL_DELIVERY_METHOD: &str = "urn:ietf:rfc:8936";

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
    let slug = format!("ssf-itest-{}", &tenant_id.to_string()[..8]);

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

pub async fn tenant_tx(pool: &PgPool, tenant_id: Uuid) -> Transaction<'_, Postgres> {
    let mut tx = pool.begin().await.expect("begin transaction");
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant RLS context");
    tx
}

pub async fn create_poll_stream(pool: &PgPool, tenant_id: Uuid) -> SsfStream {
    let mut tx = tenant_tx(pool, tenant_id).await;
    let stream = SsfStream::create(
        &mut *tx,
        CreateSsfStream {
            tenant_id,
            aud: "https://rp.example.com/ssf".to_string(),
            delivery_method: POLL_DELIVERY_METHOD.to_string(),
            endpoint_url: String::new(),
            delivery_authorization_header: None,
            events_requested: vec![SESSION_REVOKED_URI.to_string()],
            events_delivered: vec![SESSION_REVOKED_URI.to_string()],
            description: Some("ssf integration test stream".to_string()),
        },
    )
    .await
    .expect("create stream");
    tx.commit().await.expect("commit stream create");
    stream
}
