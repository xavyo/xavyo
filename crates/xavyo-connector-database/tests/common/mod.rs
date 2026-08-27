//! Shared helpers for connector-database PostgreSQL integration tests.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";
pub const USERS_TABLE: &str = "connector_db_itest_users";

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

pub async fn reset_users_table(pool: &PgPool) {
    sqlx::query(&format!("DROP TABLE IF EXISTS {USERS_TABLE}"))
        .execute(pool)
        .await
        .expect("failed to drop integration test table");

    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {USERS_TABLE} (
            id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            username TEXT NOT NULL UNIQUE,
            email TEXT
        )"
    ))
    .execute(pool)
    .await
    .expect("failed to create integration test table");

    sqlx::query(&format!("TRUNCATE TABLE {USERS_TABLE}"))
        .execute(pool)
        .await
        .expect("failed to truncate integration test table");
}
