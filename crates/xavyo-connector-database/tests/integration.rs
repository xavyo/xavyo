//! PostgreSQL integration tests for the database connector.
//!
//! Run with: `cargo test -p xavyo-connector-database --features integration -- --test-threads=1`

mod common;

use xavyo_connector::operation::{AttributeDelta, AttributeSet, Filter, PageRequest};
use xavyo_connector::traits::{CreateOp, DeleteOp, SchemaDiscovery, SearchOp, UpdateOp};
use xavyo_connector_database::config::{DatabaseConfig, DatabaseDriver};
use xavyo_connector_database::DatabaseConnector;

use common::{get_test_pool, reset_users_table, USERS_TABLE};

fn test_connector() -> DatabaseConnector {
    let config = DatabaseConfig::new(
        DatabaseDriver::PostgreSQL,
        "localhost",
        "xavyo_test",
        "xavyo",
    )
    .with_password("xavyo_test_password")
    .with_users_table(USERS_TABLE)
    .with_groups_table("connector_db_itest_groups_missing");

    DatabaseConnector::new(config).expect("valid database connector config")
}

#[tokio::test]
async fn postgres_connector_schema_and_crud_round_trip() {
    let pool = get_test_pool().await;
    reset_users_table(&pool).await;

    let connector = test_connector();

    let schema = connector
        .discover_schema()
        .await
        .expect("schema discovery should succeed");
    assert!(
        schema
            .object_classes
            .iter()
            .any(|oc| oc.name == USERS_TABLE || oc.native_name == USERS_TABLE),
        "users table should be discovered"
    );

    let mut attrs = AttributeSet::new();
    attrs.set("username", "alice");
    attrs.set("email", "alice@example.com");

    let uid = connector
        .create("user", attrs)
        .await
        .expect("create should succeed");

    let results = connector
        .search(
            "user",
            Some(Filter::eq("username", "alice")),
            None,
            Some(PageRequest::default()),
        )
        .await
        .expect("search should succeed");

    assert_eq!(results.objects.len(), 1);
    assert_eq!(
        results.objects[0].get_string("email"),
        Some("alice@example.com")
    );

    let mut changes = AttributeDelta::new();
    changes.replace("email", "alice.updated@example.com");

    let updated_uid = connector
        .update("user", &uid, changes)
        .await
        .expect("update should succeed");
    assert_eq!(updated_uid.value(), uid.value());

    connector
        .delete("user", &uid)
        .await
        .expect("delete should succeed");

    let after_delete = connector
        .search(
            "user",
            Some(Filter::eq("username", "alice")),
            None,
            Some(PageRequest::default()),
        )
        .await
        .expect("search after delete should succeed");

    assert!(after_delete.objects.is_empty());
}
