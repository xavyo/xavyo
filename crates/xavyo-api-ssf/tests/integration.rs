//! PostgreSQL integration tests for the SSF Transmitter API.
//!
//! Run with: `cargo test -p xavyo-api-ssf --features integration`

mod common;

use serde_json::json;
use uuid::Uuid;
use xavyo_db::models::{SsfQueuedEvent, SsfStream, SsfSubject, STREAM_STATUS_PAUSED};
use xavyo_ssf::SESSION_REVOKED_URI;

use common::{create_poll_stream, create_test_tenant, get_test_pool, tenant_tx};

#[tokio::test]
async fn stream_create_list_get_status_delete_round_trip() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let stream = create_poll_stream(&pool, tenant_id).await;

    {
        let mut tx = tenant_tx(&pool, tenant_id).await;
        let listed = SsfStream::list_by_tenant(&mut *tx, tenant_id)
            .await
            .expect("list streams");
        assert!(listed.iter().any(|s| s.stream_id == stream.stream_id));

        let fetched = SsfStream::get(&mut *tx, tenant_id, stream.stream_id)
            .await
            .expect("get stream")
            .expect("stream must exist");
        assert_eq!(fetched.status, "enabled");
        assert_eq!(fetched.events_delivered, vec![SESSION_REVOKED_URI]);

        let paused =
            SsfStream::update_status(&mut *tx, tenant_id, stream.stream_id, STREAM_STATUS_PAUSED)
                .await
                .expect("update status")
                .expect("updated row");
        assert_eq!(paused.status, STREAM_STATUS_PAUSED);

        let deleted = SsfStream::delete(&mut *tx, tenant_id, stream.stream_id)
            .await
            .expect("delete stream");
        assert!(deleted);

        let missing = SsfStream::get(&mut *tx, tenant_id, stream.stream_id)
            .await
            .expect("get after delete");
        assert!(missing.is_none());
        tx.commit().await.expect("commit");
    }
}

#[tokio::test]
async fn subject_add_list_remove_round_trip() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let stream = create_poll_stream(&pool, tenant_id).await;
    let subject = json!({
        "format": "email",
        "email": "alice@example.com"
    });

    let mut tx = tenant_tx(&pool, tenant_id).await;
    let added = SsfSubject::add(&mut *tx, tenant_id, stream.stream_id, &subject)
        .await
        .expect("add subject");
    assert_eq!(added.subject, subject);

    let listed = SsfSubject::list_for_stream(&mut *tx, tenant_id, stream.stream_id)
        .await
        .expect("list subjects");
    assert_eq!(listed.len(), 1);

    let removed = SsfSubject::remove(&mut *tx, tenant_id, stream.stream_id, &subject)
        .await
        .expect("remove subject");
    assert_eq!(removed, 1);

    let empty = SsfSubject::list_for_stream(&mut *tx, tenant_id, stream.stream_id)
        .await
        .expect("list after remove");
    assert!(empty.is_empty());
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn poll_queue_enqueue_poll_ack() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let stream = create_poll_stream(&pool, tenant_id).await;
    let jti = Uuid::new_v4().to_string();

    let mut tx = tenant_tx(&pool, tenant_id).await;
    SsfQueuedEvent::enqueue(
        &mut *tx,
        tenant_id,
        stream.stream_id,
        &jti,
        "header.payload.signature",
    )
    .await
    .expect("enqueue SET");

    let batch = SsfQueuedEvent::poll(&mut *tx, tenant_id, stream.stream_id, 10)
        .await
        .expect("poll queue");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].jti, jti);

    let acked = SsfQueuedEvent::ack(&mut *tx, tenant_id, stream.stream_id, &[jti.clone()])
        .await
        .expect("ack SET");
    assert_eq!(acked, 1);

    let empty = SsfQueuedEvent::poll(&mut *tx, tenant_id, stream.stream_id, 10)
        .await
        .expect("poll after ack");
    assert!(empty.is_empty());
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn list_enabled_for_event_respects_status_and_uri() {
    let pool = get_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let stream = create_poll_stream(&pool, tenant_id).await;

    let mut tx = tenant_tx(&pool, tenant_id).await;
    let enabled = SsfStream::list_enabled_for_event(&mut *tx, tenant_id, SESSION_REVOKED_URI)
        .await
        .expect("list enabled");
    assert!(enabled.iter().any(|s| s.stream_id == stream.stream_id));

    SsfStream::update_status(&mut *tx, tenant_id, stream.stream_id, STREAM_STATUS_PAUSED)
        .await
        .expect("pause stream");

    let after_pause = SsfStream::list_enabled_for_event(&mut *tx, tenant_id, SESSION_REVOKED_URI)
        .await
        .expect("list after pause");
    assert!(!after_pause.iter().any(|s| s.stream_id == stream.stream_id));
    tx.commit().await.expect("commit");
}
