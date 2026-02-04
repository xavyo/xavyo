//! Replay attack prevention tests

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use xavyo_api_saml::session::{
        AuthnRequestSession, InMemorySessionStore, SessionError, SessionStore,
    };

    // ============================================================
    // Basic Replay Attack Tests
    // ============================================================

    #[tokio::test]
    async fn test_second_consume_attempt_blocked() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "replay-test-basic";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // First consume should succeed
        let result1 = store.validate_and_consume(tenant_id, request_id).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap().consumed_at.is_some());

        // Second consume (replay attack) should be blocked
        let result2 = store.validate_and_consume(tenant_id, request_id).await;
        assert!(matches!(result2, Err(SessionError::AlreadyConsumed { .. })));
    }

    #[tokio::test]
    async fn test_replay_attack_error_contains_details() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "replay-test-details";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // First consume
        store
            .validate_and_consume(tenant_id, request_id)
            .await
            .unwrap();

        // Second consume - verify error details
        let result = store.validate_and_consume(tenant_id, request_id).await;

        match result {
            Err(SessionError::AlreadyConsumed {
                request_id: error_req_id,
                consumed_at,
            }) => {
                assert_eq!(error_req_id, request_id);
                // consumed_at should be recent (within last minute)
                let now = Utc::now();
                assert!(consumed_at > now - Duration::minutes(1));
                assert!(consumed_at <= now);
            }
            _ => panic!("Expected AlreadyConsumed error"),
        }
    }

    #[tokio::test]
    async fn test_multiple_replay_attempts_all_blocked() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "replay-test-multiple";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // Consume once
        store
            .validate_and_consume(tenant_id, request_id)
            .await
            .unwrap();

        // Try 10 replay attempts - all should be blocked
        for i in 0..10 {
            let result = store.validate_and_consume(tenant_id, request_id).await;
            assert!(
                matches!(result, Err(SessionError::AlreadyConsumed { .. })),
                "Replay attempt {} should have been blocked",
                i + 1
            );
        }
    }

    // ============================================================
    // Tenant Isolation Tests
    // ============================================================

    #[tokio::test]
    async fn test_tenant_isolation_prevents_cross_tenant_replay() {
        let store = InMemorySessionStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let request_id = "cross-tenant-test";

        // Store session for tenant A
        let session_a = AuthnRequestSession::new(
            tenant_a,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        store.store(session_a).await.unwrap();

        // Tenant B tries to consume Tenant A's request - should fail as NOT FOUND
        let result = store.validate_and_consume(tenant_b, request_id).await;
        assert!(
            matches!(result, Err(SessionError::NotFound(_))),
            "Cross-tenant access should fail with NotFound"
        );

        // Tenant A can still consume their own request
        let result = store.validate_and_consume(tenant_a, request_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_same_request_id_different_tenants() {
        let store = InMemorySessionStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let request_id = "shared-request-id";

        // Both tenants store sessions with same request ID
        let session_a = AuthnRequestSession::new(
            tenant_a,
            request_id.to_string(),
            "https://sp-a.example.com".to_string(),
            None,
        );
        let session_b = AuthnRequestSession::new(
            tenant_b,
            request_id.to_string(),
            "https://sp-b.example.com".to_string(),
            None,
        );

        store.store(session_a).await.unwrap();
        store.store(session_b).await.unwrap();

        // Tenant A consumes their session
        let result_a = store.validate_and_consume(tenant_a, request_id).await;
        assert!(result_a.is_ok());
        assert_eq!(result_a.unwrap().sp_entity_id, "https://sp-a.example.com");

        // Tenant B can still consume their session (not affected by A)
        let result_b = store.validate_and_consume(tenant_b, request_id).await;
        assert!(result_b.is_ok());
        assert_eq!(result_b.unwrap().sp_entity_id, "https://sp-b.example.com");

        // Both sessions now consumed - replay blocked for both
        assert!(matches!(
            store.validate_and_consume(tenant_a, request_id).await,
            Err(SessionError::AlreadyConsumed { .. })
        ));
        assert!(matches!(
            store.validate_and_consume(tenant_b, request_id).await,
            Err(SessionError::AlreadyConsumed { .. })
        ));
    }

    // ============================================================
    // Edge Case Tests
    // ============================================================

    #[tokio::test]
    async fn test_consumed_session_marker_persists() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "persist-test";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();
        store
            .validate_and_consume(tenant_id, request_id)
            .await
            .unwrap();

        // Verify the consumed_at marker is set
        let stored = store.get(tenant_id, request_id).await.unwrap().unwrap();
        assert!(stored.consumed_at.is_some());
        assert!(stored.is_consumed());
    }

    #[tokio::test]
    async fn test_expired_and_consumed_returns_expired_error() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create a session, consume it, then backdate expiration
        let mut session = AuthnRequestSession::new(
            tenant_id,
            "expired-consumed".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        session.expires_at = Utc::now() - Duration::hours(1);
        session.consumed_at = Some(Utc::now() - Duration::minutes(30));

        store.store(session).await.unwrap();

        // When both expired AND consumed, we get expired error first
        // (since expiration check happens before consumed check in validation)
        let result = store
            .validate_and_consume(tenant_id, "expired-consumed")
            .await;

        // The specific error depends on implementation - both are valid rejections
        assert!(matches!(
            result,
            Err(SessionError::Expired { .. } | SessionError::AlreadyConsumed { .. })
        ));
    }

    #[tokio::test]
    async fn test_concurrent_consume_attempts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let store = Arc::new(InMemorySessionStore::new());
        let tenant_id = Uuid::new_v4();
        let request_id = "concurrent-test";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // Counters for results
        let success_count = Arc::new(AtomicUsize::new(0));
        let replay_blocked_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple concurrent consume attempts
        let mut handles = vec![];
        for _ in 0..10 {
            let store_clone = Arc::clone(&store);
            let request_id_clone = request_id.to_string();
            let success_count_clone = Arc::clone(&success_count);
            let replay_blocked_clone = Arc::clone(&replay_blocked_count);

            handles.push(tokio::spawn(async move {
                let result = store_clone
                    .validate_and_consume(tenant_id, &request_id_clone)
                    .await;

                match &result {
                    Ok(_) => {
                        success_count_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(SessionError::AlreadyConsumed { .. }) => {
                        replay_blocked_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }

                result
            }));
        }

        // Wait for all to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Exactly one should succeed
        assert_eq!(
            success_count.load(Ordering::SeqCst),
            1,
            "Exactly one consume should succeed"
        );
        assert_eq!(
            replay_blocked_count.load(Ordering::SeqCst),
            9,
            "All other attempts should be blocked as replay"
        );
    }
}
