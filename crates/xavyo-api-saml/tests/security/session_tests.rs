//! Session storage and InResponseTo validation tests

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use uuid::Uuid;
    use xavyo_api_saml::session::{
        AuthnRequestSession, InMemorySessionStore, SessionError, SessionStore,
    };

    // ============================================================
    // Session Creation Tests
    // ============================================================

    #[test]
    fn test_session_creation_with_defaults() {
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-abc123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        assert_eq!(session.tenant_id, tenant_id);
        assert_eq!(session.request_id, "req-abc123");
        assert_eq!(session.sp_entity_id, "https://sp.example.com");
        assert!(session.consumed_at.is_none());
        assert!(session.relay_state.is_none());
        // Default TTL is 5 minutes
        let expected_expiry = session.created_at + Duration::seconds(300);
        assert_eq!(session.expires_at, expected_expiry);
    }

    #[test]
    fn test_session_creation_with_relay_state() {
        let session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            Some("https://app.example.com/dashboard".to_string()),
        );

        assert_eq!(
            session.relay_state,
            Some("https://app.example.com/dashboard".to_string())
        );
    }

    #[test]
    fn test_session_creation_with_custom_ttl() {
        let session = AuthnRequestSession::with_ttl(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
            120, // 2 minute TTL
        );

        let expected_expiry = session.created_at + Duration::seconds(120);
        assert_eq!(session.expires_at, expected_expiry);
    }

    // ============================================================
    // Session Storage Tests
    // ============================================================

    #[tokio::test]
    async fn test_store_and_retrieve_session() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "req-store-test".to_string();

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.clone(),
            "https://sp.example.com".to_string(),
            Some("state123".to_string()),
        );

        // Store
        store.store(session).await.unwrap();

        // Retrieve
        let retrieved = store.get(tenant_id, &request_id).await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.request_id, request_id);
        assert_eq!(retrieved.relay_state, Some("state123".to_string()));
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        let retrieved = store.get(tenant_id, "nonexistent-request").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_duplicate_request_id_rejected() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "req-duplicate".to_string();

        let session1 = AuthnRequestSession::new(
            tenant_id,
            request_id.clone(),
            "https://sp1.example.com".to_string(),
            None,
        );

        let session2 = AuthnRequestSession::new(
            tenant_id,
            request_id.clone(),
            "https://sp2.example.com".to_string(),
            None,
        );

        // First store should succeed
        store.store(session1).await.unwrap();

        // Second store with same request ID should fail
        let result = store.store(session2).await;
        assert!(matches!(result, Err(SessionError::DuplicateRequestId(_))));
    }

    // ============================================================
    // InResponseTo Validation Tests
    // ============================================================

    #[tokio::test]
    async fn test_validate_matching_request_id() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let request_id = "_abc123-def456";

        let session = AuthnRequestSession::new(
            tenant_id,
            request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // Validate with matching InResponseTo
        let result = store.validate_and_consume(tenant_id, request_id).await;
        assert!(result.is_ok());

        let consumed = result.unwrap();
        assert_eq!(consumed.request_id, request_id);
        assert!(consumed.consumed_at.is_some());
    }

    #[tokio::test]
    async fn test_reject_unknown_request_id() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Store a valid session
        let session = AuthnRequestSession::new(
            tenant_id,
            "known-request".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        store.store(session).await.unwrap();

        // Try to validate with unknown InResponseTo
        let result = store
            .validate_and_consume(tenant_id, "unknown-request")
            .await;

        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_request_id_preserved_in_response() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let original_request_id = "_saml-request-id-12345";

        let session = AuthnRequestSession::new(
            tenant_id,
            original_request_id.to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // When consumed, the request_id should be preserved for use as InResponseTo
        let consumed = store
            .validate_and_consume(tenant_id, original_request_id)
            .await
            .unwrap();

        // This request_id would be used as InResponseTo in the SAMLResponse
        assert_eq!(consumed.request_id, original_request_id);
    }
}
