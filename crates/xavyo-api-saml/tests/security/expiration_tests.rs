//! TTL expiration and cleanup tests

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use xavyo_api_saml::session::{
        AuthnRequestSession, InMemorySessionStore, SessionError, SessionStore,
        CLOCK_SKEW_GRACE_SECONDS, DEFAULT_SESSION_TTL_SECONDS,
    };

    // ============================================================
    // Expiration Validation Tests
    // ============================================================

    #[test]
    fn test_fresh_session_not_expired() {
        let session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "fresh-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        assert!(!session.is_expired());
        assert!(session.validate().is_ok());
    }

    #[test]
    fn test_session_expires_after_ttl() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "expired-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        // Set expiration to 10 minutes ago (past TTL + grace period)
        session.expires_at = Utc::now() - Duration::minutes(10);

        assert!(session.is_expired());
        let result = session.validate();
        assert!(matches!(result, Err(SessionError::Expired { .. })));
    }

    #[test]
    fn test_grace_period_allows_slight_delay() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "grace-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        // Set expiration to 20 seconds ago (within 30-second grace period)
        session.expires_at = Utc::now() - Duration::seconds(20);

        // Should NOT be expired due to grace period
        assert!(!session.is_expired());
        assert!(session.validate().is_ok());
    }

    #[test]
    fn test_grace_period_exceeded() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "no-grace-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        // Set expiration to 35 seconds ago (past 30-second grace period)
        session.expires_at = Utc::now() - Duration::seconds(35);

        assert!(session.is_expired());
        assert!(matches!(
            session.validate(),
            Err(SessionError::Expired { .. })
        ));
    }

    #[test]
    fn test_default_ttl_value() {
        // Verify the default TTL constant
        assert_eq!(DEFAULT_SESSION_TTL_SECONDS, 300); // 5 minutes
    }

    #[test]
    fn test_grace_period_value() {
        // Verify the grace period constant
        assert_eq!(CLOCK_SKEW_GRACE_SECONDS, 30);
    }

    // ============================================================
    // Expiration Validation via Store Tests
    // ============================================================

    #[tokio::test]
    async fn test_consume_expired_session_rejected() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create an expired session
        let mut session = AuthnRequestSession::new(
            tenant_id,
            "expired-consume-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        session.expires_at = Utc::now() - Duration::minutes(1);

        store.store(session).await.unwrap();

        // Try to consume - should fail due to expiration
        let result = store
            .validate_and_consume(tenant_id, "expired-consume-req")
            .await;

        assert!(matches!(result, Err(SessionError::Expired { .. })));
    }

    #[tokio::test]
    async fn test_consume_within_grace_period_succeeds() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create a session that JUST expired (within grace period)
        let mut session = AuthnRequestSession::new(
            tenant_id,
            "grace-consume-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        session.expires_at = Utc::now() - Duration::seconds(15);

        store.store(session).await.unwrap();

        // Should succeed due to grace period
        let result = store
            .validate_and_consume(tenant_id, "grace-consume-req")
            .await;

        assert!(result.is_ok());
    }

    // ============================================================
    // Cleanup Tests
    // ============================================================

    #[tokio::test]
    async fn test_cleanup_removes_expired_sessions() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create sessions with different expiration states
        let mut expired_session = AuthnRequestSession::new(
            tenant_id,
            "expired-cleanup".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        expired_session.expires_at = Utc::now() - Duration::hours(1);

        let valid_session = AuthnRequestSession::new(
            tenant_id,
            "valid-cleanup".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(expired_session).await.unwrap();
        store.store(valid_session).await.unwrap();

        // Run cleanup
        let deleted = store.cleanup_expired().await.unwrap();
        assert_eq!(deleted, 1);

        // Verify expired session is gone
        let expired = store.get(tenant_id, "expired-cleanup").await.unwrap();
        assert!(expired.is_none());

        // Verify valid session still exists
        let valid = store.get(tenant_id, "valid-cleanup").await.unwrap();
        assert!(valid.is_some());
    }

    #[tokio::test]
    async fn test_cleanup_respects_grace_period() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create a session that expired but within grace period
        let mut within_grace = AuthnRequestSession::new(
            tenant_id,
            "within-grace-cleanup".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        within_grace.expires_at = Utc::now() - Duration::seconds(15);

        store.store(within_grace).await.unwrap();

        // Run cleanup - should NOT delete the within-grace session
        let deleted = store.cleanup_expired().await.unwrap();
        assert_eq!(deleted, 0);

        // Session should still exist
        let still_exists = store.get(tenant_id, "within-grace-cleanup").await.unwrap();
        assert!(still_exists.is_some());
    }

    #[tokio::test]
    async fn test_cleanup_multiple_expired() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create multiple expired sessions
        for i in 0..5 {
            let mut session = AuthnRequestSession::new(
                tenant_id,
                format!("expired-multi-{}", i),
                "https://sp.example.com".to_string(),
                None,
            );
            session.expires_at = Utc::now() - Duration::hours(1);
            store.store(session).await.unwrap();
        }

        // Create valid sessions
        for i in 0..3 {
            let session = AuthnRequestSession::new(
                tenant_id,
                format!("valid-multi-{}", i),
                "https://sp.example.com".to_string(),
                None,
            );
            store.store(session).await.unwrap();
        }

        // Run cleanup
        let deleted = store.cleanup_expired().await.unwrap();
        assert_eq!(deleted, 5);

        // Verify valid sessions still exist
        for i in 0..3 {
            let exists = store
                .get(tenant_id, &format!("valid-multi-{}", i))
                .await
                .unwrap();
            assert!(exists.is_some());
        }
    }
}
