//! Integration tests for RFC 8693 Token Exchange (NHI delegation).
//!
//! These tests verify the delegation grant model, JWT claims structure,
//! and scope/depth enforcement for the token exchange flow.
//!
//! Run with:
//! cargo test -p xavyo-api-oauth --features integration --test token_exchange_test
//!
//! Prerequisites:
//! - PostgreSQL running with migrations applied
//! - DATABASE_URL and DATABASE_URL_SUPERUSER environment variables set

mod common;

/// Delegation grant model tests (require DB).
#[cfg(feature = "integration")]
mod delegation_grants {
    use super::common::OAuthTestContext;
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use xavyo_db::models::nhi_delegation_grant::{CreateNhiDelegationGrant, NhiDelegationGrant};

    /// Helper: create a test NHI identity for the actor agent.
    async fn create_test_nhi(ctx: &OAuthTestContext, tenant_id: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nhi_identities (id, tenant_id, name, nhi_type, lifecycle_state, owner_id)
             VALUES ($1, $2, $3, 'agent', 'active', $1)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(&ctx.admin_pool)
        .await
        .expect("Failed to create test NHI");
        id
    }

    /// Helper: create a delegation grant with tenant context set.
    async fn create_grant(
        ctx: &OAuthTestContext,
        tenant_id: Uuid,
        principal_id: Uuid,
        actor_nhi_id: Uuid,
        scopes: Vec<String>,
        max_depth: Option<i32>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> NhiDelegationGrant {
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();

        let input = CreateNhiDelegationGrant {
            principal_id,
            principal_type: "user".to_string(),
            actor_nhi_id,
            allowed_scopes: scopes,
            allowed_resource_types: vec![],
            max_delegation_depth: max_depth,
            granted_by: None,
            expires_at,
        };
        NhiDelegationGrant::grant(&ctx.pool, tenant_id, input)
            .await
            .expect("Failed to create delegation grant")
    }

    #[tokio::test]
    async fn test_active_grant_scope_enforcement() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-scope-1",
                &format!("te-scope-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(tid, "scope1@test.com", "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "scope-agent-1").await;

        let grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string(), "write:tools".to_string()],
            Some(2),
            None,
        )
        .await;

        assert!(grant.is_active());
        assert!(grant.is_scope_allowed("read:tools"));
        assert!(grant.is_scope_allowed("write:tools"));
        assert!(!grant.is_scope_allowed("admin:everything"));
        assert!(!grant.is_scope_allowed("delete:tools"));
    }

    #[tokio::test]
    async fn test_wildcard_scopes_when_empty() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-wc-1",
                &format!("te-wc-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(tid, "wc1@test.com", "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "wc-agent-1").await;

        // Empty scopes = wildcard (all allowed)
        let grant = create_grant(&ctx, tenant_id, user_id, agent_id, vec![], None, None).await;

        assert!(grant.is_scope_allowed("anything"));
        assert!(grant.is_scope_allowed("admin:everything"));
    }

    #[tokio::test]
    async fn test_revoked_grant_not_found_by_find_active() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-rev-1",
                &format!("te-rev-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(tid, "rev1@test.com", "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "rev-agent-1").await;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();

        let grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string()],
            None,
            None,
        )
        .await;

        // Initially findable
        let found = NhiDelegationGrant::find_active(&ctx.pool, tenant_id, user_id, agent_id)
            .await
            .unwrap();
        assert!(found.is_some());

        // Revoke
        let revoked = NhiDelegationGrant::revoke(&ctx.pool, tenant_id, grant.id, None)
            .await
            .unwrap();
        assert!(revoked);

        // No longer findable
        let found = NhiDelegationGrant::find_active(&ctx.pool, tenant_id, user_id, agent_id)
            .await
            .unwrap();
        assert!(
            found.is_none(),
            "revoked grant must not be returned by find_active"
        );
    }

    #[tokio::test]
    async fn test_expired_grant_not_active() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-exp-1",
                &format!("te-exp-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(tid, "exp1@test.com", "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "exp-agent-1").await;

        let grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string()],
            None,
            Some(Utc::now() - Duration::hours(1)),
        )
        .await;

        assert!(!grant.is_active(), "expired grant must not be active");
    }

    #[tokio::test]
    async fn test_max_delegation_depth_stored() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-depth-1",
                &format!("te-depth-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(tid, "depth1@test.com", "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "depth-agent-1").await;

        let grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec![],
            Some(3),
            None,
        )
        .await;

        assert_eq!(grant.max_delegation_depth, 3);
    }

    #[tokio::test]
    async fn test_grant_upsert_updates_existing() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-upsert-1",
                &format!("te-upsert-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(
                tid,
                "upsert1@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "upsert-agent-1").await;

        let grant1 = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string()],
            Some(1),
            None,
        )
        .await;

        // Upsert with different scopes
        let grant2 = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["write:tools".to_string(), "admin:tools".to_string()],
            Some(2),
            None,
        )
        .await;

        // Same row was updated (same ID)
        assert_eq!(grant1.id, grant2.id);
        // Scopes were replaced
        assert_eq!(
            grant2.allowed_scopes,
            vec!["write:tools".to_string(), "admin:tools".to_string()]
        );
        assert!(grant2.is_scope_allowed("write:tools"));
        assert!(grant2.is_scope_allowed("admin:tools"));
        assert!(!grant2.is_scope_allowed("read:tools"));
        assert_eq!(grant2.max_delegation_depth, 2);
    }

    #[tokio::test]
    async fn test_find_by_id() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-fbi-1",
                &format!("te-fbi-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(
                tid,
                "fbi1@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "fbi-agent-1").await;

        let grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string()],
            None,
            None,
        )
        .await;

        // Find in correct tenant
        let found = NhiDelegationGrant::find_by_id(&ctx.pool, tenant_id, grant.id)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, grant.id);

        // Find with wrong tenant returns None
        let wrong_tenant = Uuid::new_v4();
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(wrong_tenant.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();
        let not_found = NhiDelegationGrant::find_by_id(&ctx.pool, wrong_tenant, grant.id)
            .await
            .unwrap();
        assert!(
            not_found.is_none(),
            "grant must not be found in a different tenant"
        );
    }

    #[tokio::test]
    async fn test_list_by_principal_pagination() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-lbp-1",
                &format!("te-lbp-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(
                tid,
                "lbp1@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;

        // Create 3 grants for the same principal but different actors
        let agent_a = create_test_nhi(&ctx, tenant_id, "lbp-agent-a").await;
        let agent_b = create_test_nhi(&ctx, tenant_id, "lbp-agent-b").await;
        let agent_c = create_test_nhi(&ctx, tenant_id, "lbp-agent-c").await;

        create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_a,
            vec!["read:a".to_string()],
            None,
            None,
        )
        .await;
        create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_b,
            vec!["read:b".to_string()],
            None,
            None,
        )
        .await;
        create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_c,
            vec!["read:c".to_string()],
            None,
            None,
        )
        .await;

        // Page 1: limit=2, offset=0 → 2 results
        let page1 =
            NhiDelegationGrant::list_by_principal(&ctx.pool, tenant_id, user_id, 2, 0)
                .await
                .unwrap();
        assert_eq!(page1.len(), 2);

        // Page 2: limit=2, offset=2 → 1 result
        let page2 =
            NhiDelegationGrant::list_by_principal(&ctx.pool, tenant_id, user_id, 2, 2)
                .await
                .unwrap();
        assert_eq!(page2.len(), 1);

        // All: limit=10, offset=0 → 3 results
        let all =
            NhiDelegationGrant::list_by_principal(&ctx.pool, tenant_id, user_id, 10, 0)
                .await
                .unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_list_by_actor() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-lba-1",
                &format!("te-lba-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let agent_id = create_test_nhi(&ctx, tenant_id, "lba-agent-1").await;

        // Create 2 grants for the same actor but different principals
        let user_a = ctx
            .create_user(
                tid,
                "lba-a@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;
        let user_b = ctx
            .create_user(
                tid,
                "lba-b@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;

        create_grant(
            &ctx,
            tenant_id,
            user_a,
            agent_id,
            vec!["read:a".to_string()],
            None,
            None,
        )
        .await;
        create_grant(
            &ctx,
            tenant_id,
            user_b,
            agent_id,
            vec!["read:b".to_string()],
            None,
            None,
        )
        .await;

        let results =
            NhiDelegationGrant::list_by_actor(&ctx.pool, tenant_id, agent_id, 10, 0)
                .await
                .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-clean-1",
                &format!("te-clean-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(
                tid,
                "clean1@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;

        // Active grant (no expiration)
        let agent_active = create_test_nhi(&ctx, tenant_id, "clean-agent-active").await;
        let active_grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_active,
            vec!["read:tools".to_string()],
            None,
            None,
        )
        .await;

        // Another grant that we'll force-expire via admin_pool
        let agent_expired = create_test_nhi(&ctx, tenant_id, "clean-agent-expired").await;
        let expired_grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_expired,
            vec!["write:tools".to_string()],
            None,
            None,
        )
        .await;

        // Force the second grant to be expired using admin_pool
        sqlx::query(
            "UPDATE nhi_delegation_grants SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
        )
        .bind(expired_grant.id)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

        // Run cleanup
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();
        let cleaned = NhiDelegationGrant::cleanup_expired(&ctx.pool, tenant_id)
            .await
            .unwrap();
        assert_eq!(cleaned, 1, "exactly one grant should have been cleaned up");

        // Verify the expired grant now has status='expired'
        let refetched_expired =
            NhiDelegationGrant::find_by_id(&ctx.pool, tenant_id, expired_grant.id)
                .await
                .unwrap()
                .expect("expired grant should still exist");
        assert_eq!(refetched_expired.status, "expired");

        // Verify the active grant is unchanged
        let refetched_active =
            NhiDelegationGrant::find_by_id(&ctx.pool, tenant_id, active_grant.id)
                .await
                .unwrap()
                .expect("active grant should still exist");
        assert_eq!(refetched_active.status, "active");
    }

    #[tokio::test]
    async fn test_cross_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;

        // Tenant A
        let tid_a = ctx
            .create_tenant(
                "te-iso-a",
                &format!("te-iso-a-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_a = *tid_a.as_uuid();
        let user_a = ctx
            .create_user(
                tid_a,
                "iso-a@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;
        let agent_a = create_test_nhi(&ctx, tenant_a, "iso-agent-a").await;

        let grant = create_grant(
            &ctx,
            tenant_a,
            user_a,
            agent_a,
            vec!["read:tools".to_string()],
            None,
            None,
        )
        .await;

        // Tenant B
        let tid_b = ctx
            .create_tenant(
                "te-iso-b",
                &format!("te-iso-b-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_b = *tid_b.as_uuid();

        // Set RLS context to tenant B
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_b.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();

        // find_active with tenant B should not see tenant A's grant
        let found_active =
            NhiDelegationGrant::find_active(&ctx.pool, tenant_b, user_a, agent_a)
                .await
                .unwrap();
        assert!(
            found_active.is_none(),
            "tenant B must not see tenant A's active grant"
        );

        // find_by_id with tenant B should not see tenant A's grant
        let found_by_id = NhiDelegationGrant::find_by_id(&ctx.pool, tenant_b, grant.id)
            .await
            .unwrap();
        assert!(
            found_by_id.is_none(),
            "tenant B must not see tenant A's grant by ID"
        );
    }

    #[tokio::test]
    async fn test_resource_type_enforcement() {
        let ctx = OAuthTestContext::new().await;
        let tid = ctx
            .create_tenant(
                "te-rt-1",
                &format!("te-rt-1-{}", OAuthTestContext::unique_id()),
            )
            .await;
        let tenant_id = *tid.as_uuid();
        let user_id = ctx
            .create_user(
                tid,
                "rt1@test.com",
                "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA",
            )
            .await;
        let agent_id = create_test_nhi(&ctx, tenant_id, "rt-agent-1").await;

        // Create grant with specific resource types (bypass helper to set allowed_resource_types)
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();

        let input = CreateNhiDelegationGrant {
            principal_id: user_id,
            principal_type: "user".to_string(),
            actor_nhi_id: agent_id,
            allowed_scopes: vec![],
            allowed_resource_types: vec!["api".to_string(), "database".to_string()],
            max_delegation_depth: None,
            granted_by: None,
            expires_at: None,
        };
        let grant = NhiDelegationGrant::grant(&ctx.pool, tenant_id, input)
            .await
            .expect("Failed to create grant with resource types");

        assert!(grant.is_resource_type_allowed("api"));
        assert!(grant.is_resource_type_allowed("database"));
        assert!(
            !grant.is_resource_type_allowed("storage"),
            "storage should not be allowed"
        );
    }
}

/// JWT claims and token structure tests (no DB required).
#[cfg(test)]
mod jwt_delegation_claims {
    use uuid::Uuid;
    use xavyo_auth::{ActorClaim, JwtClaims};

    #[test]
    fn test_delegated_token_has_act_and_scope() {
        let principal_id = Uuid::new_v4();
        let actor_nhi_id = Uuid::new_v4();
        let grant_id = Uuid::new_v4();

        let actor_claim = ActorClaim {
            sub: actor_nhi_id.to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject(principal_id.to_string())
            .issuer("https://idp.test.xavyo.com")
            .audience(vec!["test-client"])
            .tenant_uuid(Uuid::new_v4())
            .expires_in_secs(3600)
            .scope("read:tools write:tools")
            .act(actor_claim)
            .delegation_id(grant_id)
            .delegation_depth(1)
            .build();

        assert_eq!(claims.sub, principal_id.to_string());
        assert!(claims.is_delegated());
        assert_eq!(claims.actor_nhi_id(), Some(actor_nhi_id));
        assert_eq!(claims.delegation_id, Some(grant_id));
        assert_eq!(claims.delegation_depth, Some(1));
        assert_eq!(claims.scope.as_deref(), Some("read:tools write:tools"));
    }

    #[test]
    fn test_chained_delegation_chain() {
        let user_id = Uuid::new_v4();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        let inner = ActorClaim {
            sub: agent_a.to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };
        let outer = ActorClaim {
            sub: agent_b.to_string(),
            nhi_type: Some("agent".to_string()),
            act: Some(Box::new(inner)),
        };

        let claims = JwtClaims::builder()
            .subject(user_id.to_string())
            .issuer("test")
            .expires_in_secs(3600)
            .act(outer)
            .delegation_depth(2)
            .build();

        let chain = claims.delegation_chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], agent_b.to_string());
        assert_eq!(chain[1], agent_a.to_string());
    }

    #[test]
    fn test_non_delegated_token_has_no_act() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .build();

        assert!(!claims.is_delegated());
        assert!(claims.actor_nhi_id().is_none());
        assert!(claims.delegation_id.is_none());
        assert!(claims.delegation_depth.is_none());
        assert!(claims.scope.is_none());
        assert!(claims.delegation_chain().is_empty());
    }

    #[test]
    fn test_delegated_jwt_serialization_roundtrip() {
        let principal_id = Uuid::new_v4();
        let actor_nhi_id = Uuid::new_v4();
        let grant_id = Uuid::new_v4();

        let actor_claim = ActorClaim {
            sub: actor_nhi_id.to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject(principal_id.to_string())
            .issuer("https://idp.test.xavyo.com")
            .audience(vec!["test-client"])
            .tenant_uuid(Uuid::new_v4())
            .expires_in_secs(3600)
            .scope("read:tools")
            .act(actor_claim)
            .delegation_id(grant_id)
            .delegation_depth(1)
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        let restored: JwtClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.sub, claims.sub);
        assert_eq!(restored.act, claims.act);
        assert_eq!(restored.delegation_id, claims.delegation_id);
        assert_eq!(restored.delegation_depth, claims.delegation_depth);
        assert_eq!(restored.scope, claims.scope);
        assert!(restored.is_delegated());
        assert_eq!(restored.actor_nhi_id(), Some(actor_nhi_id));
    }

    #[test]
    fn test_scope_claim_absent_when_not_set() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        // scope should be omitted from JSON entirely (skip_serializing_if)
        assert!(
            !json.contains("\"scope\""),
            "scope field should not appear in JSON when None"
        );
    }

    #[test]
    fn test_actor_nhi_id_returns_none_for_invalid_uuid_in_act() {
        let actor_claim = ActorClaim {
            sub: "not-a-valid-uuid".to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .act(actor_claim)
            .build();

        assert!(claims.is_delegated());
        assert_eq!(
            claims.actor_nhi_id(),
            None,
            "actor_nhi_id should return None for non-UUID act.sub"
        );
    }

    #[test]
    fn test_empty_scope_serialization() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .scope("")
            .build();

        assert_eq!(claims.scope, Some(String::new()));

        let json = serde_json::to_string(&claims).unwrap();
        // Empty string scope IS serialized (only None is skipped)
        assert!(
            json.contains("\"scope\""),
            "empty-string scope should be serialized"
        );

        let restored: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.scope, Some(String::new()));
    }

    #[test]
    fn test_delegation_chain_single_actor() {
        let agent_id = Uuid::new_v4();
        let actor = ActorClaim {
            sub: agent_id.to_string(),
            nhi_type: None,
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .act(actor)
            .delegation_depth(1)
            .build();

        let chain = claims.delegation_chain();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], agent_id.to_string());
    }

    #[test]
    fn test_delegated_token_depth_zero() {
        // delegation_depth=0 is structurally valid
        let actor = ActorClaim {
            sub: Uuid::new_v4().to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .act(actor)
            .delegation_depth(0)
            .build();

        assert!(claims.is_delegated());
        assert_eq!(claims.delegation_depth, Some(0));
    }

    #[test]
    fn test_scope_with_multiple_spaces_preserved() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test")
            .expires_in_secs(3600)
            .scope("read:tools  write:tools   admin:tools")
            .build();

        assert_eq!(
            claims.scope.as_deref(),
            Some("read:tools  write:tools   admin:tools")
        );

        let json = serde_json::to_string(&claims).unwrap();
        let restored: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.scope, claims.scope);
    }
}

/// Token exchange HTTP flow tests (require DB + axum_test).
///
/// These tests exercise the full POST /oauth/token handler with
/// grant_type=urn:ietf:params:oauth:grant-type:token-exchange via axum_test.
#[cfg(feature = "integration")]
mod token_exchange_http {
    use super::common::OAuthTestContext;
    use axum::http::HeaderValue;
    use sqlx::PgPool;
    use uuid::Uuid;
    use xavyo_auth::JwtClaims;
    use xavyo_db::models::nhi_delegation_grant::{CreateNhiDelegationGrant, NhiDelegationGrant};

    // Keys and secret duplicated from the common module (which keeps them private).
    const TEST_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWvwXoegwG34YX
q+6MmsAfjZz2OZfBwbGVZSW0tiskb9UXZ2Rdz99ayewaKcLw1xwDcmI3BZWKcgfa
T2lnJbMeMv0SuewOAkZQ8ucZEScGHNcmBflGPUR/7ktUp55BJXFzkkqURqS3ORMp
Ds+4yx/GKez5HyOuK+gp0IxpoWhMMAGCA/7A3n3OLRbIkClK92u1sdCxtp5c9vEM
1oBK97p1qsPzRCUS3YLAnXAgbY8JOePbTdMrsqG2Y0/oXkjdGmcXH2KcMuRqnFql
qxegPR66n4k9LsBYk+dmKkDnAikOs0dpTWyaRI1POeLEOsjzfIL/xtZDOEK9QaaC
6S5ekP/dAgMBAAECggEACXmXvjk/nMX7aGz82TcX2NPemAZeMMZDKnP5Vv61PvzN
fMNZpmDctdjnv2w9DcTDhL7xh+pQsCtDLZhctGhE9iK3z+/CM842S7u8xVFT7dkt
t7zb4muS7OSWNQu1EXywQRaim+fFziNm/idpbIDN7jdv5uerZzToyooKbVBBHTq1
dbd+egtlLh6mGdAcpaw4CpURwH5+b5DwPwl2c8hYJKmGTEQj+FK8K9xSDVX0sov8
yseSTPo3Q1gp38lDJBZkNtxbzXORtjvTWldxI9FQtCLasedzX/HXqxh1c3qVbaVw
EZTqTSSmZX4VWD7YgweNSufxhyM5Nbd/vzaEhiFX6QKBgQDTycPQ7G0cImvnlCNX
RGMDYShHxXEe0iCoUDZoONNeVNqrs/MPVYlNiX3+Gy4VTmQpqGOAFr5afXVa3SSf
MDr+bhtJSK0MGNR/SmUsFvrCeDcDh2ZrbYFD69kEdALgM7VLs6YuBH1fJgmhhsjm
4X09bx1VpHEAh5+kSMwA6x2b1QKBgQC2NxiYQS1s005yZ2NcaO+gWk9gFpgQrvfL
C6nl/vt0wOy/P/0YApxAnQd+OQQfcfygQFj8/UZsAoI2HXj22x+ub5ZiJL/dZY6F
SarJQulNVODBsnrNHhUKLhH/mGxX3YB6pOPcX46/h6tJEM+xomBzMwXLkJPfUkkI
Gi9XRFH/6QKBgDqt1nFWcEyxRNBe/QO60OwoyS5JiDQP6Dh6MPjjdbzXKdcU/q0q
9+XhyGTVRwlkNOBN5XOh2Y/c3t0UFId+p3nDLBA78KY/YvD5vdpfa47iG+wAYeI1
7vDQscpIElvoN70Hw21QlSP9uAFnBNbjdv3EgY4vB5gr+5FbEhrXCdcZAoGAJ5Hf
bXD6BF/+8SkykqbXIuN5yUweycC1XwqxYpj00m3y+7VRqR0oAYAYWHjZRFrkmYhf
ytDVsi75R/cuha0gPClPZxDD+bhMMvXEeOBm+bws8uNnd5PIzeUjU3YuUQZxGDEm
qny16zHzKHLWJ6UzfNDfuU00T5L2+SN2lGTpycECgYEAmoV1LnfOnv7ytid8kHE8
tOmUhF0TRxS3K/I1d0EGkM0PcR4BVSxHYz0LU0ChL4SOYuo7yKzESChwdDRvm1MN
6vj1477kZXDY2XxVkiXZSD3kPRZ3RFTRIf4nObHi8sKMbGKkJUyDeN+n2SIvYST2
xxU7T7aU32bKZLygCDtwsN8=
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlr8F6HoMBt+GF6vujJrA
H42c9jmXwcGxlWUltLYrJG/VF2dkXc/fWsnsGinC8NccA3JiNwWVinIH2k9pZyWz
HjL9ErnsDgJGUPLnGREnBhzXJgX5Rj1Ef+5LVKeeQSVxc5JKlEaktzkTKQ7PuMsf
xins+R8jrivoKdCMaaFoTDABggP+wN59zi0WyJApSvdrtbHQsbaeXPbxDNaASve6
darD80QlEt2CwJ1wIG2PCTnj203TK7KhtmNP6F5I3RpnFx9inDLkapxapasXoD0e
up+JPS7AWJPnZipA5wIpDrNHaU1smkSNTznixDrI83yC/8bWQzhCvUGmgukuXpD/
3QIDAQAB
-----END PUBLIC KEY-----";

    const TEST_CSRF_SECRET: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0, 0xFE, 0xED, 0xFA, 0xCE, 0x0D, 0xD0, 0x0D, 0xAD, 0xAB, 0xCD, 0xEF, 0x01,
        0x23, 0x45, 0x67, 0x89,
    ];

    /// Helper: create a test NHI identity.
    async fn create_test_nhi(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nhi_identities (id, tenant_id, name, nhi_type, lifecycle_state, owner_id)
             VALUES ($1, $2, $3, 'agent', 'active', $1)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("Failed to create test NHI");
        id
    }

    /// Helper: create an OAuth client authorised for token-exchange.
    async fn create_exchange_client(
        ctx: &OAuthTestContext,
        tenant_id: Uuid,
        suffix: &str,
    ) -> (String, String) {
        let client_id_str = format!("te-client-{}-{}", suffix, &Uuid::new_v4().to_string()[..8]);
        let client_secret = "test-secret-very-long-enough-for-validation";
        let client_secret_hash = xavyo_auth::hash_password(client_secret).unwrap();
        let client_uuid = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO oauth_clients (id, tenant_id, client_id, client_secret_hash, name, client_type, redirect_uris, grant_types, scopes, is_active)
             VALUES ($1, $2, $3, $4, $5, 'confidential', $6, $7, $8, true)",
        )
        .bind(client_uuid)
        .bind(tenant_id)
        .bind(&client_id_str)
        .bind(&client_secret_hash)
        .bind(format!("Test Exchange Client {}", suffix))
        .bind(&vec!["https://example.com/callback"] as &[&str])
        .bind(&vec!["urn:ietf:params:oauth:grant-type:token-exchange"] as &[&str])
        .bind(&vec!["read:tools", "write:tools"] as &[&str])
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

        (client_id_str, client_secret.to_string())
    }

    /// Helper: create a delegation grant with correct RLS context.
    async fn create_grant(
        ctx: &OAuthTestContext,
        tenant_id: Uuid,
        principal_id: Uuid,
        actor_nhi_id: Uuid,
        scopes: Vec<String>,
        max_depth: Option<i32>,
    ) -> NhiDelegationGrant {
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&ctx.pool)
            .await
            .unwrap();

        let input = CreateNhiDelegationGrant {
            principal_id,
            principal_type: "user".to_string(),
            actor_nhi_id,
            allowed_scopes: scopes,
            allowed_resource_types: vec![],
            max_delegation_depth: max_depth,
            granted_by: None,
            expires_at: None,
        };
        NhiDelegationGrant::grant(&ctx.pool, tenant_id, input)
            .await
            .expect("Failed to create delegation grant")
    }

    /// Helper: build an OAuth state and axum_test server.
    fn build_server(ctx: &OAuthTestContext) -> axum_test::TestServer {
        let state = xavyo_api_oauth::router::OAuthState::new(
            ctx.pool.clone(),
            "https://idp.test.xavyo.com".to_string(),
            TEST_PRIVATE_KEY.as_bytes().to_vec(),
            TEST_PUBLIC_KEY.as_bytes().to_vec(),
            "test-key-1".to_string(),
            TEST_CSRF_SECRET.to_vec(),
        );
        let app = xavyo_api_oauth::router::oauth_router(state);
        axum_test::TestServer::new(app).expect("Failed to create test server")
    }

    /// Helper: sign a JWT for the given subject/tenant.
    fn sign_jwt(subject: Uuid, tenant_id: Uuid) -> String {
        let claims = JwtClaims::builder()
            .subject(subject.to_string())
            .issuer("https://idp.test.xavyo.com")
            .audience(vec!["test-client".to_string()])
            .tenant_uuid(tenant_id)
            .expires_in_secs(3600)
            .build();
        xavyo_auth::encode_token(&claims, TEST_PRIVATE_KEY.as_bytes()).unwrap()
    }

    /// Helper: sign a JWT with a specific delegation_depth already set.
    fn sign_jwt_with_depth(
        subject: Uuid,
        tenant_id: Uuid,
        depth: i32,
    ) -> String {
        let actor_claim = xavyo_auth::ActorClaim {
            sub: Uuid::new_v4().to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };
        let claims = JwtClaims::builder()
            .subject(subject.to_string())
            .issuer("https://idp.test.xavyo.com")
            .audience(vec!["test-client".to_string()])
            .tenant_uuid(tenant_id)
            .expires_in_secs(3600)
            .act(actor_claim)
            .delegation_depth(depth)
            .build();
        xavyo_auth::encode_token(&claims, TEST_PRIVATE_KEY.as_bytes()).unwrap()
    }

    // ---------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_token_exchange_happy_path() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-hp", &format!("te-http-hp-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("hp-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("hp-agent-{uid}")).await;

        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        let _grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string(), "write:tools".to_string()],
            Some(3),
        )
        .await;

        let user_jwt = sign_jwt(user_id, tenant_id);
        let agent_jwt = sign_jwt(agent_id, tenant_id);

        let server = build_server(&ctx);

        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
            ("scope", "read:tools"),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        assert!(body.get("access_token").is_some(), "response must contain access_token");
        assert_eq!(body["token_type"].as_str().unwrap(), "Bearer");
        assert_eq!(body["scope"].as_str().unwrap(), "read:tools");

        // Decode the returned access_token and verify delegation claims
        let access_token = body["access_token"].as_str().unwrap();
        let decoded = xavyo_auth::decode_token(access_token, TEST_PUBLIC_KEY.as_bytes()).unwrap();
        assert!(decoded.is_delegated(), "returned token must be delegated");
        assert_eq!(decoded.actor_nhi_id(), Some(agent_id));
        assert!(decoded.delegation_id.is_some(), "delegation_id must be set");
        assert_eq!(decoded.delegation_depth, Some(1));
    }

    #[tokio::test]
    async fn test_token_exchange_missing_subject_token() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-mst", &format!("te-http-mst-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("mst-agent-{uid}")).await;
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;
        let agent_jwt = sign_jwt(agent_id, tenant_id);

        let server = build_server(&ctx);

        // Omit subject_token entirely
        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn test_token_exchange_self_referential() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-self", &format!("te-http-self-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("self-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        let same_jwt = sign_jwt(user_id, tenant_id);

        let server = build_server(&ctx);

        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &same_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &same_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn test_token_exchange_cross_tenant() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        // Tenant A: the subject token's tenant
        let tid_a = ctx.create_tenant("te-http-ct-a", &format!("te-http-ct-a-{uid}")).await;
        let tenant_a = *tid_a.as_uuid();

        // Tenant B: the X-Tenant-ID we will send
        let tid_b = ctx.create_tenant("te-http-ct-b", &format!("te-http-ct-b-{uid}")).await;
        let tenant_b = *tid_b.as_uuid();

        let user_id = ctx
            .create_user(tid_a, &format!("ct-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_a, &format!("ct-agent-{uid}")).await;

        // Client lives on tenant B
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_b, &uid).await;

        // Sign user JWT with tenant A's UUID
        let user_jwt = sign_jwt(user_id, tenant_a);
        let agent_jwt = sign_jwt(agent_id, tenant_a);

        let server = build_server(&ctx);

        // Send X-Tenant-ID for tenant B, but the JWT carries tenant A
        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
            ("scope", "read:tools"),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_b.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        // Should be rejected because subject_token tid != X-Tenant-ID
        assert_ne!(
            response.status_code(),
            axum::http::StatusCode::OK,
            "cross-tenant exchange must fail"
        );
    }

    #[tokio::test]
    async fn test_token_exchange_no_active_grant() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-nag", &format!("te-http-nag-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("nag-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("nag-agent-{uid}")).await;
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        // Deliberately do NOT create a delegation grant

        let user_jwt = sign_jwt(user_id, tenant_id);
        let agent_jwt = sign_jwt(agent_id, tenant_id);

        let server = build_server(&ctx);

        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
            ("scope", "read:tools"),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        assert_ne!(
            response.status_code(),
            axum::http::StatusCode::OK,
            "exchange without active grant must fail"
        );
    }

    #[tokio::test]
    async fn test_token_exchange_scope_exceeded() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-se", &format!("te-http-se-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("se-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("se-agent-{uid}")).await;
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        // Grant only allows read:tools and write:tools
        let _grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string(), "write:tools".to_string()],
            Some(3),
        )
        .await;

        let user_jwt = sign_jwt(user_id, tenant_id);
        let agent_jwt = sign_jwt(agent_id, tenant_id);

        let server = build_server(&ctx);

        // Request scope "admin:everything" which is not in the grant
        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
            ("scope", "admin:everything"),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        assert_ne!(
            response.status_code(),
            axum::http::StatusCode::OK,
            "scope exceeding grant must fail"
        );
    }

    #[tokio::test]
    async fn test_token_exchange_depth_exceeded() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-de", &format!("te-http-de-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("de-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("de-agent-{uid}")).await;
        let (client_id_str, client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        // Grant allows max depth of 1
        let _grant = create_grant(
            &ctx,
            tenant_id,
            user_id,
            agent_id,
            vec!["read:tools".to_string()],
            Some(1),
        )
        .await;

        let user_jwt = sign_jwt(user_id, tenant_id);
        // Actor token already has delegation_depth=1 (simulating a chained delegation)
        let agent_jwt = sign_jwt_with_depth(agent_id, tenant_id, 1);

        let server = build_server(&ctx);

        // new_depth would be 2, exceeding max_delegation_depth=1
        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
            ("scope", "read:tools"),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        assert_ne!(
            response.status_code(),
            axum::http::StatusCode::OK,
            "delegation depth exceeding max must fail"
        );
    }

    #[tokio::test]
    async fn test_token_exchange_missing_client_secret() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("te-http-mcs", &format!("te-http-mcs-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let user_id = ctx
            .create_user(tid, &format!("mcs-{uid}@test.com"), "$argon2id$v=19$m=16,t=2,p=1$dGVzdA$TE/UbYA")
            .await;
        let agent_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("mcs-agent-{uid}")).await;
        let (client_id_str, _client_secret) = create_exchange_client(&ctx, tenant_id, &uid).await;

        let user_jwt = sign_jwt(user_id, tenant_id);
        let agent_jwt = sign_jwt(agent_id, tenant_id);

        let server = build_server(&ctx);

        // Omit client_secret
        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", &user_jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("actor_token", &agent_jwt),
            ("client_id", &client_id_str),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_unauthorized();
    }
}

/// OAuth client NHI-ID binding tests (require DB + axum_test).
///
/// These tests verify that an OAuth client can be bound to an NHI identity
/// and that client_credentials tokens use the NHI ID as the JWT subject.
#[cfg(feature = "integration")]
mod oauth_client_nhi_binding {
    use super::common::OAuthTestContext;
    use axum::http::HeaderValue;
    use sqlx::PgPool;
    use uuid::Uuid;

    // Keys and secret duplicated from the common module (which keeps them private).
    const TEST_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWvwXoegwG34YX
q+6MmsAfjZz2OZfBwbGVZSW0tiskb9UXZ2Rdz99ayewaKcLw1xwDcmI3BZWKcgfa
T2lnJbMeMv0SuewOAkZQ8ucZEScGHNcmBflGPUR/7ktUp55BJXFzkkqURqS3ORMp
Ds+4yx/GKez5HyOuK+gp0IxpoWhMMAGCA/7A3n3OLRbIkClK92u1sdCxtp5c9vEM
1oBK97p1qsPzRCUS3YLAnXAgbY8JOePbTdMrsqG2Y0/oXkjdGmcXH2KcMuRqnFql
qxegPR66n4k9LsBYk+dmKkDnAikOs0dpTWyaRI1POeLEOsjzfIL/xtZDOEK9QaaC
6S5ekP/dAgMBAAECggEACXmXvjk/nMX7aGz82TcX2NPemAZeMMZDKnP5Vv61PvzN
fMNZpmDctdjnv2w9DcTDhL7xh+pQsCtDLZhctGhE9iK3z+/CM842S7u8xVFT7dkt
t7zb4muS7OSWNQu1EXywQRaim+fFziNm/idpbIDN7jdv5uerZzToyooKbVBBHTq1
dbd+egtlLh6mGdAcpaw4CpURwH5+b5DwPwl2c8hYJKmGTEQj+FK8K9xSDVX0sov8
yseSTPo3Q1gp38lDJBZkNtxbzXORtjvTWldxI9FQtCLasedzX/HXqxh1c3qVbaVw
EZTqTSSmZX4VWD7YgweNSufxhyM5Nbd/vzaEhiFX6QKBgQDTycPQ7G0cImvnlCNX
RGMDYShHxXEe0iCoUDZoONNeVNqrs/MPVYlNiX3+Gy4VTmQpqGOAFr5afXVa3SSf
MDr+bhtJSK0MGNR/SmUsFvrCeDcDh2ZrbYFD69kEdALgM7VLs6YuBH1fJgmhhsjm
4X09bx1VpHEAh5+kSMwA6x2b1QKBgQC2NxiYQS1s005yZ2NcaO+gWk9gFpgQrvfL
C6nl/vt0wOy/P/0YApxAnQd+OQQfcfygQFj8/UZsAoI2HXj22x+ub5ZiJL/dZY6F
SarJQulNVODBsnrNHhUKLhH/mGxX3YB6pOPcX46/h6tJEM+xomBzMwXLkJPfUkkI
Gi9XRFH/6QKBgDqt1nFWcEyxRNBe/QO60OwoyS5JiDQP6Dh6MPjjdbzXKdcU/q0q
9+XhyGTVRwlkNOBN5XOh2Y/c3t0UFId+p3nDLBA78KY/YvD5vdpfa47iG+wAYeI1
7vDQscpIElvoN70Hw21QlSP9uAFnBNbjdv3EgY4vB5gr+5FbEhrXCdcZAoGAJ5Hf
bXD6BF/+8SkykqbXIuN5yUweycC1XwqxYpj00m3y+7VRqR0oAYAYWHjZRFrkmYhf
ytDVsi75R/cuha0gPClPZxDD+bhMMvXEeOBm+bws8uNnd5PIzeUjU3YuUQZxGDEm
qny16zHzKHLWJ6UzfNDfuU00T5L2+SN2lGTpycECgYEAmoV1LnfOnv7ytid8kHE8
tOmUhF0TRxS3K/I1d0EGkM0PcR4BVSxHYz0LU0ChL4SOYuo7yKzESChwdDRvm1MN
6vj1477kZXDY2XxVkiXZSD3kPRZ3RFTRIf4nObHi8sKMbGKkJUyDeN+n2SIvYST2
xxU7T7aU32bKZLygCDtwsN8=
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlr8F6HoMBt+GF6vujJrA
H42c9jmXwcGxlWUltLYrJG/VF2dkXc/fWsnsGinC8NccA3JiNwWVinIH2k9pZyWz
HjL9ErnsDgJGUPLnGREnBhzXJgX5Rj1Ef+5LVKeeQSVxc5JKlEaktzkTKQ7PuMsf
xins+R8jrivoKdCMaaFoTDABggP+wN59zi0WyJApSvdrtbHQsbaeXPbxDNaASve6
darD80QlEt2CwJ1wIG2PCTnj203TK7KhtmNP6F5I3RpnFx9inDLkapxapasXoD0e
up+JPS7AWJPnZipA5wIpDrNHaU1smkSNTznixDrI83yC/8bWQzhCvUGmgukuXpD/
3QIDAQAB
-----END PUBLIC KEY-----";

    const TEST_CSRF_SECRET: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0, 0xFE, 0xED, 0xFA, 0xCE, 0x0D, 0xD0, 0x0D, 0xAD, 0xAB, 0xCD, 0xEF, 0x01,
        0x23, 0x45, 0x67, 0x89,
    ];

    /// Helper: create a test NHI identity.
    async fn create_test_nhi(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nhi_identities (id, tenant_id, name, nhi_type, lifecycle_state, owner_id)
             VALUES ($1, $2, $3, 'agent', 'active', $1)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("Failed to create test NHI");
        id
    }

    /// Helper: build an OAuth state and axum_test server.
    fn build_server(ctx: &OAuthTestContext) -> axum_test::TestServer {
        let state = xavyo_api_oauth::router::OAuthState::new(
            ctx.pool.clone(),
            "https://idp.test.xavyo.com".to_string(),
            TEST_PRIVATE_KEY.as_bytes().to_vec(),
            TEST_PUBLIC_KEY.as_bytes().to_vec(),
            "test-key-1".to_string(),
            TEST_CSRF_SECRET.to_vec(),
        );
        let app = xavyo_api_oauth::router::oauth_router(state);
        axum_test::TestServer::new(app).expect("Failed to create test server")
    }

    /// Helper: insert an OAuth client with optional nhi_id.
    async fn create_client(
        ctx: &OAuthTestContext,
        tenant_id: Uuid,
        suffix: &str,
        nhi_id: Option<Uuid>,
    ) -> (String, String) {
        let client_id_str = format!("nhi-client-{}-{}", suffix, &Uuid::new_v4().to_string()[..8]);
        let client_secret = "test-secret-very-long-enough-for-validation";
        let client_secret_hash = xavyo_auth::hash_password(client_secret).unwrap();
        let client_uuid = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO oauth_clients (id, tenant_id, client_id, client_secret_hash, name, client_type, redirect_uris, grant_types, scopes, is_active, nhi_id)
             VALUES ($1, $2, $3, $4, $5, 'confidential', $6, $7, $8, true, $9)",
        )
        .bind(client_uuid)
        .bind(tenant_id)
        .bind(&client_id_str)
        .bind(&client_secret_hash)
        .bind(format!("NHI Bind Client {}", suffix))
        .bind(&vec!["https://example.com/callback"] as &[&str])
        .bind(&vec!["client_credentials"] as &[&str])
        .bind(&vec!["read:tools", "write:tools"] as &[&str])
        .bind(nhi_id)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

        (client_id_str, client_secret.to_string())
    }

    // ---------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_create_client_with_nhi_id() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("nhi-bind-1", &format!("nhi-bind-1-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let nhi_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("bind-nhi-{uid}")).await;

        let (client_id_str, _secret) = create_client(&ctx, tenant_id, &uid, Some(nhi_id)).await;

        // Verify the stored client has nhi_id set
        let row: (Option<Uuid>,) = sqlx::query_as(
            "SELECT nhi_id FROM oauth_clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(&client_id_str)
        .bind(tenant_id)
        .fetch_one(&ctx.admin_pool)
        .await
        .expect("client should exist");

        assert_eq!(row.0, Some(nhi_id), "nhi_id must be persisted on the client");
    }

    #[tokio::test]
    async fn test_client_credentials_uses_nhi_id_as_subject() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("nhi-cc-1", &format!("nhi-cc-1-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        let nhi_id = create_test_nhi(&ctx.admin_pool, tenant_id, &format!("cc-nhi-{uid}")).await;
        let (client_id_str, client_secret) = create_client(&ctx, tenant_id, &uid, Some(nhi_id)).await;

        let server = build_server(&ctx);

        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let access_token = body["access_token"].as_str().expect("access_token must be present");

        // Decode and verify the subject is the NHI ID, not the client_id
        let decoded = xavyo_auth::decode_token(access_token, TEST_PUBLIC_KEY.as_bytes()).unwrap();
        assert_eq!(
            decoded.sub,
            nhi_id.to_string(),
            "sub claim must be the NHI ID when nhi_id is bound"
        );
    }

    #[tokio::test]
    async fn test_client_credentials_without_nhi_id() {
        let ctx = OAuthTestContext::new().await;
        let uid = OAuthTestContext::unique_id();

        let tid = ctx.create_tenant("nhi-cc-2", &format!("nhi-cc-2-{uid}")).await;
        let tenant_id = *tid.as_uuid();

        // No nhi_id binding
        let (client_id_str, client_secret) = create_client(&ctx, tenant_id, &uid, None).await;

        let server = build_server(&ctx);

        let form_body = serde_urlencoded::to_string(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id_str),
            ("client_secret", &client_secret),
        ])
        .unwrap();

        let response = server
            .post("/token")
            .content_type("application/x-www-form-urlencoded")
            .add_header(
                "X-Tenant-ID",
                HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
            )
            .bytes(form_body.into())
            .await;

        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let access_token = body["access_token"].as_str().expect("access_token must be present");

        // Decode and verify the subject is the client_id (not an NHI)
        let decoded = xavyo_auth::decode_token(access_token, TEST_PUBLIC_KEY.as_bytes()).unwrap();
        assert_eq!(
            decoded.sub, client_id_str,
            "sub claim must be the client_id when no nhi_id is bound"
        );
    }
}
