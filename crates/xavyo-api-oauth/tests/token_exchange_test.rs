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
}
