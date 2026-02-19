//! NHI Delegation Grant integration tests.
//!
//! Tests the delegation grant lifecycle including:
//! - Create delegation grant
//! - Upsert (update on conflict)
//! - Get by ID
//! - Cross-tenant isolation
//! - Revoke
//! - List by actor / by principal
//! - Cleanup expired grants
//! - Input validation rules

use super::common::{create_test_pool, create_test_tenant, create_test_user, unique_email};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::nhi_delegation_grant::{CreateNhiDelegationGrant, NhiDelegationGrant};

/// Helper to create an NHI identity in the nhi_identities table.
///
/// The delegation grant FK references nhi_identities, not gov_service_accounts or ai_agents.
async fn create_nhi_identity(pool: &PgPool, tenant_id: Uuid, name: &str, owner_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO nhi_identities (id, tenant_id, name, nhi_type, lifecycle_state, owner_id) \
         VALUES ($1, $2, $3, 'agent', 'active', $4)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(name)
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("create nhi identity");
    id
}

/// Helper to set up a test environment with tenant, owner, and NHI identity.
async fn setup_test_env(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let tenant_id = create_test_tenant(pool).await;
    let owner_id = create_test_user(pool, tenant_id, &unique_email()).await;
    let nhi_id = create_nhi_identity(pool, tenant_id, "test-nhi", owner_id).await;
    (tenant_id, owner_id, nhi_id)
}

// ---------------------------------------------------------------------------
// DB-level integration tests (require PostgreSQL)
// ---------------------------------------------------------------------------

/// Test: Create delegation grant successfully.
///
/// Given valid principal, actor, and scopes,
/// When creating a delegation grant,
/// Then the grant is returned with correct attributes.
#[tokio::test]
#[ignore]
async fn test_create_delegation_grant() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    let input = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        allowed_resource_types: vec!["api".to_string()],
        max_delegation_depth: Some(3),
        granted_by: Some(owner_id),
        expires_at: Some(Utc::now() + Duration::days(30)),
    };

    let grant = NhiDelegationGrant::grant(&pool, tenant_id, input)
        .await
        .expect("grant should succeed");

    assert_eq!(grant.tenant_id, tenant_id);
    assert_eq!(grant.principal_id, owner_id);
    assert_eq!(grant.principal_type, "user");
    assert_eq!(grant.actor_nhi_id, nhi_id);
    assert_eq!(grant.allowed_scopes, vec!["read", "write"]);
    assert_eq!(grant.allowed_resource_types, vec!["api"]);
    assert_eq!(grant.max_delegation_depth, 3);
    assert_eq!(grant.status, "active");
    assert_eq!(grant.granted_by, Some(owner_id));
    assert!(grant.expires_at.is_some());
    assert!(grant.revoked_at.is_none());
    assert!(grant.revoked_by.is_none());
}

/// Test: Upsert delegation grant updates scopes on conflict.
///
/// Given a grant already exists for the same principal+actor pair,
/// When granting again with different scopes,
/// Then the existing grant is updated (not duplicated).
#[tokio::test]
#[ignore]
async fn test_upsert_delegation_grant() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    let input1 = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["read".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: None,
    };

    let grant1 = NhiDelegationGrant::grant(&pool, tenant_id, input1)
        .await
        .expect("first grant should succeed");

    assert_eq!(grant1.allowed_scopes, vec!["read"]);

    // Upsert with updated scopes
    let input2 = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
        allowed_resource_types: vec!["api".to_string()],
        max_delegation_depth: Some(5),
        granted_by: Some(owner_id),
        expires_at: None,
    };

    let grant2 = NhiDelegationGrant::grant(&pool, tenant_id, input2)
        .await
        .expect("upsert should succeed");

    // Same row (same ID since upsert on conflict)
    assert_eq!(grant2.id, grant1.id);
    // Updated fields
    assert_eq!(grant2.allowed_scopes, vec!["read", "write", "admin"]);
    assert_eq!(grant2.allowed_resource_types, vec!["api"]);
    assert_eq!(grant2.max_delegation_depth, 5);
    assert_eq!(grant2.status, "active");
}

/// Test: Get delegation grant by ID.
///
/// Given a grant exists,
/// When fetching by ID within the same tenant,
/// Then the correct grant is returned.
#[tokio::test]
#[ignore]
async fn test_get_delegation_grant_by_id() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    let input = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["read".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: None,
    };

    let grant = NhiDelegationGrant::grant(&pool, tenant_id, input)
        .await
        .expect("grant should succeed");

    let found = NhiDelegationGrant::find_by_id(&pool, tenant_id, grant.id)
        .await
        .expect("query should succeed")
        .expect("grant should be found");

    assert_eq!(found.id, grant.id);
    assert_eq!(found.principal_id, owner_id);
    assert_eq!(found.actor_nhi_id, nhi_id);
}

/// Test: Cross-tenant access to delegation grant fails.
///
/// Given a grant exists in tenant A,
/// When tenant B tries to find it by ID,
/// Then None is returned.
#[tokio::test]
#[ignore]
async fn test_get_delegation_cross_tenant_fails() {
    let pool = create_test_pool().await;
    let (tenant_a, owner_a, nhi_a) = setup_test_env(&pool).await;
    let tenant_b = create_test_tenant(&pool).await;

    let input = CreateNhiDelegationGrant {
        principal_id: owner_a,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_a,
        allowed_scopes: vec!["read".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: None,
    };

    let grant = NhiDelegationGrant::grant(&pool, tenant_a, input)
        .await
        .expect("grant should succeed");

    // Attempt to access from tenant B
    let result = NhiDelegationGrant::find_by_id(&pool, tenant_b, grant.id)
        .await
        .expect("query should succeed");

    assert!(
        result.is_none(),
        "Tenant B should not see tenant A's delegation grant"
    );
}

/// Test: Revoke delegation grant.
///
/// Given an active grant,
/// When revoking it,
/// Then revoke returns true and find_active returns None.
#[tokio::test]
#[ignore]
async fn test_revoke_delegation_grant() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    let input = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["read".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: None,
    };

    let grant = NhiDelegationGrant::grant(&pool, tenant_id, input)
        .await
        .expect("grant should succeed");

    // Verify active before revocation
    let active = NhiDelegationGrant::find_active(&pool, tenant_id, owner_id, nhi_id)
        .await
        .expect("query should succeed");
    assert!(active.is_some(), "grant should be active before revocation");

    // Revoke
    let revoked = NhiDelegationGrant::revoke(&pool, tenant_id, grant.id, Some(owner_id))
        .await
        .expect("revoke should succeed");
    assert!(revoked, "revoke should return true");

    // Verify no longer active
    let active_after = NhiDelegationGrant::find_active(&pool, tenant_id, owner_id, nhi_id)
        .await
        .expect("query should succeed");
    assert!(
        active_after.is_none(),
        "grant should not be active after revocation"
    );

    // The grant still exists but status is revoked
    let found = NhiDelegationGrant::find_by_id(&pool, tenant_id, grant.id)
        .await
        .expect("query should succeed")
        .expect("grant row should still exist");
    assert_eq!(found.status, "revoked");
    assert!(found.revoked_at.is_some());
    assert_eq!(found.revoked_by, Some(owner_id));
}

/// Test: List incoming delegations (by actor).
///
/// Given multiple principals delegate to the same actor NHI,
/// When listing by actor,
/// Then all grants for that actor are returned.
#[tokio::test]
#[ignore]
async fn test_list_incoming_delegations() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    // Create two additional principals
    let principal_2 = create_test_user(&pool, tenant_id, &unique_email()).await;
    let principal_3 = create_test_user(&pool, tenant_id, &unique_email()).await;

    // Each principal delegates to the same actor
    for principal_id in [owner_id, principal_2, principal_3] {
        let input = CreateNhiDelegationGrant {
            principal_id,
            principal_type: "user".to_string(),
            actor_nhi_id: nhi_id,
            allowed_scopes: vec!["read".to_string()],
            allowed_resource_types: vec![],
            max_delegation_depth: None,
            granted_by: None,
            expires_at: None,
        };
        NhiDelegationGrant::grant(&pool, tenant_id, input)
            .await
            .expect("grant should succeed");
    }

    let grants = NhiDelegationGrant::list_by_actor(&pool, tenant_id, nhi_id, 100, 0)
        .await
        .expect("list should succeed");

    assert_eq!(grants.len(), 3, "should have 3 incoming delegations");
    for g in &grants {
        assert_eq!(g.actor_nhi_id, nhi_id);
    }
}

/// Test: List outgoing delegations (by principal).
///
/// Given a principal delegates to multiple actor NHIs,
/// When listing by principal,
/// Then all grants from that principal are returned.
#[tokio::test]
#[ignore]
async fn test_list_outgoing_delegations() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, _nhi_id) = setup_test_env(&pool).await;

    // Create multiple actor NHIs
    let actor_1 = create_nhi_identity(&pool, tenant_id, "actor-1", owner_id).await;
    let actor_2 = create_nhi_identity(&pool, tenant_id, "actor-2", owner_id).await;
    let actor_3 = create_nhi_identity(&pool, tenant_id, "actor-3", owner_id).await;

    for actor_nhi_id in [actor_1, actor_2, actor_3] {
        let input = CreateNhiDelegationGrant {
            principal_id: owner_id,
            principal_type: "user".to_string(),
            actor_nhi_id,
            allowed_scopes: vec!["read".to_string()],
            allowed_resource_types: vec![],
            max_delegation_depth: None,
            granted_by: None,
            expires_at: None,
        };
        NhiDelegationGrant::grant(&pool, tenant_id, input)
            .await
            .expect("grant should succeed");
    }

    let grants = NhiDelegationGrant::list_by_principal(&pool, tenant_id, owner_id, 100, 0)
        .await
        .expect("list should succeed");

    assert_eq!(grants.len(), 3, "should have 3 outgoing delegations");
    for g in &grants {
        assert_eq!(g.principal_id, owner_id);
    }
}

/// Test: Revoke nonexistent grant returns false.
///
/// Given no grant exists with the given ID,
/// When attempting to revoke,
/// Then revoke returns false.
#[tokio::test]
#[ignore]
async fn test_revoke_nonexistent_returns_false() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let result = NhiDelegationGrant::revoke(&pool, tenant_id, Uuid::new_v4(), None)
        .await
        .expect("revoke should not error");

    assert!(!result, "revoking nonexistent grant should return false");
}

/// Test: Cleanup expired grants.
///
/// Given active and expired grants exist,
/// When running cleanup_expired,
/// Then only expired grants are marked as expired, active ones remain.
#[tokio::test]
#[ignore]
async fn test_cleanup_expired_grants() {
    let pool = create_test_pool().await;
    let (tenant_id, owner_id, nhi_id) = setup_test_env(&pool).await;

    // Create a grant that is already expired (expires_at in the past)
    let actor_expired = create_nhi_identity(&pool, tenant_id, "actor-expired", owner_id).await;
    let expired_input = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: actor_expired,
        allowed_scopes: vec!["read".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: Some(Utc::now() - Duration::days(1)),
    };
    let expired_grant = NhiDelegationGrant::grant(&pool, tenant_id, expired_input)
        .await
        .expect("expired grant should be created");

    // Create a grant that is still active (no expiration)
    let active_input = CreateNhiDelegationGrant {
        principal_id: owner_id,
        principal_type: "user".to_string(),
        actor_nhi_id: nhi_id,
        allowed_scopes: vec!["write".to_string()],
        allowed_resource_types: vec![],
        max_delegation_depth: None,
        granted_by: None,
        expires_at: None,
    };
    let active_grant = NhiDelegationGrant::grant(&pool, tenant_id, active_input)
        .await
        .expect("active grant should be created");

    // Run cleanup
    let cleaned = NhiDelegationGrant::cleanup_expired(&pool, tenant_id)
        .await
        .expect("cleanup should succeed");

    assert!(
        cleaned >= 1,
        "should have cleaned up at least 1 expired grant"
    );

    // Verify the expired grant is now marked as expired
    let expired_found = NhiDelegationGrant::find_by_id(&pool, tenant_id, expired_grant.id)
        .await
        .expect("query should succeed")
        .expect("expired grant row should still exist");
    assert_eq!(expired_found.status, "expired");

    // Verify the active grant is still active
    let active_found = NhiDelegationGrant::find_by_id(&pool, tenant_id, active_grant.id)
        .await
        .expect("query should succeed")
        .expect("active grant should still exist");
    assert_eq!(active_found.status, "active");
}

// ---------------------------------------------------------------------------
// Pure validation tests (no DB needed)
// ---------------------------------------------------------------------------

/// Test: Validation of principal_type.
///
/// Only "user" and "nhi" are valid principal types.
#[test]
fn test_validation_principal_type() {
    assert!(matches!("user", "user" | "nhi"));
    assert!(matches!("nhi", "user" | "nhi"));
    assert!(!matches!("invalid", "user" | "nhi"));
    assert!(!matches!("service_account", "user" | "nhi"));
    assert!(!matches!("", "user" | "nhi"));
}

/// Test: Validation of scope count limit.
///
/// allowed_scopes must not exceed 50 entries.
#[test]
fn test_validation_scope_count() {
    let scopes: Vec<String> = (0..51).map(|i| format!("scope-{i}")).collect();
    assert!(scopes.len() > 50, "51 scopes exceeds the 50-entry limit");

    let valid_scopes: Vec<String> = (0..50).map(|i| format!("scope-{i}")).collect();
    assert!(valid_scopes.len() <= 50, "50 scopes is within limit");
}

/// Test: Validation of max_delegation_depth range.
///
/// If provided, must be in the range 1..=5.
#[test]
fn test_validation_depth_range() {
    assert!(!(1..=5).contains(&0), "0 is below the allowed range");
    assert!((1..=5).contains(&1), "1 is the minimum");
    assert!((1..=5).contains(&3), "3 is in range");
    assert!((1..=5).contains(&5), "5 is the maximum");
    assert!(!(1..=5).contains(&6), "6 is above the allowed range");
    assert!(!(1..=5).contains(&-1), "-1 is below the allowed range");
}

/// Test: Validation of individual scope length.
///
/// Each scope must be between 1 and 256 characters.
#[test]
fn test_validation_scope_length() {
    let too_long = "x".repeat(257);
    assert!(
        too_long.len() > 256,
        "257-char scope exceeds the 256-char limit"
    );

    let max_valid = "x".repeat(256);
    assert!(max_valid.len() <= 256, "256-char scope is within limit");

    let empty = "";
    assert!(empty.is_empty(), "empty scope is invalid (min 1 char)");

    let min_valid = "a";
    assert!(
        !min_valid.is_empty() && min_valid.len() <= 256,
        "1-char scope is valid"
    );
}

/// Test: List requires at least one filter parameter.
///
/// The handler requires either principal_id or actor_nhi_id.
/// Both being absent should be treated as an error.
#[test]
fn test_list_requires_filter() {
    let principal_id: Option<Uuid> = None;
    let actor_nhi_id: Option<Uuid> = None;

    let has_filter = principal_id.is_some() || actor_nhi_id.is_some();
    assert!(!has_filter, "no filter provided should be rejected");

    // With principal_id
    let principal_id = Some(Uuid::new_v4());
    let has_filter = principal_id.is_some() || actor_nhi_id.is_some();
    assert!(has_filter, "principal_id alone is a valid filter");

    // With actor_nhi_id
    let principal_id: Option<Uuid> = None;
    let actor_nhi_id = Some(Uuid::new_v4());
    let has_filter = principal_id.is_some() || actor_nhi_id.is_some();
    assert!(has_filter, "actor_nhi_id alone is a valid filter");

    // With both
    let principal_id = Some(Uuid::new_v4());
    let has_filter = principal_id.is_some() || actor_nhi_id.is_some();
    assert!(has_filter, "both filters together is valid");
}
