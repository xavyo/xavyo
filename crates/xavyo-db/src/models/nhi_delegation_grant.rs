//! NHI Delegation Grant model.
//!
//! Tracks delegation grants that allow a principal (user or NHI) to act through
//! a specific NHI actor identity, with scoped permissions and depth limits.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A delegation grant allowing a principal to act through an NHI actor.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiDelegationGrant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub principal_type: String,
    pub actor_nhi_id: Uuid,
    pub allowed_scopes: Vec<String>,
    pub allowed_resource_types: Vec<String>,
    pub max_delegation_depth: i32,
    pub status: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a delegation grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiDelegationGrant {
    pub principal_id: Uuid,
    pub principal_type: String,
    pub actor_nhi_id: Uuid,
    pub allowed_scopes: Vec<String>,
    pub allowed_resource_types: Vec<String>,
    pub max_delegation_depth: Option<i32>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl NhiDelegationGrant {
    /// Check if the grant has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Check if the grant is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active" && !self.is_expired()
    }

    /// Check if a scope is allowed by this grant.
    /// An empty `allowed_scopes` list means all scopes are allowed.
    #[must_use]
    pub fn is_scope_allowed(&self, scope: &str) -> bool {
        self.allowed_scopes.is_empty() || self.allowed_scopes.iter().any(|s| s == scope)
    }

    /// Check if a resource type is allowed by this grant.
    /// An empty `allowed_resource_types` list means all resource types are allowed.
    #[must_use]
    pub fn is_resource_type_allowed(&self, resource_type: &str) -> bool {
        self.allowed_resource_types.is_empty()
            || self.allowed_resource_types.iter().any(|r| r == resource_type)
    }

    /// Grant a delegation (upsert on tenant_id + principal_id + actor_nhi_id).
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateNhiDelegationGrant,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO nhi_delegation_grants (
                tenant_id, principal_id, principal_type, actor_nhi_id,
                allowed_scopes, allowed_resource_types, max_delegation_depth,
                status, granted_by, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, 1), 'active', $8, $9)
            ON CONFLICT (tenant_id, principal_id, actor_nhi_id)
            DO UPDATE SET
                principal_type = EXCLUDED.principal_type,
                allowed_scopes = EXCLUDED.allowed_scopes,
                allowed_resource_types = EXCLUDED.allowed_resource_types,
                max_delegation_depth = EXCLUDED.max_delegation_depth,
                status = 'active',
                granted_at = NOW(),
                granted_by = EXCLUDED.granted_by,
                expires_at = EXCLUDED.expires_at,
                revoked_at = NULL,
                revoked_by = NULL,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(&input.principal_type)
        .bind(input.actor_nhi_id)
        .bind(&input.allowed_scopes)
        .bind(&input.allowed_resource_types)
        .bind(input.max_delegation_depth)
        .bind(input.granted_by)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Find a grant by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_delegation_grants
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find an active grant for a principal-actor pair.
    pub async fn find_active(
        pool: &PgPool,
        tenant_id: Uuid,
        principal_id: Uuid,
        actor_nhi_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_delegation_grants
            WHERE tenant_id = $1 AND principal_id = $2 AND actor_nhi_id = $3
              AND status = 'active'
              AND (expires_at IS NULL OR expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(actor_nhi_id)
        .fetch_optional(pool)
        .await
    }

    /// Revoke a grant by ID.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        revoked_by: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_delegation_grants
            SET status = 'revoked', revoked_at = NOW(), revoked_by = $3, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(revoked_by)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List grants by principal.
    pub async fn list_by_principal(
        pool: &PgPool,
        tenant_id: Uuid,
        principal_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_delegation_grants
            WHERE tenant_id = $1 AND principal_id = $2
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List grants by actor NHI.
    pub async fn list_by_actor(
        pool: &PgPool,
        tenant_id: Uuid,
        actor_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM nhi_delegation_grants
            WHERE tenant_id = $1 AND actor_nhi_id = $2
            ORDER BY granted_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(actor_nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Mark expired grants as 'expired' for a tenant.
    pub async fn cleanup_expired(pool: &PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_delegation_grants
            SET status = 'expired', updated_at = NOW()
            WHERE tenant_id = $1 AND expires_at < NOW() AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_grant(status: &str, expires_at: Option<DateTime<Utc>>) -> NhiDelegationGrant {
        NhiDelegationGrant {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            actor_nhi_id: Uuid::new_v4(),
            allowed_scopes: vec![],
            allowed_resource_types: vec![],
            max_delegation_depth: 1,
            status: status.to_string(),
            granted_at: Utc::now(),
            granted_by: None,
            expires_at,
            revoked_at: None,
            revoked_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_is_expired_no_expiration() {
        let grant = make_grant("active", None);
        assert!(!grant.is_expired());
    }

    #[test]
    fn test_is_expired_future() {
        let grant = make_grant("active", Some(Utc::now() + Duration::days(30)));
        assert!(!grant.is_expired());
    }

    #[test]
    fn test_is_expired_past() {
        let grant = make_grant("active", Some(Utc::now() - Duration::days(1)));
        assert!(grant.is_expired());
    }

    #[test]
    fn test_is_active() {
        let grant = make_grant("active", None);
        assert!(grant.is_active());

        let revoked = make_grant("revoked", None);
        assert!(!revoked.is_active());

        let expired = make_grant("active", Some(Utc::now() - Duration::days(1)));
        assert!(!expired.is_active());
    }

    #[test]
    fn test_is_scope_allowed_empty_allows_all() {
        let grant = make_grant("active", None);
        assert!(grant.is_scope_allowed("anything"));
    }

    #[test]
    fn test_is_scope_allowed_checks_membership() {
        let mut grant = make_grant("active", None);
        grant.allowed_scopes = vec!["read".to_string(), "write".to_string()];
        assert!(grant.is_scope_allowed("read"));
        assert!(grant.is_scope_allowed("write"));
        assert!(!grant.is_scope_allowed("admin"));
    }

    #[test]
    fn test_is_resource_type_allowed_empty_allows_all() {
        let grant = make_grant("active", None);
        assert!(grant.is_resource_type_allowed("anything"));
    }

    #[test]
    fn test_is_resource_type_allowed_checks_membership() {
        let mut grant = make_grant("active", None);
        grant.allowed_resource_types = vec!["api".to_string(), "database".to_string()];
        assert!(grant.is_resource_type_allowed("api"));
        assert!(grant.is_resource_type_allowed("database"));
        assert!(!grant.is_resource_type_allowed("storage"));
    }

    #[test]
    fn test_serialization() {
        let grant = NhiDelegationGrant {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            principal_type: "nhi".to_string(),
            actor_nhi_id: Uuid::new_v4(),
            allowed_scopes: vec!["read".to_string()],
            allowed_resource_types: vec!["api".to_string()],
            max_delegation_depth: 3,
            status: "active".to_string(),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
            expires_at: Some(Utc::now() + Duration::days(90)),
            revoked_at: None,
            revoked_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json_str = serde_json::to_string(&grant).unwrap();
        let deserialized: NhiDelegationGrant = serde_json::from_str(&json_str).unwrap();
        assert_eq!(grant.id, deserialized.id);
        assert_eq!(grant.max_delegation_depth, deserialized.max_delegation_depth);
        assert_eq!(grant.allowed_scopes, deserialized.allowed_scopes);
        assert_eq!(grant.allowed_resource_types, deserialized.allowed_resource_types);
    }

    #[test]
    fn test_create_input() {
        let input = CreateNhiDelegationGrant {
            principal_id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            actor_nhi_id: Uuid::new_v4(),
            allowed_scopes: vec!["read".to_string()],
            allowed_resource_types: vec![],
            max_delegation_depth: Some(2),
            granted_by: None,
            expires_at: None,
        };

        assert_eq!(input.principal_type, "user");
        assert_eq!(input.max_delegation_depth, Some(2));

        let json_str = serde_json::to_string(&input).unwrap();
        let deserialized: CreateNhiDelegationGrant = serde_json::from_str(&json_str).unwrap();
        assert_eq!(input.principal_id, deserialized.principal_id);
    }
}
