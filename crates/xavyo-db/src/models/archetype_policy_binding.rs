//! Archetype Policy Binding model for F-058
//!
//! Links identity archetypes to security policies (password, MFA, session).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Policy type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyType {
    Password,
    Mfa,
    Session,
}

impl PolicyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyType::Password => "password",
            PolicyType::Mfa => "mfa",
            PolicyType::Session => "session",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "password" => Some(PolicyType::Password),
            "mfa" => Some(PolicyType::Mfa),
            "session" => Some(PolicyType::Session),
            _ => None,
        }
    }
}

impl std::fmt::Display for PolicyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Archetype Policy Binding entity
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ArchetypePolicyBinding {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub archetype_id: Uuid,
    pub policy_type: String,
    pub policy_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a policy binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyBinding {
    pub policy_type: PolicyType,
    pub policy_id: Uuid,
}

/// Effective policy with source info
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub policy_type: String,
    pub policy_id: Uuid,
    pub source_archetype_id: Uuid,
    pub source_archetype_name: String,
}

impl ArchetypePolicyBinding {
    /// Find binding by archetype and policy type
    pub async fn find_by_archetype_and_type(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        policy_type: PolicyType,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, archetype_id, policy_type, policy_id, created_at
            FROM archetype_policy_bindings
            WHERE tenant_id = $1 AND archetype_id = $2 AND policy_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .bind(policy_type.as_str())
        .fetch_optional(pool)
        .await
    }

    /// List all bindings for an archetype
    pub async fn list_by_archetype(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, archetype_id, policy_type, policy_id, created_at
            FROM archetype_policy_bindings
            WHERE tenant_id = $1 AND archetype_id = $2
            ORDER BY policy_type ASC
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .fetch_all(pool)
        .await
    }

    /// Bind a policy to an archetype (upsert pattern)
    pub async fn bind_policy(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        input: CreatePolicyBinding,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO archetype_policy_bindings (tenant_id, archetype_id, policy_type, policy_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (archetype_id, policy_type)
            DO UPDATE SET policy_id = EXCLUDED.policy_id
            RETURNING id, tenant_id, archetype_id, policy_type, policy_id, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .bind(input.policy_type.as_str())
        .bind(input.policy_id)
        .fetch_one(pool)
        .await
    }

    /// Unbind a policy from an archetype
    pub async fn unbind_policy(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        policy_type: PolicyType,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM archetype_policy_bindings
            WHERE tenant_id = $1 AND archetype_id = $2 AND policy_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .bind(policy_type.as_str())
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Resolve effective policies for an archetype using inheritance chain
    /// Returns policies from the archetype or its nearest ancestor that has a binding
    pub async fn resolve_effective_policies(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Vec<EffectivePolicy>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH RECURSIVE ancestry AS (
                -- Start with the archetype itself
                SELECT id, name, parent_archetype_id, 1 as depth
                FROM identity_archetypes
                WHERE id = $1 AND tenant_id = $2

                UNION ALL

                -- Walk up the parent chain
                SELECT a.id, a.name, a.parent_archetype_id, anc.depth + 1
                FROM identity_archetypes a
                JOIN ancestry anc ON a.id = anc.parent_archetype_id
                WHERE a.tenant_id = $2
            ),
            ranked_policies AS (
                SELECT
                    pb.policy_type,
                    pb.policy_id,
                    anc.id as source_archetype_id,
                    anc.name as source_archetype_name,
                    anc.depth,
                    ROW_NUMBER() OVER (PARTITION BY pb.policy_type ORDER BY anc.depth ASC) as rn
                FROM ancestry anc
                JOIN archetype_policy_bindings pb ON pb.archetype_id = anc.id
                WHERE pb.tenant_id = $2
            )
            SELECT
                policy_type,
                policy_id,
                source_archetype_id,
                source_archetype_name
            FROM ranked_policies
            WHERE rn = 1
            ORDER BY policy_type
            "#,
        )
        .bind(archetype_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get a single effective policy for an archetype by type
    pub async fn resolve_effective_policy(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        policy_type: PolicyType,
    ) -> Result<Option<EffectivePolicy>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH RECURSIVE ancestry AS (
                -- Start with the archetype itself
                SELECT id, name, parent_archetype_id, 1 as depth
                FROM identity_archetypes
                WHERE id = $1 AND tenant_id = $2

                UNION ALL

                -- Walk up the parent chain
                SELECT a.id, a.name, a.parent_archetype_id, anc.depth + 1
                FROM identity_archetypes a
                JOIN ancestry anc ON a.id = anc.parent_archetype_id
                WHERE a.tenant_id = $2
            )
            SELECT
                pb.policy_type,
                pb.policy_id,
                anc.id as source_archetype_id,
                anc.name as source_archetype_name
            FROM ancestry anc
            JOIN archetype_policy_bindings pb ON pb.archetype_id = anc.id
            WHERE pb.tenant_id = $2 AND pb.policy_type = $3
            ORDER BY anc.depth ASC
            LIMIT 1
            "#,
        )
        .bind(archetype_id)
        .bind(tenant_id)
        .bind(policy_type.as_str())
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_from_str() {
        assert_eq!(PolicyType::parse("password"), Some(PolicyType::Password));
        assert_eq!(PolicyType::parse("mfa"), Some(PolicyType::Mfa));
        assert_eq!(PolicyType::parse("session"), Some(PolicyType::Session));
        assert_eq!(PolicyType::parse("PASSWORD"), Some(PolicyType::Password));
        assert_eq!(PolicyType::parse("invalid"), None);
    }

    #[test]
    fn test_policy_type_as_str() {
        assert_eq!(PolicyType::Password.as_str(), "password");
        assert_eq!(PolicyType::Mfa.as_str(), "mfa");
        assert_eq!(PolicyType::Session.as_str(), "session");
    }

    #[test]
    fn test_policy_type_display() {
        assert_eq!(format!("{}", PolicyType::Password), "password");
        assert_eq!(format!("{}", PolicyType::Mfa), "mfa");
        assert_eq!(format!("{}", PolicyType::Session), "session");
    }

    #[test]
    fn test_create_policy_binding_input() {
        let input = CreatePolicyBinding {
            policy_type: PolicyType::Mfa,
            policy_id: Uuid::new_v4(),
        };
        assert_eq!(input.policy_type, PolicyType::Mfa);
    }

    #[test]
    fn test_effective_policy_serialization() {
        let policy = EffectivePolicy {
            policy_type: "mfa".to_string(),
            policy_id: Uuid::new_v4(),
            source_archetype_id: Uuid::new_v4(),
            source_archetype_name: "Employee".to_string(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("mfa"));
        assert!(json.contains("Employee"));
    }
}
