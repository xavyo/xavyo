//! Governance Persona Link model (F063).
//!
//! Explicit link between physical user and persona (persona reference).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::PersonaLinkType;

/// A persona link - relationship between physical user and persona.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPersonaLink {
    /// Unique identifier for the link.
    pub id: Uuid,

    /// The tenant this link belongs to.
    pub tenant_id: Uuid,

    /// Physical user.
    pub physical_user_id: Uuid,

    /// Linked persona.
    pub persona_id: Uuid,

    /// Type of link relationship.
    pub link_type: PersonaLinkType,

    /// When the link was created.
    pub created_at: DateTime<Utc>,

    /// Who created the link.
    pub created_by: Uuid,
}

/// Request to create a persona link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePersonaLink {
    pub physical_user_id: Uuid,
    pub persona_id: Uuid,
    pub link_type: PersonaLinkType,
}

impl GovPersonaLink {
    /// Find a link by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_links
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find existing link for user + persona combination.
    pub async fn find_by_user_and_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        persona_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_links
            WHERE tenant_id = $1 AND physical_user_id = $2 AND persona_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(physical_user_id)
        .bind(persona_id)
        .fetch_optional(pool)
        .await
    }

    /// List all links for a physical user.
    pub async fn find_by_physical_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        physical_user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_links
            WHERE tenant_id = $1 AND physical_user_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(physical_user_id)
        .fetch_all(pool)
        .await
    }

    /// List all links for a persona.
    pub async fn find_by_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_links
            WHERE tenant_id = $1 AND persona_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(persona_id)
        .fetch_all(pool)
        .await
    }

    /// Find owner link for a persona.
    pub async fn find_owner(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_links
            WHERE tenant_id = $1 AND persona_id = $2 AND link_type = 'owner'
            "#,
        )
        .bind(tenant_id)
        .bind(persona_id)
        .fetch_optional(pool)
        .await
    }

    /// Create a new persona link.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreatePersonaLink,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_persona_links (
                tenant_id, physical_user_id, persona_id, link_type, created_by
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.physical_user_id)
        .bind(input.persona_id)
        .bind(input.link_type)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Delete a persona link.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_persona_links
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all links for a persona (cascade delete).
    pub async fn delete_by_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_persona_links
            WHERE tenant_id = $1 AND persona_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(persona_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_persona_link_request() {
        let input = CreatePersonaLink {
            physical_user_id: Uuid::new_v4(),
            persona_id: Uuid::new_v4(),
            link_type: PersonaLinkType::Owner,
        };

        assert_eq!(input.link_type, PersonaLinkType::Owner);
    }
}
