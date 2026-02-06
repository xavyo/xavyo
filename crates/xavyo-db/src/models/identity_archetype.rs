//! Identity Archetype model for F-058
//!
//! Represents identity sub-types (Employee, Contractor, Service Account, etc.)
//! with support for inheritance, schema extensions, and policy bindings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

/// Identity Archetype entity
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityArchetype {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub parent_archetype_id: Option<Uuid>,
    pub schema_extensions: serde_json::Value,
    pub lifecycle_model_id: Option<Uuid>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new archetype
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityArchetype {
    pub name: String,
    pub description: Option<String>,
    pub parent_archetype_id: Option<Uuid>,
    pub schema_extensions: Option<serde_json::Value>,
    pub lifecycle_model_id: Option<Uuid>,
}

/// Input for updating an existing archetype
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateIdentityArchetype {
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_archetype_id: Option<Option<Uuid>>, // None = no change, Some(None) = clear, Some(Some(id)) = set
    pub schema_extensions: Option<serde_json::Value>,
    pub lifecycle_model_id: Option<Option<Uuid>>,
    pub is_active: Option<bool>,
}

/// Archetype with ancestry chain info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchetypeWithAncestry {
    pub archetype: IdentityArchetype,
    pub ancestry_chain: Vec<AncestryNode>,
}

/// Node in the ancestry chain
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AncestryNode {
    pub id: Uuid,
    pub name: String,
    pub depth: i32,
}

impl IdentityArchetype {
    /// Find archetype by ID within a tenant
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, description, parent_archetype_id,
                   schema_extensions, lifecycle_model_id, is_active,
                   created_at, updated_at
            FROM identity_archetypes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find archetype by name within a tenant
    pub async fn find_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, description, parent_archetype_id,
                   schema_extensions, lifecycle_model_id, is_active,
                   created_at, updated_at
            FROM identity_archetypes
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List archetypes for a tenant with pagination
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        active_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if active_only {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, parent_archetype_id,
                       schema_extensions, lifecycle_model_id, is_active,
                       created_at, updated_at
                FROM identity_archetypes
                WHERE tenant_id = $1 AND is_active = true
                ORDER BY name ASC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, parent_archetype_id,
                       schema_extensions, lifecycle_model_id, is_active,
                       created_at, updated_at
                FROM identity_archetypes
                WHERE tenant_id = $1
                ORDER BY name ASC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// Count archetypes for a tenant
    pub async fn count_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        active_only: bool,
    ) -> Result<i64, sqlx::Error> {
        let query = if active_only {
            r#"
            SELECT COUNT(*)
            FROM identity_archetypes
            WHERE tenant_id = $1 AND is_active = true
            "#
        } else {
            r#"
            SELECT COUNT(*)
            FROM identity_archetypes
            WHERE tenant_id = $1
            "#
        };

        let row: (i64,) = sqlx::query_as(query)
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;
        Ok(row.0)
    }

    /// Create a new archetype
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateIdentityArchetype,
    ) -> Result<Self, sqlx::Error> {
        let schema_extensions = input
            .schema_extensions
            .unwrap_or_else(|| serde_json::json!({"attributes": []}));

        sqlx::query_as(
            r#"
            INSERT INTO identity_archetypes (
                tenant_id, name, description, parent_archetype_id,
                schema_extensions, lifecycle_model_id
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, tenant_id, name, description, parent_archetype_id,
                      schema_extensions, lifecycle_model_id, is_active,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.parent_archetype_id)
        .bind(&schema_extensions)
        .bind(input.lifecycle_model_id)
        .fetch_one(pool)
        .await
    }

    /// Update an existing archetype
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateIdentityArchetype,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First fetch current state
        let current = match Self::find_by_id(pool, tenant_id, id).await? {
            Some(a) => a,
            None => return Ok(None),
        };

        // Apply updates with defaults from current
        let name = input.name.unwrap_or(current.name);
        let description = input.description.or(current.description);
        let parent_archetype_id = match input.parent_archetype_id {
            Some(new_parent) => new_parent,
            None => current.parent_archetype_id,
        };
        let schema_extensions = input.schema_extensions.unwrap_or(current.schema_extensions);
        let lifecycle_model_id = match input.lifecycle_model_id {
            Some(new_lifecycle) => new_lifecycle,
            None => current.lifecycle_model_id,
        };
        let is_active = input.is_active.unwrap_or(current.is_active);

        sqlx::query_as(
            r#"
            UPDATE identity_archetypes
            SET name = $3, description = $4, parent_archetype_id = $5,
                schema_extensions = $6, lifecycle_model_id = $7, is_active = $8,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, name, description, parent_archetype_id,
                      schema_extensions, lifecycle_model_id, is_active,
                      created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&description)
        .bind(parent_archetype_id)
        .bind(&schema_extensions)
        .bind(lifecycle_model_id)
        .bind(is_active)
        .fetch_optional(pool)
        .await
    }

    /// Delete an archetype (hard delete)
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM identity_archetypes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count users assigned to this archetype
    pub async fn count_assigned_users(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE tenant_id = $1 AND archetype_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Check if setting parent_id would create a circular inheritance chain
    pub async fn check_circular_inheritance(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        proposed_parent_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // If proposed parent equals self, it's circular
        if archetype_id == proposed_parent_id {
            return Ok(true);
        }

        // Check if archetype_id appears anywhere in the ancestry of proposed_parent_id
        let row = sqlx::query(
            r#"
            WITH RECURSIVE ancestry AS (
                -- Start with the proposed parent
                SELECT id, parent_archetype_id
                FROM identity_archetypes
                WHERE id = $1 AND tenant_id = $2

                UNION ALL

                -- Walk up the parent chain
                SELECT a.id, a.parent_archetype_id
                FROM identity_archetypes a
                JOIN ancestry anc ON a.id = anc.parent_archetype_id
                WHERE a.tenant_id = $2
            )
            SELECT EXISTS(
                SELECT 1 FROM ancestry WHERE id = $3
            ) as is_circular
            "#,
        )
        .bind(proposed_parent_id)
        .bind(tenant_id)
        .bind(archetype_id)
        .fetch_one(pool)
        .await?;

        let is_circular: bool = row.get("is_circular");
        Ok(is_circular)
    }

    /// Get the ancestry chain for an archetype (from child to root)
    pub async fn get_ancestry_chain(
        pool: &PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Vec<AncestryNode>, sqlx::Error> {
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
            SELECT id, name, depth
            FROM ancestry
            ORDER BY depth ASC
            "#,
        )
        .bind(archetype_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_archetype_input() {
        let input = CreateIdentityArchetype {
            name: "Employee".to_string(),
            description: Some("Standard employee archetype".to_string()),
            parent_archetype_id: None,
            schema_extensions: Some(serde_json::json!({
                "attributes": [
                    {"name": "employee_id", "type": "string", "required": true}
                ]
            })),
            lifecycle_model_id: None,
        };
        assert_eq!(input.name, "Employee");
        assert!(input.description.is_some());
    }

    #[test]
    fn test_update_archetype_input_defaults() {
        let update = UpdateIdentityArchetype::default();
        assert!(update.name.is_none());
        assert!(update.description.is_none());
        assert!(update.is_active.is_none());
    }

    #[test]
    fn test_schema_extensions_default() {
        let input = CreateIdentityArchetype {
            name: "Test".to_string(),
            description: None,
            parent_archetype_id: None,
            schema_extensions: None,
            lifecycle_model_id: None,
        };
        let default_schema = input
            .schema_extensions
            .unwrap_or_else(|| serde_json::json!({"attributes": []}));
        assert!(default_schema.get("attributes").is_some());
    }

    #[test]
    fn test_ancestry_node_serialization() {
        let node = AncestryNode {
            id: Uuid::new_v4(),
            name: "Employee".to_string(),
            depth: 1,
        };
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("Employee"));
    }

    #[test]
    fn test_create_archetype_with_lifecycle_model_id() {
        let lifecycle_id = Uuid::new_v4();
        let input = CreateIdentityArchetype {
            name: "Employee".to_string(),
            description: Some("Employee with lifecycle".to_string()),
            parent_archetype_id: None,
            schema_extensions: None,
            lifecycle_model_id: Some(lifecycle_id),
        };
        assert_eq!(input.lifecycle_model_id, Some(lifecycle_id));
    }

    #[test]
    fn test_update_archetype_lifecycle_model_id() {
        // Test setting lifecycle_model_id
        let lifecycle_id = Uuid::new_v4();
        let update = UpdateIdentityArchetype {
            lifecycle_model_id: Some(Some(lifecycle_id)),
            ..Default::default()
        };
        assert_eq!(update.lifecycle_model_id, Some(Some(lifecycle_id)));

        // Test clearing lifecycle_model_id
        let update_clear = UpdateIdentityArchetype {
            lifecycle_model_id: Some(None),
            ..Default::default()
        };
        assert_eq!(update_clear.lifecycle_model_id, Some(None));

        // Test not changing lifecycle_model_id
        let update_unchanged = UpdateIdentityArchetype::default();
        assert!(update_unchanged.lifecycle_model_id.is_none());
    }
}
