//! SCIM target attribute mapping model (F087).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A SCIM target attribute mapping configuration.
///
/// Maps source identity fields to SCIM paths on outbound provisioning targets.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimTargetAttributeMapping {
    /// Unique identifier for the mapping.
    pub id: Uuid,

    /// The tenant this mapping belongs to.
    pub tenant_id: Uuid,

    /// The SCIM target this mapping is for.
    pub target_id: Uuid,

    /// Source field name from the identity store.
    pub source_field: String,

    /// Target SCIM attribute path (e.g., "emails[0].value").
    pub target_scim_path: String,

    /// Mapping type: "direct", "constant", or "expression".
    pub mapping_type: String,

    /// Constant value when mapping_type is "constant".
    pub constant_value: Option<String>,

    /// Optional transform to apply (e.g., "lowercase", "uppercase").
    pub transform: Option<String>,

    /// Resource type this mapping applies to: "user" or "group".
    pub resource_type: String,

    /// When the mapping was created.
    pub created_at: DateTime<Utc>,

    /// When the mapping was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a SCIM target attribute mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimTargetAttributeMapping {
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub source_field: String,
    pub target_scim_path: String,
    pub mapping_type: String,
    pub constant_value: Option<String>,
    pub transform: Option<String>,
    pub resource_type: String,
}

impl ScimTargetAttributeMapping {
    /// List all mappings for a target, optionally filtered by resource type.
    pub async fn list_by_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: Option<&str>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(rt) = resource_type {
            sqlx::query_as(
                r#"
                SELECT * FROM scim_target_attribute_mappings
                WHERE tenant_id = $1 AND target_id = $2 AND resource_type = $3
                ORDER BY created_at
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(rt)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM scim_target_attribute_mappings
                WHERE tenant_id = $1 AND target_id = $2
                ORDER BY created_at
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Replace all mappings for a target within a transaction.
    ///
    /// Deletes all existing mappings for the target and inserts the new ones.
    pub async fn replace_all_for_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        mappings: &[CreateScimTargetAttributeMapping],
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            DELETE FROM scim_target_attribute_mappings
            WHERE tenant_id = $1 AND target_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(target_id)
        .execute(&mut *tx)
        .await?;

        let mut inserted = Vec::with_capacity(mappings.len());

        for m in mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, constant_value, transform, resource_type
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
                "#,
            )
            .bind(m.tenant_id)
            .bind(m.target_id)
            .bind(&m.source_field)
            .bind(&m.target_scim_path)
            .bind(&m.mapping_type)
            .bind(&m.constant_value)
            .bind(&m.transform)
            .bind(&m.resource_type)
            .fetch_one(&mut *tx)
            .await?;

            inserted.push(row);
        }

        tx.commit().await?;

        Ok(inserted)
    }

    /// Delete all mappings for a target.
    pub async fn delete_all_for_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM scim_target_attribute_mappings
            WHERE tenant_id = $1 AND target_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(target_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete all existing mappings and insert defaults atomically.
    ///
    /// Wraps delete + insert in a single transaction so the target is never
    /// left in a state with zero mappings.
    pub async fn reset_to_defaults(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            DELETE FROM scim_target_attribute_mappings
            WHERE tenant_id = $1 AND target_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(target_id)
        .execute(&mut *tx)
        .await?;

        let default_user_mappings: Vec<(&str, &str)> = vec![
            ("email", "userName"),
            ("email", "emails[0].value"),
            ("first_name", "name.givenName"),
            ("last_name", "name.familyName"),
            ("display_name", "displayName"),
            ("is_active", "active"),
        ];

        let default_group_mappings: Vec<(&str, &str)> = vec![("display_name", "displayName")];

        let mut inserted = Vec::new();

        for (source, target) in &default_user_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'user')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut *tx)
            .await?;

            inserted.push(row);
        }

        for (source, target) in &default_group_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'group')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut *tx)
            .await?;

            inserted.push(row);
        }

        tx.commit().await?;

        Ok(inserted)
    }

    /// Insert default attribute mappings for a target using a pool with transaction.
    ///
    /// Creates standard user mappings (email->userName, email->emails[0].value,
    /// first_name->name.givenName, last_name->name.familyName,
    /// display_name->displayName, is_active->active) and a default group
    /// mapping (display_name->displayName).
    ///
    /// Note: This method starts its own transaction if called with a pool.
    /// For RLS support, prefer passing a transaction that already has tenant context set.
    pub async fn insert_defaults_for_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let default_user_mappings: Vec<(&str, &str)> = vec![
            ("email", "userName"),
            ("email", "emails[0].value"),
            ("first_name", "name.givenName"),
            ("last_name", "name.familyName"),
            ("display_name", "displayName"),
            ("is_active", "active"),
        ];

        let default_group_mappings: Vec<(&str, &str)> = vec![("display_name", "displayName")];

        let mut inserted = Vec::new();

        for (source, target) in &default_user_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'user')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut *tx)
            .await?;

            inserted.push(row);
        }

        for (source, target) in &default_group_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'group')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut *tx)
            .await?;

            inserted.push(row);
        }

        tx.commit().await?;

        Ok(inserted)
    }

    /// Insert default attribute mappings using a transaction with tenant context already set.
    ///
    /// This version accepts a mutable reference to a transaction and does not commit -
    /// the caller is responsible for committing the transaction.
    pub async fn insert_defaults_for_target_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let default_user_mappings: Vec<(&str, &str)> = vec![
            ("email", "userName"),
            ("email", "emails[0].value"),
            ("first_name", "name.givenName"),
            ("last_name", "name.familyName"),
            ("display_name", "displayName"),
            ("is_active", "active"),
        ];

        let default_group_mappings: Vec<(&str, &str)> = vec![("display_name", "displayName")];

        let mut inserted = Vec::new();

        for (source, target) in &default_user_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'user')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut **tx)
            .await?;

            inserted.push(row);
        }

        for (source, target) in &default_group_mappings {
            let row: ScimTargetAttributeMapping = sqlx::query_as(
                r#"
                INSERT INTO scim_target_attribute_mappings (
                    tenant_id, target_id, source_field, target_scim_path,
                    mapping_type, resource_type
                )
                VALUES ($1, $2, $3, $4, 'direct', 'group')
                RETURNING *
                "#,
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(source)
            .bind(target)
            .fetch_one(&mut **tx)
            .await?;

            inserted.push(row);
        }

        Ok(inserted)
    }
}
