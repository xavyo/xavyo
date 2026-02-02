//! Governance Archived Identity model.
//!
//! Represents soft-deleted identities preserved for audit and potential restoration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// External reference types for identities.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalReferences {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ad_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hr_employee_id: Option<String>,
    #[serde(flatten)]
    pub additional: serde_json::Map<String, serde_json::Value>,
}

/// A governance archived identity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovArchivedIdentity {
    /// Unique identifier for the archived identity.
    pub id: Uuid,

    /// The tenant this archived identity belongs to.
    pub tenant_id: Uuid,

    /// Original user ID before archival.
    pub original_user_id: Uuid,

    /// Reference to the merge operation that caused archival.
    pub merge_operation_id: Uuid,

    /// Complete identity state at archival time.
    pub snapshot: serde_json::Value,

    /// External system references (SCIM IDs, LDAP DNs, etc.).
    pub external_references: serde_json::Value,

    /// When the identity was archived.
    pub archived_at: DateTime<Utc>,
}

/// Request to create a new archived identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovArchivedIdentity {
    pub original_user_id: Uuid,
    pub merge_operation_id: Uuid,
    pub snapshot: serde_json::Value,
    pub external_references: ExternalReferences,
}

/// Filter options for listing archived identities.
#[derive(Debug, Clone, Default)]
pub struct ArchivedIdentityFilter {
    pub original_user_id: Option<Uuid>,
    pub merge_operation_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovArchivedIdentity {
    /// Find an archived identity by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_archived_identities
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an archived identity by original user ID.
    pub async fn find_by_original_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        original_user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_archived_identities
            WHERE tenant_id = $1 AND original_user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(original_user_id)
        .fetch_optional(pool)
        .await
    }

    /// Find archived identity by merge operation.
    pub async fn find_by_merge_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        merge_operation_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_archived_identities
            WHERE tenant_id = $1 AND merge_operation_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(merge_operation_id)
        .fetch_optional(pool)
        .await
    }

    /// List archived identities for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ArchivedIdentityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_archived_identities
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.original_user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND original_user_id = ${}", param_count));
        }
        if filter.merge_operation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND merge_operation_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archived_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archived_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY archived_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovArchivedIdentity>(&query).bind(tenant_id);

        if let Some(original_user_id) = filter.original_user_id {
            q = q.bind(original_user_id);
        }
        if let Some(merge_operation_id) = filter.merge_operation_id {
            q = q.bind(merge_operation_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count archived identities in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ArchivedIdentityFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_archived_identities
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.original_user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND original_user_id = ${}", param_count));
        }
        if filter.merge_operation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND merge_operation_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archived_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archived_at <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(original_user_id) = filter.original_user_id {
            q = q.bind(original_user_id);
        }
        if let Some(merge_operation_id) = filter.merge_operation_id {
            q = q.bind(merge_operation_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.fetch_one(pool).await
    }

    /// Create a new archived identity.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovArchivedIdentity,
    ) -> Result<Self, sqlx::Error> {
        let external_references = serde_json::to_value(&input.external_references)
            .unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r#"
            INSERT INTO gov_archived_identities (
                tenant_id, original_user_id, merge_operation_id, snapshot, external_references
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.original_user_id)
        .bind(input.merge_operation_id)
        .bind(&input.snapshot)
        .bind(external_references)
        .fetch_one(pool)
        .await
    }

    /// Create a new archived identity (within a transaction).
    pub async fn create_with_tx<'e, E>(
        executor: E,
        tenant_id: Uuid,
        original_user_id: Uuid,
        merge_operation_id: Uuid,
        snapshot: serde_json::Value,
        external_references: serde_json::Value,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO gov_archived_identities (
                tenant_id, original_user_id, merge_operation_id, snapshot, external_references
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(original_user_id)
        .bind(merge_operation_id)
        .bind(&snapshot)
        .bind(&external_references)
        .fetch_one(executor)
        .await
    }

    /// Search archived identities by external reference.
    pub async fn find_by_external_reference(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        reference_key: &str,
        reference_value: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_archived_identities
            WHERE tenant_id = $1
              AND external_references ->> $2 = $3
            "#,
        )
        .bind(tenant_id)
        .bind(reference_key)
        .bind(reference_value)
        .fetch_optional(pool)
        .await
    }

    /// Get the external references as structured data.
    pub fn get_external_references(&self) -> Result<ExternalReferences, serde_json::Error> {
        serde_json::from_value(self.external_references.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_references_serialization() {
        let refs = ExternalReferences {
            scim_id: Some("scim-uuid-123".to_string()),
            ldap_dn: Some("cn=john,ou=users,dc=example".to_string()),
            ad_guid: None,
            hr_employee_id: Some("EMP001".to_string()),
            additional: serde_json::Map::new(),
        };

        let json = serde_json::to_string(&refs).unwrap();
        assert!(json.contains("scim-uuid-123"));
        assert!(json.contains("cn=john"));
        assert!(json.contains("EMP001"));
        assert!(!json.contains("ad_guid")); // Should be skipped since None
    }

    #[test]
    fn test_external_references_with_additional() {
        let mut additional = serde_json::Map::new();
        additional.insert("custom_id".to_string(), serde_json::json!("custom-value"));

        let refs = ExternalReferences {
            scim_id: Some("scim-123".to_string()),
            ldap_dn: None,
            ad_guid: None,
            hr_employee_id: None,
            additional,
        };

        let json = serde_json::to_string(&refs).unwrap();
        assert!(json.contains("custom_id"));
        assert!(json.contains("custom-value"));
    }

    #[test]
    fn test_create_archived_identity() {
        let snapshot = serde_json::json!({
            "id": "user-uuid",
            "email": "test@example.com",
            "display_name": "Test User"
        });

        let input = CreateGovArchivedIdentity {
            original_user_id: Uuid::new_v4(),
            merge_operation_id: Uuid::new_v4(),
            snapshot,
            external_references: ExternalReferences::default(),
        };

        assert!(input.snapshot.get("email").is_some());
    }
}
