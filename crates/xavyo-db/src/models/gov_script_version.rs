//! Script Version model (F066).
//! Immutable version history for provisioning scripts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An immutable version record for a provisioning script.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScriptVersion {
    /// Unique identifier for the version.
    pub id: Uuid,

    /// The tenant this version belongs to.
    pub tenant_id: Uuid,

    /// The script this version belongs to.
    pub script_id: Uuid,

    /// Sequential version number (1, 2, 3...).
    pub version_number: i32,

    /// Full script body at this version.
    pub script_body: String,

    /// Description of changes in this version.
    pub change_description: Option<String>,

    /// User who created this version.
    pub created_by: Uuid,

    /// When the version was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new script version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScriptVersion {
    pub tenant_id: Uuid,
    pub script_id: Uuid,
    pub version_number: i32,
    pub script_body: String,
    pub change_description: Option<String>,
    pub created_by: Uuid,
}

impl GovScriptVersion {
    /// Create a new script version.
    pub async fn create(
        pool: &sqlx::PgPool,
        params: &CreateScriptVersion,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_script_versions (
                tenant_id, script_id, version_number, script_body,
                change_description, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(params.tenant_id)
        .bind(params.script_id)
        .bind(params.version_number)
        .bind(&params.script_body)
        .bind(&params.change_description)
        .bind(params.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a version by ID within a tenant.
    pub async fn get_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_script_versions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a specific version number for a script.
    pub async fn get_by_script_and_version(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        version_number: i32,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_script_versions
            WHERE script_id = $1 AND version_number = $2 AND tenant_id = $3
            "#,
        )
        .bind(script_id)
        .bind(version_number)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all versions for a script ordered by version number descending.
    pub async fn list_by_script(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_script_versions
            WHERE script_id = $1 AND tenant_id = $2
            ORDER BY version_number DESC
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get the latest version (highest version_number) for a script.
    pub async fn get_latest_by_script(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_script_versions
            WHERE script_id = $1 AND tenant_id = $2
            ORDER BY version_number DESC
            LIMIT 1
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_script_version_params() {
        let params = CreateScriptVersion {
            tenant_id: Uuid::new_v4(),
            script_id: Uuid::new_v4(),
            version_number: 1,
            script_body: "echo 'hello'".to_string(),
            change_description: Some("Initial version".to_string()),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(params.version_number, 1);
        assert_eq!(params.script_body, "echo 'hello'");
        assert!(params.change_description.is_some());
    }

    #[test]
    fn test_create_script_version_no_description() {
        let params = CreateScriptVersion {
            tenant_id: Uuid::new_v4(),
            script_id: Uuid::new_v4(),
            version_number: 2,
            script_body: "echo 'updated'".to_string(),
            change_description: None,
            created_by: Uuid::new_v4(),
        };

        assert_eq!(params.version_number, 2);
        assert!(params.change_description.is_none());
    }

    #[test]
    fn test_serialization() {
        let params = CreateScriptVersion {
            tenant_id: Uuid::new_v4(),
            script_id: Uuid::new_v4(),
            version_number: 3,
            script_body: "#!/bin/bash\nset -e".to_string(),
            change_description: Some("Add strict mode".to_string()),
            created_by: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: CreateScriptVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version_number, 3);
        assert_eq!(deserialized.script_body, "#!/bin/bash\nset -e");
    }
}
