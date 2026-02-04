//! Provisioning Script model (F066).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_script_types::GovScriptStatus;

/// A provisioning script that can be bound to connectors for custom logic.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovProvisioningScript {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this script belongs to.
    pub tenant_id: Uuid,

    /// Script display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Current active version number.
    pub current_version: i32,

    /// Script lifecycle status (draft, active, inactive).
    pub status: GovScriptStatus,

    /// Whether this is a system-provided script.
    pub is_system: bool,

    /// Who created this script.
    pub created_by: Uuid,

    /// When the script was created.
    pub created_at: DateTime<Utc>,

    /// When the script was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new provisioning script (creates both script and initial version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProvisioningScript {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub script_body: String,
    pub created_by: Uuid,
}

/// Request to update provisioning script metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProvisioningScript {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Filter options for listing provisioning scripts.
#[derive(Debug, Clone, Default)]
pub struct ScriptFilter {
    pub status: Option<GovScriptStatus>,
    pub search: Option<String>,
}

impl GovProvisioningScript {
    /// Create a new provisioning script.
    pub async fn create(
        pool: &sqlx::PgPool,
        params: CreateProvisioningScript,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_provisioning_scripts (
                tenant_id, name, description, created_by
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(params.tenant_id)
        .bind(&params.name)
        .bind(&params.description)
        .bind(params.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a script by ID within a tenant.
    pub async fn get_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_provisioning_scripts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List scripts for a tenant with optional filtering and pagination.
    ///
    /// Returns a tuple of (scripts, `total_count`) for pagination support.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ScriptFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_provisioning_scripts
            WHERE tenant_id = $1
            ",
        );
        let mut count_query = String::from(
            r"
            SELECT COUNT(*) FROM gov_provisioning_scripts
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            let clause = format!(" AND status = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.search.is_some() {
            param_count += 1;
            let clause = format!(" AND name ILIKE ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovProvisioningScript>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
            cq = cq.bind(status);
        }
        if let Some(ref search) = filter.search {
            let pattern = format!("%{search}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }

        let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;
        let total = cq.fetch_one(pool).await?;

        Ok((rows, total))
    }

    /// Update script metadata (name and/or description).
    pub async fn update_metadata(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
        params: UpdateProvisioningScript,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if params.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if params.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            let _ = param_idx;
        }

        let query = format!(
            "UPDATE gov_provisioning_scripts SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovProvisioningScript>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = params.name {
            q = q.bind(name);
        }
        if let Some(ref description) = params.description {
            q = q.bind(description);
        }

        q.fetch_optional(pool).await
    }

    /// Update script status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
        status: GovScriptStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_provisioning_scripts
            SET status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Update the current version number.
    pub async fn update_current_version(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
        version: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_provisioning_scripts
            SET current_version = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(version)
        .fetch_optional(pool)
        .await
    }

    /// Delete a provisioning script.
    pub async fn delete(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_provisioning_scripts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count scripts by status for a tenant.
    pub async fn count_by_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: GovScriptStatus,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_provisioning_scripts
            WHERE tenant_id = $1 AND status = $2
            ",
        )
        .bind(tenant_id)
        .bind(status)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_params() {
        let params = CreateProvisioningScript {
            tenant_id: Uuid::new_v4(),
            name: "Test Script".to_string(),
            description: Some("A test script".to_string()),
            script_body: "function transform(input) { return input; }".to_string(),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(params.name, "Test Script");
        assert!(params.description.is_some());
    }

    #[test]
    fn test_update_params() {
        let params = UpdateProvisioningScript {
            name: Some("Updated Name".to_string()),
            description: None,
        };

        assert!(params.name.is_some());
        assert!(params.description.is_none());
    }

    #[test]
    fn test_script_filter_default() {
        let filter = ScriptFilter::default();

        assert!(filter.status.is_none());
        assert!(filter.search.is_none());
    }

    #[test]
    fn test_script_filter_with_search() {
        let filter = ScriptFilter {
            status: Some(GovScriptStatus::Active),
            search: Some("email".to_string()),
        };

        assert_eq!(filter.status, Some(GovScriptStatus::Active));
        assert_eq!(filter.search, Some("email".to_string()));
    }

    #[test]
    fn test_provisioning_script_struct() {
        let now = Utc::now();
        let script = GovProvisioningScript {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Username Generator".to_string(),
            description: Some("Generates unique usernames".to_string()),
            current_version: 1,
            status: GovScriptStatus::Draft,
            is_system: false,
            created_by: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(script.name, "Username Generator");
        assert_eq!(script.current_version, 1);
        assert_eq!(script.status, GovScriptStatus::Draft);
        assert!(!script.is_system);
    }
}
