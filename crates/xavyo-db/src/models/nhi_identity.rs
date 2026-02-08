//! Unified NHI Identity base model (201-tool-nhi-promotion).
//!
//! The `nhi_identities` table is the single base table for ALL non-human identities.
//! Every NHI type (service account, agent, tool) has exactly one row here.
//! Extension tables (`nhi_tools`, `nhi_agents`, `nhi_service_accounts`) hold type-specific fields.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_nhi::{NhiLifecycleState, NhiType};

/// A unified NHI identity record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiIdentity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub nhi_type: NhiType,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub lifecycle_state: NhiLifecycleState,
    pub suspension_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub risk_score: Option<i32>,
    pub last_certified_at: Option<DateTime<Utc>>,
    pub next_certification_at: Option<DateTime<Utc>>,
    pub last_certified_by: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

/// Request to create a new NHI identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiIdentity {
    pub nhi_type: NhiType,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub rotation_interval_days: Option<i32>,
    pub created_by: Option<Uuid>,
}

/// Request to update an existing NHI identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNhiIdentity {
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner_id: Option<Option<Uuid>>,
    pub backup_owner_id: Option<Option<Uuid>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub inactivity_threshold_days: Option<Option<i32>>,
    pub rotation_interval_days: Option<Option<i32>>,
}

/// Filter options for listing NHI identities.
#[derive(Debug, Clone, Default)]
pub struct NhiIdentityFilter {
    pub nhi_type: Option<NhiType>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
}

impl NhiIdentity {
    /// Create a new NHI identity.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateNhiIdentity,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_identities (
                tenant_id, nhi_type, name, description, owner_id, backup_owner_id,
                expires_at, inactivity_threshold_days, rotation_interval_days, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.nhi_type)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.owner_id)
        .bind(input.backup_owner_id)
        .bind(input.expires_at)
        .bind(input.inactivity_threshold_days)
        .bind(input.rotation_interval_days)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find an NHI identity by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_identities
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List NHI identities with optional filtering and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiIdentityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        let mut query = String::from(
            r"
            SELECT * FROM nhi_identities
            WHERE tenant_id = $1
            ",
        );
        let mut param_idx = 2;

        if filter.nhi_type.is_some() {
            query.push_str(&format!(" AND nhi_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.lifecycle_state.is_some() {
            query.push_str(&format!(" AND lifecycle_state = ${param_idx}"));
            param_idx += 1;
        }
        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND owner_id = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(nhi_type) = filter.nhi_type {
            q = q.bind(nhi_type);
        }
        if let Some(lifecycle_state) = filter.lifecycle_state {
            q = q.bind(lifecycle_state);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count NHI identities with optional filtering.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiIdentityFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM nhi_identities
            WHERE tenant_id = $1
            ",
        );
        let mut param_idx = 2;

        if filter.nhi_type.is_some() {
            query.push_str(&format!(" AND nhi_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.lifecycle_state.is_some() {
            query.push_str(&format!(" AND lifecycle_state = ${param_idx}"));
            param_idx += 1;
        }
        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND owner_id = ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(nhi_type) = filter.nhi_type {
            q = q.bind(nhi_type);
        }
        if let Some(lifecycle_state) = filter.lifecycle_state {
            q = q.bind(lifecycle_state);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        q.fetch_one(pool).await
    }

    /// Update an existing NHI identity.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateNhiIdentity,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.owner_id.is_some() {
            updates.push(format!("owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.backup_owner_id.is_some() {
            updates.push(format!("backup_owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.expires_at.is_some() {
            updates.push(format!("expires_at = ${param_idx}"));
            param_idx += 1;
        }
        if input.inactivity_threshold_days.is_some() {
            updates.push(format!("inactivity_threshold_days = ${param_idx}"));
            param_idx += 1;
        }
        if input.rotation_interval_days.is_some() {
            updates.push(format!("rotation_interval_days = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE nhi_identities SET {} WHERE tenant_id = $1 AND id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id).bind(id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref owner_opt) = input.owner_id {
            q = q.bind(*owner_opt);
        }
        if let Some(ref backup_opt) = input.backup_owner_id {
            q = q.bind(*backup_opt);
        }
        if let Some(ref expires_opt) = input.expires_at {
            q = q.bind(*expires_opt);
        }
        if let Some(ref inactivity_opt) = input.inactivity_threshold_days {
            q = q.bind(*inactivity_opt);
        }
        if let Some(ref rotation_opt) = input.rotation_interval_days {
            q = q.bind(*rotation_opt);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an NHI identity.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM nhi_identities
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the lifecycle state of an NHI identity.
    pub async fn update_lifecycle_state(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_state: NhiLifecycleState,
        reason: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE nhi_identities
            SET lifecycle_state = $3,
                suspension_reason = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(new_state)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Update the last activity timestamp.
    pub async fn update_last_activity(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_identities
            SET last_activity_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the risk score.
    pub async fn update_risk_score(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        risk_score: i32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_identities
            SET risk_score = $3, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(risk_score)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update certification tracking fields.
    pub async fn update_certification(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        certified_by: Uuid,
        next_certification_at: Option<DateTime<Utc>>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_identities
            SET last_certified_at = NOW(),
                last_certified_by = $3,
                next_certification_at = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(certified_by)
        .bind(next_certification_at)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_identity_serialization() {
        let identity = NhiIdentity {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_type: NhiType::Agent,
            name: "test-agent".to_string(),
            description: Some("A test agent".to_string()),
            owner_id: Some(Uuid::new_v4()),
            backup_owner_id: None,
            lifecycle_state: NhiLifecycleState::Active,
            suspension_reason: None,
            expires_at: None,
            last_activity_at: None,
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            risk_score: Some(25),
            last_certified_at: None,
            next_certification_at: None,
            last_certified_by: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        };

        let json = serde_json::to_string(&identity).unwrap();
        assert!(json.contains("test-agent"));
        assert!(json.contains("\"agent\""));
        assert!(json.contains("\"active\""));

        let deserialized: NhiIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test-agent");
        assert_eq!(deserialized.nhi_type, NhiType::Agent);
        assert_eq!(deserialized.lifecycle_state, NhiLifecycleState::Active);
    }

    #[test]
    fn test_create_nhi_identity() {
        let input = CreateNhiIdentity {
            nhi_type: NhiType::Tool,
            name: "my-tool".to_string(),
            description: None,
            owner_id: None,
            backup_owner_id: None,
            expires_at: None,
            inactivity_threshold_days: None,
            rotation_interval_days: None,
            created_by: None,
        };

        assert_eq!(input.nhi_type, NhiType::Tool);
        assert_eq!(input.name, "my-tool");
    }

    #[test]
    fn test_update_nhi_identity_default() {
        let update = UpdateNhiIdentity::default();
        assert!(update.name.is_none());
        assert!(update.description.is_none());
        assert!(update.owner_id.is_none());
    }

    #[test]
    fn test_nhi_identity_filter_default() {
        let filter = NhiIdentityFilter::default();
        assert!(filter.nhi_type.is_none());
        assert!(filter.lifecycle_state.is_none());
        assert!(filter.owner_id.is_none());
    }
}
