//! Governance Access Snapshot model.
//!
//! Point-in-time captures of user access for audit purposes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of access snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "access_snapshot_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AccessSnapshotType {
    /// Captured before leaver revocations.
    PreLeaver,
    /// Captured before mover changes.
    PreMover,
    /// Current access (on-demand snapshot).
    Current,
}

/// A single assignment in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAssignment {
    pub id: Uuid,
    pub entitlement_id: Uuid,
    pub entitlement_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_external_id: Option<String>,
    pub application_id: Uuid,
    pub application_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,
    pub granted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Uuid>,
}

/// Snapshot content structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotContent {
    #[serde(default)]
    pub assignments: Vec<SnapshotAssignment>,
    #[serde(default)]
    pub total_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_at: Option<DateTime<Utc>>,
}

/// A governance access snapshot.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovAccessSnapshot {
    /// Unique identifier for the snapshot.
    pub id: Uuid,

    /// The tenant this snapshot belongs to.
    pub tenant_id: Uuid,

    /// The user whose access was captured.
    pub user_id: Uuid,

    /// The event that triggered this snapshot.
    pub event_id: Uuid,

    /// Type of snapshot.
    pub snapshot_type: AccessSnapshotType,

    /// Assignment details (JSON).
    pub assignments: serde_json::Value,

    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new access snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessSnapshot {
    pub user_id: Uuid,
    pub event_id: Uuid,
    pub snapshot_type: AccessSnapshotType,
    pub assignments: SnapshotContent,
}

/// Filter options for listing access snapshots.
#[derive(Debug, Clone, Default)]
pub struct AccessSnapshotFilter {
    pub user_id: Option<Uuid>,
    pub event_id: Option<Uuid>,
    pub snapshot_type: Option<AccessSnapshotType>,
}

impl GovAccessSnapshot {
    /// Find a snapshot by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_access_snapshots
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find snapshot by event ID.
    pub async fn find_by_event(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_access_snapshots
            WHERE tenant_id = $1 AND event_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(event_id)
        .fetch_optional(pool)
        .await
    }

    /// List snapshots for a user with pagination.
    pub async fn list_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_access_snapshots
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count snapshots for a user.
    pub async fn count_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_access_snapshots
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    /// List snapshots for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AccessSnapshotFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_access_snapshots
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.event_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_id = ${param_count}"));
        }
        if filter.snapshot_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND snapshot_type = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovAccessSnapshot>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(event_id) = filter.event_id {
            q = q.bind(event_id);
        }
        if let Some(snapshot_type) = filter.snapshot_type {
            q = q.bind(snapshot_type);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new access snapshot.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateAccessSnapshot,
    ) -> Result<Self, sqlx::Error> {
        let assignments_json = serde_json::to_value(&input.assignments)
            .unwrap_or_else(|_| serde_json::json!({"assignments": [], "total_count": 0}));

        sqlx::query_as(
            r"
            INSERT INTO gov_access_snapshots (
                tenant_id, user_id, event_id, snapshot_type, assignments
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.event_id)
        .bind(input.snapshot_type)
        .bind(&assignments_json)
        .fetch_one(pool)
        .await
    }

    /// Parse the assignments JSON.
    #[must_use] 
    pub fn parse_assignments(&self) -> SnapshotContent {
        serde_json::from_value(self.assignments.clone()).unwrap_or_default()
    }

    /// Get the total count of assignments in the snapshot.
    #[must_use] 
    pub fn assignment_count(&self) -> i32 {
        self.parse_assignments().total_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_type_serialization() {
        let pre_leaver = AccessSnapshotType::PreLeaver;
        let json = serde_json::to_string(&pre_leaver).unwrap();
        assert_eq!(json, "\"pre_leaver\"");

        let pre_mover = AccessSnapshotType::PreMover;
        let json = serde_json::to_string(&pre_mover).unwrap();
        assert_eq!(json, "\"pre_mover\"");

        let current = AccessSnapshotType::Current;
        let json = serde_json::to_string(&current).unwrap();
        assert_eq!(json, "\"current\"");
    }

    #[test]
    fn test_snapshot_content_default() {
        let content = SnapshotContent::default();
        assert!(content.assignments.is_empty());
        assert_eq!(content.total_count, 0);
    }

    #[test]
    fn test_snapshot_assignment_serialization() {
        let assignment = SnapshotAssignment {
            id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            entitlement_name: "GitHub Access".to_string(),
            entitlement_external_id: Some("github".to_string()),
            application_id: Uuid::new_v4(),
            application_name: "GitHub".to_string(),
            source: Some("birthright".to_string()),
            policy_id: Some(Uuid::new_v4()),
            granted_at: Utc::now(),
            granted_by: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&assignment).unwrap();
        assert!(json.contains("GitHub Access"));
        assert!(json.contains("birthright"));
    }
}
