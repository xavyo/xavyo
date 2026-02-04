//! Inbound Change model for tracking detected changes from external systems.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Type of change detected in external system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum InboundChangeType {
    /// New account created.
    Create,
    /// Existing account updated.
    Update,
    /// Account deleted.
    Delete,
}

impl fmt::Display for InboundChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InboundChangeType::Create => write!(f, "create"),
            InboundChangeType::Update => write!(f, "update"),
            InboundChangeType::Delete => write!(f, "delete"),
        }
    }
}

impl std::str::FromStr for InboundChangeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(InboundChangeType::Create),
            "update" => Ok(InboundChangeType::Update),
            "delete" => Ok(InboundChangeType::Delete),
            _ => Err(format!("Unknown change type: {s}")),
        }
    }
}

/// Synchronization situation determined by correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SyncSituation {
    /// Account is connected to an identity.
    Linked,
    /// Account found, one correlation match.
    Unlinked,
    /// Account found, no correlation match.
    Unmatched,
    /// Multiple correlation matches.
    Disputed,
    /// Account removed from external system.
    Deleted,
    /// Account linked to multiple identities (error).
    Collision,
}

impl fmt::Display for SyncSituation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncSituation::Linked => write!(f, "linked"),
            SyncSituation::Unlinked => write!(f, "unlinked"),
            SyncSituation::Unmatched => write!(f, "unmatched"),
            SyncSituation::Disputed => write!(f, "disputed"),
            SyncSituation::Deleted => write!(f, "deleted"),
            SyncSituation::Collision => write!(f, "collision"),
        }
    }
}

impl std::str::FromStr for SyncSituation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "linked" => Ok(SyncSituation::Linked),
            "unlinked" => Ok(SyncSituation::Unlinked),
            "unmatched" => Ok(SyncSituation::Unmatched),
            "disputed" => Ok(SyncSituation::Disputed),
            "deleted" => Ok(SyncSituation::Deleted),
            "collision" => Ok(SyncSituation::Collision),
            _ => Err(format!("Unknown sync situation: {s}")),
        }
    }
}

/// Processing status for inbound changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum InboundProcessingStatus {
    /// Waiting to be processed.
    Pending,
    /// Currently being processed.
    Processing,
    /// Successfully processed.
    Completed,
    /// Processing failed.
    Failed,
    /// Conflict detected with outbound operation.
    Conflict,
}

impl fmt::Display for InboundProcessingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InboundProcessingStatus::Pending => write!(f, "pending"),
            InboundProcessingStatus::Processing => write!(f, "processing"),
            InboundProcessingStatus::Completed => write!(f, "completed"),
            InboundProcessingStatus::Failed => write!(f, "failed"),
            InboundProcessingStatus::Conflict => write!(f, "conflict"),
        }
    }
}

impl std::str::FromStr for InboundProcessingStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(InboundProcessingStatus::Pending),
            "processing" => Ok(InboundProcessingStatus::Processing),
            "completed" => Ok(InboundProcessingStatus::Completed),
            "failed" => Ok(InboundProcessingStatus::Failed),
            "conflict" => Ok(InboundProcessingStatus::Conflict),
            _ => Err(format!("Unknown processing status: {s}")),
        }
    }
}

/// An inbound change detected from an external system.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InboundChange {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub change_type: String,
    pub external_uid: String,
    pub object_class: String,
    pub attributes: serde_json::Value,
    pub sync_situation: String,
    pub correlation_result: Option<serde_json::Value>,
    pub linked_identity_id: Option<Uuid>,
    pub conflict_id: Option<Uuid>,
    pub processing_status: String,
    pub error_message: Option<String>,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl InboundChange {
    /// Get the change type enum.
    #[must_use] 
    pub fn change_type(&self) -> InboundChangeType {
        self.change_type
            .parse()
            .unwrap_or(InboundChangeType::Update)
    }

    /// Get the sync situation enum.
    #[must_use] 
    pub fn sync_situation(&self) -> SyncSituation {
        self.sync_situation
            .parse()
            .unwrap_or(SyncSituation::Unmatched)
    }

    /// Get the processing status enum.
    #[must_use] 
    pub fn processing_status(&self) -> InboundProcessingStatus {
        self.processing_status
            .parse()
            .unwrap_or(InboundProcessingStatus::Pending)
    }

    /// Create a new inbound change.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &CreateInboundChange,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_inbound_changes (
                tenant_id, connector_id, change_type, external_uid,
                object_class, attributes, sync_situation, correlation_result,
                linked_identity_id, processing_status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.connector_id)
        .bind(input.change_type.to_string())
        .bind(&input.external_uid)
        .bind(&input.object_class)
        .bind(&input.attributes)
        .bind(input.sync_situation.to_string())
        .bind(&input.correlation_result)
        .bind(input.linked_identity_id)
        .bind(InboundProcessingStatus::Pending.to_string())
        .fetch_one(pool)
        .await
    }

    /// Find by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_inbound_changes
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List changes by connector with filtering.
    pub async fn list_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        filter: &InboundChangeFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            "SELECT * FROM gov_inbound_changes WHERE tenant_id = $1 AND connector_id = $2",
        );
        let mut param_count = 2;

        if filter.processing_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND processing_status = ${param_count}"));
        }
        if filter.sync_situation.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND sync_situation = ${param_count}"));
        }
        if filter.change_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND change_type = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, InboundChange>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(ref status) = filter.processing_status {
            q = q.bind(status.to_string());
        }
        if let Some(ref situation) = filter.sync_situation {
            q = q.bind(situation.to_string());
        }
        if let Some(ref change_type) = filter.change_type {
            q = q.bind(change_type.to_string());
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count changes by connector with filtering.
    pub async fn count_by_connector(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        filter: &InboundChangeFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            "SELECT COUNT(*) FROM gov_inbound_changes WHERE tenant_id = $1 AND connector_id = $2",
        );
        let mut param_count = 2;

        if filter.processing_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND processing_status = ${param_count}"));
        }
        if filter.sync_situation.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND sync_situation = ${param_count}"));
        }
        if filter.change_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND change_type = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(ref status) = filter.processing_status {
            q = q.bind(status.to_string());
        }
        if let Some(ref situation) = filter.sync_situation {
            q = q.bind(situation.to_string());
        }
        if let Some(ref change_type) = filter.change_type {
            q = q.bind(change_type.to_string());
        }

        q.fetch_one(pool).await
    }

    /// Get pending changes for processing (with FOR UPDATE SKIP LOCKED).
    pub async fn get_pending_for_processing(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        batch_size: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_inbound_changes
            WHERE tenant_id = $1
                AND connector_id = $2
                AND processing_status = 'pending'
            ORDER BY created_at ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(batch_size)
        .fetch_all(pool)
        .await
    }

    /// Mark change as processing.
    pub async fn mark_processing(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET processing_status = 'processing'
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Mark change as completed.
    pub async fn mark_completed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        linked_identity_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET processing_status = 'completed',
                linked_identity_id = COALESCE($3, linked_identity_id),
                processed_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(linked_identity_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark change as failed.
    pub async fn mark_failed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET processing_status = 'failed',
                error_message = $3,
                processed_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Mark change as conflict.
    pub async fn mark_conflict(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        conflict_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET processing_status = 'conflict',
                conflict_id = $3
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(conflict_id)
        .fetch_optional(pool)
        .await
    }

    /// Update sync situation and linked identity.
    pub async fn update_situation(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        situation: SyncSituation,
        linked_identity_id: Option<Uuid>,
        correlation_result: Option<serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET sync_situation = $3,
                linked_identity_id = $4,
                correlation_result = COALESCE($5, correlation_result)
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(situation.to_string())
        .bind(linked_identity_id)
        .bind(correlation_result)
        .fetch_optional(pool)
        .await
    }

    /// Reset failed change to pending for retry.
    pub async fn retry(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_inbound_changes
            SET processing_status = 'pending',
                error_message = NULL,
                processed_at = NULL
            WHERE tenant_id = $1 AND id = $2 AND processing_status = 'failed'
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }
}

/// Input for creating an inbound change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInboundChange {
    pub connector_id: Uuid,
    pub change_type: InboundChangeType,
    pub external_uid: String,
    pub object_class: String,
    pub attributes: serde_json::Value,
    pub sync_situation: SyncSituation,
    pub correlation_result: Option<serde_json::Value>,
    pub linked_identity_id: Option<Uuid>,
}

/// Filter for listing inbound changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InboundChangeFilter {
    pub processing_status: Option<InboundProcessingStatus>,
    pub sync_situation: Option<SyncSituation>,
    pub change_type: Option<InboundChangeType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_roundtrip() {
        for change_type in [
            InboundChangeType::Create,
            InboundChangeType::Update,
            InboundChangeType::Delete,
        ] {
            let s = change_type.to_string();
            let parsed: InboundChangeType = s.parse().unwrap();
            assert_eq!(change_type, parsed);
        }
    }

    #[test]
    fn test_sync_situation_roundtrip() {
        for situation in [
            SyncSituation::Linked,
            SyncSituation::Unlinked,
            SyncSituation::Unmatched,
            SyncSituation::Disputed,
            SyncSituation::Deleted,
            SyncSituation::Collision,
        ] {
            let s = situation.to_string();
            let parsed: SyncSituation = s.parse().unwrap();
            assert_eq!(situation, parsed);
        }
    }

    #[test]
    fn test_processing_status_roundtrip() {
        for status in [
            InboundProcessingStatus::Pending,
            InboundProcessingStatus::Processing,
            InboundProcessingStatus::Completed,
            InboundProcessingStatus::Failed,
            InboundProcessingStatus::Conflict,
        ] {
            let s = status.to_string();
            let parsed: InboundProcessingStatus = s.parse().unwrap();
            assert_eq!(status, parsed);
        }
    }
}
