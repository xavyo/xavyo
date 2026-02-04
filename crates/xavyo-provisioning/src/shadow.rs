//! Shadow Objects
//!
//! Shadows are local representations of accounts in external systems.
//! They track the state of provisioned accounts and enable:
//! - Detecting external modifications
//! - Managing pending operations during outages
//! - Reconciliation between xavyo and target systems

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

/// Shadow errors.
#[derive(Debug, Error)]
pub enum ShadowError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Shadow not found.
    #[error("Shadow not found: {0}")]
    NotFound(Uuid),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for shadow operations.
pub type ShadowResult<T> = Result<T, ShadowError>;

/// Synchronization situation - describes the relationship between
/// a shadow and its corresponding focus object (user).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncSituation {
    /// Shadow is properly linked to a user.
    Linked,

    /// Shadow exists but is not linked to any user.
    Unlinked,

    /// Shadow exists but no matching user could be found.
    Unmatched,

    /// Multiple users match this shadow (ambiguous).
    Disputed,

    /// Shadow is linked to multiple users (error state).
    Collision,

    /// The external account has been deleted.
    Deleted,
}

impl SyncSituation {
    /// Convert to string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncSituation::Linked => "linked",
            SyncSituation::Unlinked => "unlinked",
            SyncSituation::Unmatched => "unmatched",
            SyncSituation::Disputed => "disputed",
            SyncSituation::Collision => "collision",
            SyncSituation::Deleted => "deleted",
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
            "collision" => Ok(SyncSituation::Collision),
            "deleted" => Ok(SyncSituation::Deleted),
            _ => Err(format!("Unknown sync situation: {s}")),
        }
    }
}

/// Shadow lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowState {
    /// Shadow is active and represents a live account.
    Active,

    /// Shadow has pending operations that haven't completed.
    Pending,

    /// Shadow represents a deleted account (retained for audit).
    Dead,

    /// Shadow state is unknown (needs reconciliation).
    Unknown,
}

impl ShadowState {
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            ShadowState::Active => "active",
            ShadowState::Pending => "pending",
            ShadowState::Dead => "dead",
            ShadowState::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for ShadowState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ShadowState::Active),
            "pending" => Ok(ShadowState::Pending),
            "dead" => Ok(ShadowState::Dead),
            "unknown" => Ok(ShadowState::Unknown),
            _ => Err(format!("Unknown shadow state: {s}")),
        }
    }
}

/// A shadow object representing an account in an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shadow {
    /// Shadow ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// Linked user ID (None if unlinked/unmatched).
    pub user_id: Option<Uuid>,

    /// Object class in target system.
    pub object_class: String,

    /// Unique identifier in target system.
    pub target_uid: String,

    /// Current attributes from target system.
    pub attributes: serde_json::Value,

    /// Expected attributes (what we think should be there).
    pub expected_attributes: serde_json::Value,

    /// Synchronization situation.
    pub sync_situation: SyncSituation,

    /// Shadow lifecycle state.
    pub state: ShadowState,

    /// Number of pending operations.
    pub pending_operation_count: i32,

    /// Last successful sync timestamp.
    pub last_sync_at: Option<DateTime<Utc>>,

    /// Last error message.
    pub last_error: Option<String>,

    /// When the shadow was created.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl Shadow {
    /// Create a new shadow for a linked account.
    #[must_use] 
    pub fn new_linked(
        tenant_id: Uuid,
        connector_id: Uuid,
        user_id: Uuid,
        object_class: String,
        target_uid: String,
        attributes: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            user_id: Some(user_id),
            object_class,
            target_uid,
            attributes: attributes.clone(),
            expected_attributes: attributes,
            sync_situation: SyncSituation::Linked,
            state: ShadowState::Active,
            pending_operation_count: 0,
            last_sync_at: Some(now),
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new unlinked shadow (discovered but not matched).
    #[must_use] 
    pub fn new_unlinked(
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: String,
        target_uid: String,
        attributes: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            user_id: None,
            object_class,
            target_uid,
            attributes,
            expected_attributes: serde_json::json!({}),
            sync_situation: SyncSituation::Unlinked,
            state: ShadowState::Unknown,
            pending_operation_count: 0,
            last_sync_at: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if attributes have diverged from expected.
    #[must_use] 
    pub fn has_diverged(&self) -> bool {
        self.attributes != self.expected_attributes
    }

    /// Mark shadow as having pending operations.
    pub fn mark_pending(&mut self) {
        self.pending_operation_count += 1;
        if self.state == ShadowState::Active {
            self.state = ShadowState::Pending;
        }
        self.updated_at = Utc::now();
    }

    /// Mark operation as complete.
    pub fn operation_completed(&mut self, success: bool, error: Option<String>) {
        self.pending_operation_count = (self.pending_operation_count - 1).max(0);
        if self.pending_operation_count == 0 && self.state == ShadowState::Pending {
            self.state = ShadowState::Active;
        }
        if !success {
            self.last_error = error;
        }
        self.updated_at = Utc::now();
    }

    /// Update attributes after successful sync.
    pub fn update_attributes(&mut self, attributes: serde_json::Value) {
        self.attributes = attributes.clone();
        self.expected_attributes = attributes;
        self.last_sync_at = Some(Utc::now());
        self.last_error = None;
        self.updated_at = Utc::now();
    }

    /// Link shadow to a user.
    pub fn link_to_user(&mut self, user_id: Uuid) {
        self.user_id = Some(user_id);
        self.sync_situation = SyncSituation::Linked;
        self.updated_at = Utc::now();
    }

    /// Unlink shadow from user.
    pub fn unlink(&mut self) {
        self.user_id = None;
        self.sync_situation = SyncSituation::Unlinked;
        self.updated_at = Utc::now();
    }

    /// Mark shadow as deleted.
    pub fn mark_deleted(&mut self) {
        self.sync_situation = SyncSituation::Deleted;
        self.state = ShadowState::Dead;
        self.updated_at = Utc::now();
    }
}

/// Shadow repository for database operations.
pub struct ShadowRepository {
    pool: PgPool,
}

impl ShadowRepository {
    /// Create a new shadow repository.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create or update a shadow.
    #[instrument(skip(self, shadow))]
    pub async fn upsert(&self, shadow: &Shadow) -> ShadowResult<()> {
        sqlx::query(
            r"
            INSERT INTO gov_shadows (
                id, tenant_id, connector_id, user_id, object_class, target_uid,
                attributes, expected_attributes, sync_situation, state,
                pending_operation_count, last_sync_at, last_error, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ON CONFLICT (tenant_id, connector_id, target_uid) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                attributes = EXCLUDED.attributes,
                expected_attributes = EXCLUDED.expected_attributes,
                sync_situation = EXCLUDED.sync_situation,
                state = EXCLUDED.state,
                pending_operation_count = EXCLUDED.pending_operation_count,
                last_sync_at = EXCLUDED.last_sync_at,
                last_error = EXCLUDED.last_error,
                updated_at = EXCLUDED.updated_at
            ",
        )
        .bind(shadow.id)
        .bind(shadow.tenant_id)
        .bind(shadow.connector_id)
        .bind(shadow.user_id)
        .bind(&shadow.object_class)
        .bind(&shadow.target_uid)
        .bind(&shadow.attributes)
        .bind(&shadow.expected_attributes)
        .bind(shadow.sync_situation.as_str())
        .bind(shadow.state.as_str())
        .bind(shadow.pending_operation_count)
        .bind(shadow.last_sync_at)
        .bind(&shadow.last_error)
        .bind(shadow.created_at)
        .bind(shadow.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Find shadow by target UID.
    #[instrument(skip(self))]
    pub async fn find_by_target_uid(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        target_uid: &str,
    ) -> ShadowResult<Option<Shadow>> {
        let row = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                   attributes, expected_attributes, sync_situation, state,
                   pending_operation_count, last_sync_at, last_error, created_at, updated_at
            FROM gov_shadows
            WHERE tenant_id = $1 AND connector_id = $2 AND target_uid = $3
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(target_uid)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| self.row_to_shadow(&r)))
    }

    /// Find all shadows for a user.
    #[instrument(skip(self))]
    pub async fn find_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> ShadowResult<Vec<Shadow>> {
        let rows = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                   attributes, expected_attributes, sync_situation, state,
                   pending_operation_count, last_sync_at, last_error, created_at, updated_at
            FROM gov_shadows
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| self.row_to_shadow(r)).collect())
    }

    /// Find shadows with pending operations.
    #[instrument(skip(self))]
    pub async fn find_pending(
        &self,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        limit: i64,
    ) -> ShadowResult<Vec<Shadow>> {
        let rows = if let Some(cid) = connector_id {
            sqlx::query(
                r"
                SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                       attributes, expected_attributes, sync_situation, state,
                       pending_operation_count, last_sync_at, last_error, created_at, updated_at
                FROM gov_shadows
                WHERE tenant_id = $1 AND connector_id = $2 AND state = 'pending'
                ORDER BY updated_at
                LIMIT $3
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r"
                SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                       attributes, expected_attributes, sync_situation, state,
                       pending_operation_count, last_sync_at, last_error, created_at, updated_at
                FROM gov_shadows
                WHERE tenant_id = $1 AND state = 'pending'
                ORDER BY updated_at
                LIMIT $2
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.iter().map(|r| self.row_to_shadow(r)).collect())
    }

    /// Find unlinked shadows (orphans).
    #[instrument(skip(self))]
    pub async fn find_unlinked(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        limit: i64,
    ) -> ShadowResult<Vec<Shadow>> {
        let rows = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                   attributes, expected_attributes, sync_situation, state,
                   pending_operation_count, last_sync_at, last_error, created_at, updated_at
            FROM gov_shadows
            WHERE tenant_id = $1 AND connector_id = $2 AND sync_situation = 'unlinked'
            ORDER BY created_at
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| self.row_to_shadow(r)).collect())
    }

    /// Count how many distinct users are linked to shadows with the same `target_uid`.
    /// This detects collision situations where one external account maps to multiple users.
    /// Returns 0 if no shadow exists, 1 for normal linked state, >1 for collision.
    #[instrument(skip(self))]
    pub async fn count_links_for_target(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        target_uid: &str,
    ) -> ShadowResult<i64> {
        let row = sqlx::query(
            r"
            SELECT COUNT(DISTINCT user_id) as link_count
            FROM gov_shadows
            WHERE tenant_id = $1
              AND connector_id = $2
              AND target_uid = $3
              AND user_id IS NOT NULL
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(target_uid)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("link_count"))
    }

    /// Find shadows linked to a specific user for a connector.
    /// Useful for detecting if a user has multiple shadows (one-to-many).
    #[instrument(skip(self))]
    pub async fn find_by_user_and_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        user_id: Uuid,
    ) -> ShadowResult<Vec<Shadow>> {
        let rows = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, object_class, target_uid,
                   attributes, expected_attributes, sync_situation, state,
                   pending_operation_count, last_sync_at, last_error, created_at, updated_at
            FROM gov_shadows
            WHERE tenant_id = $1 AND connector_id = $2 AND user_id = $3
            ORDER BY created_at
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| self.row_to_shadow(r)).collect())
    }

    /// Delete old dead shadows.
    #[instrument(skip(self))]
    pub async fn cleanup_dead_shadows(&self, retention_days: i32) -> ShadowResult<u64> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_shadows
            WHERE state = 'dead' AND updated_at < NOW() - INTERVAL '1 day' * $1
            ",
        )
        .bind(retention_days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    fn row_to_shadow(&self, row: &sqlx::postgres::PgRow) -> Shadow {
        Shadow {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            connector_id: row.get("connector_id"),
            user_id: row.get("user_id"),
            object_class: row.get("object_class"),
            target_uid: row.get("target_uid"),
            attributes: row.get("attributes"),
            expected_attributes: row.get("expected_attributes"),
            sync_situation: row
                .get::<String, _>("sync_situation")
                .parse()
                .unwrap_or(SyncSituation::Unlinked),
            state: row
                .get::<String, _>("state")
                .parse()
                .unwrap_or(ShadowState::Unknown),
            pending_operation_count: row.get("pending_operation_count"),
            last_sync_at: row.get("last_sync_at"),
            last_error: row.get("last_error"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_situation_roundtrip() {
        for situation in [
            SyncSituation::Linked,
            SyncSituation::Unlinked,
            SyncSituation::Unmatched,
            SyncSituation::Disputed,
            SyncSituation::Collision,
            SyncSituation::Deleted,
        ] {
            let s = situation.as_str();
            let parsed: SyncSituation = s.parse().unwrap();
            assert_eq!(situation, parsed);
        }
    }

    #[test]
    fn test_shadow_state_roundtrip() {
        for state in [
            ShadowState::Active,
            ShadowState::Pending,
            ShadowState::Dead,
            ShadowState::Unknown,
        ] {
            let s = state.as_str();
            let parsed: ShadowState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn test_shadow_new_linked() {
        let shadow = Shadow::new_linked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "inetOrgPerson".to_string(),
            "uid=john,ou=users,dc=example,dc=com".to_string(),
            serde_json::json!({"cn": "John Doe"}),
        );

        assert_eq!(shadow.sync_situation, SyncSituation::Linked);
        assert_eq!(shadow.state, ShadowState::Active);
        assert!(shadow.user_id.is_some());
    }

    #[test]
    fn test_shadow_new_unlinked() {
        let shadow = Shadow::new_unlinked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "inetOrgPerson".to_string(),
            "uid=orphan,ou=users,dc=example,dc=com".to_string(),
            serde_json::json!({"cn": "Orphan Account"}),
        );

        assert_eq!(shadow.sync_situation, SyncSituation::Unlinked);
        assert_eq!(shadow.state, ShadowState::Unknown);
        assert!(shadow.user_id.is_none());
    }

    #[test]
    fn test_shadow_pending_operations() {
        let mut shadow = Shadow::new_linked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "user".to_string(),
            "CN=John,OU=Users,DC=corp,DC=com".to_string(),
            serde_json::json!({}),
        );

        assert_eq!(shadow.pending_operation_count, 0);
        assert_eq!(shadow.state, ShadowState::Active);

        shadow.mark_pending();
        assert_eq!(shadow.pending_operation_count, 1);
        assert_eq!(shadow.state, ShadowState::Pending);

        shadow.mark_pending();
        assert_eq!(shadow.pending_operation_count, 2);

        shadow.operation_completed(true, None);
        assert_eq!(shadow.pending_operation_count, 1);
        assert_eq!(shadow.state, ShadowState::Pending);

        shadow.operation_completed(true, None);
        assert_eq!(shadow.pending_operation_count, 0);
        assert_eq!(shadow.state, ShadowState::Active);
    }

    #[test]
    fn test_shadow_divergence_detection() {
        let mut shadow = Shadow::new_linked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "user".to_string(),
            "uid=test".to_string(),
            serde_json::json!({"cn": "Test"}),
        );

        assert!(!shadow.has_diverged());

        shadow.attributes = serde_json::json!({"cn": "Modified"});
        assert!(shadow.has_diverged());
    }

    #[test]
    fn test_shadow_link_unlink() {
        let mut shadow = Shadow::new_unlinked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "user".to_string(),
            "uid=test".to_string(),
            serde_json::json!({}),
        );

        assert!(shadow.user_id.is_none());
        assert_eq!(shadow.sync_situation, SyncSituation::Unlinked);

        let user_id = Uuid::new_v4();
        shadow.link_to_user(user_id);
        assert_eq!(shadow.user_id, Some(user_id));
        assert_eq!(shadow.sync_situation, SyncSituation::Linked);

        shadow.unlink();
        assert!(shadow.user_id.is_none());
        assert_eq!(shadow.sync_situation, SyncSituation::Unlinked);
    }

    #[test]
    fn test_shadow_mark_deleted() {
        let mut shadow = Shadow::new_linked(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "user".to_string(),
            "uid=test".to_string(),
            serde_json::json!({}),
        );

        assert_eq!(shadow.sync_situation, SyncSituation::Linked);
        assert_eq!(shadow.state, ShadowState::Active);

        shadow.mark_deleted();
        assert_eq!(shadow.sync_situation, SyncSituation::Deleted);
        assert_eq!(shadow.state, ShadowState::Dead);
    }
}
