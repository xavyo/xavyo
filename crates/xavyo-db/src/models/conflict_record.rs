//! Conflict Record model.
//!
//! Tracks detected conflicts between provisioning operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of conflict detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ConflictType {
    /// Two operations update the same entity concurrently.
    ConcurrentUpdate,
    /// Operation based on outdated state.
    StaleData,
    /// Target entity no longer exists.
    MissingTarget,
    /// External system modified data outside this system.
    ExternalChange,
}

impl std::fmt::Display for ConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictType::ConcurrentUpdate => write!(f, "concurrent_update"),
            ConflictType::StaleData => write!(f, "stale_data"),
            ConflictType::MissingTarget => write!(f, "missing_target"),
            ConflictType::ExternalChange => write!(f, "external_change"),
        }
    }
}

impl std::str::FromStr for ConflictType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "concurrent_update" => Ok(ConflictType::ConcurrentUpdate),
            "stale_data" => Ok(ConflictType::StaleData),
            "missing_target" => Ok(ConflictType::MissingTarget),
            "external_change" => Ok(ConflictType::ExternalChange),
            _ => Err(format!("Unknown conflict type: {}", s)),
        }
    }
}

/// Strategy for resolving conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    /// Most recent timestamp wins.
    LastWriteWins,
    /// First operation wins.
    FirstWriteWins,
    /// Requires administrator intervention.
    Manual,
    /// Merge non-conflicting attributes.
    Merge,
}

impl std::fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionStrategy::LastWriteWins => write!(f, "last_write_wins"),
            ResolutionStrategy::FirstWriteWins => write!(f, "first_write_wins"),
            ResolutionStrategy::Manual => write!(f, "manual"),
            ResolutionStrategy::Merge => write!(f, "merge"),
        }
    }
}

impl std::str::FromStr for ResolutionStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "last_write_wins" => Ok(ResolutionStrategy::LastWriteWins),
            "first_write_wins" => Ok(ResolutionStrategy::FirstWriteWins),
            "manual" => Ok(ResolutionStrategy::Manual),
            "merge" => Ok(ResolutionStrategy::Merge),
            _ => Err(format!("Unknown resolution strategy: {}", s)),
        }
    }
}

/// Outcome of conflict resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ResolutionOutcome {
    /// Primary operation was applied.
    Applied,
    /// Primary operation was skipped (superseded by another).
    Superseded,
    /// Attributes were merged.
    Merged,
    /// Both operations were rejected.
    Rejected,
    /// Awaiting manual resolution.
    Pending,
}

impl std::fmt::Display for ResolutionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionOutcome::Applied => write!(f, "applied"),
            ResolutionOutcome::Superseded => write!(f, "superseded"),
            ResolutionOutcome::Merged => write!(f, "merged"),
            ResolutionOutcome::Rejected => write!(f, "rejected"),
            ResolutionOutcome::Pending => write!(f, "pending"),
        }
    }
}

impl std::str::FromStr for ResolutionOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "applied" => Ok(ResolutionOutcome::Applied),
            "superseded" => Ok(ResolutionOutcome::Superseded),
            "merged" => Ok(ResolutionOutcome::Merged),
            "rejected" => Ok(ResolutionOutcome::Rejected),
            "pending" => Ok(ResolutionOutcome::Pending),
            _ => Err(format!("Unknown resolution outcome: {}", s)),
        }
    }
}

/// A conflict record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// Unique identifier for the conflict.
    pub id: Uuid,

    /// The tenant this conflict belongs to.
    pub tenant_id: Uuid,

    /// The primary operation involved in the conflict.
    pub operation_id: Uuid,

    /// The conflicting operation (if known).
    pub conflicting_operation_id: Option<Uuid>,

    /// Type of conflict.
    pub conflict_type: ConflictType,

    /// Attributes affected by the conflict.
    pub affected_attributes: serde_json::Value,

    /// When the conflict was detected.
    pub detected_at: DateTime<Utc>,

    /// Strategy used to resolve the conflict.
    pub resolution_strategy: ResolutionStrategy,

    /// When the conflict was resolved.
    pub resolved_at: Option<DateTime<Utc>>,

    /// Outcome of the resolution.
    pub resolution_outcome: Option<ResolutionOutcome>,

    /// Who resolved the conflict (user ID).
    pub resolved_by: Option<Uuid>,

    /// Notes about the resolution.
    pub notes: Option<String>,
}

/// Request to create a conflict record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateConflictRecord {
    pub operation_id: Uuid,
    pub conflicting_operation_id: Option<Uuid>,
    pub conflict_type: ConflictType,
    pub affected_attributes: Vec<String>,
    pub resolution_strategy: ResolutionStrategy,
}

/// Request to resolve a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveConflict {
    pub outcome: ResolutionOutcome,
    pub notes: Option<String>,
}

/// Filter for listing conflicts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConflictFilter {
    pub operation_id: Option<Uuid>,
    pub conflict_type: Option<ConflictType>,
    pub resolution_outcome: Option<ResolutionOutcome>,
    pub pending_only: bool,
}

impl ConflictRecord {
    /// Find a conflict by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM conflict_records
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List conflicts for an operation.
    pub async fn list_by_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM conflict_records
            WHERE (operation_id = $1 OR conflicting_operation_id = $1)
                AND tenant_id = $2
            ORDER BY detected_at DESC
            "#,
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List pending conflicts (awaiting resolution).
    pub async fn list_pending(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM conflict_records
            WHERE tenant_id = $1
                AND (resolution_outcome IS NULL OR resolution_outcome = 'pending')
            ORDER BY detected_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count pending conflicts.
    pub async fn count_pending(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM conflict_records
            WHERE tenant_id = $1
                AND (resolution_outcome IS NULL OR resolution_outcome = 'pending')
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// List conflicts with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ConflictFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM conflict_records
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.pending_only {
            query.push_str(" AND (resolution_outcome IS NULL OR resolution_outcome = 'pending')");
        }
        if filter.operation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (operation_id = ${} OR conflicting_operation_id = ${})",
                param_count, param_count
            ));
        }
        if filter.conflict_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND conflict_type = ${}", param_count));
        }
        if filter.resolution_outcome.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND resolution_outcome = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY detected_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, ConflictRecord>(&query).bind(tenant_id);

        if let Some(operation_id) = filter.operation_id {
            q = q.bind(operation_id);
        }
        if let Some(conflict_type) = filter.conflict_type {
            q = q.bind(conflict_type.to_string());
        }
        if let Some(resolution_outcome) = filter.resolution_outcome {
            q = q.bind(resolution_outcome.to_string());
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new conflict record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateConflictRecord,
    ) -> Result<Self, sqlx::Error> {
        let affected_attrs =
            serde_json::to_value(&input.affected_attributes).unwrap_or(serde_json::json!([]));

        sqlx::query_as(
            r#"
            INSERT INTO conflict_records (
                tenant_id, operation_id, conflicting_operation_id, conflict_type,
                affected_attributes, detected_at, resolution_strategy
            )
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.operation_id)
        .bind(input.conflicting_operation_id)
        .bind(input.conflict_type.to_string())
        .bind(affected_attrs)
        .bind(input.resolution_strategy.to_string())
        .fetch_one(pool)
        .await
    }

    /// Resolve a conflict.
    pub async fn resolve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        resolved_by: Uuid,
        input: &ResolveConflict,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE conflict_records
            SET resolved_at = NOW(),
                resolution_outcome = $3,
                resolved_by = $4,
                notes = $5
            WHERE id = $1 AND tenant_id = $2
                AND (resolution_outcome IS NULL OR resolution_outcome = 'pending')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.outcome.to_string())
        .bind(resolved_by)
        .bind(&input.notes)
        .fetch_optional(pool)
        .await
    }

    /// Check if the conflict is pending resolution.
    pub fn is_pending(&self) -> bool {
        self.resolution_outcome.is_none()
            || matches!(self.resolution_outcome, Some(ResolutionOutcome::Pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_type_display() {
        assert_eq!(
            ConflictType::ConcurrentUpdate.to_string(),
            "concurrent_update"
        );
        assert_eq!(ConflictType::StaleData.to_string(), "stale_data");
        assert_eq!(ConflictType::MissingTarget.to_string(), "missing_target");
        assert_eq!(ConflictType::ExternalChange.to_string(), "external_change");
    }

    #[test]
    fn test_conflict_type_from_str() {
        assert_eq!(
            "concurrent_update".parse::<ConflictType>().unwrap(),
            ConflictType::ConcurrentUpdate
        );
        assert_eq!(
            "STALE_DATA".parse::<ConflictType>().unwrap(),
            ConflictType::StaleData
        );
    }

    #[test]
    fn test_resolution_strategy_display() {
        assert_eq!(
            ResolutionStrategy::LastWriteWins.to_string(),
            "last_write_wins"
        );
        assert_eq!(ResolutionStrategy::Manual.to_string(), "manual");
    }

    #[test]
    fn test_resolution_outcome_display() {
        assert_eq!(ResolutionOutcome::Applied.to_string(), "applied");
        assert_eq!(ResolutionOutcome::Pending.to_string(), "pending");
    }

    #[test]
    fn test_create_conflict_request() {
        let request = CreateConflictRecord {
            operation_id: Uuid::new_v4(),
            conflicting_operation_id: Some(Uuid::new_v4()),
            conflict_type: ConflictType::ConcurrentUpdate,
            affected_attributes: vec!["email".to_string(), "department".to_string()],
            resolution_strategy: ResolutionStrategy::LastWriteWins,
        };

        assert_eq!(request.conflict_type, ConflictType::ConcurrentUpdate);
        assert_eq!(request.affected_attributes.len(), 2);
    }

    #[test]
    fn test_resolve_conflict_request() {
        let request = ResolveConflict {
            outcome: ResolutionOutcome::Applied,
            notes: Some("Verified with HR, primary operation is correct".to_string()),
        };

        assert_eq!(request.outcome, ResolutionOutcome::Applied);
    }

    #[test]
    fn test_conflict_filter_default() {
        let filter = ConflictFilter::default();
        assert!(filter.operation_id.is_none());
        assert!(!filter.pending_only);
    }
}
