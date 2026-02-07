//! Reconciliation Discrepancy model for F049 Reconciliation Engine.
//!
//! Represents differences detected between xavyo and target systems.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

/// Type of discrepancy detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationDiscrepancyType {
    /// Identity exists in xavyo but no account in target.
    Missing,
    /// Account exists in target but no identity in xavyo.
    Orphan,
    /// Linked identity and account have attribute differences.
    Mismatch,
    /// Multiple identities match one account.
    Collision,
    /// Account exists and owner identified but no shadow link.
    Unlinked,
    /// Shadow link exists but account was deleted from target.
    Deleted,
}

impl ReconciliationDiscrepancyType {
    /// Get suggested actions for this discrepancy type.
    #[must_use]
    pub fn suggested_actions(&self) -> Vec<ReconciliationActionType> {
        match self {
            Self::Missing => vec![ReconciliationActionType::Create],
            Self::Orphan => vec![
                ReconciliationActionType::Link,
                ReconciliationActionType::Delete,
            ],
            Self::Mismatch => vec![ReconciliationActionType::Update],
            Self::Collision => vec![ReconciliationActionType::Link],
            Self::Unlinked => vec![ReconciliationActionType::Link],
            Self::Deleted => vec![
                ReconciliationActionType::Create,
                ReconciliationActionType::Unlink,
                ReconciliationActionType::InactivateIdentity,
            ],
        }
    }
}

impl fmt::Display for ReconciliationDiscrepancyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::Orphan => write!(f, "orphan"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Collision => write!(f, "collision"),
            Self::Unlinked => write!(f, "unlinked"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

impl std::str::FromStr for ReconciliationDiscrepancyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "missing" => Ok(Self::Missing),
            "orphan" => Ok(Self::Orphan),
            "mismatch" => Ok(Self::Mismatch),
            "collision" => Ok(Self::Collision),
            "unlinked" => Ok(Self::Unlinked),
            "deleted" => Ok(Self::Deleted),
            _ => Err(format!("Unknown discrepancy type: {s}")),
        }
    }
}

/// Resolution status of a discrepancy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationResolutionStatus {
    /// Discrepancy is pending resolution.
    #[default]
    Pending,
    /// Discrepancy has been resolved.
    Resolved,
    /// Discrepancy is ignored.
    Ignored,
}

impl fmt::Display for ReconciliationResolutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Resolved => write!(f, "resolved"),
            Self::Ignored => write!(f, "ignored"),
        }
    }
}

impl std::str::FromStr for ReconciliationResolutionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "resolved" => Ok(Self::Resolved),
            "ignored" => Ok(Self::Ignored),
            _ => Err(format!("Unknown resolution status: {s}")),
        }
    }
}

/// Action type for remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationActionType {
    /// Create account in target system.
    Create,
    /// Update attributes in target or xavyo.
    Update,
    /// Delete account from target system.
    Delete,
    /// Create shadow link between identity and account.
    Link,
    /// Remove shadow link.
    Unlink,
    /// Inactivate identity in xavyo.
    InactivateIdentity,
}

impl fmt::Display for ReconciliationActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::Link => write!(f, "link"),
            Self::Unlink => write!(f, "unlink"),
            Self::InactivateIdentity => write!(f, "inactivate_identity"),
        }
    }
}

impl std::str::FromStr for ReconciliationActionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "link" => Ok(Self::Link),
            "unlink" => Ok(Self::Unlink),
            "inactivate_identity" => Ok(Self::InactivateIdentity),
            _ => Err(format!("Unknown action type: {s}")),
        }
    }
}

/// A reconciliation discrepancy record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReconciliationDiscrepancy {
    pub id: Uuid,
    pub run_id: Uuid,
    pub tenant_id: Uuid,
    pub discrepancy_type: String,
    pub identity_id: Option<Uuid>,
    pub external_uid: String,
    pub mismatched_attributes: Option<JsonValue>,
    pub resolution_status: String,
    pub resolved_action: Option<String>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub detected_at: DateTime<Utc>,
}

impl ReconciliationDiscrepancy {
    /// Get discrepancy type enum.
    #[must_use]
    pub fn discrepancy_type(&self) -> ReconciliationDiscrepancyType {
        self.discrepancy_type
            .parse()
            .unwrap_or(ReconciliationDiscrepancyType::Orphan)
    }

    /// Get resolution status enum.
    #[must_use]
    pub fn resolution_status(&self) -> ReconciliationResolutionStatus {
        self.resolution_status.parse().unwrap_or_default()
    }

    /// Get resolved action enum.
    #[must_use]
    pub fn resolved_action(&self) -> Option<ReconciliationActionType> {
        self.resolved_action.as_ref().and_then(|s| s.parse().ok())
    }

    /// Create a new discrepancy.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &CreateReconciliationDiscrepancy,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_reconciliation_discrepancies (
                run_id, tenant_id, discrepancy_type, identity_id,
                external_uid, mismatched_attributes
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(input.run_id)
        .bind(tenant_id)
        .bind(input.discrepancy_type.to_string())
        .bind(input.identity_id)
        .bind(&input.external_uid)
        .bind(&input.mismatched_attributes)
        .fetch_one(pool)
        .await
    }

    /// Bulk create discrepancies.
    pub async fn create_bulk(
        pool: &PgPool,
        tenant_id: Uuid,
        inputs: &[CreateReconciliationDiscrepancy],
    ) -> Result<Vec<Self>, sqlx::Error> {
        if inputs.is_empty() {
            return Ok(vec![]);
        }

        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let disc = Self::create(pool, tenant_id, input).await?;
            results.push(disc);
        }
        Ok(results)
    }

    /// Find discrepancy by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_discrepancies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List discrepancies with filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationDiscrepancyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from(r"SELECT * FROM gov_reconciliation_discrepancies WHERE tenant_id = $1");
        let mut param_idx = 2;

        if filter.run_id.is_some() {
            query.push_str(&format!(" AND run_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.discrepancy_type.is_some() {
            query.push_str(&format!(" AND discrepancy_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.resolution_status.is_some() {
            query.push_str(&format!(" AND resolution_status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.identity_id.is_some() {
            query.push_str(&format!(" AND identity_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.external_uid.is_some() {
            query.push_str(&format!(" AND external_uid ILIKE ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY detected_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(run_id) = filter.run_id {
            q = q.bind(run_id);
        }
        if let Some(ref dtype) = filter.discrepancy_type {
            q = q.bind(dtype.to_string());
        }
        if let Some(ref status) = filter.resolution_status {
            q = q.bind(status.to_string());
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }
        if let Some(ref external_uid) = filter.external_uid {
            q = q.bind(format!("%{external_uid}%"));
        }

        q = q.bind(limit).bind(offset);
        q.fetch_all(pool).await
    }

    /// Count discrepancies.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationDiscrepancyFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"SELECT COUNT(*) FROM gov_reconciliation_discrepancies WHERE tenant_id = $1",
        );
        let mut param_idx = 2;

        if filter.run_id.is_some() {
            query.push_str(&format!(" AND run_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.discrepancy_type.is_some() {
            query.push_str(&format!(" AND discrepancy_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.resolution_status.is_some() {
            query.push_str(&format!(" AND resolution_status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.identity_id.is_some() {
            query.push_str(&format!(" AND identity_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.external_uid.is_some() {
            query.push_str(&format!(" AND external_uid ILIKE ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(run_id) = filter.run_id {
            q = q.bind(run_id);
        }
        if let Some(ref dtype) = filter.discrepancy_type {
            q = q.bind(dtype.to_string());
        }
        if let Some(ref status) = filter.resolution_status {
            q = q.bind(status.to_string());
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }
        if let Some(ref external_uid) = filter.external_uid {
            q = q.bind(format!("%{external_uid}%"));
        }

        q.fetch_one(pool).await
    }

    /// Count discrepancies by type for a run.
    pub async fn count_by_type(
        pool: &PgPool,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> Result<Vec<(String, i64)>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT discrepancy_type, COUNT(*) as count
            FROM gov_reconciliation_discrepancies
            WHERE tenant_id = $1 AND run_id = $2
            GROUP BY discrepancy_type
            ",
        )
        .bind(tenant_id)
        .bind(run_id)
        .fetch_all(pool)
        .await
    }

    /// Mark discrepancy as resolved.
    pub async fn resolve(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        action: ReconciliationActionType,
        resolved_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_discrepancies
            SET resolution_status = 'resolved',
                resolved_action = $3,
                resolved_by = $4,
                resolved_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(action.to_string())
        .bind(resolved_by)
        .fetch_optional(pool)
        .await
    }

    /// Mark discrepancy as ignored.
    pub async fn ignore(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        ignored_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_discrepancies
            SET resolution_status = 'ignored',
                resolved_by = $3,
                resolved_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(ignored_by)
        .fetch_optional(pool)
        .await
    }

    /// Delete discrepancies for a run.
    pub async fn delete_by_run(
        pool: &PgPool,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_reconciliation_discrepancies
            WHERE run_id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get trend data aggregated by date for a connector or all connectors.
    /// Returns (date, type, count) tuples for building trend analysis.
    pub async fn get_trend_by_date(
        pool: &PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<DiscrepancyTrendPoint>, sqlx::Error> {
        if let Some(cid) = connector_id {
            sqlx::query_as(
                r"
                SELECT
                    DATE(d.detected_at) as date,
                    d.discrepancy_type as discrepancy_type,
                    COUNT(*) as count
                FROM gov_reconciliation_discrepancies d
                JOIN gov_connector_reconciliation_runs r ON d.run_id = r.id
                WHERE d.tenant_id = $1
                  AND r.connector_id = $2
                  AND d.detected_at >= $3
                  AND d.detected_at <= $4
                GROUP BY DATE(d.detected_at), d.discrepancy_type
                ORDER BY date ASC, discrepancy_type ASC
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(from)
            .bind(to)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT
                    DATE(detected_at) as date,
                    discrepancy_type,
                    COUNT(*) as count
                FROM gov_reconciliation_discrepancies
                WHERE tenant_id = $1
                  AND detected_at >= $2
                  AND detected_at <= $3
                GROUP BY DATE(detected_at), discrepancy_type
                ORDER BY date ASC, discrepancy_type ASC
                ",
            )
            .bind(tenant_id)
            .bind(from)
            .bind(to)
            .fetch_all(pool)
            .await
        }
    }
}

/// A single data point in the trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DiscrepancyTrendPoint {
    pub date: chrono::NaiveDate,
    pub discrepancy_type: String,
    pub count: i64,
}

/// Input for creating a discrepancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReconciliationDiscrepancy {
    pub run_id: Uuid,
    pub discrepancy_type: ReconciliationDiscrepancyType,
    pub identity_id: Option<Uuid>,
    pub external_uid: String,
    pub mismatched_attributes: Option<JsonValue>,
}

/// Filter for listing discrepancies.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationDiscrepancyFilter {
    pub run_id: Option<Uuid>,
    pub discrepancy_type: Option<ReconciliationDiscrepancyType>,
    pub resolution_status: Option<ReconciliationResolutionStatus>,
    pub identity_id: Option<Uuid>,
    pub external_uid: Option<String>,
}

impl ReconciliationDiscrepancyFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn for_run(mut self, run_id: Uuid) -> Self {
        self.run_id = Some(run_id);
        self
    }

    #[must_use]
    pub fn with_type(mut self, dtype: ReconciliationDiscrepancyType) -> Self {
        self.discrepancy_type = Some(dtype);
        self
    }

    #[must_use]
    pub fn pending_only(mut self) -> Self {
        self.resolution_status = Some(ReconciliationResolutionStatus::Pending);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discrepancy_type_roundtrip() {
        for dtype in [
            ReconciliationDiscrepancyType::Missing,
            ReconciliationDiscrepancyType::Orphan,
            ReconciliationDiscrepancyType::Mismatch,
            ReconciliationDiscrepancyType::Collision,
            ReconciliationDiscrepancyType::Unlinked,
            ReconciliationDiscrepancyType::Deleted,
        ] {
            let s = dtype.to_string();
            let parsed: ReconciliationDiscrepancyType = s.parse().unwrap();
            assert_eq!(dtype, parsed);
        }
    }

    #[test]
    fn test_resolution_status_roundtrip() {
        for status in [
            ReconciliationResolutionStatus::Pending,
            ReconciliationResolutionStatus::Resolved,
            ReconciliationResolutionStatus::Ignored,
        ] {
            let s = status.to_string();
            let parsed: ReconciliationResolutionStatus = s.parse().unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_action_type_roundtrip() {
        for action in [
            ReconciliationActionType::Create,
            ReconciliationActionType::Update,
            ReconciliationActionType::Delete,
            ReconciliationActionType::Link,
            ReconciliationActionType::Unlink,
            ReconciliationActionType::InactivateIdentity,
        ] {
            let s = action.to_string();
            let parsed: ReconciliationActionType = s.parse().unwrap();
            assert_eq!(action, parsed);
        }
    }

    #[test]
    fn test_suggested_actions() {
        assert_eq!(
            ReconciliationDiscrepancyType::Missing.suggested_actions(),
            vec![ReconciliationActionType::Create]
        );
        assert_eq!(
            ReconciliationDiscrepancyType::Orphan.suggested_actions(),
            vec![
                ReconciliationActionType::Link,
                ReconciliationActionType::Delete
            ]
        );
    }
}
