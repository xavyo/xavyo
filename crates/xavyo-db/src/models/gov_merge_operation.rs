//! Governance Merge Operation model.
//!
//! Represents in-progress or completed identity merge operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for merge operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_merge_operation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovMergeOperationStatus {
    /// Merge is in progress.
    InProgress,
    /// Merge completed successfully.
    Completed,
    /// Merge failed with error.
    Failed,
    /// Merge was cancelled.
    Cancelled,
}

/// Entitlement consolidation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_entitlement_strategy", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovEntitlementStrategy {
    /// Keep all entitlements from both identities.
    Union,
    /// Keep only common entitlements.
    Intersection,
    /// Manual selection of entitlements.
    Manual,
}

/// Attribute selection indicating which identity's value to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSelection {
    pub source: String, // "source" or "target"
    pub value: serde_json::Value,
}

/// SoD check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodCheckResult {
    pub has_violations: bool,
    pub can_override: bool,
    pub violations: Vec<SodViolationDetail>,
}

/// SoD violation detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolationDetail {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub conflicting_entitlements: Vec<EntitlementInfo>,
}

/// Basic entitlement info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementInfo {
    pub id: Uuid,
    pub name: String,
}

/// A governance merge operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMergeOperation {
    /// Unique identifier for the operation.
    pub id: Uuid,

    /// The tenant this operation belongs to.
    pub tenant_id: Uuid,

    /// Reference to the duplicate candidate (if from detection).
    pub candidate_id: Option<Uuid>,

    /// Identity being archived (source).
    pub source_identity_id: Uuid,

    /// Identity being kept (target).
    pub target_identity_id: Uuid,

    /// Current status.
    pub status: GovMergeOperationStatus,

    /// Entitlement consolidation strategy.
    pub entitlement_strategy: GovEntitlementStrategy,

    /// Attribute selections (which value chosen per attribute).
    pub attribute_selections: serde_json::Value,

    /// If manual strategy, which entitlements to keep.
    pub entitlement_selections: Option<serde_json::Value>,

    /// SoD validation results.
    pub sod_check_result: Option<serde_json::Value>,

    /// If SoD warning overridden, the justification.
    pub sod_override_reason: Option<String>,

    /// Who performed the merge.
    pub operator_id: Uuid,

    /// When the operation started.
    pub started_at: DateTime<Utc>,

    /// When the operation completed (if completed).
    pub completed_at: Option<DateTime<Utc>>,

    /// If failed, error details.
    pub error_message: Option<String>,
}

/// Request to create a new merge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMergeOperation {
    pub candidate_id: Option<Uuid>,
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub entitlement_strategy: GovEntitlementStrategy,
    pub attribute_selections: serde_json::Value,
    pub entitlement_selections: Option<serde_json::Value>,
    pub operator_id: Uuid,
}

/// Filter options for listing merge operations.
#[derive(Debug, Clone, Default)]
pub struct MergeOperationFilter {
    pub status: Option<GovMergeOperationStatus>,
    pub operator_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovMergeOperation {
    /// Find an operation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_merge_operations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pending operations involving an identity (to prevent conflicts).
    pub async fn find_pending_by_identity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_merge_operations
            WHERE tenant_id = $1
              AND status = 'in_progress'
              AND (source_identity_id = $2 OR target_identity_id = $2)
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
    }

    /// Check for circular merge (A→B while B→A in progress).
    pub async fn check_circular_merge(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_merge_operations
            WHERE tenant_id = $1
              AND status = 'in_progress'
              AND source_identity_id = $2
              AND target_identity_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(target_id) // Reversed: looking for target→source
        .bind(source_id)
        .fetch_optional(pool)
        .await
    }

    /// List operations for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MergeOperationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_merge_operations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.operator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operator_id = ${}", param_count));
        }
        if filter.identity_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (source_identity_id = ${0} OR target_identity_id = ${0})",
                param_count
            ));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND started_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND started_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY started_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovMergeOperation>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(operator_id) = filter.operator_id {
            q = q.bind(operator_id);
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count operations in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MergeOperationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_merge_operations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.operator_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operator_id = ${}", param_count));
        }
        if filter.identity_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (source_identity_id = ${0} OR target_identity_id = ${0})",
                param_count
            ));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND started_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND started_at <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(operator_id) = filter.operator_id {
            q = q.bind(operator_id);
        }
        if let Some(identity_id) = filter.identity_id {
            q = q.bind(identity_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.fetch_one(pool).await
    }

    /// Create a new merge operation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovMergeOperation,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_merge_operations (
                tenant_id, candidate_id, source_identity_id, target_identity_id,
                entitlement_strategy, attribute_selections, entitlement_selections,
                operator_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.candidate_id)
        .bind(input.source_identity_id)
        .bind(input.target_identity_id)
        .bind(input.entitlement_strategy)
        .bind(&input.attribute_selections)
        .bind(&input.entitlement_selections)
        .bind(input.operator_id)
        .fetch_one(pool)
        .await
    }

    /// Mark operation as completed.
    pub async fn mark_completed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_merge_operations
            SET status = 'completed', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'in_progress'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark operation as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_merge_operations
            SET status = 'failed', completed_at = NOW(), error_message = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'in_progress'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Mark operation as cancelled.
    pub async fn mark_cancelled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_merge_operations
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'in_progress'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if operation is in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(self.status, GovMergeOperationStatus::InProgress)
    }

    /// Check if operation is completed.
    pub fn is_completed(&self) -> bool {
        matches!(self.status, GovMergeOperationStatus::Completed)
    }

    /// Get the SoD check result as structured data.
    pub fn get_sod_check_result(&self) -> Result<Option<SodCheckResult>, serde_json::Error> {
        match &self.sod_check_result {
            Some(v) => Ok(Some(serde_json::from_value(v.clone())?)),
            None => Ok(None),
        }
    }

    /// Check if there's a pending merge involving an identity (either as source or target).
    pub async fn has_pending_involving(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_merge_operations
            WHERE tenant_id = $1
              AND status = 'in_progress'
              AND (source_identity_id = $2 OR target_identity_id = $2)
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Check for circular merge (attempting B→A when A→B is in progress).
    pub async fn has_pending_merge_involving(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // Check if there's an in-progress merge where target_id is source and source_id is target
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_merge_operations
            WHERE tenant_id = $1
              AND status = 'in_progress'
              AND source_identity_id = $2
              AND target_identity_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(target_id) // Reversed: looking for target→source
        .bind(source_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Create operation within a transaction.
    pub async fn create_with_tx<'e>(
        executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
        tenant_id: Uuid,
        input: CreateGovMergeOperation,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_merge_operations (
                tenant_id, candidate_id, source_identity_id, target_identity_id,
                entitlement_strategy, attribute_selections, entitlement_selections,
                operator_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.candidate_id)
        .bind(input.source_identity_id)
        .bind(input.target_identity_id)
        .bind(input.entitlement_strategy)
        .bind(&input.attribute_selections)
        .bind(&input.entitlement_selections)
        .bind(input.operator_id)
        .fetch_one(executor)
        .await
    }

    /// Set SoD override within a transaction.
    pub async fn set_sod_override<'e>(
        executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
        id: Uuid,
        sod_check_result: Option<serde_json::Value>,
        sod_override_reason: Option<String>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE gov_merge_operations
            SET sod_check_result = $2, sod_override_reason = $3
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(sod_check_result)
        .bind(sod_override_reason)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Complete within a transaction.
    pub async fn complete_with_tx<'e>(
        executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_merge_operations
            SET status = 'completed', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'in_progress'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Alias for mark_completed (used by service).
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::mark_completed(pool, tenant_id, id).await
    }

    /// Alias for mark_failed (used by service).
    pub async fn fail(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: String,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::mark_failed(pool, tenant_id, id, &error_message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_serialization() {
        let in_progress = GovMergeOperationStatus::InProgress;
        let json = serde_json::to_string(&in_progress).unwrap();
        assert_eq!(json, "\"in_progress\"");

        let completed = GovMergeOperationStatus::Completed;
        let json = serde_json::to_string(&completed).unwrap();
        assert_eq!(json, "\"completed\"");
    }

    #[test]
    fn test_strategy_serialization() {
        let union = GovEntitlementStrategy::Union;
        let json = serde_json::to_string(&union).unwrap();
        assert_eq!(json, "\"union\"");
    }

    #[test]
    fn test_sod_check_result_serialization() {
        let result = SodCheckResult {
            has_violations: true,
            can_override: true,
            violations: vec![SodViolationDetail {
                rule_id: Uuid::new_v4(),
                rule_name: "Payment Segregation".to_string(),
                conflicting_entitlements: vec![
                    EntitlementInfo {
                        id: Uuid::new_v4(),
                        name: "Payment Initiator".to_string(),
                    },
                    EntitlementInfo {
                        id: Uuid::new_v4(),
                        name: "Payment Approver".to_string(),
                    },
                ],
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("has_violations"));
        assert!(json.contains("Payment Segregation"));
    }
}
