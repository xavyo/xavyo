//! Governance Merge Audit model.
//!
//! Represents immutable audit records for identity merge operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Attribute decision record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDecision {
    pub attribute: String,
    pub source: String, // "source" or "target"
    pub selected_value: serde_json::Value,
    pub source_value: serde_json::Value,
    pub target_value: serde_json::Value,
}

/// Entitlement decision record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementDecision {
    pub strategy: String, // "union", "intersection", or "manual"
    pub source_entitlements: Vec<EntitlementSnapshot>,
    pub target_entitlements: Vec<EntitlementSnapshot>,
    pub merged_entitlements: Vec<EntitlementSnapshot>,
    pub excluded_entitlements: Vec<EntitlementSnapshot>,
}

/// Entitlement snapshot for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    pub id: Uuid,
    pub name: String,
    pub application: Option<String>,
}

/// SoD violation record for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSodViolation {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub severity: String,
    pub overridden: bool,
    pub override_reason: Option<String>,
}

/// Identity snapshot for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySnapshot {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub attributes: serde_json::Value,
    pub entitlements: Vec<EntitlementSnapshot>,
    pub external_references: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A governance merge audit record (immutable).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMergeAudit {
    /// Unique identifier for the audit record.
    pub id: Uuid,

    /// The tenant this record belongs to.
    pub tenant_id: Uuid,

    /// Reference to the merge operation.
    pub operation_id: Uuid,

    /// Complete source identity state at merge time.
    pub source_snapshot: serde_json::Value,

    /// Complete target identity state before merge.
    pub target_snapshot: serde_json::Value,

    /// Resulting merged identity state.
    pub merged_snapshot: serde_json::Value,

    /// Record of each attribute decision.
    pub attribute_decisions: serde_json::Value,

    /// Record of entitlement consolidation.
    pub entitlement_decisions: serde_json::Value,

    /// SoD violations detected/overridden.
    pub sod_violations: Option<serde_json::Value>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new merge audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMergeAudit {
    pub operation_id: Uuid,
    pub source_snapshot: IdentitySnapshot,
    pub target_snapshot: IdentitySnapshot,
    pub merged_snapshot: IdentitySnapshot,
    pub attribute_decisions: Vec<AttributeDecision>,
    pub entitlement_decisions: EntitlementDecision,
    pub sod_violations: Option<Vec<AuditSodViolation>>,
}

/// Filter options for searching merge audits.
#[derive(Debug, Clone, Default)]
pub struct MergeAuditFilter {
    pub operation_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    pub operator_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovMergeAudit {
    /// Find an audit record by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_merge_audits
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an audit record by operation ID.
    pub async fn find_by_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_merge_audits
            WHERE operation_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List audit records for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MergeAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT a.* FROM gov_merge_audits a
            "#,
        );
        let mut joins = Vec::new();
        let mut conditions = vec!["a.tenant_id = $1".to_string()];
        let mut param_count = 1;

        if filter.operation_id.is_some() {
            param_count += 1;
            conditions.push(format!("a.operation_id = ${}", param_count));
        }

        if filter.operator_id.is_some() || filter.identity_id.is_some() {
            joins.push("JOIN gov_merge_operations o ON a.operation_id = o.id");

            if filter.operator_id.is_some() {
                param_count += 1;
                conditions.push(format!("o.operator_id = ${}", param_count));
            }
            if filter.identity_id.is_some() {
                param_count += 1;
                conditions.push(format!(
                    "(o.source_identity_id = ${0} OR o.target_identity_id = ${0})",
                    param_count
                ));
            }
        }

        if filter.from_date.is_some() {
            param_count += 1;
            conditions.push(format!("a.created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            conditions.push(format!("a.created_at <= ${}", param_count));
        }

        if !joins.is_empty() {
            query.push_str(&joins.join(" "));
        }

        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));

        query.push_str(&format!(
            " ORDER BY a.created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovMergeAudit>(&query).bind(tenant_id);

        if let Some(operation_id) = filter.operation_id {
            q = q.bind(operation_id);
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

    /// Count audit records in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MergeAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_merge_audits a
            "#,
        );
        let mut joins = Vec::new();
        let mut conditions = vec!["a.tenant_id = $1".to_string()];
        let mut param_count = 1;

        if filter.operation_id.is_some() {
            param_count += 1;
            conditions.push(format!("a.operation_id = ${}", param_count));
        }

        if filter.operator_id.is_some() || filter.identity_id.is_some() {
            joins.push("JOIN gov_merge_operations o ON a.operation_id = o.id");

            if filter.operator_id.is_some() {
                param_count += 1;
                conditions.push(format!("o.operator_id = ${}", param_count));
            }
            if filter.identity_id.is_some() {
                param_count += 1;
                conditions.push(format!(
                    "(o.source_identity_id = ${0} OR o.target_identity_id = ${0})",
                    param_count
                ));
            }
        }

        if filter.from_date.is_some() {
            param_count += 1;
            conditions.push(format!("a.created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            conditions.push(format!("a.created_at <= ${}", param_count));
        }

        if !joins.is_empty() {
            query.push_str(&joins.join(" "));
        }

        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(operation_id) = filter.operation_id {
            q = q.bind(operation_id);
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

    /// Create a new merge audit record (immutable - no update/delete).
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovMergeAudit,
    ) -> Result<Self, sqlx::Error> {
        let source_snapshot =
            serde_json::to_value(&input.source_snapshot).unwrap_or_else(|_| serde_json::json!({}));
        let target_snapshot =
            serde_json::to_value(&input.target_snapshot).unwrap_or_else(|_| serde_json::json!({}));
        let merged_snapshot =
            serde_json::to_value(&input.merged_snapshot).unwrap_or_else(|_| serde_json::json!({}));
        let attribute_decisions = serde_json::to_value(&input.attribute_decisions)
            .unwrap_or_else(|_| serde_json::json!([]));
        let entitlement_decisions = serde_json::to_value(&input.entitlement_decisions)
            .unwrap_or_else(|_| serde_json::json!({}));
        let sod_violations = input
            .sod_violations
            .map(|v| serde_json::to_value(v).unwrap_or_else(|_| serde_json::json!([])));

        sqlx::query_as(
            r#"
            INSERT INTO gov_merge_audits (
                tenant_id, operation_id, source_snapshot, target_snapshot,
                merged_snapshot, attribute_decisions, entitlement_decisions, sod_violations
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.operation_id)
        .bind(source_snapshot)
        .bind(target_snapshot)
        .bind(merged_snapshot)
        .bind(attribute_decisions)
        .bind(entitlement_decisions)
        .bind(sod_violations)
        .fetch_one(pool)
        .await
    }

    /// Create a new merge audit record within a transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_tx<'e, E>(
        executor: E,
        tenant_id: Uuid,
        operation_id: Uuid,
        source_snapshot: serde_json::Value,
        target_snapshot: serde_json::Value,
        merged_snapshot: serde_json::Value,
        attribute_decisions: serde_json::Value,
        entitlement_decisions: serde_json::Value,
        sod_violations: Option<serde_json::Value>,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO gov_merge_audits (
                tenant_id, operation_id, source_snapshot, target_snapshot,
                merged_snapshot, attribute_decisions, entitlement_decisions, sod_violations
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(operation_id)
        .bind(&source_snapshot)
        .bind(&target_snapshot)
        .bind(&merged_snapshot)
        .bind(&attribute_decisions)
        .bind(&entitlement_decisions)
        .bind(&sod_violations)
        .fetch_one(executor)
        .await
    }

    /// Find audits involving a specific identity.
    pub async fn find_by_identity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT a.* FROM gov_merge_audits a
            JOIN gov_merge_operations o ON a.operation_id = o.id
            WHERE a.tenant_id = $1
              AND (o.source_identity_id = $2 OR o.target_identity_id = $2)
            ORDER BY a.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get the source snapshot as structured data.
    pub fn get_source_snapshot(&self) -> Result<IdentitySnapshot, serde_json::Error> {
        serde_json::from_value(self.source_snapshot.clone())
    }

    /// Get the target snapshot as structured data.
    pub fn get_target_snapshot(&self) -> Result<IdentitySnapshot, serde_json::Error> {
        serde_json::from_value(self.target_snapshot.clone())
    }

    /// Get the merged snapshot as structured data.
    pub fn get_merged_snapshot(&self) -> Result<IdentitySnapshot, serde_json::Error> {
        serde_json::from_value(self.merged_snapshot.clone())
    }

    /// Get the attribute decisions as structured data.
    pub fn get_attribute_decisions(&self) -> Result<Vec<AttributeDecision>, serde_json::Error> {
        serde_json::from_value(self.attribute_decisions.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_snapshot_serialization() {
        let snapshot = IdentitySnapshot {
            id: Uuid::new_v4(),
            email: Some("test@example.com".to_string()),
            display_name: Some("Test User".to_string()),
            attributes: serde_json::json!({"department": "Engineering"}),
            entitlements: vec![EntitlementSnapshot {
                id: Uuid::new_v4(),
                name: "App Access".to_string(),
                application: Some("Salesforce".to_string()),
            }],
            external_references: serde_json::json!({"scim_id": "scim-uuid"}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("Test User"));
        assert!(json.contains("Salesforce"));
    }

    #[test]
    fn test_attribute_decision_serialization() {
        let decision = AttributeDecision {
            attribute: "display_name".to_string(),
            source: "target".to_string(),
            selected_value: serde_json::json!("John Smith"),
            source_value: serde_json::json!("Jon Smyth"),
            target_value: serde_json::json!("John Smith"),
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("display_name"));
        assert!(json.contains("John Smith"));
    }
}
