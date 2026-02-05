//! Report data aggregation service for compliance reporting.
//!
//! This service handles the actual data gathering for different report types.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{ReportTemplateType, TemplateDefinition};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for aggregating report data based on template type.
pub struct ReportDataService {
    pub(crate) pool: PgPool,
}

/// Report data result containing rows and metadata.
#[derive(Debug, Clone)]
pub struct ReportData {
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Value>,
    pub total_count: i64,
}

impl ReportDataService {
    /// Create a new report data service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate report data based on template type and parameters.
    pub async fn generate_data(
        &self,
        tenant_id: Uuid,
        template_type: ReportTemplateType,
        definition: &TemplateDefinition,
        parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        match template_type {
            ReportTemplateType::AccessReview => {
                self.generate_access_review_data(tenant_id, definition, parameters)
                    .await
            }
            ReportTemplateType::SodViolations => {
                self.generate_sod_violations_data(tenant_id, definition, parameters)
                    .await
            }
            ReportTemplateType::CertificationStatus => {
                self.generate_certification_status_data(tenant_id, definition, parameters)
                    .await
            }
            ReportTemplateType::UserAccess => {
                self.generate_user_access_data(tenant_id, definition, parameters)
                    .await
            }
            ReportTemplateType::AuditTrail => {
                self.generate_audit_trail_data(tenant_id, definition, parameters)
                    .await
            }
        }
    }

    /// Generate access review report data.
    #[allow(clippy::type_complexity)]
    async fn generate_access_review_data(
        &self,
        tenant_id: Uuid,
        definition: &TemplateDefinition,
        _parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        // Query entitlement assignments with user and entitlement details
        let rows: Vec<(
            Uuid,
            String,
            Option<String>,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            r"
            SELECT
                ea.id,
                u.email as user_email,
                u.display_name as user_name,
                e.name as entitlement_name,
                a.name as application_name,
                ea.status::text,
                ea.assigned_at
            FROM gov_entitlement_assignments ea
            JOIN users u ON ea.target_id = u.id AND ea.target_type = 'user'
            JOIN gov_entitlements e ON ea.entitlement_id = e.id
            JOIN gov_applications a ON e.application_id = a.id
            WHERE ea.tenant_id = $1 AND ea.status = 'active'
            ORDER BY u.email, a.name, e.name
            LIMIT 10000
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let columns = extract_column_names(definition);
        let json_rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(
                |(id, user_email, user_name, entitlement, application, status, assigned_at)| {
                    json!({
                        "id": id,
                        "user_email": user_email,
                        "user_name": user_name.unwrap_or_default(),
                        "entitlement_name": entitlement,
                        "application_name": application,
                        "status": status,
                        "assigned_at": assigned_at.to_rfc3339()
                    })
                },
            )
            .collect();

        let total_count = json_rows.len() as i64;

        Ok(ReportData {
            columns,
            rows: json_rows,
            total_count,
        })
    }

    /// Generate `SoD` violations report data.
    #[allow(clippy::type_complexity)]
    async fn generate_sod_violations_data(
        &self,
        tenant_id: Uuid,
        definition: &TemplateDefinition,
        _parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        let rows: Vec<(
            Uuid,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            r"
            SELECT
                v.id,
                u.email as user_email,
                u.display_name as user_name,
                r.name as rule_name,
                r.severity::text,
                v.status::text,
                v.resolution_notes,
                v.detected_at
            FROM gov_sod_violations v
            JOIN users u ON v.user_id = u.id
            JOIN gov_sod_rules r ON v.rule_id = r.id
            WHERE v.tenant_id = $1
            ORDER BY v.detected_at DESC
            LIMIT 10000
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let columns = extract_column_names(definition);
        let json_rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(
                |(id, user_email, user_name, rule_name, severity, status, notes, detected_at)| {
                    json!({
                        "id": id,
                        "user_email": user_email,
                        "user_name": user_name.unwrap_or_default(),
                        "rule_name": rule_name,
                        "severity": severity,
                        "status": status,
                        "resolution_notes": notes,
                        "detected_at": detected_at.to_rfc3339()
                    })
                },
            )
            .collect();

        let total_count = json_rows.len() as i64;

        Ok(ReportData {
            columns,
            rows: json_rows,
            total_count,
        })
    }

    /// Generate certification status report data.
    async fn generate_certification_status_data(
        &self,
        tenant_id: Uuid,
        definition: &TemplateDefinition,
        _parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        let rows: Vec<(Uuid, String, String, i64, i64, i64, i64)> = sqlx::query_as(
            r"
            SELECT
                c.id,
                c.name,
                c.status::text,
                (SELECT COUNT(*) FROM gov_certification_items i WHERE i.campaign_id = c.id) as total_items,
                (SELECT COUNT(*) FROM gov_certification_items i WHERE i.campaign_id = c.id AND i.status = 'certified') as certified_count,
                (SELECT COUNT(*) FROM gov_certification_items i WHERE i.campaign_id = c.id AND i.status = 'revoked') as revoked_count,
                (SELECT COUNT(*) FROM gov_certification_items i WHERE i.campaign_id = c.id AND i.status = 'pending') as pending_count
            FROM gov_certification_campaigns c
            WHERE c.tenant_id = $1
            ORDER BY c.created_at DESC
            LIMIT 1000
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let columns = extract_column_names(definition);
        let json_rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(id, name, status, total, certified, revoked, pending)| {
                let completion_percent = if total > 0 {
                    ((certified + revoked) as f64 / total as f64 * 100.0).round() as i64
                } else {
                    0
                };
                json!({
                    "id": id,
                    "campaign_name": name,
                    "status": status,
                    "total_items": total,
                    "certified_count": certified,
                    "revoked_count": revoked,
                    "pending_count": pending,
                    "completion_percent": completion_percent
                })
            })
            .collect();

        let total_count = json_rows.len() as i64;

        Ok(ReportData {
            columns,
            rows: json_rows,
            total_count,
        })
    }

    /// Generate user access report data for a specific user.
    async fn generate_user_access_data(
        &self,
        tenant_id: Uuid,
        definition: &TemplateDefinition,
        parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        // Extract user_id from parameters
        let user_id = parameters
            .and_then(|p| p.get("user_id"))
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                GovernanceError::Validation(
                    "user_id parameter is required for user access report".to_string(),
                )
            })?;

        let rows: Vec<(
            String,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            r"
            SELECT
                a.name as application_name,
                e.name as entitlement_name,
                e.risk_level::text,
                ea.status::text,
                ea.assigned_at
            FROM gov_entitlement_assignments ea
            JOIN gov_entitlements e ON ea.entitlement_id = e.id
            JOIN gov_applications a ON e.application_id = a.id
            WHERE ea.tenant_id = $1
              AND ea.target_id = $2
              AND ea.target_type = 'user'
              AND ea.status = 'active'
            ORDER BY a.name, e.name
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let columns = extract_column_names(definition);
        let json_rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(app, ent, risk, status, assigned_at)| {
                json!({
                    "application_name": app,
                    "entitlement_name": ent,
                    "risk_level": risk,
                    "status": status,
                    "assigned_at": assigned_at.to_rfc3339()
                })
            })
            .collect();

        let total_count = json_rows.len() as i64;

        Ok(ReportData {
            columns,
            rows: json_rows,
            total_count,
        })
    }

    /// Generate audit trail report data.
    #[allow(clippy::type_complexity)]
    async fn generate_audit_trail_data(
        &self,
        tenant_id: Uuid,
        definition: &TemplateDefinition,
        parameters: Option<&serde_json::Value>,
    ) -> Result<ReportData> {
        // Extract date range from parameters
        let from_date = parameters
            .and_then(|p| p.get("from_date"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map_or_else(
                || chrono::Utc::now() - chrono::Duration::days(30),
                |dt| dt.with_timezone(&chrono::Utc),
            );

        let to_date = parameters
            .and_then(|p| p.get("to_date"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map_or_else(chrono::Utc::now, |dt| dt.with_timezone(&chrono::Utc));

        // Query admin audit logs for governance events
        let rows: Vec<(
            chrono::DateTime<chrono::Utc>,
            String,
            String,
            Option<Uuid>,
            Option<String>,
            serde_json::Value,
        )> = sqlx::query_as(
            r"
            SELECT
                performed_at,
                action,
                resource_type,
                resource_id,
                u.email as performed_by_email,
                details
            FROM admin_audit_log a
            LEFT JOIN users u ON a.performed_by = u.id
            WHERE a.tenant_id = $1
              AND a.performed_at >= $2
              AND a.performed_at <= $3
              AND a.resource_type LIKE 'gov_%'
            ORDER BY a.performed_at DESC
            LIMIT 50000
            ",
        )
        .bind(tenant_id)
        .bind(from_date)
        .bind(to_date)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let columns = extract_column_names(definition);
        let json_rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(
                |(timestamp, action, resource_type, resource_id, performed_by, details)| {
                    json!({
                        "timestamp": timestamp.to_rfc3339(),
                        "action": action,
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "performed_by": performed_by.unwrap_or_else(|| "system".to_string()),
                        "details": details
                    })
                },
            )
            .collect();

        let total_count = json_rows.len() as i64;

        Ok(ReportData {
            columns,
            rows: json_rows,
            total_count,
        })
    }
}

/// Extract column names from template definition.
fn extract_column_names(definition: &TemplateDefinition) -> Vec<String> {
    definition.columns.iter().map(|c| c.field.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::models::ColumnDefinition;

    #[test]
    fn test_extract_column_names() {
        let definition = TemplateDefinition {
            columns: vec![
                ColumnDefinition {
                    field: "user_email".to_string(),
                    label: "User Email".to_string(),
                    sortable: true,
                },
                ColumnDefinition {
                    field: "entitlement_name".to_string(),
                    label: "Entitlement".to_string(),
                    sortable: true,
                },
            ],
            filters: vec![],
            default_sort: None,
            grouping: vec![],
            data_sources: vec![],
        };

        let columns = extract_column_names(&definition);
        assert_eq!(columns, vec!["user_email", "entitlement_name"]);
    }
}
