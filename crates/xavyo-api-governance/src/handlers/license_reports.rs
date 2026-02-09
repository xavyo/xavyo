//! HTTP handlers for License Compliance Reports (F065).
//!
//! Provides endpoints for generating license compliance reports and
//! querying the license audit trail for governance and auditing purposes.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::license::ListAuditEventsParams,
    router::GovernanceState,
    services::license_report_service::{
        AuditTrailEntry, AuditTrailParams, ComplianceReport, ComplianceReportParams,
    },
};

// ============================================================================
// Request / Response Types
// ============================================================================

/// Request body for compliance report generation.
///
/// All fields are optional. When omitted, the report covers all pools,
/// all vendors, and the full available date range.
#[derive(Debug, Clone, Deserialize, Default, ToSchema)]
pub struct ComplianceReportRequest {
    /// Restrict the report to specific license pool IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_ids: Option<Vec<Uuid>>,

    /// Restrict the report to a specific vendor name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Start of the reporting period (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<DateTime<Utc>>,

    /// End of the reporting period (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<DateTime<Utc>>,
}

/// Paginated response for audit trail queries.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditTrailResponse {
    /// The audit trail entries for the current page.
    pub items: Vec<AuditTrailEntry>,
    /// Total number of matching entries across all pages.
    pub total: i64,
    /// Maximum number of entries per page.
    pub limit: i64,
    /// Number of entries skipped (for pagination).
    pub offset: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// Generate a license compliance report.
///
/// Produces a point-in-time compliance snapshot covering pool utilization,
/// assignment compliance status, expiration warnings, and audit summaries.
/// An optional JSON body can narrow the report to specific pools, vendors,
/// or a date range.
#[utoipa::path(
    post,
    path = "/governance/license-reports/compliance",
    tag = "Governance - License Management",
    request_body(content = Option<ComplianceReportRequest>, description = "Optional filters for the compliance report"),
    responses(
        (status = 200, description = "Compliance report generated", body = ComplianceReport),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn generate_compliance_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<Option<ComplianceReportRequest>>,
) -> ApiResult<Json<ComplianceReport>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let request = body.unwrap_or_default();
    let params = ComplianceReportParams {
        pool_ids: request.pool_ids,
        vendor: request.vendor,
        from_date: request.from_date,
        to_date: request.to_date,
    };

    let report = state
        .license_report_service
        .generate_compliance_report(tenant_id, params)
        .await?;

    Ok(Json(report))
}

/// Get the license audit trail.
///
/// Returns a paginated list of audit events for license management
/// operations, filterable by pool, user, action, and date range.
#[utoipa::path(
    get,
    path = "/governance/license-reports/audit-trail",
    tag = "Governance - License Management",
    params(
        ("pool_id" = Option<Uuid>, Query, description = "Filter by license pool ID"),
        ("user_id" = Option<Uuid>, Query, description = "Filter by user ID"),
        ("action" = Option<String>, Query, description = "Filter by audit action"),
        ("from_date" = Option<DateTime<Utc>>, Query, description = "Filter from date (inclusive)"),
        ("to_date" = Option<DateTime<Utc>>, Query, description = "Filter to date (inclusive)"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "Audit trail retrieved", body = AuditTrailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_audit_trail(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListAuditEventsParams>,
) -> ApiResult<Json<AuditTrailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = params.limit;
    let offset = params.offset;

    let audit_params = AuditTrailParams {
        pool_id: params.pool_id,
        user_id: params.user_id,
        action: params.action,
        from_date: params.from_date,
        to_date: params.to_date,
        limit,
        offset,
    };

    let (items, total) = state
        .license_report_service
        .get_audit_trail(tenant_id, audit_params)
        .await?;

    Ok(Json(AuditTrailResponse {
        items,
        total,
        limit,
        offset,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handler_module_exists() {
        // Placeholder test to verify the module compiles
    }
}
