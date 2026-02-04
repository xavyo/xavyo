//! Handlers for NHI risk and staleness reports.
//!
//! Provides:
//! - `GET /nhi/risk-summary` - Aggregated risk statistics
//! - `GET /nhi/staleness-report` - Inactive NHI report

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::NhiRiskSummary;

// Re-export staleness types from governance
pub use xavyo_api_governance::models::StalenessReportResponse;

use crate::services::unified_risk_service::UnifiedRiskService;
use std::sync::Arc;
use xavyo_api_governance::services::NhiUsageService;

/// Application state for risk handlers.
#[derive(Clone)]
pub struct RiskState {
    pub risk_service: UnifiedRiskService,
    pub usage_service: Option<Arc<NhiUsageService>>,
}

impl RiskState {
    /// Create a new `RiskState` with risk service only.
    #[must_use] 
    pub fn new(risk_service: UnifiedRiskService) -> Self {
        Self {
            risk_service,
            usage_service: None,
        }
    }

    /// Create a `RiskState` with both services for staleness report.
    #[must_use] 
    pub fn with_usage_service(mut self, usage_service: Arc<NhiUsageService>) -> Self {
        self.usage_service = Some(usage_service);
        self
    }
}

/// Response for risk summary endpoint.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskSummaryResponse {
    /// Total count of all NHIs.
    pub total_count: i32,

    /// Counts by NHI type.
    pub by_type: CountByType,

    /// Counts by risk level.
    pub by_risk_level: CountByRiskLevel,

    /// Number of NHIs with certification due within 30 days.
    pub pending_certification: i32,

    /// Number of NHIs inactive for 30+ days.
    pub inactive_30_days: i32,

    /// Number of NHIs expiring within 7 days.
    pub expiring_7_days: i32,
}

/// Count of NHIs by type.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CountByType {
    pub service_account: i32,
    pub ai_agent: i32,
}

/// Count of NHIs by risk level.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CountByRiskLevel {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

impl From<NhiRiskSummary> for RiskSummaryResponse {
    fn from(summary: NhiRiskSummary) -> Self {
        RiskSummaryResponse {
            total_count: summary.total_count,
            by_type: CountByType {
                service_account: summary.by_type.service_account,
                ai_agent: summary.by_type.ai_agent,
            },
            by_risk_level: CountByRiskLevel {
                critical: summary.by_risk_level.critical,
                high: summary.by_risk_level.high,
                medium: summary.by_risk_level.medium,
                low: summary.by_risk_level.low,
            },
            pending_certification: summary.pending_certification,
            inactive_30_days: summary.inactive_30_days,
            expiring_7_days: summary.expiring_7_days,
        }
    }
}

/// Handler for `GET /nhi/risk-summary`.
///
/// Returns aggregated risk statistics across all non-human identities.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/risk-summary",
    tag = "nhi",
    responses(
        (status = 200, description = "Risk summary statistics", body = RiskSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
))]
pub async fn get_risk_summary(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<RiskState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_id = extract_tenant_id(&claims)?;

    let summary = state
        .risk_service
        .get_risk_summary(tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get risk summary: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    Ok(Json(RiskSummaryResponse::from(summary)))
}

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, (StatusCode, String)> {
    claims.tenant_id().map(|t| *t.as_uuid()).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing tenant ID in claims".to_string(),
        )
    })
}

/// Query parameters for staleness report.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct StalenessReportParams {
    /// Minimum days inactive to include in report.
    pub min_inactive_days: Option<i32>,
}

/// Handler for `GET /nhi/staleness-report`.
///
/// Returns a report of NHIs that have been inactive for a specified number of days.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/staleness-report",
    tag = "NHI",
    params(StalenessReportParams),
    responses(
        (status = 200, description = "Staleness report", body = StalenessReportResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
        (status = 501, description = "Service not configured")
    ),
    security(("bearer_auth" = []))
))]
pub async fn get_staleness_report(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<RiskState>,
    Query(params): Query<StalenessReportParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_id = extract_tenant_id(&claims)?;

    let usage_service = state.usage_service.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            "Staleness report service not configured".to_string(),
        )
    })?;

    let report = usage_service
        .get_staleness_report(tenant_id, params.min_inactive_days)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get staleness report: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::models::{NhiCountByRiskLevel, NhiCountByType};

    #[test]
    fn test_risk_summary_response_from_model() {
        let model = NhiRiskSummary {
            total_count: 50,
            by_type: NhiCountByType {
                service_account: 30,
                ai_agent: 20,
            },
            by_risk_level: NhiCountByRiskLevel {
                critical: 2,
                high: 8,
                medium: 15,
                low: 25,
            },
            pending_certification: 5,
            inactive_30_days: 3,
            expiring_7_days: 1,
        };

        let response = RiskSummaryResponse::from(model);

        assert_eq!(response.total_count, 50);
        assert_eq!(response.by_type.service_account, 30);
        assert_eq!(response.by_type.ai_agent, 20);
        assert_eq!(response.by_risk_level.critical, 2);
        assert_eq!(response.by_risk_level.high, 8);
        assert_eq!(response.by_risk_level.medium, 15);
        assert_eq!(response.by_risk_level.low, 25);
        assert_eq!(response.pending_certification, 5);
        assert_eq!(response.inactive_30_days, 3);
        assert_eq!(response.expiring_7_days, 1);
    }

    #[test]
    fn test_risk_summary_response_serialization() {
        let response = RiskSummaryResponse {
            total_count: 10,
            by_type: CountByType {
                service_account: 6,
                ai_agent: 4,
            },
            by_risk_level: CountByRiskLevel {
                critical: 1,
                high: 2,
                medium: 3,
                low: 4,
            },
            pending_certification: 2,
            inactive_30_days: 1,
            expiring_7_days: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total_count\":10"));
        assert!(json.contains("\"service_account\":6"));
        assert!(json.contains("\"ai_agent\":4"));
        assert!(json.contains("\"critical\":1"));
    }

    #[test]
    fn test_staleness_report_params_defaults() {
        // T011: Test staleness report handler types
        let params = StalenessReportParams {
            min_inactive_days: None,
        };
        assert!(params.min_inactive_days.is_none());

        let params_with_days = StalenessReportParams {
            min_inactive_days: Some(30),
        };
        assert_eq!(params_with_days.min_inactive_days, Some(30));
    }

    #[test]
    fn test_risk_state_creation() {
        // Test RiskState can be created with just risk_service
        // Note: Cannot test with actual service without DB, but we verify the struct compiles

        // Verify RiskState struct has expected fields
        fn _verify_risk_state_fields(state: RiskState) {
            let _risk = state.risk_service;
            let _usage = state.usage_service;
        }
    }
}
