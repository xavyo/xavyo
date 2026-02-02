//! HTTP request handlers for unified NHI API.

pub mod certification;
pub mod get;
pub mod list;
pub mod risk;

// New consolidated handlers for F109
pub mod agents;
pub mod approvals;
pub mod service_accounts;
pub mod tools;

// Re-export handlers for router use
pub use certification::{
    bulk_decide, cancel_campaign, create_campaign, decide_item, get_campaign, get_campaign_summary,
    get_my_pending, launch_campaign, list_campaign_items, list_campaigns, CertificationState,
};
pub use get::get_nhi;
pub use list::{list_nhi, NhiItem, NhiListQuery, NhiListResponse, NhiState};
pub use risk::{
    get_risk_summary, get_staleness_report, CountByRiskLevel, CountByType, RiskState,
    RiskSummaryResponse, StalenessReportParams, StalenessReportResponse,
};
