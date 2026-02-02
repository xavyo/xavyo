//! Unified Non-Human Identity API for service accounts and AI agents.
//!
//! This crate provides REST API endpoints for unified NHI management:
//! - `GET /nhi` - List all NHIs with filtering
//! - `GET /nhi/{id}` - Get specific NHI
//! - `GET /nhi/risk-summary` - Aggregated risk statistics
//! - `GET /nhi/staleness-report` - Inactive NHI report
//! - `POST /nhi/certifications/campaigns` - Unified certification campaigns
//!
//! ## Consolidated Endpoints (F109)
//!
//! - `/nhi/service-accounts/*` - Service account CRUD and lifecycle
//! - `/nhi/agents/*` - AI agent CRUD and authorization
//! - `/nhi/tools/*` - Tool registry management
//! - `/nhi/approvals/*` - HITL approval workflow

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod router;
pub mod services;
pub mod state;

// Re-export router function for easy integration
pub use router::{router, NhiAppState};

// Re-export error types
pub use error::{ApiNhiError, ApiResult, ErrorResponse};

// Re-export state types for custom router building
pub use state::{
    AgentsState, ApprovalsState, ConsolidatedNhiState, ServiceAccountsState, ToolsState,
};

// Re-export handlers for custom router building
pub use handlers::{
    get_nhi, get_risk_summary, list_nhi, CountByRiskLevel, CountByType, NhiItem, NhiListQuery,
    NhiListResponse, NhiState, RiskState, RiskSummaryResponse,
};

// Re-export certification types
pub use handlers::certification::{
    CampaignFilterRequest, CampaignListResponse, CampaignResponse, CertificationItemResponse,
    CreateCampaignRequest, DecisionRequest, ErrorResponse as CertErrorResponse, ItemCountsResponse,
    ItemListResponse, ListCampaignsQuery, ListItemsQuery,
};

// Re-export services
pub use services::{UnifiedListService, UnifiedRiskService};

// Re-export middleware (F110)
pub use middleware::{nhi_auth_middleware, NhiAuthContext, NhiCredentialService};
