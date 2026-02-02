//! State types for consolidated NHI router.
//!
//! This module provides state structs that wrap services from
//! xavyo-api-agents and xavyo-api-governance for use in the
//! consolidated /nhi/* router.

use sqlx::PgPool;
use std::sync::Arc;

// Re-export AgentsState from xavyo-api-agents for direct use
pub use xavyo_api_agents::AgentsState;

// Import governance services
use xavyo_api_governance::services::{
    NhiCredentialService, NhiRequestService, NhiRiskService, NhiService, NhiUsageService,
};

/// State for service account endpoints under /nhi/service-accounts.
///
/// Wraps governance NHI services for service account lifecycle management.
#[derive(Clone)]
pub struct ServiceAccountsState {
    /// Service for NHI CRUD operations.
    pub nhi_service: Arc<NhiService>,
    /// Service for NHI credential operations.
    pub credential_service: Arc<NhiCredentialService>,
    /// Service for NHI usage tracking.
    pub usage_service: Arc<NhiUsageService>,
    /// Service for NHI risk assessment.
    pub risk_service: Arc<NhiRiskService>,
    /// Service for NHI access requests.
    pub request_service: Arc<NhiRequestService>,
}

impl ServiceAccountsState {
    /// Create a new ServiceAccountsState with the given database pool.
    pub fn new(pool: PgPool) -> Self {
        let nhi_service = Arc::new(NhiService::new(pool.clone()));
        let credential_service = Arc::new(NhiCredentialService::new(pool.clone()));
        let usage_service = Arc::new(NhiUsageService::new(pool.clone()));
        let risk_service = Arc::new(NhiRiskService::new(pool.clone()));
        let request_service = Arc::new(NhiRequestService::new(
            pool,
            Arc::clone(&nhi_service),
            Arc::clone(&credential_service),
        ));

        Self {
            nhi_service,
            credential_service,
            usage_service,
            risk_service,
            request_service,
        }
    }
}

/// State for tools endpoints under /nhi/tools.
///
/// Uses the ToolService from xavyo-api-agents.
#[derive(Clone)]
pub struct ToolsState {
    /// The agents state containing tool service.
    pub agents_state: AgentsState,
}

impl ToolsState {
    /// Create a new ToolsState with the given agents state.
    pub fn new(agents_state: AgentsState) -> Self {
        Self { agents_state }
    }

    /// Create a new ToolsState with the given database pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the AgentsState cannot be created.
    pub fn from_pool(pool: PgPool) -> Result<Self, crate::error::ApiNhiError> {
        Ok(Self {
            agents_state: AgentsState::new(pool)?,
        })
    }
}

/// State for approvals endpoints under /nhi/approvals.
///
/// Uses the ApprovalService from xavyo-api-agents.
#[derive(Clone)]
pub struct ApprovalsState {
    /// The agents state containing approval service.
    pub agents_state: AgentsState,
}

impl ApprovalsState {
    /// Create a new ApprovalsState with the given agents state.
    pub fn new(agents_state: AgentsState) -> Self {
        Self { agents_state }
    }

    /// Create a new ApprovalsState with the given database pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the AgentsState cannot be created.
    pub fn from_pool(pool: PgPool) -> Result<Self, crate::error::ApiNhiError> {
        Ok(Self {
            agents_state: AgentsState::new(pool)?,
        })
    }
}

/// Consolidated state for the unified NHI router.
///
/// Contains all sub-states needed by the consolidated /nhi/* router.
#[derive(Clone)]
pub struct ConsolidatedNhiState {
    /// State for unified NHI operations (list, get, risk-summary).
    pub nhi_state: crate::router::NhiAppState,
    /// State for service account operations.
    pub service_accounts_state: ServiceAccountsState,
    /// State for AI agent operations.
    pub agents_state: AgentsState,
    /// State for tool operations.
    pub tools_state: ToolsState,
    /// State for approval operations.
    pub approvals_state: ApprovalsState,
}

impl ConsolidatedNhiState {
    /// Create a new ConsolidatedNhiState with the given database pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the AgentsState cannot be created.
    pub fn new(pool: PgPool) -> Result<Self, crate::error::ApiNhiError> {
        let agents_state = AgentsState::new(pool.clone())?;

        Ok(Self {
            nhi_state: crate::router::NhiAppState::new(pool.clone()),
            service_accounts_state: ServiceAccountsState::new(pool.clone()),
            agents_state: agents_state.clone(),
            tools_state: ToolsState::new(agents_state.clone()),
            approvals_state: ApprovalsState::new(agents_state),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_state_types_compile() {
        // This test verifies the state types compile correctly.
        // Actual functionality requires a database pool.
        assert!(true);
    }
}
