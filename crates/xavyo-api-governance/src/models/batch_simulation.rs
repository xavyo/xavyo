//! Request and response models for batch simulation API (F060).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use utoipa::{IntoParams, ToSchema};

use xavyo_db::{
    AccessItem, BatchImpactSummary, BatchSimulationType, ChangeSpec, FilterCriteria, SelectionMode,
    SimulationStatus,
};

// ============================================================================
// Request Models
// ============================================================================

/// Request to create a new batch simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateBatchSimulationRequest {
    /// Name for the simulation.
    pub name: String,

    /// Type of batch operation.
    pub batch_type: BatchSimulationType,

    /// How users are selected.
    pub selection_mode: SelectionMode,

    /// Explicit user IDs (required for `user_list` mode).
    #[serde(default)]
    pub user_ids: Vec<Uuid>,

    /// Filter criteria (required for filter mode).
    #[serde(default)]
    pub filter_criteria: FilterCriteria,

    /// What change to simulate.
    pub change_spec: ChangeSpec,
}

/// Request to execute a batch simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecuteBatchSimulationRequest {
    /// Acknowledge scope warning (required if >100 users affected).
    #[serde(default)]
    pub acknowledge_scope_warning: bool,
}

/// Request to apply a batch simulation (commit changes).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplyBatchSimulationRequest {
    /// Reason/justification for applying the changes.
    pub justification: String,

    /// Acknowledge scope warning (required if >100 users affected).
    #[serde(default)]
    pub acknowledge_scope_warning: bool,
}

impl Validate for ApplyBatchSimulationRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();
        if self.justification.trim().is_empty() || self.justification.len() > 5000 {
            let mut err = validator::ValidationError::new("length");
            err.message = Some("justification must be 1-5000 characters".into());
            errors.add("justification", err);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Request to update simulation notes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateBatchSimulationNotesRequest {
    /// Notes/comments on the simulation (null to clear).
    pub notes: Option<String>,
}

impl Validate for UpdateBatchSimulationNotesRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();
        if let Some(ref n) = self.notes {
            if n.len() > 10_000 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("notes must be at most 10,000 characters".into());
                errors.add("notes", err);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ============================================================================
// Response Models
// ============================================================================

/// Response containing a batch simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSimulationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Simulation name.
    pub name: String,

    /// Type of batch operation.
    pub batch_type: BatchSimulationType,

    /// How users were selected.
    pub selection_mode: SelectionMode,

    /// Number of users in selection.
    pub total_users: i32,

    /// Users processed so far.
    pub processed_users: i32,

    /// Current status.
    pub status: SimulationStatus,

    /// Impact summary (populated after execution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_summary: Option<BatchImpactSummary>,

    /// Whether this simulation exceeds scope warning threshold.
    pub has_scope_warning: bool,

    /// Timestamp when data was captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_snapshot_at: Option<DateTime<Utc>>,

    /// Whether the simulation is archived.
    pub is_archived: bool,

    /// Notes/comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// Who created the simulation.
    pub created_by: Uuid,

    /// When it was created.
    pub created_at: DateTime<Utc>,

    /// When it was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<DateTime<Utc>>,

    /// When it was applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<DateTime<Utc>>,

    /// Who applied the simulation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_by: Option<Uuid>,
}

/// Response containing a batch simulation result (per-user impact).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSimulationResultResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Reference to parent simulation.
    pub simulation_id: Uuid,

    /// Affected user ID.
    pub user_id: Uuid,

    /// Access that would be gained.
    pub access_gained: Vec<AccessItem>,

    /// Access that would be lost.
    pub access_lost: Vec<AccessItem>,

    /// Warning messages.
    pub warnings: Vec<String>,

    /// When this result was created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of batch simulations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSimulationListResponse {
    /// List of simulations.
    pub simulations: Vec<BatchSimulationResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current page offset.
    pub offset: i64,

    /// Page size limit.
    pub limit: i64,
}

/// Paginated list of batch simulation results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSimulationResultListResponse {
    /// List of results.
    pub results: Vec<BatchSimulationResultResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current page offset.
    pub offset: i64,

    /// Page size limit.
    pub limit: i64,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing batch simulations.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListBatchSimulationsQuery {
    /// Filter by batch type.
    pub batch_type: Option<BatchSimulationType>,

    /// Filter by status.
    pub status: Option<SimulationStatus>,

    /// Filter by creator.
    pub created_by: Option<Uuid>,

    /// Include archived simulations.
    pub include_archived: Option<bool>,

    /// Page offset (default: 0).
    pub offset: Option<i64>,

    /// Page size (default: 20, max: 100).
    pub limit: Option<i64>,
}

/// Query parameters for listing batch simulation results.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListBatchSimulationResultsQuery {
    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by whether result has warnings.
    pub has_warnings: Option<bool>,

    /// Page offset (default: 0).
    pub offset: Option<i64>,

    /// Page size (default: 20, max: 100).
    pub limit: Option<i64>,
}

/// Query parameters for exporting batch simulation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ExportBatchSimulationQuery {
    /// Export format: json or csv.
    #[param(example = "json")]
    pub format: Option<String>,
}

// ============================================================================
// Conversion Implementations
// ============================================================================

impl From<xavyo_db::GovBatchSimulation> for BatchSimulationResponse {
    fn from(sim: xavyo_db::GovBatchSimulation) -> Self {
        let impact_summary = if sim.status == SimulationStatus::Executed
            || sim.status == SimulationStatus::Applied
        {
            Some(sim.parse_impact_summary())
        } else {
            None
        };

        let has_scope_warning = sim.has_scope_warning();

        Self {
            id: sim.id,
            tenant_id: sim.tenant_id,
            name: sim.name,
            batch_type: sim.batch_type,
            selection_mode: sim.selection_mode,
            total_users: sim.total_users,
            processed_users: sim.processed_users,
            status: sim.status,
            impact_summary,
            has_scope_warning,
            data_snapshot_at: sim.data_snapshot_at,
            is_archived: sim.is_archived,
            notes: sim.notes,
            created_by: sim.created_by,
            created_at: sim.created_at,
            executed_at: sim.executed_at,
            applied_at: sim.applied_at,
            applied_by: sim.applied_by,
        }
    }
}

impl From<xavyo_db::GovBatchSimulationResult> for BatchSimulationResultResponse {
    fn from(result: xavyo_db::GovBatchSimulationResult) -> Self {
        Self {
            id: result.id,
            simulation_id: result.simulation_id,
            user_id: result.user_id,
            access_gained: result.parse_access_gained(),
            access_lost: result.parse_access_lost(),
            warnings: result.parse_warnings(),
            created_at: result.created_at,
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

impl CreateBatchSimulationRequest {
    /// Validate the request.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Name is required".to_string());
        }

        if self.name.len() > 255 {
            return Err("Name must be 255 characters or less".to_string());
        }

        if self.user_ids.len() > 10_000 {
            return Err("user_ids must contain at most 10,000 entries".to_string());
        }

        match self.selection_mode {
            SelectionMode::UserList => {
                if self.user_ids.is_empty() {
                    return Err("user_ids required when selection_mode is user_list".to_string());
                }
            }
            SelectionMode::Filter => {
                // Filter criteria can be empty (matches all users) but should be intentional
            }
        }

        // Validate change spec matches batch type
        match self.batch_type {
            BatchSimulationType::RoleAdd | BatchSimulationType::RoleRemove => {
                if self.change_spec.role_id.is_none() {
                    return Err("role_id required for role operations".to_string());
                }
            }
            BatchSimulationType::EntitlementAdd | BatchSimulationType::EntitlementRemove => {
                if self.change_spec.entitlement_id.is_none() {
                    return Err("entitlement_id required for entitlement operations".to_string());
                }
            }
        }

        Ok(())
    }
}
