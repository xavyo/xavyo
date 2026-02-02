//! Request and response models for policy simulation API (F060).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::{IntoParams, ToSchema};

use xavyo_db::{ImpactSummary, ImpactType, PolicySimulationType, SimulationStatus};

// ============================================================================
// Request Models
// ============================================================================

/// Request to create a new policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatePolicySimulationRequest {
    /// Name for the simulation.
    pub name: String,

    /// Type of policy being simulated.
    pub simulation_type: PolicySimulationType,

    /// Reference to an existing policy (optional for "what-if" with draft config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,

    /// Draft policy configuration to simulate (required if policy_id is None).
    pub policy_config: serde_json::Value,
}

/// Request to execute a policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutePolicySimulationRequest {
    /// Optional: Limit analysis to specific users (default: all applicable users).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<Vec<Uuid>>,
}

/// Request to update simulation notes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdatePolicySimulationNotesRequest {
    /// Notes/comments on the simulation (null to clear).
    pub notes: Option<String>,
}

// ============================================================================
// Response Models
// ============================================================================

/// Response containing a policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySimulationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Simulation name.
    pub name: String,

    /// Type of policy simulated.
    pub simulation_type: PolicySimulationType,

    /// Reference to existing policy (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,

    /// Policy configuration used for simulation.
    pub policy_config: serde_json::Value,

    /// Current status.
    pub status: SimulationStatus,

    /// Users affected by this simulation.
    pub affected_user_count: i32,

    /// Impact summary (populated after execution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_summary: Option<ImpactSummary>,

    /// Timestamp when data was captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_snapshot_at: Option<DateTime<Utc>>,

    /// Whether the simulation results are stale.
    pub is_stale: bool,

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
}

/// Response containing a policy simulation result (per-user impact).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySimulationResultResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Reference to parent simulation.
    pub simulation_id: Uuid,

    /// Affected user ID.
    pub user_id: Uuid,

    /// Type of impact.
    pub impact_type: ImpactType,

    /// Detailed impact information.
    pub details: serde_json::Value,

    /// Severity level (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,

    /// When this result was created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of policy simulations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySimulationListResponse {
    /// List of simulations.
    pub simulations: Vec<PolicySimulationResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current page offset.
    pub offset: i64,

    /// Page size limit.
    pub limit: i64,
}

/// Paginated list of simulation results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySimulationResultListResponse {
    /// List of results.
    pub results: Vec<PolicySimulationResultResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current page offset.
    pub offset: i64,

    /// Page size limit.
    pub limit: i64,
}

/// Export response with data in requested format.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationExportResponse {
    /// Export format (json, csv).
    pub format: String,

    /// File name suggestion.
    pub filename: String,

    /// Export data (for JSON) or base64-encoded CSV.
    pub data: serde_json::Value,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing policy simulations.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListPolicySimulationsQuery {
    /// Filter by simulation type.
    pub simulation_type: Option<PolicySimulationType>,

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

/// Query parameters for listing simulation results.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListPolicySimulationResultsQuery {
    /// Filter by impact type.
    pub impact_type: Option<ImpactType>,

    /// Filter by severity.
    pub severity: Option<String>,

    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Page offset (default: 0).
    pub offset: Option<i64>,

    /// Page size (default: 20, max: 100).
    pub limit: Option<i64>,
}

/// Query parameters for exporting simulation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ExportSimulationQuery {
    /// Export format: json or csv.
    #[param(example = "json")]
    #[serde(default = "default_format")]
    pub format: String,
}

/// Query parameters for exporting policy simulation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ExportPolicySimulationQuery {
    /// Export format: json or csv (default: json).
    #[param(example = "json")]
    pub format: Option<String>,
}

/// Request to update notes on a simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateNotesRequest {
    /// Notes/comments on the simulation (null to clear).
    pub notes: Option<String>,
}

fn default_format() -> String {
    "json".to_string()
}

// ============================================================================
// Conversion Implementations
// ============================================================================

impl From<xavyo_db::GovPolicySimulation> for PolicySimulationResponse {
    fn from(sim: xavyo_db::GovPolicySimulation) -> Self {
        let impact_summary = if sim.status == SimulationStatus::Executed {
            Some(sim.parse_impact_summary())
        } else {
            None
        };

        Self {
            id: sim.id,
            tenant_id: sim.tenant_id,
            name: sim.name,
            simulation_type: sim.simulation_type,
            policy_id: sim.policy_id,
            policy_config: sim.policy_config,
            status: sim.status,
            affected_user_count: sim.affected_users.len() as i32,
            impact_summary,
            data_snapshot_at: sim.data_snapshot_at,
            is_stale: false, // Will be computed by service
            is_archived: sim.is_archived,
            notes: sim.notes,
            created_by: sim.created_by,
            created_at: sim.created_at,
            executed_at: sim.executed_at,
        }
    }
}

impl From<xavyo_db::GovPolicySimulationResult> for PolicySimulationResultResponse {
    fn from(result: xavyo_db::GovPolicySimulationResult) -> Self {
        Self {
            id: result.id,
            simulation_id: result.simulation_id,
            user_id: result.user_id,
            impact_type: result.impact_type,
            details: result.details,
            severity: result.severity,
            created_at: result.created_at,
        }
    }
}
