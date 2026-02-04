//! Request and response models for simulation comparison API (F060).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::{IntoParams, ToSchema};

use xavyo_db::{ComparisonSummary, ComparisonType, DeltaEntry, DeltaResults, ModifiedEntry};

// ============================================================================
// Request Models
// ============================================================================

/// Request to create a simulation comparison.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSimulationComparisonRequest {
    /// Name for the comparison.
    pub name: String,

    /// Type of comparison.
    pub comparison_type: ComparisonType,

    /// First simulation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_a_id: Option<Uuid>,

    /// Type of first simulation ("policy" or "batch").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_a_type: Option<String>,

    /// Second simulation ID (required for `simulation_vs_simulation`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_b_id: Option<Uuid>,

    /// Type of second simulation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_b_type: Option<String>,
}

// ============================================================================
// Response Models
// ============================================================================

/// Response containing a simulation comparison.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationComparisonResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Comparison name.
    pub name: String,

    /// Type of comparison.
    pub comparison_type: ComparisonType,

    /// First simulation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_a_id: Option<Uuid>,

    /// Type of first simulation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_a_type: Option<String>,

    /// Second simulation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_b_id: Option<Uuid>,

    /// Type of second simulation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_b_type: Option<String>,

    /// Summary statistics.
    pub summary_stats: ComparisonSummary,

    /// Delta results (added, removed, modified).
    pub delta_results: DeltaResults,

    /// Whether the comparison is stale (underlying simulations changed).
    pub is_stale: bool,

    /// Who created the comparison.
    pub created_by: Uuid,

    /// When it was created.
    pub created_at: DateTime<Utc>,
}

/// Detailed comparison showing user-level differences.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComparisonDetailResponse {
    /// Users only in simulation A.
    pub added: Vec<DeltaEntry>,

    /// Users only in simulation B (or current state).
    pub removed: Vec<DeltaEntry>,

    /// Users with different impacts between A and B.
    pub modified: Vec<ModifiedEntry>,
}

/// Paginated list of simulation comparisons.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationComparisonListResponse {
    /// List of comparisons.
    pub comparisons: Vec<SimulationComparisonResponse>,

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

/// Query parameters for listing simulation comparisons.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListSimulationComparisonsQuery {
    /// Filter by comparison type.
    pub comparison_type: Option<ComparisonType>,

    /// Filter by creator.
    pub created_by: Option<Uuid>,

    /// Page offset (default: 0).
    pub offset: Option<i64>,

    /// Page size (default: 20, max: 100).
    pub limit: Option<i64>,
}

/// Query parameters for exporting simulation comparison.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ExportSimulationComparisonQuery {
    /// Export format: json or csv (default: json).
    #[param(example = "json")]
    pub format: Option<String>,
}

// ============================================================================
// Conversion Implementations
// ============================================================================

impl From<xavyo_db::GovSimulationComparison> for SimulationComparisonResponse {
    fn from(comp: xavyo_db::GovSimulationComparison) -> Self {
        // Parse before consuming string fields
        let summary_stats = comp.parse_summary_stats();
        let delta_results = comp.parse_delta_results();

        Self {
            id: comp.id,
            tenant_id: comp.tenant_id,
            name: comp.name,
            comparison_type: comp.comparison_type,
            simulation_a_id: comp.simulation_a_id,
            simulation_a_type: comp.simulation_a_type,
            simulation_b_id: comp.simulation_b_id,
            simulation_b_type: comp.simulation_b_type,
            summary_stats,
            delta_results,
            is_stale: comp.is_stale,
            created_by: comp.created_by,
            created_at: comp.created_at,
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

impl CreateSimulationComparisonRequest {
    /// Validate the request.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Name is required".to_string());
        }

        if self.name.len() > 255 {
            return Err("Name must be 255 characters or less".to_string());
        }

        match self.comparison_type {
            ComparisonType::SimulationVsSimulation => {
                if self.simulation_a_id.is_none() {
                    return Err("simulation_a_id required for simulation_vs_simulation".to_string());
                }
                if self.simulation_a_type.is_none() {
                    return Err(
                        "simulation_a_type required for simulation_vs_simulation".to_string()
                    );
                }
                if self.simulation_b_id.is_none() {
                    return Err("simulation_b_id required for simulation_vs_simulation".to_string());
                }
                if self.simulation_b_type.is_none() {
                    return Err(
                        "simulation_b_type required for simulation_vs_simulation".to_string()
                    );
                }
            }
            ComparisonType::SimulationVsCurrent => {
                if self.simulation_a_id.is_none() {
                    return Err("simulation_a_id required for simulation_vs_current".to_string());
                }
                if self.simulation_a_type.is_none() {
                    return Err("simulation_a_type required for simulation_vs_current".to_string());
                }
                // simulation_b_* should be None for vs_current
                if self.simulation_b_id.is_some() {
                    return Err(
                        "simulation_b_id should be None for simulation_vs_current".to_string()
                    );
                }
            }
        }

        // Validate simulation types
        if let Some(ref sim_type) = self.simulation_a_type {
            if sim_type != "policy" && sim_type != "batch" {
                return Err("simulation_a_type must be 'policy' or 'batch'".to_string());
            }
        }

        if let Some(ref sim_type) = self.simulation_b_type {
            if sim_type != "policy" && sim_type != "batch" {
                return Err("simulation_b_type must be 'policy' or 'batch'".to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_simulation_vs_simulation() {
        let request = CreateSimulationComparisonRequest {
            name: "Test Comparison".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(Uuid::new_v4()),
            simulation_b_type: Some("policy".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_validate_simulation_vs_current() {
        let request = CreateSimulationComparisonRequest {
            name: "Test Comparison".to_string(),
            comparison_type: ComparisonType::SimulationVsCurrent,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("batch".to_string()),
            simulation_b_id: None,
            simulation_b_type: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_validate_missing_simulation_a() {
        let request = CreateSimulationComparisonRequest {
            name: "Test Comparison".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: None,
            simulation_a_type: None,
            simulation_b_id: Some(Uuid::new_v4()),
            simulation_b_type: Some("policy".to_string()),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_simulation_type() {
        let request = CreateSimulationComparisonRequest {
            name: "Test Comparison".to_string(),
            comparison_type: ComparisonType::SimulationVsCurrent,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("invalid".to_string()),
            simulation_b_id: None,
            simulation_b_type: None,
        };

        let result = request.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 'policy' or 'batch'"));
    }
}
