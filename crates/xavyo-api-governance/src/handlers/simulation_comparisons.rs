//! Simulation comparison handlers for governance API (F060).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateSimulationComparisonRequest, ListSimulationComparisonsQuery, PaginatedResponse,
    SimulationComparisonResponse,
};
use crate::router::GovernanceState;

// ============================================================================
// Simulation Comparison Endpoints
// ============================================================================

/// Get a simulation comparison by ID.
#[utoipa::path(
    get,
    path = "/governance/simulations/comparisons/{comparison_id}",
    tag = "Governance - Enhanced Simulation",
    params(
        ("comparison_id" = Uuid, Path, description = "Comparison ID")
    ),
    responses(
        (status = 200, description = "Comparison retrieved", body = SimulationComparisonResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Comparison not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_simulation_comparison(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(comparison_id): Path<Uuid>,
) -> ApiResult<Json<SimulationComparisonResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let comparison = state
        .simulation_comparison_service
        .get(tenant_id, comparison_id)
        .await?;

    Ok(Json(SimulationComparisonResponse::from(comparison)))
}

/// List simulation comparisons.
#[utoipa::path(
    get,
    path = "/governance/simulations/comparisons",
    tag = "Governance - Enhanced Simulation",
    params(ListSimulationComparisonsQuery),
    responses(
        (status = 200, description = "Comparisons listed", body = PaginatedSimulationComparisonResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_simulation_comparisons(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSimulationComparisonsQuery>,
) -> ApiResult<Json<PaginatedResponse<SimulationComparisonResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (comparisons, total) = state
        .simulation_comparison_service
        .list(
            tenant_id,
            query.comparison_type,
            query.created_by,
            limit,
            offset,
        )
        .await?;

    let items: Vec<SimulationComparisonResponse> = comparisons
        .into_iter()
        .map(std::convert::Into::into)
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a new simulation comparison.
#[utoipa::path(
    post,
    path = "/governance/simulations/comparisons",
    tag = "Governance - Enhanced Simulation",
    request_body = CreateSimulationComparisonRequest,
    responses(
        (status = 201, description = "Comparison created", body = SimulationComparisonResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_simulation_comparison(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSimulationComparisonRequest>,
) -> ApiResult<Json<SimulationComparisonResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request.validate().map_err(ApiGovernanceError::Validation)?;

    let comparison = state
        .simulation_comparison_service
        .create(
            tenant_id,
            request.name,
            request.comparison_type,
            request.simulation_a_id,
            request.simulation_a_type,
            request.simulation_b_id,
            request.simulation_b_type,
            user_id,
        )
        .await?;

    Ok(Json(SimulationComparisonResponse::from(comparison)))
}

/// Delete a simulation comparison.
#[utoipa::path(
    delete,
    path = "/governance/simulations/comparisons/{comparison_id}",
    tag = "Governance - Enhanced Simulation",
    params(
        ("comparison_id" = Uuid, Path, description = "Comparison ID")
    ),
    responses(
        (status = 204, description = "Comparison deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Comparison not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_simulation_comparison(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(comparison_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .simulation_comparison_service
        .delete(tenant_id, comparison_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Export Endpoint
// ============================================================================

use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::ExportSimulationComparisonQuery;

/// Export simulation comparison results.
#[utoipa::path(
    get,
    path = "/governance/simulations/comparisons/{comparison_id}/export",
    tag = "Governance - Enhanced Simulation",
    params(
        ("comparison_id" = Uuid, Path, description = "Comparison ID"),
        ExportSimulationComparisonQuery
    ),
    responses(
        (status = 200, description = "Export data", content_type = ["application/json", "text/csv"]),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Comparison not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_simulation_comparison(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(comparison_id): Path<Uuid>,
    Query(query): Query<ExportSimulationComparisonQuery>,
) -> Result<Response, ApiGovernanceError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the comparison
    let comparison = state
        .simulation_comparison_service
        .get(tenant_id, comparison_id)
        .await?;

    let format = query.format.as_deref().unwrap_or("json");

    if format == "csv" {
        // Generate CSV export
        let mut csv_output = String::from("type,user_id,impact_a,impact_b,diff\n");

        // Parse delta results
        let delta: xavyo_db::DeltaResults =
            serde_json::from_value(comparison.delta_results.clone()).unwrap_or_default();

        // Add entries
        for entry in delta.added {
            let impact_str = serde_json::to_string(&entry.impact)
                .unwrap_or_default()
                .replace('"', "\"\"");
            csv_output.push_str(&format!(
                "added,{},\"{}\",\"\",\"\"\n",
                entry.user_id, impact_str
            ));
        }

        for entry in delta.removed {
            let impact_str = serde_json::to_string(&entry.impact)
                .unwrap_or_default()
                .replace('"', "\"\"");
            csv_output.push_str(&format!(
                "removed,{},\"{}\",\"\",\"\"\n",
                entry.user_id, impact_str
            ));
        }

        for entry in delta.modified {
            let impact_a_str = serde_json::to_string(&entry.impact_a)
                .unwrap_or_default()
                .replace('"', "\"\"");
            let impact_b_str = serde_json::to_string(&entry.impact_b)
                .unwrap_or_default()
                .replace('"', "\"\"");
            let diff_str = serde_json::to_string(&entry.diff)
                .unwrap_or_default()
                .replace('"', "\"\"");
            csv_output.push_str(&format!(
                "modified,{},\"{}\",\"{}\",\"{}\"\n",
                entry.user_id, impact_a_str, impact_b_str, diff_str
            ));
        }

        let filename = format!("comparison_{comparison_id}.csv");

        Ok((
            [
                (header::CONTENT_TYPE, "text/csv"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{filename}\""),
                ),
            ],
            csv_output,
        )
            .into_response())
    } else {
        // JSON export (default)
        let export_data = SimulationComparisonExport {
            comparison: SimulationComparisonResponse::from(comparison),
        };

        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

        let filename = format!("comparison_{comparison_id}.json");

        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{filename}\""),
                ),
            ],
            json,
        )
            .into_response())
    }
}

/// Export data structure for simulation comparison.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationComparisonExport {
    /// The comparison metadata and results.
    pub comparison: SimulationComparisonResponse,
}
